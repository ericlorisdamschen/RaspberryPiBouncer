"""The DNS server: answers devices' requests, blocks what's on the lists and
forwards the rest (encrypted) to the internet."""

import asyncio
import ipaddress
import logging
import socket
import struct
import time
from collections import OrderedDict, defaultdict, deque

from dnslib import AAAA, A, CNAME, DNSRecord, QTYPE, RCODE, RR, DNSLabel

from . import blocklists as bl
from .upstream import UpstreamError, udp_query

log = logging.getLogger("bouncer.dns")

BLOCK_TTL = 10
LOCAL_TTL = 60
CHECK_NAME = "protected.bouncer.home.arpa"
LOCAL_NAMES = {"bouncer", "bouncer.local", "bouncer.home.arpa", CHECK_NAME}
LOCAL_DOMAINS = ("fritz.box", "lan", "home", "localdomain", "local", "internal", "home.arpa")
PRIVATE_REVERSE = ("10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
                   "d.f.ip6.arpa", "c.f.ip6.arpa", "8.e.f.ip6.arpa") + \
    tuple(f"{i}.172.in-addr.arpa" for i in range(16, 32))

# Family filter: force SafeSearch / restricted mode.
GOOGLE_TLDS = ["com", "lu", "de", "fr", "be", "nl", "at", "ch", "it", "es", "pt", "co.uk", "ie",
               "pl", "dk", "se", "no", "fi", "cz", "gr", "hu", "ro", "sk", "si", "hr", "bg",
               "lt", "lv", "ee", "ca", "com.au", "co.in", "com.br", "com.tr", "ru", "co.jp"]
SAFESEARCH = {f"www.google.{t}": "forcesafesearch.google.com" for t in GOOGLE_TLDS}
SAFESEARCH.update({f"google.{t}": "forcesafesearch.google.com" for t in GOOGLE_TLDS})
SAFESEARCH.update({
    "www.bing.com": "strict.bing.com", "bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com", "www.duckduckgo.com": "safe.duckduckgo.com",
    "www.youtube.com": "restrictmoderate.youtube.com", "m.youtube.com": "restrictmoderate.youtube.com",
    "youtubei.googleapis.com": "restrictmoderate.youtube.com",
    "youtube.googleapis.com": "restrictmoderate.youtube.com",
    "www.youtube-nocookie.com": "restrictmoderate.youtube.com",
})


class Cache:
    def __init__(self, max_entries=10000):
        self.data = OrderedDict()
        self.max = max_entries
        self.hits = self.misses = 0

    def get(self, key):
        item = self.data.get(key)
        if not item:
            self.misses += 1
            return None
        expires, stored, record = item
        now = time.monotonic()
        if now >= expires:
            del self.data[key]
            self.misses += 1
            return None
        self.data.move_to_end(key)
        self.hits += 1
        remaining = max(1, int(expires - now))
        rec = DNSRecord.parse(record)
        for rr in rec.rr + rec.auth + rec.ar:
            if rr.rtype != QTYPE.OPT:
                rr.ttl = min(rr.ttl, remaining)
        return rec

    def put(self, key, response: DNSRecord):
        rcode = response.header.rcode
        if rcode not in (RCODE.NOERROR, RCODE.NXDOMAIN) or response.header.tc:
            return
        ttls = [rr.ttl for rr in response.rr]
        if not ttls:  # negative answer: use the SOA minimum, at most 5 minutes
            ttls = [min(rr.ttl, 300) for rr in response.auth if rr.rtype == QTYPE.SOA] or [60]
        ttl = max(0, min(min(ttls), 86400))
        if ttl == 0:
            return
        self.data[key] = (time.monotonic() + ttl, time.time(), response.pack())
        self.data.move_to_end(key)
        while len(self.data) > self.max:
            self.data.popitem(last=False)

    def clear(self):
        self.data.clear()


class Resolver:
    def __init__(self, settings, lists, stats, upstreams, netinfo, devices):
        self.settings = settings
        self.lists = lists
        self.stats = stats
        self.upstreams = upstreams
        self.net = netinfo
        self.devices = devices
        self.cache = Cache()
        # Recently blocked ad/tracker domains per device, kept only in memory for
        # "Fix a website". Never written to disk, never shown.
        self.recent_blocked = defaultdict(lambda: deque(maxlen=300))
        self.client_last_query = {}
        self.queries_by_gateway = deque(maxlen=500)   # (ts, from_gateway) to detect proxying routers
        self.setup_mode = False
        self._load_rules()
        settings.on_change(self._on_settings_change)

    def _load_rules(self):
        s = self.settings
        self.protection = s.get("protection")
        self.allow = set(bl.normalize(d) for d in s.get("allow", []))
        self.block = set(bl.normalize(d) for d in s.get("block", []))
        self.fixes = set(bl.normalize(d) for d in s.get("fixes", []))
        self.paused_until = s.get("paused_until", 0) or 0

    def _on_settings_change(self, keys):
        if keys & {"protection", "allow", "block", "fixes", "paused_until"}:
            self._load_rules()
            self.cache.clear()

    @property
    def paused(self):
        return time.time() < self.paused_until

    # ---- answering -------------------------------------------------------
    async def handle(self, data: bytes, client_ip: str) -> bytes:
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return None
        if request.header.qr or not request.questions:
            return None
        q = request.q
        qname = str(q.qname).rstrip(".").lower()
        qtype = q.qtype
        if client_ip.startswith("::ffff:"):
            client_ip = client_ip[7:]

        local = self._local_answer(request, qname, qtype)
        if local is not None:
            return local.pack()

        device = self.devices.device_id(client_ip) if self.devices else client_ip
        self.client_last_query[device] = time.time()
        from_gateway = client_ip == self.net.gateway
        self.queries_by_gateway.append((time.time(), from_gateway))

        # Local names and reverse lookups for home addresses go to the router.
        if self._is_local_query(qname, qtype):
            if from_gateway:   # the router asking us about its own names: avoid a loop
                return self._reply(request, RCODE.NXDOMAIN).pack()
            return await self._forward_local(request, data)

        category = bl.ALLOWED
        if not self.paused:
            category = self.lists.classify(qname, self.protection, self.allow, self.block,
                                           self.fixes)
        if category != bl.ALLOWED:
            self.stats.record(device, category)
            if category == bl.ADS:
                self.recent_blocked[device].append((time.time(), qname))
            return self._blocked(request, qtype).pack()

        self.stats.record(device, bl.ALLOWED)

        if self.protection.get("family") and not self.paused and qname in SAFESEARCH:
            return (await self._safesearch(request, SAFESEARCH[qname])).pack()

        return (await self._resolve(request)).pack()

    def _reply(self, request, rcode=RCODE.NOERROR):
        reply = request.reply()
        reply.header.rcode = rcode
        reply.header.ra = 1
        return reply

    def _local_answer(self, request, qname, qtype):
        if self.setup_mode:
            return None
        if qname not in LOCAL_NAMES:
            return None
        reply = self._reply(request)
        if qtype in (QTYPE.A, QTYPE.ANY) and self.net.ipv4:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.net.ipv4), ttl=LOCAL_TTL))
        if qtype in (QTYPE.AAAA, QTYPE.ANY) and self.net.best_ipv6():
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(self.net.best_ipv6()), ttl=LOCAL_TTL))
        return reply

    def _is_local_query(self, qname, qtype):
        if "." not in qname:
            return qtype not in (QTYPE.DS, QTYPE.SOA) and qname != ""
        if qname.endswith(PRIVATE_REVERSE) or any(qname.endswith("." + p) for p in PRIVATE_REVERSE):
            return True
        return any(qname == d or qname.endswith("." + d) for d in LOCAL_DOMAINS)

    async def _forward_local(self, request, data):
        gw = self.net.gateway
        if not gw:
            return self._reply(request, RCODE.NXDOMAIN).pack()
        try:
            return await udp_query(gw, data, timeout=1.5)
        except (OSError, asyncio.TimeoutError, UpstreamError):
            return self._reply(request, RCODE.NXDOMAIN).pack()

    def _blocked(self, request, qtype):
        reply = self._reply(request)
        name = request.q.qname
        if qtype == QTYPE.A:
            reply.add_answer(RR(name, QTYPE.A, rdata=A("0.0.0.0"), ttl=BLOCK_TTL))
        elif qtype == QTYPE.AAAA:
            reply.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA("::"), ttl=BLOCK_TTL))
        return reply

    async def _resolve(self, request):
        q = request.q
        key = (str(q.qname).lower(), q.qtype, q.qclass,
               bool(request.header.cd), bool(request.ar and any(r.rtype == QTYPE.OPT for r in request.ar)))
        cached = self.cache.get(key)
        if cached is not None:
            cached.header.id = request.header.id
            cached.questions = request.questions   # keep the client's spelling
            return cached
        try:
            raw = await self.upstreams.query(request.pack())
            response = DNSRecord.parse(raw)
        except (UpstreamError, Exception) as exc:
            log.debug("upstream failed: %s", exc)
            return self._reply(request, RCODE.SERVFAIL)
        response.header.id = request.header.id
        self.cache.put(key, response)
        return response

    async def _safesearch(self, request, target):
        reply = self._reply(request)
        qname = request.q.qname
        reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(target), ttl=300))
        if request.q.qtype in (QTYPE.A, QTYPE.AAAA):
            sub = DNSRecord.question(target, QTYPE.get(request.q.qtype))
            sub.header.id = request.header.id
            resolved = await self._resolve(sub)
            for rr in resolved.rr:
                reply.add_answer(rr)
        return reply

    # ---- helpers for the dashboard ----------------------------------------
    def gateway_share(self, window=3600):
        cutoff = time.time() - window
        rows = [g for ts, g in self.queries_by_gateway if ts >= cutoff]
        if len(rows) < 20:
            return 0.0
        return sum(rows) / len(rows)

    def fix_device(self, device, window=120):
        cutoff = time.time() - window
        domains = sorted({d for ts, d in self.recent_blocked.get(device, ()) if ts >= cutoff})
        if domains:
            fixes = self.settings.get("fixes", [])
            for d in domains:
                if d not in fixes:
                    fixes.append(d)
            self.settings.update(fixes=fixes[-2000:])
            self.recent_blocked[device].clear()
        return len(domains)


# ---- network servers ---------------------------------------------------------

class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, resolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._answer(data, addr))

    async def _answer(self, data, addr):
        try:
            resp = await self.resolver.handle(data, addr[0])
        except Exception:
            log.exception("error answering")
            return
        if resp is None:
            return
        limit = 512
        try:
            req = DNSRecord.parse(data)
            for rr in req.ar:
                if rr.rtype == QTYPE.OPT:
                    limit = max(512, min(rr.rclass, 1232))
        except Exception:
            pass
        if len(resp) > limit:
            resp = _truncate(resp)
        self.transport.sendto(resp, addr)


def _truncate(resp: bytes) -> bytes:
    rec = DNSRecord.parse(resp)
    rec.rr, rec.auth, rec.ar = [], [], []
    rec.header.tc = 1
    return rec.pack()


async def _tcp_client(resolver, reader, writer):
    peer = writer.get_extra_info("peername")[0]
    try:
        while True:
            head = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            (length,) = struct.unpack("!H", head)
            data = await asyncio.wait_for(reader.readexactly(length), timeout=10)
            resp = await resolver.handle(data, peer)
            if resp is None:
                break
            writer.write(struct.pack("!H", len(resp)) + resp)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()


async def start_servers(resolver, port=53, host4="0.0.0.0", host6="::"):
    loop = asyncio.get_running_loop()
    servers = []
    for host, family in ((host4, socket.AF_INET), (host6, socket.AF_INET6)):
        if not host:
            continue
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            transport, _ = await loop.create_datagram_endpoint(lambda: _UdpServer(resolver),
                                                               sock=sock)
            servers.append(transport)
            tsock = socket.socket(family, socket.SOCK_STREAM)
            tsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                tsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tsock.bind((host, port))
            srv = await asyncio.start_server(lambda r, w: _tcp_client(resolver, r, w), sock=tsock)
            servers.append(srv)
        except OSError as exc:
            if family == socket.AF_INET:
                raise
            log.warning("IPv6 DNS listener not started: %s", exc)
    return servers
