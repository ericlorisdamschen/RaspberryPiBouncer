"""Forwarding to internet DNS servers.

Queries go over DNS-over-TLS (port 853) so the internet provider cannot read
them. If no encrypted server answers (some networks block port 853), Bouncer
falls back to normal DNS so the internet keeps working, and the dashboard
says so."""

import asyncio
import logging
import random
import ssl
import struct
import time

log = logging.getLogger("bouncer.upstream")


class UpstreamError(Exception):
    pass


class DotConnection:
    """One persistent TLS connection; many queries can be in flight at once."""

    def __init__(self, ip, tls_name, port=853, ssl_context=None):
        self.ip, self.tls_name, self.port = ip, tls_name, port
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.reader = self.writer = None
        self.pending = {}
        self._reader_task = None
        self._connect_lock = asyncio.Lock()

    @property
    def connected(self):
        return self.writer is not None and not self.writer.is_closing()

    async def _connect(self):
        async with self._connect_lock:
            if self.connected:
                return
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port, ssl=self.ssl_context,
                                        server_hostname=self.tls_name), timeout=3)
            self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self):
        reader = self.reader
        try:
            while True:
                head = await reader.readexactly(2)
                (length,) = struct.unpack("!H", head)
                msg = await reader.readexactly(length)
                if len(msg) < 2:
                    continue
                fut = self.pending.pop(msg[:2], None)
                if fut and not fut.done():
                    fut.set_result(msg)
        except Exception:
            pass
        finally:
            self._close()

    def _close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.writer = self.reader = None
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(UpstreamError("connection closed"))
        self.pending.clear()

    async def query(self, msg: bytes, timeout=2.5) -> bytes:
        msg = bytes(msg)
        for attempt in (1, 2):
            qid = None
            try:
                try:
                    await self._connect()
                except asyncio.TimeoutError:
                    raise UpstreamError("connect timeout")
                qid = msg[:2]
                while qid in self.pending:
                    qid = struct.pack("!H", random.randint(0, 65535))
                wire = qid + msg[2:]
                fut = asyncio.get_running_loop().create_future()
                self.pending[qid] = fut
                self.writer.write(struct.pack("!H", len(wire)) + wire)
                await self.writer.drain()
                resp = await asyncio.wait_for(fut, timeout=timeout)
                return msg[:2] + resp[2:]
            except asyncio.TimeoutError:
                # A slow answer: give up on this query but keep the connection.
                if qid is not None:
                    self.pending.pop(qid, None)
                raise UpstreamError("timeout")
            except (UpstreamError, ConnectionError, OSError, asyncio.IncompleteReadError,
                    ssl.SSLError) as exc:
                self._close()
                if attempt == 2 or str(exc) == "connect timeout":
                    raise UpstreamError(str(exc))
        raise UpstreamError("unreachable")

    async def close(self):
        self._close()


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self, fut, expect_id):
        self.fut, self.expect_id = fut, expect_id

    def datagram_received(self, data, addr):
        if data[:2] == self.expect_id and not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_exception(exc)


async def udp_query(ip, msg: bytes, port=53, timeout=2.0) -> bytes:
    msg = bytes(msg)
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    qid = struct.pack("!H", random.randint(0, 65535))
    family = 10 if ":" in ip else 2
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpProto(fut, qid), remote_addr=(ip, port), family=family)
    try:
        transport.sendto(qid + msg[2:])
        resp = await asyncio.wait_for(fut, timeout)
        if len(resp) > 2 and resp[2] & 0x02:  # truncated: retry over TCP
            resp = await tcp_query(ip, msg, port, timeout)
        return msg[:2] + resp[2:]
    finally:
        transport.close()


async def tcp_query(ip, msg: bytes, port=53, timeout=2.0) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    try:
        writer.write(struct.pack("!H", len(msg)) + msg)
        await writer.drain()
        (length,) = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout))
        return await asyncio.wait_for(reader.readexactly(length), timeout)
    finally:
        writer.close()


class Upstreams:
    """Tries each server in order; remembers which ones work."""

    def __init__(self, servers, encrypted=True, dot_port=853, udp_port=53, ssl_context=None):
        self.servers = servers
        self.encrypted = encrypted
        self.dot_port, self.udp_port = dot_port, udp_port
        self.ssl_context = ssl_context
        self.conns = {}
        self.last_mode = "starting"     # "encrypted", "plain", "none" (or "starting")
        self.last_ok = 0
        self._dot_failures = 0
        self._skip_dot_until = 0

    def _conn(self, server):
        key = server["ip"]
        if key not in self.conns:
            self.conns[key] = DotConnection(server["ip"], server["tls_name"], self.dot_port,
                                            self.ssl_context)
        return self.conns[key]

    async def query(self, msg: bytes) -> bytes:
        msg = bytes(msg)
        now = time.monotonic()
        if self.encrypted and now >= self._skip_dot_until:
            for server in self.servers:
                try:
                    resp = await self._conn(server).query(msg)
                    self._dot_failures = 0
                    self.last_mode, self.last_ok = "encrypted", time.time()
                    return resp
                except UpstreamError as exc:
                    log.debug("DoT %s failed: %s", server["ip"], exc)
            self._dot_failures += 1
            if self._dot_failures >= 3:
                # Port 853 seems blocked; use plain DNS for 10 minutes, then retry.
                self._skip_dot_until = now + 600
                self._dot_failures = 0
        for server in self.servers:
            try:
                resp = await udp_query(server["ip"], msg, self.udp_port)
                self.last_mode, self.last_ok = "plain", time.time()
                return resp
            except (OSError, asyncio.TimeoutError, UpstreamError) as exc:
                log.debug("UDP %s failed: %s", server["ip"], exc)
        self.last_mode = "none"
        raise UpstreamError("no upstream server answered")

    async def close(self):
        for c in self.conns.values():
            await c.close()
