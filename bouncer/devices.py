"""Recognising the devices in the home.

A device is identified by its hardware (MAC) address when Bouncer can see it,
otherwise by its IP address. Names come from, in this order: the name the
household gave it, the address-mode lease list, or the router's own name
for it (asked via reverse DNS, which a FRITZ!Box answers)."""

import asyncio
import ipaddress
import logging
import re
import socket
import subprocess
import time
from pathlib import Path

from dnslib import DNSRecord, QTYPE

from . import paths

log = logging.getLogger("bouncer.devices")

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def read_arp_table():
    """IPv4 -> MAC from the kernel's neighbour table."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and _MAC_RE.match(parts[3]) and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3]
    except OSError:
        pass
    return table


def read_ipv6_neighbours():
    table = {}
    try:
        out = subprocess.run(["ip", "-6", "neigh", "show"], capture_output=True, text=True,
                             timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    for line in out.splitlines():
        parts = line.split()
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1].lower()
            if _MAC_RE.match(mac):
                table[parts[0]] = mac
    return table


def read_leases(path: Path = None):
    """MAC -> hostname from dnsmasq's lease file (address mode only)."""
    names = {}
    try:
        for line in Path(path or paths.LEASES_FILE).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3] != "*":
                names[parts[1].lower()] = parts[3]
    except OSError:
        pass
    return names


def _clean_name(name: str) -> str:
    name = name.rstrip(".")
    for suffix in (".fritz.box", ".lan", ".home", ".local", ".localdomain", ".home.arpa",
                   ".box", ".router"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return name.split(".")[0] if "." in name and not name.replace(".", "").isdigit() else name


def ptr_lookup(router_ip: str, ip: str, timeout=1.0):
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None
    q = DNSRecord.question(rev, "PTR")
    family = socket.AF_INET6 if ":" in router_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q.pack(), (router_ip, 53))
        data, _ = s.recvfrom(4096)
        resp = DNSRecord.parse(data)
        for rr in resp.rr:
            if rr.rtype == QTYPE.PTR:
                return _clean_name(str(rr.rdata))
    except (OSError, Exception):
        return None
    finally:
        s.close()
    return None


class DeviceTracker:
    def __init__(self, settings, netinfo):
        self.settings = settings
        self.netinfo = netinfo          # object with .gateway, .own_ips
        self._ip_to_mac = {}
        self._mac_refreshed = 0
        self._ptr_cache = {}            # ip -> (name, expires)
        self.seen_on_network = {}       # device id -> last time seen in ARP sweep
        self.device_ips = {}            # device id -> last IP

    def _refresh_macs(self, force=False):
        if force or time.time() - self._mac_refreshed > 30:
            table = read_arp_table()
            table.update(read_ipv6_neighbours())
            self._ip_to_mac = table
            self._mac_refreshed = time.time()

    def device_id(self, ip: str) -> str:
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        mac = self._ip_to_mac.get(ip)
        if mac is None and time.time() - self._mac_refreshed > 5:
            self._refresh_macs(force=True)
            mac = self._ip_to_mac.get(ip)
        dev = mac or ip
        self.device_ids_ip(dev, ip)
        return dev

    def device_ids_ip(self, dev, ip):
        if ":" not in ip or dev not in self.device_ips:
            self.device_ips[dev] = ip

    def ip_of(self, dev):
        return self.device_ips.get(dev, dev if not _MAC_RE.match(dev) else "")

    def name_of(self, dev, allow_lookup=True):
        custom = self.settings.get("devices", {}).get(dev, {}).get("name")
        if custom:
            return custom, "custom"
        if _MAC_RE.match(dev):
            lease = read_leases().get(dev)
            if lease:
                return lease, "lease"
        ip = self.ip_of(dev)
        if ip and allow_lookup and self.netinfo.gateway:
            cached = self._ptr_cache.get(ip)
            if cached and cached[1] > time.time():
                if cached[0]:
                    return cached[0], "router"
            else:
                name = ptr_lookup(self.netinfo.gateway, ip)
                self._ptr_cache[ip] = (name, time.time() + 3600)
                if name:
                    return name, "router"
        return None, None

    async def sweep(self):
        """Wake up the neighbour table for the local /24 so devices that have
        never used Bouncer show up too (they would be 'not protected')."""
        net = self.netinfo.ipv4_network
        if not net or net.num_addresses > 1024:
            return
        loop = asyncio.get_running_loop()

        def _poke():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for host in net.hosts():
                    try:
                        s.sendto(b"", (str(host), 9))
                    except OSError:
                        pass
            finally:
                s.close()
        await loop.run_in_executor(None, _poke)
        await asyncio.sleep(3)
        self._refresh_macs(force=True)
        now = time.time()
        skip = {self.netinfo.gateway} | set(self.netinfo.own_ips)
        for ip, mac in self._ip_to_mac.items():
            if ip in skip or ":" in ip:
                continue
            self.seen_on_network[mac] = now
            self.device_ips.setdefault(mac, ip)
