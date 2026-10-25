"""Facts about the home network and the router check.

The router check answers: "Does the router tell devices to use Bouncer?"
- IPv4: the DNS server the router hands out (NetworkManager keeps the raw
  DHCP answer, even though the Pi itself does not use it).
- IPv6: the DNS server the router announces (router advertisement).
"""

import ipaddress
import json
import logging
import re
import subprocess
import time
import urllib.request

log = logging.getLogger("bouncer.netinfo")


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


class NetInfo:
    def __init__(self):
        self.iface = None
        self.gateway = None
        self.ipv4 = None
        self.ipv4_prefix = None
        self.ipv6 = []              # global and unique-local addresses
        self.ula = None
        self.own_ips = []
        self.ipv4_network = None
        self.updated = 0

    def refresh(self):
        try:
            routes = json.loads(_run(["ip", "-j", "route", "show", "default"]) or "[]")
        except ValueError:
            routes = []
        if routes:
            self.gateway = routes[0].get("gateway")
            self.iface = routes[0].get("dev")
        if self.iface:
            try:
                info = json.loads(_run(["ip", "-j", "addr", "show", "dev", self.iface]) or "[]")
            except ValueError:
                info = []
            v6 = []
            for entry in info:
                for a in entry.get("addr_info", []):
                    if a.get("family") == "inet" and not self.ipv4_or_skip(a):
                        self.ipv4, self.ipv4_prefix = a["local"], a["prefixlen"]
                    elif a.get("family") == "inet6" and a.get("scope") == "global":
                        v6.append(a["local"])
            self.ipv6 = v6
            self.ula = next((a for a in v6 if a.lower().startswith(("fd", "fc"))), None)
        if not self.ipv4:
            # Fallback without the "ip" tool: the address used to reach the internet.
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("9.9.9.9", 53))
                self.ipv4, self.ipv4_prefix = s.getsockname()[0], self.ipv4_prefix or 24
                s.close()
            except OSError:
                pass
        self.own_ips = [ip for ip in [self.ipv4] + self.ipv6 if ip]
        if self.ipv4 and self.ipv4_prefix:
            self.ipv4_network = ipaddress.ip_network(f"{self.ipv4}/{self.ipv4_prefix}",
                                                     strict=False)
        self.updated = time.time()
        return self

    @staticmethod
    def ipv4_or_skip(addr):
        return addr.get("local", "").startswith("169.254.")

    def best_ipv6(self):
        return self.ula or (self.ipv6[0] if self.ipv6 else None)


def dhcp4_dns_servers(iface):
    """DNS servers in the router's DHCP answer, as recorded by NetworkManager."""
    out = _run(["nmcli", "-t", "-f", "DHCP4", "device", "show", iface])
    for line in out.splitlines():
        m = re.search(r"domain_name_servers\s*=\s*(.+)$", line)
        if m:
            return m.group(1).split()
    return None


def ipv6_dns_announced(iface):
    """DNS servers announced by router advertisements (needs the rdisc6 tool)."""
    out = _run(["rdisc6", "-1", "-w", "1500", iface], timeout=6)
    servers = []
    for line in out.splitlines():
        m = re.match(r"\s*Recursive DNS server\s*:\s*(\S+)", line)
        if m:
            servers.append(m.group(1))
    has_ra = "Hop limit" in out or "Prefix" in out
    return servers, has_ra


def detect_router(gateway):
    if not gateway:
        return None
    try:
        with urllib.request.urlopen(f"http://{gateway}/", timeout=3) as resp:
            body = resp.read(200000).decode("utf-8", "replace")
    except Exception:
        return None
    patterns = [("fritzbox", r"FRITZ!Box"), ("livebox", r"Livebox"), ("tplink", r"TP-?Link|tplink"),
                ("asus", r"ASUS"), ("netgear", r"NETGEAR|Orbi"), ("unifi", r"UniFi|Ubiquiti")]
    for key, pat in patterns:
        if re.search(pat, body, re.I):
            return key
    return None


def router_check(net: NetInfo, address_mode=False):
    """Returns a dict the dashboard turns into the network status."""
    res = {"checked": int(time.time()), "ipv4": "unknown", "ipv6": "unknown",
           "ipv4_servers": None, "ipv6_servers": [], "router": None}
    if not net.iface:
        res["ipv4"] = "no_network"
        return res
    res["router"] = detect_router(net.gateway)
    if address_mode:
        res["ipv4"] = "address_mode"
    else:
        servers = dhcp4_dns_servers(net.iface)
        res["ipv4_servers"] = servers
        if servers is None:
            res["ipv4"] = "unknown"
        elif net.ipv4 in servers:
            res["ipv4"] = "ok" if servers[0] == net.ipv4 else "partial"
        else:
            res["ipv4"] = "other"
    v6servers, has_ra = ipv6_dns_announced(net.iface)
    res["ipv6_servers"] = v6servers
    if not net.ipv6 and not has_ra:
        res["ipv6"] = "not_used"
    elif not v6servers:
        res["ipv6"] = "not_announced" if net.ipv6 else "not_used"
    elif all(s in net.ipv6 for s in v6servers):
        res["ipv6"] = "ok"
    elif any(s in net.ipv6 for s in v6servers):
        res["ipv6"] = "partial"
    else:
        res["ipv6"] = "other"
    return res
