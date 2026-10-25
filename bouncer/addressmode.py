"""Address mode: Bouncer hands out the network addresses itself.

Only for routers that cannot change the DNS server they give to devices
(for example the Orange Livebox). The household first switches off the
router's DHCP server; Bouncer then gives every device an address and tells
it to use Bouncer. Uses dnsmasq with its own DNS part switched off."""

import ipaddress
import os
import random
import socket
import struct
import subprocess
import time
from pathlib import Path

from . import paths

DNSMASQ_CONF = Path(os.environ.get("BOUNCER_DNSMASQ_CONF", "/etc/dnsmasq.d/bouncer.conf"))


def _run(cmd, timeout=20):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def other_dhcp_server_present(iface: str, timeout=4.0) -> bool:
    """Send a DHCP DISCOVER and see whether any other server answers.
    Returns True if one does, False if none, None if the test could not run."""
    try:
        mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        hw = bytes.fromhex(mac.replace(":", ""))
    except OSError:
        return None
    xid = random.getrandbits(32)
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                      b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, hw.ljust(16, b"\0"),
                      b"\0" * 64, b"\0" * 128)
    pkt += b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\x37\x03\x01\x03\x06" + b"\xff"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
        except OSError:
            pass
        s.bind(("0.0.0.0", 68))
        s.settimeout(0.5)
        s.sendto(pkt, ("255.255.255.255", 67))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            if len(data) > 240 and data[0] == 2 and struct.unpack("!I", data[4:8])[0] == xid:
                return True
        return False
    except OSError:
        return None
    finally:
        s.close()


def plan(net) -> dict:
    """Pick sensible addresses from the current network."""
    network = net.ipv4_network
    hosts = list(network.hosts()) if network and network.num_addresses <= 1024 else []
    if not hosts:
        raise ValueError("unsupported network")
    if len(hosts) > 210:
        start, end = hosts[99], hosts[199]
        own = ipaddress.ip_address(net.ipv4)
        if start <= own <= end:          # keep Bouncer's own address out of the range
            start, end = hosts[29], hosts[89]
    else:
        start, end = hosts[len(hosts) // 3], hosts[-2]
    return {"ip": net.ipv4, "prefix": net.ipv4_prefix, "gateway": net.gateway,
            "iface": net.iface, "range_start": str(start), "range_end": str(end)}


def dnsmasq_config(p: dict) -> str:
    netmask = str(ipaddress.ip_network(f"{p['ip']}/{p['prefix']}", strict=False).netmask)
    return "\n".join([
        "# Written by Bouncer (address mode). Do not edit by hand.",
        "port=0",                       # DNS is done by Bouncer itself
        f"interface={p['iface']}",
        "bind-interfaces",
        f"dhcp-range={p['range_start']},{p['range_end']},{netmask},12h",
        f"dhcp-option=option:router,{p['gateway']}",
        f"dhcp-option=option:dns-server,{p['ip']}",
        "dhcp-authoritative",
        f"dhcp-leasefile={paths.LEASES_FILE}",
        "",
    ])


def _active_connection(iface):
    out = _run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"]).stdout
    for line in out.splitlines():
        name, _, dev = line.rpartition(":")
        if dev == iface:
            return name
    return None


def enable(p: dict):
    con = _active_connection(p["iface"])
    if not con:
        raise RuntimeError("no active network connection")
    # 1. Fixed address for Bouncer itself (a DHCP server cannot ask itself for one).
    _run(["nmcli", "connection", "modify", con, "ipv4.method", "manual",
          "ipv4.addresses", f"{p['ip']}/{p['prefix']}", "ipv4.gateway", p["gateway"],
          "ipv4.dns", "127.0.0.1", "ipv4.ignore-auto-dns", "yes"])
    _run(["nmcli", "connection", "up", con], timeout=60)
    # 2. Start handing out addresses.
    DNSMASQ_CONF.parent.mkdir(parents=True, exist_ok=True)
    DNSMASQ_CONF.write_text(dnsmasq_config(p))
    _run(["systemctl", "enable", "dnsmasq"])
    res = _run(["systemctl", "restart", "dnsmasq"])
    if res.returncode != 0:
        raise RuntimeError("dnsmasq did not start: " + res.stderr[-300:])


def disable(iface: str):
    try:
        DNSMASQ_CONF.unlink()
    except FileNotFoundError:
        pass
    _run(["systemctl", "disable", "--now", "dnsmasq"])
    con = _active_connection(iface)
    if con:
        _run(["nmcli", "connection", "modify", con, "ipv4.method", "auto",
              "ipv4.addresses", "", "ipv4.gateway", ""])
        _run(["nmcli", "connection", "up", con], timeout=60)
