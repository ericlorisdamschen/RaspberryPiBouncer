"""Network setup at boot.

With an Ethernet cable nothing happens here: Bouncer is online right away.
Without a cable (and without a known Wi-Fi), Bouncer opens its own open
Wi-Fi called "Bouncer-Setup". Connecting a phone to it opens a page where
the household picks its home Wi-Fi and types the password."""

import asyncio
import html
import logging
import os
import subprocess
import time
from pathlib import Path

from aiohttp import web

log = logging.getLogger("bouncer.netsetup")

HOTSPOT_NAME = "bouncer-setup"
HOTSPOT_SSID = "Bouncer-Setup"
CAPTIVE_CONF = Path("/etc/NetworkManager/dnsmasq-shared.d/bouncer-captive.conf")
PORTAL_IP = "10.42.0.1"

TEXT = {
    "en": {"title": "Connect Bouncer to your Wi-Fi", "network": "Your Wi-Fi network",
           "password": "Wi-Fi password", "button": "Connect", "other": "Other network (type name)",
           "connecting": "Bouncer is connecting to your Wi-Fi.",
           "next": "In about a minute, this Bouncer-Setup network disappears. Connect your phone "
                   "back to your home Wi-Fi and open http://bouncer.local.",
           "failed": "That did not work. Please check the password and try again.",
           "cable": "Tip: with an Ethernet cable to your router, no Wi-Fi setup is needed."},
    "de": {"title": "Bouncer mit Ihrem WLAN verbinden", "network": "Ihr WLAN",
           "password": "WLAN-Passwort", "button": "Verbinden", "other": "Anderes Netz (Name eingeben)",
           "connecting": "Bouncer verbindet sich mit Ihrem WLAN.",
           "next": "In etwa einer Minute verschwindet das Netz Bouncer-Setup. Verbinden Sie Ihr "
                   "Handy wieder mit Ihrem WLAN und öffnen Sie http://bouncer.local.",
           "failed": "Das hat nicht geklappt. Bitte prüfen Sie das Passwort und versuchen Sie es "
                     "erneut.",
           "cable": "Tipp: Mit einem Netzwerkkabel zum Router ist keine WLAN-Einrichtung nötig."},
    "fr": {"title": "Connecter Bouncer à votre Wi-Fi", "network": "Votre réseau Wi-Fi",
           "password": "Mot de passe Wi-Fi", "button": "Connecter",
           "other": "Autre réseau (saisir le nom)",
           "connecting": "Bouncer se connecte à votre Wi-Fi.",
           "next": "Dans une minute environ, le réseau Bouncer-Setup disparaît. Reconnectez votre "
                   "téléphone à votre Wi-Fi et ouvrez http://bouncer.local.",
           "failed": "Cela n'a pas fonctionné. Vérifiez le mot de passe et réessayez.",
           "cable": "Astuce : avec un câble réseau vers votre box, aucune configuration Wi-Fi "
                    "n'est nécessaire."},
}

CSS = """body{font-family:system-ui,sans-serif;background:#F4F5F2;color:#17201B;margin:0;
padding:24px 16px;line-height:1.45}main{max-width:420px;margin:0 auto}
h1{font-size:24px;margin:0 0 16px}label{display:block;font-weight:600;margin:16px 0 6px}
select,input{width:100%;box-sizing:border-box;height:48px;font-size:17px;padding:0 12px;
border:1px solid #C9D0C7;border-radius:12px;background:#fff}
button{margin-top:20px;width:100%;height:52px;border:0;border-radius:12px;background:#17201B;
color:#fff;font-size:17px;font-weight:700}.err{background:#F9DEDC;color:#8C1D18;padding:12px;
border-radius:12px}.tip{color:#46524B;font-size:15px;margin-top:24px}"""


def _run(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("%s failed: %s", args, exc)
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def online() -> bool:
    """True when there is a route to the internet (the setup hotspot has none)."""
    return bool(_run(["ip", "route", "show", "default"], timeout=5).stdout.strip())


def hotspot_active() -> bool:
    out = _run(["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"], timeout=5).stdout
    return HOTSPOT_NAME in out.splitlines()


def has_wifi() -> bool:
    return Path("/sys/class/net/wlan0").exists()


def scan_networks():
    _run(["nmcli", "device", "wifi", "rescan"], timeout=15)
    time.sleep(4)
    out = _run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"]).stdout
    best = {}
    for line in out.splitlines():
        parts = line.replace("\\:", "\0").split(":")
        if len(parts) < 3:
            continue
        ssid = parts[0].replace("\0", ":")
        if not ssid or ssid == HOTSPOT_SSID:
            continue
        try:
            signal = int(parts[1])
        except ValueError:
            signal = 0
        if signal > best.get(ssid, -1):
            best[ssid] = signal
    return [s for s, _ in sorted(best.items(), key=lambda kv: -kv[1])]


def start_hotspot():
    CAPTIVE_CONF.parent.mkdir(parents=True, exist_ok=True)
    CAPTIVE_CONF.write_text(f"address=/#/{PORTAL_IP}\n")
    _run(["nmcli", "connection", "delete", HOTSPOT_NAME])
    _run(["nmcli", "connection", "add", "type", "wifi", "ifname", "wlan0", "con-name",
          HOTSPOT_NAME, "autoconnect", "no", "ssid", HOTSPOT_SSID,
          "802-11-wireless.mode", "ap", "802-11-wireless.band", "bg",
          "ipv4.method", "shared", "ipv4.addresses", f"{PORTAL_IP}/24", "ipv6.method", "disabled"])
    res = _run(["nmcli", "connection", "up", HOTSPOT_NAME], timeout=45)
    log.info("hotspot started: %s", res.returncode == 0)


def stop_hotspot(remove_captive=True):
    _run(["nmcli", "connection", "down", HOTSPOT_NAME], timeout=20)
    if remove_captive:
        try:
            CAPTIVE_CONF.unlink()
        except FileNotFoundError:
            pass


def connect_wifi(ssid: str, password: str) -> bool:
    stop_hotspot(remove_captive=False)
    time.sleep(2)
    _run(["nmcli", "device", "wifi", "rescan"], timeout=15)
    time.sleep(3)
    args = ["nmcli", "device", "wifi", "connect", ssid, "ifname", "wlan0"]
    if password:
        args += ["password", password]
    res = _run(args, timeout=60)
    if res.returncode == 0:
        for _ in range(20):
            if _run(["ip", "route", "show", "default", "dev", "wlan0"], timeout=5).stdout.strip():
                return True
            time.sleep(1)
    _run(["nmcli", "connection", "delete", ssid])
    return False


def _lang(request):
    al = request.headers.get("Accept-Language", "en").lower()
    for code in ("de", "fr"):
        if al.startswith(code):
            return code
    return "en"


def _page(t, body, lang):
    return web.Response(text=f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
                             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
                             f"<title>Bouncer</title><style>{CSS}</style></head><body><main>"
                             f"<h1>{html.escape(t['title'])}</h1>{body}</main></body></html>",
                        content_type="text/html")


class Portal:
    def __init__(self):
        self.networks = []
        self.failed = False
        self.done = asyncio.Event()
        self.busy = False

    async def form(self, request):
        lang = _lang(request)
        t = TEXT[lang]
        opts = "".join(f"<option>{html.escape(s)}</option>" for s in self.networks)
        err = f"<p class='err'>{html.escape(t['failed'])}</p>" if self.failed else ""
        body = (f"{err}<form method='post' action='/connect'>"
                f"<label for='ssid'>{html.escape(t['network'])}</label>"
                f"<select id='ssid' name='ssid'>{opts}<option value=''>"
                f"{html.escape(t['other'])}</option></select>"
                f"<label for='other'>{html.escape(t['other'])}</label>"
                f"<input id='other' name='other' autocomplete='off'>"
                f"<label for='pw'>{html.escape(t['password'])}</label>"
                f"<input id='pw' name='password' type='password' autocomplete='off'>"
                f"<button type='submit'>{html.escape(t['button'])}</button></form>"
                f"<p class='tip'>{html.escape(t['cable'])}</p>")
        return _page(t, body, lang)

    async def connect(self, request):
        lang = _lang(request)
        t = TEXT[lang]
        data = await request.post()
        ssid = (data.get("other") or "").strip() or (data.get("ssid") or "").strip()
        password = data.get("password") or ""
        if not ssid:
            raise web.HTTPFound("/")
        if not self.busy:
            self.busy = True
            asyncio.ensure_future(self._do_connect(ssid, password))
        body = f"<p><strong>{html.escape(t['connecting'])}</strong></p><p>{html.escape(t['next'])}</p>"
        return _page(t, body, lang)

    async def _do_connect(self, ssid, password):
        await asyncio.sleep(3)   # let the phone receive the page first
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(None, connect_wifi, ssid, password)
        if ok:
            log.info("connected to Wi-Fi")
            stop_hotspot()
            self.done.set()
        else:
            log.info("Wi-Fi connection failed, reopening setup network")
            self.failed = True
            await loop.run_in_executor(None, start_hotspot)
        self.busy = False


async def run_portal(port=80):
    portal = Portal()
    loop = asyncio.get_running_loop()
    portal.networks = await loop.run_in_executor(None, scan_networks)
    await loop.run_in_executor(None, start_hotspot)
    app = web.Application()
    app.router.add_post("/connect", portal.connect)
    app.router.add_route("GET", "/{tail:.*}", portal.form)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    try:
        while not portal.done.is_set():
            # A cable plugged in meanwhile also ends the setup.
            eth = await loop.run_in_executor(None, lambda: _run(
                ["ip", "route", "show", "default", "dev", "eth0"], timeout=5).stdout.strip())
            if eth:
                await loop.run_in_executor(None, stop_hotspot)
                break
            try:
                await asyncio.wait_for(portal.done.wait(), timeout=10)
            except asyncio.TimeoutError:
                pass
    finally:
        await runner.cleanup()


def set_wifi_country(code="LU"):
    if Path("/usr/bin/raspi-config").exists():
        _run(["raspi-config", "nonint", "do_wifi_country", code])
    _run(["rfkill", "unblock", "wifi"])
    _run(["nmcli", "radio", "wifi", "on"])


def main(wait_seconds=90):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    set_wifi_country()
    stop_hotspot()
    end = time.time() + wait_seconds
    while time.time() < end:
        if online():
            log.info("network is up")
            return 0
        time.sleep(3)
    while not online():
        if has_wifi():
            asyncio.run(run_portal())
        else:
            time.sleep(10)
    return 0
