"""Wires everything together and runs the background jobs."""

import asyncio
import logging
import signal
import time

from . import addressmode, auth as auth_mod, paths
from .blocklists import Blocklists, update_lists
from .devices import DeviceTracker
from .dnsserver import Resolver, start_servers
from .netinfo import NetInfo, router_check
from .settings import Settings
from .stats import Stats
from .upstream import Upstreams

log = logging.getLogger("bouncer")


class Bouncer:
    def __init__(self, settings=None, lists=None, stats=None, upstreams=None, netinfo=None,
                 ssl_context=None, dot_port=853, udp_port=53):
        paths.ensure_dirs()
        self.started = time.time()
        self.settings = settings or Settings()
        self.net = netinfo or NetInfo().refresh()
        self.lists = lists or Blocklists()
        if lists is None:
            self.lists.load()
        self.stats = stats or Stats(retention_days=self.settings.get("history_days", 7))
        self.upstreams = upstreams or Upstreams(self.settings.get("upstreams"),
                                                encrypted=self.settings.get("encrypted_upstream",
                                                                            True),
                                                ssl_context=ssl_context, dot_port=dot_port,
                                                udp_port=udp_port)
        self.devices = DeviceTracker(self.settings, self.net)
        self.resolver = Resolver(self.settings, self.lists, self.stats, self.upstreams, self.net,
                                 self.devices)
        self.auth = auth_mod.Auth(self.settings)
        self.netcheck = {}
        self.speed_task = None
        self.speed_running = False
        self.lists_updating = False
        self._tasks = []

    # ---- background jobs ----------------------------------------------------
    async def _every(self, seconds, func, first_delay=0):
        await asyncio.sleep(first_delay)
        while True:
            try:
                res = func()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                log.exception("background job %s failed", getattr(func, "__name__", func))
            await asyncio.sleep(seconds)

    async def refresh_network(self):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.net.refresh)
        am = self.settings.get("address_mode", {}).get("enabled", False)
        self.netcheck = await loop.run_in_executor(None, router_check, self.net, am)

    async def refresh_lists(self):
        """Weekly list update (also runs at start if lists are missing)."""
        meta = self.lists.meta
        age = time.time() - (meta.get("last_attempt") or 0)
        if self.lists.total_ads() and age < 7 * 86400 and \
                (meta.get("last_attempt_ok", True) or age < 6 * 3600):
            return
        await self.update_lists_now()

    async def update_lists_now(self):
        if self.lists_updating:
            return
        self.lists_updating = True
        try:
            await update_lists()
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.lists.load)
            self.resolver.cache.clear()
        finally:
            self.lists_updating = False

    def _flush(self):
        self.stats.flush()

    def _prune(self):
        self.stats.prune()

    async def _sweep(self):
        await self.devices.sweep()

    def start_background(self):
        self._tasks = [
            asyncio.ensure_future(self._every(30, self._flush, 30)),
            asyncio.ensure_future(self._every(3600, self._prune, 60)),
            asyncio.ensure_future(self._every(300, self.refresh_network, 0)),
            asyncio.ensure_future(self._every(6 * 3600, self.refresh_lists, 20)),
            asyncio.ensure_future(self._every(600, self._sweep, 45)),
        ]

    # ---- address mode ---------------------------------------------------------
    async def set_address_mode(self, enabled: bool):
        loop = asyncio.get_running_loop()
        if enabled:
            other = await loop.run_in_executor(None, addressmode.other_dhcp_server_present,
                                               self.net.iface)
            if other:
                return {"ok": False, "reason": "router_dhcp_on"}
            plan = addressmode.plan(self.net)
            await loop.run_in_executor(None, addressmode.enable, plan)
            self.settings.update(address_mode={"enabled": True, **plan})
        else:
            await loop.run_in_executor(None, addressmode.disable, self.net.iface)
            self.settings.update(address_mode={"enabled": False})
        await self.refresh_network()
        return {"ok": True}

    def shutdown(self):
        for t in self._tasks:
            t.cancel()
        try:
            self.stats.flush()
        except Exception:
            pass


async def serve(dns_port=None, web_port=None):
    from .web import start_web
    b = Bouncer()
    for event in auth_mod.apply_pin_files(b.auth):
        log.info("PIN file: %s", event)
    await start_servers(b.resolver, port=dns_port or paths.DNS_PORT)
    await start_web(b, port=web_port or paths.WEB_PORT)
    b.start_background()
    log.info("Bouncer running (DNS port %s, web port %s)", dns_port or paths.DNS_PORT,
             web_port or paths.WEB_PORT)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    b.shutdown()
