"""The dashboard's web server and its JSON API."""

import asyncio
import io
import ipaddress
import json
import logging
import platform
import subprocess
import time
import zipfile
from datetime import datetime, timedelta

from aiohttp import web

from . import __version__, auth as auth_mod, blocklists as bl, paths, speedcheck, updater

log = logging.getLogger("bouncer.web")
COOKIE = "bouncer_session"
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00"
       b"\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
DEFAULT_KB_PER_BLOCK = 50
LOCAL_HOSTS = {"localhost", "bouncer", "bouncer.local", "bouncer.home.arpa", "bouncer.fritz.box",
               "bouncer.lan", "bouncer.home", "bouncer.localdomain", "bouncer.box",
               "protected.bouncer.home.arpa"}


def _client_ip(request):
    ip = request.remote or ""
    return ip[7:] if ip.startswith("::ffff:") else ip


def host_allowed(host: str) -> bool:
    """Only answer to Bouncer's own names and to IP addresses. This stops
    websites from reaching the dashboard through a DNS trick (rebinding)."""
    if not host:
        return False
    if host.startswith("["):
        host = host[1:host.find("]")]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return host in LOCAL_HOSTS


@web.middleware
async def security_middleware(request, handler):
    if not host_allowed(request.host):
        return web.Response(status=403, text="Forbidden")
    if request.method == "POST" and request.headers.get("X-Bouncer") != "1":
        return web.Response(status=403, text="Missing header")
    resp = await handler(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    if request.path == "/" or request.path.endswith(".html"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: http://protected.bouncer.home.arpa; "
            "style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        resp.headers["Cache-Control"] = "no-cache"
    return resp


class Api:
    def __init__(self, bouncer):
        self.b = bouncer
        self.speed_task = None

    # ---- helpers ---------------------------------------------------------
    def _token(self, request):
        return request.cookies.get(COOKIE)

    def _logged_in(self, request):
        return self.b.auth.valid_session(self._token(request))

    def _require(self, request, allow_change=False):
        if not self._logged_in(request):
            raise web.HTTPUnauthorized(text=json.dumps({"error": "login"}),
                                       content_type="application/json")
        if self.b.auth.must_change and not allow_change:
            raise web.HTTPForbidden(text=json.dumps({"error": "change_pin"}),
                                    content_type="application/json")

    @staticmethod
    async def _json(request):
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _with_cookie(self, resp, token):
        resp.set_cookie(COOKIE, token, max_age=auth_mod.SESSION_DAYS * 86400, httponly=True,
                        samesite="Strict", path="/")
        return resp

    # ---- auth ------------------------------------------------------------
    async def state(self, request):
        a = self.b.auth
        client = _client_ip(request)
        if not a.has_pin:
            step = "need_pin"
        elif not self._logged_in(request):
            step = "login"
        elif a.must_change:
            step = "change"
        else:
            step = "ok"
        return web.json_response({"step": step, "locked_until": a.locked_until(client),
                                  "tries_left": a.tries_left(client), "version": __version__,
                                  "location": self.b.settings.get("location")})

    async def login(self, request):
        data = await self._json(request)
        ok, reason = self.b.auth.login(str(data.get("pin", "")), _client_ip(request))
        if not ok:
            client = _client_ip(request)
            return web.json_response({"ok": False, "reason": reason,
                                      "locked_until": self.b.auth.locked_until(client),
                                      "tries_left": self.b.auth.tries_left(client)}, status=401)
        resp = web.json_response({"ok": True, "change": self.b.auth.must_change})
        return self._with_cookie(resp, self.b.auth.create_session())

    async def logout(self, request):
        self.b.auth.end_session(self._token(request))
        resp = web.json_response({"ok": True})
        resp.del_cookie(COOKIE, path="/")
        return resp

    async def setup_pin(self, request):
        """First PIN (when none was delivered) or the forced change at first login."""
        a = self.b.auth
        if a.has_pin:
            self._require(request, allow_change=True)
            if not a.must_change:
                raise web.HTTPForbidden()
        data = await self._json(request)
        pin = str(data.get("pin", ""))
        if not auth_mod.valid_pin(pin):
            return web.json_response({"ok": False, "reason": "invalid"}, status=400)
        if auth_mod.weak_pin(pin):
            return web.json_response({"ok": False, "reason": "weak"}, status=400)
        pin_before = a.settings.get("pin")
        if pin_before and auth_mod.check_secret(pin, pin_before):
            return web.json_response({"ok": False, "reason": "same"}, status=400)
        a.set_pin(pin, must_change=False)
        code = a.new_recovery()
        token = self._token(request) if self._logged_in(request) else a.create_session()
        return self._with_cookie(web.json_response({"ok": True, "recovery": code}), token)

    async def change_pin(self, request):
        self._require(request)
        data = await self._json(request)
        a = self.b.auth
        ok, reason = a.login(str(data.get("old", "")), _client_ip(request))
        if not ok:
            return web.json_response({"ok": False, "reason": reason}, status=400)
        pin = str(data.get("pin", ""))
        if not auth_mod.valid_pin(pin) or auth_mod.weak_pin(pin):
            return web.json_response({"ok": False, "reason": "weak" if auth_mod.valid_pin(pin)
                                      else "invalid"}, status=400)
        a.set_pin(pin)
        return web.json_response({"ok": True})

    async def new_recovery(self, request):
        self._require(request)
        return web.json_response({"ok": True, "recovery": self.b.auth.new_recovery()})

    async def recover(self, request):
        data = await self._json(request)
        a = self.b.auth
        client = _client_ip(request)
        ok, reason = a.recover(str(data.get("code", "")), client)
        if not ok:
            return web.json_response({"ok": False, "reason": reason,
                                      "locked_until": a.locked_until(client)}, status=401)
        pin = str(data.get("pin", ""))
        if not auth_mod.valid_pin(pin) or auth_mod.weak_pin(pin):
            return web.json_response({"ok": False, "reason": "weak" if auth_mod.valid_pin(pin)
                                      else "invalid"}, status=400)
        a.set_pin(pin)
        code = a.new_recovery()
        a.end_all_sessions()
        return self._with_cookie(web.json_response({"ok": True, "recovery": code}),
                                 a.create_session())

    # ---- dashboard data -----------------------------------------------------
    async def summary(self, request):
        self._require(request)
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, self._build_summary, _client_ip(request))
        return web.json_response(data)

    def _devices(self, this_ip, proxied):
        b = self.b
        per_dev = b.stats.per_device(86400)
        now = time.time()
        skip = set(b.net.own_ips) | {"127.0.0.1", "::1"}
        ids = set(per_dev) | {d for d, t in b.devices.seen_on_network.items() if now - t < 1800}
        this_dev = b.devices.device_id(this_ip) if this_ip else None
        out = []
        for dev in ids:
            ip = b.devices.ip_of(dev)
            if dev in skip or ip in skip:
                continue
            is_gateway = ip == b.net.gateway
            if is_gateway and not proxied:
                continue
            stats = per_dev.get(dev)
            name, source = b.devices.name_of(dev)
            protected = None
            if stats:
                protected = True
            elif dev in b.devices.seen_on_network:
                protected = False
            out.append({
                "id": dev, "name": name, "name_source": source, "ip": ip,
                "requests": stats["requests"] if stats else 0,
                "blocked": stats["blocked"] if stats else 0,
                "last_seen": stats["last_seen"] if stats else None,
                "protected": protected, "this": dev == this_dev, "router": is_gateway,
            })
        out.sort(key=lambda d: (not d["this"], d["protected"] is False, -d["requests"]))
        return out

    def _network_status(self, devices):
        nc = self.b.netcheck or {}
        proxied = self.b.resolver.gateway_share() > 0.8
        issues = []
        v4, v6 = nc.get("ipv4", "unknown"), nc.get("ipv6", "unknown")
        clients = [d for d in devices if d["protected"] and not d["router"]]
        level = "green"
        if proxied:
            issues.append("router_forwards")
        if v4 == "other" and not proxied:
            if len(clients) < 2:
                level = "red"
                issues.append("router_not_set")
            else:
                issues.append("router_other_but_used")
        elif v4 == "partial":
            issues.append("router_secondary")
        elif v4 in ("unknown", "no_network") and len(clients) < 1:
            level = "red" if v4 == "no_network" else "orange"
            issues.append("not_seen_yet")
        if v6 in ("other", "partial", "not_announced"):
            issues.append("ipv6_bypass")
        unprotected = [d for d in devices if d["protected"] is False]
        if unprotected:
            issues.append("devices_unprotected")
        if issues and level == "green":
            level = "orange"
        return {"level": level, "issues": issues, "ipv4": v4, "ipv6": v6,
                "router": nc.get("router"), "proxied": proxied,
                "unprotected": len(unprotected), "checked": nc.get("checked")}

    def _build_summary(self, this_ip):
        b = self.b
        s = b.settings
        today = b.stats.summary()
        proxied = b.resolver.gateway_share() > 0.8
        devices = self._devices(this_ip, proxied)
        names = {d["id"]: d["name"] for d in devices}
        speed = s.get("speed") or {}
        kb = speed.get("avg_blocked_kb") or DEFAULT_KB_PER_BLOCK
        recent = []
        for ts, dev, cat in list(b.stats.recent)[-30:][::-1]:
            name = names[dev] if dev in names else b.devices.name_of(dev, False)[0]
            recent.append({"ts": ts, "device": name, "ip": b.devices.ip_of(dev) or dev,
                           "cat": bl.CATEGORY_NAMES.get(cat)})
        byc = today["by_category"]
        upd = updater.load_state()
        return {
            "version": __version__,
            "uptime": int(time.time() - b.started),
            "paused_until": s.get("paused_until") if b.resolver.paused else 0,
            "network": self._network_status(devices),
            "today": {**today, "data_saved_mb": round(today["blocked"] * kb / 1000, 1)},
            "chart": {"hours": b.stats.hourly(), "days": b.stats.daily()},
            "protection": {**s.get("protection"),
                           "counts": {"ads": byc.get("1", 0) + byc.get("4", 0),
                                      "scam": byc.get("2", 0), "family": byc.get("3", 0)}},
            "devices": devices,
            "recent": recent,
            "speed": speed or None,
            "speed_running": bool(self.speed_task and not self.speed_task.done()),
            "addresses": {"ipv4": b.net.ipv4, "ipv6": b.net.best_ipv6(),
                          "gateway": b.net.gateway},
            "system": {
                "update": {"last_check": upd.get("last_check"), "last_result": upd.get("last_result"),
                           "failed": upd.get("failed", [])[-3:]},
                "lists": {"counts": b.lists.counts(), "updated": (b.lists.meta.get("ads") or {})
                          .get("updated"), "ok": b.lists.meta.get("last_attempt_ok"),
                          "updating": b.lists_updating},
                "upstream": b.upstreams.last_mode,
                "address_mode": bool(s.get("address_mode", {}).get("enabled")),
                "fixes": len(s.get("fixes", [])),
                "custom_allow": len(s.get("allow", [])), "custom_block": len(s.get("block", [])),
            },
        }

    # ---- actions --------------------------------------------------------------
    async def protection(self, request):
        self._require(request)
        data = await self._json(request)
        prot = self.b.settings.get("protection")
        for key in ("ads", "scam", "family"):
            if key in data:
                prot[key] = bool(data[key])
        self.b.settings.update(protection=prot)
        return web.json_response({"ok": True, "protection": prot})

    async def pause(self, request):
        self._require(request)
        data = await self._json(request)
        mode = data.get("mode")
        now = datetime.now()
        if mode == "resume":
            until = 0
        elif mode == "tomorrow":
            until = (now + timedelta(days=1)).replace(hour=6, minute=0, second=0).timestamp()
        else:
            minutes = int(data.get("minutes", 5))
            if minutes not in (5, 30, 60):
                return web.json_response({"ok": False}, status=400)
            until = time.time() + minutes * 60
        self.b.settings.update(paused_until=int(until))
        return web.json_response({"ok": True, "paused_until": int(until)})

    async def rename(self, request):
        self._require(request)
        data = await self._json(request)
        dev = str(data.get("id", ""))[:64]
        name = str(data.get("name", "")).strip()[:40]
        devices = self.b.settings.get("devices", {})
        if name:
            devices[dev] = {"name": name}
        else:
            devices.pop(dev, None)
        self.b.settings.update(devices=devices)
        return web.json_response({"ok": True})

    async def fix(self, request):
        self._require(request)
        data = await self._json(request)
        dev = str(data.get("id", ""))
        count = self.b.resolver.fix_device(dev)
        return web.json_response({"ok": True, "count": count})

    async def reset_fixes(self, request):
        self._require(request)
        self.b.settings.update(fixes=[])
        return web.json_response({"ok": True})

    async def speed_start(self, request):
        self._require(request)
        if self.speed_task and not self.speed_task.done():
            return web.json_response({"ok": True, "running": True})

        async def _run():
            try:
                res = await speedcheck.run(self.b.resolver, self.b.lists)
                if res.get("ok"):
                    self.b.settings.update(speed=res)
            except Exception:
                log.exception("speed check failed")
        self.speed_task = asyncio.ensure_future(_run())
        return web.json_response({"ok": True, "running": True})

    async def update_lists(self, request):
        self._require(request)
        asyncio.ensure_future(self.b.update_lists_now())
        return web.json_response({"ok": True})

    async def address_mode(self, request):
        self._require(request)
        data = await self._json(request)
        try:
            res = await self.b.set_address_mode(bool(data.get("enabled")))
        except Exception as exc:
            log.exception("address mode change failed")
            return web.json_response({"ok": False, "reason": "error", "detail": str(exc)[:200]},
                                     status=500)
        return web.json_response(res, status=200 if res.get("ok") else 409)

    async def custom_rule(self, request):
        """Advanced: add or remove a domain on the household's own lists."""
        self._require(request)
        data = await self._json(request)
        kind = data.get("list")
        domain = bl.normalize(str(data.get("domain", "")))
        if kind not in ("allow", "block") or "." not in domain or len(domain) > 253:
            return web.json_response({"ok": False}, status=400)
        items = self.b.settings.get(kind, [])
        if data.get("remove"):
            items = [d for d in items if d != domain]
        elif domain not in items:
            items.append(domain)
        self.b.settings.update(**{kind: items})
        return web.json_response({"ok": True, "items": items})

    async def custom_rules(self, request):
        self._require(request)
        return web.json_response({"allow": self.b.settings.get("allow", []),
                                  "block": self.b.settings.get("block", [])})

    async def clear_history(self, request):
        self._require(request)
        self.b.stats.clear()
        return web.json_response({"ok": True})

    # ---- backup / restore / diagnostics -------------------------------------
    async def backup(self, request):
        self._require(request)
        data = self.b.settings.snapshot()
        data["_bouncer_backup"] = {"version": __version__, "created": int(time.time())}
        name = f"bouncer-backup-{datetime.now():%Y-%m-%d}.json"
        return web.Response(body=json.dumps(data, indent=1), content_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="{name}"'})

    async def restore(self, request):
        self._require(request)
        data = await self._json(request)
        if "_bouncer_backup" not in data or not isinstance(data.get("protection"), dict):
            return web.json_response({"ok": False, "reason": "not_backup"}, status=400)
        data.pop("_bouncer_backup", None)
        # Keep this Bouncer's own network settings; restore everything else.
        data["address_mode"] = self.b.settings.get("address_mode")
        if not data.get("pin"):
            data["pin"] = self.b.settings.get("pin")
        self.b.settings.replace_all(data)
        return web.json_response({"ok": True})

    async def diagnostics(self, request):
        self._require(request)
        loop = asyncio.get_running_loop()
        body = await loop.run_in_executor(None, self._diagnostics_zip)
        name = f"bouncer-diagnostics-{datetime.now():%Y-%m-%d-%H%M}.zip"
        return web.Response(body=body, content_type="application/zip",
                            headers={"Content-Disposition": f'attachment; filename="{name}"'})

    def _diagnostics_zip(self):
        b = self.b

        def cmd(args):
            try:
                return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout
            except Exception as exc:
                return f"(failed: {exc})"
        settings = b.settings.snapshot()
        for secret in ("pin", "recovery"):
            settings[secret] = "(set)" if settings.get(secret) else None
        settings["fixes"] = f"({len(settings.get('fixes', []))} entries, not included)"
        settings["devices"] = f"({len(settings.get('devices', {}))} renamed devices, not included)"
        info = {
            "version": __version__, "time": datetime.now().isoformat(),
            "uptime_s": int(time.time() - b.started), "platform": platform.platform(),
            "python": platform.python_version(),
            "network": {"iface": b.net.iface, "ipv4": b.net.ipv4, "ipv6": b.net.ipv6,
                        "gateway": b.net.gateway},
            "netcheck": b.netcheck, "upstream_mode": b.upstreams.last_mode,
            "lists": b.lists.counts(), "lists_meta": b.lists.meta,
            "cache": {"entries": len(b.resolver.cache.data), "hits": b.resolver.cache.hits,
                      "misses": b.resolver.cache.misses},
            "gateway_share": b.resolver.gateway_share(), "update": updater.load_state(),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("README.txt", "Bouncer diagnostics. Contains no website names, no "
                       "PIN and no device names.\n")
            z.writestr("info.json", json.dumps(info, indent=1, default=str))
            z.writestr("settings.json", json.dumps(settings, indent=1, default=str))
            z.writestr("service-log.txt", cmd(["journalctl", "-u", "bouncer", "-u",
                                               "bouncer-update", "-n", "400", "--no-pager"]))
            z.writestr("system.txt", "\n\n".join([
                cmd(["uptime"]), cmd(["df", "-h", "/"]), cmd(["free", "-m"]),
                cmd(["vcgencmd", "measure_temp"]), cmd(["vcgencmd", "get_throttled"]),
                cmd(["ip", "addr"]), cmd(["ip", "route"]), cmd(["nmcli", "general"]),
                cmd(["systemctl", "--failed", "--no-pager"])]))
        return buf.getvalue()

    async def health(self, request):
        return web.json_response({"ok": True, "version": __version__})

    async def check_gif(self, request):
        return web.Response(body=GIF, content_type="image/gif",
                            headers={"Cache-Control": "no-store",
                                     "Access-Control-Allow-Origin": "*"})


async def index(request):
    return web.FileResponse(paths.STATIC_DIR / "index.html")


def make_app(bouncer):
    api = Api(bouncer)
    app = web.Application(middlewares=[security_middleware], client_max_size=2 * 1024 * 1024)
    r = app.router
    r.add_get("/", index)
    r.add_get("/check.gif", api.check_gif)
    r.add_get("/api/health", api.health)
    r.add_get("/api/state", api.state)
    r.add_post("/api/login", api.login)
    r.add_post("/api/logout", api.logout)
    r.add_post("/api/setup-pin", api.setup_pin)
    r.add_post("/api/change-pin", api.change_pin)
    r.add_post("/api/new-recovery", api.new_recovery)
    r.add_post("/api/recover", api.recover)
    r.add_get("/api/summary", api.summary)
    r.add_post("/api/protection", api.protection)
    r.add_post("/api/pause", api.pause)
    r.add_post("/api/rename", api.rename)
    r.add_post("/api/fix", api.fix)
    r.add_post("/api/reset-fixes", api.reset_fixes)
    r.add_post("/api/speedcheck", api.speed_start)
    r.add_post("/api/update-lists", api.update_lists)
    r.add_post("/api/address-mode", api.address_mode)
    r.add_get("/api/rules", api.custom_rules)
    r.add_post("/api/rules", api.custom_rule)
    r.add_post("/api/clear-history", api.clear_history)
    r.add_get("/api/backup", api.backup)
    r.add_post("/api/restore", api.restore)
    r.add_get("/api/diagnostics", api.diagnostics)
    r.add_static("/static/", paths.STATIC_DIR, show_index=False)
    return app


async def start_web(bouncer, port=80, host=None):
    app = make_app(bouncer)
    runner = web.AppRunner(app, access_log=None)   # no access log: it would contain URLs
    await runner.setup()
    site = web.TCPSite(runner, host, port)          # host None = all IPv4 and IPv6 addresses
    await site.start()
    return runner
