"""Speed check: how much faster pages load with blocking.

Bouncer loads a few popular pages twice: once with everything, once without
the parts that are on the ad list. It measures time and data. This is an
estimate: real browsers also run scripts that load further ads, so the
real gain is usually larger."""

import asyncio
import random
import re
import socket
import time
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

from . import blocklists as bl

TEST_PAGES = [
    "https://www.rtl.lu/",
    "https://www.wort.lu/",
    "https://www.lessentiel.lu/fr/",
    "https://www.spiegel.de/",
    "https://www.lemonde.fr/",
]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0 Safari/537.36")
RES_RE = re.compile(r"""<(?:script|img|iframe|source)[^>]+?src\s*=\s*["']([^"'>]+)["']"""
                    r"""|<link[^>]+?href\s*=\s*["']([^"'>]+)["'][^>]*>""", re.I)
MAX_RESOURCES = 60


class _BouncerResolver(AbstractResolver):
    """Resolves through Bouncer's own engine without blocking (so 'without
    blocking' really loads everything)."""

    def __init__(self, resolver):
        self.resolver = resolver

    async def resolve(self, host, port=0, family=socket.AF_INET):
        from dnslib import DNSRecord, QTYPE
        q = DNSRecord.question(host, "A")
        resp = await self.resolver._resolve(q)
        hosts = [{"hostname": host, "host": str(rr.rdata), "port": port, "family": socket.AF_INET,
                  "proto": 0, "flags": socket.AI_NUMERICHOST}
                 for rr in resp.rr if rr.rtype == QTYPE.A]
        if not hosts:
            raise OSError(f"cannot resolve {host}")
        return hosts

    async def close(self):
        pass


def extract_resources(html, base):
    urls = []
    for m in RES_RE.finditer(html):
        u = m.group(1) or m.group(2)
        if not u or u.startswith(("data:", "javascript:", "#", "mailto:")):
            continue
        full = urljoin(base, u)
        if full.startswith("http") and full not in urls:
            urls.append(full)
        if len(urls) >= MAX_RESOURCES:
            break
    return urls


async def _fetch(session, url, sem):
    async with sem:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.read()
                return len(body)
        except Exception:
            return 0


async def _load(session, page, html, resources, skip_blocked, is_blocked):
    sem = asyncio.Semaphore(6)
    chosen = [u for u in resources if not (skip_blocked and is_blocked(urlparse(u).hostname or ""))]
    start = time.monotonic()
    sizes = await asyncio.gather(*[_fetch(session, u, sem) for u in chosen])
    return time.monotonic() - start, sum(sizes) + len(html), len(resources) - len(chosen)


async def run(resolver, lists, pages=None):
    pages = pages or TEST_PAGES
    timeout = aiohttp.ClientTimeout(total=40)
    connector = aiohttp.TCPConnector(resolver=_BouncerResolver(resolver), limit=12)
    protection = {"ads": True, "scam": False, "family": False}

    def is_blocked(host):
        return lists.classify(host, protection, set(), set(), set()) == bl.ADS

    totals = {"with_s": 0.0, "without_s": 0.0, "with_bytes": 0, "without_bytes": 0,
              "blocked_items": 0, "pages": 0}
    async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                     headers={"User-Agent": UA}) as session:
        for page in pages:
            try:
                async with session.get(page) as resp:
                    html = await resp.text(errors="replace")
                    base = str(resp.url)
            except Exception:
                continue
            resources = extract_resources(html, base)
            order = [False, True]
            random.shuffle(order)
            result = {}
            for skip in order:
                result[skip] = await _load(session, page, html, resources, skip, is_blocked)
            totals["without_s"] += result[False][0]
            totals["without_bytes"] += result[False][1]
            totals["with_s"] += result[True][0]
            totals["with_bytes"] += result[True][1]
            totals["blocked_items"] += result[True][2]
            totals["pages"] += 1
    n = totals["pages"]
    if not n:
        return {"ok": False, "finished": int(time.time())}
    without_s, with_s = totals["without_s"] / n, totals["with_s"] / n
    saved_bytes = max(0, totals["without_bytes"] - totals["with_bytes"])
    return {
        "ok": True,
        "finished": int(time.time()),
        "pages": n,
        "without_s": round(without_s, 2),
        "with_s": round(with_s, 2),
        "faster_pct": max(0, round(100 * (without_s - with_s) / without_s)) if without_s else 0,
        "saved_mb_per_page": round(saved_bytes / n / 1e6, 2),
        "avg_blocked_kb": round(saved_bytes / totals["blocked_items"] / 1000)
        if totals["blocked_items"] else None,
    }
