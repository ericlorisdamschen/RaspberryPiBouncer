"""Block lists: download, store and match domains.

A domain on a list blocks itself and all of its subdomains. The household's
own allow list always wins over every block list."""

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from . import paths

log = logging.getLogger("bouncer.lists")

# Categories used everywhere (stats, dashboard, fixes)
ALLOWED, ADS, SCAM, FAMILY, CUSTOM = 0, 1, 2, 3, 4
CATEGORY_NAMES = {ALLOWED: "allowed", ADS: "ads", SCAM: "scam", FAMILY: "family", CUSTOM: "custom"}

_HZ = "hagezi/dns-blocklists"
def _sources(name):
    return [
        f"https://raw.githubusercontent.com/{_HZ}/main/wildcard/{name}",
        f"https://cdn.jsdelivr.net/gh/{_HZ}@latest/wildcard/{name}",
        f"https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/wildcard/{name}",
    ]

# "Balanced" strength. Multi NORMAL is built to rarely break websites.
LISTS = {
    "ads": {"category": ADS, "file": "ads.txt", "urls": _sources("multi-onlydomains.txt"),
            "min_entries": 50000},
    "scam": {"category": SCAM, "file": "scam.txt", "urls": _sources("tif.mini-onlydomains.txt"),
             "min_entries": 20000},
    "fake": {"category": SCAM, "file": "fake.txt", "urls": _sources("fake-onlydomains.txt"),
             "min_entries": 2000},
    "family": {"category": FAMILY, "file": "family.txt", "urls": _sources("nsfw-onlydomains.txt"),
               "min_entries": 20000},
}

# Domains that must never be blocked, or basic things stop working.
NEVER_BLOCK = {
    "localhost", "github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
    "api.github.com", "codeberg.org", "cdn.jsdelivr.net", "deb.debian.org",
    "archive.raspberrypi.com", "security.debian.org", "time.cloudflare.com",
    "connectivitycheck.gstatic.com", "captive.apple.com", "www.msftconnecttest.com",
    "dns.quad9.net", "cloudflare-dns.com",
}


def normalize(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def parse_list(text: str) -> set:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        # Accept plain domains and hosts-file lines ("0.0.0.0 domain")
        parts = line.split()
        d = parts[-1] if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
        d = normalize(d)
        if "." in d and " " not in d and len(d) <= 253:
            out.add(d)
    return out


def _suffixes(name: str):
    """example.ads.com -> example.ads.com, ads.com, com"""
    parts = name.split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


class Blocklists:
    def __init__(self, lists_dir: Path = None):
        self.dir = Path(lists_dir or paths.LISTS_DIR)
        self.sets = {key: set() for key in LISTS}
        self.meta = {}
        self.loaded_at = 0

    # ---- loading -------------------------------------------------------
    def load(self):
        for key, spec in LISTS.items():
            path = self.dir / spec["file"]
            try:
                self.sets[key] = parse_list(path.read_text(errors="replace"))
            except FileNotFoundError:
                self.sets[key] = set()
        try:
            self.meta = json.loads((self.dir / "meta.json").read_text())
        except (OSError, ValueError):
            self.meta = {}
        self.loaded_at = time.time()
        log.info("block lists loaded: %s", {k: len(v) for k, v in self.sets.items()})

    def counts(self):
        return {k: len(v) for k, v in self.sets.items()}

    def total_ads(self):
        return len(self.sets["ads"])

    # ---- matching ------------------------------------------------------
    def classify(self, name: str, protection: dict, allow, block, fixes):
        """Return the category that blocks `name`, or ALLOWED.

        `allow`, `block` and `fixes` are sets of domains (subdomains included)."""
        name = normalize(name)
        if not name:
            return ALLOWED
        sufs = list(_suffixes(name))
        if any(s in allow for s in sufs) or name in NEVER_BLOCK:
            return ALLOWED
        if any(s in block for s in sufs):
            return CUSTOM
        if protection.get("scam", True):
            if any(s in self.sets["scam"] or s in self.sets["fake"] for s in sufs):
                return SCAM
        if protection.get("family", False):
            if any(s in self.sets["family"] for s in sufs):
                return FAMILY
        if protection.get("ads", True):
            if any(s in fixes for s in sufs):
                return ALLOWED
            if any(s in self.sets["ads"] for s in sufs):
                return ADS
        return ALLOWED


async def update_lists(lists_dir: Path = None, fetch=None) -> dict:
    """Download all lists. A list is only replaced when the download worked
    and looks complete, so a failed update keeps the old list active."""
    lists_dir = Path(lists_dir or paths.LISTS_DIR)
    lists_dir.mkdir(parents=True, exist_ok=True)
    fetch = fetch or _http_get
    results = {}
    try:
        meta = json.loads((lists_dir / "meta.json").read_text())
    except (OSError, ValueError):
        meta = {}
    for key, spec in LISTS.items():
        ok = False
        for url in spec["urls"]:
            try:
                text = await fetch(url)
            except Exception as exc:  # network errors of any kind
                log.warning("list %s: %s failed: %s", key, url, exc)
                continue
            domains = parse_list(text)
            if len(domains) < spec["min_entries"]:
                log.warning("list %s from %s too small (%d), ignored", key, url, len(domains))
                continue
            tmp = lists_dir / (spec["file"] + ".tmp")
            tmp.write_text("\n".join(sorted(domains)) + "\n")
            os.replace(tmp, lists_dir / spec["file"])
            meta[key] = {"updated": int(time.time()), "entries": len(domains), "source": url}
            ok = True
            break
        results[key] = ok
    meta["last_attempt"] = int(time.time())
    meta["last_attempt_ok"] = all(results.values())
    (lists_dir / "meta.json").write_text(json.dumps(meta, indent=1))
    return results


async def _http_get(url: str) -> str:
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text(errors="replace")


def run_update_cli():
    logging.basicConfig(level=logging.INFO)
    res = asyncio.run(update_lists())
    print(json.dumps(res))
    return 0 if any(res.values()) else 1
