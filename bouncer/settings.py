"""Persistent settings, stored as one JSON file.

Writes are atomic (write to a temp file, then rename) so a power cut never
leaves a half-written file behind."""

import copy
import json
import os
import threading
from pathlib import Path

from . import paths

DEFAULT_UPSTREAMS = [
    {"ip": "9.9.9.9", "tls_name": "dns.quad9.net", "label": "Quad9"},
    {"ip": "149.112.112.112", "tls_name": "dns.quad9.net", "label": "Quad9"},
    {"ip": "1.1.1.1", "tls_name": "cloudflare-dns.com", "label": "Cloudflare"},
    {"ip": "1.0.0.1", "tls_name": "cloudflare-dns.com", "label": "Cloudflare"},
]

DEFAULTS = {
    "schema": 1,
    "protection": {"ads": True, "scam": True, "family": False},
    "paused_until": 0,
    "pin": None,            # {"salt": hex, "hash": hex, "must_change": bool}
    "recovery": None,       # {"salt": hex, "hash": hex}
    "devices": {},          # device id -> {"name": str}
    "allow": [],            # domains always allowed (custom)
    "block": [],            # domains always blocked (custom)
    "fixes": [],            # domains allowed through "Fix a website" (never shown)
    "upstreams": DEFAULT_UPSTREAMS,
    "encrypted_upstream": True,
    "address_mode": {"enabled": False},
    "location": {"lat": 49.61, "lon": 6.13},   # Luxembourg, for sunset dark mode
    "speed": None,          # last speed check result
    "history_days": 7,
}


def _merge(defaults, data):
    out = copy.deepcopy(defaults)
    for key, value in (data or {}).items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict) \
                and key not in ("devices",):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


class Settings:
    def __init__(self, path: Path = None):
        self.path = Path(path or paths.SETTINGS_FILE)
        self._lock = threading.RLock()
        self._data = self._load()
        self._listeners = []

    def _load(self):
        try:
            with open(self.path) as f:
                return _merge(DEFAULTS, json.load(f))
        except FileNotFoundError:
            return copy.deepcopy(DEFAULTS)
        except (OSError, ValueError):
            # A damaged file: keep a copy for diagnostics and start from defaults.
            try:
                os.replace(self.path, str(self.path) + ".damaged")
            except OSError:
                pass
            return copy.deepcopy(DEFAULTS)

    def get(self, key, default=None):
        with self._lock:
            return copy.deepcopy(self._data.get(key, default))

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._data)

    def update(self, **changes):
        with self._lock:
            for key, value in changes.items():
                self._data[key] = copy.deepcopy(value)
            self._save()
        for cb in list(self._listeners):
            cb(set(changes))

    def replace_all(self, data):
        with self._lock:
            self._data = _merge(DEFAULTS, data)
            self._save()
        for cb in list(self._listeners):
            cb(set(DEFAULTS))

    def on_change(self, callback):
        self._listeners.append(callback)

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
