"""File locations. Every path can be overridden with an environment variable,
which is how the tests and the development server run outside a Raspberry Pi."""

import os
from pathlib import Path

STATE_DIR = Path(os.environ.get("BOUNCER_STATE_DIR", "/var/lib/bouncer"))
ETC_DIR = Path(os.environ.get("BOUNCER_ETC_DIR", "/etc/bouncer"))
BOOT_DIR = Path(os.environ.get("BOUNCER_BOOT_DIR", "/boot/firmware"))
INSTALL_DIR = Path(os.environ.get("BOUNCER_INSTALL_DIR", "/opt/bouncer"))

SETTINGS_FILE = STATE_DIR / "settings.json"
SESSIONS_FILE = STATE_DIR / "sessions.json"
STATS_DB = STATE_DIR / "stats.db"
LISTS_DIR = STATE_DIR / "lists"
UPDATE_STATE_FILE = STATE_DIR / "update-state.json"
NETCHECK_FILE = STATE_DIR / "netcheck.json"
LEASES_FILE = STATE_DIR / "dnsmasq.leases"

UPDATE_CONFIG_FILE = ETC_DIR / "update.json"
RELEASE_PUBKEY_FILE = ETC_DIR / "release.pub"

FIRST_PIN_FILE = BOOT_DIR / "bouncer-pin.txt"
RESET_PIN_FILE = BOOT_DIR / "bouncer-reset-pin.txt"

RELEASES_DIR = INSTALL_DIR / "releases"
CURRENT_LINK = INSTALL_DIR / "current"

STATIC_DIR = Path(__file__).resolve().parent / "static"

DNS_PORT = int(os.environ.get("BOUNCER_DNS_PORT", "53"))
WEB_PORT = int(os.environ.get("BOUNCER_WEB_PORT", "80"))
DEV_MODE = os.environ.get("BOUNCER_DEV", "") == "1"


def ensure_dirs() -> None:
    for d in (STATE_DIR, LISTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
