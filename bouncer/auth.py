"""The 4-digit PIN, the recovery code, sessions and the lockout.

- PINs and recovery codes are stored only as scrypt hashes.
- 5 wrong PINs from one device lock it out for 15 minutes; 20 wrong PINs
  in total lock the dashboard for everyone for 15 minutes.
- The first PIN comes from a text file on the SD card that the owner fills
  in before delivery. Bouncer reads it once and then removes the PIN from
  the file. The household must replace it at first login."""

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

from . import paths

MAX_TRIES = 5
GLOBAL_MAX_TRIES = 20
LOCK_SECONDS = 15 * 60
SESSION_DAYS = 30
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
PIN_RE = re.compile(r"^\d{4}$")


def _hash(secret: str, salt: bytes) -> str:
    return hashlib.scrypt(secret.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


def make_secret(secret: str) -> dict:
    salt = os.urandom(16)
    return {"salt": salt.hex(), "hash": _hash(secret, salt)}


def check_secret(secret: str, stored: dict) -> bool:
    if not stored:
        return False
    try:
        expected = _hash(secret, bytes.fromhex(stored["salt"]))
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(expected, stored["hash"])


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def normalize_recovery(code: str) -> str:
    raw = re.sub(r"[^A-Z0-9]", "", (code or "").upper())
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}" if len(raw) == 12 else ""


def valid_pin(pin: str) -> bool:
    return bool(PIN_RE.match(pin or ""))


def weak_pin(pin: str) -> bool:
    return pin in {"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888",
                   "9999", "1234", "4321", "0123", "9876"}


class Auth:
    def __init__(self, settings, sessions_file: Path = None):
        self.settings = settings
        self.sessions_file = Path(sessions_file or paths.SESSIONS_FILE)
        self.sessions = self._load_sessions()
        self.failures = {}          # client -> [timestamps]
        self.global_failures = []

    # ---- sessions --------------------------------------------------------
    def _load_sessions(self):
        try:
            data = json.loads(self.sessions_file.read_text())
            now = time.time()
            return {k: v for k, v in data.items() if v > now}
        except (OSError, ValueError):
            return {}

    def _save_sessions(self):
        try:
            self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.sessions_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.sessions))
            os.replace(tmp, self.sessions_file)
        except OSError:
            pass

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[hashlib.sha256(token.encode()).hexdigest()] = \
            time.time() + SESSION_DAYS * 86400
        self._save_sessions()
        return token

    def valid_session(self, token: str) -> bool:
        if not token:
            return False
        key = hashlib.sha256(token.encode()).hexdigest()
        exp = self.sessions.get(key)
        return bool(exp and exp > time.time())

    def end_session(self, token: str):
        if token:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
            self._save_sessions()

    def end_all_sessions(self):
        self.sessions = {}
        self._save_sessions()

    # ---- lockout ---------------------------------------------------------
    def locked_until(self, client: str) -> float:
        now = time.time()
        self.global_failures = [t for t in self.global_failures if t > now - LOCK_SECONDS]
        if len(self.global_failures) >= GLOBAL_MAX_TRIES:
            return self.global_failures[0] + LOCK_SECONDS
        tries = [t for t in self.failures.get(client, []) if t > now - LOCK_SECONDS]
        self.failures[client] = tries
        if len(tries) >= MAX_TRIES:
            return tries[0] + LOCK_SECONDS
        return 0

    def _fail(self, client):
        now = time.time()
        self.failures.setdefault(client, []).append(now)
        self.global_failures.append(now)

    def tries_left(self, client):
        now = time.time()
        return max(0, MAX_TRIES - len([t for t in self.failures.get(client, [])
                                       if t > now - LOCK_SECONDS]))

    # ---- PIN ---------------------------------------------------------------
    @property
    def has_pin(self):
        return bool(self.settings.get("pin"))

    @property
    def must_change(self):
        pin = self.settings.get("pin") or {}
        return bool(pin.get("must_change"))

    def login(self, pin: str, client: str):
        """Returns (ok, reason)."""
        if self.locked_until(client):
            return False, "locked"
        if not valid_pin(pin) or not check_secret(pin, self.settings.get("pin")):
            self._fail(client)
            return False, "locked" if self.locked_until(client) else "wrong"
        self.failures.pop(client, None)
        return True, "ok"

    def set_pin(self, pin: str, must_change=False):
        stored = make_secret(pin)
        stored["must_change"] = must_change
        self.settings.update(pin=stored)

    def new_recovery(self) -> str:
        code = new_recovery_code()
        self.settings.update(recovery=make_secret(code))
        return code

    def recover(self, code: str, client: str):
        if self.locked_until(client):
            return False, "locked"
        norm = normalize_recovery(code)
        if not norm or not check_secret(norm, self.settings.get("recovery")):
            self._fail(client)
            return False, "locked" if self.locked_until(client) else "wrong"
        self.failures.pop(client, None)
        return True, "ok"


# ---- PIN files on the SD card ------------------------------------------------

def _read_pin_file(path: Path):
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("PIN") and "=" in line:
            value = line.split("=", 1)[1].strip()
            if valid_pin(value):
                return value
    return None


DONE_NOTE = ("Bouncer has read this file. The PIN has been removed from it for safety.\n"
             "Bouncer hat diese Datei gelesen, die PIN wurde daraus entfernt.\n"
             "Bouncer a lu ce fichier, le code PIN en a été retiré.\n")


def apply_pin_files(auth: Auth, first_file: Path = None, reset_file: Path = None):
    """Called at every start. Returns what happened, for the log."""
    first_file = Path(first_file or paths.FIRST_PIN_FILE)
    reset_file = Path(reset_file or paths.RESET_PIN_FILE)
    events = []
    pin = _read_pin_file(reset_file)
    if pin:
        auth.set_pin(pin, must_change=True)
        auth.settings.update(recovery=None)
        auth.end_all_sessions()
        _neutralize(reset_file)
        events.append("pin_reset")
    if not auth.has_pin:
        pin = _read_pin_file(first_file)
        if pin:
            auth.set_pin(pin, must_change=True)
            _neutralize(first_file)
            events.append("first_pin")
    return events


def _neutralize(path: Path):
    try:
        path.write_text(DONE_NOTE)
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
