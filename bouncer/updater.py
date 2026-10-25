"""Automatic, signed software updates with rollback.

Every night each Bouncer asks GitHub for the newest release of the owner's
repository. A release is installed only if its signature matches the
owner's public key, which is built into the SD card image. After switching,
Bouncer checks itself; if anything fails it switches back to the previous
version and never tries that version again."""

import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from . import __version__, paths

log = logging.getLogger("bouncer.updater")
USER_AGENT = f"Bouncer/{__version__}"


def parse_version(v: str):
    v = v.strip().lstrip("vV")
    parts = []
    for p in v.split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple((parts + [0, 0, 0])[:3])


def load_state():
    try:
        return json.loads(paths.UPDATE_STATE_FILE.read_text())
    except (OSError, ValueError):
        return {"failed": [], "last_check": 0, "last_result": None, "history": []}


def save_state(state):
    paths.UPDATE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = paths.UPDATE_STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    os.replace(tmp, paths.UPDATE_STATE_FILE)


def load_config():
    try:
        return json.loads(paths.UPDATE_CONFIG_FILE.read_text())
    except (OSError, ValueError):
        return {}


def verify_signature(data: bytes, signature_b64: str, pubkey_path: Path = None) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        raw = base64.b64decode(Path(pubkey_path or paths.RELEASE_PUBKEY_FILE).read_text().strip())
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(base64.b64decode(signature_b64.strip()), data)
        return True
    except (InvalidSignature, ValueError, OSError):
        return False


def _get(url, accept="application/octet-stream", timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_release(repo):
    data = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest",
                           accept="application/vnd.github+json"))
    assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
    return data.get("tag_name", ""), assets


def safe_extract(tar_bytes: bytes, dest: Path):
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(tar_bytes)
        tmp.flush()
        with tarfile.open(tmp.name, "r:gz") as tf:
            for m in tf.getmembers():
                if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                    raise ValueError(f"unsafe path in release: {m.name}")
            tf.extractall(dest, filter="data")


def current_release_dir():
    try:
        return paths.CURRENT_LINK.resolve(strict=True)
    except OSError:
        return None


def switch_to(release_dir: Path):
    tmp_link = paths.INSTALL_DIR / ".current.tmp"
    try:
        tmp_link.unlink()
    except FileNotFoundError:
        pass
    tmp_link.symlink_to(release_dir)
    os.replace(tmp_link, paths.CURRENT_LINK)


def health_check(timeout=90) -> bool:
    """Is the freshly started Bouncer answering DNS and the dashboard?"""
    from dnslib import DNSRecord
    end = time.time() + timeout
    while time.time() < end:
        try:
            q = DNSRecord.question("protected.bouncer.home.arpa", "A")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(q.pack(), ("127.0.0.1", paths.DNS_PORT))
            data, _ = s.recvfrom(1500)
            s.close()
            ok_dns = DNSRecord.parse(data).header.rcode == 0   # NOERROR for Bouncer's own name
            with urllib.request.urlopen(f"http://127.0.0.1:{paths.WEB_PORT}/api/health",
                                        timeout=3) as resp:
                ok_web = json.loads(resp.read()).get("ok") is True
            if ok_dns and ok_web:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def _restart_service():
    subprocess.run(["systemctl", "restart", "bouncer.service"], timeout=60)


def run_update(force=False, restart=_restart_service, check=health_check, fetch=None):
    """Check for a new release and install it. Returns a short result string."""
    fetch = fetch or (lambda repo: latest_release(repo))
    state = load_state()
    state["last_check"] = int(time.time())
    cfg = load_config()
    repo = cfg.get("repo")
    if not repo:
        state["last_result"] = "no_repo"
        save_state(state)
        return "no_repo"
    try:
        tag, assets = fetch(repo)
    except Exception as exc:
        log.warning("update check failed: %s", exc)
        state["last_result"] = "check_failed"
        save_state(state)
        return "check_failed"
    version = tag.lstrip("vV")
    if not version or parse_version(version) <= parse_version(__version__):
        state["last_result"] = "up_to_date"
        save_state(state)
        return "up_to_date"
    if version in state.get("failed", []) and not force:
        state["last_result"] = "skipped_failed"
        save_state(state)
        return "skipped_failed"
    tar_name = f"bouncer-{version}.tar.gz"
    if tar_name not in assets or tar_name + ".sig" not in assets:
        state["last_result"] = "incomplete_release"
        save_state(state)
        return "incomplete_release"
    try:
        tar_bytes = _get(assets[tar_name], timeout=120) if isinstance(assets[tar_name], str) \
            else assets[tar_name]()
        sig = _get(assets[tar_name + ".sig"]).decode() if isinstance(assets[tar_name + ".sig"], str) \
            else assets[tar_name + ".sig"]()
    except Exception as exc:
        state["last_result"] = "download_failed"
        save_state(state)
        log.warning("download failed: %s", exc)
        return "download_failed"
    if not verify_signature(tar_bytes, sig):
        state["last_result"] = "bad_signature"
        state.setdefault("failed", []).append(version)
        save_state(state)
        log.error("release %s has an invalid signature, refused", version)
        return "bad_signature"

    paths.RELEASES_DIR.mkdir(parents=True, exist_ok=True)
    target = paths.RELEASES_DIR / version
    staging = paths.RELEASES_DIR / (version + ".staging")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    try:
        safe_extract(tar_bytes, staging)
        if not (staging / "bouncer" / "__init__.py").exists() or \
                (staging / "VERSION").read_text().strip() != version:
            raise ValueError("release content does not match its version")
        # The new version must at least be able to start its own updater.
        res = subprocess.run([sys.executable, "-c", "import bouncer.updater, bouncer.web"],
                             cwd=staging, capture_output=True, timeout=60)
        if res.returncode != 0:
            raise ValueError("new version does not start: " + res.stderr.decode()[-300:])
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        state["last_result"] = "invalid_release"
        state.setdefault("failed", []).append(version)
        save_state(state)
        log.error("release %s invalid: %s", version, exc)
        return "invalid_release"
    shutil.rmtree(target, ignore_errors=True)
    os.replace(staging, target)

    previous = current_release_dir()
    switch_to(target)
    restart()
    if check():
        state["last_result"] = "updated"
        state.setdefault("history", []).append({"version": version, "at": int(time.time())})
        state["history"] = state["history"][-10:]
        save_state(state)
        _cleanup(keep={target, previous})
        log.info("updated to %s", version)
        return "updated"
    # Roll back
    if previous:
        switch_to(previous)
        restart()
    state["last_result"] = "rolled_back"
    state.setdefault("failed", []).append(version)
    save_state(state)
    log.error("version %s failed its health check, rolled back", version)
    return "rolled_back"


def _cleanup(keep):
    keep = {Path(k).resolve() for k in keep if k}
    for d in paths.RELEASES_DIR.iterdir():
        if d.is_dir() and d.resolve() not in keep:
            shutil.rmtree(d, ignore_errors=True)


def run_cli(force=False):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = run_update(force=force)
    print(result)
    return 0 if result in ("updated", "up_to_date", "no_repo") else 1
