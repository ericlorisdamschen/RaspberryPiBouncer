"""Bouncer: a home network ad, tracker and scam blocker for the Raspberry Pi."""

from pathlib import Path


def _read_version() -> str:
    for candidate in (Path(__file__).resolve().parent / "VERSION",
                      Path(__file__).resolve().parent.parent / "VERSION"):
        try:
            return candidate.read_text().strip()
        except OSError:
            continue
    return "0.0.0"


__version__ = _read_version()
