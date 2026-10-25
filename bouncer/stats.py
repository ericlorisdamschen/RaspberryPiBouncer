"""Statistics, kept for 7 days.

For privacy, no website names are ever written to disk: each request is
stored only as time, device and result (allowed / which kind of block).
Writes are batched every 30 seconds to protect the SD card."""

import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from . import paths


class Stats:
    def __init__(self, db_path: Path = None, retention_days=7):
        self.path = Path(db_path or paths.STATS_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self._buf = []
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self.recent = deque(maxlen=200)     # (ts, device, category) for blocked requests
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._db_lock, self._connect() as c:
            c.execute("CREATE TABLE IF NOT EXISTS events (ts INTEGER NOT NULL, dev TEXT NOT NULL,"
                      " cat INTEGER NOT NULL)")
            c.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")

    # ---- recording -----------------------------------------------------
    def record(self, device: str, category: int, ts: float = None):
        ts = int(ts or time.time())
        with self._lock:
            self._buf.append((ts, device, category))
            if category:
                self.recent.append((ts, device, category))

    def flush(self):
        with self._lock:
            buf, self._buf = self._buf, []
        if not buf:
            return
        with self._db_lock, self._connect() as c:
            c.executemany("INSERT INTO events (ts, dev, cat) VALUES (?, ?, ?)", buf)

    def prune(self, now=None):
        cutoff = int((now or time.time()) - self.retention_days * 86400)
        with self._db_lock, self._connect() as c:
            c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))

    def clear(self):
        with self._lock:
            self._buf.clear()
            self.recent.clear()
        with self._db_lock, self._connect() as c:
            c.execute("DELETE FROM events")

    # ---- reading -------------------------------------------------------
    def _rows(self, sql, args=()):
        self.flush()
        with self._db_lock, self._connect() as c:
            return c.execute(sql, args).fetchall()

    def summary(self, now=None):
        now = now or time.time()
        midnight = int(datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0,
                                                           microsecond=0).timestamp())
        by_cat = dict(self._rows("SELECT cat, COUNT(*) FROM events WHERE ts >= ? GROUP BY cat",
                                 (midnight,)))
        total = sum(by_cat.values())
        blocked = total - by_cat.get(0, 0)
        return {
            "total": total,
            "blocked": blocked,
            "by_category": {str(k): v for k, v in by_cat.items()},
            "share": round(100 * blocked / total) if total else 0,
        }

    def hourly(self, now=None, hours=24):
        """Blocked/allowed per hour for the last `hours` hours (oldest first)."""
        now = int(now or time.time())
        end = now - now % 3600 + 3600
        start = end - hours * 3600
        rows = self._rows("SELECT (ts - ?) / 3600 AS h, cat != 0, COUNT(*) FROM events "
                          "WHERE ts >= ? GROUP BY h, cat != 0", (start, start))
        out = [{"start": start + i * 3600, "blocked": 0, "allowed": 0} for i in range(hours)]
        for h, is_blocked, n in rows:
            if 0 <= h < hours:
                out[h]["blocked" if is_blocked else "allowed"] += n
        return out

    def daily(self, now=None, days=7):
        now = now or time.time()
        today = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
        out = []
        for i in range(days - 1, -1, -1):
            day = today - timedelta(days=i)
            out.append({"start": int(day.timestamp()), "blocked": 0, "allowed": 0})
        start = out[0]["start"]
        rows = self._rows("SELECT ts, cat FROM events WHERE ts >= ?", (start,)) \
            if days <= 7 else []
        bounds = [d["start"] for d in out] + [int((today + timedelta(days=1)).timestamp())]
        for ts, cat in rows:
            for i in range(days):
                if bounds[i] <= ts < bounds[i + 1]:
                    out[i]["blocked" if cat else "allowed"] += 1
                    break
        return out

    def per_device(self, since_seconds=86400, now=None):
        now = now or time.time()
        rows = self._rows("SELECT dev, COUNT(*), SUM(cat != 0), MAX(ts) FROM events "
                          "WHERE ts >= ? GROUP BY dev", (int(now - since_seconds),))
        return {dev: {"requests": n, "blocked": b or 0, "last_seen": last}
                for dev, n, b, last in rows}

    def last_seen_all(self):
        rows = self._rows("SELECT dev, MAX(ts) FROM events GROUP BY dev")
        return dict(rows)
