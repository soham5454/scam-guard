"""Tiny SQLite log used for the family weekly digest.

Only the verdict and category are stored - never the message text.
"""
from __future__ import annotations

import os
import sqlite3
import time
from collections import Counter
from contextlib import closing

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scamguard.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    ts REAL NOT NULL,
    is_scam INTEGER NOT NULL,
    category TEXT,
    lang TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_user_ts ON scans (user_id, ts);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("SCAMGUARD_DB") or _DEFAULT_PATH)
    conn.executescript(_SCHEMA)
    return conn


def log_scan(user_id: str, is_scam: bool, category: str | None, lang: str) -> None:
    with closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO scans (user_id, ts, is_scam, category, lang) VALUES (?, ?, ?, ?, ?)",
            (user_id, time.time(), int(is_scam), category, lang),
        )


def stats(user_id: str, days: int) -> tuple[int, int, Counter]:
    """Return (total scans, scams flagged, scams per category) for the last `days` days."""
    since = time.time() - days * 86400
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT is_scam, category FROM scans WHERE user_id = ? AND ts >= ?",
            (user_id, since),
        ).fetchall()
    by_category = Counter(cat for flagged, cat in rows if flagged and cat)
    return len(rows), sum(1 for flagged, _ in rows if flagged), by_category
