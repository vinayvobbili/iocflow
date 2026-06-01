"""Seen-key stores for de-duplicating triggers across polls.

``MemorySeenStore`` (a set) for tests/ephemeral runs; ``SqliteSeenStore`` for a
durable record that survives restarts — the same shape as a real advisory-poll
queue, but dependency-free (stdlib ``sqlite3``).
"""
from __future__ import annotations

import datetime
import os
import sqlite3
import threading
from typing import Optional


class MemorySeenStore:
    """An in-memory set of seen keys. Not durable — resets each process."""

    def __init__(self) -> None:
        self._seen: "set[str]" = set()

    def seen(self, key: str) -> bool:
        return key in self._seen

    def mark(self, key: str, *, ts: Optional[str] = None) -> None:
        self._seen.add(key)


class SqliteSeenStore:
    """A durable seen-key store backed by a SQLite file (stdlib only).

    Defaults the path to ``IOCFLOW_SOURCES_DB`` or ``iocflow_seen.sqlite`` in the
    working directory. Concurrent ``mark`` calls from one process are serialized
    with a lock; the connection allows cross-thread use.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.environ.get("IOCFLOW_SOURCES_DB", "iocflow_seen.sqlite")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS seen "
            "(key TEXT PRIMARY KEY, first_seen TEXT NOT NULL)"
        )
        self._conn.commit()

    def seen(self, key: str) -> bool:
        cur = self._conn.execute("SELECT 1 FROM seen WHERE key = ?", (key,))
        return cur.fetchone() is not None

    def mark(self, key: str, *, ts: Optional[str] = None) -> None:
        stamp = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen (key, first_seen) VALUES (?, ?)",
                (key, stamp),
            )
            self._conn.commit()

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
