"""SQLite-backed ``MemoryBackend``.

The self-hosted default for anything beyond a single dev process:
decision history and agent reputation survive restarts, with zero
external infrastructure (SQLite ships in the Python standard library).
For a multi-*process* or multi-*host* deployment behind a load balancer,
point ``sqlite_path`` at a shared volume, or implement ``MemoryBackend``
against Postgres/Redis instead - this class only needs to satisfy that
same two-method interface for the rest of the codebase to keep working
unmodified.

Not a fit for high write concurrency across many processes (SQLite's
single-writer model will serialize those writes) - fine for the request
volume a single Guardian instance handles, since each write is one small
JSON row.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional


class SQLiteStorage:
    # How many rows to retain per key (agent) before trimming the oldest.
    # Comfortably above every real reader of this data: AgentReputation's
    # DEFAULT_HISTORY_WINDOW (500) and the /agents/{id}/history endpoint's
    # hard cap (500) both stay well within this, so trimming never
    # changes what either of those actually sees - it only bounds disk
    # growth for a long-lived, high-volume agent that would otherwise
    # accumulate rows forever (this table only ever INSERTed, never
    # trimmed, before this).
    MAX_ROWS_PER_KEY = 5000

    def __init__(self, path: str = "data/guardian.db", max_rows_per_key: Optional[int] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_rows_per_key = max_rows_per_key or self.MAX_ROWS_PER_KEY
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at REAL DEFAULT (unixepoch('now', 'subsec'))
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_history_key ON history(key)")
        self._conn.commit()

    def append(self, key: str, value: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO history (key, value) VALUES (?, ?)",
                (key, json.dumps(value)),
            )
            # Trim this key back down to max_rows_per_key, oldest rows
            # first. Runs on every write rather than periodically -
            # simpler to reason about than a "trim every N writes"
            # counter, and the DELETE is indexed on `key` so it stays
            # cheap even as the table grows across many agents.
            self._conn.execute(
                """
                DELETE FROM history WHERE key = ? AND id NOT IN (
                    SELECT id FROM history WHERE key = ? ORDER BY id DESC LIMIT ?
                )
                """,
                (key, key, self.max_rows_per_key),
            )
            self._conn.commit()

    def get(self, key: str, limit: Optional[int] = None) -> List[dict]:
        with self._lock:
            if limit is None:
                rows = self._conn.execute(
                    "SELECT value FROM history WHERE key = ? ORDER BY id ASC",
                    (key,),
                ).fetchall()
            else:
                # Most recent `limit` rows, but still returned oldest-first
                # so callers see the same chronological order as the
                # unlimited case.
                rows = self._conn.execute(
                    """
                    SELECT value FROM (
                        SELECT id, value FROM history
                        WHERE key = ? ORDER BY id DESC LIMIT ?
                    ) sub ORDER BY id ASC
                    """,
                    (key, limit),
                ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_since(self, key: str, since_timestamp: float) -> List[dict]:
        # Filters on the record's own "t" field (set by the caller, e.g.
        # CapabilityRegistry) rather than this table's `created_at`
        # column, so the semantics are identical across every backend
        # (Postgres's created_at is a TIMESTAMPTZ, not a raw epoch float -
        # reconciling that per-backend isn't worth it when the caller
        # already stamps its own records). `self.get(key)` is already
        # bounded by MAX_ROWS_PER_KEY, so this never scans an unbounded
        # amount of history.
        return [r for r in self.get(key) if r.get("t", 0) > since_timestamp]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
