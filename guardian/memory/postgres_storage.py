"""Postgres-backed ``MemoryBackend`` - the fit for multiple Guardian
replicas sharing decision history/reputation behind a load balancer,
where SQLiteStorage's single-writer model becomes the bottleneck.

Same two-method interface as InMemoryStorage/SQLiteStorage - nothing
else in the codebase changes to use this instead. `psycopg` is imported
lazily inside __init__, not at module load time, so installing this
project doesn't require a Postgres client library unless this backend
is actually selected (``GUARDIAN_STORAGE_BACKEND=postgres``).
"""
from __future__ import annotations

import json
from typing import List, Optional


class PostgresStorage:
    # See SQLiteStorage.MAX_ROWS_PER_KEY for the reasoning - same default,
    # same rationale, kept in sync between the two backends.
    MAX_ROWS_PER_KEY = 5000

    def __init__(self, dsn: str, min_pool_size: int = 1, max_pool_size: int = 5,
                 max_rows_per_key: Optional[int] = None):
        try:
            import psycopg
            from psycopg_pool import ConnectionPool
        except ImportError as e:
            raise ImportError(
                "PostgresStorage requires 'psycopg[binary]' and 'psycopg_pool' - "
                "install with: pip install \"psycopg[binary]\" psycopg_pool"
            ) from e

        self._psycopg = psycopg
        self.max_rows_per_key = max_rows_per_key or self.MAX_ROWS_PER_KEY
        self.pool = ConnectionPool(dsn, min_size=min_pool_size, max_size=max_pool_size, open=True)
        self.pool.wait(timeout=10)

        with self.pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS guardian_history (
                    id BIGSERIAL PRIMARY KEY,
                    key TEXT NOT NULL,
                    value JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_guardian_history_key ON guardian_history (key)"
            )
            conn.commit()

    def append(self, key: str, value: dict) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO guardian_history (key, value) VALUES (%s, %s)",
                (key, json.dumps(value)),
            )
            # Same unbounded-growth fix as SQLiteStorage.append(): trim
            # this key back down to max_rows_per_key on every write. This
            # table previously had no DELETE anywhere - fine on
            # SQLite for a single self-hosted instance, but a genuine
            # operational problem on the backend specifically meant for
            # "multiple replicas sharing history under real load" (see
            # the module docstring).
            conn.execute(
                """
                DELETE FROM guardian_history WHERE key = %s AND id NOT IN (
                    SELECT id FROM guardian_history WHERE key = %s ORDER BY id DESC LIMIT %s
                )
                """,
                (key, key, self.max_rows_per_key),
            )
            conn.commit()

    def get(self, key: str, limit: Optional[int] = None) -> List[dict]:
        with self.pool.connection() as conn:
            if limit is None:
                rows = conn.execute(
                    "SELECT value FROM guardian_history WHERE key = %s ORDER BY id ASC",
                    (key,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT value FROM (
                        SELECT id, value FROM guardian_history
                        WHERE key = %s ORDER BY id DESC LIMIT %s
                    ) sub ORDER BY id ASC
                    """,
                    (key, limit),
                ).fetchall()
        # psycopg auto-adapts JSONB back into a Python dict already - no
        # json.loads needed here, unlike the SQLite backend which stores
        # value as plain TEXT.
        return [row[0] for row in rows]

    def get_since(self, key: str, since_timestamp: float) -> List[dict]:
        # See SQLiteStorage.get_since for why this filters on the
        # record's own "t" field rather than the created_at column.
        return [r for r in self.get(key) if r.get("t", 0) > since_timestamp]

    def close(self) -> None:
        self.pool.close()
