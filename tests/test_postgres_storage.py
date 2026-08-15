"""Tests run against a real, local Postgres instance - not mocked. If no
Postgres is reachable at TEST_POSTGRES_DSN (or the default below), the
whole class is skipped rather than silently passing against a fake that
wouldn't have caught a real SQL/adapter bug. This mirrors why the
production module exists: to prove the round-trip actually works
against the real thing, not just that the code compiles.
"""
import os
import unittest

TEST_DSN = os.environ.get("TEST_POSTGRES_DSN", "postgresql://postgres:testpass@localhost/guardian_test")


def _postgres_available() -> bool:
    try:
        import psycopg
        with psycopg.connect(TEST_DSN, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_postgres_available(), "No reachable Postgres at TEST_POSTGRES_DSN - skipping live tests")
class TestPostgresStorage(unittest.TestCase):
    def setUp(self):
        from guardian.memory.postgres_storage import PostgresStorage
        self.store = PostgresStorage(TEST_DSN)
        # Isolate each test with a random key prefix rather than
        # truncating the shared table, since tests may run concurrently.
        import uuid
        self.prefix = uuid.uuid4().hex[:8]

    def tearDown(self):
        self.store.close()

    def _key(self, suffix: str) -> str:
        return f"{self.prefix}-{suffix}"

    def test_append_and_get(self):
        key = self._key("agent-1")
        self.store.append(key, {"decision": "ALLOW", "risk_score": 5.0})
        self.store.append(key, {"decision": "BLOCK", "risk_score": 95.0})
        records = self.store.get(key)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["decision"], "ALLOW")
        self.assertEqual(records[1]["decision"], "BLOCK")

    def test_keys_are_isolated(self):
        key_a, key_b = self._key("agent-a"), self._key("agent-b")
        self.store.append(key_a, {"x": 1})
        self.store.append(key_b, {"x": 2})
        self.assertEqual(len(self.store.get(key_a)), 1)
        self.assertEqual(len(self.store.get(key_b)), 1)

    def test_unknown_key_returns_empty_list(self):
        self.assertEqual(self.store.get(self._key("never-seen")), [])

    def test_ordering_is_insertion_order(self):
        key = self._key("agent-order")
        for i in range(5):
            self.store.append(key, {"i": i})
        records = self.store.get(key)
        self.assertEqual([r["i"] for r in records], [0, 1, 2, 3, 4])

    def test_persists_across_instances(self):
        from guardian.memory.postgres_storage import PostgresStorage
        key = self._key("agent-persist")
        self.store.append(key, {"decision": "WARN"})
        self.store.close()

        store2 = PostgresStorage(TEST_DSN)
        try:
            records = store2.get(key)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["decision"], "WARN")
        finally:
            store2.close()
        # Prevent tearDown from double-closing the already-closed self.store.
        self.store = store2


class TestBuildStorageBackendPostgresConfig(unittest.TestCase):
    def test_missing_dsn_raises_rather_than_guessing(self):
        from guardian.config import GuardianConfig
        from guardian.decision.engine import build_storage_backend

        config = GuardianConfig(storage_backend="postgres", postgres_dsn="")
        with self.assertRaises(ValueError):
            build_storage_backend(config)


if __name__ == "__main__":
    unittest.main()
