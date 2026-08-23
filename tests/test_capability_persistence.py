import unittest

from guardian.core.intent import ActionIntent
from guardian.memory.storage import InMemoryStorage
from guardian.memory.sqlite_storage import SQLiteStorage
from guardian.policy.capabilities import Capability, CapabilityRegistry, evaluate_capability


class TestCapabilityRegistryDailySpendPersistence(unittest.TestCase):
    """Regression tests for the finding that CapabilityRegistry's daily
    spend tracking was in-memory only, with no way to opt into
    persistence - so any process restart (deploy, crash, routine
    rollout) silently reset every agent's daily spend counter to zero,
    letting an agent that had already hit its daily cap spend the full
    cap again the same calendar day.
    """

    def _intent(self, agent_id="agent-1", amount=100.0):
        return ActionIntent(agent_id=agent_id, wallet="0xabc", chain="ethereum",
                             action_type="transfer", target="0xdef", amount=amount)

    def test_default_behavior_is_unchanged_in_memory_only(self):
        # No storage passed - exact original behavior, nothing regresses
        # for existing callers that construct CapabilityRegistry() bare.
        registry = CapabilityRegistry()
        registry.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
        evaluate_capability(self._intent(amount=100.0), registry)
        violations = evaluate_capability(self._intent(amount=100.0), registry)
        self.assertTrue(any(v.rule == "capability_daily_limit_exceeded" for v in violations))

    def test_daily_spend_survives_a_new_registry_instance_with_shared_storage(self):
        # This is the actual fix: two separate CapabilityRegistry
        # instances (standing in for "before" and "after" a process
        # restart) sharing the same storage backend must accumulate
        # spend together, not reset to zero for the second instance.
        storage = InMemoryStorage()

        registry_before_restart = CapabilityRegistry(storage=storage)
        registry_before_restart.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
        v1 = evaluate_capability(self._intent(amount=100.0), registry_before_restart)
        self.assertFalse(any(v.rule == "capability_daily_limit_exceeded" for v in v1))

        # Simulates a process restart: fresh CapabilityRegistry, fresh
        # grant (an operator's bootstrap code re-grants on startup), but
        # the same underlying storage.
        registry_after_restart = CapabilityRegistry(storage=storage)
        registry_after_restart.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
        v2 = evaluate_capability(self._intent(amount=100.0), registry_after_restart)
        # 100 (before) + 100 (after) = 200 > 150 daily cap - the spend
        # from before the "restart" must still count.
        self.assertTrue(any(v.rule == "capability_daily_limit_exceeded" for v in v2))

    def test_without_shared_storage_a_new_instance_forgets_spend(self):
        # Documents the vulnerability this fixes: with no storage at all
        # (the pre-fix-only option), a fresh instance has no memory of
        # prior spend, so the same 100+100 sequence does NOT trigger the
        # daily cap the second time around.
        registry_before_restart = CapabilityRegistry()
        registry_before_restart.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
        evaluate_capability(self._intent(amount=100.0), registry_before_restart)

        registry_after_restart = CapabilityRegistry()  # no storage - "restart" forgets everything
        registry_after_restart.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
        v2 = evaluate_capability(self._intent(amount=100.0), registry_after_restart)
        self.assertFalse(any(v.rule == "capability_daily_limit_exceeded" for v in v2))

    def test_persists_correctly_with_real_sqlite_backend(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            db_path = str(Path(d) / "test.db")
            storage1 = SQLiteStorage(db_path)
            registry1 = CapabilityRegistry(storage=storage1)
            registry1.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
            evaluate_capability(self._intent(amount=100.0), registry1)
            storage1.close()

            storage2 = SQLiteStorage(db_path)
            registry2 = CapabilityRegistry(storage=storage2)
            registry2.grant(Capability(agent_id="agent-1", max_daily_amount=150.0))
            violations = evaluate_capability(self._intent(amount=100.0), registry2)
            self.assertTrue(any(v.rule == "capability_daily_limit_exceeded" for v in violations))
            storage2.close()

    def test_spend_tracking_is_isolated_per_agent_with_shared_storage(self):
        storage = InMemoryStorage()
        registry = CapabilityRegistry(storage=storage)
        registry.grant(Capability(agent_id="agent-a", max_daily_amount=150.0))
        registry.grant(Capability(agent_id="agent-b", max_daily_amount=150.0))

        evaluate_capability(self._intent(agent_id="agent-a", amount=100.0), registry)
        v_b = evaluate_capability(self._intent(agent_id="agent-b", amount=100.0), registry)
        self.assertFalse(any(v.rule == "capability_daily_limit_exceeded" for v in v_b))


if __name__ == "__main__":
    unittest.main()
