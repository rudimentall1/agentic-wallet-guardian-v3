import unittest

from guardian.core.intent import ActionIntent
from guardian.core.models import DecisionType
from guardian.decision.engine import DecisionEngine


class TestDecisionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DecisionEngine()

    def test_unsupported_chain_is_blocked(self):
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="doge-chain",
                               action_type="swap", amount=1)
        decision = self.engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)
        self.assertTrue(any(v.rule == "unsupported_chain" for v in decision.policy_violations))

    def test_botchain_is_a_supported_chain(self):
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="botchain",
                               action_type="transfer", target="0xdef", amount=1)
        decision = self.engine.evaluate(intent)
        self.assertFalse(any(v.rule == "unsupported_chain" for v in decision.policy_violations))

    def test_unknown_agent_large_amount_is_blocked_by_policy(self):
        intent = ActionIntent(agent_id="brand-new-agent",
                               wallet="0x000000000000000000000000000000000000aa",
                               chain="ethereum", action_type="swap", to_token="ETH", amount=999)
        decision = self.engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)
        self.assertTrue(any(v.rule == "amount_exceeds_cap" for v in decision.policy_violations))

    def test_small_known_token_amount_produces_a_full_decision(self):
        intent = ActionIntent(agent_id="trading-agent-001",
                               wallet="0xe57ab715ed0000000000000000000000000001",
                               chain="ethereum", action_type="swap", to_token="USDC", amount=1)
        decision = self.engine.evaluate(intent)
        self.assertIn(decision.decision, (DecisionType.ALLOW, DecisionType.WARN))
        self.assertGreater(len(decision.explanation), 0)
        self.assertGreater(len(decision.signals), 0)
        self.assertTrue(0.0 <= decision.confidence <= 1.0)

    def test_approve_action_always_requires_confirmation(self):
        intent = ActionIntent(agent_id="trading-agent-001",
                               wallet="0x0000000000000000000000000000000000bbbb",
                               chain="ethereum", action_type="approve",
                               target="0x00000000000000000000000000000000cccccc", amount=1)
        decision = self.engine.evaluate(intent)
        self.assertTrue(any(v.rule == "requires_confirmation" for v in decision.policy_violations))

    def test_reputation_does_not_drop_below_neutral_after_repeated_allows(self):
        agent_id = "reputable-agent"
        wallet = "0x00000000000000000000000000000000dddddd"
        last_score = None
        for _ in range(5):
            intent = ActionIntent(agent_id=agent_id, wallet=wallet, chain="ethereum",
                                   action_type="swap", to_token="USDC", amount=1)
            self.engine.evaluate(intent)
            last_score = self.engine.reputation.score_for(agent_id)
        self.assertIsNotNone(last_score)
        self.assertGreaterEqual(last_score, 50.0)

    def test_negative_amount_is_blocked(self):
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="transfer", amount=-5)
        decision = self.engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)

    def test_decision_serializes_to_dict_cleanly(self):
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="swap", to_token="USDC", amount=1)
        decision = self.engine.evaluate(intent)
        payload = decision.to_dict()
        for key in ("decision", "risk_score", "risk_level", "confidence",
                    "explanation", "signals", "policy_violations", "agent_id", "intent_id"):
            self.assertIn(key, payload)


class TestCapabilityRegistryWiring(unittest.TestCase):
    """Regression tests for Finding 7: guardian/policy/capabilities.py
    existed, was documented in README as "Done", and had its own example
    script - but DecisionEngine.evaluate() never called it. An operator
    who granted a capability got no enforcement at all through the
    normal evaluate() entry point."""

    def test_no_registry_means_feature_is_off(self):
        # Default DecisionEngine() has no capability_registry - an agent
        # with no grants anywhere must behave exactly as before this
        # wiring existed.
        engine = DecisionEngine()
        intent = ActionIntent(agent_id="agent-1", wallet="0xabc", chain="ethereum",
                               action_type="swap", to_token="USDC", amount=1)
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule.startswith("capability_") or v.rule == "action_type_not_granted"
                              or v.rule == "chain_not_granted" for v in decision.policy_violations))

    def test_capability_violation_blocks_via_the_real_pipeline(self):
        from guardian.policy.capabilities import Capability, CapabilityRegistry

        registry = CapabilityRegistry()
        registry.grant(Capability(agent_id="scoped-agent", allowed_action_types=["swap"]))
        engine = DecisionEngine(capability_registry=registry)

        intent = ActionIntent(agent_id="scoped-agent", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=1)
        decision = engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)
        self.assertTrue(any(v.rule == "action_type_not_granted" for v in decision.policy_violations))

    def test_agent_within_grant_is_unaffected(self):
        from guardian.policy.capabilities import Capability, CapabilityRegistry

        registry = CapabilityRegistry()
        registry.grant(Capability(agent_id="scoped-agent", allowed_action_types=["swap"]))
        engine = DecisionEngine(capability_registry=registry)

        intent = ActionIntent(agent_id="scoped-agent", wallet="0xabc", chain="ethereum",
                               action_type="swap", to_token="USDC", amount=1)
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule == "action_type_not_granted" for v in decision.policy_violations))


class TestIntentVerificationWiring(unittest.TestCase):
    """Regression tests for Finding 7: intent_verification.py was
    documented in README as catching declared-vs-actual approval
    mismatches, but was never called from DecisionEngine.evaluate() -
    only from its own standalone example script.

    IMPORTANT caveat these tests deliberately pin down: the engine wires
    this in with token_decimals=None (no decimals() provider exists in
    this codebase yet - see engine.py's comment at the call site), so
    verify_intent_matches_simulation() always takes its early "cannot
    verify without decimals" WARN branch and never reaches the actual
    mismatch-detection BLOCK logic below it. Wiring this in makes the
    check *reachable* and honest about why it isn't enforcing yet,
    which is strictly better than the previous state (not called at
    all, silently), but it is not yet a working guardrail on its own -
    that needs a real decimals provider as a follow-up.
    """

    def _engine_with_fake_simulation(self, decoded_approval_amount, is_unlimited=False):
        from guardian.intelligence.simulation.engine import SimulationEngine
        from guardian.intelligence.simulation.providers import SimulationResult

        class FakeProvider:
            def simulate(self, intent):
                return SimulationResult(
                    attempted=True, would_revert=False,
                    decoded_approval_amount=decoded_approval_amount,
                    is_unlimited_approval=is_unlimited,
                )

        return DecisionEngine(simulation_engine=SimulationEngine(FakeProvider()))

    def test_check_is_reachable_for_approve_with_finite_decoded_amount(self):
        # Confirms the wiring itself: this rule fires at all now, where
        # before this fix DecisionEngine.evaluate() never called
        # verify_intent_matches_simulation() under any circumstance.
        engine = self._engine_with_fake_simulation(decoded_approval_amount=5_000_000)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=0)
        decision = engine.evaluate(intent)
        self.assertTrue(any(v.rule == "intent_verification_skipped" for v in decision.policy_violations))

    def test_non_approve_action_is_not_affected(self):
        engine = self._engine_with_fake_simulation(decoded_approval_amount=5_000_000)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="swap", to_token="USDC", amount=0)
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule in ("intent_amount_mismatch", "intent_verification_skipped")
                              for v in decision.policy_violations))

    def test_unlimited_approval_short_circuits_before_the_decimals_check(self):
        # is_unlimited_approval=True returns [] immediately - that case is
        # already covered by the separate unlimited_approval_confirmed
        # signal, so it correctly does NOT also emit the "skipped" WARN.
        engine = self._engine_with_fake_simulation(decoded_approval_amount=None, is_unlimited=True)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=0)
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule in ("intent_amount_mismatch", "intent_verification_skipped")
                              for v in decision.policy_violations))

    def test_underlying_function_does_block_a_real_mismatch_once_decimals_are_known(self):
        # This exercises verify_intent_matches_simulation() directly
        # (not through the engine, since the engine has no decimals
        # source yet) to prove the actual mismatch-detection logic is
        # correct and ready for when a decimals provider is wired in.
        from guardian.intelligence.simulation.providers import SimulationResult
        from guardian.decision.intent_verification import verify_intent_matches_simulation

        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=0)
        result = SimulationResult(attempted=True, would_revert=False,
                                   decoded_approval_amount=5_000_000, is_unlimited_approval=False)
        violations = verify_intent_matches_simulation(intent, result, token_decimals=6)
        self.assertEqual([v.rule for v in violations], ["intent_amount_mismatch"])
        self.assertEqual(violations[0].severity, "BLOCK")


if __name__ == "__main__":
    unittest.main()
