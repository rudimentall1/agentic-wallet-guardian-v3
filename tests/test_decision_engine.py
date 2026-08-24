import unittest
from unittest.mock import MagicMock, patch

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

    With no decimals provider configured (GUARDIAN_DECIMALS_PROVIDER left
    at its "null" default, the default in every test below unless stated
    otherwise), the engine still passes token_decimals=None and
    verify_intent_matches_simulation() takes its "cannot verify" WARN
    branch, exactly as before - that's the deliberately conservative
    zero-config behavior, not a gap. See
    TestIntentVerificationWithRealDecimalsProvider below for the real,
    end-to-end BLOCK path once GUARDIAN_DECIMALS_PROVIDER=rpc is
    configured (guardian/intelligence/token/decimals.py).
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

    def test_unconfirmed_unlimited_approval_is_blocked(self):
        # A confirmed unlimited approval that the agent did not explicitly
        # acknowledge is now a hard BLOCK from intent_verification, not a
        # silent no-op - regardless of what the rest of the signal mix
        # looks like. This is a deliberate, independent second layer on
        # top of the unlimited_approval_confirmed Signal's own score
        # (which alone already forces BLOCK via the risk-fusion dominant
        # floor - see test_confirmed_unlimited_approval_forces_block below).
        engine = self._engine_with_fake_simulation(decoded_approval_amount=None, is_unlimited=True)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=0)
        decision = engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)
        self.assertTrue(any(v.rule == "unconfirmed_unlimited_approval" and v.severity == "BLOCK"
                             for v in decision.policy_violations))
        self.assertFalse(any(v.rule == "intent_verification_skipped" for v in decision.policy_violations))

    def test_acknowledged_unlimited_approval_is_not_blocked_by_intent_verification(self):
        # Honest opt-in escape hatch, same pattern as max_slippage_bps /
        # l2_token elsewhere in this codebase: an agent that explicitly
        # says it wants an unlimited approval (a real, if risky, pattern
        # some DeFi integrations require) is not silently overridden.
        engine = self._engine_with_fake_simulation(decoded_approval_amount=None, is_unlimited=True)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target="0xdef", amount=0,
                               metadata={"acknowledge_unlimited_approval": True})
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule == "unconfirmed_unlimited_approval" for v in decision.policy_violations))

    def test_confirmed_unlimited_approval_forces_block_via_score_alone(self):
        # Layer 1 (risk score): even without the intent_verification BLOCK
        # above, the unlimited_approval_confirmed Signal's own score
        # (92, above RiskFusionEngine.DOMINANT_SIGNAL_THRESHOLD=90) must be
        # enough on its own to force BLOCK, so this doesn't depend on
        # being diluted by whatever else is in the signal mix that
        # request. Regression test for the finding that score=75 (the
        # original value) sat *below* the dominant-floor threshold and
        # could be averaged down by ordinary benign signals.
        from guardian.decision.scoring import RiskFusionEngine
        from guardian.core.models import Signal

        fusion = RiskFusionEngine()
        signals = [
            Signal(source="simulation", name="unlimited_approval_confirmed", score=92, weight=2.0, confidence=0.95),
            Signal(source="wallet", name="wallet_established", score=10, weight=1.0, confidence=0.9),
            Signal(source="token", name="token_trusted", score=10, weight=1.0, confidence=0.9),
            Signal(source="contract", name="contract_verified", score=10, weight=1.0, confidence=0.9),
        ]
        fused = fusion.fuse(signals)
        self.assertGreaterEqual(fused, 80.0)  # DecisionEngine.BLOCK_THRESHOLD

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


class TestIntentVerificationWithRealDecimalsProvider(unittest.TestCase):
    """End-to-end tests for the decimals provider
    (guardian/intelligence/token/decimals.py) actually reaching
    DecisionEngine.evaluate() - not calling verify_intent_matches_
    simulation() directly like the test above, which only proved the
    comparison logic itself was correct in isolation. These construct a
    real DecisionEngine with GUARDIAN_DECIMALS_PROVIDER=rpc, mock only
    the RPC client underneath it, and check the actual Decision that
    comes out - the same style as
    TestTransactionBuilderIntegratedIntoDecisionEngine in
    test_tx_builder.py.
    """

    TOKEN_ADDRESS = "0x1111111111111111111111111111111111111111"
    SPENDER = "0x2222222222222222222222222222222222222222"

    def _engine_with_real_decimals_and_fake_simulation(self, decoded_approval_amount, is_unlimited=False):
        import os

        from guardian.config import reload_config
        from guardian.intelligence.simulation.engine import SimulationEngine
        from guardian.intelligence.simulation.providers import SimulationResult

        os.environ["GUARDIAN_DECIMALS_PROVIDER"] = "rpc"
        os.environ["GUARDIAN_RPC_ETHEREUM"] = "http://fake"
        self.addCleanup(self._reset_env)
        config = reload_config()

        class FakeSimulationProvider:
            def simulate(self, intent):
                return SimulationResult(
                    attempted=True, would_revert=False,
                    decoded_approval_amount=decoded_approval_amount,
                    is_unlimited_approval=is_unlimited,
                )

        engine = DecisionEngine(config=config, simulation_engine=SimulationEngine(FakeSimulationProvider()))

        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.return_value = (6).to_bytes(32, byteorder="big")  # USDC-style 6 decimals
        patcher = patch.object(engine.decimals_provider, "_client", return_value=fake_w3)
        self._fake_w3 = patcher.start()
        self.addCleanup(patcher.stop)
        return engine

    def _reset_env(self):
        import os

        from guardian.config import reload_config

        os.environ.pop("GUARDIAN_DECIMALS_PROVIDER", None)
        os.environ.pop("GUARDIAN_RPC_ETHEREUM", None)
        reload_config()

    def test_real_mismatch_is_blocked_end_to_end(self):
        # Agent declares approving 50 USDC (6 decimals -> 50_000_000
        # atomic units), but the calldata actually encodes 5_000_000
        # atomic (5 USDC) - a real, on-chain-confirmed mismatch, caught
        # via a real (mocked-RPC) decimals() lookup reaching the engine,
        # not a hand-constructed token_decimals=6 argument.
        engine = self._engine_with_real_decimals_and_fake_simulation(decoded_approval_amount=5_000_000)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target=self.SPENDER,
                               from_token=self.TOKEN_ADDRESS, amount=50)
        decision = engine.evaluate(intent)
        self.assertEqual(decision.decision, DecisionType.BLOCK)
        self.assertTrue(any(v.rule == "intent_amount_mismatch" for v in decision.policy_violations))

    def test_real_matching_amount_is_not_flagged(self):
        # Same setup, but the calldata matches the declared amount
        # exactly (50 USDC = 50_000_000 atomic units at 6 decimals) -
        # must NOT produce a mismatch violation.
        engine = self._engine_with_real_decimals_and_fake_simulation(decoded_approval_amount=50_000_000)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target=self.SPENDER,
                               from_token=self.TOKEN_ADDRESS, amount=50)
        decision = engine.evaluate(intent)
        self.assertFalse(any(v.rule == "intent_amount_mismatch" for v in decision.policy_violations))

    def test_bare_symbol_from_token_still_degrades_to_cannot_verify(self):
        # from_token="USDC" (a symbol, not an address) can't be looked up
        # on-chain - this must still degrade to the honest "cannot
        # verify" WARN, not crash or silently skip the RPC client
        # entirely (which it does - no eth_call attempted at all here).
        engine = self._engine_with_real_decimals_and_fake_simulation(decoded_approval_amount=5_000_000)
        intent = ActionIntent(agent_id="a1", wallet="0xabc", chain="ethereum",
                               action_type="approve", target=self.SPENDER,
                               from_token="USDC", amount=50)
        decision = engine.evaluate(intent)
        self.assertTrue(any(v.rule == "intent_verification_skipped" for v in decision.policy_violations))
        self._fake_w3.assert_not_called()


if __name__ == "__main__":
    unittest.main()
