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


if __name__ == "__main__":
    unittest.main()
