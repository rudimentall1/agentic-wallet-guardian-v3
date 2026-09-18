import unittest

from guardian.arc import ARC_CHAIN_ID, ARC_USDC_ADDRESS, ARC_PAYMENT_POLICY, arc_config
from guardian.config import GuardianConfig
from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.policy.engine import PolicyEngine


class TestArcIntegration(unittest.TestCase):
    def test_arc_chain_is_supported(self):
        from guardian.decision.rules import SUPPORTED_CHAINS
        self.assertIn("arc", SUPPORTED_CHAINS)

    def test_arc_policy_blocks_large_payment(self):
        cfg = GuardianConfig(storage_backend="memory")
        cfg.rpc_urls = {"arc": "https://rpc.mainnet.arc.io"}
        engine = DecisionEngine(config=arc_config(cfg), policy_engine=PolicyEngine(dict(ARC_PAYMENT_POLICY)))
        intent = ActionIntent(
            agent_id="arc-test-agent",
            wallet="0x1111111111111111111111111111111111111111",
            chain="arc",
            action_type="transfer",
            target="0x2222222222222222222222222222222222222222",
            from_token=ARC_USDC_ADDRESS,
            amount=6.0,
        )
        decision = engine.evaluate(intent)
        self.assertEqual(decision.decision.value, "BLOCK")
        self.assertTrue(any(v.rule == "amount_exceeds_cap" for v in decision.policy_violations))

    def test_arc_constants_match_mainnet(self):
        self.assertEqual(ARC_CHAIN_ID, 5042)
        self.assertEqual(ARC_USDC_ADDRESS, "0x3600000000000000000000000000000000000000")
