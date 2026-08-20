import json
import unittest

import mcp_server


class TestEvaluateAction(unittest.TestCase):
    def test_returns_valid_decision_json(self):
        result = mcp_server.evaluate_action(
            agent_id="mcp-test-agent-1", wallet="0xabc", chain="ethereum",
            action_type="swap", to_token="USDC", amount=1,
        )
        payload = json.loads(result)
        self.assertIn(payload["decision"], ("ALLOW", "WARN", "BLOCK"))
        self.assertIn("risk_score", payload)
        self.assertIn("explanation", payload)

    def test_unsupported_chain_is_blocked(self):
        result = mcp_server.evaluate_action(
            agent_id="mcp-test-agent-2", wallet="0xabc", chain="not-a-real-chain",
            action_type="swap", amount=1,
        )
        payload = json.loads(result)
        self.assertEqual(payload["decision"], "BLOCK")

    def test_nan_amount_is_blocked_not_silently_accepted(self):
        # Regression check for Finding 6: the MCP entry point has no
        # pydantic layer (that protection is api/schemas.py-only), so
        # this only works because guardian/decision/rules.py's hard
        # rule catches NaN/Infinity at the core level - confirming that
        # fixing it there (not just at the HTTP boundary) was the right
        # call for defense in depth.
        result = mcp_server.evaluate_action(
            agent_id="mcp-test-agent-3", wallet="0xabc", chain="ethereum",
            action_type="transfer", amount=float("nan"),
        )
        payload = json.loads(result)
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertTrue(any(v["rule"] == "non_finite_amount" for v in payload["policy_violations"]))


class TestGetAgentHistory(unittest.TestCase):
    def test_reports_reputation_and_history(self):
        agent_id = "mcp-history-agent"
        mcp_server.evaluate_action(agent_id=agent_id, wallet="0xabc", chain="ethereum",
                                    action_type="swap", to_token="USDC", amount=1)
        result = mcp_server.get_agent_history(agent_id=agent_id)
        payload = json.loads(result)
        self.assertEqual(payload["agent_id"], agent_id)
        self.assertIn("reputation_score", payload)
        self.assertEqual(len(payload["history"]), 1)

    def test_default_and_explicit_limit(self):
        agent_id = "mcp-history-limit-agent"
        for _ in range(20):
            mcp_server.evaluate_action(agent_id=agent_id, wallet="0xabc", chain="ethereum",
                                        action_type="swap", to_token="USDC", amount=1)
        result = json.loads(mcp_server.get_agent_history(agent_id=agent_id, limit=5))
        self.assertEqual(len(result["history"]), 5)

    def test_limit_is_capped_at_500(self):
        # Regression test for the MCP-side twin of Finding 10a
        # (api/main.py's /agents/*/history had the same unbounded read).
        agent_id = "mcp-history-cap-agent"
        for _ in range(10):
            mcp_server.evaluate_action(agent_id=agent_id, wallet="0xabc", chain="ethereum",
                                        action_type="swap", to_token="USDC", amount=1)
        result = json.loads(mcp_server.get_agent_history(agent_id=agent_id, limit=999999))
        self.assertLessEqual(len(result["history"]), 500)

    def test_unknown_agent_returns_empty_history_not_an_error(self):
        result = json.loads(mcp_server.get_agent_history(agent_id="never-seen-this-agent"))
        self.assertEqual(result["history"], [])
        self.assertEqual(result["reputation_score"], 50.0)


if __name__ == "__main__":
    unittest.main()
