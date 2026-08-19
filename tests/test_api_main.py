"""Integration tests for api/main.py's actual HTTP routes.

GUARDIAN_API_KEY must be set BEFORE api.main is first imported, since
api/main.py builds its config (and therefore auth_enabled) once at
module import time. No other test file imports api.main - keep it that
way, or these two imports would race for which env var was in effect
when the module-level `config = get_config()` actually ran.
"""
import os

os.environ["GUARDIAN_API_KEY"] = "test-api-key-123"
# Several tests below make dozens of requests in a loop to build up
# history - without this, the real RateLimitMiddleware (default 60/min)
# would throttle the test itself well before it finished, which is a
# test-environment artifact, not something these tests are meant to
# cover (that's api/security.py's own test file's job).
os.environ["GUARDIAN_RATE_LIMIT_PER_MINUTE"] = "100000"

import unittest

from fastapi.testclient import TestClient

from api.main import app

AUTH_HEADERS = {"Authorization": "Bearer test-api-key-123"}


class TestDecisionEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_requires_auth(self):
        resp = self.client.post("/decision", json={
            "agent_id": "a", "wallet": "0xabc", "action_type": "swap",
            "to_token": "USDC", "amount": 1,
        })
        self.assertEqual(resp.status_code, 401)

    def test_works_with_valid_key(self):
        resp = self.client.post(
            "/decision",
            json={"agent_id": "a", "wallet": "0xabc", "action_type": "swap",
                   "to_token": "USDC", "amount": 1},
            headers=AUTH_HEADERS,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(resp.json()["decision"], ("ALLOW", "WARN", "BLOCK"))

    def test_nan_amount_rejected_with_422(self):
        # End-to-end confirmation of Finding 6's api/schemas.py fix,
        # through the real route rather than just the schema directly.
        resp = self.client.post(
            "/decision",
            json='{"agent_id":"a","wallet":"0xabc","action_type":"swap","amount":NaN}',
            headers={**AUTH_HEADERS, "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 422)


class TestAgentHistoryEndpoint(unittest.TestCase):
    """Regression tests for Finding 10a: this endpoint read an agent's
    entire unbounded history over HTTP, bypassing the `limit` param
    added to guardian/memory/* earlier this session for exactly this
    reason."""

    def setUp(self):
        self.client = TestClient(app)

    def test_requires_auth(self):
        resp = self.client.get("/agents/some-agent/history")
        self.assertEqual(resp.status_code, 401)

    def test_default_limit_is_bounded(self):
        agent_id = "history-limit-test-agent"
        for _ in range(120):
            self.client.post(
                "/decision",
                json={"agent_id": agent_id, "wallet": "0xabc", "action_type": "swap",
                      "to_token": "USDC", "amount": 1},
                headers=AUTH_HEADERS,
            )
        resp = self.client.get(f"/agents/{agent_id}/history", headers=AUTH_HEADERS)
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.json()["history"]), 100)

    def test_limit_query_param_is_respected_and_capped(self):
        agent_id = "history-limit-test-agent-2"
        for _ in range(20):
            self.client.post(
                "/decision",
                json={"agent_id": agent_id, "wallet": "0xabc", "action_type": "swap",
                      "to_token": "USDC", "amount": 1},
                headers=AUTH_HEADERS,
            )
        resp = self.client.get(f"/agents/{agent_id}/history?limit=5", headers=AUTH_HEADERS)
        self.assertEqual(len(resp.json()["history"]), 5)

        # A caller passing an absurdly large limit still gets capped at
        # 500, not however many records actually exist.
        resp = self.client.get(f"/agents/{agent_id}/history?limit=999999", headers=AUTH_HEADERS)
        self.assertLessEqual(len(resp.json()["history"]), 500)


class TestDemoEndpoint(unittest.TestCase):
    """Regression tests for Finding 10b: this endpoint ran the full live
    decision pipeline with no authentication at all, unlike every other
    route that touches engine.evaluate()."""

    def setUp(self):
        self.client = TestClient(app)

    def test_requires_auth(self):
        resp = self.client.get("/demo/safe")
        self.assertEqual(resp.status_code, 401)

    def test_works_with_valid_key(self):
        resp = self.client.get("/demo/safe", headers=AUTH_HEADERS)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(resp.json()["decision"], ("ALLOW", "WARN", "BLOCK"))

    def test_unknown_scenario_is_404_not_401(self):
        # 404 for a bad scenario name should still require auth first -
        # but with valid auth, an unknown scenario is a 404, not a 500.
        resp = self.client.get("/demo/not-a-real-scenario", headers=AUTH_HEADERS)
        self.assertEqual(resp.status_code, 404)


class TestMetaEndpointsRemainUnauthenticated(unittest.TestCase):
    """/health and /capabilities make no external calls and no pipeline
    evaluation - confirming they're deliberately left open, unlike
    /demo."""

    def setUp(self):
        self.client = TestClient(app)

    def test_health_needs_no_auth(self):
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_capabilities_needs_no_auth(self):
        self.assertEqual(self.client.get("/capabilities").status_code, 200)


if __name__ == "__main__":
    unittest.main()
