import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException

from api.security import check_agent_bound_key, make_api_key_dependency
from guardian.config import GuardianConfig


class TestApiKeyDependency(unittest.TestCase):
    def test_disabled_when_no_key_configured(self):
        config = GuardianConfig(api_key=None)
        require_api_key = make_api_key_dependency(config)
        # Should not raise, regardless of header
        require_api_key(authorization=None)
        require_api_key(authorization="Bearer anything")

    def test_missing_header_rejected_when_key_configured(self):
        config = GuardianConfig(api_key="secret123")
        require_api_key = make_api_key_dependency(config)
        with self.assertRaises(HTTPException) as ctx:
            require_api_key(authorization=None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_wrong_key_rejected(self):
        config = GuardianConfig(api_key="secret123")
        require_api_key = make_api_key_dependency(config)
        with self.assertRaises(HTTPException) as ctx:
            require_api_key(authorization="Bearer wrong")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_correct_key_accepted(self):
        config = GuardianConfig(api_key="secret123")
        require_api_key = make_api_key_dependency(config)
        require_api_key(authorization="Bearer secret123")  # should not raise

    def test_malformed_header_rejected(self):
        config = GuardianConfig(api_key="secret123")
        require_api_key = make_api_key_dependency(config)
        with self.assertRaises(HTTPException):
            require_api_key(authorization="secret123")  # missing "Bearer " prefix


class TestAgentBoundKey(unittest.TestCase):
    """Regression tests for the finding that a single shared API key lets
    any caller submit any agent_id and inherit its reputation/capability
    grants. GUARDIAN_AGENT_API_KEYS binds a specific key to a specific
    agent_id - a different agent's key (or no key) must not authorize it.
    """

    def test_disabled_when_nothing_configured(self):
        config = GuardianConfig(api_key=None, agent_api_keys={})
        check_agent_bound_key(None, "any-agent", config)  # should not raise

    def test_agent_key_authorizes_only_its_own_agent_id(self):
        config = GuardianConfig(api_key=None, agent_api_keys={"agent-a": "key-a", "agent-b": "key-b"})
        check_agent_bound_key("Bearer key-a", "agent-a", config)  # should not raise
        with self.assertRaises(HTTPException) as ctx:
            check_agent_bound_key("Bearer key-a", "agent-b", config)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_unregistered_agent_id_is_rejected(self):
        config = GuardianConfig(api_key=None, agent_api_keys={"agent-a": "key-a"})
        with self.assertRaises(HTTPException) as ctx:
            check_agent_bound_key("Bearer key-a", "some-other-agent", config)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_no_key_at_all_is_rejected_once_per_agent_keys_configured(self):
        config = GuardianConfig(api_key=None, agent_api_keys={"agent-a": "key-a"})
        with self.assertRaises(HTTPException):
            check_agent_bound_key(None, "agent-a", config)

    def test_master_key_authorizes_any_agent_id(self):
        config = GuardianConfig(api_key="master-secret", agent_api_keys={"agent-a": "key-a"})
        check_agent_bound_key("Bearer master-secret", "agent-a", config)
        check_agent_bound_key("Bearer master-secret", "totally-different-agent", config)

    def test_agent_key_does_not_authorize_as_master(self):
        # An agent-specific key must not work for a *different* agent_id,
        # even when a master key also exists elsewhere in the deployment.
        config = GuardianConfig(api_key="master-secret", agent_api_keys={"agent-a": "key-a"})
        with self.assertRaises(HTTPException):
            check_agent_bound_key("Bearer key-a", "agent-b", config)

    def test_falls_back_to_global_key_when_no_per_agent_keys_configured(self):
        # Backward compatibility: single-tenant deployments with only
        # GUARDIAN_API_KEY set keep working exactly as before.
        config = GuardianConfig(api_key="secret123", agent_api_keys={})
        check_agent_bound_key("Bearer secret123", "any-agent", config)
        with self.assertRaises(HTTPException):
            check_agent_bound_key("Bearer wrong", "any-agent", config)

    def test_empty_bearer_token_not_accepted_when_only_agent_keys_configured(self):
        # Regression test: GuardianConfig.auth_enabled can be True from
        # agent_api_keys alone (api_key=None) - an empty token must still
        # be rejected, not silently compared against an empty api_key.
        config = GuardianConfig(api_key=None, agent_api_keys={"agent-a": "key-a"})
        with self.assertRaises(HTTPException):
            check_agent_bound_key("Bearer ", "agent-a", config)


class TestMasterKeyDependencyWithOnlyAgentKeysConfigured(unittest.TestCase):
    """Regression test for the same empty-token edge case, but through
    make_api_key_dependency (used by endpoints with no agent_id to bind,
    e.g. /demo) rather than check_agent_bound_key."""

    def test_empty_bearer_token_rejected_when_no_master_key_exists(self):
        config = GuardianConfig(api_key=None, agent_api_keys={"agent-a": "key-a"})
        require_api_key = make_api_key_dependency(config)
        with self.assertRaises(HTTPException):
            require_api_key(authorization="Bearer ")


class TestRateLimitMiddleware(unittest.TestCase):
    """Covers the memory-exhaustion fix: many distinct identities making a
    single request each must not grow ``_counters`` without bound."""

    def _make_middleware(self, limit=5, max_tracked=3):
        from api.security import RateLimitMiddleware
        app = MagicMock()
        return RateLimitMiddleware(app, limit_per_minute=limit, max_tracked_identities=max_tracked)

    def _fake_request(self, identity: str):
        req = MagicMock()
        req.headers = {"authorization": identity}
        req.client = None
        return req

    async def _call_next(self, request):
        response = MagicMock()
        return response

    def test_tracked_identities_bounded_by_lru_eviction(self):
        middleware = self._make_middleware(limit=5, max_tracked=3)
        import asyncio

        async def run():
            for i in range(10):
                await middleware.dispatch(self._fake_request(f"id-{i}"), self._call_next)

        asyncio.run(run())
        self.assertLessEqual(len(middleware._counters), 3)
        # Most recently seen identities should be the ones retained.
        self.assertIn("id-9", middleware._counters)
        self.assertNotIn("id-0", middleware._counters)

    def test_limit_still_enforced_per_identity(self):
        middleware = self._make_middleware(limit=2, max_tracked=10)
        import asyncio

        async def run():
            results = []
            for _ in range(3):
                resp = await middleware.dispatch(self._fake_request("same-id"), self._call_next)
                results.append(resp)
            return results

        results = asyncio.run(run())
        # Third call within the same window should be the 429 JSONResponse,
        # not whatever _call_next returns.
        from starlette.responses import JSONResponse
        self.assertIsInstance(results[2], JSONResponse)
        self.assertEqual(results[2].status_code, 429)


if __name__ == "__main__":
    unittest.main()
