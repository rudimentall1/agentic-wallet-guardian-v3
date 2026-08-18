import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException

from api.security import make_api_key_dependency
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
