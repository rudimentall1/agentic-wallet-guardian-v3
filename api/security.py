"""API security: bearer-token auth + a simple in-memory rate limiter.

Both are deliberately minimal - this is meant for a single self-hosted
instance sitting behind your own network boundary, not a multi-tenant
public SaaS. If you need per-tenant keys, quotas, or distributed rate
limiting across many replicas, put a real API gateway in front of this
(Kong, Envoy, your cloud provider's API gateway) rather than extending
this module indefinitely.

Auth is OFF by default (no GUARDIAN_API_KEY set) so the zero-config demo
experience keeps working. Set GUARDIAN_API_KEY before exposing this
outside localhost - a security tool with an unauthenticated decision
endpoint is a bad look, and the startup log says so loudly if you don't.
"""
from __future__ import annotations

import logging
import secrets
import time
from collections import OrderedDict
from typing import Optional

from fastapi import Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from guardian.config import GuardianConfig

logger = logging.getLogger("guardian.api.security")


def make_api_key_dependency(config: GuardianConfig):
    """Returns a FastAPI dependency that enforces ``Authorization: Bearer <key>``
    when ``config.api_key`` is set, and is a no-op otherwise."""

    def require_api_key(authorization: Optional[str] = Header(default=None)):
        if not config.auth_enabled:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = authorization.removeprefix("Bearer ").strip()
        if not secrets.compare_digest(token, config.api_key or ""):
            raise HTTPException(status_code=401, detail="Invalid API key")

    return require_api_key


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window rate limit, keyed by API key if present, else client IP.

    In-memory - correct for one process, approximate (each replica limits
    independently) if you run several. Good enough for a self-hosted
    single instance; put a shared store behind this if you scale out.

    ``_counters`` is bounded to ``max_tracked_identities`` via LRU eviction.
    Without this, an identity that makes one request and never returns
    (whether a legitimate caller with a rotating IP, or an attacker
    deliberately varying the Authorization header per request) would sit
    in memory forever - the per-bucket cleanup below only trims stale
    *timestamps* for identities that come back, it never removes an
    identity that doesn't. Left unbounded, that is a practical memory-
    exhaustion DoS against a tool whose whole job is to be trustworthy
    under adversarial input.
    """

    def __init__(self, app, limit_per_minute: int, max_tracked_identities: int = 10_000):
        super().__init__(app)
        self.limit = limit_per_minute
        self.max_tracked_identities = max_tracked_identities
        self._counters: "OrderedDict[str, list[float]]" = OrderedDict()

    async def dispatch(self, request: Request, call_next):
        if self.limit <= 0:
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        identity = auth if auth else (request.client.host if request.client else "unknown")

        now = time.monotonic()
        window_start = now - 60

        bucket = self._counters.get(identity)
        if bucket is None:
            bucket = []
            self._counters[identity] = bucket
        self._counters.move_to_end(identity)

        while bucket and bucket[0] < window_start:
            bucket.pop(0)

        if len(bucket) >= self.limit:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        bucket.append(now)

        while len(self._counters) > self.max_tracked_identities:
            self._counters.popitem(last=False)

        return await call_next(request)
