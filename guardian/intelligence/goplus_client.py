"""Thin client for the GoPlus Security Token Security API.

Free and keyless for light usage (rate-limited per IP); see
https://docs.gopluslabs.io/reference/tokensecurityusingget_1 for the
official reference. A single call to this endpoint returns contract
security (verified/proxy/mintable/self-destruct/hidden-owner), trading
security (honeypot/buy-sell tax/blacklist), and holder/liquidity
concentration - which is why both ContractAnalyzer and TokenAnalyzer can
share this client instead of hitting separate services.

Set GOPLUS_API_KEY (or pass api_key explicitly) to an access token from
GoPlus's Access Token API
(https://docs.gopluslabs.io/reference/getaccesstokenusingpost) if you
outgrow the keyless rate limit - this client sends it as a Bearer token
automatically when present, and works fine without it otherwise.

This client fails SOFT by design: any network error, timeout, non-200
response, or unexpected payload shape returns None instead of raising. A
GoPlus outage should degrade the decision pipeline to "no data available"
for this source, never take decision-making down entirely - the engine
already treats "no signals from a source" as a mild, low-confidence risk
factor on its own.
"""
from __future__ import annotations

import os
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

BASE_URL = "https://api.gopluslabs.io/api/v1/token_security"
TIMEOUT_SECONDS = 6.0
CACHE_TTL_SECONDS = 300
# _cache is a process-wide cache keyed by (chain, address) - in a
# long-running service, agents can drive lookups against effectively
# unbounded distinct addresses (attacker-influenced token/contract
# addresses included), so without a cap this grows forever: expired
# entries were only ever treated as "miss" on read, never actually
# removed. Same class of memory-exhaustion issue as the rate limiter
# fixed earlier in api/security.py - bounded the same way, via LRU
# eviction once the cache exceeds this many entries.
MAX_CACHE_ENTRIES = 10_000

# ActionIntent.chain (as used throughout this codebase) -> GoPlus chain_id.
# https://docs.gopluslabs.io/reference/response-details-9 has the full list;
# these are the chains guardian/decision/rules.py currently supports.
CHAIN_ID_MAP = {
    "ethereum": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161",
    "optimism": "10",
    "base": "8453",
    "avalanche": "43114",
    "fantom": "250",
    # "solana" intentionally omitted: it needs a different GoPlus endpoint
    # (Token Security API for Solana, still Beta as of this writing).
}

_cache: "OrderedDict[str, Tuple[float, Optional[dict]]]" = OrderedDict()


def is_chain_supported(chain: str) -> bool:
    return chain.lower() in CHAIN_ID_MAP


def get_token_security(chain: str, address: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the raw GoPlus token_security result dict for one address.

    Returns None if: the chain isn't covered by this endpoint, the
    request fails or times out, GoPlus returns a non-success code, or
    GoPlus simply has no data for this address (a real "unknown", not an
    error). Callers should treat None as "no data available" - not as
    "safe" and not as "risky".
    """
    chain_id = CHAIN_ID_MAP.get(chain.lower())
    if chain_id is None:
        return None

    address = address.lower()
    cache_key = f"{chain_id}:{address}"
    cached = _cache.get(cache_key)
    if cached is not None and (time.time() - cached[0]) < CACHE_TTL_SECONDS:
        _cache.move_to_end(cache_key)
        return cached[1]

    import httpx

    headers = {}
    key = api_key if api_key is not None else os.environ.get("GOPLUS_API_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"

    result: Optional[Dict[str, Any]] = None
    try:
        resp = httpx.get(
            f"{BASE_URL}/{chain_id}",
            params={"contract_addresses": address},
            headers=headers,
            timeout=TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("code") == 1:
            result = (payload.get("result") or {}).get(address)
    except Exception:
        # Deliberately broad: this client's whole contract is "never raise,
        # a lookup failure just means no data" (see module docstring) - a
        # narrower except (e.g. only httpx.HTTPError) would silently break
        # that promise for other failure modes, like a malformed JSON body.
        result = None

    _cache[cache_key] = (time.time(), result)
    _cache.move_to_end(cache_key)
    while len(_cache) > MAX_CACHE_ENTRIES:
        _cache.popitem(last=False)
    return result


def clear_cache() -> None:
    """Used by tests; also handy if a long-running process needs to force
    a fresh lookup for an address it already cached."""
    _cache.clear()
