"""Token data providers.

``MockTokenDataProvider`` keeps the original deterministic placeholder.
``DexScreenerTokenDataProvider`` calls DexScreener's free, no-API-key
public search endpoint to get real liquidity data for a token symbol.

Matching a bare ticker symbol to the right on-chain pair is inherently
fuzzy (many unrelated tokens share a symbol like "PEPE" across chains and
scammers deliberately mint look-alike tickers) - this provider picks the
pair with the highest liquidity on the requested chain as its best guess
and says so in the profile, rather than silently pretending the match is
certain. For anything where that ambiguity matters, match by contract
address instead of symbol.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

logger = logging.getLogger("guardian.token")


@dataclass
class TokenLiquidityProfile:
    symbol: str
    liquidity_usd: Optional[float]
    is_concentrated: Optional[bool]
    data_source: str = "unknown"
    match_confidence: float = 1.0
    # Populated only by providers that can see this (currently GoPlus) -
    # None from Mock/DexScreener. Analyzer logic must treat None as
    # "unknown", never as "false".
    is_honeypot: Optional[bool] = None
    buy_tax: Optional[float] = None
    sell_tax: Optional[float] = None
    is_blacklistable: Optional[bool] = None
    is_pausable: Optional[bool] = None
    top_holder_percent: Optional[float] = None
    is_trusted_listed: Optional[bool] = None


class TokenDataProvider(Protocol):
    def get_liquidity_profile(self, symbol: str, chain: str) -> TokenLiquidityProfile: ...


class MockTokenDataProvider:
    name = "mock"

    def get_liquidity_profile(self, symbol: str, chain: str) -> TokenLiquidityProfile:
        h = int(hashlib.sha256(f"{chain}:{symbol.lower()}".encode()).hexdigest(), 16)
        is_concentrated = (h % 4) == 0  # ~25% mock rate, matches the original v3 heuristic
        liquidity_usd = float(h % 200_000) if not is_concentrated else float(h % 5_000)
        return TokenLiquidityProfile(
            symbol=symbol, liquidity_usd=liquidity_usd, is_concentrated=is_concentrated, data_source="mock",
        )


# Below this, treat liquidity as "concentrated / thin" - crossing a
# scammer's usual bar of a few hundred to a few thousand dollars of fake
# liquidity to make a token look tradeable.
THIN_LIQUIDITY_USD_THRESHOLD = 20_000.0


class DexScreenerTokenDataProvider:
    """Real liquidity data via DexScreener's public search API.

    Requires ``httpx`` (already a base dependency). DexScreener's API is
    free and keyless, but - like any third-party API - its exact response
    schema and rate limits can change; verify against
    https://docs.dexscreener.com before depending on this in production.
    Any failure degrades to ``liquidity_usd=None`` / unknown, never a
    fabricated number.
    """

    name = "dexscreener"

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_liquidity_profile(self, symbol: str, chain: str) -> TokenLiquidityProfile:
        import httpx

        url = f"{self.base_url}/latest/dex/search"
        try:
            resp = httpx.get(url, params={"q": symbol}, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            pairs = data.get("pairs") or []
        except Exception:
            logger.warning("DexScreener lookup failed for %s on %s; returning unknown profile", symbol, chain, exc_info=True)
            return TokenLiquidityProfile(symbol=symbol, liquidity_usd=None, is_concentrated=None, data_source="dexscreener_error")

        chain_pairs = [p for p in pairs if str(p.get("chainId", "")).lower() == chain.lower()]
        candidates = chain_pairs or pairs
        if not candidates:
            return TokenLiquidityProfile(
                symbol=symbol, liquidity_usd=None, is_concentrated=None,
                data_source="dexscreener", match_confidence=0.0,
            )

        best = max(candidates, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0.0)
        liquidity_usd = (best.get("liquidity") or {}).get("usd")
        match_confidence = 0.8 if chain_pairs else 0.4  # lower confidence if we had to guess across chains

        return TokenLiquidityProfile(
            symbol=symbol,
            liquidity_usd=liquidity_usd,
            is_concentrated=(liquidity_usd is not None and liquidity_usd < THIN_LIQUIDITY_USD_THRESHOLD),
            data_source="dexscreener",
            match_confidence=match_confidence,
        )


def _looks_like_address(value: str) -> bool:
    return value.startswith("0x") and len(value) == 42


def _bool_field(data: dict, key: str) -> Optional[bool]:
    val = data.get(key)
    if val is None:
        return None
    return val == "1"


class GoPlusTokenDataProvider:
    """Real trading-security data via the GoPlus Security Token Security API.

    Covers what liquidity-USD alone can't: honeypot detection, buy/sell
    tax, blacklist/pause functions, and holder concentration - the actual
    mechanisms scam tokens use, not just a proxy signal for them.

    GoPlus needs a contract address, but ``ActionIntent.to_token`` /
    ``from_token`` may carry either a symbol ("USDC") or an address
    ("0x..."). This provider uses the address directly when given one;
    for a bare symbol it honestly reports it cannot verify (via
    ``match_confidence=0.0``) rather than guessing which of several
    same-ticker tokens - real or fake - was meant. Have agents pass the
    contract address when precision matters.
    """

    name = "goplus"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def get_liquidity_profile(self, symbol: str, chain: str) -> TokenLiquidityProfile:
        if not _looks_like_address(symbol):
            return TokenLiquidityProfile(
                symbol=symbol, liquidity_usd=None, is_concentrated=None,
                data_source="goplus", match_confidence=0.0,
            )

        from guardian.intelligence.goplus_client import get_token_security

        data = get_token_security(chain, symbol, api_key=self.api_key)
        if data is None:
            return TokenLiquidityProfile(symbol=symbol, liquidity_usd=None, is_concentrated=None, data_source="goplus")

        if data.get("trust_list") == "1":
            return TokenLiquidityProfile(
                symbol=symbol, liquidity_usd=None, is_concentrated=False, data_source="goplus",
                is_trusted_listed=True,
            )

        buy_tax = _safe_float(data.get("buy_tax"))
        sell_tax = _safe_float(data.get("sell_tax"))
        top_holder_percent = _top_unlocked_holder_percent(data.get("holders") or [])
        has_dex_liquidity = _bool_field(data, "is_in_dex")

        return TokenLiquidityProfile(
            symbol=symbol,
            liquidity_usd=None,  # GoPlus doesn't return a $ figure the way DexScreener does
            is_concentrated=(has_dex_liquidity is False),  # holder concentration is its own signal below
            data_source="goplus",
            is_honeypot=_bool_field(data, "is_honeypot"),
            buy_tax=buy_tax,
            sell_tax=sell_tax,
            is_blacklistable=_bool_field(data, "is_blacklisted"),
            is_pausable=_bool_field(data, "transfer_pausable"),
            top_holder_percent=top_holder_percent,
            is_trusted_listed=False,
        )


def _safe_float(raw) -> Optional[float]:
    try:
        return float(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _top_unlocked_holder_percent(holders: list) -> Optional[float]:
    top = 0.0
    seen_any = False
    for h in holders:
        pct = _safe_float(h.get("percent"))
        if pct is None:
            continue
        seen_any = True
        if h.get("tag") != "Burn Address" and h.get("is_locked") != "1":
            top = max(top, pct)
    return top if seen_any else None
