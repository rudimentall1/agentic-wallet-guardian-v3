"""Token intelligence analyzer.

Delegates liquidity/security data to a ``TokenDataProvider`` - the mock
generator by default, ``DexScreenerTokenDataProvider`` for real liquidity
data, or ``GoPlusTokenDataProvider`` for real trading-security data
(honeypot, tax, blacklist, holder concentration). Select via
``GUARDIAN_TOKEN_PROVIDER`` (``mock`` | ``dexscreener`` | ``goplus``).
"""
from __future__ import annotations

from typing import List, Optional

from guardian.core.models import Signal
from guardian.intelligence.token.providers import (
    DexScreenerTokenDataProvider,
    GoPlusTokenDataProvider,
    MockTokenDataProvider,
    TokenDataProvider,
)

# Real, not mock: widely-held major assets don't need a liquidity lookup at
# all - skipping the provider call here also means one fewer external
# request on the most common path (agents swapping into/out of stables).
MAJOR_TOKENS = {"ETH", "WETH", "USDC", "USDT", "DAI", "WBTC", "SOL", "USDS"}

# Below this, a buy/sell tax is worth flagging - legitimate tokens
# sometimes have a small tax, scam tokens often have an extreme one.
NOTABLE_TAX_THRESHOLD = 0.10


def build_token_provider(config) -> TokenDataProvider:
    if config.token_provider == "dexscreener":
        return DexScreenerTokenDataProvider(
            base_url=config.dexscreener_base_url, timeout=config.provider_timeout_seconds,
        )
    if config.token_provider == "goplus":
        return GoPlusTokenDataProvider(api_key=config.goplus_api_key)
    return MockTokenDataProvider()


class TokenAnalyzer:
    source = "token"

    def __init__(self, provider: Optional[TokenDataProvider] = None):
        self.provider = provider or MockTokenDataProvider()

    def analyze(self, symbol: Optional[str], chain: str) -> List[Signal]:
        if not symbol:
            return []

        if symbol.upper() in MAJOR_TOKENS:
            return [Signal(
                source=self.source, name="major_token", score=2, weight=1.0,
                confidence=0.95, reason=f"{symbol.upper()} is a widely-held, liquid asset",
            )]

        profile = self.provider.get_liquidity_profile(symbol, chain)
        mock_note = " (mock data source)" if profile.data_source == "mock" else ""

        if profile.match_confidence < 0.5:
            return [Signal(
                source=self.source, name="token_match_uncertain", score=20, weight=0.4,
                confidence=0.3,
                reason=f"Could not confidently match ticker '{symbol}' to a specific on-chain pair "
                       f"- ticker symbols are not unique and are often impersonated",
            )]

        if profile.is_trusted_listed:
            return [Signal(
                source=self.source, name="trusted_listed_token", score=3, weight=1.0,
                confidence=0.85, reason="Token is on GoPlus's trusted-asset list",
            )]

        signals: List[Signal] = []

        # $-denominated liquidity (mock/DexScreener). GoPlus doesn't return
        # a dollar figure, so it never lands in this branch - its own
        # liquidity signal (has_dex_liquidity, via is_concentrated) is
        # handled separately below instead of being forced through a
        # message that assumes a dollar amount exists.
        if profile.data_source != "goplus":
            if profile.liquidity_usd is None:
                signals.append(Signal(
                    source=self.source, name="liquidity_unknown", score=15, weight=0.4,
                    confidence=0.4,
                    reason="Token liquidity could not be determined from the configured data source",
                ))
            elif profile.is_concentrated:
                signals.append(Signal(
                    source=self.source, name="thin_liquidity", score=60, weight=1.3,
                    confidence=0.7,
                    reason=f"Token liquidity is thin (${profile.liquidity_usd:,.0f}){mock_note} "
                           f"- price impact and rug risk are both higher",
                ))
            else:
                signals.append(Signal(
                    source=self.source, name="adequate_liquidity", score=5, weight=0.6,
                    confidence=0.7, reason=f"Token liquidity looks adequate (${profile.liquidity_usd:,.0f}){mock_note}",
                ))

        # Below: only ever set by providers that can see this (GoPlus) -
        # Mock/DexScreener leave these None, so nothing fires for them.
        if profile.is_honeypot:
            signals.append(Signal(
                source=self.source, name="honeypot", score=100, weight=5.0,
                confidence=0.9, reason="Token is flagged as a honeypot - likely cannot be sold once bought",
            ))

        if profile.is_concentrated and profile.data_source == "goplus":
            signals.append(Signal(
                source=self.source, name="no_dex_liquidity", score=50, weight=1.0,
                confidence=0.6, reason="Token has no liquidity pool with a mainstream asset",
            ))

        for tax, label in ((profile.buy_tax, "buy"), (profile.sell_tax, "sell")):
            if tax is not None and tax >= NOTABLE_TAX_THRESHOLD:
                severity = 90 if tax >= 0.5 else 40 + int(tax * 60)
                signals.append(Signal(
                    source=self.source, name=f"high_{label}_tax", score=severity, weight=1.3,
                    confidence=0.7, reason=f"{label.capitalize()} tax is {tax:.0%}",
                ))

        if profile.is_blacklistable:
            signals.append(Signal(
                source=self.source, name="has_blacklist_function", score=45, weight=1.2,
                confidence=0.6, reason="Contract can blacklist addresses from trading",
            ))

        if profile.is_pausable:
            signals.append(Signal(
                source=self.source, name="transfer_pausable", score=45, weight=1.2,
                confidence=0.6, reason="Contract owner can pause all trading at will",
            ))

        if profile.top_holder_percent is not None and profile.top_holder_percent >= 0.20:
            signals.append(Signal(
                source=self.source, name="holder_concentration",
                score=min(90, 30 + int(profile.top_holder_percent * 100)), weight=1.2, confidence=0.6,
                reason=f"A single unlocked holder controls {profile.top_holder_percent:.0%} of supply",
            ))

        if not signals:
            signals.append(Signal(
                source=self.source, name="no_token_risk_indicators", score=8, weight=0.5,
                confidence=0.6, reason="No token-level risk indicators found",
            ))

        return signals
