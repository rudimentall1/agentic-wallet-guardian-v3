"""Contract intelligence analyzer.

Checks the target contract against local allow/deny lists first (see
``guardian/intelligence/threat/blocklist.py``), then falls back to a
``ContractDataProvider`` for anything unlisted - the mock heuristic by
default, ``BlockscoutContractDataProvider`` for verification status, or
``GoPlusContractDataProvider`` for real contract-security findings
(owner-can-drain, mintable, self-destruct, hidden owner). Select via
``GUARDIAN_CONTRACT_PROVIDER`` (``mock`` | ``blockscout`` | ``goplus``) -
see ``guardian/config.py``.
"""
from __future__ import annotations

from typing import List, Optional

from guardian.core.models import Signal
from guardian.intelligence.contract.providers import (
    BlockscoutContractDataProvider,
    ContractDataProvider,
    GoPlusContractDataProvider,
    MockContractDataProvider,
)
from guardian.intelligence.threat.blocklist import AddressList


def build_contract_provider(config) -> ContractDataProvider:
    if config.contract_provider == "blockscout":
        return BlockscoutContractDataProvider(
            base_url=config.blockscout_base_url, timeout=config.provider_timeout_seconds,
        )
    if config.contract_provider == "goplus":
        return GoPlusContractDataProvider(api_key=config.goplus_api_key)
    return MockContractDataProvider()


class ContractAnalyzer:
    source = "contract"

    def __init__(
        self,
        provider: Optional[ContractDataProvider] = None,
        known_safe: Optional[AddressList] = None,
        known_malicious: Optional[AddressList] = None,
    ):
        self.provider = provider or MockContractDataProvider()
        self.known_safe = known_safe or AddressList("data/threat_lists/verified_contracts.json")
        self.known_malicious = known_malicious or AddressList("data/threat_lists/malicious_contracts.json")

    def analyze(self, contract_address: Optional[str], chain: str) -> List[Signal]:
        if not contract_address:
            return []

        addr = contract_address.lower()

        if addr in self.known_malicious:
            return [Signal(
                source=self.source, name="known_malicious_contract", score=100, weight=5.0,
                confidence=0.95,
                reason=f"Target contract is on the local deny-list ({self.known_malicious.label_for(addr)})",
            )]

        if addr in self.known_safe:
            return [Signal(
                source=self.source, name="known_safe_contract", score=2, weight=1.0,
                confidence=0.9,
                reason=f"Target contract is on the local allow-list ({self.known_safe.label_for(addr)})",
            )]

        profile = self.provider.get_profile(contract_address, chain)
        mock_note = " (mock data source)" if profile.data_source == "mock" else ""
        signals: List[Signal] = []

        if profile.is_verified is None:
            signals.append(Signal(
                source=self.source, name="verification_status_unknown", score=30, weight=0.6,
                confidence=0.4,
                reason="Contract verification status could not be determined from the configured data source",
            ))
        elif profile.is_verified:
            signals.append(Signal(
                source=self.source, name="verified_contract", score=10, weight=0.8,
                confidence=0.6, reason=f"Target contract source is verified{mock_note}",
            ))
        else:
            signals.append(Signal(
                source=self.source, name="unverified_contract", score=55, weight=1.5,
                confidence=0.6, reason=f"Target contract source is not verified{mock_note}",
            ))

        if profile.is_upgradeable:
            signals.append(Signal(
                source=self.source, name="upgradeable_contract", score=40, weight=1.2,
                confidence=0.5,
                reason="Contract uses an upgradeable proxy pattern - logic can change after approval",
            ))

        # Only ever set by providers that can actually see this (GoPlus) -
        # Mock/Blockscout leave these None, so no signal fires for them.
        if profile.owner_can_change_balance:
            signals.append(Signal(
                source=self.source, name="owner_can_change_balances", score=85, weight=2.5,
                confidence=0.8,
                reason="Contract owner can arbitrarily change holder balances - a direct rug vector",
            ))

        if profile.is_mintable:
            signals.append(Signal(
                source=self.source, name="mintable_supply", score=45, weight=1.0,
                confidence=0.7,
                reason="Contract owner can mint new supply, diluting existing holders at will",
            ))

        if profile.has_selfdestruct:
            signals.append(Signal(
                source=self.source, name="has_selfdestruct", score=70, weight=1.8,
                confidence=0.8,
                reason="Contract contains a self-destruct function that can remove its code and funds",
            ))

        if profile.has_hidden_owner:
            signals.append(Signal(
                source=self.source, name="hidden_owner", score=55, weight=1.3,
                confidence=0.6,
                reason="Contract owner is obfuscated - harder to assess who actually controls it",
            ))

        return signals
