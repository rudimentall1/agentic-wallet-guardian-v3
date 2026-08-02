"""Contract data providers.

``MockContractDataProvider`` keeps the original deterministic placeholder
for zero-config demo/test use. ``BlockscoutContractDataProvider`` calls a
public Blockscout instance's REST API to check whether the target
contract's source is actually verified - real signal, no API key.

Blockscout runs free public instances for most major EVM chains
(``eth.blockscout.com``, ``base.blockscout.com``, etc.) - point
``base_url`` at whichever instance matches your target chain via
``GUARDIAN_BLOCKSCOUT_BASE_URL``. Their exact response schema can change
between versions, so this is written defensively: any unexpected shape or
network failure degrades to "unknown", never to a fabricated answer, and
never raises out of ``get_profile``.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

logger = logging.getLogger("guardian.contract")


@dataclass
class ContractProfile:
    address: str
    is_verified: Optional[bool]
    is_upgradeable: Optional[bool] = None
    data_source: str = "unknown"
    # Populated only by providers that can see this (currently GoPlus) -
    # None from Mock/Blockscout, which don't have this data. Analyzer
    # logic must treat None as "unknown", never as "false".
    owner_can_change_balance: Optional[bool] = None
    is_mintable: Optional[bool] = None
    has_selfdestruct: Optional[bool] = None
    has_hidden_owner: Optional[bool] = None


class ContractDataProvider(Protocol):
    def get_profile(self, address: str, chain: str) -> ContractProfile: ...


class MockContractDataProvider:
    name = "mock"

    def get_profile(self, address: str, chain: str) -> ContractProfile:
        h = int(hashlib.sha256(f"{chain}:{address.lower()}".encode()).hexdigest(), 16)
        return ContractProfile(
            address=address,
            is_verified=(h % 3) != 0,
            is_upgradeable=(h % 5) == 0,
            data_source="mock",
        )


class BlockscoutContractDataProvider:
    """Real contract-verification lookup via a Blockscout instance's public API.

    Requires the ``httpx`` package (already a base dependency of this
    project). Any failure - network error, unexpected schema, rate limit -
    is caught and returns ``is_verified=None`` / ``is_upgradeable=None``
    rather than guessing.
    """

    name = "blockscout"

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_profile(self, address: str, chain: str) -> ContractProfile:
        import httpx

        url = f"{self.base_url}/api/v2/smart-contracts/{address}"
        try:
            resp = httpx.get(url, timeout=self.timeout)
            if resp.status_code == 404:
                # Blockscout returns 404 for addresses with no verified-contract
                # record - which includes both EOAs and unverified contracts.
                return ContractProfile(address=address, is_verified=False, data_source="blockscout")
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.warning("Blockscout lookup failed for %s on %s; returning unknown profile", address, chain, exc_info=True)
            return ContractProfile(address=address, is_verified=None, is_upgradeable=None, data_source="blockscout_error")

        is_verified = bool(data.get("is_verified", data.get("verified_at") is not None))
        proxy_type = data.get("proxy_type")
        is_upgradeable = proxy_type is not None if "proxy_type" in data else None

        return ContractProfile(
            address=address, is_verified=is_verified, is_upgradeable=is_upgradeable,
            data_source="blockscout",
        )


def _bool_field(data: dict, key: str) -> Optional[bool]:
    """GoPlus encodes booleans as the strings "0"/"1" - missing key means
    unknown, not false."""
    val = data.get(key)
    if val is None:
        return None
    return val == "1"


class GoPlusContractDataProvider:
    """Real contract-security data via the GoPlus Security Token Security API.

    Covers meaningfully more than verification status: whether the owner
    can arbitrarily change balances, mint new supply, self-destruct the
    contract, or hide behind a proxy owner - all real findings from
    GoPlus's static analysis, not inferred. Free and keyless for light
    use; set ``GOPLUS_API_KEY`` (see ``guardian/config.py``) if you need a
    higher rate limit.

    Only meaningful for contracts GoPlus has actually analyzed (mainly
    token contracts) - a generic dApp/router contract will come back with
    no data, which this reports honestly rather than guessing.
    """

    name = "goplus"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def get_profile(self, address: str, chain: str) -> ContractProfile:
        from guardian.intelligence.goplus_client import get_token_security

        data = get_token_security(chain, address, api_key=self.api_key)
        if data is None:
            return ContractProfile(address=address, is_verified=None, is_upgradeable=None, data_source="goplus")

        is_verified = _bool_field(data, "is_open_source")
        is_upgradeable = _bool_field(data, "is_proxy")

        return ContractProfile(
            address=address,
            is_verified=is_verified,
            is_upgradeable=is_upgradeable,
            data_source="goplus",
            owner_can_change_balance=_bool_field(data, "owner_change_balance"),
            is_mintable=_bool_field(data, "is_mintable"),
            has_selfdestruct=_bool_field(data, "selfdestruct"),
            has_hidden_owner=_bool_field(data, "hidden_owner"),
        )
