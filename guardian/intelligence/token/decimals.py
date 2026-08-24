"""Real ``decimals()`` lookups for ERC-20 tokens, via ``eth_call`` — never
guessed.

This closes a real gap: ``decision/intent_verification.py`` compares an
agent's declared ``approve``/``transfer`` amount against what the
simulated calldata actually encodes, but that comparison needs the
token's decimals to convert between "human" units (the agent said
"500") and atomic on-chain units (the calldata says "500000000" for a
6-decimal token). Before this module existed, ``DecisionEngine`` always
called that check with ``token_decimals=None`` — there was no
`decimals()` provider anywhere in the engine's own pipeline, even though
``RpcTransactionBuilder`` (see ``simulation/tx_builder.py``) already had
to solve the exact same problem to build calldata in the first place.
Intent verification degraded to an honest "cannot verify" WARN instead
of ever running its real mismatch-detection BLOCK.

Most tokens use 18 decimals, but not all — USDC/USDT-style tokens
commonly use 6, and assuming 18 would scale a comparison by orders of
magnitude in exactly the cases (stablecoins) most likely to be moving
real money. So this is fetched for real, the same "no silent guessing"
rule this codebase applies to slippage, bridge addresses, and encoding
elsewhere.

``decimals()`` is an ERC-20 view function that returns a constant for
the lifetime of a deployed contract (it isn't just unlikely to change —
there's no way to change it: ERC-20 doesn't define a setter, and the
overwhelming majority of tokens aren't upgradeable proxies around this
particular value). So a successful lookup is cached forever, keyed by
(chain, token_address) — this also means a shared cache between this
module and ``RpcTransactionBuilder`` avoids two independent components
making redundant RPC calls for the same popular token within one
process (see ``RpcTransactionBuilder.__init__``'s ``decimals_provider``
parameter).
"""
from __future__ import annotations

import logging
from typing import Dict, Optional, Protocol, Tuple

logger = logging.getLogger("guardian.token_decimals")

DECIMALS_SELECTOR = "313ce567"  # decimals() - standard ERC-20 view function


class TokenDecimalsProvider(Protocol):
    def get_decimals(self, token_address: str, chain: str) -> Optional[int]: ...


class NullTokenDecimalsProvider:
    """Zero-config default: never attempts a real lookup. Every caller of
    this Protocol already treats ``None`` as "can't verify, don't guess"
    rather than crashing or assuming 18 — see intent_verification.py."""

    name = "null"

    def get_decimals(self, token_address: str, chain: str) -> Optional[int]:
        return None


class RpcTokenDecimalsProvider:
    """Real ``decimals()`` lookup via ``eth_call``, cached forever per
    (chain, token_address) — see module docstring for why caching
    forever is correct here, not just an optimization.

    Requires the ``web3`` package (see ``requirements-chain.txt``) and an
    RPC endpoint for the target chain — the same ``GUARDIAN_RPC_<CHAIN>``
    config every other Rpc* provider in this codebase uses.
    """

    name = "rpc"

    def __init__(self, rpc_urls: Dict[str, str], timeout: float = 5.0):
        self.rpc_urls = rpc_urls
        self.timeout = timeout
        self._clients: Dict[str, object] = {}
        self._cache: Dict[Tuple[str, str], Optional[int]] = {}

    def _client(self, chain: str):
        if chain in self._clients:
            return self._clients[chain]
        url = self.rpc_urls.get(chain)
        if not url:
            raise ValueError(f"No RPC URL configured for chain '{chain}'. Set GUARDIAN_RPC_{chain.upper()}.")
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": self.timeout}))
        self._clients[chain] = w3
        return w3

    def get_decimals(self, token_address: str, chain: str) -> Optional[int]:
        if not token_address:
            return None
        cache_key = (chain, token_address.lower())
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            w3 = self._client(chain)
            checksum = w3.to_checksum_address(token_address)
            result = w3.eth.call({"to": checksum, "data": f"0x{DECIMALS_SELECTOR}"})
            decimals = int.from_bytes(result, byteorder="big")
        except Exception:
            # Deliberately NOT cached: a transient RPC/network failure
            # today shouldn't permanently poison the cache for a token
            # that would resolve fine on the next real attempt - only a
            # genuine, successful on-chain read (which can never change)
            # earns a permanent cache entry.
            logger.warning(
                "Could not fetch decimals() for %s on %s - not caching this miss",
                token_address, chain, exc_info=True,
            )
            return None

        self._cache[cache_key] = decimals
        return decimals


def build_token_decimals_provider(config) -> TokenDecimalsProvider:
    if getattr(config, "decimals_provider", "null") == "rpc":
        return RpcTokenDecimalsProvider(rpc_urls=config.rpc_urls, timeout=config.provider_timeout_seconds)
    return NullTokenDecimalsProvider()
