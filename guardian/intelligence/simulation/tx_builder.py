"""Builds real transaction calldata from a semantic ``ActionIntent``, so
that ``RpcSimulationProvider`` (which needs actual calldata - see its
docstring) has something to dry-run even when the caller only described
*what* they want to do, not the exact bytes to send.

Deliberately narrow scope, and deliberately no hardcoded token-address
registry: getting a token contract address wrong here isn't just a bad
risk signal, it's an artifact that could end up in a real transaction. So
this only builds ``transfer`` and ``approve`` - the two action types where
the semantics are simple enough to encode exactly - and only when
``from_token`` is already a contract address (or left unset, meaning the
chain's native currency) rather than a bare symbol. Decimals are fetched
for real via ``eth_call`` to the token's own ``decimals()`` - never
assumed (most tokens use 18, but not all: USDC/USDT-style tokens commonly
use 6, and getting this wrong would scale the amount incorrectly by
orders of magnitude).

``swap`` and ``bridge`` are NOT handled here - building those correctly
means real DEX/bridge routing (liquidity sourcing, price impact,
slippage), which is a categorically bigger problem than encoding a single
well-known function call, and is a separate concern from what this
project set out to solve. Guardian evaluates a transaction; it
deliberately doesn't construct complex ones for you.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional, Protocol

from guardian.core.intent import ActionIntent

logger = logging.getLogger("guardian.tx_builder")

TRANSFER_SELECTOR = "a9059cbb"  # transfer(address,uint256)
APPROVE_SELECTOR = "095ea7b3"  # approve(address,uint256)
DECIMALS_SELECTOR = "313ce567"  # decimals() - standard ERC-20 view function
UNLIMITED_APPROVAL = 2**256 - 1


@dataclass
class BuiltTransaction:
    data: str
    value: int
    reason: str  # short note on what was built, for logging/debugging - not a Signal


class TransactionBuilder(Protocol):
    def build(self, intent: ActionIntent) -> Optional[BuiltTransaction]: ...


class NullTransactionBuilder:
    """Zero-config default: never builds anything. Intents without
    metadata["data"] simply go through simulation as "not attempted", same
    as before this feature existed."""

    name = "null"

    def build(self, intent: ActionIntent) -> Optional[BuiltTransaction]:
        return None


def _looks_like_address(value: Optional[str]) -> bool:
    return bool(value) and value.startswith("0x") and len(value) == 42


def _encode_uint256(value: int) -> str:
    return format(value, "064x")


def _encode_address_param(address: str) -> str:
    return address[2:].lower().rjust(64, "0")


class RpcTransactionBuilder:
    """Builds real calldata for ``transfer``/``approve`` intents via RPC.

    Requires the ``web3`` package (see ``requirements-chain.txt``) and an
    RPC endpoint for the target chain - the same ``GUARDIAN_RPC_<CHAIN>``
    config ``RpcWalletDataProvider``/``RpcSimulationProvider`` use.
    """

    name = "rpc"

    def __init__(self, rpc_urls: Dict[str, str], timeout: float = 5.0):
        self.rpc_urls = rpc_urls
        self.timeout = timeout
        self._clients: Dict[str, object] = {}

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

    def _fetch_decimals(self, w3, token_address: str) -> Optional[int]:
        try:
            checksum = w3.to_checksum_address(token_address)
            result = w3.eth.call({"to": checksum, "data": f"0x{DECIMALS_SELECTOR}"})
            return int.from_bytes(result, byteorder="big")
        except Exception:
            logger.warning("Could not fetch decimals() for %s - not building calldata without it", token_address, exc_info=True)
            return None

    def build(self, intent: ActionIntent) -> Optional[BuiltTransaction]:
        if intent.action_type not in ("transfer", "approve"):
            return None
        if not intent.target:
            return None

        # Native-currency transfer: no token contract involved, no calldata needed.
        if intent.action_type == "transfer" and not intent.from_token:
            if intent.amount is None:
                return None
            value = int(intent.amount * 10**18)
            return BuiltTransaction(data="0x", value=value, reason="native currency transfer")

        if not _looks_like_address(intent.from_token):
            # A bare symbol ("USDC") isn't enough to build real calldata -
            # see module docstring for why this deliberately isn't guessed at.
            return None

        try:
            w3 = self._client(intent.chain)
        except Exception:
            logger.warning("Transaction builder setup failed for intent %s", intent.intent_id, exc_info=True)
            return None

        if intent.action_type == "approve":
            if intent.amount is None:
                amount_units = UNLIMITED_APPROVAL
            else:
                decimals = self._fetch_decimals(w3, intent.from_token)
                if decimals is None:
                    return None
                amount_units = int(intent.amount * 10**decimals)
            data = f"0x{APPROVE_SELECTOR}{_encode_address_param(intent.target)}{_encode_uint256(amount_units)}"
            return BuiltTransaction(data=data, value=0, reason="approve() with a real decimals() lookup")

        # transfer of an ERC-20 token
        if intent.amount is None:
            return None
        decimals = self._fetch_decimals(w3, intent.from_token)
        if decimals is None:
            return None
        amount_units = int(intent.amount * 10**decimals)
        data = f"0x{TRANSFER_SELECTOR}{_encode_address_param(intent.target)}{_encode_uint256(amount_units)}"
        return BuiltTransaction(data=data, value=0, reason="ERC-20 transfer() with a real decimals() lookup")


def build_transaction_builder(config) -> TransactionBuilder:
    if getattr(config, "tx_builder_provider", "null") == "rpc":
        return RpcTransactionBuilder(rpc_urls=config.rpc_urls, timeout=config.provider_timeout_seconds)
    return NullTransactionBuilder()
