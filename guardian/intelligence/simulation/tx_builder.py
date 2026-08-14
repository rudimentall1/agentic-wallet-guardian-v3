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

``bridge`` is NOT handled here - cross-chain bridging has no single
well-known, immutable contract the way Uniswap V2 does; building it
correctly means picking (and trusting) a specific bridge protocol, which
is a project-specific decision this generic builder shouldn't make for
you.

``swap`` is handled, but only against Uniswap V2 Router02 - the most
widely deployed, unmodified-since-launch router contract, so its
function selectors are a fixed, well-known target rather than a moving
one. The expected output amount is fetched for real via ``getAmountsOut``
(an actual on-chain quote, not an off-chain price feed guess), and the
caller MUST supply ``max_slippage_bps`` explicitly via
``intent.metadata`` - there is no default slippage tolerance, because
guessing one is exactly the kind of silent, consequential assumption
this module refuses to make elsewhere (see the module-level note on
decimals above). No calldata is built if the quote, the router address
for this chain, or the slippage tolerance aren't all real and present.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional, Protocol

from guardian.core.intent import ActionIntent

logger = logging.getLogger("guardian.tx_builder")

TRANSFER_SELECTOR = "a9059cbb"  # transfer(address,uint256)
APPROVE_SELECTOR = "095ea7b3"  # approve(address,uint256)
DECIMALS_SELECTOR = "313ce567"  # decimals() - standard ERC-20 view function
UNLIMITED_APPROVAL = 2**256 - 1

# Both computed locally via Web3.keccak(text=signature)[:4] - not copied from
# memory or a third-party snippet - see tests/test_tx_builder.py for the
# same computation, so a future contributor can re-derive and check these
# rather than trust them blindly.
SWAP_EXACT_TOKENS_SELECTOR = "38ed1739"  # swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
GET_AMOUNTS_OUT_SELECTOR = "d06ca61f"  # getAmountsOut(uint256,address[])

# Uniswap V2 Router02 - unmodified since deployment, same address across
# every chain it's deployed to (CREATE2 + identical bytecode/deployer).
# Deliberately only chains where this specific address is the *actual*
# canonical Uniswap V2 Router02 deployment - not a guess, not "probably
# the same everywhere." A chain missing from this map means "swap" builds
# nothing there rather than silently targeting the wrong contract.
UNISWAP_V2_ROUTER02 = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
DEFAULT_ROUTER_ADDRESSES: Dict[str, str] = {
    "ethereum": UNISWAP_V2_ROUTER02,
}


@dataclass
class BuiltTransaction:
    data: str
    value: int
    reason: str  # short note on what was built, for logging/debugging - not a Signal
    to: Optional[str] = None  # the actual contract simulation should eth_call
    # against - NOT necessarily intent.target. For an ERC-20 transfer/
    # approve, intent.target is the recipient/spender encoded *inside* the
    # calldata, while the transaction's real "to" is the token contract
    # (from_token). Conflating the two means simulating against the wrong
    # address - see the regression test and providers.py for what that
    # silently breaks.


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


def _encode_address_array(addresses) -> str:
    """ABI-encodes a dynamic `address[]` tail: length word, then one
    32-byte word per address. Caller is responsible for the head word
    that points to this tail's offset."""
    length = _encode_uint256(len(addresses))
    body = "".join(_encode_address_param(a) for a in addresses)
    return length + body


class RpcTransactionBuilder:
    """Builds real calldata for ``transfer``/``approve`` intents via RPC.

    Requires the ``web3`` package (see ``requirements-chain.txt``) and an
    RPC endpoint for the target chain - the same ``GUARDIAN_RPC_<CHAIN>``
    config ``RpcWalletDataProvider``/``RpcSimulationProvider`` use.
    """

    name = "rpc"

    def __init__(self, rpc_urls: Dict[str, str], timeout: float = 5.0, router_addresses: Optional[Dict[str, str]] = None):
        self.rpc_urls = rpc_urls
        self.timeout = timeout
        self._clients: Dict[str, object] = {}
        self.router_addresses = router_addresses or DEFAULT_ROUTER_ADDRESSES

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
        if intent.action_type == "swap":
            return self._build_swap(intent)

        if intent.action_type not in ("transfer", "approve"):
            return None
        if not intent.target:
            return None

        # Native-currency transfer: no token contract involved, no calldata needed.
        if intent.action_type == "transfer" and not intent.from_token:
            if intent.amount is None:
                return None
            value = int(intent.amount * 10**18)
            return BuiltTransaction(data="0x", value=value, reason="native currency transfer", to=intent.target)

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
            return BuiltTransaction(data=data, value=0, reason="approve() with a real decimals() lookup", to=intent.from_token)

        # transfer of an ERC-20 token
        if intent.amount is None:
            return None
        decimals = self._fetch_decimals(w3, intent.from_token)
        if decimals is None:
            return None
        amount_units = int(intent.amount * 10**decimals)
        data = f"0x{TRANSFER_SELECTOR}{_encode_address_param(intent.target)}{_encode_uint256(amount_units)}"
        return BuiltTransaction(data=data, value=0, reason="ERC-20 transfer() with a real decimals() lookup", to=intent.from_token)

    def _fetch_amounts_out(self, w3, router: str, amount_in_units: int, path) -> Optional[int]:
        """Real on-chain quote via the router's own getAmountsOut - never a
        cached/off-chain price feed, which could be stale relative to the
        pool this swap will actually execute against."""
        try:
            checksum_router = w3.to_checksum_address(router)
            calldata = (
                f"0x{GET_AMOUNTS_OUT_SELECTOR}"
                f"{_encode_uint256(amount_in_units)}"
                f"{_encode_uint256(0x40)}"  # offset to the path array (2 head words = 0x40)
                f"{_encode_address_array(path)}"
            )
            result = w3.eth.call({"to": checksum_router, "data": calldata})
            # Return layout: [offset(32) | length(32) | amounts...(32 each)].
            # We want the LAST amount - the output of the final hop.
            if len(result) < 96:
                return None
            num_amounts = int.from_bytes(result[32:64], byteorder="big")
            last_amount_start = 32 + 32 + (num_amounts - 1) * 32
            return int.from_bytes(result[last_amount_start:last_amount_start + 32], byteorder="big")
        except Exception:
            logger.warning("getAmountsOut() call failed - not building swap calldata without a real quote", exc_info=True)
            return None

    def _build_swap(self, intent: ActionIntent) -> Optional[BuiltTransaction]:
        if not _looks_like_address(intent.from_token) or not _looks_like_address(intent.to_token):
            # Bare symbols aren't enough to build a real path - same rule
            # as transfer/approve above.
            return None
        if intent.amount is None:
            return None

        router = self.router_addresses.get(intent.chain)
        if router is None:
            logger.info("No known Uniswap V2 Router02 for chain '%s' - not guessing one", intent.chain)
            return None

        max_slippage_bps = intent.metadata.get("max_slippage_bps")
        if max_slippage_bps is None:
            logger.warning("swap intent has no metadata['max_slippage_bps'] - refusing to assume a slippage tolerance")
            return None
        if not (0 <= max_slippage_bps <= 10_000):
            logger.warning("max_slippage_bps=%s is out of the valid 0-10000 range - refusing to build with a nonsensical tolerance", max_slippage_bps)
            return None

        try:
            w3 = self._client(intent.chain)
        except Exception:
            logger.warning("Transaction builder setup failed for intent %s", intent.intent_id, exc_info=True)
            return None

        from_decimals = self._fetch_decimals(w3, intent.from_token)
        if from_decimals is None:
            return None
        amount_in_units = int(intent.amount * 10**from_decimals)

        path = [intent.from_token, intent.to_token]
        amount_out = self._fetch_amounts_out(w3, router, amount_in_units, path)
        if amount_out is None:
            # No real quote available - most likely no liquidity for this
            # pair, or a routing problem this single-hop path can't solve.
            # Building calldata anyway would mean guessing a minAmountOut,
            # which is exactly the kind of silent assumption this module
            # exists to avoid.
            return None

        min_amount_out = amount_out * (10_000 - max_slippage_bps) // 10_000

        recipient = intent.metadata.get("recipient", intent.wallet)
        if not _looks_like_address(recipient):
            return None
        deadline_seconds = intent.metadata.get("deadline_seconds_from_now", 1200)  # 20 min default - a timing knob, not a value-affecting one like slippage/decimals
        deadline = int(time.time()) + int(deadline_seconds)

        head = (
            _encode_uint256(amount_in_units)
            + _encode_uint256(min_amount_out)
            + _encode_uint256(0xA0)  # offset to path tail: 5 head words * 32 bytes = 160 = 0xa0
            + _encode_address_param(recipient)
            + _encode_uint256(deadline)
        )
        tail = _encode_address_array(path)
        data = f"0x{SWAP_EXACT_TOKENS_SELECTOR}{head}{tail}"
        return BuiltTransaction(
            data=data, value=0,
            to=router,
            reason=(
                f"swapExactTokensForTokens via Uniswap V2 Router02: real getAmountsOut() quote "
                f"({amount_out} atomic units out), {max_slippage_bps}bps max slippage -> "
                f"minAmountOut={min_amount_out}"
            ),
        )


def build_transaction_builder(config) -> TransactionBuilder:
    if getattr(config, "tx_builder_provider", "null") == "rpc":
        return RpcTransactionBuilder(rpc_urls=config.rpc_urls, timeout=config.provider_timeout_seconds)
    return NullTransactionBuilder()
