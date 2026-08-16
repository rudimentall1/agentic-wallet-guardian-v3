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

``bridge`` is handled for L1 -> L2 deposits only, and only to
destinations in ``BRIDGE_CONTRACTS`` (currently: Base, Optimism) -
official OP Stack canonical bridges, one immutable contract per
destination, same "unambiguous well-known target" property as the
Uniswap V2 router above.
L2 -> L1 withdrawals are NOT handled - that's a genuinely different,
much slower two-step proof/challenge-window flow, not a variant of the
same deposit call. Bridging to any other chain, or any bridge protocol
other than a chain's own official OP Stack bridge, returns ``None``
rather than guessing at a contract this module hasn't specifically
verified.

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

# depositETHTo/depositERC20To on the OP Stack L1StandardBridge - source read
# directly from ethereum-optimism/optimism (develop branch,
# packages/contracts-bedrock/src/L1/L1StandardBridge.sol) to compute these,
# not copied from a third-party snippet.
DEPOSIT_ETH_TO_SELECTOR = "9a2ac6d5"  # depositETHTo(address,uint32,bytes)
DEPOSIT_ERC20_TO_SELECTOR = "838b2520"  # depositERC20To(address,address,address,uint256,uint32,bytes)

# L1StandardBridge on Ethereum mainnet, keyed by DESTINATION chain (this is
# an L1 contract - the deposit transaction itself always executes on
# Ethereum). Each address cross-checked against two independent sources
# before being hardcoded here - "base" against Etherscan's label plus
# basehub.org's canonical Base contract-address reference; "optimism"
# against the official ethereum-optimism/superchain-registry
# (L1StandardBridgeProxy for chain 10) plus a second, independent
# supersim.pages.dev dev-tool config that mirrors real mainnet addresses.
# Adding another destination means adding its own similarly-verified
# address, not assuming these two generalize.
BRIDGE_CONTRACTS: Dict[str, str] = {
    "base": "0x3154Cf16ccdb4C6d922629664174b904d80F2C35",
    "optimism": "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1",
}
DEFAULT_BRIDGE_MIN_GAS_LIMIT = 200_000  # a timing/gas knob, not value-affecting - same reasoning as swap's deadline default

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


def _encode_bytes_param(data: bytes) -> str:
    """ABI-encodes a dynamic `bytes` tail: length word, then the data
    right-padded to a 32-byte boundary."""
    length = _encode_uint256(len(data))
    hex_data = data.hex()
    padded_len = ((len(data) + 31) // 32) * 32 * 2  # hex chars, padded to 32-byte multiple
    return length + hex_data.ljust(padded_len, "0")


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
        if intent.action_type == "bridge":
            return self._build_bridge(intent)

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

    def _build_bridge(self, intent: ActionIntent) -> Optional[BuiltTransaction]:
        """L1 -> L2 deposit via an OP Stack L1StandardBridge - see
        BRIDGE_CONTRACTS for which destinations are supported. This is a
        deposit only: no withdrawal (L2 -> L1) support, which needs a
        completely different, much slower two-step proof/challenge flow
        this module doesn't attempt to model.
        """
        destination = intent.metadata.get("destination_chain")
        bridge = BRIDGE_CONTRACTS.get(destination) if destination else None
        if bridge is None:
            logger.info("No known canonical bridge to destination '%s' - not guessing one", destination)
            return None
        if intent.amount is None:
            return None

        recipient = intent.metadata.get("recipient", intent.wallet)
        if not _looks_like_address(recipient):
            return None

        min_gas_limit = intent.metadata.get("min_gas_limit", DEFAULT_BRIDGE_MIN_GAS_LIMIT)
        extra_data = intent.metadata.get("extra_data", b"")
        if isinstance(extra_data, str):
            extra_data = bytes.fromhex(extra_data[2:] if extra_data.startswith("0x") else extra_data)

        if intent.from_token is None:
            # Native ETH deposit.
            value = int(intent.amount * 10**18)
            head = (
                _encode_address_param(recipient)
                + _encode_uint256(min_gas_limit)
                + _encode_uint256(0x60)  # offset to extraData tail: 3 head words * 32 = 96 = 0x60
            )
            tail = _encode_bytes_param(extra_data)
            data = f"0x{DEPOSIT_ETH_TO_SELECTOR}{head}{tail}"
            return BuiltTransaction(
                data=data, value=value, to=bridge,
                reason=f"depositETHTo() on the canonical {destination} bridge, minGasLimit={min_gas_limit}",
            )

        # ERC-20 deposit - the L2-side token address can't be derived or
        # guessed from the L1 address; a wrong one here means tokens
        # minted to (or expected at) the wrong L2 contract entirely, not
        # just a bad risk signal. Same "refuse rather than guess" rule as
        # decimals and slippage elsewhere in this module.
        l2_token = intent.metadata.get("l2_token")
        if not _looks_like_address(l2_token):
            logger.warning("bridge intent for an ERC-20 has no metadata['l2_token'] - refusing to guess the L2-side token contract")
            return None
        if not _looks_like_address(intent.from_token):
            return None

        try:
            w3 = self._client(intent.chain)
        except Exception:
            logger.warning("Transaction builder setup failed for intent %s", intent.intent_id, exc_info=True)
            return None
        decimals = self._fetch_decimals(w3, intent.from_token)
        if decimals is None:
            return None
        amount_units = int(intent.amount * 10**decimals)

        head = (
            _encode_address_param(intent.from_token)
            + _encode_address_param(l2_token)
            + _encode_address_param(recipient)
            + _encode_uint256(amount_units)
            + _encode_uint256(min_gas_limit)
            + _encode_uint256(0xC0)  # offset to extraData tail: 6 head words * 32 = 192 = 0xc0
        )
        tail = _encode_bytes_param(extra_data)
        data = f"0x{DEPOSIT_ERC20_TO_SELECTOR}{head}{tail}"
        return BuiltTransaction(
            data=data, value=0, to=bridge,
            reason=f"depositERC20To() on the canonical {destination} bridge, minGasLimit={min_gas_limit}",
        )


def build_transaction_builder(config) -> TransactionBuilder:
    if getattr(config, "tx_builder_provider", "null") == "rpc":
        return RpcTransactionBuilder(rpc_urls=config.rpc_urls, timeout=config.provider_timeout_seconds)
    return NullTransactionBuilder()
