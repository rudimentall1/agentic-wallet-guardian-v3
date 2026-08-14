"""Pre-execution simulation providers.

Real simulation needs something concrete to execute: the actual calldata,
value, and target of the transaction the agent is about to send - not just
the high-level semantic description ("swap 5 ETH for USDC") that
``ActionIntent`` carries by default. So this only activates for callers
that pass the raw transaction fields through ``intent.metadata``::

    ActionIntent(..., metadata={"data": "0x095ea7b3...", "value": 0})

When that's present, ``RpcSimulationProvider`` dry-runs it for real via
``eth_call`` against current chain state - no forked node, no paid API,
just the RPC endpoint you already configured for
``RpcWalletDataProvider``. This tells you, with certainty rather than a
statistical guess, whether the transaction would revert right now, and
decodes the exact approval amount for ERC-20 ``approve`` calls instead of
inferring "unlimited" from the intent's semantic ``amount`` field.

When no calldata is supplied - the common case for a high-level intent
that hasn't been built into a transaction yet - this honestly reports
"not attempted" rather than guessing. That gap is real and worth knowing
about: a simulation signal that's silently skipped is very different from
one that ran and came back clean.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional, Protocol

from guardian.core.intent import ActionIntent

logger = logging.getLogger("guardian.simulation")

ERC20_APPROVE_SELECTOR = "095ea7b3"
# The canonical "infinite approval" value many wallets/dApps use
# (2**256 - 1, or values close enough to it to be functionally unlimited).
NEAR_MAX_UINT256 = 2**255


@dataclass
class SimulationResult:
    attempted: bool
    would_revert: Optional[bool] = None
    revert_reason: Optional[str] = None
    gas_estimate: Optional[int] = None
    decoded_approval_amount: Optional[int] = None
    is_unlimited_approval: Optional[bool] = None
    error: Optional[str] = None


class SimulationProvider(Protocol):
    def simulate(self, intent: ActionIntent) -> SimulationResult: ...


class NullSimulationProvider:
    """Zero-config default: never attempts a real dry run."""

    name = "null"

    def simulate(self, intent: ActionIntent) -> SimulationResult:
        return SimulationResult(attempted=False)


def _decode_approve_amount(calldata: str) -> Optional[int]:
    data = calldata[2:] if calldata.startswith("0x") else calldata
    if not data.lower().startswith(ERC20_APPROVE_SELECTOR):
        return None
    # selector (4 bytes / 8 hex chars) + spender (32 bytes) + amount (32 bytes)
    if len(data) < 8 + 64 + 64:
        return None
    amount_hex = data[8 + 64: 8 + 64 + 64]
    try:
        return int(amount_hex, 16)
    except ValueError:
        return None


class RpcSimulationProvider:
    """Real pre-execution dry run via ``eth_call`` / ``eth_estimateGas``.

    Requires the ``web3`` package (see ``requirements-chain.txt``) and an
    RPC endpoint for the target chain (``GUARDIAN_RPC_<CHAIN>`` - the same
    config ``RpcWalletDataProvider`` uses).
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

    def simulate(self, intent: ActionIntent) -> SimulationResult:
        # `intent.target` here MUST already be the real contract this call
        # goes "to" - the token contract for an ERC-20 transfer/approve, the
        # router for a swap, or the recipient for a plain native transfer.
        # It is NOT necessarily the same as the target the caller
        # originally supplied (e.g. an ERC-20 recipient/spender, which is
        # encoded *inside* calldata, not the call's own "to"). DecisionEngine
        # overwrites target with `BuiltTransaction.to` before calling this
        # when it built the calldata itself - see engine.py and
        # tx_builder.py. A caller supplying pre-built calldata directly
        # (bypassing tx_builder) is responsible for getting this right;
        # get it wrong and this dry-runs the wrong contract, and - for an
        # EOA target especially - silently "succeeds" every time instead of
        # ever catching a real revert.
        calldata = intent.metadata.get("data")
        if not calldata or not intent.target:
            return SimulationResult(attempted=False)

        value = intent.metadata.get("value", 0)
        decoded_amount = _decode_approve_amount(calldata) if intent.action_type == "approve" else None
        is_unlimited = decoded_amount is not None and decoded_amount >= NEAR_MAX_UINT256

        try:
            from web3.exceptions import ContractLogicError

            w3 = self._client(intent.chain)
            call_params = {
                "from": w3.to_checksum_address(intent.wallet),
                "to": w3.to_checksum_address(intent.target),
                "data": calldata,
                "value": int(value or 0),
            }
        except Exception as exc:  # RPC not configured / bad addresses / import failure
            logger.warning("Simulation setup failed for %s", intent.intent_id, exc_info=True)
            return SimulationResult(attempted=False, error=str(exc))

        try:
            w3.eth.call(call_params)
            gas_estimate = w3.eth.estimate_gas(call_params)
            return SimulationResult(
                attempted=True, would_revert=False, gas_estimate=gas_estimate,
                decoded_approval_amount=decoded_amount, is_unlimited_approval=is_unlimited,
            )
        except ContractLogicError as exc:
            reason = exc.args[0] if exc.args else str(exc)
            return SimulationResult(
                attempted=True, would_revert=True, revert_reason=str(reason),
                decoded_approval_amount=decoded_amount, is_unlimited_approval=is_unlimited,
            )
        except Exception as exc:
            logger.warning("Simulation call failed for %s (RPC/network issue, not a revert)", intent.intent_id, exc_info=True)
            return SimulationResult(attempted=False, error=str(exc))
