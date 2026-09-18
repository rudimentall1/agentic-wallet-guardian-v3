"""Arc mainnet integration for the Agentic Wallet Guardian demo.

Arc treats USDC as the native gas asset and exposes an ERC-20 interface at
ARC_USDC_ADDRESS for standard token transfers. This module keeps the Arc
specifics in one place and deliberately does not hold keys or broadcast
transactions: it prepares a transaction only after Guardian returns ALLOW.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict

from guardian.config import GuardianConfig
from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.policy.engine import PolicyEngine

ARC_CHAIN = "arc"
ARC_CHAIN_ID = 5042
ARC_RPC_URL = "https://rpc.mainnet.arc.io"
ARC_EXPLORER_URL = "https://explorer.arc.io"
ARC_USDC_ADDRESS = "0x3600000000000000000000000000000000000000"
ARC_USDC_DECIMALS = 6
ARC_NATIVE_DECIMALS = 18
ARC_GAS_FLOOR_WEI = 20_000_000_000

# Microgrant demo policy: autonomous agents can make small USDC payments,
# while contract approvals/swaps/bridges are outside this payment surface.
ARC_PAYMENT_POLICY = {
    "max_amount_per_action": 5.0,
    "max_amount_unknown_agent": 5.0,
    "high_value_threshold": 5.0,
    "min_reputation_for_high_value": 60.0,
    "blocked_action_types": ["approve", "swap", "bridge", "contract_call"],
    "require_confirmation_action_types": [],
}


def arc_config(config: GuardianConfig) -> GuardianConfig:
    """Return an Arc-ready config without mutating the process-wide config."""
    rpc_urls = dict(config.rpc_urls)
    rpc_urls.setdefault(ARC_CHAIN, ARC_RPC_URL)
    return replace(
        config,
        wallet_provider="rpc",
        simulation_provider="rpc",
        tx_builder_provider="rpc",
        decimals_provider="rpc",
        rpc_urls=rpc_urls,
    )


def build_arc_engine(config: GuardianConfig) -> DecisionEngine:
    return DecisionEngine(
        config=arc_config(config),
        policy_engine=PolicyEngine(dict(ARC_PAYMENT_POLICY)),
    )


def arc_network_status(rpc_url: str = ARC_RPC_URL) -> Dict[str, Any]:
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    chain_id = int(w3.eth.chain_id)
    block_number = int(w3.eth.block_number)
    gas_price = int(w3.eth.gas_price)
    return {
        "chain_id": chain_id,
        "block_number": block_number,
        "gas_price_wei": gas_price,
        "gas_price_gwei": gas_price / 1_000_000_000,
        "rpc": rpc_url,
        "explorer": ARC_EXPLORER_URL,
        "usdc_address": ARC_USDC_ADDRESS,
        "usdc_decimals": ARC_USDC_DECIMALS,
        "native_gas_decimals": ARC_NATIVE_DECIMALS,
        "rpc_matches_arc_mainnet": chain_id == ARC_CHAIN_ID,
    }


def prepare_arc_payment(engine: DecisionEngine, intent: ActionIntent) -> Dict[str, Any]:
    """Evaluate and, only for ALLOW, prepare a wallet-signable ERC-20 tx."""
    decision = engine.evaluate(intent)
    result: Dict[str, Any] = {
        "decision": decision.to_dict(),
        "chain": ARC_CHAIN,
        "chain_id": ARC_CHAIN_ID,
        "usdc_address": ARC_USDC_ADDRESS,
        "explorer": ARC_EXPLORER_URL,
        "transaction_ready": False,
    }

    if decision.decision.value != "ALLOW":
        return result

    built = engine.tx_builder.build(intent)
    if built is None or built.to is None:
        result["preparation_error"] = "Guardian allowed the action, but no safe transaction could be built."
        return result

    from web3 import Web3

    rpc_url = engine.decimals_provider.rpc_urls.get(ARC_CHAIN, ARC_RPC_URL) if hasattr(engine.decimals_provider, "rpc_urls") else ARC_RPC_URL
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    if int(w3.eth.chain_id) != ARC_CHAIN_ID:
        result["preparation_error"] = "Configured RPC is not Arc mainnet (chain ID 5042)."
        return result

    call = {
        "from": w3.to_checksum_address(intent.wallet),
        "to": w3.to_checksum_address(built.to),
        "data": built.data,
        "value": int(built.value),
    }
    gas = int(w3.eth.estimate_gas(call))
    gas_price = int(w3.eth.gas_price)
    max_fee = max(gas_price, ARC_GAS_FLOOR_WEI)

    result["transaction_ready"] = True
    result["transaction"] = {
        "from": intent.wallet,
        "to": built.to,
        "data": built.data,
        "value": hex(built.value),
        "gas": hex(gas),
        "maxFeePerGas": hex(max_fee),
        "maxPriorityFeePerGas": hex(0),
        "gas_price_gwei": gas_price / 1_000_000_000,
    }
    return result
