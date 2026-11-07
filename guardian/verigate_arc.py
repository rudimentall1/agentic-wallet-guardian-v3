"""Fail-closed Verigate authorization and consume bridge for Arc payments."""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from decimal import Decimal
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian.arc import ARC_CHAIN, ARC_CHAIN_ID, ARC_USDC_ADDRESS, ARC_DEMO_AGENT_ID


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required Verigate setting: {name}")
    return value


def _private_key() -> Ed25519PrivateKey:
    path = Path(_required("VERIGATE_AGENT_PRIVATE_KEY_PATH"))
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Verigate agent key must be an Ed25519 PEM private key")
    return key


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def authorize_arc_payment(*, sender: str, recipient: str, amount: str, transaction: dict) -> dict:
    """Sign the exact ActionIntent and request Verigate's signed execution authorization."""
    base_url = _required("VERIGATE_URL").rstrip("/")
    agent_id = _required("VERIGATE_AGENT_ID")
    if agent_id != ARC_DEMO_AGENT_ID:
        raise RuntimeError(f"VERIGATE_AGENT_ID must equal Guardian Arc agent id: {ARC_DEMO_AGENT_ID}")
    identity_id = _required("VERIGATE_IDENTITY_ID")
    capability_id = _required("VERIGATE_CAPABILITY_ID")
    api_key = os.environ.get("VERIGATE_API_KEY", "").strip()

    amount_decimal = Decimal(str(amount))
    intent_id = str(uuid.uuid4())
    timestamp = time.time()
    metadata = {
        "network_family": "evm",
        "evm_transaction": {
            "chain_id": ARC_CHAIN_ID,
            "from": sender.lower(),
            "to": ARC_USDC_ADDRESS.lower(),
            "value_wei": 0,
            "data": transaction["data"].lower(),
        },
        "arc": {
            "chain_id": ARC_CHAIN_ID,
            "asset": "USDC",
            "token_address": ARC_USDC_ADDRESS,
            "token_decimals": 6,
        },
    }
    action = {
        "intent_id": intent_id,
        "agent_id": agent_id,
        "action_type": "payment",
        "target": recipient.lower(),
        "resource": "",
        "amount": None,
        "amount_exact": format(amount_decimal, "f"),
        "asset": "USDC",
        "network": ARC_CHAIN,
        "purpose": "Arc USDC payment via Guardian",
        "declared_context": {},
        "input_provenance": {},
        "parent_intent_id": None,
        "requested_capability": None,
        "constraints": {},
        "metadata": metadata,
        "timestamp": timestamp,
    }
    signature_payload = {"identity_id": identity_id, "action": action}
    signature = base64.b64encode(_private_key().sign(_canonical(signature_payload))).decode("ascii")
    request = {
        "identity_id": identity_id,
        "capability_id": capability_id,
        "agent_id": agent_id,
        "agent_signature": signature,
        "intent_id": intent_id,
        "timestamp": timestamp,
        "action_type": "payment",
        "target": recipient.lower(),
        "purpose": action["purpose"],
        "amount_exact": format(amount_decimal, "f"),
        "asset": "USDC",
        "network": ARC_CHAIN,
        "metadata": metadata,
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    response = httpx.post(
        f"{base_url}/v1/integrations/arc/authorize",
        json=request,
        headers=headers,
        timeout=20.0,
    )
    response.raise_for_status()
    result = response.json()
    authorization = result.get("execution_authorization")
    wallet_tx = result.get("wallet_transaction")
    if not authorization or not wallet_tx:
        raise RuntimeError("Verigate did not issue an executable authorization; refusing to release transaction")
    expected = {
        "chainId": hex(ARC_CHAIN_ID),
        "from": sender.lower(),
        "to": ARC_USDC_ADDRESS.lower(),
        "data": transaction["data"].lower(),
        "value": "0x0",
    }
    for field, value in expected.items():
        if str(wallet_tx.get(field, "")).lower() != str(value).lower():
            raise RuntimeError(f"Verigate wallet transaction mismatch: {field}")
    return {
        "authorization": authorization,
        "wallet_transaction": wallet_tx,
        "decision_receipt": result.get("decision_receipt"),
        "authorization_id": authorization.get("payload", {}).get("authorization_id"),
        "arc_network": result.get("arc_network"),
    }


def consume_arc_authorization(authorization: dict) -> dict:
    """Consume the exact Verigate authorization; fail closed on every error."""
    base_url = _required("VERIGATE_URL").rstrip("/")
    api_key = os.environ.get("VERIGATE_API_KEY", "").strip()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    response = httpx.post(
        f"{base_url}/v1/execution/consume",
        json={"authorization": authorization},
        headers=headers,
        timeout=20.0,
    )
    response.raise_for_status()
    result = response.json()
    if result.get("execute") is not True:
        raise RuntimeError(f"Verigate refused execution: {result.get('reason', 'unknown reason')}")
    return result
