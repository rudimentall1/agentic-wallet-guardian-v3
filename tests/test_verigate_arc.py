import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian import verigate_arc


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def _configure(monkeypatch, tmp_path):
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "agent-ed25519.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("VERIGATE_URL", "https://verigate.example")
    monkeypatch.setenv("VERIGATE_AGENT_ID", "guardian-arc-agent")
    monkeypatch.setenv("VERIGATE_IDENTITY_ID", "identity-1")
    monkeypatch.setenv("VERIGATE_CAPABILITY_ID", "capability-1")
    monkeypatch.setenv("VERIGATE_AGENT_PRIVATE_KEY_PATH", str(key_path))
    return private_key


def test_authorize_signs_the_exact_verigate_action(monkeypatch, tmp_path):
    private_key = _configure(monkeypatch, tmp_path)
    sender = "0x" + "11" * 20
    recipient = "0x" + "22" * 20
    calldata = "0xa9059cbb" + "0" * 120
    wallet_tx = {
        "chainId": hex(verigate_arc.ARC_CHAIN_ID),
        "from": sender,
        "to": verigate_arc.ARC_USDC_ADDRESS.lower(),
        "data": calldata,
        "value": "0x0",
    }
    captured = {}

    def fake_post(url, *, json, headers, timeout):
        captured.update(url=url, body=json, headers=headers, timeout=timeout)
        return FakeResponse({
            "execution_authorization": {"payload": {"authorization_id": "auth-1"}},
            "decision_receipt": {"payload": {"decision": "ALLOW"}},
            "wallet_transaction": wallet_tx,
            "arc_network": {"verified": True},
        })

    monkeypatch.setattr(verigate_arc.httpx, "post", fake_post)
    result = verigate_arc.authorize_arc_payment(
        sender=sender,
        recipient=recipient,
        amount="0.25",
        transaction={"data": calldata},
    )

    assert captured["url"] == "https://verigate.example/v1/integrations/arc/authorize"
    action = {
        "intent_id": captured["body"]["intent_id"],
        "agent_id": "guardian-arc-agent",
        "action_type": "payment",
        "target": recipient,
        "resource": "",
        "amount": "0.25",
        "amount_exact": "0.25",
        "asset": "USDC",
        "network": "arc",
        "purpose": "Arc USDC payment via Guardian",
        "declared_context": {},
        "input_provenance": {},
        "parent_intent_id": None,
        "requested_capability": None,
        "constraints": {},
        "metadata": captured["body"]["metadata"],
        "timestamp": captured["body"]["timestamp"],
    }
    signed_payload = {"identity_id": "identity-1", "action": action}
    public_key = private_key.public_key()
    public_key.verify(
        base64.b64decode(captured["body"]["agent_signature"]),
        json.dumps(
            signed_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8"),
    )

    assert result["authorization"]["payload"]["authorization_id"] == "auth-1"
    assert result["wallet_transaction"] == wallet_tx


def test_authorize_rejects_wallet_transaction_drift(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    sender = "0x" + "11" * 20
    recipient = "0x" + "22" * 20
    calldata = "0xa9059cbb" + "0" * 120
    wrong_wallet_tx = {
        "chainId": hex(verigate_arc.ARC_CHAIN_ID),
        "from": sender,
        "to": "0x" + "33" * 20,
        "data": calldata,
        "value": "0x0",
    }

    monkeypatch.setattr(
        verigate_arc.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse({
            "execution_authorization": {"payload": {"authorization_id": "auth-1"}},
            "wallet_transaction": wrong_wallet_tx,
        }),
    )

    import pytest

    with pytest.raises(RuntimeError, match="wallet transaction mismatch: to"):
        verigate_arc.authorize_arc_payment(
            sender=sender,
            recipient=recipient,
            amount="0.25",
            transaction={"data": calldata},
        )
