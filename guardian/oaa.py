"""
Vendored copy of the Open Agent Attestation (OAA) v0.1 reference
implementation: https://github.com/rudimentall1/open-agent-attestation

Copied here (not installed as a dependency) because OAA isn't
published to PyPI yet. Keep in sync manually with the upstream repo
until it is. See SPEC.md there for the format definition.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REQUIRED_CLAIMS = {"iss", "sub", "iat", "oaa_decision", "oaa_action", "oaa_reason", "oaa_policy_ref"}
VALID_DECISIONS = {"ALLOW", "WARN", "BLOCK", "REQUIRE_APPROVAL"}


class InvalidOAAToken(Exception):
    pass


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def issue(*, issuer, subject, decision, action, reason, policy_ref, private_key_pem) -> str:
    if decision not in VALID_DECISIONS:
        raise InvalidOAAToken(f"oaa_decision must be one of {sorted(VALID_DECISIONS)}, got {decision!r}")
    claims = {
        "iss": issuer, "sub": subject, "iat": int(time.time()),
        "oaa_decision": decision, "oaa_action": action,
        "oaa_reason": reason, "oaa_policy_ref": policy_ref,
    }
    return jwt.encode(claims, private_key_pem, algorithm="EdDSA")


@dataclass
class OAAToken:
    issuer: str
    subject: str
    issued_at: int
    decision: str
    action: str
    reason: str
    policy_ref: str
    raw_claims: dict


def verify(token: str, public_key_pem: bytes, *, expected_issuer: str | None = None) -> OAAToken:
    claims = jwt.decode(token, public_key_pem, algorithms=["EdDSA"])
    missing = REQUIRED_CLAIMS - claims.keys()
    if missing:
        raise InvalidOAAToken(f"missing required claims: {sorted(missing)}")
    if claims["oaa_decision"] not in VALID_DECISIONS:
        raise InvalidOAAToken(f"oaa_decision must be one of {sorted(VALID_DECISIONS)}, got {claims['oaa_decision']!r}")
    if expected_issuer is not None and claims["iss"] != expected_issuer:
        raise InvalidOAAToken(f"expected issuer {expected_issuer!r}, got {claims['iss']!r}")
    return OAAToken(
        issuer=claims["iss"], subject=claims["sub"], issued_at=claims["iat"],
        decision=claims["oaa_decision"], action=claims["oaa_action"],
        reason=claims["oaa_reason"], policy_ref=claims["oaa_policy_ref"], raw_claims=claims,
    )