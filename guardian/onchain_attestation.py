"""EIP-712 attestations for GuardianValidator.sol, the on-chain enforcement
module (see guardian-onchain/src/GuardianValidator.sol in this project's
companion Foundry repo).

WHY THIS EXISTS ALONGSIDE OAA (guardian/oaa.py):
OAA tokens are Ed25519-signed and built for a portable, chain-agnostic,
offline-verifiable audit trail - the right choice for that job. But EVM
chains have no native Ed25519 precompile (EIP-665 proposed one in 2018; it
was never adopted), and verifying Ed25519 in pure Solidity costs on the
order of 2,000,000 gas - regularly gating transactions through that would
be prohibitively expensive on essentially any EVM chain today. A secp256k1
(ECDSA) signature, by contrast, verifies on-chain via `ecrecover` for about
3,000 gas - independently measured at 27k-59k gas for the whole
`validateUserOp` call including this check (see
guardian-onchain/test/GuardianValidator.t.sol's gas report), three orders
of magnitude cheaper. So Guardian signs the *same underlying decision* a
second time, with a second, EVM-native key, specifically for the on-chain
leg - OAA is untouched and remains the off-chain standard.

This is the ONLY thing that turns a Guardian decision into something that
can physically stop a UserOperation from executing, rather than merely
advising against it - see GuardianValidator.sol's own module docstring for
the full picture of what problem that solves.

WARN NEVER PRODUCES A USABLE ATTESTATION FOR THIS PATH: GuardianValidator
treats anything other than an explicit ALLOW as invalid on-chain (see its
docstring for why - there's no synchronous human-in-the-loop path inside
ERC-4337 validation). Calling sign_onchain_attestation with a WARN or
BLOCK decision still produces a syntactically valid attestation (so a
caller can inspect what the module would do with it, e.g. in tests) - but
GuardianValidator itself will reject it every time.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data

DECISION_ALLOW = 0
DECISION_WARN = 1
DECISION_BLOCK = 2

_DECISION_CODE = {"ALLOW": DECISION_ALLOW, "WARN": DECISION_WARN, "BLOCK": DECISION_BLOCK}

_EIP712_TYPES = {
    "GuardianAttestation": [
        {"name": "account", "type": "address"},
        {"name": "entryPoint", "type": "address"},
        {"name": "chainId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "callDataHash", "type": "bytes32"},
        {"name": "decision", "type": "uint8"},
        {"name": "expiry", "type": "uint48"},
        {"name": "requestId", "type": "bytes32"},
    ],
}


@dataclass
class OnChainAttestation:
    decision: int
    expiry: int
    request_id: bytes
    signature_r: int
    signature_s: int
    signature_v: int

    def as_user_op_signature(self) -> bytes:
        """The exact byte layout GuardianValidator.validateUserOp expects
        in userOp.signature: abi.encode(uint8, uint48, bytes32, uint8,
        bytes32, bytes32) - see the contract's own docstring on
        validateUserOp for this layout.
        """
        return abi_encode(
            ["uint8", "uint48", "bytes32", "uint8", "bytes32", "bytes32"],
            [
                self.decision,
                self.expiry,
                self.request_id,
                self.signature_v,
                self.signature_r.to_bytes(32, "big"),
                self.signature_s.to_bytes(32, "big"),
            ],
        )


def sign_onchain_attestation(
    *,
    private_key: str,
    validator_address: str,
    chain_id: int,
    entry_point: str,
    account: str,
    nonce: int,
    call_data: bytes,
    decision: str,
    ttl_seconds: int = 300,
    request_id: Optional[bytes] = None,
) -> OnChainAttestation:
    """Signs an EIP-712 GuardianAttestation for one specific UserOperation.

    ``private_key`` is the EVM-native (secp256k1) signing key this
    deployment of GuardianValidator was installed with (see the module's
    ``onInstall`` - the account only trusts one specific address). This is
    NOT the same key OAA tokens are signed with (guardian/oaa.py uses
    Ed25519) - see this module's docstring for why they're deliberately
    different formats for the same underlying decision.

    ``validator_address``, ``chain_id``, and ``entry_point`` together form
    the EIP-712 domain/struct binding that stops an attestation issued for
    one (module deployment, chain, EntryPoint version) from being replayed
    against another - see GuardianValidator.sol's struct comment for the
    exact same reasoning from the verifier's side.

    ``account``, ``nonce``, and ``call_data`` bind the attestation to one
    specific operation - change any of them and the signature no longer
    verifies. ``decision`` must be "ALLOW", "WARN", or "BLOCK" (matching
    guardian.core.models.DecisionType) - only "ALLOW" will ever actually
    pass GuardianValidator's on-chain check, but the others are accepted
    here so a BLOCK/WARN decision can still be represented and inspected
    (e.g. for tests, or an off-chain audit trail) rather than this
    function silently refusing to sign what Guardian actually decided.
    """
    if decision not in _DECISION_CODE:
        raise ValueError(f"decision must be one of {list(_DECISION_CODE)}, got {decision!r}")

    from eth_utils import keccak

    call_data_hash = keccak(call_data)
    expiry = int(time.time()) + ttl_seconds
    req_id = request_id if request_id is not None else keccak(os.urandom(32))
    if len(req_id) != 32:
        raise ValueError("request_id must be exactly 32 bytes")

    domain = {
        "name": "GuardianValidator",
        "version": "1",
        "chainId": chain_id,
        "verifyingContract": validator_address,
    }
    message = {
        "account": account,
        "entryPoint": entry_point,
        "chainId": chain_id,
        "nonce": nonce,
        "callDataHash": call_data_hash,
        "decision": _DECISION_CODE[decision],
        "expiry": expiry,
        "requestId": req_id,
    }

    signable = encode_typed_data(
        domain_data=domain, message_types=_EIP712_TYPES, message_data=message
    )
    signed = Account.sign_message(signable, private_key=private_key)

    return OnChainAttestation(
        decision=_DECISION_CODE[decision],
        expiry=expiry,
        request_id=req_id,
        signature_r=signed.r,
        signature_s=signed.s,
        signature_v=signed.v,
    )
