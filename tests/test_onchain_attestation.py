import unittest

from eth_account import Account

from guardian.onchain_attestation import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    DECISION_WARN,
    sign_onchain_attestation,
)

# Test-only private key - never used for anything real.
TEST_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690"


class TestSignOnchainAttestation(unittest.TestCase):
    def setUp(self):
        self.guardian_signer = Account.from_key(TEST_PRIVATE_KEY)
        self.validator_address = Account.create().address
        self.account_address = Account.create().address
        self.entry_point = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

    def _sign(self, **overrides):
        kwargs = dict(
            private_key=TEST_PRIVATE_KEY,
            validator_address=self.validator_address,
            chain_id=8453,
            entry_point=self.entry_point,
            account=self.account_address,
            nonce=0,
            call_data=bytes.fromhex("a9059cbb"),
            decision="ALLOW",
            ttl_seconds=300,
            request_id=(1).to_bytes(32, "big"),
        )
        kwargs.update(overrides)
        return sign_onchain_attestation(**kwargs)

    def test_decision_codes_match_contract_constants(self):
        # Must stay in lockstep with GuardianValidator.sol's
        # DECISION_ALLOW/WARN/BLOCK constants - these are the values
        # ecrecover-adjacent on-chain logic compares against directly.
        self.assertEqual(DECISION_ALLOW, 0)
        self.assertEqual(DECISION_WARN, 1)
        self.assertEqual(DECISION_BLOCK, 2)

    def test_rejects_unknown_decision_string(self):
        with self.assertRaises(ValueError):
            self._sign(decision="MAYBE")

    def test_produces_a_valid_recoverable_signature(self):
        att = self._sign()
        # Reconstruct the exact same EIP-712 digest independently (not by
        # calling sign_onchain_attestation again) and confirm ecrecover
        # via eth_account recovers the real Guardian signer - this is the
        # Python-side half of the same guarantee GuardianValidator.sol's
        # tests check on the Solidity side.
        from eth_account.messages import encode_typed_data
        from eth_utils import keccak

        domain = {
            "name": "GuardianValidator", "version": "1",
            "chainId": 8453, "verifyingContract": self.validator_address,
        }
        types = {
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
        message = {
            "account": self.account_address, "entryPoint": self.entry_point,
            "chainId": 8453, "nonce": 0, "callDataHash": keccak(bytes.fromhex("a9059cbb")),
            "decision": att.decision, "expiry": att.expiry, "requestId": att.request_id,
        }
        signable = encode_typed_data(domain_data=domain, message_types=types, message_data=message)
        recovered = Account.recover_message(signable, vrs=(att.signature_v, att.signature_r, att.signature_s))
        self.assertEqual(recovered, self.guardian_signer.address)

    def test_signature_changes_if_call_data_changes(self):
        att1 = self._sign(call_data=bytes.fromhex("a9059cbb"))
        att2 = self._sign(call_data=bytes.fromhex("095ea7b3"))
        self.assertNotEqual(
            (att1.signature_r, att1.signature_s), (att2.signature_r, att2.signature_s)
        )

    def test_signature_changes_if_account_changes(self):
        att1 = self._sign(account=self.account_address)
        att2 = self._sign(account=Account.create().address)
        self.assertNotEqual(
            (att1.signature_r, att1.signature_s), (att2.signature_r, att2.signature_s)
        )

    def test_signature_changes_if_nonce_changes(self):
        att1 = self._sign(nonce=0)
        att2 = self._sign(nonce=1)
        self.assertNotEqual(
            (att1.signature_r, att1.signature_s), (att2.signature_r, att2.signature_s)
        )

    def test_signature_changes_if_chain_id_changes(self):
        att1 = self._sign(chain_id=8453)
        att2 = self._sign(chain_id=1)
        self.assertNotEqual(
            (att1.signature_r, att1.signature_s), (att2.signature_r, att2.signature_s)
        )

    def test_signature_changes_if_validator_address_changes(self):
        att1 = self._sign(validator_address=self.validator_address)
        att2 = self._sign(validator_address=Account.create().address)
        self.assertNotEqual(
            (att1.signature_r, att1.signature_s), (att2.signature_r, att2.signature_s)
        )

    def test_expiry_is_now_plus_ttl(self):
        import time
        before = int(time.time())
        att = self._sign(ttl_seconds=300)
        after = int(time.time())
        self.assertGreaterEqual(att.expiry, before + 300)
        self.assertLessEqual(att.expiry, after + 300)

    def test_random_request_id_generated_when_not_supplied(self):
        att1 = self._sign(request_id=None)
        att2 = self._sign(request_id=None)
        self.assertNotEqual(att1.request_id, att2.request_id)
        self.assertEqual(len(att1.request_id), 32)

    def test_rejects_non_32_byte_request_id(self):
        with self.assertRaises(ValueError):
            self._sign(request_id=b"too-short")

    def test_as_user_op_signature_layout(self):
        att = self._sign()
        packed = att.as_user_op_signature()
        # abi.encode(uint8, uint48, bytes32, uint8, bytes32, bytes32) - six
        # 32-byte words, matching exactly what GuardianValidator.sol's
        # validateUserOp decodes from userOp.signature.
        self.assertEqual(len(packed), 6 * 32)

    def test_warn_and_block_decisions_can_still_be_signed(self):
        # GuardianValidator itself will reject these on-chain (see its own
        # docstring) - but this function shouldn't refuse to represent
        # what Guardian actually decided.
        warn_att = self._sign(decision="WARN")
        block_att = self._sign(decision="BLOCK")
        self.assertEqual(warn_att.decision, DECISION_WARN)
        self.assertEqual(block_att.decision, DECISION_BLOCK)


if __name__ == "__main__":
    unittest.main()
