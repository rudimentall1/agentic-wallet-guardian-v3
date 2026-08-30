// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { GuardianValidator } from "../src/GuardianValidator.sol";

/// @notice Cross-verifies that guardian/onchain_attestation.py (the real
/// Python code Guardian will actually run) and this Solidity contract
/// agree on the exact same EIP-712 digest and that a signature genuinely
/// produced by eth_account in Python is accepted here - not two
/// independent implementations that happen to both pass their own
/// isolated tests while silently disagreeing with each other.
///
/// The account/validator addresses and signature values below were
/// produced by:
///   1. Deploying GuardianValidator in a Foundry test and logging its
///      deterministic address plus a makeAddr()'d account address.
///   2. Feeding those exact addresses into
///      guardian/onchain_attestation.sign_onchain_attestation() in a real
///      Python process, with a real (test-only) secp256k1 private key.
///   3. Copying the resulting v/r/s here verbatim - nothing in this file
///      was derived from Solidity's own signing tools.
contract PythonCrossVerifyTest is Test {
    address internal constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    // From guardian/onchain_attestation.py's Account.from_key() on the
    // same test private key used to sign below.
    address internal constant GUARDIAN_SIGNER = 0x9cb2FB92a71b0f99D51F000a54Dc028d31C46b74;

    function test_signatureProducedByRealPythonCodeIsAcceptedOnChain() public {
        GuardianValidator validator = new GuardianValidator(ENTRY_POINT_V07);
        // Must match forge's deployment address that was fed into the
        // Python signer - re-deploying in the exact same sequence (this
        // is the very first contract deployed by this test's sender)
        // reproduces the same deterministic address every time.
        assertEq(
            address(validator),
            0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f,
            "deployment address drifted - re-run PrintAddresses.t.sol and re-sign in Python"
        );

        address account = makeAddr("cross-verify-account");
        assertEq(account, 0x179920f889FD8d5e7FD755914fab7b8d1D6221D2, "makeAddr() output drifted");

        vm.prank(account);
        validator.onInstall(abi.encode(GUARDIAN_SIGNER));

        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            // Verbatim output of guardian/onchain_attestation.py's
            // sign_onchain_attestation(...).as_user_op_signature() for
            // decision=ALLOW, expiry=1788065468, request_id=1, this
            // account, nonce=0, this callData.
            signature: abi.encode(
                uint8(0), // DECISION_ALLOW
                uint48(1788065468),
                bytes32(uint256(1)),
                uint8(27),
                bytes32(0x5d4fe3683f5a7dfd3dbd90c6eaecd57ff55d65cf405823fc970ce41fcc0d5220),
                bytes32(0x63adfda7e13cab39d0a05eb83d315484715dcdd33dfce135142d1bde141f421a)
            )
        });

        // The attestation's expiry (1788065468) is a real future Unix
        // timestamp from when it was signed - move the EVM clock to just
        // before it so this test keeps passing regardless of when it's
        // actually run, without needing to re-sign.
        vm.warp(1788065468 - 60);

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));

        assertEq(result & 1, 0, "genuine Python-signed attestation was rejected on-chain");
    }
}
