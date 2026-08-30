// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED } from "account-abstraction/core/Helpers.sol";
import { IModule } from "erc7579-implementation/interfaces/IERC7579Module.sol";
import { GuardianValidator } from "../src/GuardianValidator.sol";

contract GuardianValidatorTest is Test {
    GuardianValidator internal validator;

    uint256 internal guardianKey;
    address internal guardianSigner;
    uint256 internal wrongKey;
    address internal account;

    address internal constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public {
        validator = new GuardianValidator(ENTRY_POINT_V07);
        (guardianSigner, guardianKey) = makeAddrAndKey("guardian");
        (, wrongKey) = makeAddrAndKey("not-guardian");
        account = makeAddr("account");

        vm.prank(account);
        validator.onInstall(abi.encode(guardianSigner));
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _buildUserOp(bytes memory callData, uint256 nonce) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _sign(
        uint256 signerKey,
        address forAccount,
        uint256 nonce,
        bytes memory callData,
        uint8 decision,
        uint48 expiry,
        bytes32 requestId
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = validator.attestationDigest(forAccount, nonce, callData, decision, expiry, requestId);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encode(decision, expiry, requestId, v, r, s);
    }

    // -------------------------------------------------------------------
    // Module bookkeeping
    // -------------------------------------------------------------------

    function test_onInstall_setsGuardianSigner() public view {
        assertEq(validator.guardianSignerOf(account), guardianSigner);
        assertTrue(validator.isInitialized(account));
    }

    function test_onInstall_revertsIfAlreadyInitialized() public {
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(IModule.AlreadyInitialized.selector, account));
        validator.onInstall(abi.encode(guardianSigner));
    }

    function test_onUninstall_clearsGuardianSigner() public {
        vm.prank(account);
        validator.onUninstall("");
        assertEq(validator.guardianSignerOf(account), address(0));
        assertFalse(validator.isInitialized(account));
    }

    function test_onUninstall_revertsIfNotInitialized() public {
        address fresh = makeAddr("fresh-account");
        vm.prank(fresh);
        vm.expectRevert(abi.encodeWithSelector(IModule.NotInitialized.selector, fresh));
        validator.onUninstall("");
    }

    function test_isModuleType_onlyValidator() public view {
        assertTrue(validator.isModuleType(1));
        assertFalse(validator.isModuleType(2));
        assertFalse(validator.isModuleType(4));
    }

    // -------------------------------------------------------------------
    // The actual enforcement guarantee
    // -------------------------------------------------------------------

    function test_validateUserOp_succeedsForGenuineAllowAttestation() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-1")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));

        // packed validation data: sigFailed=false, validUntil=expiry, validAfter=0
        assertEq(result & 1, 0, "must not be SIG_VALIDATION_FAILED");
    }

    function test_validateUserOp_failsForBlockDecision() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_BLOCK(), uint48(block.timestamp + 300), bytes32("req-2")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsForWarnDecision() public {
        // Regression test for the deliberate design decision documented in
        // the contract: WARN must never pass, only an explicit ALLOW does -
        // there is no synchronous human-in-the-loop path inside
        // validateUserOp.
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_WARN(), uint48(block.timestamp + 300), bytes32("req-3")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsForExpiredAttestation() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        uint48 expiry = uint48(block.timestamp + 100);
        userOp.signature =
            _sign(guardianKey, account, 0, callData, validator.DECISION_ALLOW(), expiry, bytes32("req-4"));

        vm.warp(block.timestamp + 101);

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsForWrongSigner() public {
        // Signed by a key the account never configured as trusted - this is
        // the core "can an attacker just forge their own attestation"
        // check.
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            wrongKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-5")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_revertsIfNoSignerConfigured() public {
        address freshAccount = makeAddr("uninitialized-account");
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: freshAccount,
            nonce: 0,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            signature: hex""
        });

        vm.prank(freshAccount);
        vm.expectRevert(
            abi.encodeWithSelector(GuardianValidator.NoGuardianSignerConfigured.selector, freshAccount)
        );
        validator.validateUserOp(userOp, bytes32(0));
    }

    // -------------------------------------------------------------------
    // The exact-operation binding - this is the whole point of the module
    // -------------------------------------------------------------------

    function test_validateUserOp_failsIfCallDataTamperedAfterSigning() public {
        // The attacker takes a genuinely-issued ALLOW attestation for one
        // transfer and tries to splice it onto a *different* transfer
        // (e.g. a different recipient or amount encoded in callData).
        bytes memory originalCallData = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 1 ether);
        bytes memory tamperedCallData = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 1000 ether);

        PackedUserOperation memory userOp = _buildUserOp(tamperedCallData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, originalCallData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-6")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsIfNonceTampered() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 7);
        // signed for nonce 0, submitted with nonce 7
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-7")
        );

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsIfAttestationReplayedForDifferentAccount() public {
        // A second account also trusts the same Guardian signer key (a
        // realistic multi-account deployment). An attestation issued for
        // account A must not validate on behalf of account B, even with an
        // identical nonce and callData.
        address otherAccount = makeAddr("other-account");
        vm.prank(otherAccount);
        validator.onInstall(abi.encode(guardianSigner));

        bytes memory callData = hex"a9059cbb";
        bytes memory sig = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-8")
        );

        PackedUserOperation memory forgedOp = _buildUserOp(callData, 0);
        forgedOp.sender = otherAccount;
        forgedOp.signature = sig;

        vm.prank(otherAccount);
        uint256 result = validator.validateUserOp(forgedOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    function test_validateUserOp_failsIfAttestationReplayedAgainstDifferentEntryPointDeployment() public {
        // A second GuardianValidator deployment bound to a different
        // EntryPoint (e.g. v0.9 once available) must not accept an
        // attestation signed for the v0.7 deployment, even for the exact
        // same account/nonce/callData/decision/expiry - entryPoint is part
        // of the signed struct precisely to prevent this.
        GuardianValidator otherEntryPointValidator = new GuardianValidator(makeAddr("entrypoint-v09"));
        vm.prank(account);
        otherEntryPointValidator.onInstall(abi.encode(guardianSigner));

        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        // Signed against the ORIGINAL validator's entryPoint (v0.7).
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-ep")
        );

        vm.prank(account);
        uint256 result = otherEntryPointValidator.validateUserOp(userOp, bytes32(0));
        assertEq(result, SIG_VALIDATION_FAILED);
    }

    // -------------------------------------------------------------------
    // Single-use / replay protection
    // -------------------------------------------------------------------

    function test_validateUserOp_revertsOnSecondUseOfSameAttestation() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-9")
        );

        vm.prank(account);
        validator.validateUserOp(userOp, bytes32(0));

        vm.prank(account);
        vm.expectRevert(); // AttestationAlreadyUsed
        validator.validateUserOp(userOp, bytes32(0));
    }

    function test_validateUserOp_marksAttestationConsumed() public {
        bytes memory callData = hex"a9059cbb";
        PackedUserOperation memory userOp = _buildUserOp(callData, 0);
        userOp.signature = _sign(
            guardianKey, account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-10")
        );

        bytes32 digest = validator.attestationDigest(
            account, 0, callData, validator.DECISION_ALLOW(), uint48(block.timestamp + 300), bytes32("req-10")
        );
        assertFalse(validator.consumed(digest));

        vm.prank(account);
        validator.validateUserOp(userOp, bytes32(0));

        assertTrue(validator.consumed(digest));
    }

    // -------------------------------------------------------------------
    // ERC-1271 path fails closed
    // -------------------------------------------------------------------

    function test_isValidSignatureWithSender_alwaysFailsClosed() public view {
        bytes4 result = validator.isValidSignatureWithSender(account, bytes32(0), "");
        assertEq(result, bytes4(0xffffffff));
    }

    // -------------------------------------------------------------------
    // Fuzzing the core guarantee
    // -------------------------------------------------------------------

    function testFuzz_onlyGenuineAllowFromTrustedSignerEverSucceeds(
        uint256 nonce,
        bytes calldata callData,
        uint8 decision,
        uint48 expirySeed,
        bool useCorrectSigner
    )
        public
    {
        uint48 expiry = uint48(bound(expirySeed, block.timestamp + 1, block.timestamp + 365 days));
        uint256 signerKey = useCorrectSigner ? guardianKey : wrongKey;

        PackedUserOperation memory userOp = _buildUserOp(callData, nonce);
        userOp.signature = _sign(signerKey, account, nonce, callData, decision, expiry, bytes32("fuzz"));

        vm.prank(account);
        uint256 result = validator.validateUserOp(userOp, bytes32(0));

        bool shouldSucceed = useCorrectSigner && decision == validator.DECISION_ALLOW();
        if (shouldSucceed) {
            assertEq(result & 1, 0, "expected success");
        } else {
            assertEq(result, SIG_VALIDATION_FAILED, "expected failure");
        }
    }
}
