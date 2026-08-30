// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IValidator } from "erc7579-implementation/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import {
    _packValidationData,
    SIG_VALIDATION_FAILED
} from "account-abstraction/core/Helpers.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title GuardianValidator
/// @notice An ERC-7579 validator module that only allows a UserOperation to
/// execute when it carries a fresh, on-chain-verifiable attestation from a
/// Guardian instance (github.com/rudimentall1/agentic-wallet-guardian-v3)
/// saying this *exact* operation was evaluated and got ALLOW.
///
/// This is the missing piece between "Guardian can tell you a transaction is
/// dangerous" and "Guardian can stop it": every other integration in the
/// Guardian project (the REST API, the enforced MCP server in the sibling
/// agent-guardrail project) is advisory in the sense that the caller still
/// has to *choose* to respect the decision — nothing stops a compromised or
/// misbehaving agent process from just not asking, or asking and ignoring
/// the answer. Once this module is installed as the account's validator,
/// there is no such choice: the ERC-4337 EntryPoint itself will not include
/// a UserOperation in a block unless `validateUserOp` returns success, and
/// this implementation returns success only for an operation a trusted
/// Guardian signer actually attested to.
///
/// WHY A SEPARATE ATTESTATION FORMAT, NOT OAA/Ed25519 REUSED DIRECTLY:
/// Guardian's existing Open Agent Attestation (OAA) tokens are Ed25519-signed
/// JWTs — the right choice for a portable, chain-agnostic, offline-verifiable
/// audit trail (see guardian/oaa.py). But EVM chains, including Base, have no
/// native Ed25519 precompile (EIP-665 proposed one in 2018; it was never
/// adopted). Verifying an Ed25519 signature in pure Solidity costs on the
/// order of 2,000,000 gas — regularly gating every transaction through that
/// would be prohibitively expensive on essentially any EVM chain today. A
/// secp256k1 signature, by contrast, verifies via `ecrecover` for about 3,000
/// gas — three orders of magnitude cheaper, and it is what every EVM chain
/// already supports natively. So Guardian additionally signs an EIP-712
/// typed attestation with a *second*, EVM-native (secp256k1) key
/// specifically for this on-chain leg, while OAA/Ed25519 remains exactly as
/// it was for the off-chain, chain-agnostic audit trail. Same underlying
/// decision, same operator, two signature formats for two different
/// verification contexts — not a weaker attestation, just a cheaper one
/// where cheap is what makes on-chain enforcement viable at all.
///
/// WARN IS NOT ALLOW: this module treats anything other than an explicit
/// ALLOW attestation as invalid, including WARN. There is no synchronous way
/// to route a WARN to a human for confirmation from inside ERC-4337's
/// validation phase — that confirmation flow (see agent-guardrail's
/// confirmation/web_ui.py and cli_ui.py for the equivalent off-chain
/// pattern) has to happen *before* the UserOperation is even built and
/// submitted, entirely off-chain, resulting in either a fresh ALLOW
/// attestation (if approved) or nothing (if rejected) — never a WARN
/// attestation reaching this contract.
contract GuardianValidator is IValidator, EIP712 {
    using ECDSA for bytes32;

    /// @dev decision codes in the attestation, mirroring guardian.core.models.DecisionType.
    /// Only ALLOW ever satisfies validateUserOp - see the WARN note above.
    uint8 public constant DECISION_ALLOW = 0;
    uint8 public constant DECISION_WARN = 1;
    uint8 public constant DECISION_BLOCK = 2;

    // EIP-712 typed data:
    //   GuardianAttestation(address account,address entryPoint,uint256 chainId,
    //     uint256 nonce,bytes32 callDataHash,uint8 decision,uint48 expiry,bytes32 requestId)
    // Binding account + entryPoint + chainId prevents an attestation issued
    // for one account/chain from being replayed against a different one that
    // happens to trust the same Guardian signer key. Binding nonce +
    // callDataHash means the attestation is only valid for this *exact*
    // operation - changing so much as one argument invalidates it.
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "GuardianAttestation(address account,address entryPoint,uint256 chainId,uint256 nonce,bytes32 callDataHash,uint8 decision,uint48 expiry,bytes32 requestId)"
    );

    /// @dev Per-account configured Guardian signer. address(0) means "not
    /// installed" - validateUserOp always fails closed in that state, it
    /// never falls back to "no Guardian required".
    mapping(address account => address guardianSigner) public guardianSignerOf;

    /// @dev Attestations are single-use even though callDataHash+nonce
    /// already bind them to one specific operation - nonce reuse across a
    /// UserOperation's own retry/replacement semantics is handled by the
    /// EntryPoint itself, but this mapping additionally guards against a
    /// still-valid (not yet expired) attestation being presented a second
    /// time for the exact same operation via a different execution path
    /// (e.g. a direct call bypassing the EntryPoint's own nonce tracking on
    /// an account that also exposes this validator for ERC-1271 checks).
    /// Cheap, and removes any need to reason about whether every possible
    /// caller path already prevents replay on its own.
    mapping(bytes32 attestationHash => bool used) public consumed;

    event GuardianSignerSet(address indexed account, address indexed guardianSigner);
    event AttestationConsumed(address indexed account, bytes32 indexed requestId, bytes32 attestationHash);

    error NoGuardianSignerConfigured(address account);
    error AttestationAlreadyUsed(bytes32 attestationHash);

    /// @dev The ERC-4337 EntryPoint this deployment of the module is bound
    /// to - set once at deploy time, not hardcoded as a constant. This was
    /// originally a hardcoded pure function returning the canonical v0.7
    /// EntryPoint address (0x0000000071727De22E5E9d8BAf0edAc6f37da032,
    /// deployed at the same address on Base, Ethereum, and effectively
    /// every other EVM chain via a deterministic factory). Independently
    /// confirmed live on BaseScan while building this: verified, actively
    /// processing millions of real UserOperations. But that same page
    /// explicitly flags a newer EntryPoint 0.9.0 as the version wallets
    /// and apps are now encouraged to use - a version the code didn't know
    /// about at write time. Hardcoding a specific EntryPoint version as a
    /// constant bakes in staleness the moment the ecosystem moves; an
    /// immutable set at deployment lets the same module source be
    /// redeployed against whichever EntryPoint version is current,
    /// without an upgrade path being needed for this alone.
    address public immutable entryPoint;

    constructor(address entryPoint_) EIP712("GuardianValidator", "1") {
        entryPoint = entryPoint_;
    }

    // ---------------------------------------------------------------------
    // IModule
    // ---------------------------------------------------------------------

    /// @param data abi-encoded (address guardianSigner) - the EVM address
    /// corresponding to the secp256k1 key this Guardian deployment signs
    /// on-chain attestations with (see guardian/onchain_attestation.py).
    /// Every account installs its own trust in a specific Guardian
    /// instance/key - there is no shared global signer.
    function onInstall(bytes calldata data) external override {
        if (guardianSignerOf[msg.sender] != address(0)) {
            revert AlreadyInitialized(msg.sender);
        }
        address signer = abi.decode(data, (address));
        guardianSignerOf[msg.sender] = signer;
        emit GuardianSignerSet(msg.sender, signer);
    }

    function onUninstall(bytes calldata) external override {
        if (guardianSignerOf[msg.sender] == address(0)) {
            revert NotInitialized(msg.sender);
        }
        delete guardianSignerOf[msg.sender];
        emit GuardianSignerSet(msg.sender, address(0));
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1; // MODULE_TYPE_VALIDATOR
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return guardianSignerOf[smartAccount] != address(0);
    }

    // ---------------------------------------------------------------------
    // IValidator
    // ---------------------------------------------------------------------

    /// @dev userOp.signature layout expected by this validator:
    ///   abi.encode(uint8 decision, uint48 expiry, bytes32 requestId, uint8 v, bytes32 r, bytes32 s)
    /// This validator is single-purpose (Guardian-gated actions only) - an
    /// account that also wants an ordinary owner signature on some
    /// operations composes this with another validator via the account's own
    /// multi-validator dispatch (standard ERC-7579 pattern; out of scope for
    /// this module itself, which only ever checks for a valid Guardian
    /// attestation).
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash */
    )
        external
        override
        returns (uint256)
    {
        address account = userOp.sender;
        address guardianSigner = guardianSignerOf[account];
        if (guardianSigner == address(0)) {
            revert NoGuardianSignerConfigured(account);
        }

        (uint8 decision, uint48 expiry, bytes32 requestId, uint8 v, bytes32 r, bytes32 s) =
            abi.decode(userOp.signature, (uint8, uint48, bytes32, uint8, bytes32, bytes32));

        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                account,
                entryPoint,
                block.chainid,
                userOp.nonce,
                keccak256(userOp.callData),
                decision,
                expiry,
                requestId
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        if (consumed[digest]) {
            revert AttestationAlreadyUsed(digest);
        }

        address recovered = digest.recover(v, r, s);

        // Every failure path below returns SIG_VALIDATION_FAILED rather than
        // reverting, matching ERC-4337's expectation that validateUserOp
        // signal failure through the return value during simulation/
        // validation rather than reverting outright - reverting here would
        // make the operation unsimulable rather than cleanly rejected. The
        // AttestationAlreadyUsed/NoGuardianSignerConfigured reverts above are
        // deliberately different: those indicate a misconfigured or
        // misused account, not "this specific operation didn't pass",  and
        // should surface loudly rather than be swallowed into a generic
        // validation failure.
        if (recovered != guardianSigner) {
            return SIG_VALIDATION_FAILED;
        }
        if (decision != DECISION_ALLOW) {
            return SIG_VALIDATION_FAILED;
        }
        if (block.timestamp > expiry) {
            return SIG_VALIDATION_FAILED;
        }

        consumed[digest] = true;
        emit AttestationConsumed(account, requestId, digest);

        return _packValidationData(false, expiry, 0);
    }

    /// @dev ERC-1271 path (e.g. an account verifying an EIP-1271 signature
    /// outside the ERC-4337 flow). Not implemented for the MVP - Guardian
    /// attestations gate *actions* (UserOperations), not arbitrary message
    /// signing, so there is no meaningful "decision" to attach to a bare
    /// isValidSignature check. Always fails closed rather than approving.
    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    )
        external
        pure
        override
        returns (bytes4)
    {
        return 0xffffffff;
    }

    // ---------------------------------------------------------------------

    /// @notice Recomputes the exact digest a Guardian off-chain signer must
    /// produce for a given (account, nonce, callData, decision, expiry,
    /// requestId) - exposed so the off-chain signer/tests can construct the
    /// identical hash without duplicating the EIP-712 encoding logic.
    function attestationDigest(
        address account,
        uint256 nonce,
        bytes calldata callData,
        uint8 decision,
        uint48 expiry,
        bytes32 requestId
    )
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                account,
                entryPoint,
                block.chainid,
                nonce,
                keccak256(callData),
                decision,
                expiry,
                requestId
            )
        );
        return _hashTypedDataV4(structHash);
    }
}
