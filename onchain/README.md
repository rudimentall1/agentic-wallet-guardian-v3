# Guardian on-chain — GuardianValidator

An [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) validator module
that turns a Guardian decision into something that physically stops a
transaction from executing, not just something an agent is advised to
respect.

## Why this exists

Every other integration in this project — the REST API, the MCP server,
even the `guardian-check` skill — is **advisory**: Guardian tells you
ALLOW/WARN/BLOCK, but the caller still has to *choose* to respect that
answer. Nothing stops a compromised or misbehaving agent process from
simply not asking, or asking and ignoring the answer.

`GuardianValidator` closes that gap for any [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)
smart account that installs it as a validator module: the account's
UserOperations are only ever included on-chain if `validateUserOp`
returns success, and this implementation returns success only when a
trusted Guardian signer has attested — for this *exact* operation, not
a generic "this account is fine" — that the decision was ALLOW.

## Why a second signature format, not OAA/Ed25519 reused directly

Guardian's [Open Agent Attestation](../README.md) tokens are Ed25519-signed
JWTs — the right choice for a portable, chain-agnostic, offline-verifiable
audit trail. But EVM chains, Base included, have no native Ed25519
precompile ([EIP-665](https://eips.ethereum.org/EIPS/eip-665) proposed one
in 2018; it was never adopted). Verifying Ed25519 in pure Solidity costs on
the order of 2,000,000 gas — regularly gating transactions through that
would be prohibitively expensive on essentially any EVM chain today.

A secp256k1 signature, by contrast, verifies via `ecrecover` for about
3,000 gas — independently measured (`forge test --gas-report`) at
**27k–59k gas for the entire `validateUserOp` call**, three orders of
magnitude cheaper. So Guardian signs the same underlying decision a
*second* time, with a second, EVM-native key, specifically for this
on-chain leg — see [`guardian/onchain_attestation.py`](../guardian/onchain_attestation.py)
for the Python side. OAA/Ed25519 is untouched and remains the off-chain
standard; this is an additional, EVM-specific attestation format for a
different verification context, not a replacement.

## What's deliberately out of scope

- **WARN never passes on-chain.** There's no synchronous way to route a
  WARN to a human for confirmation from inside ERC-4337's validation
  phase — that has to happen entirely off-chain, before a UserOperation
  is even built, resulting in either a fresh ALLOW attestation or
  nothing. See the contract's own docstring for the full reasoning.
- **This module doesn't compose with other validators for you.** An
  account that wants an ordinary owner signature on some operations and
  Guardian-gating on others does that via its own standard ERC-7579
  multi-validator dispatch — this module only ever checks for a valid
  Guardian attestation.
- **No mainnet deployment yet.** This has real, independently-verified
  unit and integration tests (see below) but has not been through a
  professional security audit — do not point this at real funds without
  one.

## Building and testing

Requires [Foundry](https://getfoundry.sh/).

```bash
cd onchain
forge install eth-infinitism/account-abstraction --no-git
forge install erc7579/erc7579-implementation --no-git
forge install OpenZeppelin/openzeppelin-contracts --no-git
forge install foundry-rs/forge-std --no-git
forge build
forge test -vv
```

21 tests, all real (fuzzed core guarantee at 256 runs; no mocked
signature verification anywhere — every "does a bad signature get
rejected" test uses `vm.sign` to produce a genuine, invalid-for-this-case
ECDSA signature, not a stub). Includes
[`test/PythonCrossVerify.t.sol`](test/PythonCrossVerify.t.sol), which
verifies a signature produced by `guardian/onchain_attestation.py`
running as real Python (not reimplemented in Solidity) is accepted
on-chain — proving the EIP-712 digest the two languages compute
independently is byte-identical, not just that each side's own tests
pass in isolation.

```
validateUserOp   27,270 – 58,774 gas (min–max across the test suite)
```

## Deploying

```solidity
new GuardianValidator(entryPointAddress)
```

`entryPointAddress` is not hardcoded as a constant — pass the ERC-4337
EntryPoint this deployment should trust (e.g.
`0x0000000071727De22E5E9d8BAf0edAc6f37da032` for the current canonical
v0.7 EntryPoint, independently confirmed live and verified on
[BaseScan](https://basescan.org/address/0x0000000071727de22e5e9d8baf0edac6f37da032)
while building this — though note that page itself already flags a
newer v0.9 EntryPoint as the currently-recommended version; check what's
current before deploying). Binding it explicitly rather than hardcoding
one version means the same module source can be redeployed against
whichever EntryPoint version is current, without needing an upgrade path
for this alone.

After deployment, each smart account installs it with:

```solidity
account.installModule(MODULE_TYPE_VALIDATOR, address(guardianValidator), abi.encode(guardianSignerAddress));
```

where `guardianSignerAddress` is the EVM address corresponding to the
secp256k1 key your Guardian instance signs on-chain attestations with
(see `guardian/onchain_attestation.py` — this is a *different* key from
your OAA Ed25519 key).
