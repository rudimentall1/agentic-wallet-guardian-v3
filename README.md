<!-- mcp-name: io.github.rudimentall1/agentic-wallet-guardian-v3 -->
# Agentic Wallet Guardian
[![agentic-wallet-guardian-v3 MCP server](https://glama.ai/mcp/servers/rudimentall1/agentic-wallet-guardian-v3/badges/card.svg)](https://glama.ai/mcp/servers/rudimentall1/agentic-wallet-guardian-v3)

📄 [Read the white paper](docs/whitepaper.pdf)

**Let AI agents transact on-chain without giving them unrestricted control of the wallet.** Guardian evaluates each proposed action before signing or broadcast and returns an explainable ALLOW / WARN / BLOCK decision.

```
POST /decision   ->   ALLOW / WARN / BLOCK  (with a reasoned explanation)
```

It runs on your own infrastructure, using your own policy rules and your
own reputation data - see [Why self-hosted](#why-self-hosted) for why that
matters and how this differs from calling a hosted security API directly.

Guardian is chain- and use-case-agnostic - Arc/USDC below is one live
deployment, not the whole scope. See [docs/hackathons.md](docs/hackathons.md)
for which track this submission targets and why.


## Arc Mainnet Demo

**Live demo:** http://77.239.125.37:8765/arc

**Demo video:** https://youtu.be/srH0ZLwtwqQ

Agentic Wallet Guardian is deployed on Arc mainnet and includes a live browser demo for USDC payments. The Guardian evaluates the requested operation before execution, applies its security policies, and only an approved operation is passed to the user's wallet for signing.

**Verified Arc mainnet transaction:**
0xd781e8b04b5ca89c3a34fcec50a6636049f7647d2b0e1b2bb64d5b1ee54daadf

The transaction was successfully executed on Arc mainnet using USDC through the Guardian demo.

---

**See it decide, live:** run the API locally (`GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO=true
uvicorn api.main:app --reload`), then open [`examples/browser-demo.html`](examples/browser-demo.html)
in a browser - no build step, no server for the page itself. Every
scenario button sends a real `POST /decision` to your running instance
and renders the actual response (risk score, every signal that fed into
it, every policy rule that fired) - nothing in the page is scripted or
faked. `GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO` is off by default (see
`guardian/config.py`) since it's specifically for this local-demo case,
not something to leave on for a real deployment.

---

## Why self-hosted

There are good hosted alternatives for agent-transaction security (GoPlus's
AgentGuard, Blockaid, Chainalysis/TRM for compliance). If you just want a
risk score and don't care who sees the query, calling one of those directly
is less work than running this. Guardian exists for the cases where that
tradeoff doesn't work for you:

- **Nothing about which wallets, contracts, or amounts your agents touch
  leaves your infrastructure.** Threat-intel and contract allow/deny checks
  are local JSON files you populate yourself (see
  `data/threat_lists/README.md`), not a lookup call to a third party. A
  hosted API inherently sees every address and amount you ask it about.
- **Your policy rules live in your code, not a vendor's dashboard.**
  Spending caps, reputation gates, and which action types require
  confirmation are plain Python in `guardian/policy/`, reviewable and
  changeable without waiting on anyone else's product roadmap.
- **No per-call fees or rate limits imposed by someone else** - only the
  ones you configure for your own users (`GUARDIAN_RATE_LIMIT_PER_MINUTE`).
- **No vendor lock-in.** Every external data source (RPC endpoint,
  Blockscout instance, DexScreener) is swappable behind a small provider
  interface - see [Architecture](#architecture).

The honest tradeoff going the other way: you also take on running it,
keeping your local threat lists current, and you don't get a hosted
vendor's chain coverage or dedicated threat-research team for free. This is
the right choice for teams that specifically need data sovereignty or deep
policy customization - not a strict upgrade over every hosted option.

---

## Architecture

```
                AI Agent
                    |
                    v
             Action Intent
   { agent_id, wallet, chain, action_type,
     target, amount, metadata }
                    |
                    v
        ┌───────────────────────────────┐
        │   Guardian Decision Engine    │
        ├───────────────────────────────┤
        │  1. Hard Rules                │  <- chain support, sanity checks
        │  2. Wallet Intelligence       │  <- mock | real RPC (web3.py)
        │  3. Token Intelligence        │  <- mock | real DexScreener | real GoPlus
        │  4. Contract Intelligence     │  <- local lists, then mock | real Blockscout | real GoPlus
        │  5. Simulation                │  <- mock | real eth_call dry-run (see below)
        │  6. Threat Intelligence       │  <- local JSON allow/deny lists
        │  7. Anomaly Detection         │  <- vs. this agent's own history (see below)
        │  8. Policy Engine             │  <- spending caps, reputation gates
        │  9. Risk Fusion               │  <- signals -> single 0-100 score
        │ 10. Reputation Adjustment     │
        │ 11. Explanation               │  <- evidence -> human-readable reasons
        └───────────────────────────────┘
                    |
                    v
          ALLOW / WARN / BLOCK
                    |
                    v
          Blockchain Execution
```

Every data source in steps 2-4 is a small provider interface with a mock
implementation (zero config, zero network calls) and a real one, selected
per-source by environment variable - see `.env.example`. Switching from
demo mode to a real deployment is a config change, not a code change.

### Repository layout

```
guardian/
    config.py          GuardianConfig - the one place that reads os.environ
    core/               ActionIntent, Signal, Decision, EvaluationContext
                            (zero external dependencies - no pydantic/FastAPI)
    decision/           DecisionEngine (orchestrator), RiskFusionEngine, hard rules
    reasoning/          explanation + confidence builders
    intelligence/
        wallet/           analyzer.py + providers.py (mock | RpcWalletDataProvider)
        token/            analyzer.py + providers.py (mock | DexScreenerTokenDataProvider | GoPlusTokenDataProvider)
        contract/         analyzer.py + providers.py (mock | BlockscoutContractDataProvider | GoPlusContractDataProvider)
        simulation/       pre-execution dry-run (mock | real eth_call) + tx_builder.py (real calldata for transfer/approve)
        goplus_client.py  shared GoPlus Token Security API client (used by both contract + token)
        threat/           blocklist.py (local AddressList) + intelligence.py
    policy/             PolicyEngine + policy templates (spending caps, reputation gates)
    reputation/         AgentReputation (score derived from decision history)
    memory/             storage.py (protocol) + InMemoryStorage + sqlite_storage.py
api/
    main.py             FastAPI app: /decision, /health, /capabilities, /agents/{id}/history, /demo/{scenario}
    security.py         API-key auth dependency + rate-limit middleware
    schemas.py          pydantic request/response models (API boundary only)
mcp_server.py           MCP stdio server - same DecisionEngine, no HTTP required
data/threat_lists/      local, operator-maintained allow/deny lists (empty by default - see its README)
scripts/
    refresh_ofac_list.py   fetch OFAC's public SDN list into the local threat list
tests/                  101 tests covering the engine, policy, reputation, and every provider
```

`guardian/*` is intentionally dependency-free (standard library only,
except where a real provider needs `httpx` or `web3`), so the decision
core can be unit-tested, embedded in another service, or ported to a
different web framework without dragging FastAPI along. Only `api/`
touches pydantic/FastAPI.

---

## Honesty about the current state

This is real, runnable, tested decision infrastructure with real (not
mock) data sources available for every signal source - but "available"
isn't the same as "flip a switch and trust it blindly." Specifics:

- **Wallet (RPC provider):** `is_contract` and `tx_count` (nonce-based) are
  reliable with any JSON-RPC endpoint. Wallet *age* requires an
  archive-capable node and is off by default
  (`GUARDIAN_RPC_ESTIMATE_AGE=false`) - most free public RPC endpoints
  don't serve historical state, so this fails closed to "unknown" rather
  than guessing.
- **Contract (Blockscout provider):** real verification-status lookups
  against a public Blockscout instance. Their exact response schema and
  rate limits can change - this is written to degrade to "unknown" on any
  unexpected response, never to fabricate an answer, but hasn't been load-
  tested against production traffic.
- **Token (DexScreener provider):** real liquidity data, but matching a
  bare ticker symbol to an on-chain pair is inherently ambiguous (many
  unrelated tokens share a symbol, and scammers deliberately mint
  look-alikes). The provider picks the highest-liquidity pair on the
  requested chain and reports its own match confidence rather than
  presenting a guess as certain - for anything where that ambiguity
  matters, match by contract address instead of symbol.
- **Contract + Token (GoPlus provider):** real contract-security
  (owner-can-drain, mintable, self-destruct, hidden owner) and
  trading-security (honeypot, buy/sell tax, blacklist, pausable transfers,
  holder concentration) from GoPlus's Token Security API - meaningfully
  more signal types than Blockscout/DexScreener give individually, since
  GoPlus's own static analysis covers both in one call. Two real limits:
  it only has data for contracts it's actually analyzed (mostly token
  contracts, not generic dApp/router contracts), and `GoPlusTokenDataProvider`
  needs a contract *address* - a bare symbol like "PEPE" can't be resolved
  and is honestly reported as unverifiable rather than guessed at.
- **Sanctioned-address list is real, populated data**: 103 addresses (100
  EVM + 3 Solana) from OFAC's SDN list, via
  [0xB10C/ofac-sanctioned-digital-currency-addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) -
  verified end-to-end (a known-sanctioned address correctly triggers
  `BLOCK` through the full pipeline) and verified to correctly reflect
  delistings, not just additions (Tornado Cash's addresses, removed from
  the SDN list in March 2025, are correctly absent). Re-run
  `scripts/refresh_ofac_list.py` periodically - sanctions change in both
  directions.
- **`malicious_contracts.json` / `verified_contracts.json` still ship
  empty on purpose** (see `data/threat_lists/README.md`) - there's no
  single authoritative source for "malicious contract" the way OFAC's
  list is authoritative for sanctions, so populating these is a judgment
  call for whoever operates this instance, not something to seed by
  default with unverified entries.
- **Simulation is real, but conditional.** `RpcSimulationProvider`
  (`GUARDIAN_SIMULATION_PROVIDER=rpc`) genuinely dry-runs a transaction via
  `eth_call`/`eth_estimateGas` against current chain state - a revert comes
  back with its actual reason, not a guess, and ERC-20 `approve()` amounts
  are decoded from real calldata instead of inferred. This activates when
  the caller supplies raw calldata via `intent.metadata["data"]`, OR - new -
  when `GUARDIAN_TX_BUILDER=rpc` is also set and the intent is a plain
  `transfer` or `approve` (see next bullet). A `swap` intent with no
  transaction built yet still has nothing to dry-run - Guardian reports
  that honestly (`simulation_not_attempted`) rather than guessing.
- **Transaction building closes part of that gap, deliberately not all
  of it.** `RpcTransactionBuilder` (`GUARDIAN_TX_BUILDER=rpc`) turns a
  semantic `transfer`/`approve` intent into real calldata - it fetches the
  token's actual `decimals()` via RPC rather than assuming 18 (a wrong
  assumption there would scale the amount by orders of magnitude), and
  deliberately has no hardcoded token-address registry: a bare symbol like
  "USDC" is refused rather than guessed at, since a wrong address here
  wouldn't just be a bad risk signal, it'd be an artifact that could end up
  in a real transaction. `swap` is built against Uniswap V2 Router02 only
  (one immutable, well-known contract - function selectors computed
  locally via `Web3.keccak`, not copied from memory) - real
  `getAmountsOut()` on-chain quote, caller-supplied `max_slippage_bps`
  required (never a default, same reasoning as decimals above). `bridge`
  is a genuinely open-ended L2/bridge routing problem in general - dozens
  of protocols, wildly different trust models - but this module handles
  one well-scoped slice of it: L1 -> L2 deposits through a destination
  chain's own official OP Stack bridge (currently: Base and Optimism -
  `depositETHTo`/`depositERC20To` on `L1StandardBridge`, both addresses
  independently cross-checked - Base against Etherscan's label plus
  basehub.org, Optimism against the official
  ethereum-optimism/superchain-registry plus a second independent
  dev-tool config - before being hardcoded).
  L2 -> L1 withdrawals are NOT built - that's a genuinely different, much
  slower proof/challenge-window flow, not a variant of the deposit call.
  Bridging to anywhere else, or via any non-canonical bridge, returns
  `None` rather than guessing.
- **Intent verification can now actually enforce, not just flag.**
  `decision/intent_verification.py` compares an agent's declared
  `approve` amount against what the simulated calldata really encodes -
  but that comparison needs the token's `decimals()` to convert between
  human units and atomic ones. `GUARDIAN_DECIMALS_PROVIDER=rpc`
  (`RpcTokenDecimalsProvider`, see
  `guardian/intelligence/token/decimals.py`) fetches that for real via
  `eth_call`, cached forever per (chain, token) since a deployed
  contract's `decimals()` can't change. Left at its `null` default, a
  mismatch this module could otherwise catch degrades to an honest
  "cannot verify" WARN instead - same "no silent guessing" rule as
  everywhere else in this module, not a gap that got missed.
  `RpcTransactionBuilder` shares this same cache when both are
  configured with a real provider, instead of doing its own independent,
  uncached lookup for the same token.
- **Storage:** `InMemoryStorage` (default, zero setup), `SQLiteStorage`
  (`GUARDIAN_STORAGE_BACKEND=sqlite` - persists across restarts, no
  external infra), or `PostgresStorage`
  (`GUARDIAN_STORAGE_BACKEND=postgres` + `GUARDIAN_POSTGRES_DSN` - the
  fit for multiple replicas behind a load balancer, where SQLite's
  single-writer model becomes the bottleneck; `pip install -r
  requirements-postgres.txt`). Tested against a real local Postgres
  instance, not mocked - see `tests/test_postgres_storage.py`. Redis is
  still open if you specifically want it; the two-method
  `MemoryBackend` interface is small enough to implement against
  anything.
- **API auth/rate-limiting** are intentionally minimal - built for one
  self-hosted instance behind your own network boundary, not a
  multi-tenant gateway. Put a real API gateway in front if you need that.
- **Not security-audited.** The policy engine and risk fusion logic have
  not been reviewed by anyone outside this repo. Treat `BLOCK` as a strong
  signal, not a guarantee, until that's happened.

Everything downstream of a `Signal` - fusion, policy, reputation,
explanation, the API - does **not** need to change as any of the above
gets hardened further. That boundary is the actual design contract here.

---

## Quickstart

Zero-config demo mode (mock providers, in-memory storage, no auth):

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Or with Docker:

```bash
docker compose up --build
```

Try the canned scenarios:

```bash
curl http://localhost:8000/demo/safe
curl http://localhost:8000/demo/unknown
curl http://localhost:8000/demo/malicious
```

Or submit your own intent:

```bash
curl -X POST http://localhost:8000/decision \
  -H "Content-Type: application/json" \
  -d '{
        "agent_id": "trading-agent-001",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "chain": "ethereum",
        "action_type": "swap",
        "from_token": "ETH",
        "to_token": "USDC",
        "amount": 5
      }'
```

### Going from demo to a real self-hosted deployment

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

At minimum for a real deployment: set `GUARDIAN_API_KEY` (auth is off by
default), `GUARDIAN_STORAGE_BACKEND=sqlite` (persistence), and whichever
`GUARDIAN_*_PROVIDER` variables you want pointed at real data instead of
mock - see the comments in `.env.example` for every option, and
`RpcWalletDataProvider`/`BlockscoutContractDataProvider`/
`DexScreenerTokenDataProvider`/`GoPlusContractDataProvider`/
`GoPlusTokenDataProvider`'s docstrings for what each one actually
gives you.

**If more than one agent shares this deployment**, also set
`GUARDIAN_AGENT_API_KEYS` (format: `agent_id:key,agent_id2:key2`). A
single `GUARDIAN_API_KEY` only proves *a* caller holds a valid key - it
does not prove *which* agent_id a given request actually came from, since
`agent_id` is just a field in the request body. Anyone holding the shared
key can submit any agent_id and inherit that agent_id's accumulated
reputation and capability grants. `GUARDIAN_AGENT_API_KEYS` binds each
agent_id to its own key; `GUARDIAN_API_KEY`, if also set, keeps working
as a master key that can act as any agent, for admin/testing use. For a
genuinely single-agent deployment, `GUARDIAN_API_KEY` alone is fine.

### MCP (no HTTP required)

For agent frameworks that speak MCP (LangChain, CrewAI, Claude Desktop,
etc.), `mcp_server.py` exposes the same decision engine as two tools
(`evaluate_action`, `get_agent_history`) over stdio - install
`requirements-mcp.txt` alongside `requirements.txt` (they resolve into one
environment; see the comment at the top of `requirements-mcp.txt`) and
point your MCP client at `python mcp_server.py`.

---


## Arc mainnet payment demo

Guardian 3.2 adds a small, non-custodial Arc mainnet surface for autonomous USDC payments.

- Arc mainnet, chain ID 5042, official RPC `https://rpc.mainnet.arc.io`
- Arc USDC ERC-20 interface `0x3600000000000000000000000000000000000000` (6 decimals)
- Guardian runs the normal hard-rules, intelligence, simulation, policy and risk pipeline before it releases a transaction
- the demo policy caps autonomous payments at 5 USDC and blocks approve/swap/bridge/contract-call actions on this surface
- only an `ALLOW` decision produces a signable transaction; the browser wallet remains the only signer
- the public demo keeps one bounded history identity (`arc-demo-agent`) so visitor traffic cannot create unbounded per-agent memory keys
- open `/arc` on a running instance to connect a wallet, ask Guardian, and sign the resulting Arc payment

Manual Arc verification:

```bash
python scripts/verify_arc_mainnet.py
```

The script checks chain ID, live block height, gas price and the mainnet USDC `decimals()` call. It does not require a private key.

## Running the tests

```bash
pip install -r requirements.txt -r requirements-chain.txt -r requirements-mcp.txt
pytest -q
```

`requirements-chain.txt` (`web3`) is needed by the RPC and on-chain
attestation tests. `requirements-mcp.txt` installs the MCP SDK used by
`mcp_server.py`. PyJWT and cryptography are core dependencies because OAA
attestations use JWTs and Ed25519 signing. The CI install matches this
full test environment.

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

CI (`.github/workflows/ci.yml`) runs the full suite on every push/PR
against Python 3.11 and 3.12.

---

## Signed, verifiable decisions (OAA)

Every decision this service returns — from a single policy check up
through the full pipeline — is signed as an [OAA (Open Agent
Attestation)](https://github.com/rudimentall1/open-agent-attestation)
token: an Ed25519-signed JWT wrapping the decision, the action, and
the reason.

Anyone holding the public key can verify a decision offline, without
calling back to whatever instance of Guardian issued it — useful for
an auditor, a downstream service, or just a record you want to trust
later without trusting the server that produced it.

```bash
python examples/example_oaa_attestation.py
python examples/example_full_pipeline.py   # capability -> intent -> engine -> OAA
```

The reference OAA implementation is ~150 lines
(`oaa.py`/`attestation.py` upstream) and is shared, unmodified,
across this project and [agent-guardrail](https://github.com/rudimentall1/agent-guardrail) —
same signing format, same verification path, no per-project fork.

---

## Using Guardian in front of MetaMask Agent Wallet

MetaMask Agent Wallet's Guard Mode / Beast Mode apply the same static
spend limits and allowlists to every agent. Guardian is a second,
independent check in front of it: does *this* specific action look
right for *this* agent, right now — before the `mm` CLI is ever
invoked.

[`skills/guardian-check/`](skills/guardian-check/) is a standard
[Agent Skill](https://agentskills.io) — the same open format MetaMask
itself uses for `mm` (`npx skills add MetaMask/agent-skills`). Install
it alongside MetaMask's own skill in any Agent-Skills-compatible
runtime (Claude Code, Cursor, Codex, OpenClaw), and the agent will
call a running Guardian instance for an ALLOW/WARN/BLOCK decision
before running any `mm` command that moves funds — `mm send`, `mm
swap`, `mm bridge`, `mm perps`, `mm predict trade`, `mm earn`, `mm
aave`, `mm pay`.

Guardian never holds keys and never executes anything — `mm` remains
the only thing that signs or broadcasts. This is a decision gate the
agent is instructed to consult first, not a modification to
MetaMask's own pipeline (there's no public hook for that today).

```bash
uvicorn api.main:app --reload   # run Guardian locally
export GUARDIAN_API_URL="http://localhost:8000"
python skills/guardian-check/scripts/check.py \
  --agent-id my-agent --wallet 0x... --chain ethereum \
  --action-type transfer --target 0x... --amount 50
```

---

## From advisory to enforced: GuardianValidator

Everything above is advisory - Guardian tells you ALLOW/WARN/BLOCK, but
the caller still has to *choose* to respect that. [`onchain/`](onchain/)
is a real ERC-7579 validator module for ERC-4337 smart accounts that
closes that gap: once installed, the account's UserOperations only ever
reach the chain if a trusted Guardian signer attested, for that *exact*
operation, that the decision was ALLOW - not something an agent can skip
asking or ignore the answer to. See [`onchain/README.md`](onchain/README.md)
for why it needs a second, EVM-native signature format alongside OAA
(Ed25519 has no EVM precompile and costs ~2,000,000 gas to verify in pure
Solidity; this module's entire `validateUserOp` costs 27k-59k gas), what's
deliberately out of scope (WARN never passes on-chain; no professional
audit yet), and how to build, test, and deploy it - including a test that
verifies a signature produced by real, running Python
(`guardian/onchain_attestation.py`) is accepted by the real Solidity
contract, not two implementations that only agree with themselves.

---

## Roadmap

1. ~~Replace the mock wallet/token/contract analyzers with real data
   sources.~~ Done - see [Honesty about the current state](#honesty-about-the-current-state)
   for what "real" does and doesn't cover yet per source.
2. ~~Wire up real pre-execution simulation.~~ Done for `transfer`/
   `approve` end to end (`GUARDIAN_SIMULATION_PROVIDER=rpc` +
   `GUARDIAN_TX_BUILDER=rpc` - see
   [Honesty about the current state](#honesty-about-the-current-state)).
   ~~`swap` needs real DEX routing.~~ Done against Uniswap V2 Router02 -
   real on-chain `getAmountsOut()` quote, explicit caller-supplied
   `max_slippage_bps` (never defaulted), no calldata built without a real
   quote. Fixed a real bug found while building this: simulation was
   dry-running against `intent.target` (the recipient/spender encoded
   *inside* ERC-20 calldata) instead of the actual contract being called
   (`from_token`) - meaning transfer/approve simulation silently
   "succeeded" against any EOA recipient regardless of whether the real
   call would have reverted. `BuiltTransaction` now carries an explicit
   `to`; see `tests/test_tx_builder.py` for the regression tests that
   would have caught it. ~~`bridge` still open.~~ Done for L1->L2
   deposits to Base and Optimism via the official OP Stack
   `L1StandardBridge` (`depositETHTo`/`depositERC20To`) - other
   destinations, other bridge protocols, and L2->L1 withdrawals all
   remain open; see
   [Honesty about the current state](#honesty-about-the-current-state).
3. ~~Populate threat-intel / sanctions feeds; stop shipping empty
   sets.~~ Done for sanctions (`sanctioned_addresses.json` - 103 real OFAC
   SDN addresses, refreshable via `scripts/refresh_ofac_list.py`).
   `malicious_contracts.json` / `verified_contracts.json` remain empty by
   design - no single authoritative source exists to seed them the way
   OFAC's list does for sanctions.
4. ~~Swap `InMemoryStorage` for a persistent backend.~~ `SQLiteStorage` is
   available; ~~a Postgres/Redis backend is still open for multi-replica
   deployments.~~ `PostgresStorage` done - tested against a real local
   Postgres instance (`tests/test_postgres_storage.py`), same
   two-method `MemoryBackend` interface as the other backends. Redis
   remains open if specifically wanted.
5. ~~Add an MCP server wrapper.~~ Done (`mcp_server.py`). A packaged
   Python/TypeScript SDK on top of the REST API is still open.
6. Publish an OpenAPI spec and a hosted demo endpoint.
7. Get the policy engine and risk fusion reviewed/audited before anyone
   relies on a `BLOCK` from this service in production - it's a security
   tool, so it needs the same scrutiny it applies to others.
8. ~~Add per-agent capability limits (delegation scoping).~~ Done -
   `guardian/policy/capabilities.py`, and wired into
   `DecisionEngine.evaluate()` via an optional `capability_registry`
   constructor argument (previously it was a standalone module you had
   to call yourself outside the normal pipeline - see
   `examples/example_capability_limits.py`, which now runs through
   `DecisionEngine` directly). Opt-in: pass no registry (the default)
   and nothing changes; an operator can grant a specific agent a scoped
   capability (allowed action types, allowed chains, per-action and
   daily spending caps, an expiry) with zero private-key material
   involved. Agents with no grant are unaffected. This module still
   never touches private keys or session-key issuance itself - that
   remains out of scope, a categorically higher-stakes problem. ~~Real
   enforcement of a decision (vs. an agent choosing to respect it)
   remains deliberately out of scope.~~ Partially done -
   [`onchain/`](onchain/)'s `GuardianValidator` is an ERC-7579 module
   that makes a decision genuinely unbypassable for any ERC-4337 smart
   account that installs it, without Guardian ever holding a key. It
   does not manage session keys, custody, or account creation - it
   only gates execution behind an attestation - so this is a real,
   load-bearing piece of "account abstraction," not the whole of it.
9. ~~Verify declared intent against decoded simulation results.~~
   Done - `guardian/decision/intent_verification.py` catches
   the case where an agent declares one amount but the actual calldata
   it was handed encodes a meaningfully different (but still finite)
   one, and `DecisionEngine.evaluate()` now actually calls it (it
   didn't before - the module and its example script existed, but
   nothing in the real decision pipeline invoked it). ~~It's still not
   a working guardrail on its own, though: comparing atomic units needs
   the token's `decimals()`, and no decimals provider exists yet.~~
   `GUARDIAN_DECIMALS_PROVIDER=rpc` (`RpcTokenDecimalsProvider`, see
   `guardian/intelligence/token/decimals.py`) closes that: a real
   `eth_call` to the token's own `decimals()`, cached forever per
   (chain, token) since that value can never change once a contract is
   deployed. Left at its `null` default, every `approve` with a
   successful, finite-amount simulation still gets an honest "cannot
   verify without decimals" WARN instead of either a false BLOCK or a
   silent skip - configuring the real provider is what turns that into
   an actual BLOCK on a genuine mismatch. See
   `examples/example_intent_verification.py` for the check blocking a
   real mismatch, and `tests/test_decision_engine.py`'s
   `TestIntentVerificationWithRealDecimalsProvider` for the end-to-end
   version wired through a real (mocked-RPC) decimals lookup rather
   than a hand-supplied `token_decimals` argument.
10. ~~Flag actions that deviate from an agent's own historical
    pattern.~~ Done - `guardian/intelligence/anomaly/analyzer.py`.
    Distinct from reputation (a single trust score) and policy (static,
    operator-set limits): this compares the current intent against
    *this specific agent's* own recorded history - new action type,
    new chain, or an amount that's a statistical outlier versus what
    this agent has done before, even if it's within policy limits and
    the agent's reputation is fine. Honestly reports "insufficient
    history" rather than guessing a baseline from fewer than 5 prior
    data points - see `tests/test_anomaly_detection.py`.
11. ~~Sit in front of a real agent wallet, not just accept intents
    from a generic API caller.~~ Done for MetaMask Agent Wallet -
    `skills/guardian-check/` is a standard Agent Skill an agent
    installs alongside MetaMask's own `mm` skill; the agent calls it
    before running any fund-moving `mm` command and only proceeds on
    ALLOW. Tested end-to-end against a live `uvicorn` instance
    (ALLOW/WARN/BLOCK/config-error all exercised for real, not just
    asserted) - see the "Using Guardian in front of MetaMask Agent
    Wallet" section above. No public hook exists (yet) to run inside
    MetaMask's own pipeline; this works at the agent-orchestration
    layer instead.

---

## Related projects

Same author, same principle applied elsewhere:

- [agent-guardrail](https://github.com/rudimentall1/agent-guardrail) -
  a generic policy firewall for AI agent tool calls (not
  blockchain-specific). Published on PyPI, MIT, 46 tests.
- [x402-attest](https://github.com/rudimentall1/x402-attest) -
  cryptographically signed (Ed25519), independently verifiable
  attestations for agent-to-agent payment policy decisions. Early
  proof of concept.
- [open-agent-attestation](https://github.com/rudimentall1/open-agent-attestation) -
  vendor-neutral open spec (JWT+EdDSA) for signing agent policy
  decisions, verifiable by anyone. x402-attest above uses a custom
  format; this is the generalized version. Draft v0.1.

---

## License

MIT - see `LICENSE`.
