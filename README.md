# Agentic Wallet Guardian

**A self-hosted decision engine that sits between an AI agent and blockchain
execution.** Agents submit a proposed action, Guardian returns an
explainable ALLOW / WARN / BLOCK before anything gets signed or broadcast.

```
POST /decision   ->   ALLOW / WARN / BLOCK  (with a reasoned explanation)
```

It runs on your own infrastructure, using your own policy rules and your
own reputation data - see [Why self-hosted](#why-self-hosted) for why that
matters and how this differs from calling a hosted security API directly.

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
        ┌─────────────────────────┐
        │   Guardian Decision      │
        │        Engine             │
        ├───────────────────────────┤
        │  1. Hard Rules             │  <- chain support, sanity checks
        │  2. Wallet Intelligence     │  <- mock | real RPC (web3.py)
        │  3. Token Intelligence       │  <- mock | real DexScreener | real GoPlus
        │  4. Contract Intelligence     │  <- local lists, then mock | real Blockscout | real GoPlus
        │  5. Simulation                 │  <- mock | real eth_call dry-run (see below)
        │  6. Threat Intelligence          │  <- local JSON allow/deny lists
        │  7. Policy Engine                 │  <- spending caps, reputation gates
        │  8. Risk Fusion                    │  <- signals -> single 0-100 score
        │  9. Reputation Adjustment            │
        │ 10. Explanation                       │  <- evidence -> human-readable reasons
        └───────────────────────────────────────┘
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
  in a real transaction. `swap` and `bridge` are NOT built - that needs
  real DEX/bridge routing (liquidity sourcing, price impact, slippage),
  a categorically bigger problem than encoding one well-known function
  call, and still genuinely open.
- **Storage:** `InMemoryStorage` (default, zero setup) or `SQLiteStorage`
  (`GUARDIAN_STORAGE_BACKEND=sqlite` - persists across restarts, no
  external infra). Neither is a fit for many replicas writing
  concurrently at high volume; implement `MemoryBackend` against
  Postgres/Redis for that.
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

### MCP (no HTTP required)

For agent frameworks that speak MCP (LangChain, CrewAI, Claude Desktop,
etc.), `mcp_server.py` exposes the same decision engine as two tools
(`evaluate_action`, `get_agent_history`) over stdio - install
`requirements-mcp.txt` **in its own virtual environment** (see the comment
at the top of that file for why it can't share an environment with
`requirements.txt`) and point your MCP client at
`python mcp_server.py`.

---

## Running the tests

```bash
pip install -r requirements.txt -r requirements-chain.txt
pytest -q
```

`requirements-chain.txt` (`web3`) is only needed for the RPC-provider
tests; the rest of the suite runs with just `requirements.txt`. The
`guardian/*` core has no external dependencies beyond that, so it's also
runnable with:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

CI (`.github/workflows/ci.yml`) runs the full suite on every push/PR
against Python 3.11 and 3.12.

---

## Roadmap

1. ~~Replace the mock wallet/token/contract analyzers with real data
   sources.~~ Done - see [Honesty about the current state](#honesty-about-the-current-state)
   for what "real" does and doesn't cover yet per source.
2. ~~Wire up real pre-execution simulation.~~ Done for `transfer`/
   `approve` end to end (`GUARDIAN_SIMULATION_PROVIDER=rpc` +
   `GUARDIAN_TX_BUILDER=rpc` - see
   [Honesty about the current state](#honesty-about-the-current-state)).
   `swap`/`bridge` still need real DEX/bridge routing to build a
   transaction from a semantic intent - a categorically bigger problem,
   still open.
3. ~~Populate threat-intel / sanctions feeds; stop shipping empty
   sets.~~ Done for sanctions (`sanctioned_addresses.json` - 103 real OFAC
   SDN addresses, refreshable via `scripts/refresh_ofac_list.py`).
   `malicious_contracts.json` / `verified_contracts.json` remain empty by
   design - no single authoritative source exists to seed them the way
   OFAC's list does for sanctions.
4. ~~Swap `InMemoryStorage` for a persistent backend.~~ `SQLiteStorage` is
   available; a Postgres/Redis backend is still open for multi-replica
   deployments.
5. ~~Add an MCP server wrapper.~~ Done (`mcp_server.py`). A packaged
   Python/TypeScript SDK on top of the REST API is still open.
6. Publish an OpenAPI spec and a hosted demo endpoint.
7. Get the policy engine and risk fusion reviewed/audited before anyone
   relies on a `BLOCK` from this service in production - it's a security
   tool, so it needs the same scrutiny it applies to others.

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

---

## License

MIT - see `LICENSE`.
