"""Guardian v3 API — FastAPI entrypoint.

Run locally:

    uvicorn api.main:app --reload

Endpoints:

    POST /decision              evaluate an action intent -> ALLOW / WARN / BLOCK
    GET  /health                   liveness check
    GET  /capabilities              what this deployment supports
    GET  /agents/{agent_id}/history   audit trail + current reputation for an agent
    GET  /demo/{scenario}             canned scenarios: safe | unknown | malicious
"""
from __future__ import annotations

import logging
from pathlib import Path

from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

from api.schemas import DecisionRequest, DecisionResponse
from api.security import RateLimitMiddleware, check_agent_bound_key, make_api_key_dependency
from guardian.config import get_config
from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.decision.rules import SUPPORTED_CHAINS
from guardian.arc import ARC_CHAIN, ARC_CHAIN_ID, ARC_EXPLORER_URL, ARC_USDC_ADDRESS, ARC_DEMO_AGENT_ID, build_arc_engine, prepare_arc_payment, arc_network_status

logger = logging.getLogger("guardian.api")

app = FastAPI(
    title="Agentic Wallet Guardian",
    version="3.2.0",
    description=(
        "Decision infrastructure for autonomous AI agents acting on blockchain "
        "wallets. Agents submit an action intent and receive an explainable "
        "ALLOW / WARN / BLOCK decision before execution."
    ),
)

config = get_config()

# A single shared engine instance keeps reputation/history in-process across
# requests for the lifetime of this process. Before running more than one
# instance behind a load balancer, swap DecisionHistory's backend for a
# shared store (Redis/Postgres) — see guardian/memory/storage.py, or set
# GUARDIAN_STORAGE_BACKEND=sqlite for a single-instance persistent default.
engine = DecisionEngine(config=config)
arc_engine = build_arc_engine(config)

require_api_key = make_api_key_dependency(config)
app.add_middleware(RateLimitMiddleware, limit_per_minute=config.rate_limit_per_minute)

if config.enable_cors_for_browser_demo:
    from fastapi.middleware.cors import CORSMiddleware

    # allow_origins=["*"] is deliberate here, not an oversight: this flag
    # exists specifically so a local browser demo (any static HTML page,
    # served from any origin - file://, a local dev server, claude.ai's
    # artifact sandbox) can call this instance directly. Scoping it to
    # one origin would defeat that purpose without adding real security,
    # since this is explicitly opt-in and documented as being for local
    # demo use - the actual access control is still whatever
    # GUARDIAN_API_KEY/GUARDIAN_AGENT_API_KEYS you have configured
    # separately; this only affects whether a browser is allowed to read
    # the response, not who can authenticate.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"],
    )
    logger.warning(
        "GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO is set - any web page can call this "
        "instance's API from a browser. Fine for a local demo; turn this off for any "
        "deployment reachable beyond your own machine."
    )

if not config.auth_enabled:
    logger.warning(
        "GUARDIAN_API_KEY is not set - /decision and /agents/*/history are running "
        "WITHOUT authentication. Fine for local dev; set GUARDIAN_API_KEY before "
        "exposing this instance beyond localhost."
    )


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.get("/capabilities", tags=["meta"])
def capabilities():
    return {
        "version": "3.1.0",
        "supported_chains": sorted(SUPPORTED_CHAINS),
        "action_types": ["swap", "transfer", "approve", "contract_call", "bridge"],
        "decision_types": ["ALLOW", "WARN", "BLOCK"],
        "pipeline": [
            "hard_rules",
            "wallet_intelligence",
            "token_intelligence",
            "contract_intelligence",
            "simulation",
            "threat_intelligence",
            "policy_engine",
            "risk_fusion",
            "reputation_adjustment",
            "explanation",
        ],
    }


@app.post("/decision", response_model=DecisionResponse, tags=["core"])
def decide(payload: DecisionRequest, authorization: Optional[str] = Header(default=None)):
    # Agent-bound, not just "is there a valid key at all": when
    # GUARDIAN_AGENT_API_KEYS is configured, the presented key must match
    # the specific agent_id in this payload - see check_agent_bound_key's
    # docstring for why a single shared key isn't enough to trust the
    # agent_id a caller claims. Falls back to the same global-key-only
    # check as before when no per-agent keys are configured.
    check_agent_bound_key(authorization, payload.agent_id, config)
    intent = ActionIntent(
        # Public demo traffic shares one bounded history key so arbitrary
        # caller-supplied agent IDs cannot create unbounded SQLite keys.
        agent_id=ARC_DEMO_AGENT_ID,
        wallet=payload.wallet,
        chain=payload.chain,
        action_type=payload.action_type,
        target=payload.target,
        from_token=payload.from_token,
        to_token=payload.to_token,
        amount=payload.amount,
        metadata=payload.metadata,
    )
    decision = engine.evaluate(intent)
    return decision.to_dict()


@app.get("/arc", include_in_schema=False)
def arc_demo():
    return FileResponse(str(Path(__file__).parent.parent / "examples" / "arc-demo.html"))


@app.get("/arc/status", tags=["arc"])
def arc_status():
    status = arc_network_status()
    return {"project": "Agentic Wallet Guardian", "arc": status}


@app.post("/arc/prepare", tags=["arc"])
def arc_prepare(payload: DecisionRequest):
    if payload.chain.lower() != ARC_CHAIN:
        raise HTTPException(400, "Arc payment endpoint only accepts chain='arc'.")
    if payload.action_type != "transfer":
        raise HTTPException(400, "Arc demo currently supports only USDC transfer payments.")
    if (payload.from_token or "").lower() != ARC_USDC_ADDRESS.lower():
        raise HTTPException(400, f"Use Arc mainnet USDC ERC-20 interface {ARC_USDC_ADDRESS}.")
    if not payload.target or not payload.wallet:
        raise HTTPException(422, "wallet and target are required.")

    intent = ActionIntent(
        agent_id=payload.agent_id,
        wallet=payload.wallet,
        chain=ARC_CHAIN,
        action_type="transfer",
        target=payload.target,
        from_token=ARC_USDC_ADDRESS,
        amount=payload.amount,
        metadata=payload.metadata,
    )
    return prepare_arc_payment(arc_engine, intent)


@app.get("/agents/{agent_id}/history", tags=["core"])
def agent_history(agent_id: str, limit: int = 100, authorization: Optional[str] = Header(default=None)):
    # Agent-bound for the same reason as /decision above: without this,
    # any holder of a shared key could read *any* agent's reputation and
    # history, not just query its own.
    check_agent_bound_key(authorization, agent_id, config)
    # Bounded by default: without this, a heavily-used agent's full,
    # ever-growing history would be read and serialized into one JSON
    # response on every call - exactly the unbounded-read cost this
    # session's reputation/history `limit` param (guardian/memory/*) was
    # built to avoid, just reached via a different door (this endpoint
    # wasn't using it). 500 is DecisionEngine's own default
    # history_window for reputation scoring - capping the same here
    # keeps this endpoint's cost in the same ballpark as a normal
    # decision instead of unbounded.
    limit = max(1, min(limit, 500))
    records = engine.history.get(agent_id, limit=limit)
    return {
        "agent_id": agent_id,
        "reputation_score": engine.reputation.score_for(agent_id),
        "history": [
            {
                "intent_id": r.intent_id,
                "decision": r.decision.value,
                "risk_score": r.risk_score,
                "created_at": r.created_at,
            }
            for r in records
        ],
    }


_DEMO_SCENARIOS = {
    "safe": dict(
        agent_id="trading-agent-001",
        wallet="0x1111111111111111111111111111111111aaaa",
        chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=5,
    ),
    "unknown": dict(
        agent_id="new-agent-777",
        wallet="0x2222222222222222222222222222222222bbbb",
        chain="ethereum", action_type="swap", from_token="ETH", to_token="PEPE2", amount=3,
    ),
    "malicious": dict(
        agent_id="unverified-agent-x",
        wallet="0x3333333333333333333333333333333333cccc",
        chain="ethereum", action_type="transfer",
        target="0x4444444444444444444444444444444444dddd", amount=500,
    ),
}


@app.get("/demo/{scenario}", tags=["meta"], dependencies=[Depends(require_api_key)])
def demo(scenario: str):
    # Same auth as /decision and /agents/*/history, not the no-auth
    # /health and /capabilities it's grouped under by tag: this endpoint
    # runs the real engine.evaluate() pipeline, same as /decision - with
    # real providers configured (not the Null/Mock defaults), that means
    # real RPC/GoPlus/DexScreener calls. Leaving it unauthenticated would
    # let anyone burn this deployment's provider quota for free, with a
    # fixed payload but the full pipeline cost, on every call.
    if scenario not in _DEMO_SCENARIOS:
        raise HTTPException(404, f"Unknown scenario '{scenario}'. Try one of: {list(_DEMO_SCENARIOS)}")
    intent = ActionIntent(**_DEMO_SCENARIOS[scenario])
    return engine.evaluate(intent).to_dict()
