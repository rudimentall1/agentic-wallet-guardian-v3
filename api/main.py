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

from fastapi import Depends, FastAPI, HTTPException

from api.schemas import DecisionRequest, DecisionResponse
from api.security import RateLimitMiddleware, make_api_key_dependency
from guardian.config import get_config
from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.decision.rules import SUPPORTED_CHAINS

logger = logging.getLogger("guardian.api")

app = FastAPI(
    title="Agentic Wallet Guardian",
    version="3.1.0",
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

require_api_key = make_api_key_dependency(config)
app.add_middleware(RateLimitMiddleware, limit_per_minute=config.rate_limit_per_minute)

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


@app.post("/decision", response_model=DecisionResponse, tags=["core"], dependencies=[Depends(require_api_key)])
def decide(payload: DecisionRequest):
    intent = ActionIntent(
        agent_id=payload.agent_id,
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


@app.get("/agents/{agent_id}/history", tags=["core"], dependencies=[Depends(require_api_key)])
def agent_history(agent_id: str, limit: int = 100):
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
