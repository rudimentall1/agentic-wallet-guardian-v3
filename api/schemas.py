"""FastAPI request/response schemas.

Kept separate from ``guardian/core`` so the decision engine itself has no
pydantic/FastAPI dependency and can be tested or embedded without a web
framework installed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class DecisionRequest(BaseModel):
    model_config = ConfigDict(
        allow_inf_nan=False,
        json_schema_extra={
            "example": {
                "agent_id": "trading-agent-001",
                "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "chain": "ethereum",
                "action_type": "swap",
                "from_token": "ETH",
                "to_token": "USDC",
                "amount": 5,
            }
        },
    )

    agent_id: str = Field(..., description="Identifier of the requesting AI agent")
    wallet: str = Field(..., description="Wallet address initiating the action")
    chain: str = Field("ethereum", description="Target chain, e.g. ethereum, base, solana")
    action_type: str = Field(..., description="swap | transfer | approve | contract_call | bridge")
    target: Optional[str] = Field(None, description="Contract or recipient address")
    from_token: Optional[str] = None
    to_token: Optional[str] = None
    amount: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SignalOut(BaseModel):
    source: str
    name: str
    score: float
    weight: float
    confidence: float
    reason: str


class PolicyViolationOut(BaseModel):
    rule: str
    message: str
    severity: str


class DecisionResponse(BaseModel):
    decision: str
    risk_score: float
    risk_level: str
    confidence: float
    explanation: List[str]
    signals: List[SignalOut]
    policy_violations: List[PolicyViolationOut]
    agent_id: str
    intent_id: str
    created_at: float
