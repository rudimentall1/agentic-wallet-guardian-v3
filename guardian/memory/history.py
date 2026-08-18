"""Decision history: append-only record of past Guardian decisions per
agent, used both for Agent Reputation and for building context ("this
agent has done N swaps before, this is not new behavior").
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from guardian.core.intent import ActionIntent
from guardian.core.models import Decision, DecisionType
from guardian.memory.storage import InMemoryStorage, MemoryBackend


@dataclass
class HistoryRecord:
    intent_id: str
    decision: DecisionType
    risk_score: float
    created_at: float
    action_type: Optional[str] = None
    amount: Optional[float] = None
    chain: Optional[str] = None


class DecisionHistory:
    def __init__(self, backend: Optional[MemoryBackend] = None):
        self.backend = backend or InMemoryStorage()

    def record(self, agent_id: str, decision: Decision, intent: Optional[ActionIntent] = None) -> None:
        entry = {
            "intent_id": decision.intent_id,
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "created_at": decision.created_at,
        }
        # `intent` is optional and new — old call sites (and old stored
        # records from before this field existed) keep working with these
        # as None rather than a fabricated 0 or "unknown".
        if intent is not None:
            entry["action_type"] = intent.action_type
            entry["amount"] = intent.amount
            entry["chain"] = intent.chain
        self.backend.append(agent_id, entry)

    def get(self, agent_id: str, limit: Optional[int] = None) -> List[HistoryRecord]:
        raw = self.backend.get(agent_id, limit=limit)
        return [
            HistoryRecord(
                intent_id=r["intent_id"],
                decision=DecisionType(r["decision"]),
                risk_score=r["risk_score"],
                created_at=r["created_at"],
                action_type=r.get("action_type"),
                amount=r.get("amount"),
                chain=r.get("chain"),
            )
            for r in raw
        ]
