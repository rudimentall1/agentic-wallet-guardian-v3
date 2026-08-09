from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from guardian.core.intent import ActionIntent
from guardian.core.models import PolicyViolation


@dataclass
class Capability:
    agent_id: str
    allowed_action_types: Optional[List[str]] = None
    allowed_chains: Optional[List[str]] = None
    max_amount_per_action: Optional[float] = None
    max_daily_amount: Optional[float] = None
    expires_at: Optional[float] = None


class CapabilityRegistry:
    def __init__(self) -> None:
        self._grants: Dict[str, Capability] = {}
        self._daily_spend: Dict[str, List[Tuple[float, float]]] = {}

    def grant(self, capability: Capability) -> None:
        self._grants[capability.agent_id] = capability

    def revoke(self, agent_id: str) -> None:
        self._grants.pop(agent_id, None)

    def get(self, agent_id: str) -> Optional[Capability]:
        return self._grants.get(agent_id)

    def _record_and_sum_today(self, agent_id: str, amount: float) -> float:
        now = time.time()
        window_start = now - 86400
        history = self._daily_spend.setdefault(agent_id, [])
        history[:] = [(t, a) for t, a in history if t > window_start]
        history.append((now, amount))
        return sum(a for _, a in history)


def evaluate_capability(intent: ActionIntent, registry: CapabilityRegistry) -> List[PolicyViolation]:
    cap = registry.get(intent.agent_id)
    if cap is None:
        return []

    if cap.expires_at is not None and time.time() > cap.expires_at:
        return [PolicyViolation(
            rule="capability_expired",
            message=f"Capability grant for agent '{intent.agent_id}' has expired",
            severity="BLOCK",
        )]

    violations: List[PolicyViolation] = []

    if cap.allowed_action_types is not None and intent.action_type not in cap.allowed_action_types:
        violations.append(PolicyViolation(
            rule="action_type_not_granted",
            message=f"Agent '{intent.agent_id}' is not granted permission for action type '{intent.action_type}' (allowed: {cap.allowed_action_types})",
            severity="BLOCK",
        ))

    if cap.allowed_chains is not None and intent.chain.lower() not in [c.lower() for c in cap.allowed_chains]:
        violations.append(PolicyViolation(
            rule="chain_not_granted",
            message=f"Agent '{intent.agent_id}' is not granted permission on chain '{intent.chain}' (allowed: {cap.allowed_chains})",
            severity="BLOCK",
        ))

    amount = intent.amount or 0.0

    if cap.max_amount_per_action is not None and amount > cap.max_amount_per_action:
        violations.append(PolicyViolation(
            rule="capability_amount_exceeded",
            message=f"Amount {amount} exceeds this agent's granted per-action limit of {cap.max_amount_per_action}",
            severity="BLOCK",
        ))

    if cap.max_daily_amount is not None:
        total_today = registry._record_and_sum_today(intent.agent_id, amount)
        if total_today > cap.max_daily_amount:
            violations.append(PolicyViolation(
                rule="capability_daily_limit_exceeded",
                message=f"Agent '{intent.agent_id}' has moved {total_today:.2f} in the last 24h, exceeding its daily limit of {cap.max_daily_amount}",
                severity="BLOCK",
            ))

    return violations