from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from guardian.core.intent import ActionIntent
from guardian.core.models import PolicyViolation
from guardian.memory.storage import MemoryBackend


@dataclass
class Capability:
    agent_id: str
    allowed_action_types: Optional[List[str]] = None
    allowed_chains: Optional[List[str]] = None
    max_amount_per_action: Optional[float] = None
    max_daily_amount: Optional[float] = None
    expires_at: Optional[float] = None


class CapabilityRegistry:
    def __init__(self, storage: Optional[MemoryBackend] = None) -> None:
        self._grants: Dict[str, Capability] = {}
        # In-memory fallback for the daily-spend window, used only when
        # no `storage` is supplied - this was previously the *only*
        # option, which meant any process restart (deploy, crash, routine
        # rollout) silently reset every agent's daily spend to zero,
        # letting a capped agent spend its full daily limit again the
        # same day. Passing a `storage` backend (the same
        # MemoryBackend used for DecisionHistory - sqlite/postgres/etc.)
        # persists the spend log across restarts instead. This is opt-in
        # and backward compatible: existing callers that construct
        # `CapabilityRegistry()` with no arguments keep the original
        # in-memory-only behavior unchanged.
        self._daily_spend: Dict[str, List[Tuple[float, float]]] = {}
        self.storage = storage

    def grant(self, capability: Capability) -> None:
        self._grants[capability.agent_id] = capability

    def revoke(self, agent_id: str) -> None:
        self._grants.pop(agent_id, None)

    def get(self, agent_id: str) -> Optional[Capability]:
        return self._grants.get(agent_id)

    def snapshot_for(self, agent_id: str) -> Optional[Dict]:
        """JSON-serializable snapshot of this agent's grant, for embedding
        in an OAA attestation's policy_ref (see guardian/attestation.py).
        A decision made under a stricter/looser grant than another agent -
        or than this same agent at a different point in time, after
        `grant()` was called again - should not be attestable as "the same
        effective policy" just because rules.py and DEFAULT_POLICY were
        unchanged. Returns None when this agent has no grant at all,
        which is itself a meaningful, distinct state (unrestricted by any
        capability grant) worth fingerprinting differently from any
        specific grant.
        """
        cap = self._grants.get(agent_id)
        if cap is None:
            return None
        return {
            "agent_id": cap.agent_id,
            "allowed_action_types": cap.allowed_action_types,
            "allowed_chains": cap.allowed_chains,
            "max_amount_per_action": cap.max_amount_per_action,
            "max_daily_amount": cap.max_daily_amount,
            "expires_at": cap.expires_at,
        }

    def _record_and_sum_today(self, agent_id: str, amount: float) -> float:
        now = time.time()
        window_start = now - 86400
        if self.storage is not None:
            key = f"capability_spend:{agent_id}"
            self.storage.append(key, {"t": now, "a": amount})
            records = self.storage.get_since(key, window_start)
            return sum(r["a"] for r in records)
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