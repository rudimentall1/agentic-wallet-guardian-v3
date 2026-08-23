from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, Dict, Optional

from guardian.core.models import Decision
from guardian.decision import rules as rules_module
from guardian.oaa import issue


def _policy_fingerprint(
    policy_engine: Optional[Any] = None,
    capability_snapshot: Optional[Dict] = None,
) -> str:
    """Hashes every input that can actually change what a decision comes
    out to, not just the hard-rules source code.

    The previous version of this function (``_ruleset_fingerprint``)
    hashed only ``guardian/decision/rules.py``. That misses two things
    that just as directly determine a decision: ``PolicyEngine.policy``
    (which an operator can - and in a real deployment, likely will -
    override away from ``DEFAULT_POLICY``; see ``PolicyEngine.__init__``),
    and any per-agent ``Capability`` grant from
    ``guardian/policy/capabilities.py``. Without them, two deployments
    running wildly different effective policy but identical ``rules.py``
    produce the *same* ``policy_ref`` - and, just as misleadingly, editing
    an unrelated comment in ``rules.py`` changes ``policy_ref`` even
    though the policy that ran is bit-for-bit the same. Either way, a
    third party checking "was this decision made under a known policy?"
    against the wrong evidence.

    Passing ``policy_engine=None``/``capability_snapshot=None`` still
    produces a fingerprint (hard rules alone) for callers that genuinely
    have nothing else to attach - but callers that have the
    ``DecisionEngine`` that actually produced the ``Decision`` should
    always pass its ``policy_engine`` (and, when a capability registry is
    in play, ``capability_registry.snapshot_for(decision.agent_id)``).
    """
    hasher = hashlib.sha256()
    hasher.update(inspect.getsource(rules_module).encode())
    if policy_engine is not None:
        hasher.update(b"|policy:")
        hasher.update(json.dumps(policy_engine.policy, sort_keys=True, default=str).encode())
    hasher.update(b"|capability:")
    hasher.update(json.dumps(capability_snapshot, sort_keys=True, default=str).encode())
    return "sha256:" + hasher.hexdigest()


def decision_to_oaa_token(
    decision: Decision,
    *,
    issuer: str,
    private_key_pem: bytes,
    ttl_seconds: int | None = None,
    policy_engine: Optional[Any] = None,
    capability_snapshot: Optional[Dict] = None,
) -> str:
    reasons = list(decision.explanation)
    reasons += [v.message for v in decision.policy_violations]
    reason = "; ".join(reasons) or "no violations, risk within threshold"

    kwargs = {}
    if ttl_seconds is not None:
        kwargs["ttl_seconds"] = ttl_seconds

    return issue(
        issuer=issuer,
        subject=decision.agent_id,
        decision=decision.decision.value,
        action=f"intent:{decision.intent_id}",
        reason=reason,
        policy_ref=_policy_fingerprint(policy_engine, capability_snapshot),
        private_key_pem=private_key_pem,
        **kwargs,
    )