from __future__ import annotations

import hashlib
import inspect

from guardian.core.models import Decision
from guardian.decision import rules as rules_module
from guardian.oaa import issue


def _ruleset_fingerprint() -> str:
    source = inspect.getsource(rules_module)
    return "sha256:" + hashlib.sha256(source.encode()).hexdigest()


def decision_to_oaa_token(
    decision: Decision,
    *,
    issuer: str,
    private_key_pem: bytes,
) -> str:
    reasons = list(decision.explanation)
    reasons += [v.message for v in decision.policy_violations]
    reason = "; ".join(reasons) or "no violations, risk within threshold"

    return issue(
        issuer=issuer,
        subject=decision.agent_id,
        decision=decision.decision.value,
        action=f"intent:{decision.intent_id}",
        reason=reason,
        policy_ref=_ruleset_fingerprint(),
        private_key_pem=private_key_pem,
    )