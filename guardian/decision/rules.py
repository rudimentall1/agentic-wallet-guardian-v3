"""Hard rules: deterministic checks that can force a decision independent
of the fused risk score. These run first so an obviously-disallowed action
never has to "argue its way" through statistical scoring.
"""
from __future__ import annotations

import math
from typing import List

from guardian.core.intent import ActionIntent
from guardian.core.models import PolicyViolation

SUPPORTED_CHAINS = {"ethereum", "base", "arbitrum", "optimism", "polygon", "solana", "botchain"}


def evaluate_hard_rules(intent: ActionIntent) -> List[PolicyViolation]:
    violations: List[PolicyViolation] = []

    if intent.chain.lower() not in SUPPORTED_CHAINS:
        violations.append(PolicyViolation(
            rule="unsupported_chain",
            message=f"Chain '{intent.chain}' is not supported by this Guardian deployment",
            severity="BLOCK",
        ))

    if intent.amount is not None:
        # NaN/Infinity are floats too, and `amount < 0` / `amount > cap`
        # comparisons are silently False against NaN - a plain negative-
        # amount check does not catch it. That means an amount of NaN
        # would previously have sailed past both this rule *and* every
        # spending cap in the policy engine (guardian/policy/engine.py),
        # since those also compare with `>`. Reject non-finite amounts
        # outright rather than let a comparison-based check silently
        # pass them through.
        if math.isnan(intent.amount) or math.isinf(intent.amount):
            violations.append(PolicyViolation(
                rule="non_finite_amount",
                message="Action amount must be a finite number (got NaN or Infinity)",
                severity="BLOCK",
            ))
        elif intent.amount < 0:
            violations.append(PolicyViolation(
                rule="negative_amount",
                message="Action amount cannot be negative",
                severity="BLOCK",
            ))

    if not intent.wallet:
        violations.append(PolicyViolation(
            rule="missing_wallet",
            message="Intent is missing a wallet address",
            severity="BLOCK",
        ))

    return violations
