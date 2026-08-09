from __future__ import annotations

from typing import List, Optional

from guardian.core.intent import ActionIntent
from guardian.core.models import PolicyViolation
from guardian.intelligence.simulation.providers import SimulationResult

DEFAULT_TOLERANCE = 0.01


def verify_intent_matches_simulation(
    intent: ActionIntent,
    simulation_result: SimulationResult,
    token_decimals: Optional[int] = None,
    tolerance: float = DEFAULT_TOLERANCE,
) -> List[PolicyViolation]:
    if not simulation_result.attempted:
        return []

    if intent.action_type != "approve":
        return []

    if simulation_result.decoded_approval_amount is None:
        return []

    if intent.amount is None:
        return []

    if simulation_result.is_unlimited_approval:
        return []

    if token_decimals is None:
        return [PolicyViolation(
            rule="intent_verification_skipped",
            message="Cannot verify the declared approval amount against the decoded calldata without the token's decimals() - skipping this check rather than guessing at a value that could be wrong in either direction.",
            severity="WARN",
        )]

    declared_atomic = intent.amount * (10 ** token_decimals)
    actual_atomic = simulation_result.decoded_approval_amount

    if declared_atomic == 0:
        if actual_atomic != 0:
            return [PolicyViolation(
                rule="intent_amount_mismatch",
                message=f"Agent declared a zero/no approval, but the actual calldata encodes a nonzero amount ({actual_atomic} atomic units). This transaction does not do what the agent said it would do.",
                severity="BLOCK",
            )]
        return []

    relative_diff = abs(actual_atomic - declared_atomic) / declared_atomic
    if relative_diff > tolerance:
        return [PolicyViolation(
            rule="intent_amount_mismatch",
            message=f"Agent declared an approval of {intent.amount} ({declared_atomic:.0f} atomic units), but the actual calldata encodes {actual_atomic} atomic units - a {relative_diff:.0%} difference. This transaction does not do what the agent said it would do.",
            severity="BLOCK",
        )]

    return []