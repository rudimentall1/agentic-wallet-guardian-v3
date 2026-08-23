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

    if simulation_result.is_unlimited_approval:
        # This used to be a silent `return []` on the theory that the
        # separate `unlimited_approval_confirmed` Signal (see
        # simulation/engine.py) already covers it. But that signal only
        # ever *contributes to a score* - whether it actually forces BLOCK
        # depends on RiskFusionEngine's dominant-floor arithmetic and
        # what else is in the signal mix that request. That's an indirect,
        # score-dependent guarantee for the single most severe thing this
        # module can observe (an approve() that would hand out unlimited
        # spending rights) - not something this module should rely on
        # silently.
        #
        # Some legitimate DeFi integrations genuinely need an unlimited
        # approval (this is a real, if risky, pattern - e.g. some routers
        # expect it to avoid re-approving on every trade). Rather than
        # blanket-BLOCK every unlimited approval with no way through, the
        # agent can explicitly acknowledge it wants exactly this via
        # `intent.metadata["acknowledge_unlimited_approval"] = True` - the
        # same "no silent guessing, require an explicit opt-in" rule this
        # codebase already applies to `max_slippage_bps`, `recipient`,
        # `l2_token`, etc. Anything else is treated as a mismatch: the
        # agent did not explicitly say it wanted this, so Guardian does
        # not assume it's fine.
        if intent.metadata.get("acknowledge_unlimited_approval") is True:
            return []
        return [PolicyViolation(
            rule="unconfirmed_unlimited_approval",
            message=(
                "Dry run confirms this approve() grants an unlimited (or near-unlimited) "
                "spending amount, and the agent did not explicitly acknowledge intending "
                "an unlimited approval (set metadata['acknowledge_unlimited_approval']=True "
                "if this is genuinely intended). Treating this as a mismatch between what "
                "the agent asked for and what this transaction actually does."
            ),
            severity="BLOCK",
        )]

    if simulation_result.decoded_approval_amount is None:
        return []

    if intent.amount is None:
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