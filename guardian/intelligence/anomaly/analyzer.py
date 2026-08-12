"""Behavioral anomaly detection: does this action look like what this
*specific* agent normally does?

This is deliberately distinct from three other signals that could be
confused with it:

- **Reputation** (`guardian/reputation/agent.py`) is a single trust score
  derived from how many past decisions were ALLOW vs BLOCK. It says
  nothing about whether *this* action is typical for the agent.
- **Intent verification** (`guardian/decision/intent_verification.py`)
  checks whether the agent's *stated* intent matches the actual calldata
  it's about to sign — a single-transaction consistency check.
- **Policy** (`guardian/policy/`) enforces static, operator-configured
  limits (e.g. "no agent may move more than $5k/day") that apply the same
  way to every agent regardless of its own history.

Anomaly detection asks a narrower question: "this agent has done N things
before — is this one a statistical outlier compared to its own past, even
if it's within policy limits and the agent has a fine reputation?" A
well-behaved agent that suddenly proposes a transfer 50x its usual size,
or touches a chain or action type it has never used before, is worth a
second look even if no single static rule was broken.

Consistent with the rest of this codebase: never fabricate a baseline
from too little data. An agent with fewer than `MIN_HISTORY_FOR_BASELINE`
comparable data points gets an honest "insufficient history" signal
instead of a guessed anomaly score.
"""
from __future__ import annotations

import statistics
from typing import List, Optional

from guardian.core.intent import ActionIntent
from guardian.core.models import Signal
from guardian.memory.history import HistoryRecord

MIN_HISTORY_FOR_BASELINE = 5


class AnomalyAnalyzer:
    """Flags actions that deviate from an agent's own historical pattern.

    Pure statistics over this agent's own recorded history — no external
    provider, no mock/real split needed (there's nothing to mock: either
    the agent has enough history to compare against, or it honestly
    doesn't yet).
    """

    source = "anomaly"

    def analyze(self, intent: ActionIntent, history: List[HistoryRecord]) -> List[Signal]:
        signals: List[Signal] = []

        # Only compare against the agent's *own* past intents that actually
        # recorded these fields — older records (from before history
        # tracked action_type/amount/chain) or records missing a field
        # don't count as "no history", they're just not usable for that
        # specific comparison.
        seen_action_types = {r.action_type for r in history if r.action_type is not None}
        seen_chains = {r.chain for r in history if r.chain is not None}
        amounts = [r.amount for r in history if r.amount is not None]

        if history and intent.action_type not in seen_action_types and seen_action_types:
            signals.append(Signal(
                source=self.source, name="new_action_type_for_agent", score=30, weight=0.8,
                confidence=0.7,
                reason=(
                    f"Agent has never performed a '{intent.action_type}' action before "
                    f"(seen: {', '.join(sorted(seen_action_types))})"
                ),
            ))

        if history and intent.chain not in seen_chains and seen_chains:
            signals.append(Signal(
                source=self.source, name="new_chain_for_agent", score=20, weight=0.6,
                confidence=0.7,
                reason=f"Agent has never transacted on chain '{intent.chain}' before",
            ))

        amount_signal = self._amount_outlier_signal(intent.amount, amounts)
        if amount_signal is not None:
            signals.append(amount_signal)

        return signals

    def _amount_outlier_signal(self, amount: Optional[float], history_amounts: List[float]) -> Optional[Signal]:
        if amount is None:
            return None

        if len(history_amounts) < MIN_HISTORY_FOR_BASELINE:
            # Honest about the cold-start problem: a brand-new agent isn't
            # "anomalous", it's simply unmeasured yet. This is informative
            # (nudges caution) without pretending to be a real outlier
            # detection.
            return Signal(
                source=self.source, name="insufficient_history_for_baseline", score=10, weight=0.3,
                confidence=0.3,
                reason=(
                    f"Only {len(history_amounts)} prior amount(s) on record for this agent "
                    f"— too few to establish a normal-amount baseline "
                    f"(need {MIN_HISTORY_FOR_BASELINE}+)"
                ),
            )

        mean = statistics.mean(history_amounts)
        stdev = statistics.pstdev(history_amounts)

        if stdev == 0:
            # Every past amount was identical — any deviation at all is
            # notable, but treat it gently: one data pattern isn't a lot
            # of evidence either.
            if amount != mean:
                return Signal(
                    source=self.source, name="amount_deviates_from_fixed_pattern", score=35, weight=0.7,
                    confidence=0.5,
                    reason=(
                        f"Agent's prior {len(history_amounts)} action(s) all used amount "
                        f"{mean:g}; this one uses {amount:g}"
                    ),
                )
            return None

        z_score = (amount - mean) / stdev
        if z_score <= 3.0:
            return None

        # Cap the score contribution so an extreme z-score on a thin,
        # noisy sample doesn't single-handedly force a BLOCK the way a
        # hard rule or policy violation does — this stays a signal among
        # signals, fused with everything else.
        score = min(90, 40 + (z_score - 3.0) * 10)
        return Signal(
            source=self.source, name="amount_outlier_for_agent", score=score, weight=1.2,
            confidence=0.75,
            reason=(
                f"Amount {amount:g} is {z_score:.1f} standard deviations above this "
                f"agent's historical mean ({mean:g}, n={len(history_amounts)})"
            ),
        )
