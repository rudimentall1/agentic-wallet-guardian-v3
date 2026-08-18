"""Agent Reputation Engine.

Tracks how an agent's past decisions should influence trust in its future
requests. Reputation starts at a neutral prior for unknown agents and
moves based on the outcome history stored in memory: ALLOW nudges it up,
WARN nudges it down more, BLOCK nudges it down sharply.
"""
from __future__ import annotations

from guardian.core.models import DecisionType
from guardian.memory.history import DecisionHistory

NEUTRAL_SCORE = 50.0
MIN_SCORE = 0.0
MAX_SCORE = 100.0

DELTA = {
    DecisionType.ALLOW: +2.0,
    DecisionType.WARN: -5.0,
    DecisionType.BLOCK: -15.0,
}

# score_for() is recomputed from history on every single decision, so an
# unbounded read here is O(total history ever recorded for this agent) per
# call - a real cost for a long-lived, active agent. Reputation is meant
# to reflect *recent* trustworthiness anyway, so bounding the window both
# fixes the scaling problem and matches the intent better than an
# ever-growing full replay would.
DEFAULT_HISTORY_WINDOW = 500


class AgentReputation:
    def __init__(self, history: DecisionHistory, history_window: int = DEFAULT_HISTORY_WINDOW):
        self.history = history
        self.history_window = history_window

    def score_for(self, agent_id: str) -> float:
        records = self.history.get(agent_id, limit=self.history_window)
        if not records:
            return NEUTRAL_SCORE

        # Clamp incrementally, not just at the end. Summing every delta
        # first and clamping only the final total lets a run of BLOCKs
        # push the "true" score arbitrarily far below MIN_SCORE - that
        # invisible debt then has to be paid off before an agent's visible
        # score starts recovering, even though the score has read 0 (the
        # actual floor) the whole time. Clamping at each step means
        # recovery starts from the real floor, matching what a live
        # score would have done record-by-record.
        score = NEUTRAL_SCORE
        for record in records:
            score += DELTA.get(record.decision, 0.0)
            score = max(MIN_SCORE, min(MAX_SCORE, score))
        return score

    def history_size(self, agent_id: str) -> int:
        return len(self.history.get(agent_id))
