import unittest

from guardian.core.models import Decision, DecisionType, RiskLevel
from guardian.memory.history import DecisionHistory
from guardian.reputation.agent import NEUTRAL_SCORE, AgentReputation


def _fake_decision(agent_id: str, decision_type: DecisionType) -> Decision:
    return Decision(
        decision=decision_type, risk_score=0, risk_level=RiskLevel.LOW, confidence=1.0,
        explanation=[], signals=[], policy_violations=[], agent_id=agent_id, intent_id="x",
    )


class TestReputation(unittest.TestCase):
    def test_neutral_for_unknown_agent(self):
        rep = AgentReputation(DecisionHistory())
        self.assertEqual(rep.score_for("nobody"), NEUTRAL_SCORE)

    def test_score_drops_after_blocks(self):
        history = DecisionHistory()
        rep = AgentReputation(history)
        history.record("bad-agent", _fake_decision("bad-agent", DecisionType.BLOCK))
        history.record("bad-agent", _fake_decision("bad-agent", DecisionType.BLOCK))
        self.assertLess(rep.score_for("bad-agent"), NEUTRAL_SCORE)

    def test_score_rises_after_allows(self):
        history = DecisionHistory()
        rep = AgentReputation(history)
        for _ in range(10):
            history.record("good-agent", _fake_decision("good-agent", DecisionType.ALLOW))
        self.assertGreater(rep.score_for("good-agent"), NEUTRAL_SCORE)

    def test_score_is_clamped_between_0_and_100(self):
        history = DecisionHistory()
        rep = AgentReputation(history)
        for _ in range(50):
            history.record("very-bad-agent", _fake_decision("very-bad-agent", DecisionType.BLOCK))
        self.assertGreaterEqual(rep.score_for("very-bad-agent"), 0.0)

    def test_recovery_is_not_slowed_by_invisible_debt_below_floor(self):
        """Regression test: score_for() used to sum every delta first and
        clamp only the final total, so a long run of BLOCKs before the
        floor could push the "true" score arbitrarily below 0. That debt
        then had to be paid off before the visible score moved again,
        even though a live, step-by-step score would already have sat at
        the floor (0) after the same run. Recovery must start from the
        real floor."""
        history = DecisionHistory()
        rep = AgentReputation(history)
        agent = "recovering-agent"
        for _ in range(10):  # far past enough BLOCKs to hit the floor
            history.record(agent, _fake_decision(agent, DecisionType.BLOCK))
        self.assertEqual(rep.score_for(agent), 0.0)

        for _ in range(3):
            history.record(agent, _fake_decision(agent, DecisionType.ALLOW))
        # 3 ALLOWs at +2.0 each from the real floor (0) => 6.0, not 0.0
        # (which the old sum-then-clamp implementation would have given
        # here, since raw sum = 50 - 150 + 6 = -94, still clamped to 0).
        self.assertEqual(rep.score_for(agent), 6.0)

    def test_history_window_bounds_the_read(self):
        """score_for() must not require reading an agent's entire history
        on every call - only the most recent `history_window` records."""
        history = DecisionHistory()
        rep = AgentReputation(history, history_window=5)
        agent = "long-history-agent"
        for _ in range(100):
            history.record(agent, _fake_decision(agent, DecisionType.ALLOW))
        # Only the last 5 ALLOWs should count: 50 + 5*2.0 = 60.0, not
        # clamped-at-100 as an unbounded read of 100 ALLOWs would give.
        self.assertEqual(rep.score_for(agent), 60.0)


if __name__ == "__main__":
    unittest.main()
