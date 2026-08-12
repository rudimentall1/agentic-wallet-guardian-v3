import unittest

from guardian.core.intent import ActionIntent
from guardian.core.models import DecisionType
from guardian.intelligence.anomaly.analyzer import AnomalyAnalyzer, MIN_HISTORY_FOR_BASELINE
from guardian.memory.history import HistoryRecord


def _record(action_type=None, amount=None, chain=None) -> HistoryRecord:
    return HistoryRecord(
        intent_id="x", decision=DecisionType.ALLOW, risk_score=10.0, created_at=0.0,
        action_type=action_type, amount=amount, chain=chain,
    )


def _intent(action_type="transfer", amount=100.0, chain="ethereum") -> ActionIntent:
    return ActionIntent(
        agent_id="agent-1", wallet="0xabc", chain=chain,
        action_type=action_type, amount=amount,
    )


class TestNoHistory(unittest.TestCase):
    def test_no_history_produces_no_new_type_or_chain_signals(self):
        # A genuinely brand-new agent shouldn't be flagged for "new
        # action type" / "new chain" — those signals are about deviating
        # from an *established* pattern, which doesn't exist yet.
        analyzer = AnomalyAnalyzer()
        signals = analyzer.analyze(_intent(), history=[])
        names = {s.name for s in signals}
        self.assertNotIn("new_action_type_for_agent", names)
        self.assertNotIn("new_chain_for_agent", names)

    def test_no_history_still_reports_insufficient_baseline_for_amount(self):
        analyzer = AnomalyAnalyzer()
        signals = analyzer.analyze(_intent(amount=100.0), history=[])
        names = {s.name for s in signals}
        self.assertIn("insufficient_history_for_baseline", names)


class TestNewActionTypeAndChain(unittest.TestCase):
    def test_flags_action_type_never_seen_before(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(action_type="transfer") for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(action_type="swap"), history)
        names = {s.name for s in signals}
        self.assertIn("new_action_type_for_agent", names)

    def test_does_not_flag_action_type_already_seen(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(action_type="swap") for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(action_type="swap"), history)
        names = {s.name for s in signals}
        self.assertNotIn("new_action_type_for_agent", names)

    def test_flags_chain_never_seen_before(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(chain="ethereum") for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(chain="base"), history)
        names = {s.name for s in signals}
        self.assertIn("new_chain_for_agent", names)

    def test_records_missing_action_type_do_not_count_as_history(self):
        # Old records from before this field existed have action_type=None
        # — they must not be treated as "agent has done a None action
        # before" or silently suppress the new-type signal.
        analyzer = AnomalyAnalyzer()
        history = [_record(action_type=None) for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(action_type="swap"), history)
        names = {s.name for s in signals}
        self.assertNotIn("new_action_type_for_agent", names)  # no seen_action_types at all


class TestAmountOutlier(unittest.TestCase):
    def test_typical_amount_not_flagged(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(amount=100.0) for _ in range(10)]
        signals = analyzer.analyze(_intent(amount=105.0), history)
        names = {s.name for s in signals}
        self.assertNotIn("amount_outlier_for_agent", names)

    def test_large_outlier_amount_flagged(self):
        analyzer = AnomalyAnalyzer()
        # Small, consistent amounts historically...
        history = [_record(amount=100.0 + i) for i in range(10)]
        # ...then a proposal 50x the historical range.
        signals = analyzer.analyze(_intent(amount=5000.0), history)
        outlier = [s for s in signals if s.name == "amount_outlier_for_agent"]
        self.assertEqual(len(outlier), 1)
        self.assertGreater(outlier[0].score, 0)

    def test_fixed_pattern_deviation_flagged_gently(self):
        analyzer = AnomalyAnalyzer()
        # Every past amount identical (stdev == 0) — a different amount
        # should still be notable, just via the fixed-pattern path.
        history = [_record(amount=50.0) for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(amount=51.0), history)
        names = {s.name for s in signals}
        self.assertIn("amount_deviates_from_fixed_pattern", names)

    def test_fixed_pattern_exact_match_not_flagged(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(amount=50.0) for _ in range(MIN_HISTORY_FOR_BASELINE)]
        signals = analyzer.analyze(_intent(amount=50.0), history)
        names = {s.name for s in signals}
        self.assertNotIn("amount_deviates_from_fixed_pattern", names)

    def test_amount_none_produces_no_amount_signal(self):
        analyzer = AnomalyAnalyzer()
        history = [_record(amount=100.0) for _ in range(10)]
        signals = analyzer.analyze(_intent(amount=None), history)
        amount_related = [s for s in signals if "amount" in s.name or s.name == "insufficient_history_for_baseline"]
        self.assertEqual(amount_related, [])


if __name__ == "__main__":
    unittest.main()
