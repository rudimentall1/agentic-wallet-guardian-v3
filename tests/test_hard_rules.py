import unittest

from guardian.core.intent import ActionIntent
from guardian.decision.rules import evaluate_hard_rules


def _intent(**overrides):
    defaults = dict(agent_id="agent-1", wallet="0xabc", action_type="transfer")
    defaults.update(overrides)
    return ActionIntent(**defaults)


class TestHardRules(unittest.TestCase):
    def test_supported_chain_no_violation(self):
        self.assertEqual(evaluate_hard_rules(_intent(chain="ethereum")), [])

    def test_unsupported_chain_blocked(self):
        violations = evaluate_hard_rules(_intent(chain="dogechain"))
        self.assertEqual([v.rule for v in violations], ["unsupported_chain"])
        self.assertEqual(violations[0].severity, "BLOCK")

    def test_missing_wallet_blocked(self):
        violations = evaluate_hard_rules(_intent(wallet=""))
        self.assertIn("missing_wallet", [v.rule for v in violations])

    def test_negative_amount_blocked(self):
        violations = evaluate_hard_rules(_intent(amount=-1.0))
        self.assertEqual([v.rule for v in violations], ["negative_amount"])

    def test_positive_amount_no_violation(self):
        self.assertEqual(evaluate_hard_rules(_intent(amount=100.0)), [])

    def test_zero_amount_no_violation(self):
        self.assertEqual(evaluate_hard_rules(_intent(amount=0.0)), [])

    def test_none_amount_no_violation(self):
        self.assertEqual(evaluate_hard_rules(_intent(amount=None)), [])

    def test_nan_amount_blocked(self):
        """Regression test for the amount-cap bypass: `nan < 0` and
        `nan > cap` are both False in Python, so a plain comparison-based
        check silently let a NaN amount through every downstream cap.
        """
        violations = evaluate_hard_rules(_intent(amount=float("nan")))
        self.assertEqual([v.rule for v in violations], ["non_finite_amount"])
        self.assertEqual(violations[0].severity, "BLOCK")

    def test_positive_infinity_amount_blocked(self):
        violations = evaluate_hard_rules(_intent(amount=float("inf")))
        self.assertEqual([v.rule for v in violations], ["non_finite_amount"])

    def test_negative_infinity_amount_blocked_as_non_finite_not_negative(self):
        # -inf is both "negative" and "non-finite" - non-finite must win
        # so the message correctly explains why (not a generic negative
        # amount, which would suggest a merely large real-world debit).
        violations = evaluate_hard_rules(_intent(amount=float("-inf")))
        self.assertEqual([v.rule for v in violations], ["non_finite_amount"])


if __name__ == "__main__":
    unittest.main()
