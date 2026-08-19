import unittest

from pydantic import ValidationError

from api.schemas import DecisionRequest


def _body(amount_literal: str) -> str:
    return (
        '{"agent_id":"a","wallet":"0x1","action_type":"transfer",'
        f'"amount":{amount_literal}}}'
    )


class TestDecisionRequestSchema(unittest.TestCase):
    def test_normal_amount_accepted(self):
        req = DecisionRequest.model_validate_json(_body("5.0"))
        self.assertEqual(req.amount, 5.0)

    def test_missing_amount_accepted(self):
        req = DecisionRequest.model_validate(
            {"agent_id": "a", "wallet": "0x1", "action_type": "transfer"}
        )
        self.assertIsNone(req.amount)

    def test_nan_amount_rejected(self):
        with self.assertRaises(ValidationError):
            DecisionRequest.model_validate_json(_body("NaN"))

    def test_positive_infinity_amount_rejected(self):
        with self.assertRaises(ValidationError):
            DecisionRequest.model_validate_json(_body("Infinity"))

    def test_negative_infinity_amount_rejected(self):
        with self.assertRaises(ValidationError):
            DecisionRequest.model_validate_json(_body("-Infinity"))

    def test_schema_example_still_present(self):
        # Regression guard: an earlier merge of `class Config` into
        # `model_config` could silently drop json_schema_extra.
        schema = DecisionRequest.model_json_schema()
        self.assertIn("example", schema)
        self.assertEqual(schema["example"]["agent_id"], "trading-agent-001")


if __name__ == "__main__":
    unittest.main()
