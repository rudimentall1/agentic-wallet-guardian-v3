import unittest

from guardian.attestation import _policy_fingerprint, decision_to_oaa_token
from guardian.core.models import Decision, DecisionType, RiskLevel
from guardian.oaa import generate_keypair, verify
from guardian.policy.engine import PolicyEngine


def _make_decision(agent_id="agent-a"):
    return Decision(
        decision=DecisionType.ALLOW,
        risk_score=10.0,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        explanation=["no violations"],
        signals=[],
        policy_violations=[],
        agent_id=agent_id,
        intent_id="intent-123",
    )


class TestPolicyFingerprint(unittest.TestCase):
    """Regression tests for the finding that policy_ref only ever hashed
    rules.py's source, and so didn't change when the *effective* policy
    (PolicyEngine.policy, capability grants) did - or worse, changed when
    they didn't, on an unrelated rules.py edit."""

    def test_fingerprint_is_stable_for_same_inputs(self):
        engine = PolicyEngine()
        a = _policy_fingerprint(engine, {"max_amount_per_action": 100.0})
        b = _policy_fingerprint(engine, {"max_amount_per_action": 100.0})
        self.assertEqual(a, b)

    def test_fingerprint_changes_with_different_policy_dict(self):
        strict = PolicyEngine(policy={"blocked_action_types": ["swap"]})
        permissive = PolicyEngine(policy={"blocked_action_types": []})
        self.assertNotEqual(
            _policy_fingerprint(strict, None),
            _policy_fingerprint(permissive, None),
        )

    def test_fingerprint_changes_with_different_capability_snapshot(self):
        engine = PolicyEngine()
        low_limit = _policy_fingerprint(engine, {"max_amount_per_action": 100.0})
        high_limit = _policy_fingerprint(engine, {"max_amount_per_action": 100000.0})
        self.assertNotEqual(low_limit, high_limit)

    def test_fingerprint_distinguishes_no_grant_from_a_grant(self):
        engine = PolicyEngine()
        no_grant = _policy_fingerprint(engine, None)
        with_grant = _policy_fingerprint(engine, {"max_amount_per_action": 100.0})
        self.assertNotEqual(no_grant, with_grant)

    def test_fingerprint_with_no_policy_engine_still_produces_a_value(self):
        # Backward-compatible degraded mode for callers with no
        # PolicyEngine handy - still just the rules.py hash plus the
        # (absent) capability snapshot, same shape as before this fix,
        # not a crash.
        result = _policy_fingerprint(None, None)
        self.assertTrue(result.startswith("sha256:"))

    def test_two_deployments_same_rules_different_policy_get_different_refs(self):
        # The core bug this fixes: identical rules.py (same process, same
        # import) but different *effective* policy must not attest to the
        # same policy_ref.
        deployment_a = PolicyEngine(policy={"high_value_threshold": 1000})
        deployment_b = PolicyEngine(policy={"high_value_threshold": 50})
        self.assertNotEqual(
            _policy_fingerprint(deployment_a, None),
            _policy_fingerprint(deployment_b, None),
        )


class TestDecisionToOaaToken(unittest.TestCase):
    def test_token_is_issued_and_verifiable_with_policy_engine_passed(self):
        private_key, public_key = generate_keypair()
        decision = _make_decision()
        engine = PolicyEngine()
        token = decision_to_oaa_token(
            decision,
            issuer="https://example.test",
            private_key_pem=private_key,
            policy_engine=engine,
            capability_snapshot={"max_amount_per_action": 500.0},
        )
        result = verify(token, public_key)
        self.assertEqual(result.decision, "ALLOW")
        self.assertTrue(result.policy_ref.startswith("sha256:"))

    def test_omitting_policy_engine_still_works(self):
        # Full backward compatibility: existing callers that don't pass
        # policy_engine/capability_snapshot at all keep working exactly
        # as before (degraded to a rules.py-only fingerprint).
        private_key, public_key = generate_keypair()
        decision = _make_decision()
        token = decision_to_oaa_token(
            decision, issuer="https://example.test", private_key_pem=private_key,
        )
        result = verify(token, public_key)
        self.assertEqual(result.decision, "ALLOW")


if __name__ == "__main__":
    unittest.main()
