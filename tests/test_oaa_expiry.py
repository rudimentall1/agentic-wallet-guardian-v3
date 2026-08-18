import time
import unittest

import jwt

from guardian.oaa import DEFAULT_TTL_SECONDS, InvalidOAAToken, generate_keypair, issue, verify


class TestOaaExpiry(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_keypair()

    def _issue(self, **overrides):
        kwargs = dict(
            issuer="guardian-test",
            subject="agent-1",
            decision="ALLOW",
            action="intent:abc",
            reason="risk within threshold",
            policy_ref="sha256:deadbeef",
            private_key_pem=self.private_pem,
        )
        kwargs.update(overrides)
        return issue(**kwargs)

    def test_token_has_exp_claim_by_default(self):
        token = self._issue()
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertIn("exp", claims)
        self.assertEqual(claims["exp"], claims["iat"] + DEFAULT_TTL_SECONDS)

    def test_fresh_token_verifies(self):
        token = self._issue()
        result = verify(token, self.public_pem, expected_issuer="guardian-test")
        self.assertEqual(result.decision, "ALLOW")

    def test_expired_token_rejected(self):
        token = self._issue(ttl_seconds=-1)  # already expired at issuance
        with self.assertRaises(InvalidOAAToken):
            verify(token, self.public_pem)

    def test_explicit_none_ttl_omits_exp_claim(self):
        token = self._issue(ttl_seconds=None)
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertNotIn("exp", claims)
        # Still verifies - no exp claim means PyJWT performs no expiry check.
        result = verify(token, self.public_pem)
        self.assertEqual(result.decision, "ALLOW")

    def test_custom_ttl_respected(self):
        token = self._issue(ttl_seconds=30)
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertEqual(claims["exp"] - claims["iat"], 30)


if __name__ == "__main__":
    unittest.main()
