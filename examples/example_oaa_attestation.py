"""
example_oaa_attestation.py — shows a Guardian Decision becoming a
signed, independently verifiable OAA token.

Run: python3 examples/example_oaa_attestation.py
"""
import sys
sys.path.insert(0, ".")
from guardian.decision.engine import DecisionEngine
from guardian.core.intent import ActionIntent
from guardian.attestation import decision_to_oaa_token
from guardian.oaa import generate_keypair, verify

engine = DecisionEngine()

intent = ActionIntent(
    agent_id="trading-agent-001",
    wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="botchain",
    action_type="swap",
    from_token="ETH",
    to_token="USDC",
    amount=5,
)
decision = engine.evaluate(intent)
print(f"decision: {decision.decision.value} (risk score {decision.risk_score:.1f})")

private_key, public_key = generate_keypair()

token = decision_to_oaa_token(
    decision,
    issuer="https://github.com/rudimentall1/agentic-wallet-guardian-v3",
    private_key_pem=private_key,
)
print(f"\nOAA token:\n{token}")

result = verify(token, public_key)
print(f"\nverified by a third party:")
print(f"  decision: {result.decision}")
print(f"  action:   {result.action}")
print(f"  reason:   {result.reason}")