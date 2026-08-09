import sys
sys.path.insert(0, ".")

import hashlib
import inspect

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.decision.intent_verification import verify_intent_matches_simulation
from guardian.decision import intent_verification as intent_verification_module
from guardian.intelligence.simulation.providers import SimulationResult
from guardian.policy.capabilities import Capability, CapabilityRegistry, evaluate_capability
from guardian.policy import capabilities as capabilities_module
from guardian.decision import rules as rules_module
from guardian.oaa import generate_keypair, issue, verify

USDC_DECIMALS = 6

registry = CapabilityRegistry()
registry.grant(Capability(
    agent_id="trading-agent-001",
    allowed_action_types=["approve", "swap"],
    allowed_chains=["ethereum"],
    max_amount_per_action=1000.0,
    max_daily_amount=5000.0,
))

engine = DecisionEngine()
private_key, public_key = generate_keypair()
ISSUER = "https://github.com/rudimentall1/agentic-wallet-guardian-v3"


def _fingerprint(module) -> str:
    return "sha256:" + hashlib.sha256(inspect.getsource(module).encode()).hexdigest()


def run_pipeline(label, intent, simulated_calldata_amount=None):
    print(f"=== {label} ===")

    cap_violations = evaluate_capability(intent, registry)
    if cap_violations:
        v = cap_violations[0]
        print(f"  [1/3] capability: BLOCKED - {v.message}")
        token = issue(
            issuer=ISSUER, subject=intent.agent_id, decision="BLOCK",
            action=f"intent:{intent.intent_id}", reason=v.message,
            policy_ref=_fingerprint(capabilities_module), private_key_pem=private_key,
        )
        _print_attestation(token)
        return
    print("  [1/3] capability: OK")

    if intent.action_type == "approve" and simulated_calldata_amount is not None:
        sim_result = SimulationResult(
            attempted=True, would_revert=False,
            decoded_approval_amount=simulated_calldata_amount,
            is_unlimited_approval=simulated_calldata_amount >= 2**255,
        )
        iv_violations = verify_intent_matches_simulation(
            intent, sim_result, token_decimals=USDC_DECIMALS,
        )
        blocking = [v for v in iv_violations if v.severity == "BLOCK"]
        if blocking:
            v = blocking[0]
            print(f"  [2/3] intent verification: BLOCKED - {v.message}")
            token = issue(
                issuer=ISSUER, subject=intent.agent_id, decision="BLOCK",
                action=f"intent:{intent.intent_id}", reason=v.message,
                policy_ref=_fingerprint(intent_verification_module), private_key_pem=private_key,
            )
            _print_attestation(token)
            return
        print("  [2/3] intent verification: OK")
    else:
        print("  [2/3] intent verification: skipped (not applicable)")

    decision = engine.evaluate(intent)
    print(f"  [3/3] decision engine: {decision.decision.value} (risk {decision.risk_score:.1f})")
    reason = "; ".join(decision.explanation) or "no violations, risk within threshold"
    token = issue(
        issuer=ISSUER, subject=intent.agent_id, decision=decision.decision.value,
        action=f"intent:{intent.intent_id}", reason=reason,
        policy_ref=_fingerprint(rules_module),
        private_key_pem=private_key,
    )
    _print_attestation(token)


def _print_attestation(token):
    result = verify(token, public_key)
    print(f"  -> signed attestation: decision={result.decision}, verifiable by anyone with the public key")


run_pipeline(
    "Case 1: blocked by capability (wrong chain)",
    ActionIntent(agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                 chain="botchain", action_type="swap", from_token="ETH", to_token="USDC", amount=50),
)

run_pipeline(
    "Case 2: blocked by intent verification (500 declared, 5000 in calldata)",
    ActionIntent(agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                 chain="ethereum", action_type="approve", to_token="USDC", amount=500),
    simulated_calldata_amount=5000000000,
)

run_pipeline(
    "Case 3: passes capability + intent verification, reaches full engine",
    ActionIntent(agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                 chain="ethereum", action_type="approve", to_token="USDC", amount=500),
    simulated_calldata_amount=500000000,
)