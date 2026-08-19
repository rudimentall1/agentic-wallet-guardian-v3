import sys
sys.path.insert(0, ".")

import hashlib
import inspect

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.decision.intent_verification import verify_intent_matches_simulation
from guardian.decision import intent_verification as intent_verification_module
from guardian.intelligence.simulation.providers import SimulationResult
from guardian.policy.capabilities import Capability, CapabilityRegistry
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

# capability_registry wires the capability check into the engine itself
# (DecisionEngine.evaluate() calls evaluate_capability() internally now -
# it used to require calling that function by hand, outside the engine).
# Intent verification is NOT similarly wired with real decimals below:
# the engine always calls it with token_decimals=None (no decimals()
# provider exists in this codebase yet - see decision/engine.py's
# comment at that call site), so it can only ever emit an honest "cannot
# verify" WARN through the engine, never the real mismatch-detection
# BLOCK this demo wants to show. That real check is still called
# directly here with explicit decimals, same as
# examples/example_intent_verification.py - this stays a manual step
# until a decimals provider exists to wire it in for real.
engine = DecisionEngine(capability_registry=registry)
private_key, public_key = generate_keypair()
ISSUER = "https://github.com/rudimentall1/agentic-wallet-guardian-v3"


def _fingerprint(module) -> str:
    return "sha256:" + hashlib.sha256(inspect.getsource(module).encode()).hexdigest()


def run_pipeline(label, intent, simulated_calldata_amount=None):
    print(f"=== {label} ===")

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
            print(f"  [1/3] intent verification (checked manually - see comment above): BLOCKED - {v.message}")
            token = issue(
                issuer=ISSUER, subject=intent.agent_id, decision="BLOCK",
                action=f"intent:{intent.intent_id}", reason=v.message,
                policy_ref=_fingerprint(intent_verification_module), private_key_pem=private_key,
            )
            _print_attestation(token)
            return
        print("  [1/3] intent verification (checked manually - see comment above): OK")
    else:
        print("  [1/3] intent verification: skipped (not applicable)")

    # Capability enforcement happens inside evaluate() below (registry
    # was passed to DecisionEngine above) - decision.policy_violations
    # is where a capability BLOCK would show up if this were opaque, but
    # we already know which rule fired from the label, so just show the
    # end-to-end result plus pull the specific violation out for the
    # attestation reason if the engine did block on it.
    decision = engine.evaluate(intent)
    capability_rule_names = {
        "action_type_not_granted", "chain_not_granted", "capability_amount_exceeded",
        "capability_daily_limit_exceeded", "capability_expired",
    }
    capability_hit = next((v for v in decision.policy_violations if v.rule in capability_rule_names), None)
    if capability_hit:
        print(f"  [2/3] capability (enforced by the engine): BLOCKED - {capability_hit.message}")
    else:
        print("  [2/3] capability (enforced by the engine): OK")

    print(f"  [3/3] decision engine: {decision.decision.value} (risk {decision.risk_score:.1f})")

    policy_ref = _fingerprint(capabilities_module) if capability_hit else _fingerprint(rules_module)
    reason = capability_hit.message if capability_hit else (
        "; ".join(decision.explanation) or "no violations, risk within threshold"
    )
    token = issue(
        issuer=ISSUER, subject=intent.agent_id, decision=decision.decision.value,
        action=f"intent:{intent.intent_id}", reason=reason,
        policy_ref=policy_ref, private_key_pem=private_key,
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
    "Case 3: passes intent verification + capability, reaches full engine",
    ActionIntent(agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                 chain="ethereum", action_type="approve", to_token="USDC", amount=500),
    simulated_calldata_amount=500000000,
)
