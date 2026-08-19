import sys
sys.path.insert(0, ".")

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.policy.capabilities import Capability, CapabilityRegistry

registry = CapabilityRegistry()

registry.grant(Capability(
    agent_id="trading-agent-001",
    allowed_action_types=["swap"],
    allowed_chains=["ethereum"],
    max_amount_per_action=100.0,
    max_daily_amount=500.0,
))

# Passing capability_registry here is what actually enforces the grant -
# DecisionEngine.evaluate() calls evaluate_capability() itself now. A
# DecisionEngine() with no registry (the default) is completely
# unaffected by any of this.
engine = DecisionEngine(capability_registry=registry)


def try_intent(label, intent):
    print(f"--- {label} ---")
    decision = engine.evaluate(intent)
    capability_violations = [
        v for v in decision.policy_violations
        if v.rule in ("action_type_not_granted", "chain_not_granted",
                       "capability_amount_exceeded", "capability_daily_limit_exceeded",
                       "capability_expired")
    ]
    if capability_violations:
        for v in capability_violations:
            print(f"  BLOCKED by capability: [{v.rule}] {v.message}")
    else:
        print("  capability check: OK (or agent has no grant - unaffected)")
    print(f"  engine decision: {decision.decision.value}")


try_intent("Case 1: swap within grant", ActionIntent(
    # Kept small on purpose: a brand-new agent (no history yet in this
    # engine instance) is also subject to the ordinary policy engine's
    # tighter max_amount_unknown_agent cap (see policy/templates.py),
    # separately from anything capability-related. $50 would trip that
    # unrelated cap and BLOCK for a reason that has nothing to do with
    # capabilities, which would make this demo confusing.
    agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=3,
))

try_intent("Case 2: action type not granted", ActionIntent(
    agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="bridge", amount=10,
))

try_intent("Case 3: chain not granted", ActionIntent(
    agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="botchain", action_type="swap", from_token="ETH", to_token="USDC", amount=50,
))

try_intent("Case 4: exceeds per-action cap", ActionIntent(
    agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=250,
))

print("--- Case 5: daily cap ---")
for i in range(8):
    intent = ActionIntent(
        agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=80,
    )
    decision = engine.evaluate(intent)
    daily_violation = next(
        (v for v in decision.policy_violations if v.rule == "capability_daily_limit_exceeded"),
        None,
    )
    status = "BLOCKED" if daily_violation else "ok"
    reason = daily_violation.message if daily_violation else ""
    print(f"  swap #{i+1} ($80): {status}  {reason}")

try_intent("Case 6: unregistered agent (no capability grant)", ActionIntent(
    agent_id="some-other-agent", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=5000,
))
