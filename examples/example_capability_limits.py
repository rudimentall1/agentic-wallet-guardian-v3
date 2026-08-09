import sys
sys.path.insert(0, ".")

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.policy.capabilities import Capability, CapabilityRegistry, evaluate_capability

registry = CapabilityRegistry()

registry.grant(Capability(
    agent_id="trading-agent-001",
    allowed_action_types=["swap"],
    allowed_chains=["ethereum"],
    max_amount_per_action=100.0,
    max_daily_amount=500.0,
))

engine = DecisionEngine()


def try_intent(label, intent):
    print(f"--- {label} ---")
    cap_violations = evaluate_capability(intent, registry)
    if cap_violations:
        for v in cap_violations:
            print(f"  BLOCKED by capability: [{v.rule}] {v.message}")
        return
    print("  capability check: OK (or agent has no grant - unaffected)")
    decision = engine.evaluate(intent)
    print(f"  engine decision: {decision.decision.value}")


try_intent("Case 1: swap within grant", ActionIntent(
    agent_id="trading-agent-001", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=50,
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
    violations = evaluate_capability(intent, registry)
    status = "BLOCKED" if violations else "ok"
    reason = violations[0].message if violations else ""
    print(f"  swap #{i+1} ($80): {status}  {reason}")

try_intent("Case 6: unregistered agent (no capability grant)", ActionIntent(
    agent_id="some-other-agent", wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain="ethereum", action_type="swap", from_token="ETH", to_token="USDC", amount=5000,
))