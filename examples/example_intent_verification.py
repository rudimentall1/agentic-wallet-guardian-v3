import sys
sys.path.insert(0, ".")

from guardian.core.intent import ActionIntent
from guardian.decision.intent_verification import verify_intent_matches_simulation
from guardian.intelligence.simulation.providers import SimulationResult

USDC_DECIMALS = 6


def run_case(label, intent, sim, decimals=USDC_DECIMALS):
    print(f"--- {label} ---")
    violations = verify_intent_matches_simulation(intent, sim, token_decimals=decimals)
    if not violations:
        print("  no mismatch detected")
    for v in violations:
        print(f"  [{v.severity}] {v.rule}: {v.message}")


run_case(
    "Case 1: declared amount matches calldata",
    ActionIntent(agent_id="agent-42", wallet="0xWallet", chain="ethereum",
                 action_type="approve", to_token="USDC", amount=500),
    SimulationResult(attempted=True, would_revert=False,
                      decoded_approval_amount=500_000000, is_unlimited_approval=False),
)

run_case(
    "Case 2: agent said 500, calldata actually encodes 5000",
    ActionIntent(agent_id="agent-42", wallet="0xWallet", chain="ethereum",
                 action_type="approve", to_token="USDC", amount=500),
    SimulationResult(attempted=True, would_revert=False,
                      decoded_approval_amount=5_000_000000, is_unlimited_approval=False),
)

run_case(
    "Case 3: decimals unknown - refuses to guess",
    ActionIntent(agent_id="agent-42", wallet="0xWallet", chain="ethereum",
                 action_type="approve", to_token="???", amount=500),
    SimulationResult(attempted=True, would_revert=False,
                      decoded_approval_amount=500_000000, is_unlimited_approval=False),
    decimals=None,
)

run_case(
    "Case 4: unlimited approval (already handled elsewhere, no duplicate)",
    ActionIntent(agent_id="agent-42", wallet="0xWallet", chain="ethereum",
                 action_type="approve", to_token="USDC", amount=500),
    SimulationResult(attempted=True, would_revert=False,
                      decoded_approval_amount=2**256 - 1, is_unlimited_approval=True),
)