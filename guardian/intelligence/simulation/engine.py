"""Pre-execution transaction simulation.

Delegates to a ``SimulationProvider`` (see
``guardian/intelligence/simulation/providers.py``). By default
(``NullSimulationProvider``) this never attempts a real dry run - select
``GUARDIAN_SIMULATION_PROVIDER=rpc`` for a real ``eth_call``-based check,
which activates whenever the caller supplies raw calldata via
``intent.metadata["data"]``.

Even with the real provider configured, an intent without calldata still
falls back to the semantic heuristic below (an "approve" with no explicit
finite amount is treated as a soft signal for a possible unlimited
approval) - weaker evidence than a decoded on-chain amount, but better
than nothing when that's all the caller gave us.
"""
from __future__ import annotations

from typing import List, Optional

from guardian.core.intent import ActionIntent
from guardian.core.models import Signal
from guardian.intelligence.simulation.providers import (
    NullSimulationProvider,
    RpcSimulationProvider,
    SimulationProvider,
)


def build_simulation_provider(config) -> SimulationProvider:
    if getattr(config, "simulation_provider", "null") == "rpc":
        return RpcSimulationProvider(rpc_urls=config.rpc_urls, timeout=config.provider_timeout_seconds)
    return NullSimulationProvider()


class SimulationEngine:
    source = "simulation"

    def __init__(self, provider: Optional[SimulationProvider] = None):
        self.provider = provider or NullSimulationProvider()

    def simulate(self, intent: ActionIntent) -> List[Signal]:
        result = self.provider.simulate(intent)

        if not result.attempted:
            return self._fallback_heuristic(intent, note=result.error)

        signals: List[Signal] = []

        if result.would_revert:
            signals.append(Signal(
                source=self.source, name="simulation_reverts", score=100, weight=6.0,
                confidence=0.98,
                reason=f"Dry run shows this transaction would revert right now"
                       + (f": {result.revert_reason}" if result.revert_reason else ""),
            ))
            # A transaction that would revert can't also leak an unlimited
            # approval - it wouldn't execute at all. Stop here.
            return signals

        if result.is_unlimited_approval:
            signals.append(Signal(
                source=self.source, name="unlimited_approval_confirmed", score=75, weight=2.0,
                confidence=0.95,
                reason="Dry run confirms this approve() grants an unlimited (or near-unlimited) spending amount",
            ))
        elif result.decoded_approval_amount is not None:
            signals.append(Signal(
                source=self.source, name="finite_approval_confirmed", score=5, weight=0.5,
                confidence=0.95,
                reason=f"Dry run confirms a finite approval amount ({result.decoded_approval_amount})",
            ))

        signals.append(Signal(
            source=self.source, name="simulation_succeeds", score=2, weight=0.5,
            confidence=0.9, reason="Dry run confirms this transaction executes successfully at the current chain state",
        ))
        return signals

    def _fallback_heuristic(self, intent: ActionIntent, note: Optional[str] = None) -> List[Signal]:
        if intent.action_type == "approve" and (intent.amount is None or intent.amount <= 0):
            return [Signal(
                source=self.source, name="unlimited_approval_suspected", score=55, weight=1.0,
                confidence=0.5,
                reason="Approval has no explicit finite amount and could not be dry-run to confirm "
                       "- may grant unlimited spending",
            )]
        return [Signal(
            source=self.source, name="simulation_not_attempted", score=0, weight=0.0,
            confidence=0.0,
            reason="No real dry run was performed" + (f" ({note})" if note else " - no transaction calldata provided"),
        )]
