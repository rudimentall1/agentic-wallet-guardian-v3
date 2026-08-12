"""Guardian Decision Engine.

The single entry point of the v3 architecture:

    decision = DecisionEngine().evaluate(intent)

Pipeline:

    Intent
      -> Hard Rules              (can force BLOCK immediately)
      -> Collect Signals          (wallet / token / contract / simulation / threat intel)
      -> Policy Check              (spending caps, reputation gates, action-type rules)
      -> Risk Fusion                (signals -> single 0-100 score)
      -> Reputation Adjustment       (trusted agents get a discount, unknowns a penalty)
      -> Decision + Explanation       (ALLOW / WARN / BLOCK, with reasons)
      -> Record to Memory              (feeds future reputation lookups)
"""
from __future__ import annotations

from typing import List, Optional

from dataclasses import replace as dataclasses_replace

from guardian.config import GuardianConfig, get_config
from guardian.core.context import EvaluationContext
from guardian.core.intent import ActionIntent
from guardian.core.models import Decision, DecisionType, PolicyViolation
from guardian.decision.rules import evaluate_hard_rules
from guardian.decision.scoring import RiskFusionEngine
from guardian.intelligence.anomaly.analyzer import AnomalyAnalyzer
from guardian.intelligence.contract.analyzer import ContractAnalyzer, build_contract_provider
from guardian.intelligence.simulation.engine import SimulationEngine, build_simulation_provider
from guardian.intelligence.simulation.tx_builder import build_transaction_builder
from guardian.intelligence.threat.blocklist import AddressList
from guardian.intelligence.threat.intelligence import ThreatIntelligence
from guardian.intelligence.token.analyzer import TokenAnalyzer, build_token_provider
from guardian.intelligence.wallet.analyzer import WalletAnalyzer, build_wallet_provider
from guardian.memory.history import DecisionHistory
from guardian.memory.storage import InMemoryStorage, MemoryBackend
from guardian.policy.engine import PolicyEngine
from guardian.reasoning.confidence import compute_confidence
from guardian.reasoning.explanation import build_explanation
from guardian.reputation.agent import AgentReputation


def build_storage_backend(config: GuardianConfig) -> MemoryBackend:
    if config.storage_backend == "sqlite":
        from guardian.memory.sqlite_storage import SQLiteStorage

        return SQLiteStorage(config.sqlite_path)
    return InMemoryStorage()

# Thresholds for translating a fused risk score into a decision, once no
# hard rule / BLOCK-severity policy violation has already forced BLOCK.
BLOCK_THRESHOLD = 80.0
WARN_THRESHOLD = 40.0


class DecisionEngine:
    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        history: Optional[DecisionHistory] = None,
        config: Optional[GuardianConfig] = None,
        wallet_analyzer: Optional[WalletAnalyzer] = None,
        token_analyzer: Optional[TokenAnalyzer] = None,
        contract_analyzer: Optional[ContractAnalyzer] = None,
        simulation_engine: Optional[SimulationEngine] = None,
        anomaly_analyzer: Optional[AnomalyAnalyzer] = None,
    ):
        config = config or get_config()
        self.wallet_analyzer = wallet_analyzer or WalletAnalyzer(build_wallet_provider(config))
        self.token_analyzer = token_analyzer or TokenAnalyzer(build_token_provider(config))
        self.contract_analyzer = contract_analyzer or ContractAnalyzer(
            build_contract_provider(config),
            known_safe=AddressList(config.verified_contracts_path),
            known_malicious=AddressList(config.malicious_contracts_path),
        )
        self.simulation_engine = simulation_engine or SimulationEngine(build_simulation_provider(config))
        self.tx_builder = build_transaction_builder(config)
        self.threat_intel = ThreatIntelligence(AddressList(config.sanctioned_addresses_path))
        self.risk_fusion = RiskFusionEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.history = history or DecisionHistory(build_storage_backend(config))
        self.reputation = AgentReputation(self.history)
        self.anomaly_analyzer = anomaly_analyzer or AnomalyAnalyzer()

    def evaluate(self, intent: ActionIntent) -> Decision:
        # 1. Hard rules can short-circuit straight to BLOCK before we spend
        #    any effort gathering signals.
        hard_violations = evaluate_hard_rules(intent)
        if any(v.severity == "BLOCK" for v in hard_violations):
            return self._finalize(intent, DecisionType.BLOCK, 100.0, [], hard_violations)

        # 2. Build context — reputation/history first, since policy checks need it.
        ctx = EvaluationContext(
            intent=intent,
            agent_reputation_score=self.reputation.score_for(intent.agent_id),
            agent_history_size=self.reputation.history_size(intent.agent_id),
        )

        # 3. Collect signals from every intelligence source.
        for s in self.wallet_analyzer.analyze(intent.wallet, intent.chain):
            ctx.add_signal(s)
        for s in self.token_analyzer.analyze(intent.to_token or intent.from_token, intent.chain):
            ctx.add_signal(s)
        for s in self.contract_analyzer.analyze(intent.target, intent.chain):
            ctx.add_signal(s)

        # If the caller didn't already supply real calldata, try building it
        # for the simple cases (transfer/approve) where that's unambiguous -
        # see tx_builder.py for exactly what this does and doesn't cover.
        # Never mutates the caller's own intent object.
        sim_intent = intent
        if "data" not in intent.metadata:
            built = self.tx_builder.build(intent)
            if built is not None:
                sim_intent = dataclasses_replace(
                    intent, metadata={**intent.metadata, "data": built.data, "value": built.value},
                )
        for s in self.simulation_engine.simulate(sim_intent):
            ctx.add_signal(s)
        for s in self.threat_intel.check(intent.wallet, intent.target):
            ctx.add_signal(s)

        # Anomaly detection compares this intent against the agent's own
        # past — must run against history *before* this decision is
        # recorded, which is naturally the case here (recording happens
        # in _finalize, after this).
        for s in self.anomaly_analyzer.analyze(intent, self.history.get(intent.agent_id)):
            ctx.add_signal(s)

        # 4. Policy evaluation — business rules independent of statistical risk.
        policy_violations: List[PolicyViolation] = hard_violations + self.policy_engine.evaluate(ctx)
        if any(v.severity == "BLOCK" for v in policy_violations):
            return self._finalize(intent, DecisionType.BLOCK, 100.0, ctx.signals, policy_violations)

        # 5. Risk fusion — signals become one 0-100 score.
        risk_score = self.risk_fusion.fuse(ctx.signals)

        # 6. Reputation adjustment: trusted agents get a modest discount,
        #    low-reputation/unknown agents get a modest penalty.
        rep_adjustment = (50.0 - ctx.agent_reputation_score) * 0.15
        risk_score = max(0.0, min(100.0, risk_score + rep_adjustment))

        # 7. Translate the score (+ any WARN-severity policy hit) into a decision.
        has_warn_violation = any(v.severity == "WARN" for v in policy_violations)
        if risk_score >= BLOCK_THRESHOLD:
            decision_type = DecisionType.BLOCK
        elif risk_score >= WARN_THRESHOLD or has_warn_violation:
            decision_type = DecisionType.WARN
        else:
            decision_type = DecisionType.ALLOW

        return self._finalize(intent, decision_type, risk_score, ctx.signals, policy_violations)

    def _finalize(self, intent, decision_type, risk_score, signals, violations) -> Decision:
        explanation = build_explanation(signals, violations)
        confidence = compute_confidence(signals)
        decision = Decision(
            decision=decision_type,
            risk_score=risk_score,
            risk_level=self.risk_fusion.to_risk_level(risk_score),
            confidence=confidence,
            explanation=explanation,
            signals=signals,
            policy_violations=violations,
            agent_id=intent.agent_id,
            intent_id=intent.intent_id,
        )
        self.history.record(intent.agent_id, decision, intent)
        return decision
