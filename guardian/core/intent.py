"""ActionIntent: the single unit of analysis in Guardian v3.

The core paradigm shift from v2: the pipeline no longer analyzes a wallet
in isolation (``analyze(wallet)``); it evaluates what an agent is *about to
do* (``evaluate(action_intent)``). The wallet is just one field of context
on the intent, alongside the chain, the action type, the target, and the
amount.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ActionIntent:
    agent_id: str
    wallet: str
    chain: str = "ethereum"
    action_type: str = "unknown"  # swap | transfer | approve | contract_call | bridge ...
    target: Optional[str] = None  # contract / recipient address
    # For `approve`/`transfer`: from_token is the ERC-20 token contract
    # being approved/transferred (this is what RpcTransactionBuilder
    # requires to build real calldata - see tx_builder.py - and what
    # DecisionEngine looks decimals() up for during intent verification).
    # For `swap`: from_token/to_token are the two sides of the trade.
    from_token: Optional[str] = None
    to_token: Optional[str] = None
    amount: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    submitted_at: float = field(default_factory=time.time)

    @property
    def intent_id(self) -> str:
        """Deterministic-ish identifier for correlation, logging and audit trails."""
        raw = (
            f"{self.agent_id}:{self.wallet}:{self.chain}:{self.action_type}:"
            f"{self.target}:{self.amount}:{self.submitted_at}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionIntent":
        known_fields = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known_fields}
        return cls(**clean)
