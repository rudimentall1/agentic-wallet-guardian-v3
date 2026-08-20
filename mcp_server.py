#!/usr/bin/env python3
"""Guardian as an MCP server.

This is the "plug straight into your agent framework" path the REST API
can't offer on its own: LangChain, CrewAI, Claude Desktop, or any other
MCP-capable client can call Guardian as a local tool over stdio, with no
HTTP client code, no API key to manage, and no network hop if the agent
runs on the same host.

Can be installed alongside the REST API's requirements.txt in one
environment - see the comment at the top of requirements-mcp.txt for
why (this used to require a separate venv; that was documented as a
starlette conflict, which turned out to be wrong - the actual cause was
pydantic/uvicorn version floors, fixed in requirements.txt).

Run:

    pip install -r requirements.txt -r requirements-mcp.txt
    python mcp_server.py

Then point your MCP client at this command (stdio transport). Example
Claude Desktop config entry:

    {
      "mcpServers": {
        "wallet-guardian": {
          "command": "/path/to/venv-mcp/bin/python",
          "args": ["/path/to/agentic-wallet-guardian/mcp_server.py"]
        }
      }
    }
"""
from __future__ import annotations

import json

from mcp.server import MCPServer

from guardian.config import get_config
from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine

mcp = MCPServer("agentic-wallet-guardian")

# One shared engine for the process lifetime, same rationale as api/main.py:
# reputation/history need to persist across calls within a run. Set
# GUARDIAN_STORAGE_BACKEND=sqlite (see .env.example) for persistence across
# restarts too.
_engine = DecisionEngine(config=get_config())


@mcp.tool()
def evaluate_action(
    agent_id: str,
    wallet: str,
    chain: str,
    action_type: str,
    target: str | None = None,
    from_token: str | None = None,
    to_token: str | None = None,
    amount: float | None = None,
) -> str:
    """Evaluate a proposed blockchain action before executing it.

    Call this BEFORE submitting any transaction on behalf of a user or
    agent. Returns a JSON object with a decision ("ALLOW", "WARN", or
    "BLOCK"), a 0-100 risk score, and a human-readable explanation of
    which signals drove the decision. Treat "BLOCK" as a hard stop and
    "WARN" as something that needs explicit user confirmation before
    proceeding.

    Args:
        agent_id: Stable identifier for the calling agent (used for
            reputation history - reuse the same id across calls).
        wallet: The wallet address initiating the action.
        chain: Chain name, e.g. "ethereum", "base", "arbitrum", "polygon".
        action_type: One of "swap", "transfer", "approve",
            "contract_call", "bridge".
        target: Contract or recipient address, if applicable.
        from_token: Token symbol being sent/sold, if applicable.
        to_token: Token symbol being received/bought, if applicable.
        amount: Transaction amount in the relevant unit.
    """
    intent = ActionIntent(
        agent_id=agent_id, wallet=wallet, chain=chain, action_type=action_type,
        target=target, from_token=from_token, to_token=to_token, amount=amount,
    )
    decision = _engine.evaluate(intent)
    return json.dumps(decision.to_dict())


@mcp.tool()
def get_agent_history(agent_id: str, limit: int = 100) -> str:
    """Return this agent's past decisions and current reputation score.

    Useful before evaluate_action if you want to check standing first, or
    after a WARN/BLOCK to review why.

    Args:
        agent_id: The agent to look up.
        limit: Maximum number of most-recent records to return (default
            100, capped at 500). Same reasoning as the REST API's
            equivalent /agents/{id}/history?limit= - an agent's history
            grows without bound, and returning all of it on every call
            doesn't scale.
    """
    limit = max(1, min(limit, 500))
    records = _engine.history.get(agent_id, limit=limit)
    return json.dumps({
        "agent_id": agent_id,
        "reputation_score": _engine.reputation.score_for(agent_id),
        "history": [
            {"intent_id": r.intent_id, "decision": r.decision.value,
             "risk_score": r.risk_score, "created_at": r.created_at}
            for r in records
        ],
    })


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
