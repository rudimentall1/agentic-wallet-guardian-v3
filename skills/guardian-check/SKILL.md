---
name: guardian-check
description: Use before executing any MetaMask Agent Wallet (mm CLI) command that moves funds or changes on-chain state — mm send, mm swap, mm bridge, mm perps open/modify/close, mm predict trade, mm earn supply/withdraw, mm aave borrow/repay, mm pay. Sends the proposed action to a self-hosted Agentic Wallet Guardian instance for an ALLOW/WARN/BLOCK decision before the mm command runs. Do not use for read-only commands (mm balance, mm history, mm address) — those don't move funds and don't need a check.
---

# guardian-check

MetaMask Agent Wallet's own Guard Mode / Beast Mode settings (spend
limits, allowlists, threat scanning) apply the same static rules to
every agent. Guardian adds a second, independent check: does this
specific action look right for *this* agent, right now — comparing
declared intent against actual calldata, this agent's own history, and
an explainable policy engine — before the `mm` command is allowed to
run at all.

Guardian has no access to private keys and never executes anything
itself. It only returns a decision. MetaMask Agent Wallet remains the
only thing that ever signs or broadcasts a transaction.

## When to use this

Before running any `mm` command that moves funds or changes on-chain
state. Map the command to the fields Guardian needs:

| mm command | action_type | notes |
|---|---|---|
| `mm send` | `transfer` | `target` = recipient address |
| `mm swap` | `swap` | `from_token`/`to_token` from the swap args |
| `mm bridge` | `bridge` | |
| `mm perps open/modify/close` | `contract_call` | treat as a contract call against the perps protocol |
| `mm predict trade` | `contract_call` | |
| `mm earn supply/withdraw` | `contract_call` | |
| `mm aave borrow/repay` | `contract_call` | |
| `mm pay` (x402) | `transfer` or `contract_call` depending on the resource being paid for | |

Do **not** run this check for read-only commands (`mm balance`, `mm
history`, `mm address`, `mm portfolio`) — nothing to evaluate, they
never move funds.

## How to use this

1. Build the intent from what the user/agent is about to do with `mm`:
   `agent_id`, `wallet` (the `mm` address), `chain`, `action_type`
   (from the table above), `target`, `amount`, `from_token`/`to_token`
   if relevant.
2. Run:

   ```
   python scripts/check.py \
     --agent-id "<your agent's stable id>" \
     --wallet "<mm wallet address>" \
     --chain "<chain>" \
     --action-type "<mapped action_type>" \
     --amount <amount> \
     --target "<recipient or contract address>"
   ```

   (omit `--target`/`--amount`/`--from-token`/`--to-token` when not
   applicable to the command)

3. Read the exit code and JSON on stdout:
   - **exit 0, decision=ALLOW** → proceed and run the `mm` command normally.
   - **exit 1, decision=WARN** → do not run the `mm` command yet. Show
     the user the `explanation` from the JSON output and ask for
     explicit confirmation before proceeding.
   - **exit 2, decision=BLOCK** → do not run the `mm` command. Tell the
     user it was blocked and why, quoting the `explanation` field.
     Do not retry with different wording to get a different decision.
   - **exit 3** → Guardian was unreachable or misconfigured (see
     stderr). Tell the user Guardian couldn't be reached rather than
     silently skipping the check and running the `mm` command anyway.

## Configuration

Requires a running Guardian instance (`uvicorn api.main:app`) — see
the main [README](../../README.md) for setup. Set before use:

```
export GUARDIAN_API_URL="http://localhost:8000"
export GUARDIAN_API_KEY="<your GUARDIAN_API_KEY>"
```

If `GUARDIAN_API_URL` is not set, `scripts/check.py` exits 3
immediately rather than guessing a default — a silently-skipped check
is worse than a visibly-broken one.
