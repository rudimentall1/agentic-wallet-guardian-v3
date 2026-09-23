# Hackathon Submissions

Guardian is submitted to multiple hackathons in parallel. The core
architecture and codebase are identical across all of them (see main
README) - this file only documents which angle is relevant to each track,
so reviewers on any one track see the right context without the README
reading as if it were built for a single chain or ecosystem.

## Arc Microgrants (DoraHacks)
https://dorahacks.io/hackathon/arc-microgrants/detail

**Relevant work:** live deployment on Arc mainnet gating real USDC
payments (see [Arc Mainnet Demo](../README.md#arc-mainnet-demo) in the
main README, verified transaction included). Guardian's policy engine
and spending-cap enforcement map directly onto the Circle/Arc
digital-finance use case: an AI agent's USDC payment intent is evaluated
and can be blocked or require confirmation before it is ever signed.

### Why this matters for Arc

Arc's current builder thesis explicitly highlights the agentic economy and intelligent accounts: agents can hold funds, transact in USDC, and operate within bounded mandates and risk limits.

Guardian adds a security boundary around that model. An agent can initiate the intent, but Guardian evaluates it before the wallet signs, and the GuardianValidator can enforce an approved decision on-chain.

This positions Guardian as infrastructure for safer agentic commerce on Arc, rather than an Arc-specific demo only.
## [Next hackathon name]
[link]

**Relevant work:** [which part of the codebase is relevant to this track]

---

Adding a new hackathon here should never require editing the main
README or any chain-specific section - just append a new entry above.
