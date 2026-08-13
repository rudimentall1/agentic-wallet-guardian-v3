#!/usr/bin/env python3
"""Calls a running Guardian instance's POST /decision endpoint and prints
the result as JSON, exiting with a code the calling agent can branch on
without having to parse JSON itself if it doesn't want to:

    0 = ALLOW      1 = WARN      2 = BLOCK      3 = error (see stderr)

Dependency-free (stdlib only, `urllib.request`) - this runs inside a
skill invoked by many different agent runtimes, and we don't want the
check itself to fail because `requests` wasn't installed in whatever
environment the agent happens to be running in.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

EXIT_BY_DECISION = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def main() -> int:
    parser = argparse.ArgumentParser(description="Ask Guardian for an ALLOW/WARN/BLOCK decision before running an mm command.")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--chain", default="ethereum")
    parser.add_argument("--action-type", required=True, choices=["swap", "transfer", "approve", "contract_call", "bridge"])
    parser.add_argument("--target", default=None)
    parser.add_argument("--amount", type=float, default=None)
    parser.add_argument("--from-token", default=None)
    parser.add_argument("--to-token", default=None)
    args = parser.parse_args()

    api_url = os.environ.get("GUARDIAN_API_URL")
    api_key = os.environ.get("GUARDIAN_API_KEY")
    if not api_url:
        print("GUARDIAN_API_URL is not set - refusing to guess a default. "
              "Set it to your running Guardian instance, e.g. http://localhost:8000",
              file=sys.stderr)
        return 3

    payload = {
        "agent_id": args.agent_id,
        "wallet": args.wallet,
        "chain": args.chain,
        "action_type": args.action_type,
        "target": args.target,
        "amount": args.amount,
        "from_token": args.from_token,
        "to_token": args.to_token,
    }
    body = json.dumps(payload).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    req = urllib.request.Request(f"{api_url.rstrip('/')}/decision", data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        print(f"Guardian returned HTTP {e.code}: {detail}", file=sys.stderr)
        return 3
    except urllib.error.URLError as e:
        print(f"Could not reach Guardian at {api_url}: {e.reason}", file=sys.stderr)
        return 3

    print(json.dumps(result, indent=2))
    return EXIT_BY_DECISION.get(result.get("decision", ""), 3)


if __name__ == "__main__":
    sys.exit(main())
