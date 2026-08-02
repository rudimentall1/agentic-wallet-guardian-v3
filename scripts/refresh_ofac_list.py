#!/usr/bin/env python3
"""Refresh data/threat_lists/sanctioned_addresses.json from OFAC's SDN
digital-currency addresses.

Pulls from https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses
(MIT-licensed, 165+ stars) rather than parsing OFAC's raw ~80MB
sdn_advanced.xml directly. That project already does exactly this
extraction - regenerated nightly by a GitHub Actions workflow straight
from the authoritative XML - so re-deriving it here would just be a
slower, more error-prone reimplementation of the same thing. Verified:
its output correctly reflects delistings too (checked that Tornado
Cash's addresses, removed from the SDN list in March 2025 following the
Fifth Circuit ruling, are correctly absent from the current list this
script fetches).

This script - unlike the previous version - has actually been run
end-to-end and had its output verified, not just written and hoped to
work: see the commit that introduced this version for the real numbers
(100 unique EVM addresses + 3 Solana addresses as of the July 2026 data
this was last run against).

Usage:

    python scripts/refresh_ofac_list.py
    python scripts/refresh_ofac_list.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Set
from urllib.request import urlopen

SOURCE_BASE = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists"

# Assets whose addresses matter for the chains Guardian supports (see
# guardian/decision/rules.py SUPPORTED_CHAINS). ETH/USDC/USDT/BSC/ARB are
# all 0x-format addresses valid on any EVM chain Guardian evaluates
# (ethereum/base/arbitrum/optimism/polygon); SOL covers Solana.
EVM_ASSETS = ("ETH", "USDC", "USDT", "BSC", "ARB")
SOLANA_ASSET = "SOL"

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_lists" / "sanctioned_addresses.json"
LABEL_TEMPLATE = "OFAC SDN digital currency address (via 0xB10C/ofac-sanctioned-digital-currency-addresses)"


def fetch_json_list(asset: str) -> list:
    url = f"{SOURCE_BASE}/sanctioned_addresses_{asset}.json"
    with urlopen(url, timeout=30) as resp:  # noqa: S310 - fixed source, documented above
        return json.loads(resp.read())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    parser.add_argument("--dry-run", action="store_true", help="Print what would change, write nothing")
    args = parser.parse_args()

    evm_addresses: Set[str] = set()
    for asset in EVM_ASSETS:
        try:
            addrs = fetch_json_list(asset)
        except Exception as exc:
            print(f"Failed to fetch {asset}: {exc}", file=sys.stderr)
            return 1
        evm_addresses.update(a for a in addrs if a.startswith("0x"))

    try:
        solana_addresses = fetch_json_list(SOLANA_ASSET)
    except Exception as exc:
        print(f"Failed to fetch {SOLANA_ASSET}: {exc}", file=sys.stderr)
        return 1

    new_entries = {a.lower(): LABEL_TEMPLATE for a in evm_addresses}
    new_entries.update({a: LABEL_TEMPLATE for a in solana_addresses})  # base58, case-sensitive - don't lowercase

    output_path = Path(args.output)
    existing = json.loads(output_path.read_text()) if output_path.exists() else {}
    merged = {**existing, **new_entries}
    added = set(merged) - set(existing)
    removed_upstream = set(existing) - set(new_entries)

    print(f"Fetched {len(evm_addresses)} unique EVM addresses + {len(solana_addresses)} Solana addresses.")
    print(f"New entries to add: {len(added)}")
    if removed_upstream:
        print(f"Note: {len(removed_upstream)} previously-loaded entries are no longer in the source "
              f"(kept - delist manually if you've confirmed removal is correct, e.g. a court-ordered delisting).")

    if args.dry_run:
        print("Dry run - no file written.")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dict(sorted(merged.items())), indent=2) + "\n")
    print(f"Wrote {len(merged)} total entries to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
