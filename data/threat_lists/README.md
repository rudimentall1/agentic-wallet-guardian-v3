# Threat lists

These three files back Guardian's `threat_intel` and `contract` signal
sources.

- **`sanctioned_addresses.json` is now populated with real data**: 103
  addresses (100 EVM + 3 Solana) from OFAC's Specially Designated
  Nationals list, via
  [0xB10C/ofac-sanctioned-digital-currency-addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses)
  - a community tool that extracts exactly this from OFAC's own
    authoritative XML, regenerated nightly. Verified when this was seeded:
    delistings are correctly reflected (Tornado Cash's addresses, removed
    from the SDN list in March 2025 after the Fifth Circuit ruling, are
    correctly absent). Refresh it yourself periodically with
    `python scripts/refresh_ofac_list.py` - sanctions lists change.
- **`malicious_contracts.json` / `verified_contracts.json` still ship
  empty on purpose.** Populating them with invented or loosely-sourced
  addresses would be worse than shipping nothing, since a hit is treated
  as conclusive (forced weight regardless of whatever the configured
  `ContractDataProvider` would have said). Unlike OFAC's list, there's no
  single authoritative source for "malicious contract" - see below for
  where to source real entries yourself.

This is also the point of the self-hosted design: these are plain JSON
files on your own disk, not a call to a third-party API. Nothing about
which addresses you're checking ever leaves your infrastructure for this
signal.

## Format

Each file is a flat JSON object: lower-cased address → short label/reason.

```json
{
  "0xabc0000000000000000000000000000000abc0": "OFAC SDN list entry, added 2026-01-15",
  "0xdef0000000000000000000000000000000def0": "Reported rug-pull contract, see incident #142"
}
```

- `sanctioned_addresses.json` - checked against both the initiating wallet
  and the transaction target by `ThreatIntelligence`.
- `malicious_contracts.json` / `verified_contracts.json` - checked against
  the transaction target by `ContractAnalyzer`, before it falls back to
  whichever `ContractDataProvider` you've configured.

## Where to source entries

- **OFAC SDN list** (US sanctions): done - see above. Re-run
  `scripts/refresh_ofac_list.py` on a schedule (cron/systemd timer) to
  keep it current; sanctions get added *and removed*.
- **Community scam-address databases** (e.g. Chainabuse, CryptoScamDB
  exports, your own incident tracker) - many publish CSV/JSON exports you
  can transform into this schema. Still unpopulated here - no single
  source is authoritative enough to seed by default the way OFAC's list
  is, so this is a judgment call for whoever operates this instance.
- **Your own findings** - anything your team has directly investigated and
  confirmed.

## Reloading

`AddressList` loads the file once at process start. Call `.reload()` on
the instance (or restart the process) after editing a file to pick up
changes without a code change - e.g. from a scheduled refresh job.
