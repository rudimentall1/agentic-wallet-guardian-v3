"""Local, file-based address lists.

This is the self-hosted answer to "sanctions list" / "known malicious
contract registry" / "verified contract registry": a plain JSON file that
lives in *your* deployment, that *you* maintain, and that never requires
sending a wallet address to a third-party API just to check it against a
list. No data about who is being checked ever leaves your infrastructure
for this signal.

Format (one file per list): a flat JSON object mapping a lower-cased
address to a short human-readable label/reason::

    {
        "0xabc123...": "OFAC SDN list entry, added 2026-01-15"
    }

Populate these yourself from whatever sources you trust - OFAC's public
SDN list, Chainalysis/TRM if you have a subscription, community
scam-address databases, or your own incident findings. See
``scripts/refresh_ofac_list.py`` for one example of an automated refresh
script you can run on a schedule (it needs network access to
treasury.gov, which this repo does not assume you have at build time).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("guardian.threat")


class AddressList:
    """Reload semantics deliberately favor staying safe over staying
    fresh: the *first* load treats a missing or unparseable file as
    empty (there's nothing to fall back to yet). Every *subsequent*
    reload() that fails (file deleted, corrupted, permissions changed)
    keeps serving the last successfully-loaded entries instead of
    reverting to empty - this list is as likely to be a deny-list
    (malicious contracts, sanctioned addresses) as an allow-list, and
    silently going empty on a deny-list is a silent fail-open: every
    previously-blocked address would stop being blocked.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self._entries: Dict[str, str] = {}
        self._has_loaded_successfully = False
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            if not self._has_loaded_successfully:
                logger.info("Address list %s does not exist yet - treating as empty. "
                            "Create it (see guardian/intelligence/threat/blocklist.py docstring "
                            "for the format) to start using this list.", self.path)
                self._entries = {}
            else:
                # The file existed a moment ago and now doesn't (deleted,
                # unmounted, a bad deploy). For a deny-list specifically,
                # silently going back to empty means every previously-known
                # malicious/sanctioned address stops being blocked with no
                # operator-visible signal beyond a log line. Keep serving
                # the last successfully-loaded entries instead - stale-but-
                # blocking beats silently-permissive.
                logger.error(
                    "Address list %s existed before but is now missing - "
                    "continuing to enforce the last successfully loaded %d "
                    "entries rather than silently reverting to an empty list.",
                    self.path, len(self._entries),
                )
            return
        try:
            raw = json.loads(self.path.read_text())
            if not isinstance(raw, dict):
                raise ValueError("expected a JSON object mapping address -> label")
            self._entries = {str(k).lower(): str(v) for k, v in raw.items()}
            self._has_loaded_successfully = True
        except Exception:
            if not self._has_loaded_successfully:
                logger.error("Failed to parse address list %s - treating as empty this run "
                              "(no prior successful load to fall back to)", self.path, exc_info=True)
                self._entries = {}
            else:
                # Same reasoning as the missing-file branch above: a
                # corrupted file on a later reload must not erase
                # previously-known entries.
                logger.error(
                    "Failed to parse address list %s on reload - keeping the "
                    "last successfully loaded %d entries rather than wiping "
                    "them out. This deploy's edit to the file was NOT picked "
                    "up; fix and reload again.",
                    self.path, len(self._entries), exc_info=True,
                )

    def __contains__(self, address: str) -> bool:
        return bool(address) and address.lower() in self._entries

    def label_for(self, address: str) -> Optional[str]:
        return self._entries.get((address or "").lower())

    def __len__(self) -> int:
        return len(self._entries)
