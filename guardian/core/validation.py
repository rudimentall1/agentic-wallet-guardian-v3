"""Shared address-format validation.

Previously duplicated as a private `_looks_like_address()` in both
`intelligence/simulation/tx_builder.py` and
`intelligence/token/providers.py` - and, notably, *not* present at all in
`intelligence/contract/providers.py`, which built external HTTP request
URLs by directly f-string-interpolating `intent.target` (a fully
caller-controlled string) with no validation whatsoever. This module
gives every caller the same one check, so "validate before it reaches an
external API/RPC call" isn't something each analyzer has to remember to
reimplement (or not) on its own.

This is intentionally a shallow, cheap check (0x-prefix, correct length,
hex digits) - not a checksum (EIP-55) validator, and not chain-aware
(Solana/other non-EVM address formats are out of scope here). Its job is
to reject the kind of malformed/adversarial input that has no business
reaching a URL path segment or being ABI-encoded, not to certify that an
address is real or checksummed correctly.
"""
from __future__ import annotations

import re
from typing import Optional

_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def looks_like_address(value: Optional[str]) -> bool:
    return bool(value) and bool(_HEX_ADDRESS_RE.match(value))
