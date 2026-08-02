"""Regression tests for the shipped sanctioned-addresses data itself (not
just the AddressList loading mechanism, which test_contract_and_lists.py
already covers). This file exists because that data was hand-verified
once at seed time - these tests make sure it doesn't silently regress
back to empty or drift into staleness undetected."""
import json
from pathlib import Path

import unittest

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_lists" / "sanctioned_addresses.json"

# A real Garantex Europe address from OFAC's April 2022 designation
# (Russia-related sanctions) - a durable entry, unlikely to be delisted.
KNOWN_SANCTIONED_ADDRESS = "0x7ff9cfad3877f21d41da833e2f775db0569ee3d9"

# Tornado Cash addresses were removed from the SDN list in March 2025
# following the Fifth Circuit's ruling that OFAC exceeded its authority
# sanctioning immutable smart contracts. If this address is present, the
# data is stale by at least a year and should not be trusted as current.
DELISTED_TORNADO_CASH_ADDRESS = "0x8589427373d6d84e98730d7795d8f6f8731fda16"


class TestShippedSanctionedAddressData(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(DATA_PATH.read_text())

    def test_is_not_empty(self):
        self.assertGreater(len(self.data), 50, "sanctioned_addresses.json should not have regressed to near-empty")

    def test_known_sanctioned_address_present(self):
        self.assertIn(KNOWN_SANCTIONED_ADDRESS, self.data)

    def test_delisted_address_is_absent(self):
        self.assertNotIn(
            DELISTED_TORNADO_CASH_ADDRESS, self.data,
            "Tornado Cash addresses were delisted in March 2025 - their presence means this data is stale",
        )


if __name__ == "__main__":
    unittest.main()
