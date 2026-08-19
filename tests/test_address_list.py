import json
import tempfile
import unittest
from pathlib import Path

from guardian.intelligence.threat.blocklist import AddressList


class TestAddressList(unittest.TestCase):
    def test_missing_file_on_first_load_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            addr_list = AddressList(str(Path(d) / "does-not-exist.json"))
            self.assertEqual(len(addr_list), 0)
            self.assertNotIn("0xabc", addr_list)

    def test_loads_entries_from_valid_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xABC": "test entry"}))
            addr_list = AddressList(str(path))
            self.assertEqual(len(addr_list), 1)
            self.assertIn("0xabc", addr_list)  # lower-cased
            self.assertEqual(addr_list.label_for("0xABC"), "test entry")

    def test_malformed_json_on_first_load_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text("{not valid json")
            addr_list = AddressList(str(path))
            self.assertEqual(len(addr_list), 0)

    def test_non_object_json_on_first_load_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps(["0xabc", "0xdef"]))  # array, not object
            addr_list = AddressList(str(path))
            self.assertEqual(len(addr_list), 0)

    def test_reload_picks_up_new_entries(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xabc": "first"}))
            addr_list = AddressList(str(path))
            self.assertEqual(len(addr_list), 1)

            path.write_text(json.dumps({"0xabc": "first", "0xdef": "second"}))
            addr_list.reload()
            self.assertEqual(len(addr_list), 2)
            self.assertIn("0xdef", addr_list)

    def test_corrupted_file_on_reload_keeps_prior_entries(self):
        """Regression test for the fail-open bug: a deny-list (malicious
        contracts, sanctioned addresses) that fails to reload must not
        silently revert to empty - that would silently un-block every
        previously-known-bad address."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xbadactor": "known scammer"}))
            addr_list = AddressList(str(path))
            self.assertIn("0xbadactor", addr_list)

            path.write_text("{this is now corrupted")
            addr_list.reload()

            # Still enforcing the last good load, not silently empty.
            self.assertIn("0xbadactor", addr_list)
            self.assertEqual(len(addr_list), 1)

    def test_deleted_file_on_reload_keeps_prior_entries(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xbadactor": "known scammer"}))
            addr_list = AddressList(str(path))
            self.assertIn("0xbadactor", addr_list)

            path.unlink()
            addr_list.reload()

            self.assertIn("0xbadactor", addr_list)
            self.assertEqual(len(addr_list), 1)

    def test_recovering_after_a_bad_reload_works_normally(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xbadactor": "known scammer"}))
            addr_list = AddressList(str(path))

            path.write_text("{corrupted")
            addr_list.reload()
            self.assertIn("0xbadactor", addr_list)  # still there during the outage

            path.write_text(json.dumps({"0xbadactor": "known scammer", "0xnew": "new entry"}))
            addr_list.reload()
            self.assertEqual(len(addr_list), 2)
            self.assertIn("0xnew", addr_list)

    def test_contains_handles_empty_and_none_gracefully(self):
        with tempfile.TemporaryDirectory() as d:
            addr_list = AddressList(str(Path(d) / "empty.json"))
            self.assertNotIn("", addr_list)
            self.assertFalse(addr_list.__contains__(None))


if __name__ == "__main__":
    unittest.main()
