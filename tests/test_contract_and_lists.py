import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from guardian.intelligence.contract.analyzer import ContractAnalyzer
from guardian.intelligence.contract.providers import (
    BlockscoutContractDataProvider,
    MockContractDataProvider,
)
from guardian.intelligence.threat.blocklist import AddressList


class TestAddressList(unittest.TestCase):
    def test_missing_file_is_treated_as_empty(self):
        alist = AddressList("/tmp/definitely-does-not-exist-guardian-test.json")
        self.assertNotIn("0xabc", alist)
        self.assertEqual(len(alist), 0)

    def test_loads_and_matches_case_insensitively(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({"0xABC123": "test entry"}))
            alist = AddressList(str(path))
            self.assertIn("0xabc123", alist)
            self.assertIn("0xABC123", alist)
            self.assertEqual(alist.label_for("0xabc123"), "test entry")

    def test_malformed_json_degrades_to_empty_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.json"
            path.write_text("{not valid json")
            alist = AddressList(str(path))  # should not raise
            self.assertEqual(len(alist), 0)

    def test_reload_picks_up_changes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "list.json"
            path.write_text(json.dumps({}))
            alist = AddressList(str(path))
            self.assertNotIn("0xdef", alist)
            path.write_text(json.dumps({"0xdef": "added later"}))
            alist.reload()
            self.assertIn("0xdef", alist)


class TestMockContractDataProvider(unittest.TestCase):
    def test_deterministic(self):
        provider = MockContractDataProvider()
        p1 = provider.get_profile("0xabc", "ethereum")
        p2 = provider.get_profile("0xabc", "ethereum")
        self.assertEqual(p1.is_verified, p2.is_verified)


class TestBlockscoutContractDataProvider(unittest.TestCase):
    def test_verified_contract(self):
        provider = BlockscoutContractDataProvider(base_url="https://eth.blockscout.com")
        fake_response = MagicMock()
        fake_response.status_code = 200
        fake_response.json.return_value = {"is_verified": True, "proxy_type": None}
        fake_response.raise_for_status = MagicMock()
        with patch("httpx.get", return_value=fake_response):
            profile = provider.get_profile("0xAbC1234567890AbC1234567890aBc12345678901", "ethereum")
        self.assertTrue(profile.is_verified)
        self.assertEqual(profile.data_source, "blockscout")

    def test_404_means_not_verified(self):
        provider = BlockscoutContractDataProvider(base_url="https://eth.blockscout.com")
        fake_response = MagicMock()
        fake_response.status_code = 404
        with patch("httpx.get", return_value=fake_response):
            profile = provider.get_profile("0xAbC1234567890AbC1234567890aBc12345678901", "ethereum")
        self.assertFalse(profile.is_verified)

    def test_network_failure_degrades_to_unknown(self):
        provider = BlockscoutContractDataProvider(base_url="https://eth.blockscout.com")
        with patch("httpx.get", side_effect=ConnectionError("timeout")):
            profile = provider.get_profile("0xAbC1234567890AbC1234567890aBc12345678901", "ethereum")
        self.assertIsNone(profile.is_verified)
        self.assertEqual(profile.data_source, "blockscout_error")

    def test_malformed_address_never_reaches_the_http_call(self):
        # Regression test: `address` comes straight from
        # ActionIntent.target with no upstream format validation - this
        # used to be f-string'd directly into the request URL with
        # nothing checked at all. A malformed value must now degrade to
        # an honest "unknown" profile *without* ever calling httpx.get.
        provider = BlockscoutContractDataProvider(base_url="https://eth.blockscout.com")
        with patch("httpx.get") as mock_get:
            profile = provider.get_profile("not-an-address", "ethereum")
        mock_get.assert_not_called()
        self.assertIsNone(profile.is_verified)
        self.assertEqual(profile.data_source, "invalid_address")

    def test_wrong_length_address_is_rejected(self):
        provider = BlockscoutContractDataProvider(base_url="https://eth.blockscout.com")
        with patch("httpx.get") as mock_get:
            profile = provider.get_profile("0xabc", "ethereum")
        mock_get.assert_not_called()
        self.assertEqual(profile.data_source, "invalid_address")


class TestContractAnalyzerListPrecedence(unittest.TestCase):
    """Local lists must be checked BEFORE falling back to any provider."""

    def _lists(self, safe=None, malicious=None):
        with tempfile.TemporaryDirectory() as d:
            safe_path = Path(d) / "safe.json"
            mal_path = Path(d) / "mal.json"
            safe_path.write_text(json.dumps(safe or {}))
            mal_path.write_text(json.dumps(malicious or {}))
            return AddressList(str(safe_path)), AddressList(str(mal_path))

    def test_malicious_list_hit_short_circuits_provider(self):
        safe, malicious = self._lists(malicious={"0xbad": "known scam"})
        provider = MagicMock()
        analyzer = ContractAnalyzer(provider=provider, known_safe=safe, known_malicious=malicious)
        signals = analyzer.analyze("0xbad", "ethereum")
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].name, "known_malicious_contract")
        self.assertEqual(signals[0].score, 100)
        provider.get_profile.assert_not_called()

    def test_safe_list_hit_short_circuits_provider(self):
        safe, malicious = self._lists(safe={"0xgood": "audited, verified"})
        provider = MagicMock()
        analyzer = ContractAnalyzer(provider=provider, known_safe=safe, known_malicious=malicious)
        signals = analyzer.analyze("0xgood", "ethereum")
        self.assertEqual(signals[0].name, "known_safe_contract")
        provider.get_profile.assert_not_called()

    def test_unlisted_address_falls_back_to_provider(self):
        safe, malicious = self._lists()
        provider = MagicMock()
        provider.get_profile.return_value = MagicMock(is_verified=None, is_upgradeable=None, data_source="mock")
        analyzer = ContractAnalyzer(provider=provider, known_safe=safe, known_malicious=malicious)
        analyzer.analyze("0xunknown", "ethereum")
        provider.get_profile.assert_called_once_with("0xunknown", "ethereum")


if __name__ == "__main__":
    unittest.main()
