"""Tests for GoPlus-backed providers.

IMPORTANT ABOUT WHAT THESE TESTS PROVE: they mock ``httpx.get``, so they
verify that this codebase correctly *parses* a GoPlus-shaped response into
the right profile fields and Signals - they do NOT prove the GoPlus API is
reachable, that its schema hasn't changed, or that a live lookup for a
real address returns what you'd expect. That can only be verified by an
operator with real network access running against the live API. Treat a
green run here as "the parsing logic is correct given the documented
response shape", not as "this is proven to work in production".
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from guardian.intelligence import goplus_client
from guardian.intelligence.contract.analyzer import ContractAnalyzer
from guardian.intelligence.contract.providers import GoPlusContractDataProvider
from guardian.intelligence.token.analyzer import TokenAnalyzer
from guardian.intelligence.token.providers import GoPlusTokenDataProvider

GOOD_ADDRESS = "0x111111111111111111111111111111111111aaaa"


def _mock_response(payload: dict, status_ok: bool = True):
    resp = MagicMock()
    resp.json.return_value = payload
    if status_ok:
        resp.raise_for_status.return_value = None
    else:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    return resp


class TestGoPlusClient(unittest.TestCase):
    def setUp(self):
        goplus_client.clear_cache()

    def test_unsupported_chain_returns_none_without_a_network_call(self):
        with patch("httpx.get") as mock_get:
            result = goplus_client.get_token_security("solana", GOOD_ADDRESS)
        self.assertIsNone(result)
        mock_get.assert_not_called()

    def test_successful_response_is_parsed(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_open_source": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            result = goplus_client.get_token_security("ethereum", GOOD_ADDRESS)
        self.assertEqual(result, {"is_open_source": "1"})

    def test_non_success_code_returns_none(self):
        payload = {"code": 0, "message": "error"}
        with patch("httpx.get", return_value=_mock_response(payload)):
            result = goplus_client.get_token_security("ethereum", GOOD_ADDRESS)
        self.assertIsNone(result)

    def test_network_failure_returns_none_instead_of_raising(self):
        with patch("httpx.get", side_effect=Exception("boom")):
            result = goplus_client.get_token_security("ethereum", GOOD_ADDRESS)
        self.assertIsNone(result)

    def test_result_is_cached_between_calls(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_open_source": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)) as mock_get:
            goplus_client.get_token_security("ethereum", GOOD_ADDRESS)
            goplus_client.get_token_security("ethereum", GOOD_ADDRESS)
        self.assertEqual(mock_get.call_count, 1)

    def test_api_key_sent_as_bearer_token_when_provided(self):
        payload = {"code": 1, "message": "ok", "result": {}}
        with patch("httpx.get", return_value=_mock_response(payload)) as mock_get:
            goplus_client.get_token_security("ethereum", GOOD_ADDRESS, api_key="secret123")
        self.assertEqual(mock_get.call_args.kwargs["headers"]["Authorization"], "Bearer secret123")


class TestContractAnalyzerWithGoPlus(unittest.TestCase):
    def setUp(self):
        goplus_client.clear_cache()
        self.analyzer = ContractAnalyzer(provider=GoPlusContractDataProvider())

    def test_owner_can_change_balance_is_flagged(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {
            "is_open_source": "1", "owner_change_balance": "1",
        }}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "owner_can_change_balances" and s.score >= 80 for s in signals))

    def test_selfdestruct_is_flagged(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {
            "is_open_source": "1", "selfdestruct": "1",
        }}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "has_selfdestruct" for s in signals))

    def test_clean_verified_contract_has_no_high_severity_signals(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_open_source": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(all(s.score < 40 for s in signals))

    def test_missing_data_produces_low_confidence_signal_not_a_crash(self):
        with patch("httpx.get", side_effect=Exception("boom")):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].name, "verification_status_unknown")
        self.assertLess(signals[0].confidence, 0.5)

    def test_local_denylist_still_short_circuits_before_goplus(self):
        from guardian.intelligence.threat.blocklist import AddressList
        import tempfile, json
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "mal.json"
            path.write_text(json.dumps({GOOD_ADDRESS: "test entry"}))
            analyzer = ContractAnalyzer(
                provider=GoPlusContractDataProvider(),
                known_malicious=AddressList(str(path)),
            )
            with patch("httpx.get") as mock_get:
                signals = analyzer.analyze(GOOD_ADDRESS, "ethereum")
            mock_get.assert_not_called()
            self.assertEqual(signals[0].name, "known_malicious_contract")


class TestTokenAnalyzerWithGoPlus(unittest.TestCase):
    def setUp(self):
        goplus_client.clear_cache()
        self.analyzer = TokenAnalyzer(provider=GoPlusTokenDataProvider())

    def test_major_symbol_never_calls_the_api(self):
        with patch("httpx.get") as mock_get:
            signals = self.analyzer.analyze("USDC", "ethereum")
        mock_get.assert_not_called()
        self.assertEqual(signals[0].name, "major_token")

    def test_bare_unresolvable_symbol_is_honest_about_not_knowing(self):
        with patch("httpx.get") as mock_get:
            signals = self.analyzer.analyze("SOMECOIN", "ethereum")
        mock_get.assert_not_called()  # can't look up a bare symbol at all
        self.assertEqual(signals[0].name, "token_match_uncertain")

    def test_honeypot_address_is_maximum_risk(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_honeypot": "1", "is_in_dex": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "honeypot" and s.score == 100 for s in signals))

    def test_high_sell_tax_is_flagged(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"sell_tax": "0.35", "is_in_dex": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "high_sell_tax" for s in signals))

    def test_holder_concentration_is_detected(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {
            "is_in_dex": "1",
            "holders": [{"address": "0xwhale", "percent": "0.42", "is_locked": "0"}],
        }}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "holder_concentration" for s in signals))

    def test_locked_holder_not_counted_toward_concentration(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {
            "is_in_dex": "1",
            "holders": [{"address": "0xlocked", "percent": "0.90", "is_locked": "1"}],
        }}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertFalse(any(s.name == "holder_concentration" for s in signals))

    def test_no_dex_liquidity_is_flagged(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_in_dex": "0"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertTrue(any(s.name == "no_dex_liquidity" for s in signals))

    def test_trust_listed_token_short_circuits_to_low_risk(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {
            "trust_list": "1", "is_honeypot": "1",  # trust_list should win even if other fields look bad
        }}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].name, "trusted_listed_token")

    def test_clean_token_with_dex_liquidity_has_no_risk_indicators(self):
        payload = {"code": 1, "message": "ok", "result": {GOOD_ADDRESS: {"is_in_dex": "1"}}}
        with patch("httpx.get", return_value=_mock_response(payload)):
            signals = self.analyzer.analyze(GOOD_ADDRESS, "ethereum")
        self.assertEqual(signals[0].name, "no_token_risk_indicators")


if __name__ == "__main__":
    unittest.main()
