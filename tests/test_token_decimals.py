import unittest
from unittest.mock import MagicMock, patch

from guardian.config import GuardianConfig
from guardian.intelligence.token.decimals import (
    NullTokenDecimalsProvider,
    RpcTokenDecimalsProvider,
    build_token_decimals_provider,
)

from tests.fixtures import DUMMY_ADDRESS_1, DUMMY_ADDRESS_2

TOKEN_A = DUMMY_ADDRESS_1
TOKEN_B = DUMMY_ADDRESS_2


def _decimals_response(n: int) -> bytes:
    return n.to_bytes(32, byteorder="big")


class TestNullTokenDecimalsProvider(unittest.TestCase):
    def test_always_returns_none(self):
        provider = NullTokenDecimalsProvider()
        self.assertIsNone(provider.get_decimals(TOKEN_A, "ethereum"))


class TestRpcTokenDecimalsProvider(unittest.TestCase):
    def _stub_web3(self, decimals_return: bytes):
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.return_value = decimals_return
        return fake_w3

    def test_fetches_real_decimals_via_eth_call(self):
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(6))):
            result = provider.get_decimals(TOKEN_A, "ethereum")
        self.assertEqual(result, 6)

    def test_caches_a_successful_lookup(self):
        # decimals() can never change for a deployed ERC-20 contract - a
        # second call for the same (chain, token) must not hit the RPC
        # client again.
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(18))) as mock_client:
            first = provider.get_decimals(TOKEN_A, "ethereum")
            second = provider.get_decimals(TOKEN_A, "ethereum")
        self.assertEqual(first, 18)
        self.assertEqual(second, 18)
        mock_client.assert_called_once()

    def test_cache_is_case_insensitive_on_address(self):
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(6))) as mock_client:
            provider.get_decimals(TOKEN_A.lower(), "ethereum")
            provider.get_decimals(TOKEN_A.upper().replace("0X", "0x"), "ethereum")
        mock_client.assert_called_once()

    def test_cache_is_isolated_per_chain(self):
        # Same token address on two different chains is two different
        # contracts (or could be) - must not share a cache entry.
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake", "base": "http://fake2"})
        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(6))) as mock_client:
            provider.get_decimals(TOKEN_A, "ethereum")
            provider.get_decimals(TOKEN_A, "base")
        self.assertEqual(mock_client.call_count, 2)

    def test_cache_is_isolated_per_token(self):
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(6))) as mock_client:
            provider.get_decimals(TOKEN_A, "ethereum")
            provider.get_decimals(TOKEN_B, "ethereum")
        self.assertEqual(mock_client.call_count, 2)

    def test_a_failed_lookup_is_not_cached(self):
        # A transient RPC/network failure today shouldn't permanently
        # poison the cache - only a genuine successful on-chain read
        # (which can never change) earns a permanent entry.
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client", side_effect=ConnectionError("timeout")):
            first = provider.get_decimals(TOKEN_A, "ethereum")
        self.assertIsNone(first)

        with patch.object(provider, "_client", return_value=self._stub_web3(_decimals_response(6))):
            second = provider.get_decimals(TOKEN_A, "ethereum")
        self.assertEqual(second, 6)

    def test_missing_rpc_url_for_chain_returns_none(self):
        provider = RpcTokenDecimalsProvider(rpc_urls={})
        self.assertIsNone(provider.get_decimals(TOKEN_A, "ethereum"))

    def test_empty_token_address_returns_none_without_any_rpc_call(self):
        provider = RpcTokenDecimalsProvider(rpc_urls={"ethereum": "http://fake"})
        with patch.object(provider, "_client") as mock_client:
            result = provider.get_decimals("", "ethereum")
        mock_client.assert_not_called()
        self.assertIsNone(result)


class TestBuildTokenDecimalsProvider(unittest.TestCase):
    def test_default_is_null(self):
        config = GuardianConfig()
        provider = build_token_decimals_provider(config)
        self.assertIsInstance(provider, NullTokenDecimalsProvider)

    def test_rpc_when_configured(self):
        config = GuardianConfig(decimals_provider="rpc", rpc_urls={"ethereum": "http://fake"})
        provider = build_token_decimals_provider(config)
        self.assertIsInstance(provider, RpcTokenDecimalsProvider)


if __name__ == "__main__":
    unittest.main()
