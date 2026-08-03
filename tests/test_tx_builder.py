import unittest
from unittest.mock import MagicMock, patch

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.intelligence.simulation.tx_builder import (
    APPROVE_SELECTOR,
    RpcTransactionBuilder,
    TRANSFER_SELECTOR,
    UNLIMITED_APPROVAL,
    _encode_uint256,
)

from tests.fixtures import DUMMY_ADDRESS_1, DUMMY_ADDRESS_2

TOKEN_ADDRESS = DUMMY_ADDRESS_1
RECIPIENT = DUMMY_ADDRESS_2


def _decimals_response(n: int) -> bytes:
    return n.to_bytes(32, byteorder="big")


class TestRpcTransactionBuilderTransfer(unittest.TestCase):
    def _stub_web3(self, decimals_return: bytes):
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.return_value = decimals_return
        return fake_w3

    def test_native_transfer_needs_no_rpc_call(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="transfer", target=RECIPIENT, amount=1.5)
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertEqual(result.data, "0x")
        self.assertEqual(result.value, int(1.5 * 10**18))

    def test_erc20_transfer_uses_real_decimals(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_web3(_decimals_response(6))  # USDC-style 6 decimals
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="transfer", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=100)
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        self.assertTrue(result.data.startswith(f"0x{TRANSFER_SELECTOR}"))
        # 100 * 10^6 = 100000000, encoded as the last 64 hex chars
        self.assertEqual(result.data[-64:], _encode_uint256(100_000_000))

    def test_wrong_decimals_would_scale_incorrectly_so_18_vs_6_must_differ(self):
        """Guards against a regression where decimals is ignored/hardcoded -
        the whole point of fetching it for real."""
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="transfer", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=1)

        with patch.object(builder, "_client", return_value=self._stub_web3(_decimals_response(18))):
            result_18 = builder.build(intent)
        with patch.object(builder, "_client", return_value=self._stub_web3(_decimals_response(6))):
            result_6 = builder.build(intent)

        self.assertNotEqual(result_18.data, result_6.data)

    def test_bare_symbol_is_not_guessed_at(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="transfer", target=RECIPIENT, from_token="USDC", amount=100)
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)

    def test_decimals_lookup_failure_means_no_calldata_not_a_guess(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.side_effect = Exception("node error")
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="transfer", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=100)
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        self.assertIsNone(result)

    def test_non_transfer_approve_action_types_are_ignored(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="swap", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=100)
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)


class TestRpcTransactionBuilderApprove(unittest.TestCase):
    def test_unlimited_approval_when_amount_is_none(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="approve", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=None)
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        fake_w3.eth.call.assert_not_called()  # no decimals lookup needed for an unlimited approval
        self.assertEqual(result.data[-64:], _encode_uint256(UNLIMITED_APPROVAL))

    def test_finite_approval_uses_real_decimals(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.return_value = _decimals_response(18)
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="approve", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=2)
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        self.assertTrue(result.data.startswith(f"0x{APPROVE_SELECTOR}"))
        self.assertEqual(result.data[-64:], _encode_uint256(2 * 10**18))


class TestTransactionBuilderIntegratedIntoDecisionEngine(unittest.TestCase):
    """The whole point: a semantic intent with no calldata should get real
    calldata built automatically, which the simulation engine can then
    actually dry-run - closing the loop end to end."""

    def test_built_calldata_flows_into_simulation(self):
        import os
        from web3.exceptions import ContractLogicError

        os.environ["GUARDIAN_TX_BUILDER"] = "rpc"
        os.environ["GUARDIAN_SIMULATION_PROVIDER"] = "rpc"
        os.environ["GUARDIAN_RPC_ETHEREUM"] = "http://fake"
        try:
            from guardian.config import reload_config
            config = reload_config()
            engine = DecisionEngine(config=config)

            fake_w3 = MagicMock()
            fake_w3.to_checksum_address.side_effect = lambda a: a
            fake_w3.eth.call.side_effect = [
                _decimals_response(18),  # tx_builder's decimals() lookup
                ContractLogicError("execution reverted: insufficient balance"),  # simulation's eth_call
            ]

            with patch.object(engine.tx_builder, "_client", return_value=fake_w3), \
                 patch.object(engine.simulation_engine.provider, "_client", return_value=fake_w3):
                intent = ActionIntent(
                    agent_id="a", wallet="0xabc", chain="ethereum", action_type="transfer",
                    target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=100,
                )
                decision = engine.evaluate(intent)

            self.assertEqual(decision.decision.value, "BLOCK")
            self.assertTrue(any("revert" in line.lower() for line in decision.explanation))
            # The caller's original intent must be untouched.
            self.assertNotIn("data", intent.metadata)
        finally:
            for var in ("GUARDIAN_TX_BUILDER", "GUARDIAN_SIMULATION_PROVIDER", "GUARDIAN_RPC_ETHEREUM"):
                os.environ.pop(var, None)
            from guardian.config import reload_config
            reload_config()


if __name__ == "__main__":
    unittest.main()
