import unittest
from unittest.mock import MagicMock, patch

from guardian.core.intent import ActionIntent
from guardian.decision.engine import DecisionEngine
from guardian.intelligence.simulation.tx_builder import (
    APPROVE_SELECTOR,
    RpcTransactionBuilder,
    SWAP_EXACT_TOKENS_SELECTOR,
    TRANSFER_SELECTOR,
    UNLIMITED_APPROVAL,
    _encode_address_param,
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

    def test_non_transfer_approve_swap_action_types_are_ignored(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum",
                               action_type="bridge", target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=100)
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

            # Regression guard: simulation must dry-run against the TOKEN
            # CONTRACT (from_token), not the recipient (target) encoded
            # inside the calldata. Sending eth_call to an EOA recipient
            # with ERC-20 calldata silently "succeeds" (no revert) every
            # time, which would make this whole test pass for the wrong
            # reason - it only actually blocks here because the mock is
            # configured to reject regardless of "to". This assertion is
            # what would have caught it before it shipped.
            sim_call_kwargs = fake_w3.eth.call.call_args_list[1][0][0]
            self.assertEqual(sim_call_kwargs["to"], TOKEN_ADDRESS)
        finally:
            for var in ("GUARDIAN_TX_BUILDER", "GUARDIAN_SIMULATION_PROVIDER", "GUARDIAN_RPC_ETHEREUM"):
                os.environ.pop(var, None)
            from guardian.config import reload_config
            reload_config()

    def test_approve_simulates_against_token_contract_not_spender(self):
        import os
        os.environ["GUARDIAN_TX_BUILDER"] = "rpc"
        os.environ["GUARDIAN_SIMULATION_PROVIDER"] = "rpc"
        os.environ["GUARDIAN_RPC_ETHEREUM"] = "http://fake"
        try:
            from guardian.config import reload_config
            config = reload_config()
            engine = DecisionEngine(config=config)

            fake_w3 = MagicMock()
            fake_w3.to_checksum_address.side_effect = lambda a: a
            fake_w3.eth.call.side_effect = [_decimals_response(18), b""]

            with patch.object(engine.tx_builder, "_client", return_value=fake_w3), \
                 patch.object(engine.simulation_engine.provider, "_client", return_value=fake_w3):
                intent = ActionIntent(
                    agent_id="a", wallet="0xabc", chain="ethereum", action_type="approve",
                    target=RECIPIENT, from_token=TOKEN_ADDRESS, amount=50,
                )
                engine.evaluate(intent)

            sim_call_kwargs = fake_w3.eth.call.call_args_list[1][0][0]
            self.assertEqual(sim_call_kwargs["to"], TOKEN_ADDRESS)
            self.assertNotEqual(sim_call_kwargs["to"], RECIPIENT)
        finally:
            for var in ("GUARDIAN_TX_BUILDER", "GUARDIAN_SIMULATION_PROVIDER", "GUARDIAN_RPC_ETHEREUM"):
                os.environ.pop(var, None)
            from guardian.config import reload_config
            reload_config()

    def test_native_transfer_simulates_against_recipient(self):
        # The one case where target IS the correct "to": a plain native
        # transfer has no separate contract - the recipient IS what you're
        # calling.
        import os
        os.environ["GUARDIAN_TX_BUILDER"] = "rpc"
        os.environ["GUARDIAN_SIMULATION_PROVIDER"] = "rpc"
        os.environ["GUARDIAN_RPC_ETHEREUM"] = "http://fake"
        try:
            from guardian.config import reload_config
            config = reload_config()
            engine = DecisionEngine(config=config)

            fake_w3 = MagicMock()
            fake_w3.to_checksum_address.side_effect = lambda a: a
            fake_w3.eth.call.side_effect = [b""]

            with patch.object(engine.tx_builder, "_client", return_value=fake_w3), \
                 patch.object(engine.simulation_engine.provider, "_client", return_value=fake_w3):
                intent = ActionIntent(
                    agent_id="a", wallet="0xabc", chain="ethereum", action_type="transfer",
                    target=RECIPIENT, amount=1,  # no from_token -> native
                )
                engine.evaluate(intent)

            sim_call_kwargs = fake_w3.eth.call.call_args_list[0][0][0]
            self.assertEqual(sim_call_kwargs["to"], RECIPIENT)
        finally:
            for var in ("GUARDIAN_TX_BUILDER", "GUARDIAN_SIMULATION_PROVIDER", "GUARDIAN_RPC_ETHEREUM"):
                os.environ.pop(var, None)
            from guardian.config import reload_config
            reload_config()


class TestRpcTransactionBuilderSwap(unittest.TestCase):
    FROM_TOKEN = TOKEN_ADDRESS
    TO_TOKEN = RECIPIENT  # reusing a valid-looking address as a stand-in "token"
    ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"

    def _stub_w3_for_swap(self, decimals: int, amount_out: int):
        """First eth_call = decimals() lookup, second = getAmountsOut()."""
        amounts_out_response = (
            _encode_uint256(0x20)      # offset to array data
            + _encode_uint256(2)        # array length: [amountIn, amountOut]
            + _encode_uint256(0)        # amounts[0] = amountIn (irrelevant to the code path)
            + _encode_uint256(amount_out)  # amounts[1] = amountOut - the one we read
        )
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.side_effect = [
            _decimals_response(decimals),
            bytes.fromhex(amounts_out_response),
        ]
        return fake_w3

    def _swap_intent(self, amount=100, max_slippage_bps=50, wallet="0x" + "9" * 40, recipient=None, metadata_extra=None):
        metadata = {"max_slippage_bps": max_slippage_bps}
        if recipient is not None:
            metadata["recipient"] = recipient
        if metadata_extra:
            metadata.update(metadata_extra)
        return ActionIntent(
            agent_id="a", wallet=wallet, chain="ethereum", action_type="swap",
            from_token=self.FROM_TOKEN, to_token=self.TO_TOKEN, amount=amount,
            metadata=metadata,
        )

    def test_happy_path_builds_correct_selector_and_min_amount_out(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_w3_for_swap(decimals=18, amount_out=1_000_000)
        intent = self._swap_intent(amount=1, max_slippage_bps=100)  # 1% slippage

        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)

        self.assertIsNotNone(result)
        self.assertTrue(result.data.startswith(f"0x{SWAP_EXACT_TOKENS_SELECTOR}"))
        # amountOutMin = 1_000_000 * (10000-100)/10000 = 990_000
        expected_min_out = _encode_uint256(990_000)
        # head layout: amountIn(32) amountOutMin(32) offset(32) to(32) deadline(32)
        head = result.data[2 + 8:2 + 8 + 5 * 64]
        self.assertEqual(head[64:128], expected_min_out)

    def test_missing_slippage_refuses_to_guess(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="swap",
            from_token=self.FROM_TOKEN, to_token=self.TO_TOKEN, amount=1,
            metadata={},  # no max_slippage_bps
        )
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)

    def test_out_of_range_slippage_rejected(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = self._swap_intent(max_slippage_bps=10_001)
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)

    def test_bare_symbol_tokens_not_guessed(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="swap",
            from_token="USDC", to_token="WETH", amount=1,
            metadata={"max_slippage_bps": 50},
        )
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)

    def test_unknown_chain_has_no_router_and_is_not_guessed(self):
        builder = RpcTransactionBuilder(rpc_urls={"some-l2": "http://fake"})
        intent = self._swap_intent()
        intent.chain = "some-l2"
        with patch.object(builder, "_client") as mock_client:
            result = builder.build(intent)
        mock_client.assert_not_called()
        self.assertIsNone(result)

    def test_quote_failure_means_no_calldata(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        fake_w3.eth.call.side_effect = [
            _decimals_response(18),
            Exception("execution reverted: INSUFFICIENT_LIQUIDITY"),
        ]
        intent = self._swap_intent()
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        self.assertIsNone(result)

    def test_recipient_defaults_to_wallet_when_not_specified(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_w3_for_swap(decimals=18, amount_out=1_000_000)
        wallet = "0x" + "7" * 40
        intent = self._swap_intent(wallet=wallet)

        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)

        head = result.data[2 + 8:2 + 8 + 5 * 64]
        to_field = head[192:256]  # 4th head word
        self.assertEqual(to_field, _encode_address_param(wallet))

    def test_invalid_recipient_address_rejected(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_w3_for_swap(decimals=18, amount_out=1_000_000)
        intent = self._swap_intent(recipient="not-an-address")
        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)
        self.assertIsNone(result)

    def test_path_tail_encodes_both_tokens_in_order(self):
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_w3_for_swap(decimals=18, amount_out=1_000_000)
        intent = self._swap_intent()

        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)

        tail = result.data[2 + 8 + 5 * 64:]
        length = int(tail[:64], 16)
        self.assertEqual(length, 2)
        addr0 = tail[64:128]
        addr1 = tail[128:192]
        self.assertEqual(addr0, _encode_address_param(self.FROM_TOKEN))
        self.assertEqual(addr1, _encode_address_param(self.TO_TOKEN))

    def test_built_swap_transaction_targets_the_router(self):
        # Same regression class as the transfer/approve fix: `to` must be
        # the ROUTER (what actually executes the swap), not intent.target
        # (unset/irrelevant for swaps) and not from_token/to_token.
        builder = RpcTransactionBuilder(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_w3_for_swap(decimals=18, amount_out=1_000_000)
        intent = self._swap_intent()

        with patch.object(builder, "_client", return_value=fake_w3):
            result = builder.build(intent)

        self.assertEqual(result.to, self.ROUTER)


if __name__ == "__main__":
    unittest.main()
