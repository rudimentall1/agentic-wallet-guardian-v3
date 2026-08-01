import unittest
from unittest.mock import MagicMock, patch

from guardian.core.intent import ActionIntent
from guardian.intelligence.simulation.engine import SimulationEngine
from guardian.intelligence.simulation.providers import (
    NullSimulationProvider,
    RpcSimulationProvider,
    _decode_approve_amount,
)

# approve(spender=0x1111...1111, amount=<value>) calldata, hand-built
SPENDER_PADDED = "0" * 24 + "1" * 40  # 32-byte padded address slot


def _approve_calldata(amount_hex_64: str) -> str:
    return "0x095ea7b3" + SPENDER_PADDED + amount_hex_64


UNLIMITED_AMOUNT = "f" * 64  # 2**256 - 1
FINITE_AMOUNT = "0" * 62 + "64"  # 100


class TestDecodeApproveAmount(unittest.TestCase):
    def test_decodes_unlimited_amount(self):
        amount = _decode_approve_amount(_approve_calldata(UNLIMITED_AMOUNT))
        self.assertEqual(amount, 2**256 - 1)

    def test_decodes_finite_amount(self):
        amount = _decode_approve_amount(_approve_calldata(FINITE_AMOUNT))
        self.assertEqual(amount, 100)

    def test_non_approve_calldata_returns_none(self):
        self.assertIsNone(_decode_approve_amount("0xa9059cbb" + "0" * 128))

    def test_truncated_calldata_returns_none(self):
        self.assertIsNone(_decode_approve_amount("0x095ea7b3" + "00"))


class TestRpcSimulationProviderNoCalldata(unittest.TestCase):
    def test_no_calldata_means_not_attempted(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum", action_type="swap", target="0xdef")
        result = provider.simulate(intent)
        self.assertFalse(result.attempted)

    def test_no_target_means_not_attempted(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(agent_id="a", wallet="0xabc", chain="ethereum", action_type="swap",
                               metadata={"data": "0x1234"})
        result = provider.simulate(intent)
        self.assertFalse(result.attempted)


class TestRpcSimulationProviderWithCalldata(unittest.TestCase):
    def _stub_web3(self):
        fake_w3 = MagicMock()
        fake_w3.to_checksum_address.side_effect = lambda a: a
        return fake_w3

    def test_successful_call_reports_no_revert(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_web3()
        fake_w3.eth.call.return_value = b""
        fake_w3.eth.estimate_gas.return_value = 21000
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="transfer", target="0xdef",
            metadata={"data": "0xa9059cbb" + "0" * 128},
        )
        with patch.object(provider, "_client", return_value=fake_w3):
            result = provider.simulate(intent)
        self.assertTrue(result.attempted)
        self.assertFalse(result.would_revert)
        self.assertEqual(result.gas_estimate, 21000)

    def test_revert_is_captured_with_reason(self):
        from web3.exceptions import ContractLogicError

        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_web3()
        fake_w3.eth.call.side_effect = ContractLogicError("execution reverted: insufficient balance")
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="transfer", target="0xdef",
            metadata={"data": "0xa9059cbb" + "0" * 128},
        )
        with patch.object(provider, "_client", return_value=fake_w3):
            result = provider.simulate(intent)
        self.assertTrue(result.attempted)
        self.assertTrue(result.would_revert)
        self.assertIn("insufficient balance", result.revert_reason)

    def test_unlimited_approval_detected_on_success(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_web3()
        fake_w3.eth.call.return_value = b""
        fake_w3.eth.estimate_gas.return_value = 45000
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="approve", target="0xdef",
            metadata={"data": _approve_calldata(UNLIMITED_AMOUNT)},
        )
        with patch.object(provider, "_client", return_value=fake_w3):
            result = provider.simulate(intent)
        self.assertTrue(result.is_unlimited_approval)

    def test_finite_approval_not_flagged_as_unlimited(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        fake_w3 = self._stub_web3()
        fake_w3.eth.call.return_value = b""
        fake_w3.eth.estimate_gas.return_value = 45000
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="approve", target="0xdef",
            metadata={"data": _approve_calldata(FINITE_AMOUNT)},
        )
        with patch.object(provider, "_client", return_value=fake_w3):
            result = provider.simulate(intent)
        self.assertFalse(result.is_unlimited_approval)
        self.assertEqual(result.decoded_approval_amount, 100)

    def test_rpc_failure_degrades_to_not_attempted(self):
        provider = RpcSimulationProvider(rpc_urls={"ethereum": "http://fake"})
        intent = ActionIntent(
            agent_id="a", wallet="0xabc", chain="ethereum", action_type="transfer", target="0xdef",
            metadata={"data": "0xa9059cbb" + "0" * 128},
        )
        with patch.object(provider, "_client", side_effect=ConnectionError("node unreachable")):
            result = provider.simulate(intent)
        self.assertFalse(result.attempted)
        self.assertIsNotNone(result.error)


class TestSimulationEngineSignals(unittest.TestCase):
    def test_default_null_provider_uses_semantic_fallback(self):
        engine = SimulationEngine()  # no provider -> NullSimulationProvider
        intent = ActionIntent(agent_id="a", wallet="0xabc", action_type="approve", amount=None)
        signals = engine.simulate(intent)
        self.assertEqual(signals[0].name, "unlimited_approval_suspected")

    def test_revert_produces_critical_signal_and_stops(self):
        provider = MagicMock()
        from guardian.intelligence.simulation.providers import SimulationResult
        provider.simulate.return_value = SimulationResult(attempted=True, would_revert=True, revert_reason="boom")
        engine = SimulationEngine(provider)
        intent = ActionIntent(agent_id="a", wallet="0xabc", action_type="transfer", target="0xdef")
        signals = engine.simulate(intent)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].name, "simulation_reverts")
        self.assertEqual(signals[0].score, 100)

    def test_confirmed_unlimited_approval_produces_high_confidence_signal(self):
        provider = MagicMock()
        from guardian.intelligence.simulation.providers import SimulationResult
        provider.simulate.return_value = SimulationResult(
            attempted=True, would_revert=False, is_unlimited_approval=True, decoded_approval_amount=2**256 - 1,
        )
        engine = SimulationEngine(provider)
        intent = ActionIntent(agent_id="a", wallet="0xabc", action_type="approve", target="0xdef")
        signals = engine.simulate(intent)
        names = [s.name for s in signals]
        self.assertIn("unlimited_approval_confirmed", names)
        confirmed = next(s for s in signals if s.name == "unlimited_approval_confirmed")
        self.assertGreaterEqual(confirmed.confidence, 0.9)


if __name__ == "__main__":
    unittest.main()
