"""End-to-end test for skills/guardian-check/scripts/check.py.

This deliberately runs a *real* uvicorn server and invokes check.py as a
real subprocess making a real HTTP request over urllib - the bug this
guards against (check.py sending `X-API-Key` while the server only ever
checks `Authorization: Bearer <key>`) is exactly the kind of thing a
mocked HTTP client would hide, since a mock doesn't care what header
name you used to look up its canned response.
"""
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "skills" / "guardian-check" / "scripts" / "check.py"
API_KEY = "test-check-script-key"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestGuardianCheckScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        env = dict(os.environ)
        env["GUARDIAN_API_KEY"] = API_KEY
        env["GUARDIAN_RATE_LIMIT_PER_MINUTE"] = "100000"
        cls.server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "api.main:app",
             "--host", "127.0.0.1", "--port", str(cls.port), "--log-level", "warning"],
            cwd=str(REPO_ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls._wait_for_server_ready()

    @classmethod
    def _wait_for_server_ready(cls, timeout=15):
        import urllib.request
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{cls.base_url}/health", timeout=1)
                return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("Guardian test server did not become ready in time")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=10)

    def _run_check(self, extra_env=None, **cli_args):
        env = dict(os.environ)
        env["GUARDIAN_API_URL"] = self.base_url
        env.update(extra_env or {})
        args = [sys.executable, str(CHECK_SCRIPT)]
        for key, value in cli_args.items():
            if value is None:
                continue
            args += [f"--{key.replace('_', '-')}", str(value)]
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)

    def test_allow_decision_exits_0(self):
        result = self._run_check(
            extra_env={"GUARDIAN_API_KEY": API_KEY},
            agent_id="check-script-agent-1", wallet="0xabc", chain="ethereum",
            action_type="swap", to_token="USDC", amount=1,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_correct_auth_header_is_actually_sent(self):
        """Regression test for Finding 12: check.py used to send
        X-API-Key, which api/security.py's require_api_key never looks
        at (it only checks Authorization: Bearer <key>) - every call
        would 401 whenever the server had auth enabled, exactly the
        configuration this skill's own docs recommend. A wrong-header
        bug like this needs a real server round-trip to catch; a mocked
        HTTP client wouldn't notice which header name was used."""
        result = self._run_check(
            extra_env={"GUARDIAN_API_KEY": API_KEY},
            agent_id="check-script-agent-2", wallet="0xabc", chain="ethereum",
            action_type="swap", to_token="USDC", amount=1,
        )
        self.assertNotEqual(result.returncode, 3,
                             msg=f"got exit 3 (misconfigured/unreachable) - stderr: {result.stderr}")

    def test_missing_api_key_gets_401_and_exits_3(self):
        # Sanity check that auth is actually enforced server-side (not
        # that the script is just never sending any auth at all and
        # happening to work because the server has no key configured).
        result = self._run_check(
            extra_env={"GUARDIAN_API_KEY": ""},
            agent_id="check-script-agent-3", wallet="0xabc", chain="ethereum",
            action_type="swap", to_token="USDC", amount=1,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("401", result.stderr)

    def test_block_decision_exits_2(self):
        result = self._run_check(
            extra_env={"GUARDIAN_API_KEY": API_KEY},
            agent_id="check-script-agent-4", wallet="0xabc", chain="not-a-real-chain",
            action_type="swap", amount=1,
        )
        self.assertEqual(result.returncode, 2, msg=result.stderr)

    def test_missing_api_url_exits_3_without_a_request(self):
        env = dict(os.environ)
        env.pop("GUARDIAN_API_URL", None)
        result = subprocess.run(
            [sys.executable, str(CHECK_SCRIPT), "--agent-id", "a", "--wallet", "0xabc",
             "--action-type", "swap"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("GUARDIAN_API_URL", result.stderr)

    def test_non_http_scheme_url_is_rejected(self):
        env = dict(os.environ)
        env["GUARDIAN_API_URL"] = "file:///etc/passwd"
        result = subprocess.run(
            [sys.executable, str(CHECK_SCRIPT), "--agent-id", "a", "--wallet", "0xabc",
             "--action-type", "swap"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("http", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
