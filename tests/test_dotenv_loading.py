import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestDotenvAutoloading(unittest.TestCase):
    """Regression test for a real bug: .env.example told people to copy it
    to .env, but nothing ever actually loaded that file - config.py only
    read real process environment variables. Runs in a fresh subprocess
    so it exercises the actual module-import-time load_dotenv() call,
    not an already-loaded guardian.config module from a previous test."""

    def test_dot_env_file_is_actually_loaded(self):
        repo_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as d:
            env_path = Path(d) / ".env"
            env_path.write_text("GUARDIAN_CONTRACT_PROVIDER=goplus\nGUARDIAN_TOKEN_PROVIDER=goplus\n")

            result = subprocess.run(
                [sys.executable, "-c",
                 "from guardian.config import get_config; c = get_config(); "
                 "print(c.contract_provider, c.token_provider)"],
                cwd=str(d),
                env={**os.environ, "PYTHONPATH": str(repo_root)},
                capture_output=True, text=True, timeout=15,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "goplus goplus")


if __name__ == "__main__":
    unittest.main()
