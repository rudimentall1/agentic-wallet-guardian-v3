"""Standalone test for GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO.

api/main.py builds its FastAPI app (and conditionally adds
CORSMiddleware) once at module import time from a process-wide config
singleton - see test_api_main.py's own docstring on this exact hazard.
This file forces a fresh rebuild under a different config by calling
guardian.config.reload_config() (refreshes the singleton from the
current environment) and then importlib.reload()-ing api.main (re-runs
its module-level setup against that fresh config) - rather than
importing api.main a second, independently-configured time, which would
just get Python's cached module and silently see none of this.

Runs in its own file so it can freely reload api.main without racing
test_api_main.py's own import of the same module in the same test
session.
"""
import importlib
import os
import unittest

from fastapi.testclient import TestClient

import api.main
from guardian.config import reload_config


class TestCorsForBrowserDemo(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO", None)
        reload_config()
        importlib.reload(api.main)

    def test_cors_headers_present_when_enabled(self):
        os.environ["GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO"] = "true"
        reload_config()
        importlib.reload(api.main)
        client = TestClient(api.main.app)

        response = client.get("/health", headers={"Origin": "https://example.com"})
        self.assertEqual(response.headers.get("access-control-allow-origin"), "*")

    def test_cors_headers_absent_by_default(self):
        os.environ.pop("GUARDIAN_ENABLE_CORS_FOR_BROWSER_DEMO", None)
        reload_config()
        importlib.reload(api.main)
        client = TestClient(api.main.app)

        response = client.get("/health", headers={"Origin": "https://example.com"})
        self.assertNotIn("access-control-allow-origin", response.headers)


if __name__ == "__main__":
    unittest.main()
