"""
test_core_client.py -- unit tests for reeflex_mcp.core_client against a local
stub HTTP server standing in for reeflex-core.

Anti-hang discipline: the stub server binds an ephemeral port (0) on a daemon
thread; every HTTP call goes through config.core_timeout_seconds(), set to a
small value here so a dead-port test fails fast instead of hanging (same
idiom as reeflex-holds/tests/test_client.py).
"""

from __future__ import annotations

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from reeflex_mcp import core_client

_ENV_KEYS = ("REEFLEX_CORE_URL", "REEFLEX_CORE_TOKEN", "REEFLEX_VERIFY_SSL", "REEFLEX_MCP_TIMEOUT")


class _StubCoreHandler(BaseHTTPRequestHandler):
    decide_status: int = 200
    decide_body: bytes = json.dumps(
        {"decision": "allow", "reason": "ok", "rule": "reeflex.policy/test", "obligations": []}
    ).encode("utf-8")
    healthz_status: int = 200
    healthz_body: bytes = b'{"status":"ok"}'

    last_path: str = ""
    last_headers: dict = {}
    last_body: bytes = b""

    def log_message(self, fmt, *args):  # noqa: A003 -- suppress test noise
        pass

    def do_GET(self):  # noqa: N802
        cls = self.__class__
        cls.last_path = self.path
        cls.last_headers = dict(self.headers)
        if self.path == "/healthz":
            self._respond(cls.healthz_status, cls.healthz_body)
            return
        self._respond(404, b'{"error":"not_found"}')

    def do_POST(self):  # noqa: N802
        cls = self.__class__
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        cls.last_path = self.path
        cls.last_headers = dict(self.headers)
        cls.last_body = body
        if self.path == "/v1/decide":
            self._respond(cls.decide_status, cls.decide_body)
            return
        self._respond(404, b'{"error":"not_found"}')

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StubServerCase(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

        _StubCoreHandler.decide_status = 200
        _StubCoreHandler.decide_body = json.dumps(
            {"decision": "allow", "reason": "ok", "rule": "reeflex.policy/test", "obligations": []}
        ).encode("utf-8")
        _StubCoreHandler.healthz_status = 200
        _StubCoreHandler.healthz_body = b'{"status":"ok"}'

        self.server = HTTPServer(("127.0.0.1", 0), _StubCoreHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        os.environ["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["REEFLEX_MCP_TIMEOUT"] = "2"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestDecide(_StubServerCase):
    def test_allow_roundtrip(self) -> None:
        result = core_client.decide({"action": {"verb": "read"}})
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(_StubCoreHandler.last_path, "/v1/decide")
        sent = json.loads(_StubCoreHandler.last_body.decode("utf-8"))
        self.assertEqual(sent, {"action": {"verb": "read"}})

    def test_deny_roundtrip(self) -> None:
        _StubCoreHandler.decide_body = json.dumps(
            {"decision": "deny", "reason": "nope", "rule": "reeflex.policy/x", "obligations": []}
        ).encode("utf-8")
        result = core_client.decide({"action": {"verb": "delete"}})
        self.assertEqual(result["decision"], "deny")

    def test_require_approval_roundtrip(self) -> None:
        _StubCoreHandler.decide_body = json.dumps(
            {
                "decision": "require_approval",
                "reason": "needs a human",
                "rule": "reeflex.policy/y",
                "obligations": [],
                "hold_id": "abc",
                "expires_ts": "2099-01-01T00:00:00Z",
            }
        ).encode("utf-8")
        result = core_client.decide({"action": {"verb": "delete"}})
        self.assertEqual(result["decision"], "require_approval")
        self.assertEqual(result["hold_id"], "abc")

    def test_core_500_with_decision_body_is_not_an_error(self) -> None:
        # core's own fail-closed 500 path (server.py) still carries a
        # structured {"decision": "deny", ...} body -- decide() treats that
        # as a normal Decision, matching reeflex-claude/enforce.py's behavior.
        _StubCoreHandler.decide_status = 500
        _StubCoreHandler.decide_body = json.dumps(
            {"decision": "deny", "reason": "internal error - failing closed", "rule": "reeflex.core/internal_error",
             "obligations": []}
        ).encode("utf-8")
        result = core_client.decide({"action": {"verb": "delete"}})
        self.assertEqual(result["decision"], "deny")

    def test_400_without_decision_raises_api_error(self) -> None:
        _StubCoreHandler.decide_status = 400
        _StubCoreHandler.decide_body = b'{"error":"invalid_json"}'
        with self.assertRaises(core_client.CoreAPIError):
            core_client.decide({"action": {"verb": "read"}})

    def test_bearer_token_sent_when_configured(self) -> None:
        os.environ["REEFLEX_CORE_TOKEN"] = "s3cr3t-token"
        core_client.decide({"action": {"verb": "read"}})
        self.assertEqual(_StubCoreHandler.last_headers.get("Authorization"), "Bearer s3cr3t-token")

    def test_no_auth_header_when_token_unset(self) -> None:
        core_client.decide({"action": {"verb": "read"}})
        self.assertNotIn("Authorization", _StubCoreHandler.last_headers)


class TestHealthz(_StubServerCase):
    def test_ok(self) -> None:
        self.assertTrue(core_client.healthz())

    def test_non_ok_status_returns_false(self) -> None:
        _StubCoreHandler.healthz_status = 503
        _StubCoreHandler.healthz_body = b'{"status":"degraded"}'
        self.assertFalse(core_client.healthz())


class TestUnreachable(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        # An address that refuses connections immediately (nothing bound).
        os.environ["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"
        os.environ["REEFLEX_MCP_TIMEOUT"] = "2"

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_decide_raises_connection_error_never_allow(self) -> None:
        with self.assertRaises(core_client.CoreConnectionError):
            core_client.decide({"action": {"verb": "read"}})

    def test_healthz_returns_false_not_raise(self) -> None:
        self.assertFalse(core_client.healthz())


if __name__ == "__main__":
    unittest.main()
