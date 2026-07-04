"""
test_client.py -- unit tests for reeflex_holds.client against a local stub
HTTP server standing in for reeflex-core.

Anti-hang discipline: every stub server binds an ephemeral port (0) on a
daemon thread; every HTTP call goes through config.timeout_seconds(), set to
a small value here so a dead-port test fails fast instead of hanging.
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_holds import client  # noqa: E402
from reeflex_holds import config  # noqa: E402

_ENV_KEYS = (
    "REEFLEX_CORE_URL",
    "REEFLEX_TOKEN",
    "REEFLEX_PRINCIPAL",
    "REEFLEX_VERIFY_SSL",
    "REEFLEX_HOLDS_TIMEOUT",
)

SAMPLE_HOLD = {
    "id": "abc123",
    "created_ts": "2026-07-04T12:00:00Z",
    "expires_ts": "2099-01-01T00:00:00Z",
    "envelope": {
        "action": {"namespace": "wordpress", "verb": "delete", "ability": "wordpress/delete-post"},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
        "magnitude": {"count": 47},
        "agent": {"id": "agent:wordpress", "on_behalf_of": "user:alice", "session_id": "sess_1"},
    },
    "envelope_hash": "deadbeefcafe",
    "rule_id": "reeflex.policy/irreversible_broad_prod",
    "status": "pending",
    "decided_by": None,
    "decided_ts": None,
    "reason": None,
    "consumed_ts": None,
}


# ---------------------------------------------------------------------------
# Stub reeflex-core HTTP server
# ---------------------------------------------------------------------------

class _StubCoreHandler(http.server.BaseHTTPRequestHandler):
    """Serves canned responses; records the last request for assertions."""

    holds_list_status: int = 200
    holds_list_body: bytes = json.dumps({"items": [], "count": 0}).encode("utf-8")
    hold_detail_status: int = 200
    hold_detail_body: bytes = b"{}"
    resolve_status: int = 200
    resolve_body: bytes = b"{}"
    healthz_status: int = 200
    healthz_body: bytes = b'{"status":"ok"}'

    last_method: str = ""
    last_path: str = ""
    last_headers: dict = {}
    last_body: bytes = b""

    def log_message(self, fmt, *args):  # noqa: A003
        pass  # suppress test noise

    def do_GET(self):  # noqa: N802
        cls = self.__class__
        cls.last_method = "GET"
        cls.last_path = self.path
        cls.last_headers = dict(self.headers.items())
        if self.path == "/healthz":
            self._send(cls.healthz_status, cls.healthz_body)
        elif self.path.startswith("/v1/holds/"):
            self._send(cls.hold_detail_status, cls.hold_detail_body)
        elif self.path.startswith("/v1/holds"):
            self._send(cls.holds_list_status, cls.holds_list_body)
        else:
            self._send(404, b'{"error":"not_found"}')

    def do_POST(self):  # noqa: N802
        cls = self.__class__
        length = int(self.headers.get("Content-Length", 0))
        body_in = self.rfile.read(length)
        cls.last_method = "POST"
        cls.last_path = self.path
        cls.last_headers = dict(self.headers.items())
        cls.last_body = body_in
        self._send(cls.resolve_status, cls.resolve_body)

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_stub_server():
    class _Handler(_StubCoreHandler):
        pass

    _Handler.last_headers = {}
    _Handler.last_method = ""
    _Handler.last_path = ""
    _Handler.last_body = b""
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, _Handler


def _stop_stub_server(server) -> None:
    server.shutdown()
    server.server_close()


class _BaseClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ["REEFLEX_HOLDS_TIMEOUT"] = "3"  # bounded -- anti-hang

        self.server, self.port, self.handler_cls = _start_stub_server()
        os.environ["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        _stop_stub_server(self.server)
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# list_holds
# ---------------------------------------------------------------------------

class TestListHolds(_BaseClientTest):
    def test_no_status_filter_sends_no_query_param(self) -> None:
        self.handler_cls.holds_list_body = json.dumps({"items": [], "count": 0}).encode("utf-8")
        result = client.list_holds()
        self.assertEqual(result, {"items": [], "count": 0})
        self.assertEqual(self.handler_cls.last_method, "GET")
        self.assertEqual(self.handler_cls.last_path, "/v1/holds")

    def test_status_filter_sent_as_query_param(self) -> None:
        self.handler_cls.holds_list_body = json.dumps({"items": [SAMPLE_HOLD], "count": 1}).encode("utf-8")
        result = client.list_holds(status="pending")
        self.assertEqual(result["count"], 1)
        self.assertEqual(self.handler_cls.last_path, "/v1/holds?status=pending")

    def test_non_2xx_raises_holds_api_error(self) -> None:
        self.handler_cls.holds_list_status = 500
        self.handler_cls.holds_list_body = json.dumps({"error": "internal_error"}).encode("utf-8")
        with self.assertRaises(client.HoldsAPIError) as ctx:
            client.list_holds()
        self.assertEqual(ctx.exception.status, 500)


# ---------------------------------------------------------------------------
# get_hold
# ---------------------------------------------------------------------------

class TestGetHold(_BaseClientTest):
    def test_happy_path_returns_hold(self) -> None:
        self.handler_cls.hold_detail_body = json.dumps(SAMPLE_HOLD).encode("utf-8")
        result = client.get_hold("abc123")
        self.assertEqual(result["id"], "abc123")
        self.assertEqual(self.handler_cls.last_path, "/v1/holds/abc123")
        self.assertEqual(self.handler_cls.last_method, "GET")

    def test_not_found_raises_holds_api_error_with_body(self) -> None:
        self.handler_cls.hold_detail_status = 404
        self.handler_cls.hold_detail_body = json.dumps(
            {"error": "not_found", "hold_id": "nope"}
        ).encode("utf-8")
        with self.assertRaises(client.HoldsAPIError) as ctx:
            client.get_hold("nope")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.body.get("error"), "not_found")

    def test_hold_id_is_url_quoted(self) -> None:
        self.handler_cls.hold_detail_body = json.dumps(SAMPLE_HOLD).encode("utf-8")
        client.get_hold("weird/id with space")
        self.assertEqual(self.handler_cls.last_path, "/v1/holds/weird%2Fid%20with%20space")


# ---------------------------------------------------------------------------
# resolve_hold -- principal split, decision validation, error passthrough
# ---------------------------------------------------------------------------

class TestResolveHold(_BaseClientTest):
    def test_happy_path_sends_principal_split_from_env(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:leo"
        resolved = dict(SAMPLE_HOLD)
        resolved.update({"status": "approved", "decided_by": "human:leo", "reason": "reviewed"})
        self.handler_cls.resolve_body = json.dumps(resolved).encode("utf-8")

        result = client.resolve_hold("abc123", "approve", reason="reviewed")

        self.assertEqual(result["status"], "approved")
        self.assertEqual(self.handler_cls.last_method, "POST")
        self.assertEqual(self.handler_cls.last_path, "/v1/holds/abc123/resolve")

        sent = json.loads(self.handler_cls.last_body.decode("utf-8"))
        self.assertEqual(sent["decision"], "approve")
        self.assertEqual(sent["principal"], {"type": "human", "id": "leo"})
        self.assertEqual(sent["reason"], "reviewed")

    def test_agent_principal_split(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "agent:triage-bot"
        self.handler_cls.resolve_body = json.dumps(SAMPLE_HOLD).encode("utf-8")
        client.resolve_hold("abc123", "reject")
        sent = json.loads(self.handler_cls.last_body.decode("utf-8"))
        self.assertEqual(sent["principal"], {"type": "agent", "id": "triage-bot"})
        self.assertNotIn("reason", sent)  # no reason given -> omitted, not null

    def test_missing_principal_raises_config_error_before_any_request(self) -> None:
        os.environ.pop("REEFLEX_PRINCIPAL", None)
        with self.assertRaises(config.ConfigError):
            client.resolve_hold("abc123", "approve")
        self.assertEqual(self.handler_cls.last_method, "", "must not have reached core at all")

    def test_invalid_decision_raises_value_error_before_any_request(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:leo"
        with self.assertRaises(ValueError):
            client.resolve_hold("abc123", "maybe")
        self.assertEqual(self.handler_cls.last_method, "", "must not have reached core at all")

    def test_core_rejection_actor_is_approver_surfaces_verbatim(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:leo"
        self.handler_cls.resolve_status = 403
        self.handler_cls.resolve_body = json.dumps({
            "error": "actor_is_approver",
            "reason": "the principal resolving the hold must not be the same as the agent that triggered it",
            "hold_id": "abc123",
        }).encode("utf-8")
        with self.assertRaises(client.HoldsAPIError) as ctx:
            client.resolve_hold("abc123", "approve")
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.body.get("error"), "actor_is_approver")


# ---------------------------------------------------------------------------
# Bearer token header
# ---------------------------------------------------------------------------

class TestBearerToken(_BaseClientTest):
    def test_token_set_adds_authorization_header(self) -> None:
        os.environ["REEFLEX_TOKEN"] = "s3cr3t-test-token"
        self.handler_cls.holds_list_body = json.dumps({"items": [], "count": 0}).encode("utf-8")
        client.list_holds()
        self.assertEqual(
            self.handler_cls.last_headers.get("Authorization"),
            "Bearer s3cr3t-test-token",
        )

    def test_token_unset_omits_authorization_header(self) -> None:
        os.environ.pop("REEFLEX_TOKEN", None)
        self.handler_cls.holds_list_body = json.dumps({"items": [], "count": 0}).encode("utf-8")
        client.list_holds()
        self.assertNotIn("Authorization", self.handler_cls.last_headers)

    def test_blank_token_omits_authorization_header(self) -> None:
        os.environ["REEFLEX_TOKEN"] = "   "
        self.handler_cls.holds_list_body = json.dumps({"items": [], "count": 0}).encode("utf-8")
        client.list_holds()
        self.assertNotIn("Authorization", self.handler_cls.last_headers)


# ---------------------------------------------------------------------------
# REEFLEX_VERIFY_SSL -- SSL context construction (unit-level, no real socket)
# ---------------------------------------------------------------------------

class TestBuildSslContext(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get("REEFLEX_VERIFY_SSL")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("REEFLEX_VERIFY_SSL", None)
        else:
            os.environ["REEFLEX_VERIFY_SSL"] = self._saved

    def test_https_with_verify_off_returns_cert_none_context(self) -> None:
        import ssl as _ssl

        os.environ["REEFLEX_VERIFY_SSL"] = "false"
        ctx = client._build_ssl_context("https://api-dev.reeflex.io")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.verify_mode, _ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_https_with_verify_on_default_returns_none(self) -> None:
        os.environ.pop("REEFLEX_VERIFY_SSL", None)
        ctx = client._build_ssl_context("https://api-dev.reeflex.io")
        self.assertIsNone(ctx)

    def test_http_target_always_returns_none(self) -> None:
        os.environ["REEFLEX_VERIFY_SSL"] = "false"
        ctx = client._build_ssl_context("http://127.0.0.1:8080")
        self.assertIsNone(ctx)


# ---------------------------------------------------------------------------
# Fail path: dead port -> HoldsConnectionError, never a hang
# ---------------------------------------------------------------------------

class TestConnectionFailure(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ["REEFLEX_HOLDS_TIMEOUT"] = "2"

    def tearDown(self) -> None:
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_dead_port_raises_holds_connection_error(self) -> None:
        # Port 1 is a privileged port -- always connection-refused on any OS.
        os.environ["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"
        with self.assertRaises(client.HoldsConnectionError):
            client.list_holds()

    def test_get_freeze_status_handles_dead_core_gracefully(self) -> None:
        """get_freeze_status must NEVER raise -- it degrades to a status dict."""
        os.environ["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"
        result = client.get_freeze_status()
        self.assertFalse(result["core_reachable"])
        self.assertEqual(result["freeze_state"], "unknown")
        self.assertIn("no dedicated freeze-status endpoint", result["note"])


# ---------------------------------------------------------------------------
# get_freeze_status -- honest best-effort framing when core IS reachable
# ---------------------------------------------------------------------------

class TestGetFreezeStatusReachable(_BaseClientTest):
    def test_healthz_ok_reports_reachable_but_freeze_state_unknown(self) -> None:
        self.handler_cls.healthz_status = 200
        self.handler_cls.healthz_body = b'{"status":"ok"}'
        result = client.get_freeze_status()
        self.assertTrue(result["core_reachable"])
        self.assertEqual(result["freeze_state"], "unknown")
        self.assertIn("no dedicated freeze-status endpoint", result["note"])
        self.assertEqual(self.handler_cls.last_path, "/healthz")

    def test_healthz_unexpected_body_reports_not_reachable(self) -> None:
        self.handler_cls.healthz_status = 200
        self.handler_cls.healthz_body = b'{"status":"degraded"}'
        result = client.get_freeze_status()
        self.assertFalse(result["core_reachable"])
        self.assertEqual(result["freeze_state"], "unknown")


if __name__ == "__main__":
    unittest.main()
