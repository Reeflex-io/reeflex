"""
test_auth.py — HTTP-layer bearer-token auth tests for reeflex-core.

Starts the REAL server (_DecideHandler) on an ephemeral port in a background
daemon thread and exercises the five auth cases via urllib.request.

Cases:
  AUTH_OFF_NO_HEADER     env unset + no Authorization -> HTTP 200 with decision
  AUTH_ON_CORRECT_TOKEN  env set   + correct Bearer   -> HTTP 200 with decision
  AUTH_ON_NO_HEADER      env set   + no Authorization -> HTTP 401, body={"error":"unauthorized"},
                         WWW-Authenticate header present, no decision:allow leaked
  AUTH_ON_WRONG_TOKEN    env set   + wrong Bearer     -> HTTP 401
  AUTH_ON_HEALTHZ_EXEMPT env set   + GET /healthz (no token) -> HTTP 200

Run:
  cd reeflex-core
  python -m unittest tests.test_auth -v
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid

# Make app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.server import _DecideHandler

# ---------------------------------------------------------------------------
# Test fixture token — obvious throwaway value, NOT a real secret
# ---------------------------------------------------------------------------

TEST_TOKEN = "reeflex-test-token-not-a-secret"


# ---------------------------------------------------------------------------
# Minimal valid ActionEnvelope (read-only / reversible / single / internal)
# ---------------------------------------------------------------------------

def _minimal_envelope() -> dict:
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:auth-test-runner",
            "on_behalf_of": "user:synthetic",
            "session_id": f"auth_test_{uuid.uuid4().hex[:12]}",
        },
        "action": {
            "namespace": "test",
            "verb": "read",
            "ability": "test/read",
        },
        "target": {
            "kind": "entity",
            "ref": None,
            "environment": "staging",
        },
        "params": {},
        "magnitude": {"count": 1},
        "axes": {
            "reversibility": "reversible",
            "blast_radius": "single",
            "externality": "internal",
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-06-29T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


# ---------------------------------------------------------------------------
# Shared server lifecycle — one instance for the whole test class
# ---------------------------------------------------------------------------

class TestBearerAuth(unittest.TestCase):
    """Auth tests against the real _DecideHandler on an ephemeral port."""

    _srv: http.server.HTTPServer
    _base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        # Bind to 127.0.0.1:0 so the OS assigns a free ephemeral port
        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        port = cls._srv.server_address[1]
        cls._base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        t.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()

    def tearDown(self) -> None:
        # Ensure REEFLEX_AUTH_TOKEN never bleeds from one test into the next
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _post_decide(
        self,
        *,
        auth_header: str | None = None,
    ) -> tuple[int, dict, http.client.HTTPResponse]:
        """POST /v1/decide with a fresh minimal envelope.

        Returns (status_code, parsed_body, raw_response).
        On HTTP 4xx/5xx, urllib raises HTTPError; we catch it and return
        the error response so assertions can inspect it.
        """
        envelope = _minimal_envelope()
        payload = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base_url}/v1/decide",
            data=payload,
            method="POST",
        )
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", str(len(payload)))
        if auth_header is not None:
            req.add_header("Authorization", auth_header)

        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body, resp
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode("utf-8"))
            return exc.code, body, exc

    # ------------------------------------------------------------------
    # Case 1: AUTH OFF (env unset) — no Authorization header -> HTTP 200
    # ------------------------------------------------------------------

    def test_auth_off_no_header_returns_200(self) -> None:
        """AUTH OFF: env unset + no Authorization -> HTTP 200 with a decision key."""
        # REEFLEX_AUTH_TOKEN is absent (tearDown cleaned it; setUpClass didn't set it)
        self.assertNotIn("REEFLEX_AUTH_TOKEN", os.environ)

        status, body, _ = self._post_decide(auth_header=None)

        print(f"\n[T_auth/off_no_header] status={status} body={json.dumps(body)}")

        self.assertEqual(status, 200, f"expected 200 when auth disabled, got {status}: {body}")
        self.assertIn("decision", body, f"response must contain 'decision' key: {body}")

    # ------------------------------------------------------------------
    # Case 2: AUTH ON — correct token -> HTTP 200
    # ------------------------------------------------------------------

    def test_auth_on_correct_token_returns_200(self) -> None:
        """AUTH ON: correct Bearer token -> HTTP 200 with a decision key."""
        os.environ["REEFLEX_AUTH_TOKEN"] = TEST_TOKEN

        status, body, _ = self._post_decide(auth_header=f"Bearer {TEST_TOKEN}")

        print(f"\n[T_auth/on_correct] status={status} body={json.dumps(body)}")

        self.assertEqual(status, 200, f"expected 200 with correct token, got {status}: {body}")
        self.assertIn("decision", body, f"response must contain 'decision' key: {body}")

    # ------------------------------------------------------------------
    # Case 3: AUTH ON — no Authorization header -> HTTP 401
    # ------------------------------------------------------------------

    def test_auth_on_no_header_returns_401(self) -> None:
        """AUTH ON: no Authorization header -> HTTP 401 with correct body and header."""
        os.environ["REEFLEX_AUTH_TOKEN"] = TEST_TOKEN

        status, body, raw = self._post_decide(auth_header=None)

        print(f"\n[T_auth/on_no_header] status={status} body={json.dumps(body)}")

        self.assertEqual(status, 401, f"expected 401 with no token, got {status}: {body}")
        self.assertEqual(
            body, {"error": "unauthorized"},
            f"body must be exactly {{\"error\":\"unauthorized\"}}, got: {body}",
        )
        # WWW-Authenticate header must be present
        www_auth = raw.headers.get("WWW-Authenticate") if hasattr(raw, "headers") else None
        self.assertIsNotNone(
            www_auth,
            "WWW-Authenticate response header must be present on 401",
        )
        # No decision:allow must be leaked
        self.assertNotEqual(
            body.get("decision"), "allow",
            "FAIL-CLOSED VIOLATION: 401 response must not contain decision:allow",
        )

    # ------------------------------------------------------------------
    # Case 4: AUTH ON — wrong token -> HTTP 401
    # ------------------------------------------------------------------

    def test_auth_on_wrong_token_returns_401(self) -> None:
        """AUTH ON: wrong Bearer token -> HTTP 401."""
        os.environ["REEFLEX_AUTH_TOKEN"] = TEST_TOKEN

        status, body, _ = self._post_decide(auth_header="Bearer wrong-token-xyz")

        print(f"\n[T_auth/on_wrong_token] status={status} body={json.dumps(body)}")

        self.assertEqual(status, 401, f"expected 401 with wrong token, got {status}: {body}")
        self.assertEqual(
            body, {"error": "unauthorized"},
            f"body must be exactly {{\"error\":\"unauthorized\"}}, got: {body}",
        )

    # ------------------------------------------------------------------
    # Case 5: AUTH ON — GET /healthz without token -> HTTP 200
    # ------------------------------------------------------------------

    def test_auth_on_healthz_exempt(self) -> None:
        """AUTH ON: GET /healthz without any token -> HTTP 200 (health exempt)."""
        os.environ["REEFLEX_AUTH_TOKEN"] = TEST_TOKEN

        req = urllib.request.Request(
            f"{self._base_url}/healthz",
            method="GET",
        )
        # No Authorization header — intentional

        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = json.loads(exc.read().decode("utf-8"))

        print(f"\n[T_auth/healthz_exempt] status={status} body={json.dumps(body)}")

        self.assertEqual(status, 200, f"expected 200 for /healthz regardless of auth, got {status}: {body}")
        self.assertEqual(body.get("status"), "ok", f"healthz body must be {{status:ok}}: {body}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
