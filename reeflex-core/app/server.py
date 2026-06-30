"""
server.py — Minimal HTTP layer for POST /v1/decide.

Uses Python stdlib http.server only — zero external dependencies.
Binds to HOST:PORT from env REEFLEX_HOST (default 127.0.0.1) and
REEFLEX_PORT (default 8080).

Routes:
  POST /v1/decide  { ActionEnvelope } -> { Decision }   (HTTP 200 / 400 / 500)
  GET  /healthz                       -> {"status":"ok"} (HTTP 200)

All other paths/methods -> HTTP 404 or 405.

Content-Type for all responses: application/json; charset=utf-8.

Auth (optional bearer token):
  If env REEFLEX_AUTH_TOKEN is set, POST /v1/decide requires
  "Authorization: Bearer <token>"; missing or wrong token -> HTTP 401.
  If REEFLEX_AUTH_TOKEN is unset/empty, auth is disabled (backward compatible).
  GET /healthz is always unauthenticated.

Security hardening (applied to all responses):
  - Server banner suppressed to "reeflex-core" (no Python/version leakage).
  - Security headers: X-Content-Type-Options: nosniff, Cache-Control: no-store.
  - Request body size cap: 413 if Content-Length exceeds REEFLEX_MAX_BODY_BYTES
    (default 256 KB) — DoS guard.
  - Unsupported HTTP methods (PUT, DELETE, PATCH) return 405 JSON, not 501 HTML.
"""

from __future__ import annotations

import hmac
import http.server
import json
import os
import sys

from .decide import process

_MAX_BODY_BYTES = int(os.environ.get("REEFLEX_MAX_BODY_BYTES", str(256 * 1024)))


class _DecideHandler(http.server.BaseHTTPRequestHandler):

    server_version = "reeflex-core"
    sys_version = ""

    def version_string(self) -> str:  # noqa: N802
        """Return a clean server banner with no Python or BaseHTTP version leak."""
        return self.server_version

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        # Override to prefix with service name; goes to stderr
        print(f"[reeflex-core] {fmt % args}", file=sys.stderr)

    # ------------------------------------------------------------------
    # GET /healthz
    # ------------------------------------------------------------------

    def _authorized(self) -> bool:
        """Return True if the request is authorized to reach /v1/decide.

        Auth is OPTIONAL: if REEFLEX_AUTH_TOKEN is unset or empty the method
        always returns True (backward-compatible — identical to prior behavior).
        When the env var is set, the request must supply a matching bearer token
        in the Authorization header.  Comparison is constant-time to resist
        timing attacks.
        """
        expected = os.environ.get("REEFLEX_AUTH_TOKEN")
        if not expected:
            return True  # auth disabled (default) — backward compatible
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        provided = header[len(prefix):].strip()
        return hmac.compare_digest(provided, expected)

    def do_GET(self) -> None:  # noqa: N802
        # /healthz is intentionally unauthenticated — health probes and docker
        # healthcheck must work without credentials regardless of auth config.
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not_found"})

    # ------------------------------------------------------------------
    # POST /v1/decide
    # ------------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._do_POST_inner()
        except Exception:  # noqa: BLE001
            # BELT: if anything slips past process() (e.g. a _respond I/O error
            # on a broken connection is acceptable to propagate, but any logic
            # error must never leave the socket empty).
            # Sanitized: no traceback, no internal paths sent to client.
            print("[reeflex-core] ERROR: unexpected handler error - failing closed", file=sys.stderr)
            try:
                self._respond(500, {
                    "decision": "deny",
                    "reason": "internal error - failing closed",
                    "rule": "reeflex.core/internal_error",
                    "obligations": [],
                    "modulation": None,
                })
            except Exception:  # noqa: BLE001
                # Socket already broken; nothing more we can do.
                pass

    def _do_POST_inner(self) -> None:
        if self.path != "/v1/decide":
            self._respond(404, {"error": "not_found"})
            return

        # Auth check BEFORE reading the body: an unauthenticated client's body
        # (possibly huge or hostile) is never consumed.
        if not self._authorized():
            self._respond(
                401,
                {"error": "unauthorized"},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        # Read body
        length_str = self.headers.get("Content-Length", "")
        try:
            length = int(length_str)
        except (ValueError, TypeError):
            self._respond(411, {"error": "content_length_required"})
            return

        if length > _MAX_BODY_BYTES:
            self._respond(413, {"error": "payload_too_large"})
            return

        raw = self.rfile.read(length)

        # Parse JSON
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_json"})
            return

        # Delegate to the decision pipeline
        status, response = process(body)
        self._respond(status, response)

    # ------------------------------------------------------------------
    # Unsupported methods
    # ------------------------------------------------------------------

    def _method_not_allowed(self) -> None:
        self._respond(405, {"error": "method_not_allowed"}, extra_headers={"Allow": "GET, POST"})

    def do_PUT(self) -> None:     # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:   # noqa: N802
        self._method_not_allowed()

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _respond(
        self,
        status: int,
        body: dict,
        extra_headers: dict | None = None,
    ) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)


def run() -> None:
    host = os.environ.get("REEFLEX_HOST", "127.0.0.1")
    port = int(os.environ.get("REEFLEX_PORT", "8080"))

    server = http.server.HTTPServer((host, port), _DecideHandler)
    print(f"[reeflex-core] listening on http://{host}:{port}/v1/decide", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[reeflex-core] shutdown", file=sys.stderr)
    finally:
        server.server_close()
