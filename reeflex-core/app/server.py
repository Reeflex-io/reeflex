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
"""

from __future__ import annotations

import http.server
import json
import os
import sys

from .decide import process


class _DecideHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        # Override to prefix with service name; goes to stderr
        print(f"[reeflex-core] {fmt % args}", file=sys.stderr)

    # ------------------------------------------------------------------
    # GET /healthz
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
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

        # Read body
        length_str = self.headers.get("Content-Length", "")
        try:
            length = int(length_str)
        except (ValueError, TypeError):
            self._respond(411, {"error": "content_length_required"})
            return

        raw = self.rfile.read(length)

        # Parse JSON
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._respond(400, {"error": "invalid_json", "detail": str(exc)})
            return

        # Delegate to the decision pipeline
        status, response = process(body)
        self._respond(status, response)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
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
