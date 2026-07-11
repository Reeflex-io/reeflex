"""
stub_core_obligations.py -- a throwaway, real HTTP stand-in for reeflex-core's
`/v1/decide`, used ONLY for the Track 5.1 obligations E2E
(tests/fixtures/e2e_obligations.py). The REAL reeflex-core's base policy pack
emits no obligations today (design doc ADDENDUM v1.5's own finding) -- this
lets the E2E drive a REAL gateway subprocess + REAL MCP client against a
REAL HTTP decision response that DOES carry a synthetic obligation, without
touching reeflex-core's actual code (out of scope for this track).

Dispatch is purely by the envelope's `params.tool_name` (never by the tool's
free-text content) -- deterministic, matching the project's own zero-LLM
decision-path invariant:
  read_note      -> allow, obligations: []                 (case a)
  delete_note    -> allow, obligations: ["audit:full"]      (case b -- KNOWN)
  delete_notes   -> allow, obligations: ["redact:pii"]      (case c -- UNKNOWN)

Run: python tests/fixtures/stub_core_obligations.py --port 8080
"""

from __future__ import annotations

import argparse
import json
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

_OBLIGATIONS_BY_TOOL = {
    "read_note": [],
    "delete_note": ["audit:full"],
    "delete_notes": ["redact:pii"],
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 -- suppress noise
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
            return
        self._respond(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/v1/decide":
            self._respond(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        try:
            envelope = json.loads(body.decode("utf-8"))
        except Exception:  # noqa: BLE001
            self._respond(400, {"error": "invalid_json"})
            return

        tool_name = (envelope.get("params") or {}).get("tool_name", "")
        obligations = _OBLIGATIONS_BY_TOOL.get(tool_name, [])
        decision = {
            "decision": "allow",
            "reason": f"stub allow for {tool_name}",
            "rule": "stub.policy/allow",
            "obligations": obligations,
            "modulation": None,
            "decision_id": uuid.uuid4().hex,
        }
        self._respond(200, decision)

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), _Handler)
    print(f"[stub-core-obligations] listening on http://{args.host}:{args.port}")
    server.serve_forever()
