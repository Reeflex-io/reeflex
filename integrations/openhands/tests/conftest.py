"""Shared fixtures: a fake Reeflex gate (core + portal) on a real socket.

The fake speaks the same HTTP the real planes speak, so the analyzer's own
urllib client, its JSON, its headers and its HMAC are what is under test --
nothing is patched inside the package.  The portal half VERIFIES the §5
signature with an independent HMAC computed here, and validates every record
against the same closed field lists the reeflex-app server enforces
(`api/evidence_validation.py`, `api/holds.py`), copied below rather than
imported from the package under test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"

SIGNING_KEY_HEX = "11" * 32
GATE_TOKEN = "rfx_gate_testtoken"
CORE_TOKEN = "core-test-credential"

# reeflex-app's closed lists, independently restated (NOT imported from
# reeflex_openhands.wire, which is the thing being checked).
APP_EVIDENCE_TOP = {"decision_id", "verdict", "rule", "envelope_hash", "occurred_ts",
                    "action", "magnitude", "agent_id", "traceparent", "hold", "sig_alg"}
APP_EVIDENCE_ACTION = {"verb", "target_system", "target_environment"}
APP_VERBS = {"read", "create", "update", "delete", "execute", "transact", "emit"}
APP_HOLD_ALLOWED = {"hold_id", "decision_id", "verb", "target_system", "target_environment",
                    "magnitude_count", "rule", "agent_id", "envelope_hash", "reason",
                    "created_ts", "expires_ts", "sig_alg"}
APP_HOLD_REQUIRED = ("hold_id", "decision_id", "verb", "target_environment", "rule",
                     "envelope_hash", "created_ts")


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class FakeGate:
    """`rules`: list of (predicate(envelope) -> bool, response dict | "timeout" |
    ("http", status, body)).  First match wins; default allow."""

    def __init__(self):
        self.rules = []
        self.decide_calls = []
        self.evidence = []
        self.holds = []
        self.resolutions = []
        self.portal_errors = []
        self.auth_seen = []
        self.slow_seconds = 0.0
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = "http://127.0.0.1:%d" % self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    # -- scripting -------------------------------------------------------
    def on(self, predicate, response):
        self.rules.append((predicate, response))

    def resolve(self, hold_id, decision, *, by_id="user-uuid-1", reason=None):
        row = {"hold_id": hold_id, "decision": decision,
               "decided_by": {"type": "human", "id": by_id},
               "resolved_ts": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime())}
        if reason:
            row["reason"] = reason
        self.resolutions.append(row)

    # -- server ----------------------------------------------------------
    def _handler(self):
        gate = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                gate.auth_seen.append(self.headers.get("Authorization"))
                if self.path.startswith("/api/v1/holds/resolutions"):
                    if self.headers.get("Authorization") != "Bearer " + GATE_TOKEN:
                        return self._send(401, {"detail": "unknown or revoked gate token"})
                    since = None
                    if "since=" in self.path:
                        from urllib.parse import parse_qs, urlsplit
                        since = parse_qs(urlsplit(self.path).query)["since"][0]
                    rows = [r for r in gate.resolutions if since is None or r["resolved_ts"] > since]
                    return self._send(200, rows)
                self._send(404, {"detail": "not found"})

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                gate.auth_seen.append(self.headers.get("Authorization"))
                if self.path == "/v1/decide":
                    env = json.loads(raw)
                    gate.decide_calls.append(env)
                    if gate.slow_seconds:
                        time.sleep(gate.slow_seconds)
                    for pred, resp in gate.rules:
                        if pred(env):
                            break
                    else:
                        resp = {"decision": "allow", "rule": "reeflex.policy/default_allow",
                                "reason": "default"}
                    if isinstance(resp, tuple) and resp[0] == "http":
                        return self._send(resp[1], resp[2])
                    body = dict(resp)
                    body.setdefault("decision_id", uuid.uuid4().hex)
                    if body["decision"] == "require_approval":
                        body.setdefault("hold_id", "hold_" + uuid.uuid4().hex[:12])
                        body.setdefault("expires_ts", "2099-01-01T00:00:00Z")
                    return self._send(200, body)
                if self.path in ("/api/v1/evidence", "/api/v1/holds"):
                    err = self._verify(raw)
                    if err:
                        gate.portal_errors.append(err)
                        return self._send(err[0], {"detail": err[1]})
                    records = json.loads(raw)
                    for rec in records:
                        bad = (_check_evidence if self.path.endswith("evidence")
                               else _check_hold)(rec)
                        if bad:
                            gate.portal_errors.append((422, bad))
                            return self._send(422, {"detail": bad})
                    (gate.evidence if self.path.endswith("evidence") else gate.holds).extend(records)
                    return self._send(200, {"accepted": len(records), "duplicates": 0,
                                            "total": len(records)})
                self._send(404, {"detail": "not found"})

            def _verify(self, raw):
                if self.headers.get("Authorization") != "Bearer " + GATE_TOKEN:
                    return (401, "unknown or revoked gate token")
                ts = self.headers.get("X-Reeflex-Timestamp")
                sig = self.headers.get("X-Reeflex-Signature", "")
                if not ts or not sig.startswith("hmac-sha256="):
                    return (401, "missing signature/timestamp headers")
                if abs(int(time.time()) - int(ts)) > 300:
                    return (401, "timestamp outside the ±300s window")
                body = _canonical(json.loads(raw))  # the server re-canonicalizes
                expect = hmac.new(bytes.fromhex(SIGNING_KEY_HEX),
                                  ("%s.\n" % ts).encode() + body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expect, sig.split("=", 1)[1]):
                    return (401, "signature verification failed")
                return None

        return H


def _check_evidence(rec):
    if set(rec) - APP_EVIDENCE_TOP:
        return "unknown field(s) %s" % sorted(set(rec) - APP_EVIDENCE_TOP)
    for f in ("decision_id", "verdict", "rule", "envelope_hash", "occurred_ts", "sig_alg"):
        if not rec.get(f):
            return "%s required" % f
    if set(rec["action"]) - APP_EVIDENCE_ACTION or rec["action"].get("verb") not in APP_VERBS:
        return "action invalid"
    if rec["verdict"] not in ("allow", "deny", "require_approval"):
        return "verdict invalid"
    return None


def _check_hold(rec):
    if set(rec) - APP_HOLD_ALLOWED:
        return "pending-hold: unknown field(s) %s" % sorted(set(rec) - APP_HOLD_ALLOWED)
    for f in APP_HOLD_REQUIRED:
        if not rec.get(f) or not isinstance(rec[f], str):
            return "pending-hold: %s required" % f
    return None


@pytest.fixture
def gate():
    g = FakeGate()
    yield g
    g.close()


@pytest.fixture
def analyzer_factory(gate):
    from reeflex_openhands import ReeflexSecurityAnalyzer

    def make(**kw):
        kw.setdefault("portal_url", gate.url)
        kw.setdefault("gate_token", GATE_TOKEN)
        kw.setdefault("evidence_signing_key", SIGNING_KEY_HEX)
        kw.setdefault("timeout", 2.0)
        return ReeflexSecurityAnalyzer(kw.pop("gate_url", gate.url), kw.pop("api_key", CORE_TOKEN), **kw)
    return make


@pytest.fixture
def recorded_events():
    return json.loads((FIXTURES / "sdk_1_56_action_events.json").read_text())


class Shim:
    """The two attributes the mapping reads, built from a recorded event."""

    def __init__(self, recorded):
        self.id = recorded["id"]
        self.tool_name = recorded["tool_name"]
        data = dict(recorded["action"])
        kind = data.get("kind")
        if kind == "MCPToolAction":
            from openhands.sdk.mcp.definition import MCPToolAction
            self.action = MCPToolAction(data=data.get("data") or {})
        else:
            self.action = _Plain(data)


class _Plain:
    def __init__(self, data):
        self._d = data

    def model_dump(self, mode="json"):
        return dict(self._d)


@pytest.fixture
def shim():
    return Shim
