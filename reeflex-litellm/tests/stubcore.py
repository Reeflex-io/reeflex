"""
stubcore.py -- a scriptable stand-in for reeflex-core, for the unit suite.

NOT a test file (no `test_` prefix), so `gate.py`'s drift walk does not count it
and the census does not expect tests in it.

WHY A STUB AT ALL, GIVEN THE PROJECT RULE THAT A MOCK IS NOT EVIDENCE
=====================================================================
It is not evidence about core, and this module claims nothing about core.  It
exists so the suite can pin the ADAPTER'S OWN behaviour on paths a real core
cannot be made to produce on demand -- an unparseable body, a 200 with no
`decision` key, a decision string nobody has implemented, a socket that refuses
the connection -- and so the suite runs in `gate.py`'s venv with no Docker.

Every verdict this stub is scripted to return was FIRST observed coming out of
the published `ghcr.io/reeflex-io/reeflex-core:v0.2.0` image (digest
sha256:58a0a531dfa1…) and the transcripts are in the round's evidence
directory.  The end-to-end walk against that image, through a real LiteLLM
proxy, is the evidence for the seat; this stub is the regression net under the
adapter's own branches.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# A uuid4 hex, 32 chars -- the shape EVIDENCE-INGEST-SPEC-v1 §4 requires of
# `decision_id` and §6 uses as the idempotency key.  Core's `decide.py` sets one
# on EVERY response shape, including the denial and fail-closed ones, so a stub
# that omitted it would let an evidence test pass on a record core would never
# have allowed to exist.  Fixed rather than random so a test can assert on it.
DECISION_ID = "9f2c4b1ea7d3465fb08c15d2e6a37c40"


class StubCore:
    """A localhost HTTP server that answers /v1/decide and /v1/holds/{id}.

    Scripting:
      decide_queue     list of (status, body_dict_or_raw_bytes) popped in order;
                       when exhausted, `decide_default` is used
      decide_default   (status, body) for every call past the queue
      hold_status      what GET /v1/holds/{id} reports; may be reassigned mid
                       test to simulate a human deciding
      hold_http        override the hold response entirely: (status, body)
      requests         every decode-able request body received, in order
      auth_seen        the Authorization header of each request, in order
    """

    def __init__(self):
        self.decide_queue = []
        self.decide_default = (200, {"decision": "allow", "reason": "ok",
                                     "rule": "reeflex.policy/default_allow",
                                     "obligations": [],
                                     "decision_id": DECISION_ID})
        self.hold_status = "pending"
        # WHO decided the hold, in core's frozen `"{type}:{id}"` shape, plus
        # core's own verification flag. `None` = core recorded no decider,
        # which is what a pending hold looks like.
        self.hold_decided_by = None
        self.hold_decided_by_verified = False
        self.hold_http = None
        self.requests = []
        self.auth_seen = []
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a):  # silence
                pass

            def _send(self, status, payload):
                if isinstance(payload, (bytes, bytearray)):
                    raw = bytes(payload)
                else:
                    raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with stub._lock:
                    stub.auth_seen.append(self.headers.get("Authorization"))
                    try:
                        stub.requests.append(json.loads(body.decode("utf-8")))
                    except Exception:
                        stub.requests.append({"_unparseable": True})
                    if self.path == "/v1/decide":
                        status, payload = (stub.decide_queue.pop(0)
                                           if stub.decide_queue
                                           else stub.decide_default)
                    else:
                        status, payload = 404, {"error": "not_found"}
                self._send(status, payload)

            def do_GET(self):
                with stub._lock:
                    if self.path.startswith("/v1/holds/"):
                        if stub.hold_http is not None:
                            status, payload = stub.hold_http
                        else:
                            status, payload = 200, {
                                "id": self.path.rsplit("/", 1)[-1],
                                "status": stub.hold_status,
                                "decided_by": stub.hold_decided_by,
                                "decided_by_verified":
                                    stub.hold_decided_by_verified,
                            }
                    else:
                        status, payload = 404, {"error": "not_found"}
                self._send(status, payload)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        return "http://%s:%d" % (host, port)

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # -- convenience scripting --------------------------------------------

    def answer_allow(self, rule="reeflex.policy/read_only_internal",
                     decision_id=None):
        self.decide_default = (200, {"decision": "allow", "reason": "read-only",
                                     "rule": rule, "obligations": [],
                                     "decision_id": decision_id or DECISION_ID})

    def answer_deny(self, rule="reeflex.policy/irreversible_systemic_prod",
                    reason="irreversible systemic change in production",
                    decision_id=None):
        self.decide_default = (200, {"decision": "deny", "reason": reason,
                                     "rule": rule, "obligations": [],
                                     "decision_id": decision_id or DECISION_ID})

    def approve(self, who="human:alice.approver@acme.example", verified=True):
        """A human decided it -- what core's record looks like afterwards."""
        self.hold_status = "approved"
        self.hold_decided_by = who
        self.hold_decided_by_verified = verified

    def answer_hold(self, hold_id="hold-1",
                    rule="reeflex.policy/irreversible_broad_prod",
                    reason="irreversible broad change in production requires human approval",
                    decision_id=None):
        self.decide_default = (200, {"decision": "require_approval",
                                     "reason": reason, "rule": rule,
                                     "obligations": [], "hold_id": hold_id,
                                     "expires_ts": "2026-09-08T12:00:00Z",
                                     "decision_id": decision_id or DECISION_ID})


def unused_port() -> int:
    """A port nothing is listening on -- for the fail-closed case."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tool_call(call_id, name, arguments):
    """One OpenAI-shaped tool call, `arguments` as the JSON STRING it is on the wire."""
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


def chat_response(tool_calls, content=None, model="mock-tools",
                  finish_reason="tool_calls"):
    """A chat-completion response in plain-dict shape."""
    return {
        "id": "chatcmpl-stub",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": content,
                        "tool_calls": list(tool_calls)},
        }],
    }
