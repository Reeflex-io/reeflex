"""
connector.py -- the Reeflex connector: the same decision, served over HTTP.

WHY THIS EXISTS, IN ONE PARAGRAPH
=================================
`guardrail.py` is a `CustomGuardrail` loaded by a DOTTED IMPORT PATH, which
means `reeflex_litellm` has to be importable INSIDE the customer's LiteLLM
container.  `ghcr.io/berriai/litellm` does not contain it, so that path costs a
customer a derived image and a rebuild on every LiteLLM upgrade.  LiteLLM also
ships a Generic Guardrail API: the proxy POSTs to an external HTTP server, and
the server answers.  This module is that server.  The customer's LiteLLM stays
the stock image; what they run instead is this container.

The decision itself is NOT reimplemented here.  Tenancy, normalisation, the
envelope, the call to core, the hold loop, the ledger and the evidence push are
`tenancy` / `normalize` / `enforce` / `evidence` -- the same functions, in the
same order, that `guardrail.py` calls.  What is new is only the transport and
the translation between LiteLLM's guardrail vocabulary and ours.

THE WIRE, READ OFF litellm 1.101.0 AND NOT OFF THE DOCUMENTATION
================================================================
`POST <api_base>/beta/litellm_basic_guardrail_api`, Content-Type JSON, the
`api_key` from the guardrail config sent as `x-api-key`.  The body is
`GenericGuardrailAPIRequest`
(`litellm/types/proxy/guardrails/guardrail_hooks/generic_guardrail_api.py`):

    input_type       "request" (pre_call) or "response" (post_call)
    tool_calls       the assistant's tool calls, OpenAI-shaped dicts.  THE
                     FIELD THIS SEAT EXISTS FOR.
    texts            the assistant's text content, one entry per choice
    model            the model that answered
    request_data     eight `user_api_key_*` metadata fields -- tenancy
    request_headers  the inbound request's headers, SANITIZED: litellm
                     forwards the VALUE only for an allowlist (`host`,
                     `accept`, `content-type`, `user-agent`, `x-stainless-*`,
                     `x-litellm-*`, ...) plus anything named in the guardrail's
                     `extra_headers`, and replaces every other value with the
                     literal string "[present]".  A custom session header
                     therefore arrives WITHOUT ITS VALUE unless the operator
                     lists it in `extra_headers` -- see `session_id()`.
    additional_provider_specific_params
                     static config from `litellm_params`, merged with the
                     per-request `extra_body` a caller may pass under
                     `guardrails: [{"reeflex": {"extra_body": {...}}}]`
    litellm_call_id / litellm_trace_id / litellm_version / images / tools /
    structured_messages

THE ANSWER VOCABULARY IS SMALLER THAN THE ONE THE IN-PROCESS SEAT HAS, AND
THAT IS THE LOAD-BEARING FACT OF THIS MODULE
=========================================================================
`GenericGuardrailAPIResponse` has exactly six fields: `action`,
`blocked_reason`, `texts`, `images`, `tools`, `stream_holdback_chars`.
**There is no `tool_calls` and no `structured_messages` on the RESPONSE**, and
`GenericGuardrailAPI._build_guardrail_return_inputs()` copies back only
`texts`, `images`, `tools` and `stream_holdback_chars`.

So over this transport a guardrail CANNOT delete one tool call and keep the
others.  The in-process seat does exactly that (`response.apply_refusals`);
this one cannot, and the honest consequence is:

    ANY refusal on a response refuses THE WHOLE RESPONSE, with `action:
    "BLOCKED"`.  If a response proposes two tool calls and core denies one of
    them, the caller gets a refusal naming the denied call -- and does not get
    the allowed one either.

That is stricter than the in-process seat, never weaker, and it is stated in
the doc rather than discovered by a customer whose agent lost a tool call it
was allowed to make.  `blocked_reason` carries the same structured payload the
in-process seat writes into the assistant message, so a client parses one shape
on both paths:

    {"reeflex": {"version": 1, "refused": [{"error": ..., "rule": ...,
     "reason": ..., "tool_call_id": ..., "tool": ..., "stage":
     "refused_at_gateway"}, ...]}}

`stage` is `refused_at_gateway` here for the same reason it is there: a gateway
sees a tool call PROPOSED, not executed.  Nothing about running this seat as a
separate container changes that, and no refusal this module emits may be read
as prevention at the point of execution.

FAILURE POSTURE, AND WHY THIS SERVER NEVER ANSWERS 502/503/504
==============================================================
LiteLLM's `unreachable_fallback` (default `fail_closed`) and `fail_on_error`
(default true) decide what happens when this server is unreachable or errors.
Measured in `generic_guardrail_api.py`: a status code in {502, 503, 504} is
classified `is_unreachable=True`, and THAT is the class `fail_open` releases.
So a connector that answered 503 on its own internal error would be handing the
release decision to a customer's config toggle.

This server therefore answers **200 with `action: "BLOCKED"`** when its own
code fails on a governed response -- fail-closed by the body, not by the status
code, on every customer configuration.  Status codes are used only for things
that are not a decision at all: 401 (no/incorrect token), 404, 405, 413, 400.

WHAT RUNS WHERE (the question this container settles)
=====================================================
Classification and envelope construction run HERE, in a process we own -- not
inside litellm, not inside core.  EVIDENCE-INGEST-SPEC-v1 §6's property that
core observes none of the axes it decides on is untouched: core still receives
the axes computed, in the envelope, from this process.

WHAT THIS MODULE DOES NOT DO
============================
No prompt reading, no PII masking, no content scoring, no LLM in the decision
path -- unchanged from the in-process seat.  It also does not terminate TLS and
does not authenticate a human: it authenticates ONE caller (the proxy) with one
shared token, and belongs on a network only the proxy can reach.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import socketserver
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional

from . import core as _core
from . import enforce as _enforce
from . import evidence as _evidence
from . import normalize as _normalize
from . import routing as _routing
from . import tenancy as _tenancy

_logger = logging.getLogger("reeflex_litellm.connector")

ENDPOINT_PATH = "/beta/litellm_basic_guardrail_api"
HEALTH_PATH = "/healthz"

ACTION_NONE = "NONE"
ACTION_BLOCKED = "BLOCKED"
ACTION_INTERVENED = "GUARDRAIL_INTERVENED"

INPUT_TYPE_RESPONSE = "response"
INPUT_TYPE_REQUEST = "request"

TOKEN_ENV = "REEFLEX_CONNECTOR_TOKEN"
PORT_ENV = "REEFLEX_CONNECTOR_PORT"
HOST_ENV = "REEFLEX_CONNECTOR_HOST"
PRINCIPAL_ENV = "REEFLEX_CONNECTOR_PRINCIPAL"
ENVIRONMENT_ENV = "REEFLEX_CONNECTOR_ENVIRONMENT"
SESSION_HEADER_ENV = "REEFLEX_CONNECTOR_SESSION_HEADER"
MAX_BODY_ENV = "REEFLEX_CONNECTOR_MAX_BODY"

DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - a container port, published by compose
DEFAULT_SESSION_HEADER = "x-reeflex-session"
DEFAULT_MAX_BODY = 4 * 1024 * 1024

# litellm replaces the value of any header outside its allowlist with this
# literal.  Treating it as a session id would give every caller behind one
# proxy the SAME R5 cumulative budget -- see session_id().
HEADER_PRESENT_PLACEHOLDER = "[present]"

# `additional_provider_specific_params` keys this connector reads.  They are
# namespaced because that dict is shared with whatever else an operator puts in
# `litellm_params` / a caller puts in `extra_body`.
PARAM_SESSION = "reeflex_session"
PARAM_PRINCIPAL = "reeflex_principal"
PARAM_ENVIRONMENT = "reeflex_environment"


def _log(message: str) -> None:
    """One place for the operator-facing log line.

    WARNING level for the same reason `guardrail.py` uses it: every line this
    emits is either a governance refusal an operator must fix or a gap in the
    evidence record.  Newlines are stripped -- the interpolated values include
    operator- and caller-supplied aliases, and a forged extra log line would be
    a way to write a false governance record into a text log.
    """
    _logger.warning("reeflex-connector: %s",
                    message.replace("\n", " ").replace("\r", " "))


class Counters:
    """What this process has seen, for `/healthz` and for the operator.

    Deliberately small and deliberately NOT a decision record: the ledger is
    the record.  These exist so a customer can answer "is the guardrail
    actually wired to this connector, and in which mode" without reading two
    logs -- `pre_call_requests` in particular is how a `mode: pre_call`
    misconfiguration becomes visible instead of silently governing nothing.
    """

    __slots__ = ("responses_seen", "tool_calls_decided", "blocked",
                 "allowed", "pre_call_requests", "unmapped_tenant",
                 "internal_errors", "unauthorised", "started_at", "_lock")

    def __init__(self) -> None:
        self.responses_seen = 0
        self.tool_calls_decided = 0
        self.blocked = 0
        self.allowed = 0
        self.pre_call_requests = 0
        self.unmapped_tenant = 0
        self.internal_errors = 0
        self.unauthorised = 0
        self.started_at = time.time()
        self._lock = threading.Lock()

    def bump(self, name: str, by: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + by)

    def as_dict(self) -> dict:
        with self._lock:
            return {n: getattr(self, n) for n in
                    ("responses_seen", "tool_calls_decided", "allowed",
                     "blocked", "pre_call_requests", "unmapped_tenant",
                     "internal_errors", "unauthorised")}


COUNTERS = Counters()


# ---------------------------------------------------------------------------
# The decision, as a pure function of the request payload
# ---------------------------------------------------------------------------

def decide_payload(payload: dict, *, principal: Optional[str] = None,
                   environment: Optional[str] = None,
                   hold_wait: Optional[float] = None,
                   session_header: Optional[str] = None,
                   counters: Optional[Counters] = None) -> dict:
    """One Generic Guardrail API request in, one answer out.

    Separated from the HTTP layer so the contract can be tested without a
    socket, and so the answer for a given wire body is reproducible from a
    saved fixture.  NEVER raises: the caller turns an exception into a BLOCKED
    answer, and this function turns everything it can foresee into one itself.

    Returns the response body dict.  Evidence is written as a side effect --
    after the answer is decided, for the same reason `guardrail.py` records
    after enforcing: an evidence outage must not change or delay a decision.
    """
    counters = counters if counters is not None else COUNTERS
    input_type = payload.get("input_type")

    if input_type != INPUT_TYPE_RESPONSE:
        # A pre_call request carries the prompt and the tool SCHEMA -- which
        # tools exist -- not which tool the model chose or with what
        # arguments.  There is no action to rule on yet, so this is NONE, and
        # it is counted and logged because a proxy configured `mode: pre_call`
        # is a proxy where this seat governs NOTHING while appearing wired.
        counters.bump("pre_call_requests")
        _log("input_type=%r: this seat rules on ACTIONS, which do not exist "
             "until the model has answered. Set `mode: post_call` on the "
             "guardrail -- nothing was ruled on for this request."
             % (input_type,))
        return {"action": ACTION_NONE}

    counters.bump("responses_seen")
    raw_calls = payload.get("tool_calls")
    if not isinstance(raw_calls, list) or not raw_calls:
        # Not an action.  Core is never called and TENANCY IS NOT RESOLVED --
        # which is why a text answer still flows when core is down AND when
        # the caller's key is not in the tenancy map.  Identical rule, and the
        # same reason, as `guardrail.py::_rule_on_response`.
        return {"action": ACTION_NONE}

    calls = [_normalize.normalize_tool_call(raw) for raw in raw_calls]
    counters.bump("tool_calls_decided", len(calls))

    # TENANCY FIRST, BEFORE ANY DECISION.  An unresolved caller is refused
    # here: core is never asked, so no decision lands in the wrong org's
    # evidence and no R5 budget is charged to a session that belongs to
    # nobody.
    request_data = payload.get("request_data")
    identity = _tenancy.read_identity_from_gateway_metadata(request_data)
    resolution = _tenancy.resolve_identity(identity)
    if not resolution.resolved:
        counters.bump("unmapped_tenant")
        counters.bump("blocked")
        _log("tenancy: REFUSED every tool call -- unmapped gateway caller [%s]"
             % identity.describe())
        refusals = [_enforce.refuse_unmapped_tenant(c, resolution.reason).refusal
                    for c in calls]
        return _blocked(refusals)

    tenant = resolution.tenant
    model = _s(payload.get("model")) or "unknown"
    session = session_id(payload, session_header=session_header)
    gateway_routing = _routing.build(
        data={"model": model, "stream": payload.get("stream")},
        response={"model": model},
        tenant=tenant, identity=identity, model=model)
    gateway_routing["transport"] = "generic_guardrail_api"
    gateway_routing["litellm_version"] = _s(payload.get("litellm_version"))

    refusals, ledger_lines = [], []
    for call in calls:
        outcome = _enforce.rule_one_call(
            call, session_id=session, model=model,
            principal=_s(_param(payload, PARAM_PRINCIPAL)) or principal or None,
            environment=_s(_param(payload, PARAM_ENVIRONMENT)) or environment or None,
            hold_wait=hold_wait, tenant=tenant,
            gateway_routing=gateway_routing)
        if not outcome.allowed:
            refusals.append(outcome.refusal)
        if outcome.ledger is not None:
            ledger_lines.append(outcome.ledger)

    # AFTER the answer is decided, and never able to change it.
    _record_evidence(ledger_lines, tenant)

    if refusals:
        counters.bump("blocked")
        return _blocked(refusals)
    counters.bump("allowed")
    return {"action": ACTION_NONE}


def refusal_payload(refusals: list) -> str:
    """The structured refusal, in the shape the in-process seat also emits."""
    return json.dumps({"reeflex": {"version": 1, "refused": refusals}},
                      sort_keys=True)


def _blocked(refusals: list) -> dict:
    """`action: BLOCKED`, with the refusal in `blocked_reason`.

    `blocked_reason` is the ONLY field litellm reads on a block
    (`GuardrailRaisedException(message=blocked_reason,
    should_wrap_with_default_message=False)`), so it carries both halves: a
    sentence a human reads in an error, and the JSON a client parses.  The
    sentence comes first because some clients truncate.
    """
    first = (refusals[0] or {}).get("reason") if refusals else None
    head = first or "Reeflex refused this response."
    return {"action": ACTION_BLOCKED,
            "blocked_reason": "%s %s" % (head, refusal_payload(refusals))}


def blocked_for_internal_error(exc: BaseException) -> dict:
    """Fail closed on our own bug, loudly, and in the BODY not the status.

    Mirrors `guardrail.py::_refuse_everything`.  The refusal names no tool call
    because on this path the payload may be exactly what could not be read.
    """
    reason = ("Reeflex: the connector's governance path failed, so no tool "
              "call on this response was cleared and the response is refused "
              "[rule=%s]: %s: %s"
              % (_core.FAIL_CLOSED_RULE, type(exc).__name__, exc))
    _log("REFUSED the whole response -- %s: %s" % (type(exc).__name__, exc))
    return _blocked([{
        "error": _enforce.ERROR_UNAVAILABLE,
        "rule": _core.FAIL_CLOSED_RULE,
        "reason": reason,
        "stage": _enforce.STAGE,
    }])


def session_id(payload: dict, session_header: Optional[str] = None) -> str:
    """The session R5's cumulative budget is charged against.

    Precedence, and every step of it is a fact about what this transport can
    actually carry:

      1. `additional_provider_specific_params.reeflex_session` -- set once in
         `litellm_params` for a whole deployment, or per request by a caller
         through `guardrails: [{"<name>": {"extra_body": {"reeflex_session":
         ...}}}]`.  The explicit answer, and the one this transport supports
         best.
      2. the request header named by `REEFLEX_CONNECTOR_SESSION_HEADER`
         (default `x-reeflex-session`) -- **only if its VALUE arrived.**
         LiteLLM sanitises inbound headers before forwarding them and replaces
         every value outside its allowlist with the literal "[present]", so
         this step works only when the operator has listed the header in the
         guardrail's `extra_headers`.  A "[present]" value is DISCARDED here:
         using it would give every caller behind one proxy one shared session
         id, and therefore one shared cumulative budget.
      3. `user_api_key_end_user_id` -- litellm's home for the OpenAI `user`
         field, which is what step 2 of the in-process seat's precedence uses.
      4. `litellm_trace_id`, then `litellm_call_id`.

    KNOWN LIMIT, the same one the in-process seat documents: with none of 1-3
    supplied the fallback is PER REQUEST, so R5's cumulative session budget is
    scoped to one request.  The budget is not wrong; it is scoped narrowly.
    Whatever this returns is namespaced by the tenant's org in `envelope.py`
    (`litellm:<org>:<session>`), so two departments sending the same session id
    do not share a budget.
    """
    explicit = _s(_param(payload, PARAM_SESSION))
    if explicit:
        return explicit

    name = (session_header or DEFAULT_SESSION_HEADER).lower()
    headers = payload.get("request_headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == name and isinstance(v, str):
                v = v.strip()
                if v and v != HEADER_PRESENT_PLACEHOLDER:
                    return v

    meta = payload.get("request_data")
    if isinstance(meta, dict):
        end_user = _s(meta.get("user_api_key_end_user_id"))
        if end_user:
            return end_user

    for key in ("litellm_trace_id", "litellm_call_id"):
        v = _s(payload.get(key))
        if v:
            return v
    return "litellm-" + uuid.uuid4().hex


def _param(payload: dict, name: str) -> Any:
    params = payload.get("additional_provider_specific_params")
    if isinstance(params, dict):
        return params.get(name)
    return None


def _s(v) -> Optional[str]:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return None


def _record_evidence(ledger_lines: list, tenant) -> None:
    """Append the ledger and, when enabled, push the §4 records.

    Best-effort and unable to raise, exactly as in `guardrail.py`: the decision
    is already made by the time this runs, so an evidence failure is a gap in
    the record -- surfaced in the log -- not a reason to change a verdict.
    """
    if not ledger_lines:
        return
    try:
        for line in ledger_lines:
            _evidence.append_ledger(line)
        if not _evidence.push_enabled():
            return
        wire = []
        for line in ledger_lines:
            try:
                wire.append(_evidence.wire_record(line))
            except Exception as exc:
                _log("evidence: skipped one record for org=%s: %s"
                     % (getattr(tenant, "org", None), exc))
        if not wire:
            return
        result = _evidence.push(wire, tenant)
        if not result.ok:
            _log("evidence: push FAILED for org=%s (%d records): %s"
                 % (result.org, result.records, result.error))
    except Exception as exc:  # pragma: no cover - defensive
        _log("evidence: recording failed: %s: %s" % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# The HTTP layer
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """One request, one thread.

    `rule_one_call` is stdlib-blocking and may poll a hold for tens of seconds,
    so a request occupies its thread for as long as the decision takes.  That
    is the shape of the work, not an accident of the server: the alternative --
    answering before the human has -- is what `reeflex_hold_wait: 0` is for.
    """

    server_version = "reeflex-connector"
    sys_version = ""
    # Keep-alive: httpx (litellm's client) reuses connections, and without
    # HTTP/1.1 every decision would pay a TCP handshake.  Every response below
    # sets Content-Length, which HTTP/1.1 requires for this to be safe.
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        # BaseHTTPRequestHandler writes to stderr with its own format; route it
        # through logging so a container's log has one shape.  DEBUG, because
        # one line per decision at INFO would bury the WARNING lines that mean
        # something.
        _logger.debug("reeflex-connector: %s - %s", self.address_string(),
                      fmt % args)

    def _send(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorised(self) -> bool:
        expected = self.server.token
        if not expected:
            return True
        presented = self.headers.get("x-api-key") or ""
        if not presented:
            auth = self.headers.get("Authorization") or ""
            if auth[:7].lower() == "bearer ":
                presented = auth[7:]
        return hmac.compare_digest(presented.strip(), expected)

    def _drain(self, length: int, limit: int = 64 * 1024 * 1024) -> None:
        """Read and throw away up to `limit` bytes of a body we will not use."""
        remaining = min(length, limit)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)

    def _reject(self, status: int, body: dict) -> None:
        """Answer WITHOUT having read the request body, and stay in sync.

        `protocol_version = "HTTP/1.1"` means keep-alive, and litellm's httpx
        client pools connections -- so an early return that answers a POST
        without consuming its body leaves those bytes in the socket, where the
        NEXT request on that connection parses them as its request line.  The
        symptom is an alternation: a correct 401, then a 400 carrying
        `BaseHTTPRequestHandler`'s HTML error page, then a 401 again as the
        parser resynchronises.

        That was measured against the 401 path on 2026-09-17 and it corrupts
        the diagnostic for the single most likely first-run mistake -- a token
        that does not match the guardrail's `api_key`.  An operator reading
        "400 Bad Request" with an HTML body looks for a malformed request; the
        actual fault is one wrong environment variable, which the 401 names.

        So: drain a body whose length we know, and when we cannot know it
        (chunked, absent or unparseable `Content-Length`) close the connection
        instead.  The 413 path already did exactly this and documents why; this
        helper is that same discipline in one place.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        chunked = (self.headers.get("Transfer-Encoding") or "").lower() == "chunked"
        if chunked or length < 0:
            self.close_connection = True
        elif length:
            self._drain(length)
        self._send(status, body)

    def _read_body(self) -> Optional[dict]:
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            self._reject(400, {"error": "chunked request bodies are not read "
                                        "by this server; send Content-Length"})
            return None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            self._reject(400, {"error": "Content-Length required"})
            return None
        if length > self.server.max_body:
            # A governance service that buffers whatever it is sent is a memory
            # exhaustion away from being unavailable, and an unavailable
            # connector is a blocked proxy.
            #
            # The oversized body is DISCARDED IN BOUNDED CHUNKS before the
            # answer goes out, and the connection is then closed. Answering
            # while the client is still writing gives the client a broken pipe
            # instead of the 413, which reads as "the connector crashed" -- a
            # different operator problem from the real one, which is a cap.
            self._drain(length)
            self.close_connection = True
            self._send(413, {"error": "request body too large",
                             "max_bytes": self.server.max_body})
            return None
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send(400, {"error": "request body is not JSON"})
            return None
        if not isinstance(payload, dict):
            self._send(400, {"error": "request body is not a JSON object"})
            return None
        return payload

    # -- routes ------------------------------------------------------------

    def do_GET(self):  # noqa: N802 - stdlib signature
        if self.path.split("?")[0] != HEALTH_PATH:
            self._send(404, {"error": "not found"})
            return
        self._send(200, self.server.health(authorised=self._authorised()))

    def do_POST(self):  # noqa: N802 - stdlib signature
        if self.path.split("?")[0] != ENDPOINT_PATH:
            self._reject(404, {"error": "not found",
                               "endpoint": ENDPOINT_PATH})
            return
        if not self._authorised():
            COUNTERS.bump("unauthorised")
            _log("REFUSED a request with no valid token. With litellm's "
                 "defaults (fail_on_error: true) the proxy blocks it; set the "
                 "same value in the guardrail's `api_key` and in %s."
                 % TOKEN_ENV)
            # 401, deliberately not 503: litellm classifies {502,503,504} as
            # "unreachable", which is the class `unreachable_fallback:
            # fail_open` releases.
            self._reject(401, {"error": "unauthorised"})
            return
        payload = self._read_body()
        if payload is None:
            return
        try:
            answer = decide_payload(
                payload,
                principal=self.server.principal,
                environment=self.server.environment,
                hold_wait=self.server.hold_wait,
                session_header=self.server.session_header)
        except Exception as exc:  # fail closed on our own bugs, loudly
            COUNTERS.bump("internal_errors")
            answer = blocked_for_internal_error(exc)
        self._send(200, answer)


class ConnectorServer(socketserver.ThreadingMixIn, HTTPServer):
    """The server, holding the config a handler needs."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, *, token: Optional[str],
                 principal: Optional[str] = None,
                 environment: Optional[str] = None,
                 hold_wait: Optional[float] = None,
                 session_header: Optional[str] = None,
                 max_body: int = DEFAULT_MAX_BODY):
        super().__init__(address, _Handler)
        self.token = token
        self.principal = principal
        self.environment = environment
        self.hold_wait = hold_wait
        self.session_header = session_header or DEFAULT_SESSION_HEADER
        self.max_body = max_body

    def health(self, authorised: bool = False) -> dict:
        """What `/healthz` answers.

        Unauthenticated callers get liveness and CONFIGURATION SHAPE -- whether
        a token is required, whether a tenancy map loaded -- because a
        container healthcheck has no token and an operator debugging a refusal
        needs to know which of the two is missing.  Values that describe the
        deployment's topology (the core URL, the map's source, the counters)
        are added only for a caller presenting the token.  No secret is in
        either.
        """
        from . import __version__ as _version
        try:
            mapping = _tenancy.load_map()
            tenancy_block = {"loaded": True, "orgs": len(mapping.tenants)}
            source = mapping.source
        except Exception as exc:
            tenancy_block = {"loaded": False,
                             "error": "%s: %s" % (type(exc).__name__, exc)}
            source = None
        body = {
            "status": "ok",
            "service": "reeflex-connector",
            "version": _version,
            "endpoint": ENDPOINT_PATH,
            "auth_required": bool(self.token),
            "tenancy": tenancy_block,
        }
        if authorised:
            body["core_url"] = _core.core_url()
            body["hold_wait_seconds"] = (
                self.hold_wait if self.hold_wait is not None
                else _core._float_env("REEFLEX_LITELLM_HOLD_WAIT",
                                      _core.DEFAULT_HOLD_WAIT,
                                      allow_zero=True))
            body["tenancy_source"] = source
            body["counters"] = COUNTERS.as_dict()
            body["uptime_seconds"] = round(time.time() - COUNTERS.started_at, 1)
        return body


def build_server(host: Optional[str] = None, port: Optional[int] = None,
                 **kwargs) -> ConnectorServer:
    host = host or os.environ.get(HOST_ENV) or DEFAULT_HOST
    if port is None:
        port = _int_env(PORT_ENV, DEFAULT_PORT)
    kwargs.setdefault("token", (os.environ.get(TOKEN_ENV) or "").strip() or None)
    kwargs.setdefault("principal", _s(os.environ.get(PRINCIPAL_ENV)))
    kwargs.setdefault("environment", _s(os.environ.get(ENVIRONMENT_ENV)))
    kwargs.setdefault("session_header",
                      _s(os.environ.get(SESSION_HEADER_ENV)))
    kwargs.setdefault("max_body", _int_env(MAX_BODY_ENV, DEFAULT_MAX_BODY))
    return ConnectorServer((host, port), **kwargs)


def _int_env(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return v if v > 0 else default


def main(argv: Optional[list] = None) -> int:
    """Run the connector.  `reeflex-connector` on the command line.

    Refuses to start WITHOUT a token unless the operator says so explicitly:
    anything that can reach this port can propose actions in the name of any
    org in the tenancy map, and a governance service that is open by default
    when a `docker compose` forgets one line is a worse default than a startup
    failure that names the line.
    """
    logging.basicConfig(
        level=os.environ.get("REEFLEX_CONNECTOR_LOG_LEVEL", "WARNING").upper(),
        format="%(asctime)s %(levelname)s %(message)s")
    token = (os.environ.get(TOKEN_ENV) or "").strip()
    anonymous = (os.environ.get("REEFLEX_CONNECTOR_ALLOW_ANONYMOUS", "")
                 .strip().lower() in ("1", "true", "yes", "on"))
    if not token and not anonymous:
        sys.stderr.write(
            "reeflex-connector: %s is not set. Set it to a shared secret and "
            "give LiteLLM the same value as the guardrail's `api_key`, or set "
            "REEFLEX_CONNECTOR_ALLOW_ANONYMOUS=1 if the port is reachable only "
            "by the proxy and you accept that anything reaching it can propose "
            "actions for any org in the tenancy map.\n" % TOKEN_ENV)
        return 2
    server = build_server()
    host, port = server.server_address[0], server.server_address[1]
    sys.stderr.write("reeflex-connector: listening on %s:%s%s (auth: %s)\n"
                     % (host, port, ENDPOINT_PATH,
                        "token" if token else "NONE"))
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
