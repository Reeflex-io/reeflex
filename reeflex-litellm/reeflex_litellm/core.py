"""
core.py -- the client for reeflex-core: POST /v1/decide, plus the holds loop.

FAIL-CLOSED INVARIANT
=====================
`decide()` never raises and never returns "allow" on an error.  Connection
refused, DNS failure, timeout, a non-JSON body, a 200 with no `decision`, an
HTTP 5xx, an unknown decision string -- every one of them returns
`Verdict(kind="deny", rule="reeflex.core/fail_closed", core_reachable=False)`.

The verdict strings and the fail-closed rule id are `reeflex_claude.enforce`'s,
not new ones.  This module deliberately does NOT import
`enforce.call_core_and_map()` even though the mapping is identical, for one
reason: that function returns a 5-tuple that drops `hold_id` and `expires_ts`,
and the gateway's require_approval path is built on them.  Calling it and then
POSTing a second time to recover the hold id would raise a SECOND hold for the
same action.

So the mapping is duplicated in `_map()` below -- 20 lines -- and
`tests/test_enforce_contract.py` pins it: for every decision value core can
return, it asserts `_map()` agrees with `enforce.call_core_and_map()` run
against the same stub body.  If reeflex-claude's fail-closed mapping changes,
that test goes red here rather than the two seats drifting silently.

CONCURRENCY
===========
The HTTP calls are stdlib-blocking (`urllib`), so the async entry points hand
them to a bounded thread pool rather than blocking the proxy's event loop.
REEFLEX_LITELLM_MAX_INFLIGHT sizes that pool (default 32).  A gateway that
holds the loop for the duration of a decision serialises every other request
behind it, which would show up as a latency cliff at concurrency, not as a
wrong answer -- the worst kind of defect to leave in a governance seat.

TOOL CALLS WITHIN ONE RESPONSE ARE DECIDED IN ORDER, NOT IN PARALLEL.
That costs one round trip per tool call, and it is deliberate: R5's cumulative
session budget is charged per decision on a shared session, so deciding a
response's calls concurrently would make the verdict depend on which decision
reached the ledger first.  The measured cost of the choice is in the README's
latency table (a 2-tool-call response costs about twice a 1-tool-call one).

Env:
  REEFLEX_CORE_URL                default http://127.0.0.1:8080  (shared name)
  REEFLEX_CORE_TOKEN              optional bearer               (shared name)
  REEFLEX_VERIFY_SSL              TLS verification, default ON  (shared name)
  REEFLEX_LITELLM_TIMEOUT         seconds per HTTP call, default 5.0
  REEFLEX_LITELLM_MAX_INFLIGHT    decision thread pool size, default 32
  REEFLEX_LITELLM_HOLD_WAIT       seconds to withhold a response awaiting a
                                  hold resolution, default 30.0.  0 disables
                                  waiting: the response is refused immediately,
                                  naming the hold, so the caller can retry
                                  after a human decides.
  REEFLEX_LITELLM_HOLD_POLL       seconds between hold polls, default 1.0
  REEFLEX_LITELLM_APPROVER        the principal to send on `approval.by` when
                                  resubmitting an approved envelope.  Recorded
                                  only; core takes the real approver from the
                                  hold record, never from this field.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_CORE_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT = 5.0
DEFAULT_HOLD_WAIT = 30.0
DEFAULT_HOLD_POLL = 1.0
FAIL_CLOSED_RULE = "reeflex.core/fail_closed"
UNKNOWN_DECISION_RULE = "adapter/unknown_decision_fail_closed"
_MAX_ERROR_LEN = 300
_VERIFY_SSL_FALSY = frozenset({"0", "false", "no", "off"})


class Verdict:
    """The gateway's reading of one core Decision.

    kind            "allow" | "deny" | "ask"   (reeflex_claude.enforce's values)
    decision        the raw core decision string, or "" on an error
    reason          human-readable, SHOWN TO THE MODEL on a refusal
    rule            the rule id that decided
    core_reachable  False only when core could not be reached or parsed
    hold_id         set when core raised a hold
    expires_ts      the hold's expiry, when core supplied one
    obligations     the core Decision's obligations (empty on an error)
    """

    __slots__ = ("kind", "decision", "reason", "rule", "core_reachable",
                 "hold_id", "expires_ts", "obligations", "http_status")

    def __init__(self, kind, decision="", reason="", rule="unknown",
                 core_reachable=True, hold_id=None, expires_ts=None,
                 obligations=None, http_status=None):
        self.kind = kind
        self.decision = decision
        self.reason = reason
        self.rule = rule
        self.core_reachable = core_reachable
        self.hold_id = hold_id
        self.expires_ts = expires_ts
        self.obligations = obligations or []
        self.http_status = http_status

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("Verdict(kind=%r, rule=%r, hold_id=%r, core_reachable=%r)"
                % (self.kind, self.rule, self.hold_id, self.core_reachable))


# ---------------------------------------------------------------------------
# Decide
# ---------------------------------------------------------------------------

def decide(envelope: dict) -> Verdict:
    """POST /v1/decide.  Never raises; fails closed on every error path."""
    status, body, err = _post("/v1/decide", envelope)
    if err is not None:
        return _fail_closed(err)
    if not isinstance(body, dict) or "decision" not in body:
        if status is not None and status != 200:
            return _fail_closed("core returned HTTP %s without decision" % status)
        return _fail_closed("core response missing 'decision' field")
    return _map(body, http_status=status)


def resubmit_with_approval(approved_envelope: dict) -> Verdict:
    """POST an envelope carrying `approval` -- the second half of a hold."""
    return decide(approved_envelope)


# ---------------------------------------------------------------------------
# Holds
# ---------------------------------------------------------------------------

def get_hold(hold_id: str) -> tuple:
    """(status_string_or_None, error_or_None) for one hold.

    `status` is core's hold status: pending | approved | rejected | expired |
    consumed.  A hold this adapter cannot read is (None, reason) -- never
    treated as approved.
    """
    status, body, err = _get("/v1/holds/%s" % hold_id)
    if err is not None:
        return None, err
    if not isinstance(body, dict):
        return None, "hold response not an object"
    st = body.get("status")
    if not isinstance(st, str) or not st:
        # Core returns the hold's event stream; the freshest event type is the
        # status when no explicit `status` key is present.
        st = body.get("event_type") if isinstance(body.get("event_type"), str) else ""
        st = {"created": "pending"}.get(st, st)
    if not st:
        return None, "hold response carried no status"
    return st, None


def await_hold(hold_id: str, wait_seconds: Optional[float] = None,
               poll_seconds: Optional[float] = None) -> tuple:
    """Block until the hold leaves `pending`.  (final_status, error).

    Returns ("pending", None) on timeout -- the caller decides what a timeout
    means, and for this adapter it means REFUSE, never release.  A hold this
    adapter could not read is (None, reason), also a refusal.

    wait_seconds=0 polls exactly once and returns immediately, which is the
    configuration for a gateway that does not want to hold an HTTP request open.
    """
    wait = _float_env("REEFLEX_LITELLM_HOLD_WAIT", DEFAULT_HOLD_WAIT,
                      allow_zero=True) if wait_seconds is None else wait_seconds
    poll = _float_env("REEFLEX_LITELLM_HOLD_POLL", DEFAULT_HOLD_POLL) \
        if poll_seconds is None else poll_seconds
    deadline = time.monotonic() + max(wait, 0.0)
    while True:
        status, err = get_hold(hold_id)
        if err is not None:
            return None, err
        if status != "pending":
            return status, None
        if time.monotonic() >= deadline:
            return "pending", None
        time.sleep(min(max(poll, 0.05), max(deadline - time.monotonic(), 0.05)))


# ---------------------------------------------------------------------------
# Async entry points -- the proxy's event loop must not block on a decision
# ---------------------------------------------------------------------------

_executor_lock = threading.Lock()
_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None


def _get_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            n = int(_float_env("REEFLEX_LITELLM_MAX_INFLIGHT", 32.0))
            _executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=max(n, 1), thread_name_prefix="reeflex-decide")
        return _executor


async def adecide(envelope: dict) -> Verdict:
    import asyncio
    return await asyncio.get_running_loop().run_in_executor(
        _get_executor(), decide, envelope)


async def aawait_hold(hold_id: str, wait_seconds: Optional[float] = None) -> tuple:
    import asyncio
    return await asyncio.get_running_loop().run_in_executor(
        _get_executor(), await_hold, hold_id, wait_seconds)


# ---------------------------------------------------------------------------
# Mapping -- see the module docstring for why this is duplicated and pinned
# ---------------------------------------------------------------------------

def _map(body: dict, http_status=None) -> Verdict:
    decision = body.get("decision", "")
    reason = body.get("reason", "")
    rule = body.get("rule", "unknown")
    obligations = body.get("obligations", [])
    if not isinstance(obligations, list):
        obligations = list(obligations) if obligations else []
    common = dict(decision=decision, rule=rule, obligations=obligations,
                  core_reachable=True, http_status=http_status,
                  hold_id=body.get("hold_id"), expires_ts=body.get("expires_ts"),
                  reason="Reeflex: %s [rule=%s]" % (reason, rule))
    if decision == "allow":
        return Verdict("allow", **common)
    if decision == "deny":
        return Verdict("deny", **common)
    if decision == "require_approval":
        return Verdict("ask", **common)
    common["reason"] = (
        "Reeflex: unknown decision value '%s' -- failing closed "
        "[rule=adapter/unknown_decision]" % _trunc(str(decision)))
    common["rule"] = UNKNOWN_DECISION_RULE
    common["obligations"] = []
    return Verdict("deny", **common)


def _fail_closed(reason: str) -> Verdict:
    return Verdict(
        "deny",
        decision="",
        reason=("Reeflex: core unreachable or error -- failing closed: %s "
                "[rule=%s]" % (reason, FAIL_CLOSED_RULE)),
        rule=FAIL_CLOSED_RULE,
        core_reachable=False,
    )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def core_url() -> str:
    return os.environ.get("REEFLEX_CORE_URL", DEFAULT_CORE_URL).rstrip("/")


def _request(path: str, data: Optional[bytes], method: str) -> tuple:
    """(status, parsed_body, error_string).  Exactly one of body/error is set."""
    url = core_url() + path
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("REEFLEX_CORE_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    # `token` is not referenced past this point and never enters a reason
    # string, a log line or an audit record.
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = _ssl_context(url)
    timeout = _float_env("REEFLEX_LITELLM_TIMEOUT", DEFAULT_TIMEOUT)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
            status = exc.code
        except Exception:
            return None, None, "core HTTP %s: %s" % (exc.code, _trunc(str(exc.reason)))
        try:
            return status, json.loads(raw.decode("utf-8")), None
        except Exception:
            return None, None, "core HTTP %s: %s" % (status, _trunc(str(exc.reason)))
    except Exception as exc:
        return None, None, "core unreachable: %s" % _trunc(str(exc))
    try:
        return status, json.loads(raw.decode("utf-8")), None
    except Exception as exc:
        return None, None, "core response not JSON: %s" % _trunc(str(exc))


def _post(path: str, body: dict) -> tuple:
    return _request(path, json.dumps(body).encode("utf-8"), "POST")


def _get(path: str) -> tuple:
    return _request(path, None, "GET")


def _ssl_context(url: str):
    if not url.lower().startswith("https://"):
        return None
    raw = os.environ.get("REEFLEX_VERIFY_SSL", "").strip().lower()
    if raw not in _VERIFY_SSL_FALSY:
        return None  # full verification -- the secure default
    # OPT-IN INSECURE, dev/self-signed endpoints only.  Same env name and same
    # semantics as the WordPress and Claude Code adapters.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _float_env(name: str, default: float, allow_zero: bool = False) -> float:
    try:
        v = float(os.environ.get(name, ""))
    except (ValueError, TypeError):
        return default
    if v < 0:
        return default
    if v == 0 and not allow_zero:
        return default
    return v


def _trunc(text: str) -> str:
    return text if len(text) <= _MAX_ERROR_LEN else text[:_MAX_ERROR_LEN] + "...[truncated]"
