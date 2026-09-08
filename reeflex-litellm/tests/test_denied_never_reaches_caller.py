"""
THE test: a denied tool call is not in the response the caller receives.

Driven through the guardrail's OWN hook -- `async_post_call_success_hook`, the
method LiteLLM's proxy awaits -- with the response object the proxy would hand
it, and asserted on THAT object afterwards.  Not on the Outcome objects the
adapter produced internally: an adapter that computes a perfect refusal and then
returns the original response would satisfy every other test in this suite.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from reeflex_litellm import core, response as R
from reeflex_litellm.guardrail import ReeflexActionGuardrail

import stubcore
from conftest import PAYMENTS_CALLER, caller


@pytest.fixture(autouse=True)
def _mapped(tenancy_map):
    """Every test in this module drives the hook, and the hook resolves tenancy
    before it decides anything.  Requested explicitly (module-wide autouse)
    rather than made ambient in conftest, so that a test asserting "no map ->
    deny" stays possible in the same suite."""
    yield


def run(coro):
    return asyncio.run(coro)


def hook(response, data=None, key=None, **kw):
    """Drive the real hook as the proxy does, with an AUTHENTICATED caller.

    `key` defaults to the payments team's virtual key.  Passing
    `key=None` explicitly is not the same thing as omitting it -- see
    `test_tenancy_isolation.py`, which relies on the difference."""
    g = ReeflexActionGuardrail(reeflex_hold_wait=0.0, **kw)
    return run(g.async_post_call_success_hook(
        data if data is not None else {"model": "mock-tools",
                                       "litellm_call_id": "req-1"},
        caller(**PAYMENTS_CALLER) if key is None else key,
        response))


DESTRUCTIVE = {"command": "rm -rf /"}
BENIGN = {"path": "/etc/hosts"}


def test_a_denied_tool_call_is_absent_from_the_response_the_caller_gets(stub):
    stub.answer_deny()
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "run_shell", DESTRUCTIVE)])

    out = hook(r)

    wire = json.dumps(out, sort_keys=True)
    assert "rm -rf /" not in wire, (
        "the denied command is still somewhere in the response the caller "
        "receives: %s" % wire)
    assert out["choices"][0]["message"]["tool_calls"] is None
    assert out["choices"][0]["finish_reason"] == "stop"
    assert R.refused_payloads(out)[0]["error"] == "reeflex_denied"


def test_the_control_an_allowed_tool_call_IS_in_the_response(stub):
    """Without this row the test above proves only that the hook empties
    tool_calls, which an unconditionally-refusing hook also does."""
    stub.answer_allow()
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "read_file", BENIGN)])

    out = hook(r)

    assert out["choices"][0]["message"]["tool_calls"] is not None
    assert len(out["choices"][0]["message"]["tool_calls"]) == 1
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    assert R.refused_payloads(out) == []


def test_one_denied_call_beside_one_allowed_call_removes_exactly_one(stub):
    """The seat rules per CALL, not per response. A response is not all-or
    nothing -- that was the point of building an envelope per tool call."""
    stub.decide_queue = [
        (200, {"decision": "allow", "reason": "read-only",
               "rule": "reeflex.policy/read_only_internal", "obligations": []}),
        (200, {"decision": "deny", "reason": "irreversible systemic in prod",
               "rule": "reeflex.policy/irreversible_systemic_prod",
               "obligations": []}),
    ]
    r = stubcore.chat_response([
        stubcore.tool_call("call_a", "read_file", BENIGN),
        stubcore.tool_call("call_b", "run_shell", DESTRUCTIVE),
    ])

    out = hook(r)

    kept = out["choices"][0]["message"]["tool_calls"]
    assert [c["id"] for c in kept] == ["call_a"]
    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    refused = R.refused_payloads(out)
    assert [x["tool_call_id"] for x in refused] == ["call_b"]
    assert out["choices"][0]["finish_reason"] == "tool_calls"


def test_core_unreachable_removes_the_tool_call_and_says_why(monkeypatch):
    """Fail CLOSED, with a reason the model sees."""
    monkeypatch.setenv("REEFLEX_CORE_URL",
                       "http://127.0.0.1:%d" % stubcore.unused_port())
    monkeypatch.setenv("REEFLEX_LITELLM_TIMEOUT", "1")
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "run_shell", DESTRUCTIVE)])

    out = hook(r)

    assert out["choices"][0]["message"]["tool_calls"] is None
    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    payload = R.refused_payloads(out)[0]
    assert payload["error"] == "reeflex_unavailable"
    assert payload["rule"] == core.FAIL_CLOSED_RULE
    assert payload["stage"] == "refused_at_gateway"


def test_with_core_down_a_TEXT_answer_still_reaches_the_caller(monkeypatch):
    """The seat rules on actions. A prose answer is not an action, so core being
    unreachable must not take the gateway's text traffic down with it -- and it
    is never even asked."""
    monkeypatch.setenv("REEFLEX_CORE_URL",
                       "http://127.0.0.1:%d" % stubcore.unused_port())
    monkeypatch.setenv("REEFLEX_LITELLM_TIMEOUT", "1")
    r = stubcore.chat_response([], content="the capital of France is Paris",
                               finish_reason="stop")
    before = json.dumps(r, sort_keys=True)

    out = hook(r)

    assert json.dumps(out, sort_keys=True) == before


def test_a_hold_nobody_resolved_also_never_reaches_the_caller(stub):
    stub.answer_hold(hold_id="hold-1")
    stub.hold_status = "pending"
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf ./build"})])

    out = hook(r)

    assert out["choices"][0]["message"]["tool_calls"] is None
    assert "rm -rf ./build" not in json.dumps(out, sort_keys=True)
    payload = R.refused_payloads(out)[0]
    assert payload["error"] == "reeflex_hold_timeout"
    assert payload["hold_id"] == "hold-1"


def test_an_approved_hold_releases_the_call_to_the_caller(stub):
    stub.hold_status = "approved"
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "obligations": [], "hold_id": "hold-1"}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission", "obligations": []}),
    ]
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf ./build"})])

    g = ReeflexActionGuardrail(reeflex_hold_wait=2.0)
    out = run(g.async_post_call_success_hook(
        {"model": "m"}, caller(**PAYMENTS_CALLER), r))

    kept = out["choices"][0]["message"]["tool_calls"]
    assert kept is not None and len(kept) == 1
    assert R.refused_payloads(out) == []


def test_a_bug_in_the_hook_itself_refuses_everything(stub, monkeypatch):
    """If this module raises where enforce.py did not already handle it, the
    response still returns -- with nothing executable on it. An exception
    escaping a post-call hook is either a 500 for text traffic too or, worse,
    swallowed by a caller: a swallowed governance error is a fail-open."""
    stub.answer_allow()

    def boom(*a, **k):
        raise RuntimeError("synthetic bug in the hook")

    monkeypatch.setattr("reeflex_litellm.guardrail._enforce.rule_one_call", boom)
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "read_file", BENIGN)])

    out = hook(r)

    assert out["choices"][0]["message"]["tool_calls"] is None
    payload = R.refused_payloads(out)[0]
    assert payload["error"] == "reeflex_unavailable"
    assert "synthetic bug in the hook" in payload["reason"]


def test_the_session_header_is_what_the_budget_is_charged_against(stub):
    stub.answer_allow()
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "read_file", BENIGN)])

    hook(r, data={"model": "m",
                  "proxy_server_request": {
                      "headers": {"X-Reeflex-Session": "tenant-42"}}})

    assert stub.requests[0]["agent"]["session_id"] == \
        "litellm:acme-payments:tenant-42"


def test_without_a_session_header_the_openai_user_field_is_used(stub):
    stub.answer_allow()
    r = stubcore.chat_response(
        [stubcore.tool_call("call_1", "read_file", BENIGN)])
    hook(r, data={"model": "m", "user": "user-7"})
    assert stub.requests[0]["agent"]["session_id"] == \
        "litellm:acme-payments:user-7"


def test_with_neither_the_budget_falls_back_to_ONE_REQUEST(stub):
    """A named limit, not an accident: with no session header and no `user`,
    R5's cumulative session budget cannot accumulate across a conversation.
    RFX-243 scoped the NAMESPACE to the tenant; it did not close this."""
    stub.answer_allow()
    r1 = stubcore.chat_response([stubcore.tool_call("c", "read_file", BENIGN)])
    r2 = stubcore.chat_response([stubcore.tool_call("c", "read_file", BENIGN)])
    hook(r1, data={"model": "m", "litellm_call_id": "req-1"})
    hook(r2, data={"model": "m", "litellm_call_id": "req-2"})
    sessions = [q["agent"]["session_id"] for q in stub.requests]
    assert sessions == ["litellm:acme-payments:req-1",
                        "litellm:acme-payments:req-2"]
