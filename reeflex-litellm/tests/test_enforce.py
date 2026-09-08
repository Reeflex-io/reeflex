"""One test per verdict, plus the fail-closed case.

The verdicts these tests script were first observed coming out of the published
ghcr.io/reeflex-io/reeflex-core:v0.2.0 image; see tests/stubcore.py.
"""

from __future__ import annotations

import threading
import time

from reeflex_litellm import core, enforce, normalize

import stubcore


def call(name="run_shell", args=None, call_id="call_1"):
    return normalize.normalize_tool_call(
        stubcore.tool_call(call_id, name,
                           args if args is not None else {"command": "rm -rf ./build"}))


def rule(c=None, **kw):
    kw.setdefault("session_id", "sess-1")
    kw.setdefault("model", "mock-tools")
    kw.setdefault("hold_wait", 0.0)
    return enforce.rule_one_call(c or call(), **kw)


# -- ALLOW -------------------------------------------------------------------

def test_allow_releases_the_tool_call_untouched(stub):
    stub.answer_allow()
    out = rule(call("read_file", {"path": "/etc/hosts"}))
    assert out.allowed is True
    assert out.refusal is None
    assert out.verdict.rule == "reeflex.policy/read_only_internal"


def test_allow_still_sent_one_envelope_to_core(stub):
    stub.answer_allow()
    rule()
    assert len(stub.requests) == 1
    env = stub.requests[0]
    assert env["action"]["namespace"] == "litellm-gateway"


# -- DENY --------------------------------------------------------------------

def test_deny_refuses_with_the_rule_and_reason_the_model_can_read(stub):
    stub.answer_deny(rule="reeflex.policy/irreversible_systemic_prod",
                     reason="irreversible systemic change in production")
    out = rule(call("run_shell", {"command": "rm -rf /"}))
    assert out.allowed is False
    r = out.refusal
    assert r["error"] == "reeflex_denied"
    assert r["rule"] == "reeflex.policy/irreversible_systemic_prod"
    assert "irreversible systemic change in production" in r["reason"]
    assert r["tool"] == "run_shell"
    assert r["tool_call_id"] == "call_1"


def test_every_refusal_says_it_happened_at_the_gateway(stub):
    """SPEC 5.1: 'refused at gateway' is a different recorded fact from
    'prevented at execution'. Collapsing them would let an Attest report claim
    prevention this seat cannot deliver."""
    stub.answer_deny()
    assert rule().refusal["stage"] == "refused_at_gateway"


# -- REQUIRE_APPROVAL --------------------------------------------------------

def test_a_hold_that_nobody_resolves_in_time_is_refused_not_released(stub):
    stub.answer_hold(hold_id="hold-1")
    stub.hold_status = "pending"
    out = rule(hold_wait=0.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_hold_timeout"
    assert out.refusal["hold_id"] == "hold-1"
    # The refusal tells the caller the hold is still open.
    assert "retry" in out.refusal["reason"].lower()


def test_an_approved_hold_is_released_only_after_core_accepts_the_resubmission(stub):
    stub.answer_hold(hold_id="hold-1")
    stub.hold_status = "approved"
    # First POST raises the hold; the second is the resubmission core allows.
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "obligations": [], "hold_id": "hold-1"}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission", "obligations": []}),
    ]
    out = rule(hold_wait=1.0)
    assert out.allowed is True
    assert out.released_after_approval is True
    assert out.hold_id == "hold-1"
    assert len(stub.requests) == 2
    assert stub.requests[1]["approval"] == {
        "present": True, "hold_id": "hold-1", "by": None, "role": None}
    # the resubmission carries a FRESH nonce (core 400s a replay)
    assert stub.requests[1]["meta"]["nonce"] != stub.requests[0]["meta"]["nonce"]


def test_a_human_approval_that_core_then_refuses_is_NOT_released(stub):
    """The gateway does not release on the strength of the hold status alone.
    Core's eight resubmission checks are the authority -- one of them exists
    because a hold id alone was once enough to spend someone else's approval."""
    stub.hold_status = "approved"
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "obligations": [], "hold_id": "hold-1"}),
        (200, {"decision": "deny", "reason": "reeflex_hold_actor_mismatch",
               "rule": "reeflex.core/hold_validation", "obligations": []}),
    ]
    out = rule(hold_wait=1.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_denied"
    assert "reeflex_hold_actor_mismatch" in out.refusal["reason"]


def test_a_rejected_hold_is_refused_and_says_a_human_rejected_it(stub):
    stub.answer_hold(hold_id="hold-2")
    stub.hold_status = "rejected"
    out = rule(hold_wait=1.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_rejected"
    assert "human" in out.refusal["reason"].lower()


def test_an_expired_or_consumed_hold_is_refused(stub):
    for status in ("expired", "consumed"):
        stub.answer_hold(hold_id="hold-3")
        stub.hold_status = status
        out = rule(hold_wait=1.0)
        assert out.allowed is False, status
        assert out.refusal["error"] == "reeflex_hold_expired", status


def test_an_unrecognized_hold_status_is_not_an_approval(stub):
    stub.answer_hold(hold_id="hold-4")
    stub.hold_status = "under_review_by_committee"
    out = rule(hold_wait=1.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_hold_unreadable"


def test_a_hold_this_adapter_cannot_read_is_refused(stub):
    stub.answer_hold(hold_id="hold-5")
    stub.hold_http = (500, {"error": "boom"})
    out = rule(hold_wait=1.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_hold_unreadable"


def test_require_approval_with_no_hold_id_is_refused_not_awaited(stub):
    """A hold with no id cannot be resolved, so it cannot be released. Refuse
    rather than wait forever on nothing."""
    stub.decide_default = (200, {"decision": "require_approval",
                                 "reason": "needs a human",
                                 "rule": "reeflex.policy/irreversible_broad_prod",
                                 "obligations": []})
    out = rule(hold_wait=5.0)
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_unavailable"


def test_the_response_is_actually_withheld_while_the_hold_is_pending(stub):
    """'Withheld until resolution' has to mean the call BLOCKS. A human
    approving mid-wait must release it."""
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "obligations": [], "hold_id": "hold-6"}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission", "obligations": []}),
    ]
    stub.hold_status = "pending"

    def approve_later():
        time.sleep(0.4)
        stub.hold_status = "approved"

    t = threading.Thread(target=approve_later, daemon=True)
    t.start()
    started = time.monotonic()
    out = rule(hold_wait=5.0)
    elapsed = time.monotonic() - started
    t.join()

    assert out.allowed is True
    assert out.released_after_approval is True
    assert elapsed >= 0.3, (
        "the call returned in %.3fs, so it did not actually wait for the "
        "human -- 'withheld until resolution' would be a claim, not a "
        "behaviour" % elapsed)


# -- FAIL CLOSED -------------------------------------------------------------

def test_core_unreachable_refuses_the_call_with_a_reason_the_model_sees(monkeypatch):
    monkeypatch.setenv("REEFLEX_CORE_URL",
                       "http://127.0.0.1:%d" % stubcore.unused_port())
    monkeypatch.setenv("REEFLEX_LITELLM_TIMEOUT", "1")
    out = rule()
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_unavailable"
    assert out.refusal["rule"] == core.FAIL_CLOSED_RULE
    assert "failing closed" in out.refusal["reason"]
    assert out.verdict.core_reachable is False


def test_a_200_with_no_decision_field_fails_closed(stub):
    stub.decide_default = (200, {"reason": "hello"})
    out = rule()
    assert out.allowed is False
    assert out.verdict.rule == core.FAIL_CLOSED_RULE


def test_a_body_that_is_not_json_fails_closed(stub):
    stub.decide_default = (200, b"<html>proxy error</html>")
    out = rule()
    assert out.allowed is False
    assert out.verdict.core_reachable is False


def test_a_500_without_a_decision_fails_closed(stub):
    stub.decide_default = (500, {"error": "internal"})
    out = rule()
    assert out.allowed is False
    assert out.verdict.rule == core.FAIL_CLOSED_RULE


def test_a_500_that_DOES_carry_a_decision_is_honoured(stub):
    """core's own fail-closed response is a 500 with a deny in the body. That is
    a decision, not an error, and must be recorded as core's deny."""
    stub.decide_default = (500, {"decision": "deny",
                                 "reason": "internal error - failing closed",
                                 "rule": "reeflex.core/internal_error",
                                 "obligations": []})
    out = rule()
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_denied"
    assert out.refusal["rule"] == "reeflex.core/internal_error"
    assert out.verdict.core_reachable is True


def test_a_decision_value_nobody_implemented_fails_closed(stub):
    stub.decide_default = (200, {"decision": "probably_fine", "reason": "?",
                                 "rule": "x", "obligations": []})
    out = rule()
    assert out.allowed is False
    assert out.verdict.rule == core.UNKNOWN_DECISION_RULE


def test_a_401_from_core_is_a_refusal_not_an_allow(stub):
    """A misconfigured gateway token must not become an open door."""
    stub.decide_default = (401, {"error": "unauthorized"})
    out = rule()
    assert out.allowed is False


def test_an_envelope_that_cannot_be_built_is_refused_not_skipped(stub):
    stub.answer_allow()
    out = rule(session_id="")
    assert out.allowed is False
    assert out.refusal["error"] == "reeflex_unavailable"
    assert len(stub.requests) == 0, "nothing should have been sent to core"


# -- the token ---------------------------------------------------------------

def test_the_core_token_is_sent_as_a_bearer_and_never_lands_in_a_refusal(stub, monkeypatch):
    monkeypatch.setenv("REEFLEX_CORE_TOKEN", "s3cr3t-not-a-real-token")
    stub.answer_deny()
    out = rule()
    assert stub.auth_seen[0] == "Bearer s3cr3t-not-a-real-token"
    blob = repr(out.refusal) + out.refusal["reason"]
    assert "s3cr3t-not-a-real-token" not in blob
