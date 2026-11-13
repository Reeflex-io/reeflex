"""ReeflexConfirmationPolicy + resolve_pending / run_governed inside a real
SDK conversation.  `sdk_harness.EXECUTED` is the ground truth for "the SDK ran
this action": the recording tool appends to it only when executed."""

from __future__ import annotations

import pytest

from openhands.sdk.event import UserRejectObservation
from openhands.sdk.security.risk import SecurityRisk

import sdk_harness
from reeflex_openhands import ReeflexConfirmationPolicy, console_confirm, run_governed


def _cmd(env):
    return (env.get("context") or {}).get("command_preview") or ""


def _rejections(conv):
    return [e.rejection_reason for e in conv.state.events if isinstance(e, UserRejectObservation)]


@pytest.fixture
def governed(gate, analyzer_factory):
    made = []

    def make(*commands, batch=False, **kw):
        msgs = sdk_harness.batch_call(*commands) if batch else sdk_harness.shell_calls(*commands)
        conv = sdk_harness.conversation(msgs)
        a = analyzer_factory(**kw)
        a.attach(conv)
        conv.send_message("go")
        made.append(conv)
        return conv, a
    yield make
    for c in made:
        c.close()


def _hold_rm(gate):
    gate.on(lambda e: "rm -rf" in _cmd(e),
            {"decision": "require_approval", "rule": "reeflex.policy/irreversible_broad_prod",
             "reason": "held"})


def test_should_confirm_table():
    p = ReeflexConfirmationPolicy(None)
    assert p.should_confirm(SecurityRisk.HIGH) and p.should_confirm(SecurityRisk.UNKNOWN)
    assert not p.should_confirm(SecurityRisk.MEDIUM) and not p.should_confirm(SecurityRisk.LOW)


def test_allow_runs_without_stopping(gate, governed):
    conv, a = governed("ls -la", "touch out.txt")
    log = run_governed(conv, a)
    assert log == []
    assert sdk_harness.EXECUTED == ["ls -la", "touch out.txt"]


def test_deny_is_rejected_automatically_and_never_runs(gate, governed):
    gate.on(lambda e: "push --force" in _cmd(e),
            {"decision": "deny", "rule": "reeflex.policy/irreversible_broad_prod"})
    conv, a = governed("git push --force origin main")
    log = run_governed(conv, a)
    assert sdk_harness.EXECUTED == []
    assert log[0]["outcome"] == "rejected"
    assert _rejections(conv) == ["Reeflex denied: reeflex.policy/irreversible_broad_prod"]


def test_hold_approved_in_the_portal_runs_and_records_who(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build")

    def approve_once(state):
        if not gate.resolutions:
            gate.resolve(gate.holds[0]["hold_id"], "approve", by_id="user-uuid-7")
    log = run_governed(conv, a, poll=0.01, max_wait=5, on_wait=approve_once)
    assert sdk_harness.EXECUTED == ["rm -rf ./build"]
    assert log[0]["outcome"] == "approved"
    (row,) = gate.evidence
    assert row["hold"]["resolution"] == "approved"
    assert row["hold"]["decided_by"] == {"type": "human", "id": "user-uuid-7"}


def test_hold_rejected_in_the_portal_carries_the_resolvers_reason(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build")
    log = run_governed(conv, a, poll=0.01, max_wait=5, on_wait=lambda s: gate.resolutions or
                       gate.resolve(gate.holds[0]["hold_id"], "deny", reason="not on a Friday"))
    assert sdk_harness.EXECUTED == []
    assert "not on a Friday" in _rejections(conv)[0]
    assert gate.evidence[0]["hold"]["resolution"] == "rejected"
    assert log[0]["outcome"] == "rejected"


def test_hold_expired_in_the_portal_is_rejected(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build")
    run_governed(conv, a, poll=0.01, max_wait=5, on_wait=lambda s: gate.resolutions or
                 gate.resolve(gate.holds[0]["hold_id"], "expired"))
    assert sdk_harness.EXECUTED == []
    assert gate.evidence[0]["hold"]["resolution"] == "expired"


def test_hold_nobody_answers_times_out_closed(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build")
    t = [0.0]
    log = run_governed(conv, a, poll=1, max_wait=3, sleep=lambda s: t.__setitem__(0, t[0] + s),
                       clock=lambda: t[0])
    assert sdk_harness.EXECUTED == []
    assert "not resolved within 3s" in _rejections(conv)[0]
    assert "resolution" not in gate.evidence[0]["hold"]       # not stated, not invented
    assert log[0]["outcome"] == "rejected"


def test_unreachable_gate_rejects_closed(governed):
    conv, a = governed("ls -la", gate_url="http://127.0.0.1:9", timeout=0.5)
    log = run_governed(conv, a)
    assert sdk_harness.EXECUTED == []
    assert "unreachable" in _rejections(conv)[0]
    assert log[0]["outcome"] == "rejected"


def test_a_mixed_batch_is_rejected_whole(gate, governed):
    """The SDK approves and rejects per BATCH; one deny in a parallel batch
    rejects the allowed action beside it too."""
    gate.on(lambda e: "push --force" in _cmd(e), {"decision": "deny", "rule": "r/deny"})
    conv, a = governed("ls -la", "git push --force origin main", batch=True)
    run_governed(conv, a)
    assert sdk_harness.EXECUTED == []
    assert len(_rejections(conv)) == 2


def test_hold_without_a_portal_is_rejected_not_waited_on(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build", gate_token=None, portal_url=None)
    a._gate_token = None
    run_governed(conv, a, poll=0.01, max_wait=1)
    assert sdk_harness.EXECUTED == []
    assert "could not be put in front of a human" in _rejections(conv)[0]


def test_console_confirm_never_offers_a_deny(gate, governed):
    gate.on(lambda e: True, {"decision": "deny", "rule": "r/deny"})
    conv, a = governed("rm -rf /")

    def must_not_ask(prompt):
        raise AssertionError("a deny was offered for override")
    run_governed(conv, a, resolver=lambda c, an, **k: console_confirm(c, an, input_fn=must_not_ask,
                                                                      print_fn=lambda s: None, **k))
    assert sdk_harness.EXECUTED == []


def test_console_confirm_yes_runs_a_hold(gate, governed):
    _hold_rm(gate)
    conv, a = governed("rm -rf ./build")
    run_governed(conv, a, resolver=lambda c, an, **k: console_confirm(
        c, an, input_fn=lambda p: "yes", print_fn=lambda s: None, approver_id="ops-1", **k))
    assert sdk_harness.EXECUTED == ["rm -rf ./build"]
    assert gate.evidence[0]["hold"]["decided_by"] == {"type": "human", "id": "ops-1"}


def test_control_a_bare_run_after_a_deny_executes_it(gate, governed):
    """THE DOCUMENTED LIMIT, measured: the SDK's approve is `run()`, and it
    executes the pending batch whatever Reeflex said.  The verdict is
    enforced only by a caller that goes through resolve_pending/run_governed."""
    gate.on(lambda e: True, {"decision": "deny", "rule": "r/deny"})
    conv, a = governed("rm -rf ./build")
    conv.run()          # stops: WAITING_FOR_CONFIRMATION
    assert sdk_harness.EXECUTED == []
    conv.run()          # a naive caller "continues"
    assert sdk_harness.EXECUTED == ["rm -rf ./build"]


def test_control_execute_tool_bypasses_the_analyzer(gate, governed):
    gate.on(lambda e: True, {"decision": "deny", "rule": "r/deny"})
    conv, a = governed("ls")
    conv.execute_tool("terminal", sdk_harness.RecordedShellAction(command="rm -rf /srv"))
    assert sdk_harness.EXECUTED == ["rm -rf /srv"]
    assert gate.decide_calls == []


def test_driver_reads_verdicts_from_the_event_log_when_the_side_map_is_empty(gate, governed):
    """A remote agent server runs the analyzer in ITS process; the client only
    has the SecurityAnalysisEvent details.  The deny must still be rejected."""
    gate.on(lambda e: True, {"decision": "deny", "rule": "r/deny"})
    conv, a = governed("rm -rf ./build")
    conv.run()
    a._decisions.clear()                 # what a client-side copy would hold
    from reeflex_openhands import resolve_pending
    out = resolve_pending(conv, a, resume=False)
    assert out["outcome"] == "rejected" and _rejections(conv) == ["Reeflex denied: r/deny"]
