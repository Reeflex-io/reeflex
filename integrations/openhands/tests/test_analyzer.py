"""ReeflexSecurityAnalyzer against a fake gate on a real socket: allow / hold /
deny / timeout / unreachable, the evidence and hold wires, and the secrets."""

from __future__ import annotations

import json
import socket

import pytest

from openhands.sdk.security.risk import SecurityRisk

from conftest import CORE_TOKEN, GATE_TOKEN, SIGNING_KEY_HEX


def _ev(shim, recorded, idx):
    return shim(recorded["events"][idx])


def _cmd(env):
    return (env.get("context") or {}).get("command_preview") or ""


def test_allow_read_is_low_and_allow_write_is_medium(gate, analyzer_factory, shim, recorded_events):
    a = analyzer_factory()
    assert a.security_risk(_ev(shim, recorded_events, 3)) == SecurityRisk.LOW      # ls -la
    assert a.security_risk(_ev(shim, recorded_events, 4)) == SecurityRisk.MEDIUM   # create file
    assert [e["action"]["verb"] for e in gate.decide_calls] == ["read", "create"]
    assert gate.auth_seen[0] == "Bearer " + CORE_TOKEN
    assert len(gate.evidence) == 2 and gate.portal_errors == []


def test_deny_is_high_and_its_evidence_row_is_pushed_signed(gate, analyzer_factory, shim,
                                                           recorded_events):
    gate.on(lambda e: "push --force" in _cmd(e),
            {"decision": "deny", "rule": "reeflex.policy/irreversible_broad_prod", "reason": "r"})
    a = analyzer_factory()
    ev = _ev(shim, recorded_events, 1)
    analysis = a.analyze_action(ev)
    assert analysis.risk == SecurityRisk.HIGH
    rec = a.decisions[ev.id]
    assert rec["verdict"] == "deny" and rec["rule"] == "reeflex.policy/irreversible_broad_prod"
    assert analysis.details["reeflex_decision_id"] == rec["reeflex_decision_id"]
    (row,) = gate.evidence
    assert row["decision_id"] == rec["reeflex_decision_id"]
    assert row["verdict"] == "deny"
    assert row["action"] == {"verb": "emit", "target_environment": "production",
                             "target_system": "openhands"}
    assert row["agent_id"].startswith("agent:openhands/openhands/")
    assert "hold" not in row
    assert gate.portal_errors == []


def test_hold_is_high_pushes_the_pending_hold_and_defers_evidence(gate, analyzer_factory, shim,
                                                                 recorded_events):
    gate.on(lambda e: "rm -rf" in _cmd(e),
            {"decision": "require_approval", "rule": "reeflex.policy/irreversible_broad_prod",
             "reason": "needs a human"})
    a = analyzer_factory()
    ev = _ev(shim, recorded_events, 0)
    assert a.security_risk(ev) == SecurityRisk.HIGH
    rec = a.decisions[ev.id]
    assert rec["hold_id"] and rec["hold_announced"] == "announced"
    (hold,) = gate.holds
    assert hold["hold_id"] == rec["hold_id"] and hold["decision_id"] == rec["reeflex_decision_id"]
    assert hold["verb"] == "delete" and hold["reason"] == "needs a human"
    assert gate.evidence == []                      # deferred until resolved
    a.complete_hold(rec["hold_id"], resolution="approved", decided_by_type="human",
                    decided_by_id="user-uuid-1")
    (row,) = gate.evidence
    assert row["hold"] == {"hold_id": rec["hold_id"], "resolution": "approved",
                           "decided_by": {"type": "human", "id": "user-uuid-1"}}
    assert row["verdict"] == "require_approval"


def test_unreachable_gate_is_unknown_when_closed_and_low_when_open(shim, recorded_events):
    from reeflex_openhands import ReeflexSecurityAnalyzer
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    ev = _ev(shim, recorded_events, 0)
    closed = ReeflexSecurityAnalyzer("http://127.0.0.1:%d" % port, "t", timeout=1.0)
    assert closed.security_risk(ev) == SecurityRisk.UNKNOWN
    assert closed.decisions[ev.id]["verdict"] == "unreachable"
    opened = ReeflexSecurityAnalyzer("http://127.0.0.1:%d" % port, "t", timeout=1.0, fail="open")
    assert opened.security_risk(ev) == SecurityRisk.LOW


def test_a_slow_gate_times_out_to_unknown(gate, analyzer_factory, shim, recorded_events):
    gate.slow_seconds = 1.5
    a = analyzer_factory(timeout=0.3)
    assert a.security_risk(_ev(shim, recorded_events, 3)) == SecurityRisk.UNKNOWN
    assert gate.evidence == []


@pytest.mark.parametrize("status,body,expect", [
    (500, {"error": "internal"}, SecurityRisk.UNKNOWN),        # no decision: not core's verdict
    (400, {"error": "invalid_envelope"}, SecurityRisk.UNKNOWN),
    (401, {"error": "unauthorized"}, SecurityRisk.UNKNOWN),
    (200, {"decision": "maybe"}, SecurityRisk.UNKNOWN),        # unknown decision string
    # core's OWN fail-closed deny (OPA down) is a decision, and it is a deny
    (500, {"decision": "deny", "rule": "reeflex.core/fail_closed", "decision_id": "d" * 32},
     SecurityRisk.HIGH),
])
def test_protocol_failures(gate, analyzer_factory, shim, recorded_events, status, body, expect):
    gate.on(lambda e: True, ("http", status, body))
    a = analyzer_factory()
    assert a.security_risk(_ev(shim, recorded_events, 3)) == expect


def test_evidence_failure_never_changes_the_risk(gate, analyzer_factory, shim, recorded_events):
    a = analyzer_factory(gate_token="rfx_gate_wrong")
    ev = _ev(shim, recorded_events, 3)
    assert a.security_risk(ev) == SecurityRisk.LOW
    assert a.decisions[ev.id]["evidence_pushed"] == "failed"
    assert gate.portal_errors[0][0] == 401


def test_a_bad_signing_key_is_refused_by_the_server_check(gate, analyzer_factory, shim,
                                                        recorded_events):
    """Control for the signature assertions above: the fake's verifier does fail."""
    a = analyzer_factory(evidence_signing_key="22" * 32)
    a.security_risk(_ev(shim, recorded_events, 3))
    assert gate.evidence == [] and gate.portal_errors[0] == (401, "signature verification failed")


def test_no_portal_configured_means_hold_not_announced(gate, shim, recorded_events):
    from reeflex_openhands import ReeflexSecurityAnalyzer
    gate.on(lambda e: True, {"decision": "require_approval", "rule": "r"})
    a = ReeflexSecurityAnalyzer(gate.url, CORE_TOKEN)
    ev = _ev(shim, recorded_events, 0)
    a.security_risk(ev)
    assert a.decisions[ev.id]["hold_announced"] == "not_configured"
    assert gate.holds == []


def test_secrets_never_serialize(analyzer_factory):
    a = analyzer_factory()
    dumped = a.model_dump_json()
    for secret in (CORE_TOKEN, GATE_TOKEN, SIGNING_KEY_HEX):
        assert secret not in dumped
    assert json.loads(dumped)["kind"] == "ReeflexSecurityAnalyzer"


def test_secrets_come_back_from_the_environment_on_resume(monkeypatch, gate):
    """The SDK resumes a persisted conversation with model_validate(), which
    does not call __init__."""
    from openhands.sdk.security.analyzer import SecurityAnalyzerBase
    from reeflex_openhands import ReeflexSecurityAnalyzer
    dumped = json.loads(ReeflexSecurityAnalyzer(gate.url, "explicit").model_dump_json())
    monkeypatch.setenv("REEFLEX_CORE_TOKEN", "from-env")
    resumed = SecurityAnalyzerBase.model_validate(dumped)
    assert type(resumed).__name__ == "ReeflexSecurityAnalyzer"
    assert resumed._api_key == "from-env"


# --- inside a real SDK conversation -------------------------------------------

def test_details_land_in_the_sdk_security_analysis_event(gate, analyzer_factory):
    import sdk_harness
    from openhands.sdk.event import SecurityAnalysisEvent
    gate.on(lambda e: "rm -rf" in _cmd(e), {"decision": "deny", "rule": "reeflex.policy/x"})
    conv = sdk_harness.conversation(sdk_harness.shell_calls("rm -rf ./build"))
    a = analyzer_factory()
    a.attach(conv)
    conv.send_message("go")
    conv.run()
    events = [e for e in conv.state.events if isinstance(e, SecurityAnalysisEvent)]
    assert len(events) == 1
    ((action_id, details),) = events[0].details.items()
    assert events[0].risks[action_id] == SecurityRisk.HIGH
    assert details["verdict"] == "deny" and details["rule"] == "reeflex.policy/x"
    assert details["reeflex_decision_id"] == a.decisions[action_id]["reeflex_decision_id"]
    assert sdk_harness.EXECUTED == []
    assert a.session_id == str(conv.id)
    assert gate.decide_calls[0]["agent"]["session_id"] == "openhands:%s" % conv.id
    conv.close()


def test_builtin_tool_annotations_do_not_reprice_a_read(gate, analyzer_factory):
    """The recording terminal declares destructiveHint=True, exactly as the real
    TerminalTool does.  `ls` must still be priced from its arguments."""
    import sdk_harness
    conv = sdk_harness.conversation(sdk_harness.shell_calls("ls -la"))
    a = analyzer_factory()
    a.attach(conv)
    conv.send_message("go")
    conv.run()
    (rec,) = a.decisions.values()
    assert rec["risk"] == "LOW" and rec["axes"]["reversibility"] == "reversible"
    assert sdk_harness.EXECUTED == ["ls -la"]
    conv.close()
