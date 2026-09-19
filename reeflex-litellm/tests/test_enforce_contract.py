"""
The tripwire under the ONE piece of logic this package duplicates.

`reeflex_claude.enforce.call_core_and_map()` already maps a core Decision to a
verdict and already carries the fail-closed invariant.  This package does not
call it, for one reason stated in `core.py`: it returns a 5-tuple that drops
`hold_id`, and the whole require_approval path is built on the hold id.  Calling
it and then POSTing again to recover the id would raise a SECOND hold for the
same action.

So `core._map()` duplicates roughly twenty lines.  These tests assert that the
duplicate AGREES with the original, decision value by decision value, against
the same HTTP body -- so if reeflex-claude's mapping changes, this suite goes
red here instead of the two seats drifting apart quietly.
"""

from __future__ import annotations

import pytest
from reeflex_claude import enforce as claude_enforce

from reeflex_litellm import core

import stubcore

# core "decision" -> the verdict string both sides must produce.
CASES = [
    ({"decision": "allow", "reason": "read-only",
      "rule": "reeflex.policy/read_only_internal", "obligations": []}, "allow"),
    ({"decision": "deny", "reason": "irreversible systemic in prod",
      "rule": "reeflex.policy/irreversible_systemic_prod", "obligations": []}, "deny"),
    ({"decision": "require_approval", "reason": "needs a human",
      "rule": "reeflex.policy/irreversible_broad_prod", "obligations": ["notify"],
      "hold_id": "h-1"}, "ask"),
    ({"decision": "probably_fine", "reason": "?", "rule": "x",
      "obligations": []}, "deny"),
]


@pytest.mark.parametrize("body,expected", CASES)
def test_the_duplicated_mapping_agrees_with_reeflex_claudes(body, expected, stub,
                                                            monkeypatch):
    stub.decide_default = (200, body)
    monkeypatch.setenv("REEFLEX_CORE_URL", core.core_url())

    mine = core.decide({"probe": True})
    theirs = claude_enforce.call_core_and_map({"probe": True})

    assert mine.kind == expected
    assert mine.kind == theirs[0], (
        "reeflex-litellm mapped %r as %r while reeflex-claude mapped it as %r "
        "-- the two seats have drifted" % (body["decision"], mine.kind, theirs[0]))
    # THE ONE INTENDED DIFFERENCE, NAMED (RFX-365).  Both seats compose the
    # same facts from the same `enforce.hold_clause`; only reeflex-claude
    # appends the sentence about answering a dialog, because only reeflex-claude
    # has one.  Subtracting it by the exported constant -- rather than loosening
    # this to a substring check -- keeps the assertion exact, so any OTHER drift
    # between the two reason strings still fails here.
    assert mine.reason == theirs[1].replace(
        " " + claude_enforce.LOCAL_DIALOG_CONSEQUENCE, ""), (
        "the two seats' reason strings differ by more than this seat's missing "
        "dialog sentence:\n  litellm: %r\n  claude : %r" % (mine.reason, theirs[1]))
    assert mine.rule == theirs[2]
    assert mine.core_reachable == theirs[3]
    assert mine.obligations == theirs[4]


def test_this_seats_reason_names_the_hold_not_just_agrees(stub, monkeypatch):
    """RFX-318, pinned by BEHAVIOUR here and not only by agreement.

    The agreement test above would stay green if both seats went silent
    together, which is the state this ticket was filed about.  This one asserts
    what the human is actually told, so a regression has to fail something that
    names the defect.
    """
    stub.decide_default = (200, {
        "decision": "require_approval", "reason": "needs a human",
        "rule": "reeflex.policy/irreversible_broad_prod", "obligations": [],
        "hold_id": "h-318", "expires_ts": "2026-09-18T16:17:49Z",
        "decision_id": "d-318",
    })
    monkeypatch.setenv("REEFLEX_CORE_URL", core.core_url())
    monkeypatch.setenv("REEFLEX_PORTAL_URL", "https://portal.example.test")

    mine = core.decide({"probe": True})

    assert mine.kind == "ask"
    assert "h-318" in mine.reason, (
        "the gateway had the hold id in hand and did not tell the human: %r"
        % mine.reason)
    assert "2026-09-18T16:17:49Z" in mine.reason
    assert "https://portal.example.test" in mine.reason
    # The structured fields must keep working -- the hold loop is built on them.
    assert mine.hold_id == "h-318"
    assert mine.expires_ts == "2026-09-18T16:17:49Z"


def test_this_seat_does_not_talk_about_a_dialog_it_does_not_have(stub, monkeypatch):
    """RFX-365 -- the complement of RFX-318, in the seat it was exported to.

    Sharing `hold_clause` is right for the FACTS and was wrong for the sentence
    about answering a dialog: this seat asks nobody.  It withholds the response
    and polls the hold.  Pinned as an ABSENCE, because the regression is an
    addition -- a future edit that re-exports the default consequence here has
    to fail this.
    """
    stub.decide_default = (200, {
        "decision": "require_approval", "reason": "needs a human",
        "rule": "reeflex.policy/irreversible_broad_prod", "obligations": [],
        "hold_id": "h-363", "expires_ts": "2026-09-18T16:17:49Z",
        "decision_id": "d-363",
    })
    monkeypatch.setenv("REEFLEX_CORE_URL", core.core_url())

    mine = core.decide({"probe": True})

    assert claude_enforce.LOCAL_DIALOG_CONSEQUENCE not in mine.reason, (
        "this seat emitted reeflex-claude's dialog sentence: %r" % mine.reason)
    for phrase in ("this dialog", "this terminal", "Answering"):
        assert phrase not in mine.reason, (
            "the gateway's reason names %r, and this seat has no %s: %r"
            % (phrase, phrase, mine.reason))
    # The facts the clause exists for are still there -- this is not a revert.
    assert "h-363" in mine.reason
    assert "2026-09-18T16:17:49Z" in mine.reason


def test_the_inbox_row_next_to_approve_does_not_deny_what_approve_does(stub, monkeypatch):
    """RFX-365, on the screen where the sentence was INVERTED, not just absent.

    `verdict.reason` does not stop at the model.  `ledger_record` puts it on the
    ledger line, `hold_record_from_ledger` carries it onto the
    `POST /api/v1/holds` record, and evidence.py calls that field "the sentence
    a human reads in the inbox next to an Approve button".  The reader of that
    row IS the person resolving the hold; a sentence telling them their answer
    "does not resolve that hold" is the opposite of what their click does.

    Driven through the shipped builders, so this fails if any of them starts
    carrying the clause again.
    """
    from reeflex_litellm import evidence as _evidence
    from reeflex_litellm import normalize as _normalize
    from reeflex_litellm import tenancy as _tenancy

    stub.decide_default = (200, {
        "decision": "require_approval", "reason": "needs a human",
        "rule": "reeflex.policy/irreversible_broad_prod", "obligations": [],
        "hold_id": "h-363", "expires_ts": "2026-09-18T16:17:49Z",
        "decision_id": "d-363",
    })
    monkeypatch.setenv("REEFLEX_CORE_URL", core.core_url())

    verdict = core.decide({"probe": True})
    call = _normalize.normalize_tool_call({
        "id": "call-363", "type": "function",
        "function": {"name": "sql_exec", "arguments": "{}"}})
    envelope = {
        "agent": {"id": "agent-363", "session_id": "sess-363"},
        "action": {"verb": "delete", "ability": "sql_exec"},
        "target": {"system": "orders-db", "environment": "production"},
        "magnitude": {"count": 1},
    }
    ledger = _evidence.ledger_record(
        envelope=envelope, verdict=verdict, outcome_allowed=False,
        gateway_routing={}, call=call, tenant=_tenancy.UNSCOPED,
        hold_id="h-363")
    record = _evidence.hold_record_from_ledger(
        ledger, hold_id="h-363", expires_ts="2026-09-18T16:17:49Z")

    assert "does not resolve that hold" not in record["reason"], (
        "the inbox row tells the approver their approval does not resolve the "
        "hold it is attached to: %r" % record["reason"])
    assert "this dialog" not in record["reason"]
    # Still a useful sentence, not an empty one.
    assert record["reason"].startswith("Reeflex: needs a human")


def test_a_decision_with_no_hold_keeps_the_plain_reason(stub, monkeypatch):
    """An ordinary allow does not grow a clause in this seat either."""
    stub.decide_default = (200, {
        "decision": "allow", "reason": "read-only",
        "rule": "reeflex.policy/read_only_internal", "obligations": []})
    monkeypatch.setenv("REEFLEX_CORE_URL", core.core_url())

    mine = core.decide({"probe": True})

    assert mine.reason == "Reeflex: read-only [rule=reeflex.policy/read_only_internal]"


def test_both_sides_fail_closed_on_the_same_unreachable_core(monkeypatch):
    port = stubcore.unused_port()
    monkeypatch.setenv("REEFLEX_CORE_URL", "http://127.0.0.1:%d" % port)
    monkeypatch.setenv("REEFLEX_LITELLM_TIMEOUT", "1")
    monkeypatch.setenv("REEFLEX_CLAUDE_TIMEOUT", "1")

    mine = core.decide({"probe": True})
    theirs = claude_enforce.call_core_and_map({"probe": True})

    assert mine.kind == "deny" == theirs[0]
    assert mine.rule == theirs[2] == "reeflex.core/fail_closed"
    assert mine.core_reachable is False and theirs[3] is False


def test_the_hold_id_is_the_field_this_package_needed_and_theirs_drops(stub):
    """Names the reason the duplication exists, so nobody 'simplifies' it away."""
    stub.answer_hold(hold_id="hold-xyz")
    mine = core.decide({"probe": True})
    theirs = claude_enforce.call_core_and_map({"probe": True})
    assert mine.hold_id == "hold-xyz"
    assert len(theirs) == 5 and "hold-xyz" not in theirs
