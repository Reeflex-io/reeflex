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
    assert mine.reason == theirs[1]
    assert mine.rule == theirs[2]
    assert mine.core_reachable == theirs[3]
    assert mine.obligations == theirs[4]


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
