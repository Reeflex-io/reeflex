"""
test_article14_evidence.py -- the evidence record has to say WHO approved.

THE DEFECT THIS FILE PINS
=========================
`wire_record()` used to emit `hold: {"hold_id": ...}` and nothing more, so the
evidence feed carried the fact that a hold existed and never the fact that a
human resolved it. `EVIDENCE-INGEST-SPEC-v1` §4 RESERVES all four fields --
`hold.hold_id`, `hold.parent_decision_id`, `hold.resolution`,
`hold.decided_by.{type,id}` -- and reeflex-app's ingest maps every one of them
onto a column. Nothing was frozen or blocked. They were simply never filled.

Measured consequence, on the live application on 2026-09-08 with TWO REAL UI
APPROVALS inside the reporting period: the Attest report read

    production_holds: 7
    of_those_a_human_decided: 0

and `decided_by_id: null` on every evidence-chain row. The report was right
about its inputs and wrong about the world -- which is the worse of the two
failure modes for a compliance artefact, because nothing in it looks broken.

WHAT THE TESTS BELOW GUARD
  * the four §4 hold fields are present on a released-after-approval record,
    and `parent_decision_id` points at the decision that RAISED the hold and
    not at the resubmission (a self-loop would break §6's chain);
  * `resolution` and `decided_by.type` are validated against §4's ENUMS before
    the request, because an unknown value 422s the WHOLE batch and would take
    other actions' valid evidence down with it;
  * an unreadable hold record NEVER blocks the release -- an evidence gap must
    not become a governance outage;
  * `verified: false` (an approver core could not tie to a credential) is
    carried, not silently dropped, and not silently upgraded either.
"""

from __future__ import annotations

import json

import pytest

import stubcore
from conftest import PAYMENTS_CALLER, caller

from reeflex_litellm import core, enforce, evidence, normalize, tenancy


def a_call():
    return normalize.normalize_tool_call(stubcore.tool_call(
        "call_1", "run_shell", {"command": 'psql -c "DROP TABLE customers"'}))


@pytest.fixture
def tenant(tenancy_map):
    return tenancy.resolve(caller(**PAYMENTS_CALLER)).tenant


def rule_it(tenant, hold_wait=0.0):
    return enforce.rule_one_call(
        a_call(), session_id="s1", model="mock-tools", tenant=tenant,
        hold_wait=hold_wait, gateway_routing={"gateway": "litellm"})


RAISED_ID = "1" * 32          # the decide that created the hold
RESUB_ID = "2" * 32           # the resubmission core allowed


def _approved_run(stub, tenant):
    """A hold raised, approved by a human, and released."""
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "hold_id": "h-a14", "decision_id": RAISED_ID,
               "expires_ts": "2026-09-08T12:00:00Z"}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission",
               "decision_id": RESUB_ID}),
    ]
    stub.approve()
    return rule_it(tenant)


# ---------------------------------------------------------------------------
# the four fields
# ---------------------------------------------------------------------------

def test_the_wire_record_names_the_human_who_approved(stub, tenant):
    out = _approved_run(stub, tenant)
    assert out.allowed is True and out.released_after_approval is True
    wire = evidence.wire_record(out.ledger)
    assert wire["hold"] == {
        "hold_id": "h-a14",
        "parent_decision_id": RAISED_ID,
        "resolution": "approved",
        "decided_by": {"type": "human",
                       "id": "alice.approver@acme.example"},
    }
    # ...and the record's own decision_id is the RESUBMISSION's, so the two
    # ends of the chain are different rows.
    assert wire["decision_id"] == RESUB_ID


def test_parent_decision_id_is_the_raising_decision_not_the_resubmission(
        stub, tenant):
    """A self-loop would make §6's chain unwalkable and look fine."""
    out = _approved_run(stub, tenant)
    assert out.ledger["parent_decision_id"] == RAISED_ID
    assert out.ledger["decision_id"] == RESUB_ID
    assert out.ledger["parent_decision_id"] != out.ledger["decision_id"]


def test_a_pending_hold_carries_only_the_hold_id(stub, tenant):
    """Nobody has decided yet, so there is nothing to say about who did.

    §4 reads an absent field as "not stated". This is the case that must NOT
    grow a `resolution` -- a pending hold recorded as resolved would be a
    fabricated attestation.
    """
    stub.answer_hold(hold_id="h-pending")
    out = rule_it(tenant)
    assert out.allowed is False
    wire = evidence.wire_record(out.ledger)
    assert wire["hold"] == {"hold_id": "h-pending"}
    assert out.ledger["hold_decision"] is None


def test_a_rejected_hold_records_the_rejection_and_the_rejecter(stub, tenant):
    stub.answer_hold(hold_id="h-rej")
    stub.hold_status = "rejected"
    stub.hold_decided_by = "human:alice.approver@acme.example"
    stub.hold_decided_by_verified = True
    out = rule_it(tenant)
    assert out.allowed is False
    assert out.refusal["error"] == enforce.ERROR_REJECTED
    # A rejection is a human decision too, and Article 14 is about oversight
    # being exercised -- not about it saying yes.
    assert out.ledger["hold_decision"]["resolution"] == "rejected"
    wire = evidence.wire_record(out.ledger)
    assert wire["hold"]["resolution"] == "rejected"
    assert wire["hold"]["decided_by"]["id"] == "alice.approver@acme.example"


# ---------------------------------------------------------------------------
# §4's enums, and the closed schema
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["Approved", "approve", "granted", "", None, 1])
def test_a_resolution_outside_sec4s_enum_is_omitted_not_sent(bad):
    """An unknown value 422s the WHOLE batch -- one bad record would take
    every other action's evidence down with it. Omitted is also honest: §4
    reads absent as "not stated", never as "no human"."""
    ledger = _ledger_stub(resolution=bad)
    wire = evidence.wire_record(ledger)
    assert "resolution" not in wire["hold"], bad
    # the hold id and the chain key still travel
    assert wire["hold"]["hold_id"] == "h-x"


@pytest.mark.parametrize("bad", ["Human", "person", "automation", "", None])
def test_a_decided_by_type_outside_sec4s_enum_is_omitted_not_sent(bad):
    ledger = _ledger_stub(decided_by={"type": bad, "id": "a@b.example"})
    wire = evidence.wire_record(ledger)
    assert "decided_by" not in wire["hold"], bad


def test_an_empty_approver_id_is_omitted(stub, tenant):
    ledger = _ledger_stub(decided_by={"type": "human", "id": "   "})
    wire = evidence.wire_record(ledger)
    assert "decided_by" not in wire["hold"]


def test_CONTROL_the_hold_block_allowlist_rejects_an_undefined_field():
    """CONTROL: the §4 hold-block check has to refuse something.

    `verified` is the exact field this code would most plausibly leak: the
    adapter reads it off core's record and carries it on the LEDGER, and §4
    has no home for it.
    """
    wire = evidence.wire_record(_ledger_stub())
    wire["hold"]["verified"] = True
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.assert_wire_is_spec_clean(wire)
    assert "verified" in str(exc.value)


def test_CONTROL_the_decided_by_allowlist_rejects_an_undefined_field():
    wire = evidence.wire_record(_ledger_stub())
    wire["hold"]["decided_by"]["email"] = "a@b.example"
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.assert_wire_is_spec_clean(wire)
    assert "email" in str(exc.value)


def test_verified_false_is_carried_on_the_ledger_and_not_upgraded(stub, tenant):
    """An approver core could not tie to a credential is a WEAK attestation.

    It is recorded as one -- on the ledger, where the flag has a home -- and
    the §4 record says the same thing it says for a verified approver, because
    §4 has no field for the distinction. That asymmetry is real and it is why
    the flag is kept locally rather than dropped: a consumer of the ledger can
    tell, a consumer of the wire cannot, and pretending otherwise in either
    direction would be the overclaim.
    """
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "hold_id": "h-unverified", "decision_id": RAISED_ID}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission",
               "decision_id": RESUB_ID}),
    ]
    stub.approve(who="human:someone@acme.example", verified=False)
    out = rule_it(tenant)
    assert out.allowed is True
    assert out.ledger["hold_decision"]["verified"] is False
    wire = evidence.wire_record(out.ledger)
    assert wire["hold"]["decided_by"]["id"] == "someone@acme.example"
    assert "verified" not in wire["hold"]


# ---------------------------------------------------------------------------
# an evidence gap must never become a governance outage
# ---------------------------------------------------------------------------

def test_an_unreadable_hold_record_does_not_block_the_release(stub, tenant,
                                                              monkeypatch):
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "hold_id": "h-blind", "decision_id": RAISED_ID}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission",
               "decision_id": RESUB_ID}),
    ]
    stub.approve()
    monkeypatch.setattr(core, "hold_decision",
                        lambda hold_id: (None, "core said no"))
    out = rule_it(tenant)
    assert out.allowed is True, "an evidence read failure blocked a release"
    assert out.ledger["hold_decision"] is None
    wire = evidence.wire_record(out.ledger)
    # The chain key survives -- it comes from the verdict, not from the hold
    # record -- so the row is still joinable even with the approver unknown.
    assert wire["hold"] == {"hold_id": "h-blind",
                            "parent_decision_id": RAISED_ID}


@pytest.mark.parametrize("body,why", [
    ({"status": "approved"}, "no decided_by at all"),
    ({"status": "approved", "decided_by": "alice"}, "no ':' separator"),
    ({"status": "approved", "decided_by": "human:"}, "empty id"),
    ({"status": "approved", "decided_by": ":alice"}, "empty type"),
    ({"status": "approved", "decided_by": 42}, "not a string"),
])
def test_hold_decision_refuses_to_invent_an_approver(stub, body, why):
    """Every shape core could return that is not an identity -> (None, error).

    Guessing here would mint an attestation, which is the whole class of defect
    verified approvers exist to close.
    """
    stub.hold_http = (200, body)
    decision, err = core.hold_decision("h-1")
    assert decision is None, why
    assert err


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------

def _ledger_stub(resolution="approved",
                 decided_by=None, parent_decision_id=RAISED_ID):
    """A minimal ledger line, for the projection tests that need no HTTP."""
    return {
        "decision_id": RESUB_ID, "verdict": "allow",
        "rule": "reeflex.policy/approved_resubmission",
        "envelope_hash": "e" * 64, "occurred_ts": "2026-09-08T08:00:00Z",
        "action": {"verb": "delete", "target_environment": "production",
                   "namespace": "litellm-gateway"},
        "magnitude": {"count": 1},
        "agent_id": "agent:litellm-gateway/acme-payments/mock-tools",
        "hold_id": "h-x", "parent_decision_id": parent_decision_id,
        "hold_decision": {
            "resolution": resolution,
            "decided_by": decided_by if decided_by is not None
            else {"type": "human", "id": "alice.approver@acme.example"},
            "verified": True},
    }
