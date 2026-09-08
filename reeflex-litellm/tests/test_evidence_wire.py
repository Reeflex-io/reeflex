"""
The evidence record: what an Attest report may and may not be told (RFX-243).

THE OVERCLAIM THIS FILE EXISTS TO PREVENT
=========================================
This seat sees a tool call PROPOSED and removes it from the response. It does
NOT see the tool execute, and it cannot stop an application that kept its own
copy of the model's output. The Claude Code hook and the WordPress gate run
where the effect happens, so a refusal there IS the effect not happening.

If both seats' records look the same, a report that counts them says "N actions
prevented" over a population where some were only ever un-suggested. Every test
below defends one half of that distinction.

AND THE FROZEN WIRE
===================
`docs/EVIDENCE-INGEST-SPEC-v1.md` §4 is a CLOSED schema -- "unknown top-level
keys -> 422 (fail closed -- never store un-vetted data)" -- and the contract is
FROZEN. So `gateway_routing` and `enforcement_stage` have no home on it. They
are NOT sent, they live in the adapter's own ledger, and the gap is flagged
rather than closed by editing a deployed contract. The tests here pin that the
adapter cannot grow a §4 violation by accident, WITH a control that proves the
guard fires rather than merely being present.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys

import pytest

from reeflex_litellm import core as C
from reeflex_litellm import enforce, evidence, normalize, routing, tenancy

import conftest
import stubcore


def a_call(name="run_shell", args=None, call_id="call_1"):
    return normalize.normalize_tool_call(stubcore.tool_call(
        call_id, name, args if args is not None
        else {"command": "rm -rf ./build"}))


def an_envelope(tenant=None):
    return enforce._envelope.build_gateway_envelope(
        session_id="s-1", model="mock-tools", call=a_call(),
        tenant=tenant or tenancy.UNSCOPED,
        gateway_routing={"gateway": "litellm", "placement": "on_prem"})


def a_verdict(decision="deny", rule="reeflex.policy/irreversible_systemic_prod"):
    return C.Verdict("deny" if decision == "deny" else "allow",
                     decision=decision, rule=rule, reason="because",
                     decision_id=stubcore.DECISION_ID)


def a_ledger(outcome_allowed=False, **kw):
    kw.setdefault("envelope", an_envelope())
    kw.setdefault("verdict", a_verdict())
    kw.setdefault("gateway_routing", {"gateway": "litellm",
                                      "placement": "on_prem"})
    kw.setdefault("call", a_call())
    kw.setdefault("tenant", tenancy.UNSCOPED)
    return evidence.ledger_record(outcome_allowed=outcome_allowed, **kw)


# ---------------------------------------------------------------------------
# The stage vocabulary: this seat records a proposal, never a prevention
# ---------------------------------------------------------------------------

def test_a_refused_call_records_refused_at_gateway():
    rec = a_ledger(outcome_allowed=False)
    assert rec["enforcement_stage"] == "refused_at_gateway"


def test_an_allowed_call_records_allowed_at_gateway():
    rec = a_ledger(outcome_allowed=True)
    assert rec["enforcement_stage"] == "allowed_at_gateway"


def test_every_record_says_it_observed_a_PROPOSAL():
    for allowed in (True, False):
        rec = a_ledger(outcome_allowed=allowed)
        assert rec["observed"] == "proposal"


def test_every_record_says_explicitly_that_it_prevents_nothing():
    """Machine-readable, so a consumer never has to infer this seat's reach
    from the adapter name. A report totalling `prevents_execution` cannot
    accidentally count a gateway refusal as a prevented execution."""
    for allowed in (True, False):
        assert a_ledger(outcome_allowed=allowed)["prevents_execution"] is False


def test_this_seat_cannot_emit_prevented_at_execution():
    """The vocabulary is SHARED with the seats that do prevent execution, so
    the string exists -- and this adapter must be unable to write it. A runtime
    guard rather than a comment, because the failure mode is silent: a record
    saying `prevented_at_execution` reads as stronger evidence than it is."""
    with pytest.raises(ValueError) as exc:
        evidence.assert_never_claims_prevention(
            evidence.STAGE_PREVENTED_AT_EXECUTION)
    assert "sees a tool call PROPOSED" in str(exc.value)


def test_the_prevention_stage_is_defined_so_the_two_seats_share_one_vocabulary():
    assert evidence.STAGE_PREVENTED_AT_EXECUTION == "prevented_at_execution"
    assert evidence.STAGE_PREVENTED_AT_EXECUTION not in \
        evidence.STAGES_THIS_SEAT_CAN_EMIT


def test_the_caller_visible_stage_and_the_ledger_stage_are_the_same_string():
    """A caller matching on `stage` in the refusal payload and a report
    counting `enforcement_stage` rows must be reading the same fact. Two
    string literals in two modules is how that silently stops being true."""
    assert enforce.STAGE == evidence.STAGE_REFUSED_AT_GATEWAY
    payload = enforce.refusal(a_call(), "reeflex_denied", "r", "reason")
    assert payload["stage"] == a_ledger()["enforcement_stage"]


# ---------------------------------------------------------------------------
# The §4 wire: a closed allowlist, with a control
# ---------------------------------------------------------------------------

def test_the_wire_record_carries_only_fields_section_4_defines():
    wire = evidence.wire_record(a_ledger())
    assert set(wire) <= evidence.WIRE_TOP_LEVEL_FIELDS
    assert set(wire["action"]) <= evidence.WIRE_ACTION_FIELDS


def test_the_allowlist_matches_the_frozen_spec_field_for_field():
    """Pinned as a literal, because the value of a closed allowlist is that it
    does not quietly grow. §4's top-level keys, transcribed."""
    assert evidence.WIRE_TOP_LEVEL_FIELDS == {
        "decision_id", "verdict", "rule", "envelope_hash", "occurred_ts",
        "action", "magnitude", "agent_id", "traceparent", "hold", "sig_alg"}


def test_gateway_routing_never_reaches_the_wire():
    """THE FROZEN-CONTRACT ANSWER. The ledger has it; §4 has no field for it;
    the server would answer 422. So it is not sent."""
    ledger = a_ledger()
    assert ledger["gateway_routing"]          # it IS recorded locally
    wire = evidence.wire_record(ledger)
    assert "gateway_routing" not in wire
    assert "gateway_routing" not in json.dumps(wire)


def test_enforcement_stage_never_reaches_the_wire():
    ledger = a_ledger()
    assert ledger["enforcement_stage"]
    wire = evidence.wire_record(ledger)
    assert "enforcement_stage" not in wire
    for forbidden in ("observed", "prevents_execution", "tenant_org"):
        assert forbidden not in wire


def test_a_new_ledger_key_cannot_reach_the_wire_by_default():
    """The projection NAMES each §4 field rather than filtering the ledger, so
    a future ledger addition is absent from the wire by construction -- not by
    someone remembering to exclude it."""
    ledger = a_ledger()
    ledger["some_field_a_later_round_adds"] = "value"
    wire = evidence.wire_record(ledger)
    assert "some_field_a_later_round_adds" not in wire


def test_the_spec_clean_guard_ACTUALLY_FIRES_on_an_unknown_key():
    """THE CONTROL. Every assertion above is "the field is absent", which would
    also pass if the guard were a no-op and the projection simply never added
    it. This proves the guard itself rejects a §4 violation -- so the tests
    above are testing a mechanism, not an omission."""
    wire = evidence.wire_record(a_ledger())
    wire["gateway_routing"] = {"placement": "on_prem"}
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.assert_wire_is_spec_clean(wire)
    assert "gateway_routing" in str(exc.value)
    assert "FROZEN" in str(exc.value)


def test_the_spec_clean_guard_fires_on_an_unknown_ACTION_key():
    wire = evidence.wire_record(a_ledger())
    wire["action"]["arguments"] = {"command": "rm -rf /"}
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.assert_wire_is_spec_clean(wire)
    assert "arguments" in str(exc.value)


def test_push_re_checks_every_record_before_sending_it(monkeypatch):
    """The guard runs on the way out too, so a record built by any other path
    cannot reach the network un-vetted. Asserted by handing `push()` a dirty
    record and observing it fail WITHOUT a request being made."""
    called = []
    monkeypatch.setattr(evidence.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    monkeypatch.setenv("RFX_T", "tok")
    monkeypatch.setenv("RFX_K", "11" * 32)
    tenant = tenancy.Tenant(org="o", evidence={
        "ingest_url": "http://127.0.0.1:1/x", "gate_token_env": "RFX_T",
        "signing_key_env": "RFX_K"})
    dirty = evidence.wire_record(a_ledger())
    dirty["gateway_routing"] = {"placement": "cloud"}
    result = evidence.push([dirty], tenant)
    assert result.ok is False
    assert called == [], "a §4-violating record was put on the wire"


def test_a_record_missing_a_required_field_is_refused_not_sent():
    """§4 makes five fields required. Sending a record without one earns a 422
    the connector contract says not to retry, so it is caught here instead."""
    ledger = a_ledger()
    ledger["decision_id"] = None
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.wire_record(ledger)
    assert "decision_id" in str(exc.value)


def test_the_decision_id_comes_from_core_and_is_not_invented_locally(stub,
                                                                     tenancy_map):
    """§6 makes `decision_id` the idempotency key. A locally-minted one would
    make the same decision arriving via core's audit log look like a second
    event."""
    stub.answer_deny()
    outcome = enforce.rule_one_call(
        a_call(), session_id="s", model="m",
        tenant=tenancy.resolve(conftest.caller(team_id="team_pay")).tenant)
    assert outcome.ledger["decision_id"] == stubcore.DECISION_ID


def test_the_hold_id_is_wrapped_the_way_section_4_nests_it():
    ledger = a_ledger(hold_id="hold-7")
    wire = evidence.wire_record(ledger)
    assert wire["hold"] == {"hold_id": "hold-7"}


def test_target_system_falls_back_to_the_namespace_like_the_connector_does():
    """§4.2: core has a first-class `target_system` only from v0.1.13; until
    then the connector derives it from `action.namespace`, and this adapter
    must derive it the same way or two feeds disagree about one action."""
    ledger = a_ledger()
    ledger["action"]["target_system"] = None
    wire = evidence.wire_record(ledger)
    assert wire["action"]["target_system"] == "litellm-gateway"


def test_magnitude_is_a_count_and_never_the_records_themselves():
    """§1: metadata only. R5 charges `magnitude.count` (and only that), so the
    count is both the sufficient and the maximum honest carry."""
    wire = evidence.wire_record(a_ledger())
    assert set(wire["magnitude"]) == {"count"}
    assert isinstance(wire["magnitude"]["count"], int)


# ---------------------------------------------------------------------------
# The integrity anchor
# ---------------------------------------------------------------------------

CORE_SRC = pathlib.Path(__file__).resolve().parents[2] / "reeflex-core"


@pytest.mark.skipif(not (CORE_SRC / "app" / "holds.py").exists(),
                    reason="reeflex-core source is not alongside this package "
                           "(installed from a wheel rather than the monorepo)")
def test_the_envelope_hash_agrees_with_the_core_that_will_verify_it():
    """NOT a transcribed constant -- core's OWN `canonical_hash()` is imported
    and run over the same envelope.

    This adapter cannot import core (it is a separate package), so the
    projection is duplicated. A duplicate that drifts would produce an
    `envelope_hash` that fails to match the hold core stored, and the
    approval-resubmission path would break for every gateway caller.
    """
    sys.path.insert(0, str(CORE_SRC))
    try:
        from app import holds as core_holds
    finally:
        sys.path.remove(str(CORE_SRC))

    assert set(evidence._HASH_ALLOWLIST) == set(core_holds._HASH_ALLOWLIST)
    env = an_envelope()
    assert evidence.envelope_hash(env) == core_holds.canonical_hash(env)


def test_context_is_outside_the_hash_so_routing_cannot_move_a_hold_binding():
    """`gateway_routing` rides on `envelope.context`. Core's projection is
    {action, axes, magnitude, target}, so adding it must NOT change the hash --
    otherwise every RFX-243 envelope would fail to match a hold raised by an
    older build, and approvals would silently stop being spendable."""
    bare = an_envelope()
    routed = copy.deepcopy(bare)
    routed["context"]["gateway_routing"] = {"placement": "cloud",
                                            "model_served": "gpt-4o"}
    routed["context"]["tenancy"] = {"org": "acme-payments"}
    assert evidence.envelope_hash(bare) == evidence.envelope_hash(routed)


def test_the_hash_changes_when_the_ACTION_changes():
    """The control for the row above: a projection that ignored everything
    would also make context irrelevant."""
    a = an_envelope()
    b = copy.deepcopy(a)
    b["action"]["verb"] = "read"
    assert evidence.envelope_hash(a) != evidence.envelope_hash(b)


# ---------------------------------------------------------------------------
# §5 signing and canonicalization
# ---------------------------------------------------------------------------

def test_the_signature_is_hmac_sha256_over_the_timestamped_canonical_body():
    """§5, verbatim: HMAC-SHA256 over `"<ts>.\\n" + canonical_json(body)`."""
    import hashlib
    import hmac
    body = evidence.canonical_body([{"a": 1}])
    key = bytes.fromhex("33" * 32)
    expected = hmac.new(key, b"1757000000.\n" + body, hashlib.sha256).hexdigest()
    assert evidence.sign(body, 1757000000, key) == expected


def test_the_canonical_body_sorts_keys_at_every_level_with_no_whitespace():
    """§5.1: client and server MUST agree byte-for-byte."""
    body = evidence.canonical_body([{"b": 1, "a": {"d": 2, "c": 3}}])
    assert body == b'[{"a":{"c":3,"d":2},"b":1}]'
    assert not body.endswith(b"\n")


def test_two_orderings_of_the_same_record_sign_identically():
    one = evidence.canonical_body([{"a": 1, "b": 2}])
    two = evidence.canonical_body([{"b": 2, "a": 1}])
    assert one == two


# ---------------------------------------------------------------------------
# Credentials: by reference, never by value
# ---------------------------------------------------------------------------

def test_credentials_are_read_from_the_env_vars_the_map_NAMES(monkeypatch):
    monkeypatch.setenv("RFX_T", "tok-abc")
    monkeypatch.setenv("RFX_K", "44" * 32)
    t = tenancy.Tenant(org="o", evidence={"ingest_url": "https://x/y",
                                          "gate_token_env": "RFX_T",
                                          "signing_key_env": "RFX_K"})
    creds = evidence.credentials_for(t)
    assert creds.gate_token == "tok-abc"
    assert creds.signing_key == bytes.fromhex("44" * 32)


def test_a_missing_credential_error_names_the_variable_never_its_value(
        monkeypatch):
    monkeypatch.setenv("RFX_T", "")
    monkeypatch.setenv("RFX_K", "44" * 32)
    t = tenancy.Tenant(org="o", evidence={"ingest_url": "https://x/y",
                                          "gate_token_env": "RFX_T",
                                          "signing_key_env": "RFX_K"})
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.credentials_for(t)
    assert "RFX_T" in str(exc.value)
    assert "44" * 32 not in str(exc.value)


def test_the_credentials_repr_prints_neither_secret(monkeypatch):
    monkeypatch.setenv("RFX_T", "tok-abc")
    monkeypatch.setenv("RFX_K", "44" * 32)
    t = tenancy.Tenant(org="o", evidence={"ingest_url": "https://x/y",
                                          "gate_token_env": "RFX_T",
                                          "signing_key_env": "RFX_K"})
    text = repr(evidence.credentials_for(t))
    assert "tok-abc" not in text
    assert "44" * 32 not in text
    assert "redacted" in text


def test_a_signing_key_of_the_wrong_length_is_refused(monkeypatch):
    """§5/RFX-44 hands the operator a DERIVED 32-byte key. A 16-byte value is
    someone pasting the wrong secret, and it would sign batches the gate then
    rejects -- an evidence outage that looks like a network problem."""
    monkeypatch.setenv("RFX_T", "tok")
    monkeypatch.setenv("RFX_K", "44" * 16)
    t = tenancy.Tenant(org="o", evidence={"ingest_url": "https://x/y",
                                          "gate_token_env": "RFX_T",
                                          "signing_key_env": "RFX_K"})
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.credentials_for(t)
    assert "32" in str(exc.value)


def test_a_non_hex_signing_key_is_refused_with_the_spec_reference(monkeypatch):
    monkeypatch.setenv("RFX_T", "tok")
    monkeypatch.setenv("RFX_K", "not-hex-at-all")
    t = tenancy.Tenant(org="o", evidence={"ingest_url": "https://x/y",
                                          "gate_token_env": "RFX_T",
                                          "signing_key_env": "RFX_K"})
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.credentials_for(t)
    assert "not-hex-at-all" not in str(exc.value)
    assert "REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY" in str(exc.value)


# ---------------------------------------------------------------------------
# The ledger: durable, and never able to break a decision
# ---------------------------------------------------------------------------

def test_the_ledger_is_disabled_when_no_path_is_configured():
    assert evidence.append_ledger(a_ledger(), path="") is None


def test_an_unwritable_ledger_returns_None_instead_of_raising(tmp_path):
    """"audit failure != deny". An evidence write that raised on the response
    path would let a full disk deny traffic core allowed."""
    assert evidence.append_ledger(a_ledger(),
                                  path=str(tmp_path / "no" / "such" / "d.jsonl")) is None


def test_the_ledger_appends_one_json_object_per_line(tmp_path):
    path = tmp_path / "l.jsonl"
    evidence.append_ledger(a_ledger(), path=str(path))
    evidence.append_ledger(a_ledger(outcome_allowed=True), path=str(path))
    lines = [json.loads(l) for l in
             path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert [l["enforcement_stage"] for l in lines] == ["refused_at_gateway",
                                                       "allowed_at_gateway"]
    assert all(l["schema"] == "reeflex-litellm/decision-ledger/v1"
               for l in lines)


def test_a_push_that_fails_returns_the_failure_and_never_raises(monkeypatch):
    """An ingest outage must not become an exception on the response path."""
    monkeypatch.setenv("RFX_T", "tok")
    monkeypatch.setenv("RFX_K", "55" * 32)
    t = tenancy.Tenant(org="o", evidence={
        # port 1: nothing listens, so this is a real connection failure
        "ingest_url": "http://127.0.0.1:1/api/v1/evidence",
        "gate_token_env": "RFX_T", "signing_key_env": "RFX_K"})
    result = evidence.push([evidence.wire_record(a_ledger())], t)
    assert result.ok is False
    assert result.error
    assert result.org == "o"


def test_pushing_nothing_is_a_success_not_an_error():
    assert evidence.push([], tenancy.Tenant(org="o")).ok is True


# ---------------------------------------------------------------------------
# What the ledger records about routing
# ---------------------------------------------------------------------------

def test_the_ledger_carries_the_routing_block_the_wire_cannot(stub,
                                                              tenancy_map,
                                                              tmp_path,
                                                              monkeypatch):
    """End to end: the two facts §4 has no home for are durably recorded."""
    monkeypatch.setenv("REEFLEX_LITELLM_LEDGER_PATH", str(tmp_path / "l.jsonl"))
    stub.answer_deny()
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    gr = routing.build(
        data={"model": "gpt-4o-mini", "stream": False},
        response={"model": "gpt-4o-mini-2024",
                  "_hidden_params": {"api_base":
                                     "https://llm.internal.acme.example/v1",
                                     "model_id": "dep-7"}},
        tenant=tenant, identity=tenancy.read_identity(
            conftest.caller(team_id="team_pay", key_alias="payments-bot")),
        model="gpt-4o-mini")
    outcome = enforce.rule_one_call(a_call(), session_id="s", model="gpt-4o-mini",
                                    tenant=tenant, gateway_routing=gr)
    rec = outcome.ledger
    assert rec["enforcement_stage"] == "refused_at_gateway"
    assert rec["gateway_routing"]["placement"] == "on_prem"
    assert rec["gateway_routing"]["model_served"] == "gpt-4o-mini-2024"
    assert rec["gateway_routing"]["caller"]["key_alias"] == "payments-bot"
    assert rec["tenant_org"] == "acme-payments"
    # ...and none of it survives the §4 projection.
    assert "gateway_routing" not in evidence.wire_record(rec)
