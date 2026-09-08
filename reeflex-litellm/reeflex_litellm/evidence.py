"""
evidence.py -- the seat's AUDIT responsibility (SPEC §6.4), and the one line an
Attest report must not be allowed to overclaim.

THE CLAIM THIS MODULE EXISTS TO PREVENT
=======================================
A gateway sees a tool call PROPOSED.  It removes the instruction from the
response the caller receives.  It does NOT see the tool execute and cannot stop
an application that kept its own copy of the model's output, or that reads the
structured refusal and runs the tool anyway.

The Claude Code hook and the WordPress gate sit at the other end: they run
where the effect happens, and a refusal there is the effect not happening.

Both produce a decision record.  If the two records are the same shape, a report
that counts them says "N actions prevented" over a population where some were
only ever un-suggested.  That is the overclaim, and it is exactly the kind the
claims canon forbids.  So every record this module writes carries:

    enforcement_stage   refused_at_gateway | allowed_at_gateway
    observed            "proposal"
    prevents_execution  false

`prevented_at_execution` is DEFINED here and is never emitted by this adapter.
It is in the vocabulary so the two seats share one, and `assert_never_claims_
prevention()` is a runtime guard, not a comment: `ledger_record()` raises if a
caller ever hands it that stage.

WHERE EACH FIELD CAN AND CANNOT GO -- MEASURED, NOT ASSUMED
===========================================================
There are two destinations and they have opposite rules.

1. THE ADAPTER'S OWN LEDGER (`ledger_record()`), a local append-only JSONL.
   This adapter owns it.  `gateway_routing` and `enforcement_stage` live here
   in full.

2. THE EVIDENCE INGEST WIRE (`wire_record()`), `POST /api/v1/evidence`,
   governed by `docs/EVIDENCE-INGEST-SPEC-v1.md` -- **FROZEN**.

   §4's schema is CLOSED: "The server validates against the closed schema
   above; unknown top-level keys -> 422 (fail closed -- never store un-vetted
   data)."  There is no §4 field for a routing block and none for an
   enforcement stage.

   SO `gateway_routing` AND `enforcement_stage` CANNOT GO ON THE WIRE, and this
   module does not try.  Adding them would need a §4 schema change, which is a
   change to a frozen wire contract with deployed gates -- flagged for the spec
   owner (RFX-246), not made here.  `wire_record()` is a CLOSED ALLOWLIST built
   from §4's field list, and `assert_wire_is_spec_clean()` re-checks its own
   output against that list on every call, so this module cannot grow a §4
   violation by accident.

   WHAT DOES REACH AN ATTEST REPORT, AND IT IS ONE FIELD.  `agent_id` is §4's
   only adapter-controlled identity field: core's `audit.record()` writes
   `agent_id` from `envelope.agent.id`, and the connector's `map_decision()`
   copies it to the wire.  This adapter's `agent.id` is
   `agent:litellm-gateway/<org>/<model>`, so a report row sourced from this seat
   NAMES the gateway seat in a field a reader already has.  That is the maximum
   honest carry inside the frozen contract.  It is a weaker signal than a stage
   field -- it says where the decision was made, not what the decision achieved
   -- and that gap is stated in the README rather than papered over.

SIGNING
=======
§5, unchanged and not reimplemented loosely: HMAC-SHA256 over
`"<ts>.\\n" + canonical_json(body)`, header
`X-Reeflex-Signature: hmac-sha256=<lowercase-hex>`, canonicalization per §5.1
(UTF-8, keys sorted at every level, compact separators, no trailing newline).

The signing key is the DERIVED 32 bytes the app hands the operator as
`REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY` at gate registration (§5, RFX-44), so
this adapter never needs `EVIDENCE_HMAC_PEPPER` -- on a hosted deployment that
pepper belongs to the platform and a customer could never legitimately hold it.

CREDENTIALS ARE BY REFERENCE.  The tenancy map names ENVIRONMENT VARIABLES
(`gate_token_env`, `signing_key_env`); it never carries a value, and
`tenancy.parse_map()` refuses a map that does.  Nothing in this module writes a
token or a key into the ledger, a log line or an exception message.

TENANCY IS ENFORCED BY THE SERVER, NOT BY THIS FILE
===================================================
§3: the gate token resolves `(gate_id, org_id)` server-side and "a record may
not name a different org".  So isolation between two departments behind one
gateway is NOT this module choosing an org id to write -- there is no org field
on the wire to write.  It is this module choosing WHICH GATE TOKEN signs the
batch.  Two keys -> two tenants -> two gate tokens -> two orgs -> Postgres
row-level security on `org_id` in reeflex-app keeps them apart.  That is where
the isolation lives, and it is the reason the isolation test in
`tests/test_tenancy_isolation.py` asserts on the credential presented, not on a
field in the payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from . import tenancy as _tenancy

SIG_ALG_V1 = "hmac-sha256"

# The enforcement-stage vocabulary, shared with every other Reeflex seat.
STAGE_ALLOWED_AT_GATEWAY = "allowed_at_gateway"
STAGE_REFUSED_AT_GATEWAY = "refused_at_gateway"
# Defined, never emitted here.  See the module docstring.
STAGE_PREVENTED_AT_EXECUTION = "prevented_at_execution"

STAGES_THIS_SEAT_CAN_EMIT = frozenset({STAGE_ALLOWED_AT_GATEWAY,
                                       STAGE_REFUSED_AT_GATEWAY})

OBSERVED_PROPOSAL = "proposal"

LEDGER_PATH_ENV = "REEFLEX_LITELLM_LEDGER_PATH"
PUSH_ENV = "REEFLEX_LITELLM_EVIDENCE_PUSH"
TIMEOUT_ENV = "REEFLEX_LITELLM_EVIDENCE_TIMEOUT"
DEFAULT_TIMEOUT = 5.0

# EVIDENCE-INGEST-SPEC-v1 §4, verbatim.  Top-level keys only; the nested shapes
# are built explicitly below.  `wire_record()` asserts its output against this.
WIRE_TOP_LEVEL_FIELDS = frozenset({
    "decision_id", "verdict", "rule", "envelope_hash", "occurred_ts",
    "action", "magnitude", "agent_id", "traceparent", "hold", "sig_alg",
})
WIRE_ACTION_FIELDS = frozenset({"verb", "target_system", "target_environment"})
# §4's `hold` block. All four are DEFINED BY §4 -- filling them is not a spec
# change, it is sending fields the frozen contract already reserves and the
# ingest already maps onto columns (`parent_decision_id`, `resolution`,
# `decided_by_type`, `decided_by_id` in reeflex-app's evidence table).
WIRE_HOLD_FIELDS = frozenset({"hold_id", "parent_decision_id", "resolution",
                              "decided_by"})
WIRE_DECIDED_BY_FIELDS = frozenset({"type", "id"})

# The PENDING-HOLD wire, `POST /api/v1/holds` (CONTRACT holds-v1), which is a
# DIFFERENT closed schema from §4 and a different route.  Same discipline: an
# allowlist, an explicit builder, and a re-check before the request.
#
# WHY THIS ROUTE EXISTS SEPARATELY FROM THE EVIDENCE ROUTE, measured 2026-09-08
# against the deployed `reeflex-app:main-dbfe954`: the evidence ingest stores
# `hold.hold_id` ON the evidence row and creates NO `pending_holds` row --
# `PendingHold(...)` is constructed in exactly one place in that codebase, the
# `/api/v1/holds` handler.  No `pending_holds` row means no hold in the inbox
# and no Approve control.  So an adapter that pushes only evidence has recorded
# that a human was asked and has not actually asked one.
HOLD_TOP_LEVEL_FIELDS = frozenset({
    "hold_id", "decision_id", "verb", "target_system", "target_environment",
    "magnitude_count", "rule", "agent_id", "envelope_hash", "reason",
    "created_ts", "expires_ts", "sig_alg",
})
HOLD_REQUIRED_FIELDS = ("hold_id", "decision_id", "verb", "target_environment",
                        "rule", "envelope_hash", "created_ts")
HOLDS_PUSH_ENV = "REEFLEX_LITELLM_HOLDS_PUSH"

# §4's enums for the hold block. Anything else is omitted rather than sent:
# the ingest validates against a closed schema and an unknown value rejects
# the WHOLE batch, taking valid evidence down with the invalid record.
HOLD_RESOLUTIONS = frozenset({"approved", "rejected", "expired"})
DECIDED_BY_TYPES = frozenset({"human", "agent"})

# §4's projection for the integrity anchor, matching reeflex-core's
# `holds.canonical_hash()` (`_HASH_ALLOWLIST` in reeflex-core/app/holds.py).
# Duplicated because an adapter cannot import core -- they are separate
# packages -- and pinned by tests/test_evidence_wire.py, which imports core's
# OWN `canonical_hash()` from the monorepo source and asserts both the
# allowlist and the resulting digest agree over the same envelope.  That test
# SKIPS when core's source is not alongside this package (installed from a
# wheel), so it is a monorepo-CI pin, not a runtime guarantee.
_HASH_ALLOWLIST = ("action", "axes", "magnitude", "target")


class EvidenceConfigError(ValueError):
    """A tenant's evidence credentials are missing or unusable."""


# ---------------------------------------------------------------------------
# The integrity anchor
# ---------------------------------------------------------------------------

def envelope_hash(envelope: dict) -> str:
    """sha256 of the action-defining projection -- core's `canonical_hash()`."""
    projection = {k: envelope[k] for k in _HASH_ALLOWLIST if k in envelope}
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The adapter's own ledger record -- the full truth
# ---------------------------------------------------------------------------

def assert_never_claims_prevention(stage: str) -> None:
    """Refuse to write a record claiming this seat prevented an execution.

    A runtime guard rather than a comment because the failure mode is silent:
    a record that says `prevented_at_execution` reads as stronger evidence than
    it is, and nothing downstream can tell it was written by a seat that only
    ever saw a proposal.
    """
    if stage not in STAGES_THIS_SEAT_CAN_EMIT:
        raise ValueError(
            "reeflex-litellm cannot emit enforcement_stage=%r: this seat sees a "
            "tool call PROPOSED, not executed, so it may only record %s. "
            "See evidence.py's module docstring."
            % (stage, " or ".join(sorted(STAGES_THIS_SEAT_CAN_EMIT))))


def ledger_record(*, envelope: dict, verdict, outcome_allowed: bool,
                  gateway_routing: dict, call, tenant, hold_id=None,
                  released_after_approval: bool = False,
                  refusal: Optional[dict] = None,
                  occurred_ts: Optional[str] = None,
                  hold_announced: Optional[str] = None,
                  hold_decision: Optional[dict] = None,
                  parent_decision_id: Optional[str] = None) -> dict:
    """One line of the adapter's own append-only decision ledger.

    A SUPERSET of the wire record: it carries everything the wire cannot
    (§4 is a closed schema), and it is the only place `gateway_routing` and
    `enforcement_stage` are recorded durably today.
    """
    stage = (STAGE_ALLOWED_AT_GATEWAY if outcome_allowed
             else STAGE_REFUSED_AT_GATEWAY)
    assert_never_claims_prevention(stage)

    return {
        "schema": "reeflex-litellm/decision-ledger/v1",
        "decision_id": getattr(verdict, "decision_id", None),
        "verdict": getattr(verdict, "decision", "") or "",
        "rule": getattr(verdict, "rule", "unknown"),
        "reason": getattr(verdict, "reason", ""),
        "envelope_hash": envelope_hash(envelope),
        "occurred_ts": occurred_ts or _rfc3339_now(),
        "agent_id": (envelope.get("agent") or {}).get("id"),
        "session_id": (envelope.get("agent") or {}).get("session_id"),
        "action": {
            "verb": (envelope.get("action") or {}).get("verb"),
            "ability": (envelope.get("action") or {}).get("ability"),
            "namespace": (envelope.get("action") or {}).get("namespace"),
            "target_system": (envelope.get("target") or {}).get("system"),
            "target_environment": (envelope.get("target") or {}).get("environment"),
        },
        "magnitude": envelope.get("magnitude"),
        "axes": envelope.get("axes"),

        # --- the two facts §4 has no home for -------------------------------
        "enforcement_stage": stage,
        "observed": OBSERVED_PROPOSAL,
        # Explicit and machine-readable, so a consumer never has to infer it
        # from the adapter name.  This seat's answer is always false.
        "prevents_execution": False,
        "gateway_routing": gateway_routing,
        # --------------------------------------------------------------------

        "gateway_tool": getattr(call, "gateway_tool", None),
        "tool_call_id": getattr(call, "call_id", None),
        "normalization": getattr(call, "mapping_source", None),
        "tenant_org": getattr(tenant, "org", None),
        "hold_id": hold_id,
        # WAS A HUMAN ACTUALLY ASKED?  One of the ANNOUNCE_* states, or None
        # when no hold was raised at all.  A report that counts holds as
        # "human oversight exercised" needs this: `not_configured` and
        # `failed` are holds nobody was told about, and reading them as
        # oversight would be the Art.14 overclaim in miniature.
        "hold_announced": hold_announced,
        # WHO decided it, from core's own hold record:
        # {"resolution", "decided_by": {"type","id"}, "verified"}. None when
        # no hold was raised, nobody decided, or the record was unreadable.
        "hold_decision": hold_decision,
        # The decision that RAISED the hold (§6's chain key), so a report can
        # walk decision -> hold -> approval -> re-decision.
        "parent_decision_id": parent_decision_id,
        "released_after_approval": bool(released_after_approval),
        "refusal_error": (refusal or {}).get("error"),
        "core_reachable": bool(getattr(verdict, "core_reachable", True)),
    }


def append_ledger(record: dict, path: Optional[str] = None) -> Optional[str]:
    """Append one ledger line.  Returns the path written, or None if disabled.

    NEVER raises.  The ledger is evidence, and evidence failing to write must
    not change a decision that has already been made correctly -- the same rule
    core applies to its own audit ("audit failure != deny").  A failure is
    returned as None and surfaced by the caller's counter, not by an exception
    that would reach the model's caller as a governance error.
    """
    target = path if path is not None else os.environ.get(LEDGER_PATH_ENV, "")
    target = (target or "").strip()
    if not target:
        return None
    try:
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with _ledger_lock:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return target
    except Exception:
        return None


_ledger_lock = threading.Lock()


# ---------------------------------------------------------------------------
# The §4 wire record -- a closed allowlist
# ---------------------------------------------------------------------------

def wire_record(ledger: dict) -> dict:
    """Project a ledger line onto EVIDENCE-INGEST-SPEC-v1 §4.  Nothing else.

    Built by NAMING each §4 field rather than by filtering the ledger, so a new
    ledger key can never leak onto a frozen wire by default -- the same closed
    -allowlist shape the evidence connector's `map_decision()` uses, and for the
    same reason.
    """
    missing = [k for k in ("decision_id", "verdict", "rule", "envelope_hash",
                           "occurred_ts") if not ledger.get(k)]
    action = ledger.get("action") or {}
    if not action.get("verb"):
        missing.append("action.verb")
    if not action.get("target_environment"):
        missing.append("action.target_environment")
    if missing:
        raise EvidenceConfigError(
            "cannot build a §4 evidence record, required field(s) missing: %s"
            % ", ".join(missing))

    wire = {
        "decision_id": ledger["decision_id"],
        "verdict": ledger["verdict"],
        "rule": ledger["rule"],
        "envelope_hash": ledger["envelope_hash"],
        "occurred_ts": ledger["occurred_ts"],
        "action": {
            "verb": action["verb"],
            "target_environment": action["target_environment"],
        },
        "sig_alg": SIG_ALG_V1,
    }

    # §4.2: core has a first-class `target_system` from v0.1.13; fall back to
    # the namespace, which is what the connector does.
    target_system = action.get("target_system") or action.get("namespace")
    if target_system:
        wire["action"]["target_system"] = target_system

    magnitude = ledger.get("magnitude") or {}
    count = magnitude.get("count") if isinstance(magnitude, dict) else None
    if isinstance(count, int):
        wire["magnitude"] = {"count": count}

    # THE ONE ADAPTER-CONTROLLED FIELD THAT REACHES AN ATTEST REPORT.
    if ledger.get("agent_id"):
        wire["agent_id"] = ledger["agent_id"]

    if ledger.get("traceparent"):
        wire["traceparent"] = ledger["traceparent"]

    if ledger.get("hold_id"):
        # THE ARTICLE 14 BLOCK, and the reason it is not just `hold_id`.
        #
        # Measured on the live app, 2026-09-08: with `hold: {hold_id}` alone,
        # two holds APPROVED BY A HUMAN IN THE UI produced an Attest report
        # reading `production_holds: 7, of_those_a_human_decided: 0` and
        # `decided_by_id: null` on every evidence-chain row. The resolution
        # existed in the application's own tables; the report is computed from
        # this feed, so it was right about its inputs and wrong about the
        # world. §4 reserves all four of these fields; none of them is a spec
        # change.
        hold = {"hold_id": ledger["hold_id"]}
        if ledger.get("parent_decision_id"):
            hold["parent_decision_id"] = ledger["parent_decision_id"]
        decision = ledger.get("hold_decision") or {}
        resolution = decision.get("resolution")
        if resolution in HOLD_RESOLUTIONS:
            hold["resolution"] = resolution
        by = decision.get("decided_by") or {}
        ptype, pid = by.get("type"), by.get("id")
        # §4 constrains `decided_by.type` to an ENUM. An approver core recorded
        # under some other type is dropped rather than sent, because an unknown
        # value 422s the whole batch -- and dropped is honest: §4 reads an
        # absent field as "not stated", never as "no human".
        if ptype in DECIDED_BY_TYPES and isinstance(pid, str) and pid.strip():
            hold["decided_by"] = {"type": ptype, "id": pid.strip()}
        wire["hold"] = hold

    assert_wire_is_spec_clean(wire)
    return wire


def assert_wire_is_spec_clean(wire: dict) -> None:
    """Re-check a wire record against §4's closed schema before it is sent.

    The server answers `422` for an unknown key and the connector contract (§10)
    says to treat that as a bug to surface rather than to retry.  Surfacing it
    HERE -- before the request -- is the same check one hop earlier, and it is
    what makes "this adapter cannot put `gateway_routing` on a frozen wire" a
    property the test suite can assert rather than a promise in a comment.
    """
    unknown = set(wire) - WIRE_TOP_LEVEL_FIELDS
    if unknown:
        raise EvidenceConfigError(
            "evidence record carries field(s) EVIDENCE-INGEST-SPEC-v1 §4 does "
            "not define: %s. §4 is a closed schema (unknown key -> 422) and the "
            "contract is FROZEN -- the field belongs in the adapter ledger, or "
            "needs a spec change from the spec owner."
            % ", ".join(sorted(unknown)))
    unknown_action = set(wire.get("action") or {}) - WIRE_ACTION_FIELDS
    if unknown_action:
        raise EvidenceConfigError(
            "evidence record `action` carries field(s) §4 does not define: %s"
            % ", ".join(sorted(unknown_action)))
    hold = wire.get("hold") or {}
    unknown_hold = set(hold) - WIRE_HOLD_FIELDS
    if unknown_hold:
        raise EvidenceConfigError(
            "evidence record `hold` carries field(s) §4 does not define: %s"
            % ", ".join(sorted(unknown_hold)))
    unknown_by = set(hold.get("decided_by") or {}) - WIRE_DECIDED_BY_FIELDS
    if unknown_by:
        raise EvidenceConfigError(
            "evidence record `hold.decided_by` carries field(s) §4 does not "
            "define: %s" % ", ".join(sorted(unknown_by)))
    resolution = hold.get("resolution")
    if resolution is not None and resolution not in HOLD_RESOLUTIONS:
        raise EvidenceConfigError(
            "evidence record `hold.resolution` is %r; §4's enum is %s"
            % (resolution, sorted(HOLD_RESOLUTIONS)))
    ptype = (hold.get("decided_by") or {}).get("type")
    if ptype is not None and ptype not in DECIDED_BY_TYPES:
        raise EvidenceConfigError(
            "evidence record `hold.decided_by.type` is %r; §4's enum is %s"
            % (ptype, sorted(DECIDED_BY_TYPES)))


# ---------------------------------------------------------------------------
# The PENDING-HOLD wire -- asking the human, not merely recording that we did
# ---------------------------------------------------------------------------

def hold_record(*, hold_id: str, decision_id: str, verb: str,
                target_environment: str, rule: str, envelope_hash: str,
                created_ts: str, target_system=None, magnitude_count=None,
                agent_id=None, reason=None, expires_ts=None) -> dict:
    """Build one `POST /api/v1/holds` record (CONTRACT holds-v1).

    Keyword-only and built by NAMING each field, for the same reason
    `wire_record()` is: the server's allowlist is closed (`unknown field(s)` ->
    422 on the WHOLE BATCH), so a field this adapter grows later must not be
    able to reach the wire because some dict happened to carry it.

    `reason` is the one field worth a note.  It is the sentence a human reads
    in the inbox next to an Approve button, so it carries core's decision
    reason -- which for this seat's holds names the rule and, for a mapped
    shell tool, the classifier's read of the command.  It does NOT carry the
    tool arguments, the prompt or the completion: this seat never sends prose,
    and `context.command_preview` stays in the envelope core holds, which is
    the record an operator reads through core, not through this wire.
    """
    rec = {
        "hold_id": hold_id,
        "decision_id": decision_id,
        "verb": verb,
        "target_environment": target_environment,
        "rule": rule,
        "envelope_hash": envelope_hash,
        "created_ts": created_ts,
        "sig_alg": SIG_ALG_V1,
    }
    missing = [f for f in HOLD_REQUIRED_FIELDS
               if not isinstance(rec.get(f), str) or not rec[f]]
    if missing:
        raise EvidenceConfigError(
            "cannot build a pending-hold record, required field(s) missing or "
            "not a non-empty string: %s" % ", ".join(missing))
    if target_system:
        rec["target_system"] = target_system
    if isinstance(magnitude_count, int) and not isinstance(magnitude_count, bool) \
            and magnitude_count >= 0:
        rec["magnitude_count"] = magnitude_count
    if agent_id:
        rec["agent_id"] = agent_id
    if reason:
        rec["reason"] = reason
    # OPTIONAL AND STAYS OPTIONAL.  `expires_ts` is core's own deadline for
    # this hold, read off the /v1/decide response; a core that does not emit
    # one leaves it absent rather than having this adapter invent a deadline
    # from a local TTL.  The app leaves a hold with no deadline open (its
    # `hold_expiry.py` says so in as many words), which is the correct
    # handling of "deadline unknown" -- but it does mean an older core buys an
    # unbounded inbox row, and that is worth knowing rather than papering over.
    if expires_ts:
        rec["expires_ts"] = expires_ts
    assert_hold_is_spec_clean(rec)
    return rec


def hold_record_from_ledger(ledger: dict, *, hold_id: str,
                            expires_ts=None) -> dict:
    """The pending-hold record for a ledger line that raised a hold."""
    action = ledger.get("action") or {}
    magnitude = ledger.get("magnitude") or {}
    return hold_record(
        hold_id=hold_id,
        decision_id=ledger.get("decision_id") or "",
        verb=action.get("verb") or "",
        target_environment=action.get("target_environment") or "",
        rule=ledger.get("rule") or "",
        envelope_hash=ledger.get("envelope_hash") or "",
        created_ts=ledger.get("occurred_ts") or _rfc3339_now(),
        target_system=action.get("target_system") or action.get("namespace"),
        magnitude_count=magnitude.get("count")
        if isinstance(magnitude, dict) else None,
        agent_id=ledger.get("agent_id"),
        reason=ledger.get("reason"),
        expires_ts=expires_ts,
    )


def assert_hold_is_spec_clean(rec: dict) -> None:
    """Re-check a pending-hold record against holds-v1's closed allowlist.

    Same one-hop-earlier check as `assert_wire_is_spec_clean()`, and it matters
    more here: the holds route rejects the WHOLE BATCH on the first bad record
    ("whole-batch reject on the first bad record" in the handler), so one
    unknown key would drop every other hold in the batch -- i.e. it would take
    other actions' holds out of a human's inbox.
    """
    unknown = set(rec) - HOLD_TOP_LEVEL_FIELDS
    if unknown:
        raise EvidenceConfigError(
            "pending-hold record carries field(s) CONTRACT holds-v1 does not "
            "define: %s. The route's schema is closed (unknown key -> 422 for "
            "the whole batch); the field belongs in the adapter ledger."
            % ", ".join(sorted(unknown)))


def holds_push_enabled() -> bool:
    """Separate switch from the evidence push, deliberately.

    Pushing a pending hold is not a recording action -- it makes a human's
    inbox ring, on a route that writes a row a person is then expected to
    answer.  An operator who wants the decision RECORD without wiring their
    holds inbox to this gateway must be able to have exactly that, and an
    operator who turns the holds push on must have said so about the holds
    push.  Defaults OFF for the same reason: a package upgrade must not start
    writing into somebody's approval queue.
    """
    return (os.environ.get(HOLDS_PUSH_ENV, "") or "").strip().lower() in (
        "1", "true", "yes", "on")


def push_holds(records: list, tenant) -> PushResult:
    """POST pending-hold records to the tenant's holds route.  NEVER raises.

    Separate URL from the evidence ingest, resolved from the tenancy map's
    `evidence.holds_url`; the gate TOKEN and signing key are the same ones,
    because §3 resolves `(gate_id, org_id)` from that token and both routes
    authenticate identically.  A tenant with no `holds_url` cannot push holds
    and gets a named configuration error -- never a silent skip, because a
    silent skip here means a human is never asked.
    """
    return _push_signed(records, tenant, url_key="holds_url",
                        validator=assert_hold_is_spec_clean,
                        what="pending-hold")


#: What `announce_hold()` reports back, for the ledger line.
ANNOUNCE_OFF = "not_configured"
ANNOUNCE_SENT = "sent"
ANNOUNCE_FAILED = "failed"


def announce_hold(*, envelope: dict, verdict, tenant) -> tuple:
    """Put a hold core has just raised into the tenant's approval inbox.

    Returns `(state, detail)` where state is one of the ANNOUNCE_* constants.
    NEVER raises.

    WHY THIS IS CALLED WHERE IT IS -- and it is the whole point of the function.
    Everything else this module writes is recorded AFTER enforcement, on
    purpose, so that an evidence outage can never change or delay a verdict.  A
    pending hold is the one exception, and the reason is arithmetic: the seat
    then blocks for up to `reeflex_hold_wait` seconds waiting for a human, so a
    row pushed after the response is final reaches the inbox AFTER the window
    it was supposed to be answered in.  Recorded-after would mean asking
    somebody a question and hanging up before they could hear it.

    So this runs before the wait, and it pays for that with two properties it
    must have:

      * it never raises and never denies -- a holds-inbox outage leaves the
        seat behaving exactly as it did before this function existed (the hold
        is still open in core, still resolvable by any other route), and
      * its outcome is RECORDED on the ledger line (`hold_announced`), because
        "a human was asked" and "we tried to ask a human and the inbox was
        unreachable" are different facts and a report must not read the second
        as the first.
    """
    if not holds_push_enabled():
        return ANNOUNCE_OFF, "%s is not enabled" % HOLDS_PUSH_ENV
    hold_id = getattr(verdict, "hold_id", None)
    if not hold_id:
        return ANNOUNCE_FAILED, "core raised a hold with no hold_id"
    try:
        action = envelope.get("action") or {}
        target = envelope.get("target") or {}
        magnitude = envelope.get("magnitude") or {}
        agent = envelope.get("agent") or {}
        rec = hold_record(
            hold_id=hold_id,
            decision_id=getattr(verdict, "decision_id", None) or "",
            verb=action.get("verb") or "",
            target_environment=target.get("environment") or "",
            rule=getattr(verdict, "rule", None) or "",
            envelope_hash=envelope_hash(envelope),
            created_ts=_rfc3339_now(),
            target_system=action.get("namespace"),
            magnitude_count=magnitude.get("count"),
            agent_id=agent.get("id"),
            reason=getattr(verdict, "reason", None),
            expires_ts=getattr(verdict, "expires_ts", None),
        )
    except Exception as exc:
        return ANNOUNCE_FAILED, "%s: %s" % (type(exc).__name__, exc)
    result = push_holds([rec], tenant)
    if result.ok:
        return ANNOUNCE_SENT, "HTTP %s" % result.status
    return ANNOUNCE_FAILED, result.error or "push failed"


# ---------------------------------------------------------------------------
# §5 signing
# ---------------------------------------------------------------------------

def canonical_body(records: list) -> bytes:
    """§5.1 canonical bytes of the request body (a JSON array of records)."""
    return json.dumps(records, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign(body: bytes, timestamp: int, signing_key: bytes) -> str:
    """§5: HMAC-SHA256 over `"<ts>.\\n"` + the canonical body."""
    preimage = ("%d.\n" % timestamp).encode("utf-8") + body
    return hmac.new(signing_key, preimage, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Per-tenant credentials, by reference only
# ---------------------------------------------------------------------------

class GateCredentials:
    """One tenant's evidence credentials, resolved from env-var NAMES.

    `__repr__` deliberately prints neither value: this object is held on a
    request path whose exceptions are logged.
    """

    __slots__ = ("ingest_url", "gate_token", "signing_key", "org")

    def __init__(self, ingest_url, gate_token, signing_key, org):
        self.ingest_url = ingest_url
        self.gate_token = gate_token
        self.signing_key = signing_key
        self.org = org

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("GateCredentials(org=%r, ingest_url=%r, gate_token=<redacted>, "
                "signing_key=<redacted>)" % (self.org, self.ingest_url))


def credentials_for(tenant, url_key: str = "ingest_url") -> GateCredentials:
    """Resolve a tenant's gate credentials.  Raises EvidenceConfigError.

    The error names the env var that is missing -- never its value, and never
    a prefix of its value.

    `url_key` selects WHICH route's URL to resolve -- `ingest_url` for §4
    evidence, `holds_url` for the pending-hold route.  The token and the
    signing key are shared between them on purpose: §3 resolves
    `(gate_id, org_id)` from the gate token, so one gate is one org on every
    route it serves, and giving the two routes separate credentials would
    invite a deployment where a department's holds and its evidence land in
    two different orgs.
    """
    spec = dict(getattr(tenant, "evidence", None) or {})
    url = (spec.get(url_key) or "").strip()
    token_env = (spec.get("gate_token_env") or "").strip()
    key_env = (spec.get("signing_key_env") or "").strip()
    org = getattr(tenant, "org", None)

    missing = []
    if not url:
        missing.append("evidence.%s" % url_key)
    if not token_env:
        missing.append("evidence.gate_token_env")
    if not key_env:
        missing.append("evidence.signing_key_env")
    if missing:
        raise EvidenceConfigError(
            "tenant %r cannot push evidence: %s not set in the tenancy map"
            % (org, ", ".join(missing)))

    token = (os.environ.get(token_env) or "").strip()
    key_hex = (os.environ.get(key_env) or "").strip()
    if not token:
        raise EvidenceConfigError(
            "tenant %r: environment variable %s (the gate token) is empty"
            % (org, token_env))
    if not key_hex:
        raise EvidenceConfigError(
            "tenant %r: environment variable %s (the evidence signing key) is "
            "empty" % (org, key_env))
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise EvidenceConfigError(
            "tenant %r: %s is not hex. §5/RFX-44 hands the operator the DERIVED "
            "32-byte signing key hex-encoded at gate registration "
            "(REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY)." % (org, key_env)) from None
    if len(key) != 32:
        raise EvidenceConfigError(
            "tenant %r: %s decodes to %d bytes; §5's derived signing key is 32"
            % (org, key_env, len(key)))

    return GateCredentials(url.rstrip("/"), token, key, org)


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------

class PushResult:
    __slots__ = ("ok", "status", "body", "error", "org", "records")

    def __init__(self, ok, status=None, body=None, error=None, org=None,
                 records=0):
        self.ok = ok
        self.status = status
        self.body = body
        self.error = error
        self.org = org
        self.records = records

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("PushResult(ok=%r, status=%r, org=%r, records=%r, error=%r)"
                % (self.ok, self.status, self.org, self.records, self.error))


def push_enabled() -> bool:
    return (os.environ.get(PUSH_ENV, "") or "").strip().lower() in (
        "1", "true", "yes", "on")


def push(records: list, tenant) -> PushResult:
    """POST a batch of §4 records to the tenant's gate.  NEVER raises.

    The decision has already been made and enforced by the time this runs.  An
    evidence push that failed is a gap in the record, and it must be visible --
    but turning it into an exception on the response path would let an ingest
    outage deny traffic that core allowed.  So: never raises, and the failure is
    returned.
    """
    return _push_signed(records, tenant, url_key="ingest_url",
                        validator=assert_wire_is_spec_clean,
                        what="evidence")


def _push_signed(records: list, tenant, *, url_key: str, validator,
                 what: str) -> PushResult:
    """One §5-signed POST of a record batch.  NEVER raises.

    Shared by the evidence push and the pending-hold push so the signing, the
    ±300s timestamp window, the header shape and the never-raise posture cannot
    drift between the two routes -- which is exactly the class of bug that once
    shipped a DIR-2 response wrapped in an object the other side rejected.
    """
    if not records:
        return PushResult(True, records=0, org=getattr(tenant, "org", None))
    try:
        creds = credentials_for(tenant, url_key)
    except EvidenceConfigError as exc:
        return PushResult(False, error=str(exc),
                          org=getattr(tenant, "org", None),
                          records=len(records))

    try:
        for r in records:
            validator(r)
        body = canonical_body(records)
        ts = int(time.time())
        signature = sign(body, ts, creds.signing_key)
        req = urllib.request.Request(
            creds.ingest_url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer %s" % creds.gate_token,
                "X-Reeflex-Timestamp": str(ts),
                "X-Reeflex-Signature": "%s=%s" % (SIG_ALG_V1, signature),
            })
        timeout = _timeout()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return PushResult(True, status=resp.status, body=raw,
                              org=creds.org, records=len(records))
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        return PushResult(False, status=exc.code, body=raw,
                          error="%s push: HTTP %s" % (what, exc.code),
                          org=creds.org, records=len(records))
    except Exception as exc:
        return PushResult(False,
                          error="%s push: %s: %s" % (what, type(exc).__name__,
                                                     exc),
                          org=creds.org, records=len(records))


def _timeout() -> float:
    try:
        return float(os.environ.get(TIMEOUT_ENV, "") or DEFAULT_TIMEOUT)
    except ValueError:
        return DEFAULT_TIMEOUT


def _rfc3339_now() -> str:
    """`%Y-%m-%dT%H:%M:%SZ` -- the shape core's audit emits and §4 requires."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
