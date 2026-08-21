"""
decide.py — Core decision handler for POST /v1/decide.

Orchestrates the full decision pipeline per SPEC §5 + §6:
  1. Validate envelope (structural; conservative defaults for missing axis values)
  2. FREEZE check: if REEFLEX_FREEZE=true and verb is not a READ, deny immediately
  3. Compute cumulative state from session ledger (SPEC §4.1)
  4. Inject cumulative into the OPA input
  5. Evaluate via OPA -> Decision
  6. FAIL-CLOSED on any OPA error
  7. HIL hold handling: create hold on require_approval, validate hold on resubmission
  8. Append to session ledger (AFTER eval)
  9. Append to audit log
 10. Return Decision

Returns a (status_code, response_dict) tuple.  The HTTP layer is in server.py.

=============================================================================
DETERMINISM INVARIANT
=============================================================================
Given the same Action Envelope AND the same session ledger state AND the same
hold store state, this function always returns the same Decision.  No clocks
or randomness are consulted in the OPA input (the timestamp is for audit only,
not policy eval).

=============================================================================
FAIL-CLOSED INVARIANT
=============================================================================
If OPA errors, times out, or returns undefined/empty -> deny, reason
"policy evaluation unavailable - failing closed", rule "reeflex.core/fail_closed".
If hold handling errors for ANY reason -> deny.
We NEVER return allow on an OPA error or a hold error.

=============================================================================
FREEZE (T2a)
=============================================================================
Env REEFLEX_FREEZE (true/1/yes = on).  Re-read per request so it is
hot-reloadable without restart.  When ON:
  - Non-read verbs -> deny, reason "frozen by operator",
    rule "reeflex.policy/frozen".
  - READ verbs pass through to normal evaluation.
When the freeze state CHANGES between consecutive requests:
  - Audit a freeze.flipped event.
  - Fire webhook freeze.flipped.

=============================================================================
HOLD APPROVAL FLOW (T2b/T2c)
=============================================================================
When the normal verdict is require_approval AND the request carries NO valid
approval:
  - Create a pending hold (holds.py).
  - Audit the decision annotated with hold_id.
  - Fire webhook hold.created.
  - Add hold_id + expires_ts to the /v1/decide response.

When the request carries approval={present:true, hold_id:"..."}:
  - Run the validation chain (8 checks).  On FIRST failure return deny with
    a machine reason code, WITHOUT consuming the hold.
  - On success: mark_consumed(hold_id), return ALLOW, audit.

The chain grew from 6 to 8 because checks 5 and 6 turned out not to cover
everything a human was shown: check 7 binds the decision inputs the envelope
hash omits (params — RFX-133), and check 8 binds WHO the approval was granted
to (agent.id / agent.on_behalf_of — RFX-138, a human's approval was otherwise
spendable by any agent holding the hold_id).

=============================================================================
TRACEABILITY (decision_id / hold_id / envelope_hash / parent_decision_id /
traceparent) — additive, non-breaking
=============================================================================
Every call to process() generates a `decision_id` (uuid4 hex) as the very
first statement in the function, before the envelope is even validated, so
it is available to EVERY return path -- including the belt-and-braces
outer `except Exception` fail-closed path.  It is added to the Decision
response dict, the audit record, and the SIEM decision event for every
verdict (allow / deny / require_approval), and it is threaded into
`create_hold()` so a hold names the decision that created it.

`envelope_hash` reuses `holds.canonical_hash()` verbatim (the same
{action, axes, magnitude, target} projection already used to bind a hold to
its approval) so audit / SIEM / hold records join on the exact same key.

`parent_decision_id` (populated only on an approval resubmission): the
adapter MAY pass the original decision_id back via `approval.parent_decision_id`
on the envelope; if absent, core falls back to the `decision_id` recorded on
the consumed hold (the hold that require_approval created).  This stitches
decision -> hold -> approval -> re-decision into one navigable chain.  The
fallback reuses the SAME hold record `_validate_approval()` already fetched
for its six-check chain -- it does NOT issue a second get_hold(hold_id) read
between validation and mark_consumed(), keeping the pre-CAS read path tight.
`mark_consumed()` itself now has a CAS (compare-and-set) guard: the
status-check and the consume-append happen atomically under holds.py's
module lock, so even if two callers both reach mark_consumed() concurrently
on the same hold_id, exactly one wins the consume and the other gets None
(-> denied, reason reeflex_hold_already_consumed).  See holds.mark_consumed()
docstring for the CAS guarantee.

`traceparent` (opaque W3C trace-context passthrough, NOT OpenTelemetry — no
SDK, no spans): if present at `envelope.context.traceparent`, it is echoed
UNTOUCHED into the audit record and SIEM event.  Absent -> omitted.

None of the above touches OPA input, the hash allowlist, or decision logic;
it is pure enrichment of the response/audit/SIEM records.
"""

from __future__ import annotations

import os
import sys
import time
import uuid

from .envelope import validate_and_fill_defaults, ValidationError
from .ledger import compute_cumulative, append_entry
from .opa import evaluate, OpaEvalError
from .audit import record
from .telemetry import get_emitter
from .holds import canonical_hash

_WINDOW_SECONDS = int(os.environ.get("REEFLEX_WINDOW_SECONDS", "3600"))

# THE ENVELOPE FIELDS THIS MODULE READS TO REACH A VERDICT.
#
# decide.py is the THIRD reader of the envelope, after policy/*.rego and
# ledger.py, and it is the one that decides things OPA never sees: the freeze
# gate short-circuits on the verb, and the whole hold-approval chain runs here
# and can return allow or deny without an eval at all.  RFX-127 lived in
# exactly that gap — `approval.hold_id` appears in no .rego file and in no
# ledger read, so an enumeration built from those two would not have covered
# the field whose absence switched off every budget.
#
# Declared here, next to the code that reads them, and required to carry a
# treatment in app/field_treatments.py.  See tests/test_field_treatments.py.
#
# Audit-only caller-supplied fields (approval.parent_decision_id,
# context.traceparent, meta.*) are deliberately NOT listed: they cannot change
# a verdict.  They are an evidence-integrity surface, not a decision one — see
# the RESIDUAL notes in field_treatments.py.
DECIDE_ENVELOPE_PATHS: tuple[str, ...] = (
    "agent.session_id",   # ledger key + principal_budgets override key
    # RFX-139: these two were READ here all along and declared nowhere.
    # Check 6 calls principal.is_self_approval(), which iterates
    # ("id", "on_behalf_of", "session_id"); check 8 compares them as the
    # approval's actor key.  Only session_id was listed, so
    # tests/test_field_treatments.py's "decide.py reads nothing undeclared"
    # assertion passed by under-reporting -- and a path that is never declared
    # can never be picked up by the approval binding derived from TREATMENTS.
    # That is how RFX-138 got through a sweep built to be exhaustive.
    "agent.id",           # four-eyes compare + approval actor key
    "agent.on_behalf_of", # four-eyes compare + approval actor key
    "action.verb",        # freeze gate (_is_read_verb)
    "approval.present",   # routes into the hold-validation chain
    "approval.hold_id",   # names the hold the eight checks run against
)

# The Decision returned when OPA evaluation fails for any reason.
_FAIL_CLOSED_DECISION: dict = {
    "decision": "deny",
    "reason": "policy evaluation unavailable - failing closed",
    "rule": "reeflex.core/fail_closed",
    "obligations": [],
    "modulation": None,
}


_INTERNAL_ERROR_DECISION: dict = {
    "decision": "deny",
    "reason": "internal error - failing closed",
    "rule": "reeflex.core/internal_error",
    "obligations": [],
    "modulation": None,
}

# ---------------------------------------------------------------------------
# FREEZE state tracking (module-level; updated per request in the hot path)
# ---------------------------------------------------------------------------

# Stores the last-seen freeze state so we can detect flips.
# None = not yet read (first request).  True/False = last known state.
_last_freeze_state: bool | None = None
_freeze_lock = None  # we use module-level state + GIL; no explicit lock needed
                     # (Python bool assignment is atomic under the GIL)


def _read_freeze() -> bool:
    """Read the freeze flag from env on every call (hot-reloadable)."""
    val = os.environ.get("REEFLEX_FREEZE", "").strip().lower()
    return val in ("true", "1", "yes")


def _check_freeze_flip(current: bool) -> None:
    """Detect freeze state changes; audit + webhook if it flipped.

    Must be called after the envelope is validated (so session_id is available
    if needed for auditing). Called outside the decision path proper, so any
    exception here is swallowed rather than blocking the request.
    """
    global _last_freeze_state
    if _last_freeze_state is None:
        _last_freeze_state = current
        return
    if current == _last_freeze_state:
        return
    # State changed
    _last_freeze_state = current
    _try_fire_freeze_flipped(current)


def _try_fire_freeze_flipped(freeze_on: bool) -> None:
    """Audit + webhook + SIEM for a freeze.flipped event. Best-effort; never raises.

    The freeze (REEFLEX_FREEZE) IS the operator kill switch, so a flip must
    surface on ALL THREE observability surfaces — the webhook, the audit log,
    AND the SIEM (a SOC's primary surface). Emitting on the flip only (a state
    CHANGE), never per request, so there is no per-decision noise.
    """
    try:
        from .webhook import fire as wh_fire  # type: ignore[import]
        wh_fire("freeze.flipped", {
            "freeze_on": freeze_on,
        })
    except Exception:  # noqa: BLE001
        pass
    # Audit the flip (best-effort)
    try:
        _audit_freeze_flip(freeze_on)
    except Exception:  # noqa: BLE001
        pass
    # SIEM kill-switch event (best-effort, fire-and-forget — never blocks/raises).
    try:
        from .telemetry import get_emitter  # type: ignore[import]
        if freeze_on:
            action, reason = "flipped", (
                "operator engaged the freeze kill-switch (REEFLEX_FREEZE on) — "
                "all non-read actions now denied"
            )
        else:
            action, reason = "cleared", (
                "operator cleared the freeze kill-switch (REEFLEX_FREEZE off) — "
                "normal gating resumed"
            )
        get_emitter().emit_kill_switch(action, reason)
    except Exception:  # noqa: BLE001
        pass


def _audit_freeze_flip(freeze_on: bool) -> None:
    """Write a freeze.flipped synthetic audit record."""
    from .audit import _log_path, _lock as audit_lock  # type: ignore[import]
    import json
    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "freeze.flipped",
        "freeze_on": freeze_on,
    }
    line = json.dumps(rec, separators=(",", ":")) + "\n"
    import os as _os
    with audit_lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            _os.fsync(fh.fileno())


# ---------------------------------------------------------------------------
# Read-verb detection (used by freeze logic)
# ---------------------------------------------------------------------------

_READ_VERBS = frozenset({"read", "list", "get", "query", "search", "describe", "inspect"})


def _is_read_verb(verb: str) -> bool:
    """Return True if the verb is considered a read-only operation."""
    return verb.strip().lower() in _READ_VERBS


# ---------------------------------------------------------------------------
# Hold-based approval helpers (T2b/T2c)
# ---------------------------------------------------------------------------

def resolve_session_identity(envelope: dict) -> str:
    """Resolve the identity that keys the ledger AND that budgets.rego reads
    as `input.agent.session_id` for per-principal cumulative budgets (RFX-11).

    THE SEAM: this is the ONE place in core that decides "what identifies a
    session/principal for cumulative accounting". Today that is verbatim
    `agent.session_id` (SPEC §4.1 F3, already required by envelope.py).
    RFX-9 is still open on WHERE that identity should come from once adapters
    speak the post-MCP-spec session model (e.g. an MCP session token vs an
    adapter-minted id) — when that lands, only this function changes; ledger
    keying and the Rego budget lookups are untouched because both already
    consume this function's return value, not the raw envelope field.
    """
    return (envelope.get("agent") or {}).get("session_id") or ""


def _validate_approval(envelope: dict) -> tuple[int, dict | None, dict | None]:
    """Validate the hold approval attached to the envelope.

    Returns (status_code, error_dict, hold) on validation failure -- `hold` is
    whatever hold record we managed to fetch before failing (None if hold_id
    was absent or the hold does not exist at all).
    Returns (0, None, hold) on success (caller should proceed with allow) --
    `hold` is the SAME fully-validated hold record read by the six checks
    below.

    TOCTOU note: callers MUST reuse this returned `hold` dict (e.g. its
    `decision_id`) for any downstream read (e.g. parent_decision_id
    resolution) instead of issuing a fresh get_hold(hold_id) between this
    call and mark_consumed(hold_id).  `mark_consumed()` has a CAS
    (compare-and-set) guard -- its status-check and consume-append are
    atomic under holds.py's module lock -- so even if two callers reach
    mark_consumed() concurrently for the same hold_id, exactly one wins the
    consume and the other is refused (None -> caller must deny, reason
    reeflex_hold_already_consumed).  The single-caller-wins guarantee lives
    in mark_consumed() itself; the reuse-the-returned-hold discipline here is
    still worth keeping for correctness of parent_decision_id resolution.

    Validation chain per design T2c:
      1. hold exists                       else deny "reeflex_hold_not_found"
      2. status == approved                 else deny "reeflex_hold_not_approved"
      3. not expired                        else deny "reeflex_hold_expired"
      4. status != consumed                 else deny "reeflex_hold_consumed"
      5. canonical_hash(envelope) == stored else deny "reeflex_hold_envelope_mismatch"
      6. agent identity != decided_by ident else deny "reeflex_hold_actor_is_approver"
      7. decision inputs outside the hash    else deny "reeflex_hold_envelope_mismatch"
         match the held envelope (params)
      8. the actor is the party the approval else deny "reeflex_hold_actor_mismatch"
         was granted to (RFX-138)

    Checks 5-8 are four answers to one question -- "is this the same request a
    human said yes to" -- split by what they compare: the hashed projection,
    the identity of the approver, the decision inputs the hash omits, and the
    identity of the requester.  Each of the last three exists because the one
    before it turned out not to cover something.
    """
    from .holds import get_hold, canonical_hash, is_expired  # type: ignore[import]

    approval = (envelope.get("approval") or {})
    hold_id = approval.get("hold_id", "")
    if not hold_id:
        # present=True but no hold_id — treat as not_found
        return 200, _deny_response("reeflex_hold_not_found", "reeflex.core/hold_validation"), None

    hold = get_hold(hold_id)

    # Check 1: hold exists
    if hold is None:
        return 200, _deny_response("reeflex_hold_not_found", "reeflex.core/hold_validation"), None

    # Check 2: status == approved
    if hold.get("status") != "approved":
        status_val = hold.get("status", "")
        if status_val == "consumed":
            return 200, _deny_response("reeflex_hold_consumed", "reeflex.core/hold_validation"), hold
        if status_val in ("rejected", "expired"):
            return 200, _deny_response(
                f"reeflex_hold_{status_val}", "reeflex.core/hold_validation"
            ), hold
        return 200, _deny_response("reeflex_hold_not_approved", "reeflex.core/hold_validation"), hold

    # Check 3: not expired (lazy check may have updated status, re-read)
    if is_expired(hold):
        return 200, _deny_response("reeflex_hold_expired", "reeflex.core/hold_validation"), hold

    # Check 4: status != consumed (re-confirm after is_expired re-read)
    if hold.get("status") == "consumed":
        return 200, _deny_response("reeflex_hold_consumed", "reeflex.core/hold_validation"), hold

    # Check 5: canonical_hash of THIS envelope == stored envelope_hash
    # We compute the hash of the envelope as-is (the validated, normalized copy).
    this_hash = canonical_hash(envelope)
    if this_hash != hold.get("envelope_hash", ""):
        return 200, _deny_response(
            "reeflex_hold_envelope_mismatch", "reeflex.core/hold_validation"
        ), hold

    # Check 6: actor != approver.
    # Actor    = this request's agent identity (agent.id / on_behalf_of /
    #            session_id -- see principal.actor_identities()).
    # Approver = hold.decided_by, "{type}:{identity}".
    #
    # RFX-CORE-2: this was a raw `==` between agent.id and the identity half of
    # decided_by, so it missed the SAME identity written in a different case
    # ("svc-bot" vs "SVC-BOT"), with an invisible character, or named via
    # on_behalf_of -- and it was skipped entirely when agent.id was absent
    # (SPEC §2 does not require agent.id; only session_id is required).  All
    # four were confirmed live on api-dev. Now normalized and compared across
    # the whole actor identity set, mirroring the resolve-time check in
    # server.py so a resubmission cannot pass a guard the resolve already
    # applied -- or vice versa.
    from .principal import is_self_approval, normalize_identity  # type: ignore[import]

    decided_by = hold.get("decided_by") or ""
    if ":" in decided_by:
        approver_type, approver_id = decided_by.split(":", 1)
    else:
        approver_type, approver_id = "", decided_by
    if normalize_identity(approver_id) and is_self_approval(
        envelope, approver_type, approver_id
    ):
        return 200, _deny_response(
            "reeflex_hold_actor_is_approver", "reeflex.core/hold_validation"
        ), hold

    # Check 7: the decision inputs the HASH DOES NOT COVER must also match.
    #
    # canonical_hash() projects {action, axes, magnitude, target} — see
    # holds._HASH_ALLOWLIST — deliberately, so the hash is stable across the
    # submission and the resubmission.  But `params` carries a decision input
    # too: R5's money dimension is driven entirely by params.amount.  So a
    # hold raised for a EUR 6,000 payment could be resubmitted as EUR
    # 6,000,000 with a BYTE-IDENTICAL hash, and check 5 passed.  The human
    # approved one number and the agent executed another.  Confirmed end to
    # end while sweeping the enumeration for RFX-127/133.
    #
    # This is the same defect class one layer over: a caller-supplied value
    # the decision reads, which nothing verified — here, against the value a
    # human actually saw.
    #
    # WHY NOT JUST ADD `params` TO _HASH_ALLOWLIST.  That would change the
    # PREIMAGE of `envelope_hash`, which is written into the audit record, the
    # SIEM event and the hold record, and which downstream evidence joins on.
    # Widening it would silently invalidate every cross-build join for a fix
    # that does not need it.  Comparing the fields directly binds the same
    # facts and leaves the hash — and the wire — alone.
    #
    # The path list is DERIVED from field_treatments.TREATMENTS rather than
    # hardcoded, so a future declared decision input in `params` is bound
    # without anyone remembering to add it here.
    from .field_treatments import approval_bound_paths  # type: ignore[import]

    held_envelope = hold.get("envelope") or {}
    for path in approval_bound_paths():
        block, _, leaf = path.partition(".")
        now_block = envelope.get(block)
        was_block = held_envelope.get(block)
        now = now_block.get(leaf) if isinstance(now_block, dict) else None
        was = was_block.get(leaf) if isinstance(was_block, dict) else None
        # `!=` is exact and that is intended: both sides have already been
        # through validate_and_fill_defaults(), so both are canonical, and a
        # remaining difference is a real difference.
        if now != was:
            return 200, _deny_response(
                "reeflex_hold_envelope_mismatch", "reeflex.core/hold_validation"
            ), hold

    # Check 8: the approval was granted to a PARTY, not just to an action.
    #
    # RFX-138.  Checks 1-7 answer "is this the action a human approved".
    # Nothing answered "and is this the requester they approved it for".
    # `agent` is outside canonical_hash()'s {action, axes, magnitude, target}
    # projection and outside check 7's params comparison, so any caller
    # holding the hold_id could spend someone else's approval:
    #
    #   * agent ALPHA raises an irreversible production delete, a human
    #     approves it, agent BETA resubmits the identical action with ALPHA's
    #     hold_id and receives allow -- and because the resubmission CONSUMES
    #     the hold, ALPHA, the agent the human actually approved, is then
    #     refused (reeflex_hold_consumed).
    #   * quieter and worse: one bot, one session, one action, only
    #     agent.on_behalf_of changed from alice to bob.  The audit line for
    #     that allow is byte-identical to a legitimate resubmission.
    #
    # Both confirmed on the built artefact from 44c6f85 (the commit AFTER
    # check 7 landed) -- see scripts/attack-probe-rfx97-release-gate.py A6.
    #
    # WHY A DEDICATED REASON CODE.  The defect's sting is that the
    # substitution left no trace; reusing reeflex_hold_envelope_mismatch would
    # record the refusal as if the ACTION had been altered, which is a
    # different fact.  reeflex_hold_actor_mismatch names what happened and is
    # additive to the code table in the README (a consumer switching on the
    # reason -- reeflex-mcp's gateway is the only one -- treats an unknown
    # reason as the deny it is).
    #
    # AND THE HOLD IS NOT CONSUMED: this returns before mark_consumed(), so
    # the approval the human granted survives for the agent it was granted to.
    from .principal import approval_actor_key  # type: ignore[import]

    if approval_actor_key(envelope) != approval_actor_key(held_envelope):
        return 200, _deny_response(
            "reeflex_hold_actor_mismatch", "reeflex.core/hold_validation"
        ), hold

    return 0, None, hold  # all checks passed


def _deny_response(reason: str, rule: str) -> dict:
    return {
        "decision": "deny",
        "reason": reason,
        "rule": rule,
        "obligations": [],
        "modulation": None,
    }


# ---------------------------------------------------------------------------
# Main decision entry point
# ---------------------------------------------------------------------------

def process(raw_body: dict, src_ip: str = "") -> tuple[int, dict]:
    """
    Execute the full decision pipeline.

    Returns (http_status_code, response_dict).

    HTTP 400 -> structural validation failure (missing required fields).
    HTTP 200 -> decision produced (allow / deny / require_approval).
    HTTP 500 -> internal error (OPA unavailable or unexpected) -> deny, fail-closed.

    BELT: the outer except Exception ensures this function ALWAYS returns a
    (status, dict) tuple — it never raises, never leaves the socket empty.
    No traceback or internal path is ever surfaced to the caller.
    """
    # decision_id: generated FIRST, before the envelope is even validated, so
    # it is available on every possible return path of this function,
    # including the belt-and-braces fail-closed catch-all at the bottom.
    # uuid4().hex cannot raise -- this is unconditionally safe.
    decision_id: str = uuid.uuid4().hex
    envelope_hash: str = ""   # populated once the envelope validates (Step 1)
    traceparent: str = ""    # populated once the envelope validates, if present

    try:
        # Step 1: Validate and fill conservative defaults
        try:
            envelope = validate_and_fill_defaults(raw_body)
        except ValidationError as exc:
            return 400, {
                "error": "invalid_envelope",
                "detail": str(exc),
            }

        # envelope_hash reuses holds.canonical_hash() verbatim -- the action-
        # defining projection {action, axes, magnitude, target} -- so audit,
        # SIEM, and hold records all join on the exact same key.
        envelope_hash = canonical_hash(envelope)

        # traceparent (W3C trace-context, opaque passthrough): pick the
        # location envelope.context.traceparent.  No SDK, no spans -- just an
        # opaque string carried untouched into audit + SIEM.  Absent -> "".
        _context = envelope.get("context")
        if isinstance(_context, dict):
            _tp = _context.get("traceparent", "")
            traceparent = _tp if isinstance(_tp, str) else ""

        # Step 2: Resolve session identity — guaranteed non-empty by
        # validate_and_fill_defaults. Goes through resolve_session_identity()
        # (the RFX-9 seam) rather than reading envelope.agent.session_id
        # inline, so ledger keying and the budgets.rego principal lookup stay
        # correct if the identity source changes later.
        session_id: str = resolve_session_identity(envelope)

        # Step 3: FREEZE check (T2a) — re-read env per request
        try:
            freeze_on = _read_freeze()
            _check_freeze_flip(freeze_on)
        except Exception:  # noqa: BLE001
            freeze_on = False  # fail open for freeze detection; fail closed for decisions

        if freeze_on:
            verb = (envelope.get("action") or {}).get("verb", "")
            if not _is_read_verb(verb):
                frozen_decision: dict = {
                    "decision": "deny",
                    "reason": "frozen by operator",
                    "rule": "reeflex.policy/frozen",
                    "obligations": [],
                    "modulation": None,
                    "decision_id": decision_id,
                }
                _try_audit(
                    session_id, envelope, {}, frozen_decision,
                    decision_id=decision_id, envelope_hash=envelope_hash,
                    traceparent=traceparent,
                )
                return 200, frozen_decision

        # Step 4: Check for an approval resubmission (T2c)
        #
        # RFX-127 — THE GUARD USED TO READ `if approval_present and
        # approval.get("hold_id")`.  An envelope carrying a bare
        # `approval: {"present": true}` with NO hold_id therefore SKIPPED the
        # six-check validation chain entirely and fell straight through to OPA
        # still asserting present=true.  R5's predicate is
        #
        #     count(exceeded_dimensions) > 0
        #     not input.approval.present
        #
        # so that one unverified boolean switched off EVERY cumulative budget
        # — deletions, money, external_sends, objects_touched — and the verdict
        # became R4 default_allow.  Not one matching condition evaded: a whole
        # rule disabled, by a caller asserting that a human had approved
        # something when no hold had ever been created, let alone resolved.
        # Reproduced live on api-dev with the published eval token (control
        # require_approval -> attack allow) and on a pinned local build; see
        # scripts/attack-probe-envelope-boundary.py, attack A4.
        #
        # This is the SAME shape as RFX-84 (the self-asserted approving
        # principal on /resolve): a caller stating a fact about human oversight
        # that nothing checks.
        #
        # The fix is to stop excluding the no-hold_id case from validation.
        # `_validate_approval()` was ALREADY written to handle it — its first
        # statement returns `reeflex_hold_not_found` when hold_id is absent —
        # and this guard was the only reason that branch was unreachable.  So
        # an approval assertion is now always validated, and an assertion that
        # names no hold is refused rather than believed.
        #
        # WHY DENY AND NOT SILENTLY COERCE present -> false.  Either would
        # restore the budget.  A caller claiming an approval that does not
        # exist is a signal, not a formatting difference — the same reasoning
        # principal.resolve_approver() applies to a mismatched principal — and
        # a silent coercion would let a broken adapter ship an envelope that
        # LOOKS approved to every downstream reader forever.  The refusal is
        # audited, so the claim is on the record.
        #
        # WRONG-DENY TRADE-OFF (documented deliberately, as #89 did): an
        # adapter that sets approval.present=true without a hold_id now gets a
        # deny where it previously got its action through.  Per SPEC §2 that
        # envelope is already malformed — `present` is "true on resubmission
        # after hold resolution" and `hold_id` is "hold_id from the
        # require_approval response" — so the two fields are meaningless apart,
        # and the previous behaviour was not a feature anyone could rely on
        # except to evade R5.  A wrong DENY is a nuisance; this wrong ALLOW was
        # the product failing.
        #
        # WIRE CONTRACT: unchanged.  This reuses the existing
        # `reeflex_hold_not_found` machine reason code rather than minting a
        # new one — see the PR note flagging that a dedicated
        # `reeflex_approval_no_hold_id` code would read better but would add
        # vocabulary to a frozen field.
        approval = envelope.get("approval") or {}
        approval_present = approval.get("present", False)

        if approval_present:
            # Validate the approval chain — fail-closed on any exception
            try:
                fail_code, fail_resp, validated_hold = _validate_approval(envelope)
            except Exception:  # noqa: BLE001
                fail_resp = dict(_INTERNAL_ERROR_DECISION)
                fail_code = 500
                validated_hold = None

            if fail_resp is not None:
                # decision_id is attached regardless of which branch produced
                # fail_resp (the six _validate_approval checks, or the
                # exception path above) — every /v1/decide transit gets one.
                fail_resp["decision_id"] = decision_id
                # NAME THE HOLD THE DENIAL WAS DECIDED AGAINST. This branch is
                # every hold-validation refusal, including the one that says an
                # action was refused BECAUSE ITS HOLD TIMED OUT
                # (reeflex_hold_expired) -- which is exactly the fact an Art.14
                # report needs and, until this line existed, the only record of
                # it carried no hold_id at all, so nothing downstream could
                # attach the denial to the hold it was about. Conditioned on
                # `validated_hold`: the hold_id is written only when this store
                # actually holds that hold, so a hold_id on an audit line always
                # names a real hold and a fabricated/typo'd id in an envelope
                # (reeflex_hold_not_found) never invents a phantom one.
                # parent_decision_id comes from the hold's own creating decision
                # (the same fallback the allow path uses), stitching the refusal
                # back to the request that was originally gated.
                denied_hold_id = ""
                denied_parent = ""
                if validated_hold:
                    denied_hold_id = validated_hold.get("id") or ""
                    denied_parent = validated_hold.get("decision_id") or ""
                _try_audit(
                    session_id, envelope, {}, fail_resp,
                    decision_id=decision_id, hold_id=denied_hold_id,
                    envelope_hash=envelope_hash,
                    parent_decision_id=denied_parent,
                    traceparent=traceparent,
                )
                return fail_code or 200, fail_resp

            # All checks passed — consume the hold and allow
            hold_id = approval.get("hold_id")

            # Resolve parent_decision_id (change 2): the adapter MAY pass the
            # original decision_id back via approval.parent_decision_id.
            # FALLBACK: read the decision_id recorded on the hold at creation
            # time (change 4/1) — the hold names the decision that created it.
            # We reuse `validated_hold` (the SAME hold record _validate_approval
            # already fetched for the six-check chain) rather than issuing a
            # second get_hold(hold_id) here.  mark_consumed() below is a CAS
            # (compare-and-set): its approved-status check and consume-append
            # are atomic under holds.py's module lock, so even under a race
            # (two resubmissions for the same hold_id reaching mark_consumed()
            # concurrently) exactly one wins and the other gets None back,
            # which we deny below as reeflex_hold_already_consumed.
            parent_decision_id = approval.get("parent_decision_id") or ""
            if not isinstance(parent_decision_id, str):
                parent_decision_id = ""
            if not parent_decision_id and validated_hold:
                parent_decision_id = validated_hold.get("decision_id") or ""

            try:
                from .holds import mark_consumed  # type: ignore[import]
                consumed_hold = mark_consumed(hold_id)
            except Exception:  # noqa: BLE001
                # Fail-closed: if we can't consume, deny
                denial = _deny_response(
                    "reeflex_hold_consume_failed", "reeflex.core/hold_validation"
                )
                denial["decision_id"] = decision_id
                _try_audit(
                    session_id, envelope, {}, denial,
                    decision_id=decision_id, envelope_hash=envelope_hash,
                    traceparent=traceparent,
                )
                return 200, denial

            if consumed_hold is None:
                # CAS refusal (holds.mark_consumed): a concurrent racer already
                # won the single-use consume between our _validate_approval
                # read and this call (or the hold was otherwise not
                # "approved" at consume time).  This is the whole point of
                # the CAS guard -- the losing racer MUST be denied, never
                # allowed to double-execute an approved-once irreversible
                # action.  Fail-closed, not "consume failed" (that reason is
                # reserved for the exception branch above).
                denial = _deny_response(
                    "reeflex_hold_already_consumed", "reeflex.core/hold_validation"
                )
                denial["decision_id"] = decision_id
                _try_audit(
                    session_id, envelope, {}, denial,
                    decision_id=decision_id, hold_id=hold_id,
                    envelope_hash=envelope_hash,
                    parent_decision_id=parent_decision_id,
                    traceparent=traceparent,
                )
                return 200, denial

            allow_decision: dict = {
                "decision": "allow",
                "reason": "approved hold resubmission",
                "rule": "reeflex.policy/approved_resubmission",
                "obligations": [],
                "modulation": None,
                "decision_id": decision_id,
            }
            if parent_decision_id:
                allow_decision["parent_decision_id"] = parent_decision_id
            append_entry(session_id, envelope)
            _try_audit(
                session_id, envelope, {}, allow_decision,
                decision_id=decision_id, hold_id=hold_id, envelope_hash=envelope_hash,
                parent_decision_id=parent_decision_id, traceparent=traceparent,
            )
            # NB: the hold_resolution "approved" event is emitted at the human
            # DECISION point (holds.resolve_hold(), symmetric with "rejected"),
            # NOT here at consumption -- so an approved-but-never-consumed hold
            # is still evidenced (Art.14). This resubmission's decision record
            # (above) carries hold_id, correlating the executed action back to
            # that approval. See holds.py + audit.record_hold_resolution().
            _try_emit_decision(
                envelope=envelope,
                decision_response=allow_decision,
                decision_latency_ms=0,
                src_ip=src_ip,
                decision_id=decision_id,
                hold_id=hold_id,
                envelope_hash=envelope_hash,
                parent_decision_id=parent_decision_id,
                traceparent=traceparent,
            )
            return 200, allow_decision

        # Step 5: Compute cumulative state from PRIOR ledger entries
        cumulative = compute_cumulative(session_id, _WINDOW_SECONDS)

        # Step 6: Build OPA input = envelope + injected cumulative
        opa_input = dict(envelope)

        # `cumulative` is CORE-COMPUTED and unconditionally overwritten here,
        # so a caller that puts its own `cumulative` object in the envelope
        # cannot pre-load the ledger with a fabricated history.  Stated
        # explicitly because the assignment is what makes that true.
        opa_input["cumulative"] = cumulative

        # RFX-127 (belt): `input.approval.present` is a VERIFIED fact in the
        # OPA input, never the caller's assertion.
        #
        # By construction every path that reaches this line has approval
        # present=false — Step 4 above now routes EVERY present=true envelope
        # into the six-check validation chain, which either returns a deny or
        # returns allow without consulting OPA at all.  This assignment makes
        # that an ENFORCED property rather than an emergent one: if a future
        # change re-introduces a path where an unvalidated approval reaches
        # eval, the budget rule still sees present=false and still fires.  A
        # rule may only be switched off by an approval core has verified.
        _opa_approval = dict(envelope.get("approval") or {})
        _opa_approval["present"] = False
        opa_input["approval"] = _opa_approval

        # Step 7: Evaluate via OPA — measure wall-clock latency for telemetry.
        # perf_counter is used for latency only; NOT injected into OPA input
        # (determinism invariant holds).
        _t0 = time.perf_counter()
        try:
            opa_result = evaluate(opa_input)
        except OpaEvalError:
            # FAIL-CLOSED: deny on any OPA failure — do NOT silently allow.
            decision_response = dict(_FAIL_CLOSED_DECISION)
            decision_response["decision_id"] = decision_id
            _try_audit(
                session_id, envelope, cumulative, decision_response,
                decision_id=decision_id, envelope_hash=envelope_hash,
                traceparent=traceparent,
            )
            return 500, decision_response
        _decision_latency_ms = int((time.perf_counter() - _t0) * 1000)

        # Step 8: Build the full Decision response (SPEC §5)
        decision_response: dict = {
            "decision": opa_result["decision"],
            "reason": opa_result["reason"],
            "rule": opa_result["rule"],
            "obligations": opa_result.get("obligations", []),
            "modulation": None,  # reserved (SPEC §5)
            "decision_id": decision_id,
        }

        # Step 9: HIL hold creation (T2b) — when verdict is require_approval
        # and there is NO valid approval already (normal first submission)
        if (
            decision_response["decision"] == "require_approval"
            and not approval_present
        ):
            hold_id = None
            expires_ts = None
            try:
                from .holds import create_hold  # type: ignore[import]
                from .webhook import fire as wh_fire  # type: ignore[import]
                hold_rec = create_hold(
                    envelope, decision_response["rule"], decision_id=decision_id,
                )
                hold_id = hold_rec["id"]
                expires_ts = hold_rec["expires_ts"]
                # Annotate the response with hold info
                decision_response["hold_id"] = hold_id
                decision_response["expires_ts"] = expires_ts
                # Fire hold.created webhook (non-blocking, fail-open)
                wh_fire("hold.created", {
                    "hold_id": hold_id,
                    "rule_id": decision_response["rule"],
                    "status": "pending",
                    "expires_ts": expires_ts,
                })
            except Exception:  # noqa: BLE001
                # Fail-closed: hold creation failure -> deny
                denial = dict(_INTERNAL_ERROR_DECISION)
                denial["reason"] = "hold creation failed - failing closed"
                denial["rule"] = "reeflex.core/hold_creation_failed"
                denial["decision_id"] = decision_id
                _try_audit(
                    session_id, envelope, cumulative, denial,
                    decision_id=decision_id, envelope_hash=envelope_hash,
                    traceparent=traceparent,
                )
                return 500, denial

        # Step 10: Append to session ledger AFTER eval
        append_entry(session_id, envelope)

        # Step 11: Audit (best-effort; audit failure does not change the decision)
        # hold_id is carried through only when a hold was just created above
        # (decision_response.get("hold_id", "") is "" on allow/deny).
        # expires_ts rides along the same way, from the SAME hold record that
        # produced the response's expires_ts -- so the audited line and the HTTP
        # response state one identical deadline. Downstream (the evidence
        # connector's tail) this is the only place a consumer can learn when a
        # hold times out: it was previously response-only, so anything reading
        # the log had to guess a TTL, and a guessed TTL drifts from this core's
        # REEFLEX_HOLD_TTL_SECONDS. "" on every non-hold decision.
        _try_audit(
            session_id, envelope, cumulative, decision_response,
            decision_id=decision_id,
            hold_id=decision_response.get("hold_id", "") or "",
            expires_ts=decision_response.get("expires_ts", "") or "",
            envelope_hash=envelope_hash,
            traceparent=traceparent,
        )

        # Step 12: Telemetry emit — FIRE-AND-FORGET, NON-BLOCKING.
        # =========================================================
        # THE INVARIANT: "Fail-closed for decisions, fail-open for telemetry."
        #
        # This call MUST be non-blocking and MUST NEVER raise into /v1/decide.
        # =========================================================
        _try_emit_decision(
            envelope=envelope,
            decision_response=decision_response,
            decision_latency_ms=_decision_latency_ms,
            src_ip=src_ip,
            decision_id=decision_id,
            hold_id=decision_response.get("hold_id", "") or "",
            envelope_hash=envelope_hash,
            traceparent=traceparent,
        )

        return 200, decision_response

    except Exception:  # noqa: BLE001
        # BELT: catch any unguarded exception anywhere in the pipeline.
        # LOG a sanitized one-line message — NO traceback, NO file paths.
        print("[reeflex-core] ERROR: unexpected internal error - failing closed", file=sys.stderr)
        _internal_error = dict(_INTERNAL_ERROR_DECISION)
        _internal_error["decision_id"] = decision_id
        return 500, _internal_error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_audit(
    session_id: str,
    envelope: dict,
    cumulative: dict,
    decision_response: dict,
    *,
    decision_id: str = "",
    hold_id: str = "",
    expires_ts: str = "",
    envelope_hash: str = "",
    parent_decision_id: str = "",
    traceparent: str = "",
) -> None:
    """Best-effort audit write; logs to stderr on failure but never raises.

    The keyword-only traceability fields are additive (default "") so any
    existing/older call site keeps working unmodified.
    """
    try:
        record(
            session_id, envelope, cumulative, decision_response,
            decision_id=decision_id,
            hold_id=hold_id,
            expires_ts=expires_ts,
            envelope_hash=envelope_hash,
            parent_decision_id=parent_decision_id,
            traceparent=traceparent,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-core] WARN: audit write failed: {exc}", file=sys.stderr)


def _try_emit_decision(
    envelope: dict,
    decision_response: dict,
    decision_latency_ms: int,
    src_ip: str = "",
    *,
    decision_id: str = "",
    hold_id: str = "",
    envelope_hash: str = "",
    parent_decision_id: str = "",
    traceparent: str = "",
) -> None:
    """
    Fire-and-forget telemetry emit for one decision event.

    THE INVARIANT: this function MUST NEVER raise. Any failure (queue full,
    disabled emitter, unexpected exception) is silently swallowed.

    The keyword-only traceability fields are additive (default "") so any
    existing/older call site keeps working unmodified.
    """
    try:
        emitter = get_emitter()
        agent = envelope.get("agent") or {}
        action = envelope.get("action") or {}
        target = envelope.get("target") or {}
        axes = envelope.get("axes") or {}
        magnitude = envelope.get("magnitude") or {}
        emitter.emit_decision(
            verdict=decision_response.get("decision", ""),
            rule_id=decision_response.get("rule", ""),
            verb=action.get("verb", ""),
            ability=action.get("ability", ""),
            axes={
                "reversibility": axes.get("reversibility", ""),
                "blast_radius": axes.get("blast_radius", ""),
                "externality": axes.get("externality", ""),
            },
            magnitude_count=int(magnitude.get("count", 1)),
            session_id=agent.get("session_id", ""),
            agent_id=agent.get("id", ""),
            on_behalf_of=agent.get("on_behalf_of", ""),
            environment=target.get("environment", ""),
            mode=envelope.get("context", {}).get("mode", "enforce")
                 if isinstance(envelope.get("context"), dict) else "enforce",
            decision_latency_ms=decision_latency_ms,
            reason=decision_response.get("reason", ""),
            namespace=action.get("namespace", ""),
            src_ip=src_ip,
            target_ref=str(target.get("ref") or ""),
            params=envelope.get("params") or {},
            decision_id=decision_id,
            hold_id=hold_id,
            envelope_hash=envelope_hash,
            parent_decision_id=parent_decision_id,
            traceparent=traceparent,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-core] WARN: telemetry emit failed: {exc}", file=sys.stderr)
