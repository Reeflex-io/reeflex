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
  - Run the validation chain (6 checks).  On FIRST failure return deny with
    a machine reason code.
  - On success: mark_consumed(hold_id), return ALLOW, audit.
"""

from __future__ import annotations

import os
import sys
import time

from .envelope import validate_and_fill_defaults, ValidationError
from .ledger import compute_cumulative, append_entry
from .opa import evaluate, OpaEvalError
from .audit import record
from .telemetry import get_emitter

_WINDOW_SECONDS = int(os.environ.get("REEFLEX_WINDOW_SECONDS", "3600"))

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
    """Audit + webhook for a freeze.flipped event. Best-effort; never raises."""
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

def _get_agent_identity(envelope: dict) -> str:
    """Extract the agent identity string from the envelope.

    Returns the agent.id field, e.g. "agent:wordpress".
    Falls back to "" if not present.
    """
    return (envelope.get("agent") or {}).get("id", "")


def _validate_approval(envelope: dict) -> tuple[int, dict | None]:
    """Validate the hold approval attached to the envelope.

    Returns (status_code, error_dict) on validation failure.
    Returns (0, None) on success (caller should proceed with allow).

    Validation chain per design T2c:
      1. hold exists                       else deny "reeflex_hold_not_found"
      2. status == approved                 else deny "reeflex_hold_not_approved"
      3. not expired                        else deny "reeflex_hold_expired"
      4. status != consumed                 else deny "reeflex_hold_consumed"
      5. canonical_hash(envelope) == stored else deny "reeflex_hold_envelope_mismatch"
      6. agent identity != decided_by ident else deny "reeflex_hold_actor_is_approver"
    """
    from .holds import get_hold, canonical_hash, is_expired  # type: ignore[import]

    approval = (envelope.get("approval") or {})
    hold_id = approval.get("hold_id", "")
    if not hold_id:
        # present=True but no hold_id — treat as not_found
        return 200, _deny_response("reeflex_hold_not_found", "reeflex.core/hold_validation")

    hold = get_hold(hold_id)

    # Check 1: hold exists
    if hold is None:
        return 200, _deny_response("reeflex_hold_not_found", "reeflex.core/hold_validation")

    # Check 2: status == approved
    if hold.get("status") != "approved":
        status_val = hold.get("status", "")
        if status_val == "consumed":
            return 200, _deny_response("reeflex_hold_consumed", "reeflex.core/hold_validation")
        if status_val in ("rejected", "expired"):
            return 200, _deny_response(
                f"reeflex_hold_{status_val}", "reeflex.core/hold_validation"
            )
        return 200, _deny_response("reeflex_hold_not_approved", "reeflex.core/hold_validation")

    # Check 3: not expired (lazy check may have updated status, re-read)
    if is_expired(hold):
        return 200, _deny_response("reeflex_hold_expired", "reeflex.core/hold_validation")

    # Check 4: status != consumed (re-confirm after is_expired re-read)
    if hold.get("status") == "consumed":
        return 200, _deny_response("reeflex_hold_consumed", "reeflex.core/hold_validation")

    # Check 5: canonical_hash of THIS envelope == stored envelope_hash
    # We compute the hash of the envelope as-is (the validated, normalized copy).
    this_hash = canonical_hash(envelope)
    if this_hash != hold.get("envelope_hash", ""):
        return 200, _deny_response(
            "reeflex_hold_envelope_mismatch", "reeflex.core/hold_validation"
        )

    # Check 6: actor != approver
    # Actor = this request's agent identity
    # Approver = the identity part of hold.decided_by ("human:leo" -> "leo")
    actor_id = _get_agent_identity(envelope)
    decided_by = hold.get("decided_by") or ""
    # decided_by format: "{type}:{identity}" — extract the identity part
    if ":" in decided_by:
        approver_id = decided_by.split(":", 1)[1]
    else:
        approver_id = decided_by
    if actor_id and approver_id and actor_id == approver_id:
        return 200, _deny_response(
            "reeflex_hold_actor_is_approver", "reeflex.core/hold_validation"
        )

    return 0, None  # all checks passed


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
    try:
        # Step 1: Validate and fill conservative defaults
        try:
            envelope = validate_and_fill_defaults(raw_body)
        except ValidationError as exc:
            return 400, {
                "error": "invalid_envelope",
                "detail": str(exc),
            }

        # Step 2: Extract session_id — guaranteed non-empty by validate_and_fill_defaults
        session_id: str = (envelope.get("agent") or {}).get("session_id")

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
                }
                _try_audit(session_id, envelope, {}, frozen_decision)
                return 200, frozen_decision

        # Step 4: Check for an approval resubmission (T2c)
        approval = envelope.get("approval") or {}
        approval_present = approval.get("present", False)

        if approval_present and approval.get("hold_id"):
            # Validate the approval chain — fail-closed on any exception
            try:
                fail_code, fail_resp = _validate_approval(envelope)
            except Exception:  # noqa: BLE001
                fail_resp = dict(_INTERNAL_ERROR_DECISION)
                fail_code = 500

            if fail_resp is not None:
                _try_audit(session_id, envelope, {}, fail_resp)
                return fail_code or 200, fail_resp

            # All checks passed — consume the hold and allow
            hold_id = approval.get("hold_id")
            try:
                from .holds import mark_consumed  # type: ignore[import]
                mark_consumed(hold_id)
            except Exception:  # noqa: BLE001
                # Fail-closed: if we can't consume, deny
                denial = _deny_response(
                    "reeflex_hold_consume_failed", "reeflex.core/hold_validation"
                )
                _try_audit(session_id, envelope, {}, denial)
                return 200, denial

            allow_decision: dict = {
                "decision": "allow",
                "reason": "approved hold resubmission",
                "rule": "reeflex.policy/approved_resubmission",
                "obligations": [],
                "modulation": None,
            }
            append_entry(session_id, envelope)
            _try_audit(session_id, envelope, {}, allow_decision)
            _try_emit_decision(
                envelope=envelope,
                decision_response=allow_decision,
                decision_latency_ms=0,
                src_ip=src_ip,
            )
            return 200, allow_decision

        # Step 5: Compute cumulative state from PRIOR ledger entries
        cumulative = compute_cumulative(session_id, _WINDOW_SECONDS)

        # Step 6: Build OPA input = envelope + injected cumulative
        opa_input = dict(envelope)
        opa_input["cumulative"] = cumulative

        # Step 7: Evaluate via OPA — measure wall-clock latency for telemetry.
        # perf_counter is used for latency only; NOT injected into OPA input
        # (determinism invariant holds).
        _t0 = time.perf_counter()
        try:
            opa_result = evaluate(opa_input)
        except OpaEvalError:
            # FAIL-CLOSED: deny on any OPA failure — do NOT silently allow.
            decision_response = dict(_FAIL_CLOSED_DECISION)
            _try_audit(session_id, envelope, cumulative, decision_response)
            return 500, decision_response
        _decision_latency_ms = int((time.perf_counter() - _t0) * 1000)

        # Step 8: Build the full Decision response (SPEC §5)
        decision_response: dict = {
            "decision": opa_result["decision"],
            "reason": opa_result["reason"],
            "rule": opa_result["rule"],
            "obligations": opa_result.get("obligations", []),
            "modulation": None,  # reserved (SPEC §5)
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
                hold_rec = create_hold(envelope, decision_response["rule"])
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
                _try_audit(session_id, envelope, cumulative, denial)
                return 500, denial

        # Step 10: Append to session ledger AFTER eval
        append_entry(session_id, envelope)

        # Step 11: Audit (best-effort; audit failure does not change the decision)
        _try_audit(session_id, envelope, cumulative, decision_response)

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
        )

        return 200, decision_response

    except Exception:  # noqa: BLE001
        # BELT: catch any unguarded exception anywhere in the pipeline.
        # LOG a sanitized one-line message — NO traceback, NO file paths.
        print("[reeflex-core] ERROR: unexpected internal error - failing closed", file=sys.stderr)
        return 500, dict(_INTERNAL_ERROR_DECISION)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_audit(
    session_id: str,
    envelope: dict,
    cumulative: dict,
    decision_response: dict,
) -> None:
    """Best-effort audit write; logs to stderr on failure but never raises."""
    try:
        record(session_id, envelope, cumulative, decision_response)
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-core] WARN: audit write failed: {exc}", file=sys.stderr)


def _try_emit_decision(
    envelope: dict,
    decision_response: dict,
    decision_latency_ms: int,
    src_ip: str = "",
) -> None:
    """
    Fire-and-forget telemetry emit for one decision event.

    THE INVARIANT: this function MUST NEVER raise. Any failure (queue full,
    disabled emitter, unexpected exception) is silently swallowed.
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
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-core] WARN: telemetry emit failed: {exc}", file=sys.stderr)
