"""
decide.py — Core decision handler for POST /v1/decide.

Orchestrates the full decision pipeline per SPEC §5 + §6:
  1. Validate envelope (structural; conservative defaults for missing axis values)
  2. Compute cumulative state from session ledger (SPEC §4.1)
  3. Inject cumulative into the OPA input
  4. Evaluate via OPA -> Decision
  5. FAIL-CLOSED on any OPA error
  6. Append to session ledger (AFTER eval)
  7. Append to audit log
  8. Return Decision

Returns a (status_code, response_dict) tuple.  The HTTP layer is in server.py.

DETERMINISM INVARIANT:
  Given the same Action Envelope AND the same session ledger state, this
  function always returns the same Decision.  No clocks or randomness are
  consulted in the OPA input (the timestamp is for audit only, not policy eval).

FAIL-CLOSED INVARIANT:
  If OPA errors, times out, or returns undefined/empty -> deny, reason
  "policy evaluation unavailable - failing closed", rule "reeflex.core/fail_closed".
  We NEVER return allow on an OPA error.
"""

from __future__ import annotations

import os
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


def process(raw_body: dict) -> tuple[int, dict]:
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
    import sys
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
        # (F3: missing/empty session_id was already rejected as HTTP 400 above).
        session_id: str = (envelope.get("agent") or {}).get("session_id")

        # Step 3: Compute cumulative state from PRIOR ledger entries
        cumulative = compute_cumulative(session_id, _WINDOW_SECONDS)

        # Step 4: Build OPA input = envelope + injected cumulative
        opa_input = dict(envelope)
        opa_input["cumulative"] = cumulative

        # Step 5: Evaluate via OPA — measure wall-clock latency for telemetry.
        # perf_counter is used for latency only; it is NOT injected into OPA
        # input and does NOT affect the decision (determinism invariant holds).
        _t0 = time.perf_counter()
        try:
            opa_result = evaluate(opa_input)
        except OpaEvalError:
            # FAIL-CLOSED: deny on any OPA failure — do NOT silently allow.
            decision_response = dict(_FAIL_CLOSED_DECISION)
            # Still audit the fail-closed event (best-effort; don't raise if audit fails)
            _try_audit(session_id, envelope, cumulative, decision_response)
            return 500, decision_response
        _decision_latency_ms = int((time.perf_counter() - _t0) * 1000)

        # Step 6: Build the full Decision response (SPEC §5)
        # F4: use obligations from OPA result (opa.py already extracts value.get("obligations", []))
        decision_response: dict = {
            "decision": opa_result["decision"],
            "reason": opa_result["reason"],
            "rule": opa_result["rule"],
            "obligations": opa_result.get("obligations", []),
            "modulation": None,  # reserved (SPEC §5)
        }

        # Step 7: Append to session ledger AFTER eval (so cumulative was accurate)
        append_entry(session_id, envelope)

        # Step 8: Audit (best-effort; audit failure does not change the decision)
        _try_audit(session_id, envelope, cumulative, decision_response)

        # Step 9: Telemetry emit — FIRE-AND-FORGET, NON-BLOCKING.
        # =========================================================
        # THE INVARIANT: "Fail-closed for decisions, fail-open for telemetry."
        #
        # This call MUST be non-blocking and MUST NEVER raise into /v1/decide.
        # The emitter uses queue.put_nowait() internally; if the queue is full,
        # the message is silently dropped (dropped_events counter incremented).
        # Socket errors, DNS failures, TLS failures, and slow endpoints are ALL
        # swallowed in the background worker thread — they never surface here.
        # The audit JSONL (Step 8) remains the authoritative record regardless.
        # =========================================================
        _try_emit_decision(
            envelope=envelope,
            decision_response=decision_response,
            decision_latency_ms=_decision_latency_ms,
        )

        return 200, decision_response

    except Exception:  # noqa: BLE001
        # BELT: catch any unguarded exception anywhere in the pipeline.
        # Log a sanitized one-line message — NO traceback, NO file paths.
        print("[reeflex-core] ERROR: unexpected internal error - failing closed", file=sys.stderr)
        return 500, dict(_INTERNAL_ERROR_DECISION)


def _try_audit(
    session_id: str,
    envelope: dict,
    cumulative: dict,
    decision_response: dict,
) -> None:
    """Best-effort audit write; logs to stderr on failure but never raises."""
    import sys
    try:
        record(session_id, envelope, cumulative, decision_response)
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-core] WARN: audit write failed: {exc}", file=sys.stderr)


def _try_emit_decision(
    envelope: dict,
    decision_response: dict,
    decision_latency_ms: int,
) -> None:
    """
    Fire-and-forget telemetry emit for one decision event.

    THE INVARIANT: this function MUST NEVER raise. Any failure (queue full,
    disabled emitter, unexpected exception) is silently swallowed. The
    decision has already been computed and audited before this is called.
    Telemetry loss is acceptable; decision integrity is not.
    """
    import sys
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
        )
    except Exception as exc:  # noqa: BLE001
        # Belt: telemetry must never surface into the decision path.
        print(f"[reeflex-core] WARN: telemetry emit failed: {exc}", file=sys.stderr)
