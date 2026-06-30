"""
hook.py -- PreToolUse hook entry point for Claude Code.

Implements the four Reeflex adapter responsibilities (SPEC §6):
  1. INTERCEPT  -- Claude Code invokes this script via the PreToolUse hook
                   mechanism BEFORE the tool call executes.  The hook receives
                   a JSON payload on stdin.
  2. NORMALIZE  -- classify.py + envelope.py build a valid signed Action
                   Envelope (SPEC §2).
  3. ENFORCE    -- enforce.py POSTs to reeflex-core /v1/decide and maps the
                   Decision to a permissionDecision (allow|deny|ask).
  4. AUDIT      -- audit.py appends one JSONL record per decision (SPEC §7).

OUTPUT CONTRACT (Claude Code PreToolUse modern form):
  Exit code 0 ALWAYS (even on deny or error).
  Stdout: exactly one JSON line:
    {"hookSpecificOutput":{"hookEventName":"PreToolUse",
                           "permissionDecision":"<allow|deny|ask>",
                           "permissionDecisionReason":"<text>"}}

FAIL-CLOSED CRITICAL INVARIANT:
  A non-zero exit from a PreToolUse hook makes Claude Code CONTINUE the tool
  anyway -- silent allow!  Therefore:
  * We ALWAYS exit(0).
  * On ANY error (bad stdin, JSON parse failure, missing session_id, core
    unreachable, timeout, unknown decision, any exception at all) we emit a
    DENY response and exit(0).
  * The top-level try/except in main() is the last safety net.  Inner modules
    also handle their own errors (belt and suspenders), but we never rely on
    them in isolation.
  * Every stdout print is wrapped in try/except Exception to handle BrokenPipe
    (which would otherwise propagate and cause a non-zero exit -> silent allow).

OBLIGATIONS (SPEC §5 / §7 M5):
  Supported obligations: {"audit:full"} -- honored by construction (we always
  write a full JSONL audit record).  If core returns an allow decision with an
  obligation we cannot honor, we OVERRIDE the decision to deny (fail-closed).
  deny/ask with unsupported obligations are audited and passed through (action
  is not running so no mandatory side-effect can be missed).

Usage:
  python -m reeflex_claude             (preferred -- works from any cwd)
  python hook_entry.py                 (convenience shim at repo root)
"""

from __future__ import annotations

import json
import sys

# Obligations we can honor by construction.
# audit:full is satisfied because we always write a complete JSONL audit record.
SUPPORTED_OBLIGATIONS = frozenset({"audit:full"})

_MAX_ERR_LEN = 300  # max chars of exception text embedded in reason strings


def _trunc_err(text: str) -> str:
    """Truncate error text to avoid embedding huge strings in reason fields."""
    s = str(text)
    return s[:_MAX_ERR_LEN] + "...[truncated]" if len(s) > _MAX_ERR_LEN else s


def _deny_output(reason: str) -> str:
    """Build the deny hookSpecificOutput JSON string."""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(payload, separators=(",", ":"))


def _output(permission_decision: str, reason: str) -> str:
    """Build the hookSpecificOutput JSON string for any decision."""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(payload, separators=(",", ":"))


def _safe_print(msg: str) -> None:
    """
    Print msg to stdout, swallowing BrokenPipeError and any other I/O error.
    This is critical: an uncaught BrokenPipeError from the final print would
    propagate to main()'s outer handler, whose own print could also raise,
    causing Python to exit non-zero -- which makes Claude Code CONTINUE the
    tool anyway (silent allow).
    """
    try:
        print(msg, flush=True)
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    """
    Main entry point.  Reads stdin, runs the full INTERCEPT->NORMALIZE->
    ENFORCE->AUDIT pipeline, writes stdout, exits 0.

    The outer try/except is the absolute last-resort fail-closed net.
    All inner modules also defend themselves, but we never trust that.
    sys.exit(0) is guaranteed to run via the finally block.
    """
    try:
        _run_pipeline()
    except Exception as exc:  # noqa: BLE001
        # Belt-and-suspenders: something escaped every inner guard.
        # Emit deny and exit 0 -- NEVER exit non-zero.
        msg = _deny_output(
            f"Reeflex: unexpected hook error -- failing closed: "
            f"{_trunc_err(exc)} [rule=reeflex.core/fail_closed]"
        )
        _safe_print(msg)
        # Best-effort stderr (non-fatal)
        try:
            print(f"[reeflex-claude] ERROR: unexpected: {_trunc_err(exc)}",
                  file=sys.stderr)
        except Exception:
            pass
    finally:
        # sys.exit(0) is in a finally block so it ALWAYS runs even if the
        # except branch itself raises (e.g. BrokenPipe on the error print).
        sys.exit(0)


def _run_pipeline() -> None:
    """
    Inner pipeline: parse stdin -> classify -> build envelope -> enforce ->
    obligations check -> audit -> print output.

    Raises on unhandled logic errors (caught by main()'s outer try/except).
    """
    # ------------------------------------------------------------------
    # Step 1: Read and parse stdin
    # ------------------------------------------------------------------
    try:
        raw_stdin = sys.stdin.read()
        hook_payload = json.loads(raw_stdin)
    except Exception as exc:
        _safe_print(_deny_output(
            f"Reeflex: could not parse hook stdin -- failing closed: "
            f"{_trunc_err(exc)} [rule=reeflex.core/fail_closed]"
        ))
        return

    # ------------------------------------------------------------------
    # Step 2: Validate session_id (REQUIRED for anti-fragmentation -- SPEC §4.1)
    # ------------------------------------------------------------------
    session_id = hook_payload.get("session_id") or ""
    if not session_id:
        _safe_print(_deny_output(
            "Reeflex: session_id missing in hook payload -- failing closed "
            "[rule=reeflex.core/fail_closed]"
        ))
        return

    # ------------------------------------------------------------------
    # Step 3: NORMALIZE -- classify + build envelope
    # ------------------------------------------------------------------
    from .classify import classify
    from .envelope import build_envelope

    tool_name  = hook_payload.get("tool_name") or "unknown"
    tool_input = hook_payload.get("tool_input") or {}

    try:
        cls      = classify(tool_name, tool_input)
        envelope = build_envelope(hook_payload, cls)
    except Exception as exc:
        _safe_print(_deny_output(
            f"Reeflex: envelope build failed -- failing closed: "
            f"{_trunc_err(exc)} [rule=reeflex.core/fail_closed]"
        ))
        return

    # ------------------------------------------------------------------
    # Step 4: ENFORCE -- call core, map decision (returns 5-tuple now)
    # ------------------------------------------------------------------
    from .enforce import call_core_and_map

    permission_decision, reason_text, rule, core_reachable, obligations = \
        call_core_and_map(envelope)

    # ------------------------------------------------------------------
    # Step 5: OBLIGATIONS CHECK (SPEC §5 / §7 M5)
    # Honor obligations fail-closed: if core returns allow with an obligation
    # we cannot satisfy, OVERRIDE to deny rather than silently proceeding.
    # deny/ask: action is not running so unsupported obligations are not
    # a safety gap -- audit them and pass through.
    # ------------------------------------------------------------------
    if permission_decision == "allow" and obligations:
        unsupported = [o for o in obligations if o not in SUPPORTED_OBLIGATIONS]
        if unsupported:
            permission_decision = "deny"
            rule = "adapter/unsupported_obligation"
            reason_text = (
                f"Reeflex: cannot honor obligation(s) {unsupported} -- failing closed "
                f"[rule=adapter/unsupported_obligation]"
            )

    # ------------------------------------------------------------------
    # Step 6: AUDIT -- best-effort, never changes the decision
    # ------------------------------------------------------------------
    from .audit import emit as audit_emit
    try:
        audit_emit(
            envelope=envelope,
            permission_decision=permission_decision,
            rule=rule,
            reason=reason_text,
            core_reachable=core_reachable,
            obligations=obligations,
        )
    except Exception as exc:  # noqa: BLE001
        # Audit failure MUST NOT affect the decision
        try:
            print(f"[reeflex-claude] WARN: audit failed: {_trunc_err(exc)}",
                  file=sys.stderr)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Step 7: Emit hookSpecificOutput
    # ------------------------------------------------------------------
    _safe_print(_output(permission_decision, reason_text))


if __name__ == "__main__":
    main()
