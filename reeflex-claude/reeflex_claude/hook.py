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

FAIL-CLOSED CRITICAL INVARIANT (enforce mode, the default):
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

AND A DEADLINE, BECAUSE "DENY ON ERROR" IS NOT ENOUGH (RFX-321/322)
  A hook that DIES is not an error the hook gets to handle.  Measured by
  qa--221 on `claude` 2.1.268: when a PreToolUse hook exceeds its settings.json
  timeout the runner kills it and RUNS THE TOOL -- so every guarantee above is
  conditional on returning first, and two customer-reachable conditions broke
  that (a socket timeout set above the hook timeout; a Bash command large
  enough that classify() alone overran it).  Both put `rm -rf` through with no
  human.  So main() arms a watchdog that writes a real answer and terminates
  the process strictly INSIDE the runner's timeout (deadline.py), and every
  stdout write in this module goes through _emit_once(), so the watchdog and
  the pipeline can never both answer.

  In observe mode the deadline answer is ALLOW, not deny: observe must never
  block the user (HIL-DESIGN §8), and a watchdog that denied would turn the
  non-blocking mode into the blocking one at 24 s.

When REEFLEX_MODE=observe, the hook records the would-be verdict but always
emits allow, and fails OPEN on error (never blocks) -- HIL-DESIGN §8.

OBLIGATIONS (SPEC §5 / §7 M5):
  Supported obligations: {"audit:full"} -- honored by construction (we always
  write a full JSONL audit record).  If core returns an allow decision with an
  obligation we cannot honor, we OVERRIDE the decision to deny (fail-closed).
  deny/ask with unsupported obligations are audited and passed through (action
  is not running so no mandatory side-effect can be missed).

Usage:
  python /abs/path/to/hook_entry.py    (preferred -- hooks run from the project
                                        cwd, so always wire the absolute-path shim)
  python -m reeflex_claude             (ONLY if cwd is reeflex-claude/; from any
                                        other cwd the import fails with exit 1,
                                        which a PreToolUse hook treats as FAIL-OPEN)
"""

from __future__ import annotations

import json
import os
import sys
import threading

from . import audit, deadline

# Obligations we can honor by construction.
# audit:full is satisfied because we always write a complete JSONL audit record.
SUPPORTED_OBLIGATIONS = frozenset({"audit:full"})

_MAX_ERR_LEN = 300  # max chars of exception text embedded in reason strings

# The rule id a deadline answer is recorded under.  It is its own id and not
# reeflex.core/fail_closed, because "the engine said nothing" and "we ran out
# of time to listen" are different operator problems with different fixes.
DEADLINE_RULE = "reeflex.core/deadline_exceeded"

# The rule id for a command too large to classify (RFX-322, classify.py's cap).
OVERSIZE_RULE = "adapter/command_too_large"

# ---------------------------------------------------------------------------
# Single emission
# ---------------------------------------------------------------------------
# Two threads can reach stdout: the pipeline, and the deadline watchdog.  Two
# JSON lines on a PreToolUse hook's stdout is an undefined verdict -- qa--221
# arm E measured what Claude Code does with stdout it cannot parse, and the
# answer is "runs the tool".  So exactly one of them writes, ever.
_emit_lock = threading.Lock()
_emitted = False

# The last envelope the pipeline built, so that a deadline answer can still be
# audited as the action it was about rather than as an anonymous timeout.
_envelope_seen: dict = {}


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


def _safe_print(msg: str) -> bool:
    """
    Emit msg as THE answer, at most once per process.

    Swallows BrokenPipeError and any other I/O error.  This is critical: an
    uncaught BrokenPipeError from the final print would propagate to main()'s
    outer handler, whose own print could also raise, causing Python to exit
    non-zero -- which makes Claude Code CONTINUE the tool anyway (silent allow).

    At most once, because the deadline watchdog answers from another thread:
    whoever gets here first is the verdict, and the loser writes nothing.
    Returns True if this call was the one that wrote.
    """
    return _emit_once(msg)


def _emit_once(msg: str, lock_timeout: float = -1) -> bool:
    """
    Write msg to stdout iff nothing has been written yet.  Returns whether this
    call wrote.

    lock_timeout: how long to wait for the emit lock.  The watchdog passes a
    short one so that a pipeline thread stuck mid-write cannot also stop the
    process from exiting before the runner kills it -- losing the answer is
    bad, losing the answer AND the exit is the fail-open.
    """
    global _emitted
    if not _emit_lock.acquire(True, lock_timeout):
        return False
    try:
        if _emitted:
            return False
        _emitted = True
        try:
            sys.stdout.write(msg + "\n")
            sys.stdout.flush()
        except Exception:  # noqa: BLE001
            pass
        return True
    finally:
        _emit_lock.release()


def _on_deadline(deadline_s: float) -> None:
    """
    The watchdog.  Answer, record, and TERMINATE -- in that order.

    Printing on its own is not the fix.  A hook that prints at 24 s and is then
    killed at 30 s has still been killed, and arm G of qa--221's matrix is what
    the runner does with a killed hook: it runs the tool.  So this ends with
    os._exit(0), which is also why it does not run atexit handlers or flush
    anything the pipeline may have buffered -- there is nothing else to flush,
    every answer this module produces goes through _emit_once().

    The audit line is written AFTER stdout and BEFORE the exit: the answer is
    the safety property and the record is the evidence, so the record never
    goes first.  At the shipped 30 s timeout there are ~6 s of margin left at
    this point and appending one JSONL line costs well under a millisecond.
    """
    reason = (
        f"Reeflex: no decision within {deadline_s:.1f}s -- failing closed at the hook "
        f"deadline, before Claude Code's PreToolUse runner "
        f"({deadline.runner_timeout():.0f}s) kills this hook and runs the tool "
        f"anyway [rule={DEADLINE_RULE}]"
    )
    wrote = _emit_once(_fail_output(reason), lock_timeout=0.5)
    if wrote:
        try:
            audit.emit(
                envelope=_envelope_seen.get("envelope") or {},
                permission_decision="deny",
                rule=DEADLINE_RULE,
                reason=reason,
                core_reachable=False,
                obligations=[],
                mode=_mode(),
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            print(f"[reeflex-claude] ERROR: hook deadline {deadline_s:.1f}s reached; "
                  f"answered without the engine", file=sys.stderr)
        except Exception:  # noqa: BLE001
            pass
    os._exit(0)


def _mode() -> str:
    """Return the current operating mode: 'observe' or 'enforce' (default)."""
    m = os.environ.get("REEFLEX_MODE", "enforce").strip().lower()
    return "observe" if m == "observe" else "enforce"


def _fail_output(reason: str) -> str:
    """
    Build the error/failure hookSpecificOutput JSON string.

    enforce: deny (fail-closed) -- a failure must never silently allow.
    observe: allow (fail-open)  -- observe must never block the user.
    HIL-DESIGN §8.
    """
    if _mode() == "observe":
        return _output("allow", "Reeflex observe (fail-open): " + reason)
    return _deny_output(reason)


def main() -> None:
    """
    Main entry point.  Reads stdin, runs the full INTERCEPT->NORMALIZE->
    ENFORCE->AUDIT pipeline, writes stdout, exits 0.

    The outer try/except is the absolute last-resort fail-closed net.
    All inner modules also defend themselves, but we never trust that.
    sys.exit(0) is guaranteed to run via the finally block.

    The watchdog is armed BEFORE the pipeline runs and is never disarmed: it is
    a daemon thread, so it cannot hold the process open, and _emit_once() makes
    a late firing a no-op.  Disarming it would be one more ordering to get
    right on a path whose whole point is that the ordering can fail.
    """
    deadline.arm(_on_deadline)
    try:
        _run_pipeline()
    except Exception as exc:  # noqa: BLE001
        # Belt-and-suspenders: something escaped every inner guard.
        # enforce: emit deny (fail-closed).  observe: emit allow (fail-open).
        # NEVER exit non-zero.
        err_text = f"{_trunc_err(exc)} [rule=reeflex.core/fail_closed]"
        if _mode() == "observe":
            msg = _output(
                "allow",
                f"Reeflex observe (fail-open): unexpected hook error: {err_text}",
            )
        else:
            msg = _deny_output(
                f"Reeflex: unexpected hook error -- failing closed: {err_text}"
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
        _safe_print(_fail_output(
            f"Reeflex: could not parse hook stdin -- failing closed: "
            f"{_trunc_err(exc)} [rule=reeflex.core/fail_closed]"
        ))
        return

    # ------------------------------------------------------------------
    # Step 2: Validate session_id (REQUIRED for anti-fragmentation -- SPEC §4.1)
    # ------------------------------------------------------------------
    session_id = hook_payload.get("session_id") or ""
    if not session_id:
        _safe_print(_fail_output(
            "Reeflex: session_id missing in hook payload -- failing closed "
            "[rule=reeflex.core/fail_closed]"
        ))
        return

    # ------------------------------------------------------------------
    # Step 2b: ADAPTER POSTURE (RFX-325) -- once per session, before anything
    # that can fail.
    #
    # An installation set up before 0.2.0 still carries 0.1.7's narrow matcher,
    # because `pip install -U` does not rewrite settings.json.  qa--222
    # measured what that looks like from outside: the ungated tool runs, the
    # adapter writes nothing, core is asked nothing -- byte for byte what an
    # installation with NO Reeflex hook produces.  The owner's decision is warn
    # and RUN (a narrowing may be deliberate and this hook cannot tell
    # deliberate from stale), so this call changes no decision; it only makes
    # the two states distinguishable by leaving one record per session.
    #
    # Placed here on purpose: it runs before classify/envelope/core, so a
    # session whose every call fails at one of those still says, once, which
    # tools were reaching this hook at all.  It cannot raise (posture.py
    # swallows its own exceptions) and after the first call of a session it
    # costs one stat.
    # ------------------------------------------------------------------
    try:
        from .posture import note_once
        note_once(session_id, mode=_mode())
    except Exception:  # noqa: BLE001
        pass

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
        # Hand the envelope to the watchdog: if the deadline fires during the
        # engine call, the audit line still says WHICH action was refused.
        _envelope_seen["envelope"] = envelope
    except Exception as exc:
        _safe_print(_fail_output(
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
    # Note: obligations check runs on the would-be decision in both modes;
    # in observe mode the would-be deny is recorded but allow is emitted.
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
    # Step 5b: OVERSIZE REFUSAL (RFX-322)
    # classify.py refuses to tokenize a Bash command past its cap and marks it
    # `oversize_command`.  The engine still SEES the action -- the envelope is
    # small (a 200-char preview), the round trip is inside the deadline, and an
    # operator who cannot see these events in their ledger cannot raise the cap
    # for the job that needs it.  But the adapter's own answer is deny, whatever
    # comes back: `ask` on a command no one can read is a dialog, not a
    # decision, and `allow` is the fail-open this ticket exists to close.
    # ------------------------------------------------------------------
    if (envelope.get("context") or {}).get("danger_signature") == "oversize_command" \
            and permission_decision != "deny":
        from .classify import max_bash_command_chars

        permission_decision = "deny"
        rule = OVERSIZE_RULE
        reason_text = (
            f"Reeflex: Bash command is longer than the {max_bash_command_chars()} "
            f"character limit this gate will classify -- refusing rather than "
            f"deciding on a command it has not read [rule={OVERSIZE_RULE}]"
        )

    # Determine operating mode AFTER computing the would-be verdict above.
    mode = _mode()

    # ------------------------------------------------------------------
    # Step 6: AUDIT -- best-effort, never changes the decision.
    # We pass the WOULD-BE permission_decision so the audit trail always
    # reflects what enforcement would have done (HIL-DESIGN §8).
    # ------------------------------------------------------------------
    try:
        audit.emit(
            envelope=envelope,
            permission_decision=permission_decision,
            rule=rule,
            reason=reason_text,
            core_reachable=core_reachable,
            obligations=obligations,
            mode=mode,
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
    # In observe mode: always emit allow (fail-open); record the would-be
    # verdict in the reason so the operator can see it.
    # In enforce mode: emit the computed decision unchanged.
    # ------------------------------------------------------------------
    if mode == "observe":
        _safe_print(_output(
            "allow",
            f"Reeflex observe -- would be '{permission_decision}' {reason_text}; "
            f"not enforced (observe mode)",
        ))
    else:
        _safe_print(_output(permission_decision, reason_text))


if __name__ == "__main__":
    main()
