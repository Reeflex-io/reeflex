"""
deadline.py -- answer before Claude Code's PreToolUse runner kills the hook.

WHY THIS MODULE EXISTS (RFX-321 / RFX-322, measured by qa--221 on the real
`claude` 2.1.268 binary and the published reeflex-claude 0.2.0 wheel).

hook.py's FAIL-CLOSED invariant says "on ANY error we emit deny".  That was
true and insufficient, because *a hook that dies is not an error the hook gets
to handle*.  Claude Code's PreToolUse runner kills a hook at the timeout
written in settings.json and then RUNS THE TOOL (qa--221 Finding C, arm G,
reproduced twice).  So the invariant holds only while we return first, and two
customer-reachable conditions broke that precondition:

  A. `REEFLEX_CLAUDE_TIMEOUT=45` against an engine that accepts the connection
     and never answers.  The socket waited 45 s, the runner killed the hook at
     30 s, and `rm -rf <production fixture>` RAN, with no human.  Two numbers
     set in two places with no clamp between them; 45 is exactly what a
     slow-engine operator reaches for.
  B. A Bash command large enough (>= ~700 KB) that `classify()` alone overran
     the 30 s hook timeout.  Same ending.

So the fix is not another error handler.  It is a clock: a deadline strictly
inside the runner's timeout, and a real answer on stdout before the runner can
kill us -- for as long as the work we are waiting on lets a timer thread run.
That covers a blocked socket and a classifier executing Python, which is
findings A and B above.  It does not cover work that holds the GIL for the
whole wait; see the limitations section at the end of this docstring.

THE ONE NUMBER, AND WHY YOU CAN ONLY LOWER IT
---------------------------------------------
Finding A is "two numbers, and the customer sets the wrong one bigger".  A fix
that adds a third settable number repeats it.  So:

  * `RUNNER_TIMEOUT_SECONDS` is the single source of truth.  It is the timeout
    `reeflex-claude setup` writes into the settings.json hook entry, and the
    timeout this module derives its deadline from.  `setup_settings.py` imports
    it from here rather than declaring its own.
  * `REEFLEX_CLAUDE_HOOK_TIMEOUT` lets an operator tell the hook that the
    runner's timeout is SHORTER than the built-in default (a hand-edited
    settings.json, an enterprise policy file).  It is clamped by
    `min(declared, RUNNER_TIMEOUT_SECONDS)`: **it can only make the gate answer
    sooner, never later.**
  * `REEFLEX_CLAUDE_TIMEOUT` (the HTTP socket timeout, enforce.py) is clamped
    under whatever is left of the deadline.  Setting it to 45 or 60 no longer
    buys 45 or 60 seconds; it buys what remains of the budget.

WHAT THAT COSTS, STATED RATHER THAN DISCOVERED LATER.  An operator who raises
the hook entry's timeout to 60 s because their engine is genuinely slow does
NOT get a 60 s budget from this version -- the deadline stays derived from the
30 s default and they will see `deny` at ~24 s with a reason that says so.
That is the deliberate direction: answering too early is a noisy deny, and
answering too late is the fail-open this module exists to close.  Raising the
ceiling needs a change to `RUNNER_TIMEOUT_SECONDS` -- a release, not an env var.

THE CLOCK STARTS AT IMPORT, NOT AT main()
-----------------------------------------
`_STARTED` is set when this module is first imported, which is earlier than
`hook.main()` and therefore conservative.  What is NOT in the clock is the
interpreter's own startup and the import of this module (~0.1-0.4 s measured on
CPython 3.9-3.12).  The 20 % reserve below absorbs it with room to spare; that
reserve is the reason the deadline is a fraction rather than `timeout - 0.1`.

WHAT THIS MODULE DOES NOT CLOSE
-------------------------------
Nothing here can help when the hook never starts (a missing command, a broken
PATH: RFX-205) or when the event never reaches the hook at all (the matcher:
RFX-204/206).  Those are a different layer and have their own tickets.  This
module is only about a hook that DID start and must finish in time.

A DEADLINE THAT IS A PYTHON THREAD CANNOT PREEMPT WORK THAT HOLDS THE GIL.
`arm()` schedules a `threading.Timer`.  CPython's `sre` engine does not release
the GIL for the duration of a single `re.search`, so while one match is running
the timer thread does not get scheduled and the deadline fires late by however
long that match takes -- measured by qa--233 as lateness independent of the
budget, and |fired - work_end| = 0.00 on every regex arm.  This is a property of
the runtime, not something this module can defend against; the durable bound on
regex time is bounding the INPUT.  RFX-338 is the instance that was reachable in
a shipped wheel: `_SENSITIVE_PATH_RE` ran uncapped on Write/Edit `file_path`,
and classify.py now bounds that field at `MAX_FILE_PATH_CHARS` before any
pattern touches it.  `test_deadline_declares_what_it_cannot_preempt.py` measures
the preemption property and requires this section to keep declaring it, so the
promise above cannot drift back to an unconditional one.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# The one number
# ---------------------------------------------------------------------------

# The PreToolUse hook timeout, in seconds, that `reeflex-claude setup` writes
# into settings.json -- and therefore the runner timeout this module must
# finish inside.  setup_settings.DEFAULT_TIMEOUT is an alias of this value so
# the installer and the clock cannot drift apart.
RUNNER_TIMEOUT_SECONDS = 30.0

# Operator override.  Read for LOWERING only -- see the module docstring.
# `reeflex-claude setup` writes it into settings["env"] alongside the hook
# entry it writes, so the two values come from one command; `reeflex-claude
# check` re-reads both and refuses to call an installation healthy when the
# env value is larger than the hook entry's timeout.
HOOK_TIMEOUT_ENV = "REEFLEX_CLAUDE_HOOK_TIMEOUT"

# Answer at 80 % of the runner's timeout, and never later than 0.5 s before it.
# At the shipped 30 s that is 24.0 s, leaving 6 s for interpreter startup, the
# stdout write, one appended audit line and the runner's own scheduling.
_DEADLINE_FRACTION = 0.8
_MIN_RESERVE       = 0.5
_FLOOR             = 0.1

# Time kept back from the socket budget so that the answer can still be
# written, and audited, after the last possible network read returns.
_EMIT_RESERVE = 0.25

_STARTED = time.monotonic()

# Is there a PreToolUse runner counting down at us?
#
# ONLY A HOOK PROCESS HAS A DEADLINE.  `enforce.call_core_and_map()` is also a
# library entry point -- reeflex-litellm's contract suite calls it directly to
# assert the two seats map a Decision the same way, and any embedder may.  A
# clock started at import and never reset turns every such caller into a
# permanent `deny` once the process has been alive for longer than the
# deadline: measured, not reasoned -- the first draft of this module did
# exactly that, and reeflex-litellm's suite went red on case 3 and 4 while the
# same cases passed in isolation, because by then the process was 60 s old.
#
# So the budget binds only after hook.main() has ARMED it, which is also the
# moment the clock is meaningful: there is a runner, and it started counting
# when this process was spawned.  Unarmed, `budget_for()` returns what the
# caller asked for and nothing here constrains anything.
_ARMED = False


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------

def is_armed() -> bool:
    """True once a hook process has armed the watchdog for this run."""
    return _ARMED

def runner_timeout() -> float:
    """
    The PreToolUse runner's timeout, in seconds, as best we can know it.

    Defaults to RUNNER_TIMEOUT_SECONDS.  HOOK_TIMEOUT_ENV may lower it and may
    NOT raise it: a value a customer can set above the runner's real timeout is
    exactly the defect this module closes (Finding A).  Unparseable or
    non-positive values are ignored rather than trusted.
    """
    declared = RUNNER_TIMEOUT_SECONDS
    raw = os.environ.get(HOOK_TIMEOUT_ENV, "").strip()
    if raw:
        try:
            value = float(raw)
        except (ValueError, TypeError):
            value = 0.0
        if value > 0:
            declared = value
    return min(declared, RUNNER_TIMEOUT_SECONDS)


def deadline() -> float:
    """Seconds after `_STARTED` at which we must have answered."""
    timeout = runner_timeout()
    return max(_FLOOR, min(timeout * _DEADLINE_FRACTION, timeout - _MIN_RESERVE))


def elapsed() -> float:
    """Seconds since this module was imported."""
    return time.monotonic() - _STARTED


def remaining() -> float:
    """Seconds left before the deadline.  Negative once it has passed."""
    return deadline() - elapsed()


def expired() -> bool:
    """True once the deadline has passed."""
    return remaining() <= 0


def budget_for(requested: float) -> float:
    """
    Clamp a caller's own timeout under what is left of the deadline.

    Returns 0.0 when there is no time left to spend -- the caller must fail
    closed immediately rather than start an I/O it cannot finish.

    Outside an armed hook process there is no runner to beat, so the caller's
    own timeout is returned untouched.  See `_ARMED`.
    """
    if not _ARMED:
        return requested
    left = remaining() - _EMIT_RESERVE
    if left <= 0:
        return 0.0
    if requested is None or requested <= 0:
        return left
    return min(requested, left)


# ---------------------------------------------------------------------------
# The watchdog
# ---------------------------------------------------------------------------

def arm(on_deadline: Callable[[float], None]) -> Optional[threading.Timer]:
    """
    Start a daemon timer that calls `on_deadline(deadline_seconds)` when the
    deadline passes.

    The callback is expected to write the answer and terminate the process --
    printing is not enough on its own.  A hook that prints at 24 s and is then
    killed at 30 s has still been killed, and qa--221 arm G measured what the
    runner does with a killed hook: it runs the tool.  So the exit is the load-
    bearing half, and it belongs to the caller (hook.py) because only the
    caller knows what a correct answer looks like in the current mode -- deny in
    enforce, allow in observe (HIL-DESIGN §8).

    Arming does NOT restart the clock.  The clock is import time, which is
    earlier than main() and therefore closer to when the runner actually
    started counting; restarting it here would hand back the milliseconds the
    imports already spent, in the one direction that is unsafe.

    Returns the timer (daemon, already started), or None when the deadline has
    already passed -- in which case the callback is invoked inline instead, so
    "armed" always means "someone will answer".
    """
    global _ARMED
    _ARMED = True
    left = remaining()
    if left <= 0:
        on_deadline(deadline())
        return None
    timer = threading.Timer(left, on_deadline, args=(deadline(),))
    timer.daemon = True
    timer.start()
    return timer


def restart_clock() -> None:
    """
    Reset the clock to now and disarm.  For tests only -- nothing in the hook
    path calls it, and nothing in the hook path may: a hook that could restart
    its own clock could out-wait the runner again.
    """
    global _STARTED, _ARMED
    _STARTED = time.monotonic()
    _ARMED = False
