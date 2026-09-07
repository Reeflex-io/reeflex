#!/usr/bin/env python3.11
"""
bite-check-rfx211-rfx218.py — does the RFX-211/RFX-218 guard actually bite?

A test that passes both before and after a fix is not a guard, and this repo has
shipped that mistake twice (RFX-87: a regression guard for a merged security fix
that collected zero tests; RFX-139: an assertion pointed at a short inventory).
So each behavioural line of the fix is REVERTED IN PLACE, one at a time, and the
suite must go RED for the arm that line protects.

Reverting the whole fix at once would be a weaker check: the test module imports
HOLD_STATUSES / UnknownCursor from app.holds, so a wholesale revert produces an
ImportError -- which is red, but only proves the constants are gone, not that the
behaviour is wrong. Each mutation below therefore keeps the constants and breaks
exactly one behaviour.

    python3.11 scripts/bite-check-rfx211-rfx218.py

Exit 0 = every mutation was caught. Exit 1 = at least one mutation survived, i.e.
that part of the guard does not guard.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CORE = REPO / "reeflex-core"
HOLDS = CORE / "app" / "holds.py"
SERVER = CORE / "app" / "server.py"
SUITE = "test_holds_vocabulary_rfx211_rfx218.py"

# (label, file, find, replace, what the mutation re-opens)
MUTATIONS = [
    (
        "RFX-218: resolve_hold coerces instead of raising",
        HOLDS,
        '    if decision not in RESOLVE_DECISIONS:\n        raise ValueError(',
        '    if False:\n        raise ValueError(',
        'the "everything else" arm rejects silently again',
    ),
    (
        "RFX-211: list_holds accepts any status word",
        HOLDS,
        '    if status is not None and status not in LIST_STATUS_FILTERS:\n        raise ValueError(',
        '    if False:\n        raise ValueError(',
        "an unrecognised filter returns an empty list again",
    ),
    (
        "sibling: unknown cursor silently restarts at page 1",
        HOLDS,
        '        if not cursor_positions:',
        '        if False:',
        "a bogus cursor serves page 1 again",
    ),
    (
        "sibling: list_holds accepts any limit",
        HOLDS,
        '    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIST_LIMIT:',
        '    if False:',
        "limit=0 / limit='100' are accepted again",
    ),
    (
        "HTTP: the handler stops refusing an unrecognised status",
        SERVER,
        '        if status_filter is not None and status_filter not in LIST_STATUS_FILTERS:',
        '        if False:',
        "the 400 becomes whatever list_holds does",
    ),
    (
        "anti-short-inventory: a status is dropped from HOLD_STATUSES",
        HOLDS,
        'HOLD_STATUSES: tuple[str, ...] = ("pending", "approved", "rejected", "expired", "consumed")',
        'HOLD_STATUSES: tuple[str, ...] = ("pending", "approved", "rejected", "expired")',
        "the declared vocabulary no longer matches what the store writes",
    ),
]


def run_suite() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".",
         "-p", SUITE],
        cwd=str(CORE), capture_output=True, text=True, timeout=600,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout)[-600:]


def main() -> int:
    green, tail = run_suite()
    if not green:
        print("BASELINE IS NOT GREEN -- nothing below would mean anything.")
        print(tail)
        return 2
    print(f"baseline: GREEN  ({tail.strip().splitlines()[-3] if tail.strip() else ''})")
    print()

    survived = []
    for label, path, find, repl, reopens in MUTATIONS:
        original = path.read_text()
        if find not in original:
            print(f"  SKIP  {label}\n        anchor not found -- the fix moved; "
                  f"this bite must be re-anchored, NOT ignored")
            survived.append(label + " (anchor lost)")
            continue
        try:
            path.write_text(original.replace(find, repl, 1))
            still_green, out = run_suite()
        finally:
            path.write_text(original)
        verdict = "SURVIVED -- NOT GUARDED" if still_green else "caught (suite RED)"
        print(f"  {'BAD ' if still_green else 'BIT '} {label}")
        print(f"        re-opens: {reopens}")
        print(f"        -> {verdict}")
        if still_green:
            survived.append(label)

    # The tree must be exactly as we found it.
    dirty = subprocess.run(
        ["git", "diff", "--stat", "--", "reeflex-core/app/holds.py",
         "reeflex-core/app/server.py"],
        cwd=str(REPO), capture_output=True, text=True,
    ).stdout
    print()
    green_again, _ = run_suite()
    print(f"restored: suite {'GREEN' if green_again else 'RED -- RESTORE FAILED'}")
    if not green_again:
        print(f"working tree diff after restore:\n{dirty}")
        return 2

    print()
    if survived:
        print(f"{len(survived)} of {len(MUTATIONS)} mutations SURVIVED:")
        for s in survived:
            print(f"  - {s}")
        return 1
    print(f"all {len(MUTATIONS)} mutations caught -- the guard bites on every arm.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
