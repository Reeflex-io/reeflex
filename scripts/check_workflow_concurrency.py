#!/usr/bin/env python3
"""check_workflow_concurrency.py — a run that was cancelled did not report (RFX-134)

WHY THIS EXISTS. `concurrency.group` for `ci.yml` and `gate.yml` evaluates to
the same string on EVERY push to main, because `github.ref` is the branch and
not the commit. With `cancel-in-progress: true`, the second merge of the day
cancels the first merge commit's run. GitHub reports that run as `cancelled`,
not `failure`: main does not go red, nobody is emailed, and the commit simply
never had a verdict — while the next run's green is about a different tree.

RFX-134 was filed on 2026-08-21 after the owner received "build failed" emails
from a window this had opened. Its first requirement — serialise merges per
repository — became rule 7 of the fleet canon and is still right; it is also a
rule a human follows, and two individually-valid claims have already composed
into a violation of it. Its second requirement is this file: "a cancelled run
on main is a hole, not a pass."

MEASURED FROM THE ACTIONS API, 2026-09-20 (dev-2--102), over each workflow's
entire main-push history — not a sample:

    reeflex      ci.yml    195 runs  181 success   1 failure   13 CANCELLED
    reeflex      gate.yml  113 runs  101 success   4 failure    8 CANCELLED
    reeflex-app  ci.yml    113 runs   89 success   8 failure   16 CANCELLED

All 37 of those commits are on main today and none was backfilled: there is no
successful run of that workflow at that sha. The one to remember is c76ad2d8
(2026-09-17) — somebody noticed and re-ran the gate, and `run_attempt: 2` was
cancelled as well.

PROVED ON A REAL RUNNER, not argued from the documentation. Two scratch
workflows, identical but for one line, two pushes seven seconds apart each —
the interval from RFX-134's own incident:

    cancel-in-progress: true                              run 1 CANCELLED
    cancel-in-progress: ${{ ... == 'pull_request' }}      BOTH runs success

The second arm is the load-bearing one: GitHub honours an expression here (a
non-boolean could have been truthy, which would have made the remedy a no-op
that reads like a remedy), and the runs QUEUE rather than drop.

WHY IT PARSES YAML BY HAND. This runs in gate.yml's ~20-second `dep-floors`
job, which does no `pip install`; PyYAML is not stdlib and nothing else under
`scripts/` imports it. `check_dependency_floors.py` has the same constraint and
answers it the same way — an anchored reader, plus a SELFTEST that cross-checks
that reader against the real library on every fixture whenever the library is
importable. `--selftest` reports whether the cross-check ran, so "PyYAML was
missing" can never be mistaken for "the reader agreed with it".

FAIL-CLOSED ON ANYTHING IT CANNOT READ. A flow-style `on: [push]`, a tab, an
unrecognised value — every one of them is an ERROR (exit 2), never a PASS. The
defect this file exists to stop is a check that reports nothing and is counted
as a check that found nothing.

WHAT IT DOES NOT COVER, said out loud. It reads the workflow files in the tree.
It does not ask GitHub which workflows are registered, and it cannot see a
cancellation caused from outside the YAML — a manual `gh run cancel`, or a
`workflow_call` from a caller carrying its own concurrency group. It says
nothing about the 37 commits already on main without a verdict: this closes the
mouth of that hole, it does not fill it.

VERDICT — anchored, case-sensitive; parse EXACTLY this line, the same
convention as check_migration_heads.py:
  WORKFLOW-CONCURRENCY: PASS (...)   exit 0
  WORKFLOW-CONCURRENCY: FAIL (...)   exit 1 — a verdict-bearing run is cancellable
  WORKFLOW-CONCURRENCY: ERROR (...)  exit 2 — the check could not run. NOT a pass.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

VERDICT_PASS = "WORKFLOW-CONCURRENCY: PASS"
VERDICT_FAIL = "WORKFLOW-CONCURRENCY: FAIL"
VERDICT_ERROR = "WORKFLOW-CONCURRENCY: ERROR"

# The two spellings that cannot destroy a verdict for a ref nobody will push
# again. `docs.yml` in this repository already carried the expression before
# RFX-134 was written, so this is the tree's own idiom, not a new invention.
CANCEL_ONLY_FOR_PULL_REQUESTS = "${{ github.event_name == 'pull_request' }}"
SAFE_VALUES = ("false", CANCEL_ONLY_FOR_PULL_REQUESTS)

# Events whose run is the ONLY verdict that ref/moment will ever get. A pull
# request branch gets pushed to again and the next run supersedes the last,
# which is exactly what cancelling is for; a merge commit and a 06:40 schedule
# do not come back.
NON_REPEATING_EVENTS = ("push", "schedule", "release")


class CheckError(Exception):
    """The check could not run. Exit 2, never conflated with a clean result."""


def _strip_comment(line: str) -> str:
    """Drop a trailing `#` comment, respecting quotes.

    `cancel-in-progress: "true"  # keep` must read as `"true"`, and a `#`
    inside the value must not truncate it.
    """
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def scan(text: str, where: str = "<text>") -> dict:
    """Return {"events": [...], "cancels": [(path, raw_value), ...]}.

    Deliberately narrow. It answers two questions and refuses everything else:
    which top-level `on:` events this workflow declares, and what every
    `cancel-in-progress:` in the file is set to.
    """
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if "\t" in line[: _indent(line) + 1]:
            raise CheckError(f"{where}:{n}: tab in the indentation — this reader will not guess")

    events: list[str] = []
    cancels: list[tuple[str, str]] = []
    in_on = False
    on_indent: int | None = None
    in_jobs = False
    jobs_indent: int | None = None
    job_name: str | None = None

    for n, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = _indent(line)
        stripped = line.strip()

        if indent == 0:
            key = stripped.split(":", 1)[0].strip()
            in_on = key in ("on", '"on"', "'on'")
            in_jobs = key == "jobs"
            on_indent = None
            jobs_indent = None
            job_name = None
            if in_on:
                after = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
                if after:
                    # `on: [push, pull_request]` / `on: push`. Refused rather
                    # than guessed: this repository does not use it, and a
                    # reader that half-understands a shape is how a check
                    # comes to report nothing and be counted as a pass.
                    raise CheckError(
                        f"{where}:{n}: flow-style `on: {after}` is not read by this checker. "
                        "Use the block form, or teach the reader and its selftest."
                    )
            continue

        if in_on:
            if on_indent is None:
                on_indent = indent
            if indent == on_indent and stripped.endswith(":"):
                events.append(stripped[:-1].strip())
            continue

        if in_jobs:
            # Job names sit at exactly ONE indent level under `jobs:` — the
            # first such level seen fixes it for the file. Anything deeper is
            # the job body, so `concurrency:` inside a job is never mistaken
            # for a job name and vice versa.
            if jobs_indent is None and stripped.endswith(":"):
                jobs_indent = indent
            if indent == jobs_indent and stripped.endswith(":"):
                job_name = stripped[:-1].strip()

        if stripped.startswith("cancel-in-progress:"):
            value = stripped.split(":", 1)[1].strip()
            path = f"jobs.{job_name}.concurrency" if in_jobs and job_name else "concurrency"
            cancels.append((path, value))

    if not events:
        raise CheckError(f"{where}: no `on:` block found — this file cannot be judged")
    return {"events": events, "cancels": cancels}


def problems_for(scanned: dict) -> list[str]:
    """Blocks that can cancel a run which is some ref's only verdict."""
    risky = [e for e in NON_REPEATING_EVENTS if e in scanned["events"]]
    if not risky:
        # Nothing here produces a verdict for a ref that will not be pushed
        # again, so superseding the previous run is exactly right.
        return []
    found = []
    for path, value in scanned["cancels"]:
        if value in SAFE_VALUES:
            continue
        found.append(
            f"{path}.cancel-in-progress = {value} with on: {risky} — a later event on "
            f"the same group cancels a run that is the only verdict that {risky[0]} "
            "will ever get for that commit"
        )
    return found


def registrable_workflows(root: pathlib.Path) -> list[pathlib.Path]:
    """The workflow files GitHub will actually register.

    NON-recursive, deliberately: GitHub reads `.github/workflows/` at the
    repository root only. This repository ships two files under
    `n8n-nodes-reeflex/.github/workflows/` that never fire (RFX-184), and
    guarding an inert file would be a green tick for a check that cannot exist.
    """
    d = root / ".github" / "workflows"
    if not d.is_dir():
        raise CheckError(f"{d} is not a directory — nothing to check, which is not a pass")
    return sorted(p for p in d.glob("*.y*ml") if p.is_file())


def check(root: pathlib.Path) -> tuple[bool, list[str], str]:
    files = registrable_workflows(root)
    if not files:
        raise CheckError(f"no workflow files under {root}/.github/workflows")
    lines, failures = [], []
    for path in files:
        scanned = scan(path.read_text(encoding="utf-8"), where=str(path))
        found = problems_for(scanned)
        lines.append(
            f"{path.name:<24} on={','.join(scanned['events'])} "
            f"cancel={[v for _, v in scanned['cancels']] or 'absent'} "
            f"{'OK' if not found else 'PROBLEM'}"
        )
        failures.extend(f"{path.name}: {p}" for p in found)
    if failures:
        return False, lines, "; ".join(failures)
    return True, lines, f"{len(files)} registered workflow(s), none can cancel a verdict nothing will reissue"


# --------------------------------------------------------------------------
# Selftest: prove the reader before its verdict is trusted (the tree's own
# pattern -- see check_dependency_floors.py --selftest).
# --------------------------------------------------------------------------

FIXTURES: list[tuple[str, str, bool]] = [
    # (name, yaml, should_report_a_problem)
    (
        # ci.yml EXACTLY as it stood on e175e4e527bf361ae510839f040216146fb3ce08.
        "ci.yml as it shipped",
        """
name: CI
on:
  workflow_dispatch:
  push:
    branches: [main]
  pull_request:
    branches: [main]
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  opa-policy-tests:
    runs-on: ubuntu-latest
    steps:
      - run: opa test
""",
        True,
    ),
    (
        "the fix",
        """
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        False,
    ),
    (
        # The string, which is what `cancel-in-progress: "true"` gives you.
        # GitHub treats a non-empty string as true: the same defect with quotes
        # on, and the shape a naive `== True` comparison waves through.
        "quoted true",
        """
name: CI
on:
  push:
    branches: [main]
concurrency:
  group: g
  cancel-in-progress: "true"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        True,
    ),
    (
        # Right instinct, wrong expression: TRUE on a schedule and on a
        # dispatch, so a daily verdict is still destroyable. Recognising this
        # as safe is the RFX-364 mistake in a new costume.
        "an expression that is still true on a schedule",
        """
name: drift
on:
  schedule:
    - cron: "40 6 * * *"
  workflow_dispatch:
concurrency:
  group: g
  cancel-in-progress: ${{ github.event_name != 'push' }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python check.py
""",
        True,
    ),
    (
        # A clean workflow-level block says nothing about a job that
        # re-introduces it. A reader that stops at the top of the file is green
        # on this.
        "job-level concurrency under a clean workflow-level block",
        """
name: CI
on:
  push:
    branches: [main]
concurrency:
  group: g
  cancel-in-progress: false
jobs:
  test:
    runs-on: ubuntu-latest
    concurrency:
      group: job-g
      cancel-in-progress: true
    steps:
      - run: pytest
""",
        True,
    ),
    (
        # Cancelling is not the defect; cancelling a verdict is. A PR-only
        # workflow may cancel freely, and a guard that failed this would be
        # pressure to delete the `concurrency:` block rather than narrow it.
        "pull_request only",
        """
name: CI
on:
  pull_request:
    branches: [main]
concurrency:
  group: g
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        False,
    ),
    (
        # A trailing comment must not change the value that is read.
        "value with a trailing comment",
        """
name: CI
on:
  push:
    branches: [main]
concurrency:
  group: g
  cancel-in-progress: false  # narrowed under RFX-134
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        False,
    ),
    (
        # Absent means false, which is GitHub's documented default.
        "no cancel-in-progress key at all",
        """
name: smoke
on:
  schedule:
    - cron: "0 5 * * *"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest
""",
        False,
    ),
]


def selftest() -> int:
    failures = []

    def check_one(name, cond, detail=""):
        if not cond:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    for name, text, expected in FIXTURES:
        try:
            got = bool(problems_for(scan(text, where=name)))
        except CheckError as exc:
            failures.append(f"{name}: reader raised {exc}")
            continue
        check_one(name, got == expected, f"reported={got}, expected={expected}")

    # Fail-closed arms: an unreadable file must be an ERROR, never a PASS.
    for name, text in (
        ("flow-style on:", "on: [push]\njobs:\n  t:\n    steps: []\n"),
        ("no on: block", "name: x\njobs:\n  t:\n    steps: []\n"),
    ):
        try:
            scan(text, where=name)
        except CheckError:
            pass
        else:
            failures.append(f"{name}: read without complaint; it must be an ERROR, not a PASS")

    # THE CROSS-CHECK. The reader is hand-written because this job has no
    # `pip install`; when the real parser IS importable, every fixture is read
    # both ways and they must agree. Whether it ran is REPORTED, so a missing
    # PyYAML can never be mistaken for agreement.
    try:
        import yaml  # noqa: PLC0415 - optional, by design; see the docstring
    except ImportError:
        print("SELFTEST: cross-check against PyYAML SKIPPED (PyYAML not importable here)")
    else:
        for name, text, _ in FIXTURES:
            loaded = yaml.safe_load(text)
            trigger = loaded.get("on", loaded.get(True))
            ours = set(scan(text, where=name)["events"])
            theirs = set(trigger) if isinstance(trigger, dict) else set()
            check_one(f"{name} (events cross-check)", ours == theirs, f"anchored={sorted(ours)} pyyaml={sorted(theirs)}")
        print(f"SELFTEST: cross-checked {len(FIXTURES)} fixtures against PyYAML")

    if failures:
        for f in failures:
            print(f"SELFTEST FAIL: {f}")
        print(f"{VERDICT_ERROR} (the reader is wrong on {len(failures)} of its own fixtures; no verdict reported)")
        return 2
    print(f"SELFTEST: {len(FIXTURES)} fixtures + 2 fail-closed arms, all as expected")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", default=".", help="repository root to check")
    parser.add_argument("--selftest", action="store_true", help="prove the reader, report no verdict")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    try:
        ok, lines, detail = check(pathlib.Path(args.root))
    except CheckError as exc:
        print(f"{VERDICT_ERROR} ({exc})")
        return 2
    for line in lines:
        print(line)
    print(f"{VERDICT_PASS if ok else VERDICT_FAIL} ({detail})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
