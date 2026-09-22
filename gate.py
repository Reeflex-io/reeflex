#!/usr/bin/env python3
"""gate.py — the uniform repo-level preflight gate (WoW §18.5 / §14.6).

WHY THIS EXISTS: on 2026-07-28 the `mcp` SDK released 2.0.0 and both published
PyPI packages died on fresh install, while every CI job stayed green for five
days — each workflow tested its own slice with `pip install -e .` and nothing
ever invoked a BUILT artifact. This gate is the single command that must be
green before trusting the tree:

  1. checks the environment FIRST and stops on a wrong one (never a lying green)
  2. builds every published package from the tree and INVOKES each entry point
     ("the file exists" is not proof — the P0 failure mode died at invocation)
  3. runs the COMPLETE test suite, not the touched slice
  4. includes the fresh-install-from-PyPI smoke (in CI this leg is DELEGATED to
     .github/workflows/smoke-pypi.yml via workflow_call — one copy, not two)
  5. parses its own output with anchored, case-sensitive regexes; a log line
     merely containing the word "pass" cannot flip the gate green
     (prove it: python gate.py --selftest)

USAGE
  python gate.py                        # full local preflight (the release preflight)
  python gate.py --pypi delegated       # CI: smoke-pypi.yml runs the PyPI leg as a sibling job
  python gate.py --pypi skip            # tree-health only; prints a flagged skip
  python gate.py --allow-skips wp-conformance
  python gate.py --core-url http://127.0.0.1:8099   # also run the WP live-core harness
  python gate.py --selftest             # prove the anchored parsing (DoD 5)

VERDICT — anchored, case-sensitive; parse EXACTLY these lines:
  GATE: GREEN        exit 0 — every component ran and passed (skips only via --allow-skips)
  GATE: RED          exit 1 — at least one component FAILED
  GATE: ENV-STOP     exit 2 — environment unfit; NOTHING was gated
  GATE: INCOMPLETE   exit 3 — no failures, but a component was SKIPPED; not green (§22.8)

A suite that cannot run in this context prints `COMPONENT <key>: SKIPPED (<reason>)`
— never silently absent. The `drift` component fails the gate when it finds test
files that no enumerated component covers, so a new suite cannot appear without
either being wired in here or turning the gate red.

SILENT SKIPS (RFX-87; sweep RFX-105..RFX-115). `drift` proved insufficient: it
checks that a test file SITS in an enumerated root, never that it YIELDS TESTS. PR #89's
regression guard for a live fail-open security hole sat in the right directory
and collected ZERO tests for its entire life — green every run, never one
assertion. Location is not execution. Three components now close that class:

  test-census   scripts/check_test_census.py — every enumerated test file must
                yield tests under the runner its root is ACTUALLY run with, no
                test body may be empty, and no test may be skipped
                unconditionally without a ticketed, printed waiver.
  suite-coverage  scripts/check_suite_coverage.py — `drift` itself made a claim
                it could not make (RFX-355): it walks five filename spellings,
                so an `attack-probe-*.py` or a `.php` is invisible to it, and
                "inside a suite root" only means "something runs it" where the
                root is run by DIRECTORY DISCOVERY. reeflex-wordpress/tests is
                run from two hardcoded literals, so a harness dropped there
                satisfied drift by its LOCATION while nothing invoked it.
                Enumerates from the directory instead: every artefact is wired
                (and its invoker still names it), or declared unwired with a
                reason, or declared not-a-check. A stale declaration FAILS.
  skip-ledger   prints every SKIPPED/DELEGATED component with its reason, and
                REFUSES an `--allow-skips` key that carries no registered
                justification (SKIP_REGISTRY) — you cannot silence a skip here
                without writing down why.
  pypi-smoke    `--pypi delegated` now VERIFIES that a sibling job actually
                invokes smoke-pypi.yml. Delegation you cannot point at is not
                delegation, it is an unrun component printing a reassuring word.

THE ARTEFACT IS NOT THE TREE (RFX-300). `pypi-smoke` installs the published
packages and proves the entry point answers `--help`; it cannot see whether that
artefact is the CODE this repository believes it published. On 2026-09-16 the
published reeflex-mcp 0.1.3 was measured 317 source lines behind the main that
declares the same version — including the fix for a hole that let a governed MCP
upstream classify its own destructive tool as read-only and turn core's DENY
into an ALLOW. `pip install -U` reports "already satisfied" and delivers none of
it. Two components close that class:

  pypi-content-selftest  the comparator proven on synthetic wheels, no network,
                BEFORE its verdict is trusted — the instrument before the
                measurement, same pattern as dep-floors-selftest.
  pypi-content  scripts/check_published_content.py — for every package that
                declares a name and version, the PUBLISHED wheel's sources are
                compared to this tree's. Equal version + different content =
                RED. A version NOT on the index is a PASS (the tree being ahead
                of the index is the normal state between a bump and a release,
                and a gate that reddens on the remedy gets switched off). The
                two collisions that exist today are waived against the tickets
                that own them, pinned to an exact version, and each waiver FAILS
                the gate once its collision is gone — a waiver that outlives its
                defect is a checkbox.

THE SAME CLASS, ONE ARTEFACT OUT (RFX-241). `pypi-smoke` installs the published
wheels and runs `<entry> --help`. That proves the entry point is not dead and
has never said anything about what the wheel DECIDES. reeflex-claude 0.1.7 was
the newest wheel on the index for 25 days after the RFX-144/145/146 fix landed;
it priced `echo starting && rm -rf /var/lib/pgsql` as read_only_internal, and it
answered `--help` with exit 0 on every one of those days.

  pypi-behaviour  scripts/check_published_classifier.py — the wheel a CUSTOMER
                installs, scored with THIS tree's conformance corpus and THIS
                tree's oracle. Any divergence fails unless it is declared with
                the ticket that closes it, and a declaration that has gone true
                fails too. Measured on 0.1.7: 42 fail-open, 4 fail-noisy, from
                an index install that pypi-smoke called PASS.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Markers that prove gate.py sits at a Reeflex repo root (wrong dir => ENV-STOP).
ROOT_MARKERS = [
    "reeflex-core/policy",
    "reeflex-core/tests",
    "reeflex-mcp/pyproject.toml",
    "reeflex-holds/pyproject.toml",
    "reeflex-claude/pyproject.toml",
    ".github/workflows",
]

# The packages this repo publishes to PyPI, with their console entry points.
# reeflex-core ships as a GHCR image, not a PyPI package — it is gated by its
# test suites below, not by a wheel build.
#
# `reeflex-litellm` is MISSING FROM THIS LIST ON PURPOSE, and only until the
# first release that publishes it (RFX-250). `release.yml` builds and offers it
# from v0.2.1; until that tag the name is a 404 on PyPI, and both consumers of
# this list would fail on it — `run_entrypoints` installs the built wheel WITH
# dependency resolution from the index, and `run_pypi_smoke` installs from the
# index outright. Adding it before the wheel exists makes this gate red on
# every PR, including the one that adds it. Its release-time coverage is
# release.yml's `verify-dist` / `verify-published`, which install and INVOKE it
# (`reeflex-litellm tenancy` plus a map that must be refused) — on a tag, not
# per PR, which is the gap RFX-250 names.
PUBLISHED = [
    # (pypi/dist name, entry point, has argparse usage banner)
    ("reeflex-mcp", "reeflex-mcp", True),
    # RFX-42: reeflex-holds now has real argparse subcommands (list/approve/
    # reject) for any argv; `--help` prints a real anchored usage banner
    # exactly like the other two. With NO argv it still starts the stdio MCP
    # server unchanged (see server.main()) -- not exercised by this smoke.
    ("reeflex-holds", "reeflex-holds", True),
    ("reeflex-claude", "reeflex-claude", True),
]

# Every test-suite root in the repo. The drift check fails the gate if a
# test-looking file exists OUTSIDE these roots (a suite nobody wired in).
SUITE_ROOTS = [
    "reeflex-core/policy",
    "reeflex-core/tests",
    "reeflex-claude/policy",
    "reeflex-claude/tests",
    "reeflex-litellm/tests",
    "reeflex-mcp/tests",
    "reeflex-holds/tests",
    "n8n-nodes-reeflex/test",
    "reeflex-wordpress/tests",
    "scripts/tests",
]

# RFX-49: candidate locations for a checked-out reeflex-app (private repo,
# never vendored into this tree) whose migrations/versions this gate can
# additionally validate. First existing match wins; none found -> SKIPPED
# (this repo itself has no alembic migrations of its own).
APP_MIGRATIONS_CANDIDATES = [
    "/root/reeflex/reeflex-app/migrations/versions",  # canonical devbox clone (WoW R.5)
    os.path.join(os.path.dirname(REPO_ROOT), "reeflex-app", "migrations", "versions"),  # sibling checkout
]

TEST_FILE_PATTERNS = ["test_*.py", "*_test.py", "*_test.rego", "*.test.ts", "*.test.js"]

# RFX-217: the floor under the drift walk. `drift` asserts that no test file
# lives outside SUITE_ROOTS -- a claim an EMPTY walk satisfies, and it printed
# the same PASS line at 0 files as at 52. Deliberately well below today's 52 so
# deleting a suite stays a normal change, and far above zero so a walk that
# stopped matching cannot pass for a tidy tree. The number this guards is
# printed in the PASS detail on every run, so the next person to move it can see
# what it was measured against.
DRIFT_MIN_TEST_FILES = 30

# The test RUNNER this gate installs into every suite venv. Bounded on purpose
# (PR #123 sweep): a bare `pytest` meant the instrument re-resolved itself to
# whatever was newest on every run, so an upstream major could redden the gate
# on a commit that touched nothing. Range measured green on 2026-09-08, on
# BOTH ends of it (8.4.2 and 9.1.1), in a venv per package:
#   reeflex-mcp     342 passed / 342 passed
#   reeflex-holds    81 passed /  81 passed   (mcp resolves 2.1.1 — the <2.2
#                                              ceiling from #123 holding 2.2.0
#                                              out, 2.2.0 having landed on PyPI
#                                              2026-09-07T16:06Z)
#   reeflex-claude  286 passed / 286 passed (+63 subtests reported on 9.1.1)
# Widen it after running the suites on the new major, not before.
PYTEST_PIN = "pytest>=8,<10"

# RFX-108: the ONLY component keys whose SKIP may be silenced via --allow-skips,
# each with the reason it can be structurally unrunnable. An --allow-skips key
# that is not registered here is REFUSED by the skip-ledger component: a skip
# that nobody wrote a reason for is precisely the class this gate exists to
# kill, and "--allow-skips <anything>" was a blank cheque.
SKIP_REGISTRY = {
    "wp-conformance":
        "needs a live reeflex-core and a php CLI. NOTE (RFX-105): CI now STARTS a "
        "core and passes --core-url, so this allowance is no longer used there — "
        "it remains for local runs on a box with no php.",
    "claude-corpus-live":
        "replays the Bash conformance corpus through the real hook against a "
        "LIVE reeflex-core (pass --core-url), so it cannot run on a box with no "
        "core. CI starts one and passes it, so this allowance is not used there "
        "— it exists for a local tree-health run. NOTE (RFX-303): the OFFLINE "
        "half of the same corpus still runs in pytest-claude on every run; what "
        "is lost when this skips is the comparison between the two planes.",
    "wp-spec-conformance":
        "needs a php CLI and NOTHING else — no core, no network (RFX-131, "
        "RFX-164). It is "
        "registered here only for a box with no php at all; if php exists this "
        "component has no reason to skip, which is why it is not folded into "
        "wp-conformance's live-core allowance.",
    "migration-heads":
        "validates the PRIVATE reeflex-app repo's alembic graph, which is never "
        "checked out on this public repo's runner. reeflex-app's own ci.yml runs "
        "the ENFORCING copy of the same check against its own migrations on every "
        "PR — this leg is the free bonus when both repos sit side by side.",
    "pypi-smoke":
        "--pypi skip is a deliberate tree-health-only run; the published-artifact "
        "smoke is owned by smoke-pypi.yml, which also runs daily on a schedule.",
    "pypi-content":
        "--pypi skip is a deliberate tree-health-only run. This component reads "
        "the PyPI JSON API, so it is unrunnable on a box with no network — but "
        "it is NOT allowed to skip for any other reason: a content comparison "
        "that did not run is not a green one (RFX-300). Note the SELFTEST arm "
        "(pypi-content-selftest) needs no network and is never skippable.",

    "pypi-behaviour":
        "needs the PyPI index to install the artefact under test (RFX-241). Skips "
        "with pypi-smoke under --pypi skip, and skips on its own when the index is "
        "unreachable — deliberately, because 'I could not install the wheel' must "
        "never render as 'the wheel is fine'. On a box with an index this "
        "component has no reason to skip.",
    "pypi-litellm-seat":
        "needs the PyPI index to resolve `reeflex-litellm` and whatever "
        "reeflex-claude its floor admits (RFX-326). Same skip rules as "
        "pypi-behaviour, and the same reason: a seat that could not be installed "
        "is not a seat that was measured.",
    "unittest-core":
        "the core suite silently drops its ~40 opa-dependent tests without the opa "
        "binary, so without opa the whole component is a loud SKIP rather than a "
        "partial green. Allowed only on a box that genuinely cannot install opa.",
    "rego-core": "no opa binary available in this context.",
    "rego-claude": "no opa binary available in this context.",
    "npm-n8n": "no npm/node >=20.15 available in this context.",
}

DRIFT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "dist-test",
    "build", "site", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist-artifacts", "pypi-dist",
}

SUBPROCESS_TIMEOUT = 1800  # seconds; generous — npm ci / pip resolve are the slow legs

# --------------------------------------------------------------------------
# Anchored, case-sensitive parsers (DoD 5). ^/$ with re.M; NO re.I anywhere.
# --------------------------------------------------------------------------

OPA_PASS_RE = re.compile(r"^PASS: (\d+)/(\d+)$", re.M)
PYTEST_PASS_RE = re.compile(r"^(\d+) passed\b[^\n]* in [0-9.]+s(?: \([^)]*\))?$", re.M)
PYTEST_SKIP_RE = re.compile(r"^\d+ passed, (\d+) skipped\b", re.M)
UNITTEST_RAN_RE = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$", re.M)
UNITTEST_OK_RE = re.compile(r"^OK(?: \((?P<detail>[^)]*)\))?$", re.M)
N8N_PASS_RE = re.compile(r"^(\d+) passed, (\d+) failed, (\d+) total$", re.M)
MIGRATION_HEADS_RE = re.compile(r"^MIGRATION-HEADS: (PASS|FAIL) \((.*)\)$", re.M)
DEP_FLOORS_RE = re.compile(r"^DEP-FLOORS: (PASS|FAIL) \((.*)\)$", re.M)
TEST_CENSUS_RE = re.compile(r"^TEST-CENSUS: (PASS|FAIL) \((.*)\)$", re.M)
SUITE_COVERAGE_RE = re.compile(r"^SUITE-COVERAGE: (PASS|FAIL) \((.*)\)$", re.M)
PUBLISHED_CONTENT_RE = re.compile(r"^PUBLISHED-CONTENT: (PASS|FAIL) \((.*)\)$", re.M)
CORPUS_LIVE_RE = re.compile(r"^CORPUS-LIVE: (PASS|FAIL) \((.*)\)$", re.M)
CORPUS_SELFTEST_RE = re.compile(r"^SELFTEST: (PASS|FAIL) \((.*)\)$", re.M)

PUBLISHED_CLASSIFIER_RE = re.compile(r"^PUBLISHED-CLASSIFIER: (PASS|FAIL|SKIP) \((.*)\)$", re.M)
PUBLISHED_SEAT_RE = re.compile(r"^PUBLISHED-LITELLM-SEAT: (PASS|FAIL|SKIP) \((.*)\)$", re.M)
USAGE_RE_TMPL = r"^usage: %s\b"
COMPONENT_RE = re.compile(r"^COMPONENT ([a-z0-9-]+): (PASS|FAIL|SKIPPED|DELEGATED)\b(?: \((.*)\))?$")


def score_entrypoint_help(pkg, entry, code, out):
    """Score one `<entry> --help` invocation. Returns (ok, detail).

    THE BANNER EXPECTATION IS LOOKED UP FROM `PUBLISHED`, NOT PASSED IN. An
    earlier draft took `has_usage` as an argument, and a sabotage arm that left
    the call in place and passed `False` neutered the whole leg with every
    selftest row still green. A call site must not be able to choose the policy
    it is judged by; an unlisted package is judged as if it declared a banner.

    ONE SCORER FOR BOTH LEGS, AND THAT IS THE POINT (RFX-149). `entrypoints`
    (the wheel built from this tree) asserted the anchored banner; `pypi-smoke`
    (the wheel a customer installs) unpacked PUBLISHED as `pkg, entry, _` and
    threw the `has_usage` flag away, so it scored `exit != 0` and nothing else.

    Measured 2026-09-21 against `reeflex-holds==0.1.2`, which the index still
    serves: `reeflex-holds --help` -> exit 0, ZERO bytes of output. That wheel is
    the artefact RFX-42 and RFX-149 were filed about -- `approve <hold-id>` on it
    exits 0 in silence and opens no connection -- and pypi-smoke's only condition
    called it PASS while entrypoints, one list away, called the same output FAIL.

    A dead console script and a silent one are the same exit code. The exit code
    is not the observation."""
    has_usage = dict((p, u) for p, _e, u in PUBLISHED).get(pkg, True)
    if code != 0:
        return False, "%s --help exit %d" % (entry, code)
    if not has_usage:
        return True, ("%s: exit 0 (no argparse -- proves the script resolves and "
                      "imports, nothing more)" % entry)
    if re.search(USAGE_RE_TMPL % re.escape(entry), out, re.M):
        return True, "%s: exit 0 + anchored usage banner" % entry
    return False, "%s: exit 0 but no anchored 'usage: %s' banner" % (entry, entry)


def parse_opa(exit_code: int, text: str):
    """PASS iff exit 0 AND the summary line `PASS: n/n` matches with n == n."""
    m = OPA_PASS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == m.group(2):
        return True, "%s/%s rego tests" % (m.group(1), m.group(2))
    if exit_code == 0:
        return False, "exit 0 but no anchored 'PASS: n/n' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_pytest(exit_code: int, text: str):
    """PASS iff exit 0 AND an anchored `N passed ... in X.XXs` summary matches."""
    m = PYTEST_PASS_RE.search(text)
    if exit_code == 0 and m:
        s = PYTEST_SKIP_RE.search(text)
        skipped = int(s.group(1)) if s else 0
        detail = "%s tests" % m.group(1)
        if skipped:
            detail += ", %d skipped in-suite" % skipped
        return True, detail
    if exit_code == 0:
        return False, "exit 0 but no anchored pytest pass summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_unittest(exit_code: int, text: str):
    """PASS iff exit 0 AND `Ran N tests in Xs` AND an anchored `OK` line."""
    ran = UNITTEST_RAN_RE.search(text)
    ok = UNITTEST_OK_RE.search(text)
    if exit_code == 0 and ran and ok:
        detail = "%s tests" % ran.group(1)
        if ok.group("detail"):
            detail += ", %s in-suite" % ok.group("detail")
        return True, detail
    if exit_code == 0:
        return False, "exit 0 but no anchored 'Ran N tests' + 'OK' — cannot confirm"
    return False, "exit %d" % exit_code


def parse_n8n(exit_code: int, text: str):
    """PASS iff exit 0 AND the runner's own `N passed, 0 failed, N total` line."""
    m = N8N_PASS_RE.search(text)
    if exit_code == 0 and m and m.group(2) == "0" and m.group(1) == m.group(3):
        return True, "%s tests" % m.group(1)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'N passed, 0 failed, N total' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_migration_heads(exit_code, text):
    """PASS iff exit 0 AND the checker's own anchored 'MIGRATION-HEADS: PASS
    (...)' line — mirrors the other parse_* functions (DoD 5): an exit 0
    with no matching line, or a matching FAIL line, cannot flip this green."""
    m = MIGRATION_HEADS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'MIGRATION-HEADS: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_dep_floors(exit_code, text):
    """PASS iff exit 0 AND the checker's own anchored 'DEP-FLOORS: PASS (...)'
    line — same shape as parse_migration_heads (DoD 5). Deliberately identical
    in spirit: the one thing that must not happen to a floor check is that it
    reports green because it printed nothing."""
    m = DEP_FLOORS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'DEP-FLOORS: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_test_census(exit_code, text):
    """PASS iff exit 0 AND the census's own anchored 'TEST-CENSUS: PASS (...)'
    line — same shape as parse_migration_heads (DoD 5). A census that cannot
    say PASS in its own words cannot flip this component green."""
    m = TEST_CENSUS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'TEST-CENSUS: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_suite_coverage(exit_code, text):
    """PASS iff exit 0 AND the checker's own anchored 'SUITE-COVERAGE: PASS'
    line — same shape as parse_test_census (DoD 5). Deliberately identical:
    a coverage checker that cannot say PASS in its own words does not get to
    flip this component green by exiting 0."""
    m = SUITE_COVERAGE_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'SUITE-COVERAGE: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_published_content(exit_code, text):
    """PASS iff exit 0 AND the checker's own anchored PUBLISHED-CONTENT line.

    Same shape as parse_test_census (DoD 5). The exit code alone is not taken:
    RFX-97 is the ticket about a verdict that did not move an exit status, and
    this component's whole subject is artefacts that report success while being
    the wrong thing.
    """
    m = PUBLISHED_CONTENT_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'PUBLISHED-CONTENT: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code
def parse_corpus_live(exit_code, text):
    """PASS iff exit 0 AND the anchored `CORPUS-LIVE: PASS (...)` line matches.

    The exit code alone is not enough and neither is the line alone: the probe
    exits non-zero for four different reasons, and a run that dies before
    printing its verdict exits non-zero with no line at all. Both, or nothing
    turns green — the same discipline as parse_opa and parse_migration_heads.
    """
    m = CORPUS_LIVE_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m:
        return False, "%s (exit %d)" % (m.group(2), exit_code)
    return False, ("exit %d and no anchored 'CORPUS-LIVE:' verdict — the live "
                   "corpus arm did not finish, so nothing was compared" % exit_code)

def parse_published_seat(exit_code, text):
    """RFX-326. Same three-valued contract as parse_published_classifier.

    A SEPARATE regex on a SEPARATE anchor on purpose. The two arms install
    different distributions and score different planes; sharing the anchor
    would let one arm's verdict be read as the other's, which is a way to have
    two components and one measurement.
    """
    m = PUBLISHED_SEAT_RE.search(text)
    if m and m.group(1) == "SKIP" and exit_code == 3:
        return "SKIPPED", m.group(2)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return "PASS", m.group(2)
    if m and m.group(1) == "FAIL":
        return "FAIL", "%s (exit %d)" % (m.group(2), exit_code)
    return "FAIL", ("exit %d and no anchored 'PUBLISHED-LITELLM-SEAT:' verdict — "
                    "the published gateway seat was not scored" % exit_code)


def parse_published_classifier(exit_code, text):
    """RFX-241. Returns (status, detail) where status is PASS/FAIL/SKIPPED.

    Three-valued, unlike its siblings, because the index can be unreachable and
    "I could not install the artefact" must not read as "the artefact is fine".
    That is the whole defect this component exists for, one layer up.
    """
    m = PUBLISHED_CLASSIFIER_RE.search(text)
    if m and m.group(1) == "SKIP" and exit_code == 3:
        return "SKIPPED", m.group(2)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return "PASS", m.group(2)
    if m and m.group(1) == "FAIL":
        return "FAIL", m.group(2)
    if exit_code == 0:
        return "FAIL", ("exit 0 but no anchored 'PUBLISHED-CLASSIFIER: PASS' summary "
                        "— cannot confirm")
    return "FAIL", "exit %d" % exit_code


def audit_skips(statuses, allow_skips, registry=None):
    """RFX-108: account for every skip in this run.

    Returns (ok, lines). NOT green when an --allow-skips key carries no
    registered justification — silencing a skip must cost you a written
    reason. A STALE allowance (the key is allowed but the component actually
    ran) is reported as a WARN rather than a failure: it is a cleanup, not a
    lying green, and failing on it would break every local invocation the
    moment a suite starts working again."""
    registry = SKIP_REGISTRY if registry is None else registry
    lines = []
    skipped = sorted(k for k, s in statuses.items() if s == "SKIPPED")
    delegated = sorted(k for k, s in statuses.items() if s == "DELEGATED")

    for k in skipped:
        allowed = k in allow_skips
        lines.append("  SKIPPED    %s%s" % (k, "  [allowed]" if allowed else "  [NOT ALLOWED -> INCOMPLETE]"))
        lines.append("             why: %s" % registry.get(k, "(no registered justification)"))
    for k in delegated:
        lines.append("  DELEGATED  %s  (ran elsewhere — verified, see the component)" % k)
    if not skipped and not delegated:
        lines.append("  nothing was skipped or delegated in this run")

    unregistered = sorted(k for k in allow_skips if k not in registry)
    stale = sorted(k for k in allow_skips if k in statuses and statuses[k] != "SKIPPED")
    for k in stale:
        lines.append("  WARN       --allow-skips %s is STALE: that component reported %s, not "
                     "SKIPPED. Drop it from --allow-skips." % (k, statuses[k]))
    for k in unregistered:
        lines.append("  REFUSED    --allow-skips %s is not in SKIP_REGISTRY — a skip with no "
                     "written justification cannot be silenced here." % k)
    return not unregistered, lines


def derive_verdict(lines, allow_skips):
    """Compute the final verdict EXCLUSIVELY by re-parsing the gate's own
    emitted COMPONENT lines (anchored, case-sensitive) — DoD(5) taken
    literally: if the transcript cannot be parsed back, nothing turns green."""
    statuses = {}
    for line in lines:
        m = COMPONENT_RE.match(line)
        if m:
            statuses[m.group(1)] = m.group(2)
    if not statuses:
        return "RED", statuses  # a gate that gated nothing is not green
    if any(s == "FAIL" for s in statuses.values()):
        return "RED", statuses
    hard_skips = [k for k, s in statuses.items() if s == "SKIPPED" and k not in allow_skips]
    if hard_skips:
        return "INCOMPLETE", statuses
    return "GREEN", statuses


# --------------------------------------------------------------------------
# Gate machinery
# --------------------------------------------------------------------------

class Gate:
    def __init__(self, args):
        self.args = args
        self.lines = []          # the transcript the verdict is parsed from
        self.tmp = tempfile.mkdtemp(prefix="reeflex-gate-")

    def emit(self, line=""):
        self.lines.append(line)
        print(line, flush=True)

    def run_cmd(self, cmd, cwd=None, env_extra=None, env_drop=(), stdin_devnull=False):
        env = dict(os.environ)
        for k in env_drop:
            env.pop(k, None)
        if env_extra:
            env.update(env_extra)
        try:
            proc = subprocess.run(
                cmd, cwd=cwd or REPO_ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=(subprocess.DEVNULL if stdin_devnull else None),
                text=True, errors="replace", timeout=SUBPROCESS_TIMEOUT,
            )
            return proc.returncode, proc.stdout.replace("\r\n", "\n")
        except subprocess.TimeoutExpired:
            return 124, "TIMEOUT after %ds: %s" % (SUBPROCESS_TIMEOUT, cmd)
        except FileNotFoundError as exc:
            return 127, "NOT RUNNABLE: %s" % exc

    def show(self, text, full=False, tail=15):
        body = text.rstrip("\n").split("\n")
        if not full and len(body) > tail:
            self.emit("  ... (%d lines suppressed; full output printed on failure)" % (len(body) - tail))
            body = body[-tail:]
        for line in body:
            self.emit("  | " + line)

    def component(self, key, status, detail=""):
        self.emit("COMPONENT %s: %s (%s)" % (key, status, detail) if detail
                  else "COMPONENT %s: %s" % (key, status))

    # -- venv helpers -------------------------------------------------------

    def make_venv(self, name):
        path = os.path.join(self.tmp, name)
        code, out = self.run_cmd([sys.executable, "-m", "venv", path])
        if code != 0:
            return None, out
        return path, ""

    @staticmethod
    def venv_bin(venv_path, exe):
        sub = "Scripts" if os.name == "nt" else "bin"
        return os.path.join(venv_path, sub, exe)

    def venv_python(self, venv_path):
        return self.venv_bin(venv_path, "python.exe" if os.name == "nt" else "python")

    # -- phase 0: environment ----------------------------------------------

    def env_check(self):
        ok = True
        if sys.version_info < (3, 10):
            self.emit("ENV: STOP python %s < 3.10 (all published packages require >=3.10)"
                      % sys.version.split()[0])
            ok = False
        else:
            self.emit("ENV: OK python %s" % sys.version.split()[0])
        missing = [m for m in ROOT_MARKERS
                   if not os.path.exists(os.path.join(REPO_ROOT, m))]
        if missing:
            self.emit("ENV: STOP not a Reeflex repo root (%s) — missing: %s"
                      % (REPO_ROOT, ", ".join(missing)))
            ok = False
        else:
            self.emit("ENV: OK repo root %s" % REPO_ROOT)
        code, out = self.run_cmd([sys.executable, "-m", "pip", "--version"])
        if code != 0:
            self.emit("ENV: STOP pip is not available (%s)" % out.strip())
            ok = False
        else:
            self.emit("ENV: OK %s" % out.strip())
        # Soft tools: their absence SKIPs the dependent suite (printed), it does
        # not stop the gate — but it is stated here so the skip is no surprise.
        self.opa = os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa")
        self.npm = shutil.which("npm")
        self.php = shutil.which("php")
        for label, path in (("opa", self.opa), ("npm", self.npm), ("php", self.php)):
            self.emit("ENV: NOTE %s = %s" % (label, path or "NOT FOUND"))
        if os.environ.get("NODE_ENV"):
            # NODE_ENV=production makes npm omit devDependencies and the n8n
            # suite would fail for the WRONG reason — neutralized per-suite.
            self.emit("ENV: NOTE NODE_ENV=%s is set; the n8n suite runs with it cleared"
                      % os.environ["NODE_ENV"])
        if os.getcwd() != REPO_ROOT:
            self.emit("ENV: NOTE cwd differs from repo root; gating %s" % REPO_ROOT)
        return ok

    # -- suites -------------------------------------------------------------

    def run_rego(self, key, rel):
        if not self.opa:
            self.component(key, "SKIPPED", "opa binary not found (install OPA or set REEFLEX_OPA_BIN)")
            return
        code, out = self.run_cmd([self.opa, "test", os.path.join(REPO_ROOT, rel), "-v"])
        ok, detail = parse_opa(code, out)
        self.show(out, full=not ok)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_core_unittest(self):
        key = "unittest-core"
        if not self.opa:
            # The suite RUNS without opa but silently drops ~40 opa-dependent
            # tests via skipUnless — that is the silent-skip class this gate
            # exists to kill, so without opa the component is a loud SKIP.
            self.component(key, "SKIPPED", "opa binary not found — the suite would silently skip its opa-dependent tests")
            return
        code, out = self.run_cmd(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
            cwd=os.path.join(REPO_ROOT, "reeflex-core"),
            env_extra={"REEFLEX_OPA_BIN": self.opa, "REEFLEX_POLICY_DIR": "policy"},
        )
        ok, detail = parse_unittest(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_pytest_suites(self):
        # (component key, package dir, extra LOCAL packages to install editable)
        keys = [("pytest-mcp", "reeflex-mcp", []),
                ("pytest-holds", "reeflex-holds", []),
                ("pytest-claude", "reeflex-claude", []),
                # RFX-236: reeflex-litellm depends on reeflex-claude for the ONE
                # classifier, and `reeflex-claude>=0.1.7` resolves off PyPI to a
                # wheel uploaded 2026-07-06 -- BEFORE RFX-144/145/146 landed on
                # 2026-08-22. Measured against the published core v0.2.0, that
                # wheel prices `echo x && rm -rf /var/lib/pgsql` as
                # reversible/single and core ALLOWS it. So this suite must be
                # run against the CHECKOUT, not the index, or it certifies a
                # classifier the repo does not contain.
                # tests/test_classifier_vintage.py is the tripwire under this
                # line: it goes red if the stale wheel ever wins the resolve.
                ("pytest-litellm", "reeflex-litellm", ["reeflex-claude"])]
        # One venv PER package, not one shared venv (RFX-26): reeflex-mcp pins
        # mcp>=1.2,<2 while reeflex-holds (ported to MCPServer) now requires
        # mcp>=2 -- installing both editable into a single venv is an
        # unsatisfiable pip resolve, not a real conflict in the tree (each
        # package's own dependency contract is internally consistent).
        for key, pkg, local_deps in keys:
            venv_path, err = self.make_venv("venv-suite-%s" % pkg)
            if not venv_path:
                self.component(key, "FAIL", "suite venv creation failed: %s" % err)
                continue
            py = self.venv_python(venv_path)
            # PYTEST IS BOUNDED (the PR #123 sweep). This was a bare `pytest`:
            # an unbounded floor inside the INSTRUMENT, so a pytest major could
            # turn the whole gate red on a commit that changed nothing — the
            # same shape as the mcp 2.1.1 breakage, one layer up, and this time
            # in the thing that decides whether the tree is healthy. The range
            # is what was measured green on all three suites (2026-09-08).
            #
            # The local_deps loop is #130's half and it is load-bearing for a
            # DIFFERENT reason (see pytest-litellm above): either side of this
            # hunk taken wholesale drops the other's fix, so both are here.
            install = [py, "-m", "pip", "install", "-q", PYTEST_PIN]
            for dep in local_deps:
                install += ["-e", os.path.join(REPO_ROOT, dep)]
            install += ["-e", os.path.join(REPO_ROOT, pkg)]
            code, out = self.run_cmd(install)
            if code != 0:
                self.show(out, full=True)
                self.component(key, "FAIL", "suite venv install failed")
                continue
            code, out = self.run_cmd([py, "-m", "pytest", "tests/", "-q"],
                                     cwd=os.path.join(REPO_ROOT, pkg))
            ok, detail = parse_pytest(code, out)
            self.show(out, full=not ok, tail=6)
            self.component(key, "PASS" if ok else "FAIL", detail)

    def run_n8n(self):
        key = "npm-n8n"
        if not self.npm:
            self.component(key, "SKIPPED", "npm not found (node >=20.15 required by n8n-nodes-reeflex)")
            return
        cwd = os.path.join(REPO_ROOT, "n8n-nodes-reeflex")
        # NODE_ENV dropped: production mode omits devDependencies (tsc) and
        # fails the suite for a reason that is the ENVIRONMENT's, not the tree's.
        code, out = self.run_cmd([self.npm, "ci", "--include=dev", "--no-audit", "--no-fund"],
                                 cwd=cwd, env_drop=("NODE_ENV",))
        if code != 0:
            self.show(out, full=True)
            self.component(key, "FAIL", "npm ci exit %d" % code)
            return
        code, out = self.run_cmd([self.npm, "test"], cwd=cwd, env_drop=("NODE_ENV",))
        ok, detail = parse_n8n(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- built artifacts + entry points (DoD 2) ------------------------------

    def run_entrypoints(self):
        key = "entrypoints"
        wheels = os.path.join(self.tmp, "wheels")
        os.makedirs(wheels, exist_ok=True)
        # Build real artifacts (wheels) from the tree — NOT `pip install -e .`,
        # which is exactly how CI stayed green over a dead published package.
        wheel_for = {}
        for pkg, _, _ in PUBLISHED:
            before = set(os.listdir(wheels))
            code, out = self.run_cmd([sys.executable, "-m", "pip", "wheel", "--no-deps",
                                      "-q", "-w", wheels, os.path.join(REPO_ROOT, pkg)])
            if code != 0:
                self.show(out, full=True)
                self.component(key, "FAIL", "wheel build failed for %s" % pkg)
                return
            wheel_for[pkg] = sorted(os.path.join(wheels, f) for f in set(os.listdir(wheels)) - before)
        # One venv PER package, not one shared venv (RFX-26): reeflex-mcp pins
        # mcp>=1.2,<2 while reeflex-holds (ported to MCPServer) now requires
        # mcp>=2 -- resolving both wheels' dependencies from PyPI into a single
        # venv is an unsatisfiable pip resolve, not a real conflict in the tree.
        failures = []
        details = []
        resolved = []
        for pkg, entry, _ in PUBLISHED:
            venv_path, err = self.make_venv("venv-entry-%s" % pkg)
            if not venv_path:
                failures.append("%s: venv creation failed" % pkg)
                continue
            py = self.venv_python(venv_path)
            # Install the wheel WITH dependency resolution from PyPI: this is
            # the leg that catches a missing/wrong dependency pin (2026-07-28 class).
            code, out = self.run_cmd([py, "-m", "pip", "install", "-q"] + wheel_for[pkg])
            if code != 0:
                self.show(out, full=True)
                failures.append("%s: installing built wheel failed" % pkg)
                continue
            code, ver_out = self.run_cmd([py, "-m", "pip", "show", "mcp"])
            ver = next((l for l in ver_out.split("\n") if l.startswith("Version:")), "Version: ?")
            resolved.append("%s: %s" % (pkg, ver.split(":", 1)[1].strip()))
            exe = self.venv_bin(venv_path, entry + (".exe" if os.name == "nt" else ""))
            code, out = self.run_cmd([exe, "--help"], stdin_devnull=True)
            self.emit("  | invoke: %s --help -> exit %d" % (entry, code))
            ok, detail = score_entrypoint_help(pkg, entry, code, out)
            if ok:
                details.append(detail)
            else:
                self.show(out, full=True)
                failures.append(detail)
        self.emit("  | resolved mcp %s" % "; ".join(resolved))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "; ".join(details))

    # -- fresh-install-from-PyPI smoke (DoD 4) -------------------------------

    # RFX-107: "DELEGATED" is the one status that asserts a component ran
    # SOMEWHERE ELSE. That was taken on trust: delete the smoke-pypi job from
    # gate.yml and this gate would print DELEGATED and stay GREEN forever,
    # while the fresh-install smoke — the leg that exists because five days of
    # green CI hid two dead published packages on 2026-07-28 — ran nowhere.
    # So the delegation is now VERIFIED against the workflow that must carry it.
    DELEGATE_WORKFLOW = os.path.join(".github", "workflows", "gate.yml")
    DELEGATE_RE = re.compile(r"^\s*uses:\s*\./\.github/workflows/smoke-pypi\.yml\s*$", re.M)

    def verify_delegation(self):
        """Returns (ok, detail): does a sibling job actually invoke the smoke?"""
        path = os.path.join(REPO_ROOT, self.DELEGATE_WORKFLOW)
        if not os.path.exists(path):
            return False, "claims delegation but %s does not exist" % self.DELEGATE_WORKFLOW
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        if not self.DELEGATE_RE.search(body):
            return False, ("claims delegation but no job in %s invokes "
                           "./.github/workflows/smoke-pypi.yml" % self.DELEGATE_WORKFLOW)
        return True, "smoke-pypi.yml via workflow_call in the same workflow run (verified wired in %s)" \
                     % self.DELEGATE_WORKFLOW

    def run_pypi_smoke(self):
        key = "pypi-smoke"
        if self.args.pypi == "delegated":
            ok, detail = self.verify_delegation()
            self.component(key, "DELEGATED" if ok else "FAIL", detail)
            return
        if self.args.pypi == "skip":
            self.component(key, "SKIPPED", "explicitly disabled via --pypi skip (tree-health run)")
            return
        failures, details = [], []
        for pkg, entry, _ in PUBLISHED:
            venv_path, err = self.make_venv("venv-pypi-" + pkg)
            if not venv_path:
                failures.append("%s: venv failed" % pkg)
                continue
            py = self.venv_python(venv_path)
            code, out = self.run_cmd([py, "-m", "pip", "install", "-q", "--no-cache-dir", pkg])
            if code != 0:
                self.show(out, full=True)
                failures.append("%s: pip install from PyPI failed" % pkg)
                continue
            code, ver_out = self.run_cmd([py, "-m", "pip", "show", pkg])
            ver = next((l.split(":", 1)[1].strip() for l in ver_out.split("\n")
                        if l.startswith("Version:")), "?")
            exe = self.venv_bin(venv_path, entry + (".exe" if os.name == "nt" else ""))
            code, out = self.run_cmd([exe, "--help"], stdin_devnull=True)
            self.emit("  | pypi %s==%s: %s --help -> exit %d, %d bytes"
                      % (pkg, ver, entry, code, len(out or "")))
            ok, detail = score_entrypoint_help(pkg, entry, code, out)
            if ok:
                details.append("%s==%s %s" % (pkg, ver, detail))
            else:
                self.show(out, full=True)
                failures.append("%s==%s: %s" % (pkg, ver, detail))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "; ".join(details))

    # -- published behaviour, not just published liveness (RFX-241) ----------

    def run_published_classifier(self):
        # pypi-smoke asserts the published entry point is not DEAD. This asserts
        # what it DECIDES. reeflex-claude 0.1.7 was newest on the index from
        # 2026-07-06 to 2026-09-16, priced `echo starting && rm -rf /var/lib/pgsql`
        # as read_only_internal, and answered `--help` with exit 0 the whole
        # time — so pypi-smoke was green over a wheel that let 42 of this repo's
        # 78 scored production destructions through with no human. Measured, not
        # reasoned: scripts/check_published_classifier.py --version 0.1.7.
        #
        # IT DOES NOT HONOUR `--pypi delegated`, AND THAT IS THE POINT.
        # pypi-smoke may delegate to smoke-pypi.yml because that workflow does
        # exactly what pypi-smoke does. This check cannot be delegated there:
        # smoke-pypi.yml has NO CHECKOUT, deliberately ("the whole point is
        # testing what a user gets ... independent of the repo state"), and the
        # corpus and oracle that make this a comparison live in the tree. A
        # DELEGATED line pointing at a job that does not run the check is the
        # RFX-107 defect this file's own header condemns — an unrun component
        # printing a reassuring word — so under `--pypi delegated` it runs
        # inline instead, and pays one venv and one resolve for it.
        key = "pypi-behaviour"
        if self.args.pypi == "skip":
            self.component(key, "SKIPPED", "explicitly disabled via --pypi skip (tree-health run)")
            return
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_published_classifier.py"), REPO_ROOT])
        status, detail = parse_published_classifier(code, out)
        self.show(out, full=status != "PASS", tail=8)
        self.component(key, status, detail)

    def run_published_seat(self):
        # RFX-326. pypi-behaviour scores `pip install reeflex-claude`. NOTHING
        # scored `pip install reeflex-litellm`, and on 2026-09-16 that stopped
        # being theoretical: the gateway seat went to PyPI, its own floor
        # resolved the reeflex-claude wheel uploaded 23 seconds earlier, and the
        # seat a customer installs allowed 23 of 24 destructive
        # command-substitution lines. The lag was DECLARED in the other arm,
        # correctly and with the right ticket — but a waiver is a statement
        # about blast radius, and nobody re-measured the radius when a second
        # published package started standing on the waived wheel.
        #
        # This arm asks the customer's question: what does THAT resolve decide,
        # through the seat's own normaliser. It is not a duplicate of
        # pypi-behaviour: the two install different distributions, and
        # reeflex-litellm's floor is its own declaration, which a future edit
        # can move without touching reeflex-claude at all.
        key = "pypi-litellm-seat"
        if self.args.pypi == "skip":
            self.component(key, "SKIPPED", "explicitly disabled via --pypi skip (tree-health run)")
            return
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_published_classifier.py"),
             "--seat", REPO_ROOT])
        status, detail = parse_published_seat(code, out)
        self.show(out, full=status != "PASS", tail=8)
        self.component(key, status, detail)

    def run_published_classifier_selftest(self):
        # The instrument before the verdict. Every branch of the comparison —
        # fail-open, fail-noisy, a declared lag, a STALE declaration, an empty
        # result set, a classifier that raises — proved on fixtures with no
        # network, so a green PUBLISHED-CLASSIFIER line is worth reading.
        key = "pypi-behaviour-selftest"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_published_classifier.py"), "--selftest"])
        ok = code == 0
        m = re.search(r"^SELFTEST: PASS \((\d+) checks\)$", out, re.M)
        detail = ("%s checks" % m.group(1)) if m \
            else "no anchored 'SELFTEST: PASS (N checks)' line — cannot confirm"
        if not m:
            ok = False
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- WordPress live-core harness -----------------------------------------

    # RFX-27: the WordPress adapter has FOUR live-core PHP harnesses, not one —
    # conformance-demo.php was the only one gate.py ever invoked; the other three
    # (added for real fixed bugs, see their own docblocks + CHANGELOG) were run by
    # nobody in any automation. One of them (fanout-regression-demo.php, and
    # transitively hold-dedup-regression-demo.php) was silently BROKEN — a fatal
    # "undefined function wp_upload_dir()" — since audit_log_path() started calling
    # it; measured + fixed 2026-08-20 (see wp-stubs.php). All four share the same
    # live-core prerequisite, so they run (or SKIP) together under one component.
    # RFX-219: conformance-security-options.php is the fifth. It is listed here
    # for the same reason the other three were added — a harness that no
    # automation invokes is a harness nobody runs. It needs the same live core,
    # and it declares in its own header which action families it covers so a
    # PASS is not read as coverage it does not have (RFX-220).
    #
    # RFX-167: conformance-decisions.php belongs HERE and not in the core-free
    # wp-spec-conformance group, and the reason is the ticket. The per-axis
    # vector suites assert one axis inside the normalizer, so they need no core.
    # R2 and R3 are CONJUNCTIONS of two axes, so a per-axis suite can be fully
    # green while a production destruction is still answered `allow` with no
    # human — scoring THAT means asking a core what it decides.
    WP_HARNESSES = [
        "conformance-demo.php",
        "admin-holds-demo.php",
        "fanout-regression-demo.php",
        "hold-dedup-regression-demo.php",
        "conformance-security-options.php",
        "conformance-decisions.php",
    ]

    def run_published_content(self):
        """RFX-300: the tree and the index disagreeing under ONE version number.

        `pypi-smoke` above installs the published packages and proves the entry
        point answers `--help`. It cannot see this: reeflex-mcp 0.1.3 on the
        index answers `--help` perfectly and is 317 lines of merged security
        fixes behind the tree that declares the same version, so
        `pip install -U` delivers nothing and reports success.

        Deliberately NOT folded into pypi-smoke. That component's question is
        "does the published artefact run"; this one's is "is the published
        artefact the code we think we published". Two questions, two verdicts —
        folding them means one PASS standing for both, and it is the second one
        that was false for 36 days.
        """
        key = "pypi-content"
        if self.args.pypi == "skip":
            self.component(key, "SKIPPED",
                           "explicitly disabled via --pypi skip (tree-health run)")
            return
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_published_content.py")])
        ok, detail = parse_published_content(code, out)
        # Always shown in full: a waived collision is only accounted for if the
        # reader can see WHICH files moved, in the run that waived it.
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_published_content_selftest(self):
        key = "pypi-content-selftest"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_published_content.py"), "--selftest"])
        ok = code == 0
        m = re.search(r"^SELFTEST: (PASS|FAIL) \((.*)\)$", out, re.M)
        if not m or m.group(1) != "PASS":
            ok = False
        detail = m.group(2) if m else "no anchored 'SELFTEST:' line — cannot confirm"
        self.show(out, full=not ok, tail=15)
    CORPUS_PROBE = "attack-probe-rfx144-agent-prices-own-action.py"

    def run_corpus_live(self):
        """RFX-303: the Bash conformance corpus, through the real hook, against
        a real core — and every verdict compared back against the SAME offline
        oracle the unit suite uses.

        WHY THIS IS A COMPONENT AND NOT A LINE IN pytest-claude. The offline
        suite scores the corpus against a transcription of the policy pack. A
        transcription drifts, and this arm is the only thing that can see it
        drift. It existed, it worked, and it was invoked by NOTHING: before
        this ticket `attack-probe` appeared zero times in this file and zero
        times in .github/workflows/, while four files in the tree said the two
        planes were kept honest against each other by running both in the gate.
        Two divergences had accumulated in the gap — the oracle was missing R6
        (`irreversible_protected_asset_prod`, shipped with RFX-153) and it
        ranked R1 first where the pack ranks it last.

        THE SELFTEST RUNS FIRST, IN THIS COMPONENT, and its failure fails the
        component. A divergence detector that cannot detect a divergence
        reports a clean run over anything — which is this same defect one layer
        down. It is folded in here rather than filed as a sixth component
        because it proves THIS instrument and nothing else.

        THE TARGET IS PINNED, ALWAYS. This is an attack suite: it replays
        ground-truth production destructions. It is handed --core-url
        explicitly and the probe itself now refuses the hosted hostnames and
        has no default target — until RFX-303 its default was
        api-dev.reeflex.io, which is the production core.
        """
        key = "claude-corpus-live"
        if not self.args.core_url:
            self.component(key, "SKIPPED",
                           "needs a LIVE reeflex-core (pass --core-url); it replays the whole "
                           "corpus through the real hook and compares every verdict against the "
                           "offline oracle in reeflex-claude/tests/policy_oracle.py")
            return
        probe = os.path.join(REPO_ROOT, "scripts", self.CORPUS_PROBE)

        # The instrument, before the verdict.
        code, out = self.run_cmd([sys.executable, probe, "--selftest"])
        m = CORPUS_SELFTEST_RE.search(out)
        if code != 0 or not m or m.group(1) != "PASS":
            self.show(out, full=True)
            self.component(key, "FAIL",
                           "the live-vs-oracle comparator failed its own selftest — no verdict "
                           "from this component can be trusted")
            return
        self.emit("  -- comparator selftest: %s" % m.group(2))

        env = {
            "REEFLEX_PROBE_BASE": self.args.core_url,
            "REEFLEX_PROBE_PACE": "0",
            # R5 is keyed on session_id server-side. A fixed run id would make
            # the second gate run against a long-lived core inherit the first
            # one's cumulative ledger.
            "REEFLEX_PROBE_RUN": "gate-%d" % int(time.time()),
        }
        code, out = self.run_cmd([sys.executable, probe], env_extra=env)
        ok, detail = parse_corpus_live(code, out)
        # tail 22 on a pass is chosen to reach the "LIVE vs OFFLINE ORACLE"
        # block: a reader must be able to see that the comparison HAPPENED, not
        # only that the component passed.
        self.show(out, full=not ok, tail=22)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_wp(self):
        key = "wp-conformance"
        if not self.args.core_url:
            self.component(key, "SKIPPED",
                           "needs a LIVE reeflex-core (pass --core-url); the harnesses POST real /v1/decide calls "
                           "AND resolve real holds, so since core 0.2.0 that core must also be started with "
                           "REEFLEX_RESOLVER_TOKENS=reeflex-wordpress/tests/harness-resolver-tokens.json "
                           "(or REEFLEX_REQUIRE_VERIFIED_APPROVER=false) — see reeflex-wordpress/tests/README.md")
            return
        if not self.php:
            self.component(key, "SKIPPED", "php CLI not found")
            return
        failures, details = [], []
        for script in self.WP_HARNESSES:
            code, out = self.run_cmd([self.php, "tests/%s" % script, self.args.core_url],
                                     cwd=os.path.join(REPO_ROOT, "reeflex-wordpress"))
            self.emit("  -- %s" % script)
            self.show(out, full=code != 0, tail=12)
            if code == 0:
                details.append("%s: exit 0" % script)
            else:
                failures.append("%s: exit %d" % (script, code))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "%d harnesses vs %s (%s)"
                           % (len(self.WP_HARNESSES), self.args.core_url, "; ".join(details)))

    # -- SPEC conformance vectors, no live core ------------------------------

    # RFX-131 and RFX-164: these harnesses assert the SPEC's normative axis
    # derivations against the shared vector files in reeflex-spec/conformance/.
    # They resolve entirely inside the normalizer — no /v1/decide call, no
    # network — so they must NOT sit behind --core-url. Filed as their own
    # component precisely because inheriting wp-conformance's live-core
    # prerequisite would SKIP them for a reason that does not apply to them, and
    # a suite skipped for the wrong reason is the RFX-105 defect with a
    # different label.
    #
    # MERGE NOTE, RESOLVED (dev-3 round 039). #94 (RFX-131, blast_radius) and
    # #101 (RFX-164, reversibility) each introduced this component
    # independently — same SKIP_REGISTRY key, same `run_wp_spec` body, same
    # component-list row, differing only in the RFX number in the prose. #94
    # landed first (`0243ee1`); the union is ONE component with BOTH entries,
    # which is what #101's original note asked for. Nothing is lost: each
    # harness is still driven, and `run_wp_spec` reports every one of them.
    WP_SPEC_HARNESSES = [
        ("conformance-blast-radius.php", "SPEC §4.2 axes.blast_radius"),
        ("conformance-reversibility.php", "SPEC §2 axes.reversibility"),
    ]

    def run_wp_spec(self):
        key = "wp-spec-conformance"
        if not self.php:
            self.component(key, "SKIPPED", "php CLI not found")
            return
        failures, details = [], []
        for script, what in self.WP_SPEC_HARNESSES:
            code, out = self.run_cmd([self.php, "tests/%s" % script],
                                     cwd=os.path.join(REPO_ROOT, "reeflex-wordpress"))
            self.emit("  -- %s (%s)" % (script, what))
            self.show(out, full=code != 0, tail=20)
            if code == 0:
                details.append("%s: exit 0" % script)
            else:
                failures.append("%s: exit %d" % (script, code))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "%d spec harness(es), no live core needed (%s)"
                           % (len(self.WP_SPEC_HARNESSES), "; ".join(details)))

    # -- drift check ----------------------------------------------------------

    def run_drift(self):
        key = "drift"
        covered = [os.path.normpath(os.path.join(REPO_ROOT, r)) for r in SUITE_ROOTS]
        strays = []
        matched = 0
        for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in DRIFT_EXCLUDE_DIRS and not d.startswith("reeflex-gate-")]
            for f in filenames:
                if any(fnmatch.fnmatch(f, p) for p in TEST_FILE_PATTERNS):
                    matched += 1
                    full = os.path.normpath(os.path.join(dirpath, f))
                    if not any(full.startswith(c + os.sep) or os.path.dirname(full) == c
                               for c in covered):
                        strays.append(os.path.relpath(full, REPO_ROOT))
        if strays:
            for s in strays:
                self.emit("  | unenumerated test file: %s" % s)
            self.component(key, "FAIL",
                           "%d test file(s) outside the enumerated suite roots — wire them into gate.py or they run NOWHERE" % len(strays))
        elif matched < DRIFT_MIN_TEST_FILES:
            # RFX-217: this component asserts "no member of a DISCOVERED set is
            # a stray", which an empty set satisfies. Measured on 759b83f: with
            # TEST_FILE_PATTERNS changed to match nothing, and again with
            # DRIFT_EXCLUDE_DIRS swallowing the tree, this printed
            # "PASS (no test files outside the 9 enumerated suite roots)" --
            # byte-identical to the honest verdict, having examined 0 files
            # instead of 52. The walk not finding the suites is not evidence
            # that the suites are tidy.
            self.component(key, "FAIL",
                           "the walk matched %d test file(s), below the floor of %d — TEST_FILE_PATTERNS, "
                           "DRIFT_EXCLUDE_DIRS or REPO_ROOT is what changed, not the tree. This component "
                           "cannot certify a tree it did not enumerate"
                           % (matched, DRIFT_MIN_TEST_FILES))
        else:
            self.component(key, "PASS",
                           "%d test file(s) walked, none outside the %d enumerated suite roots"
                           % (matched, len(SUITE_ROOTS)))

    # -- test census (RFX-87) -------------------------------------------------

    def run_test_census(self):
        # Unconditional and static (ast only, no imports, no deps): every
        # enumerated test file must YIELD TESTS under the runner its root is
        # actually run with. `drift` proves a test file is in a directory some
        # component names; this proves the file is not inert. #89's guard
        # satisfied drift and collected zero tests.
        key = "test-census"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "check_test_census.py"), REPO_ROOT]
        )
        ok, detail = parse_test_census(code, out)
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- suite coverage (RFX-355) --------------------------------------------

    def run_suite_coverage_selftest(self):
        # The instrument before the verdict. A coverage checker that cannot
        # detect an uncovered file reports a clean tree over anything — this
        # same defect one layer down, and the reason `drift` was believed for
        # so long.
        key = "suite-coverage-selftest"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_suite_coverage.py"), "--selftest"])
        m = CORPUS_SELFTEST_RE.search(out)
        ok = code == 0 and bool(m) and m.group(1) == "PASS"
        detail = m.group(2) if m else \
            "no anchored 'SELFTEST: PASS' line — cannot confirm"
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_suite_coverage(self):
        # `drift` proves a test-LOOKING file is inside a directory some
        # component names. Measured on caf2cd6, that is two claims short of
        # the one it makes about itself (RFX-355): it walks five filename
        # spellings, so a stray attack-probe-*.py or .php is invisible to it;
        # and "inside a suite root" only implies "something runs it" for the
        # roots run by DIRECTORY DISCOVERY. reeflex-wordpress/tests is run
        # from two hardcoded literals, so a .php dropped there satisfies drift
        # by its location and is invoked by nothing. This enumerates from the
        # directory instead and requires every artefact to be dispositioned.
        key = "suite-coverage"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_suite_coverage.py"), REPO_ROOT])
        ok, detail = parse_suite_coverage(code, out)
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- dependency floors (the PR #123 sweep) -------------------------------

    def run_dep_floors(self):
        # Static, no network, no installs: every requirement this repo DECLARES
        # must be bounded above. #123's `mcp>=2` turned main red on a commit
        # that touched none of the package, and worse, changed what a holds
        # operator sees. Not skippable — there is no environment in which this
        # cannot run, which is exactly why it is not in SKIP_REGISTRY.
        key = "dep-floors"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_dependency_floors.py"), REPO_ROOT])
        ok, detail = parse_dep_floors(code, out)
        self.show(out, full=not ok, tail=12)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_dep_floors_selftest(self):
        # The instrument before the verdict (same pattern as the census
        # selftest in gate.yml): a manifest reader is worth exactly what its
        # parser is worth, and three defects this month were a correct tree
        # measured by a wrong instrument.
        key = "dep-floors-selftest"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_dependency_floors.py"), "--selftest"])
        ok = code == 0
        m = re.search(r"^selftest: (\d+) properties, (\d+) failed$", out, re.M)
        detail = ("%s properties, %s failed" % (m.group(1), m.group(2))) if m \
            else "no anchored 'selftest: N properties' line — cannot confirm"
        if not m:
            ok = False
        self.show(out, full=not ok, tail=6)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- migration graph (RFX-49) --------------------------------------------

    def run_migration_heads_selftest(self):
        # Unconditional: proves the CHECKER TOOL itself is correct (single
        # head passes, a shared-parent collision fails, re-parenting fixes
        # it, merge migrations/dangling parents/duplicate ids are handled).
        # This runs regardless of whether reeflex-app is checked out here.
        key = "migration-heads-selftest"
        code, out = self.run_cmd(
            [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-t", "scripts"],
        )
        ok, detail = parse_unittest(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_migration_heads(self):
        # Optional: this repo has no alembic migrations of its own (reeflex-core
        # is OPA/Rego, not a DB-backed service) — the graph that actually broke
        # in RFX-49 lives in the private reeflex-app repo, cloned separately
        # (never vendored into this tree). When that checkout is present
        # (canonical devbox layout, WoW R.5, or a REEFLEX_APP_MIGRATIONS_DIR
        # override) this gate ALSO validates its migration graph, for free,
        # in the same command a developer already runs on that machine.
        key = "migration-heads"
        app_dir = os.environ.get("REEFLEX_APP_MIGRATIONS_DIR")
        if app_dir and not os.path.isdir(app_dir):
            app_dir = None
        if not app_dir:
            app_dir = next((c for c in APP_MIGRATIONS_CANDIDATES if os.path.isdir(c)), None)
        if not app_dir:
            self.component(key, "SKIPPED",
                           "no reeflex-app checkout found (set REEFLEX_APP_MIGRATIONS_DIR, "
                           "or check out reeflex-app as a sibling of this repo) — this repo "
                           "itself has no alembic migrations")
            return
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "check_migration_heads.py"), app_dir]
        )
        ok, detail = parse_migration_heads(code, out)
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- main -----------------------------------------------------------------

    def main(self):
        self.emit("REEFLEX PREFLIGHT GATE (gate.py) — repo root: %s" % REPO_ROOT)
        self.emit("")
        if not self.env_check():
            self.emit("")
            self.emit("GATE: ENV-STOP")
            return 2
        self.emit("")
        for header, fn in [
            ("rego-core       opa test reeflex-core/policy/", lambda: self.run_rego("rego-core", "reeflex-core/policy")),
            ("rego-claude     opa test reeflex-claude/policy/", lambda: self.run_rego("rego-claude", "reeflex-claude/policy")),
            ("unittest-core   full discovery over reeflex-core/tests", self.run_core_unittest),
            ("pytest suites   reeflex-mcp + reeflex-holds + reeflex-claude + reeflex-litellm", self.run_pytest_suites),
            ("npm-n8n         n8n-nodes-reeflex npm ci + npm test", self.run_n8n),
            ("entrypoints     build wheels from tree + invoke every entry point", self.run_entrypoints),
            ("pypi-smoke      fresh install of the PUBLISHED packages", self.run_pypi_smoke),
            ("pypi-content-selftest  the content comparator, on synthetic wheels, before its verdict is trusted", self.run_published_content_selftest),
            ("pypi-content    PUBLISHED sources vs this tree, under the SAME version string (RFX-300)", self.run_published_content),
            ("claude-corpus-live  the Bash corpus through the real hook vs a real core, "
             "compared against the offline oracle (RFX-303)", self.run_corpus_live),

            ("pypi-behaviour-selftest  the published-wheel comparison, on fixtures, before its verdict is trusted", self.run_published_classifier_selftest),
            ("pypi-behaviour  the PUBLISHED reeflex-claude scored with this tree's corpus (RFX-241)", self.run_published_classifier),
            ("pypi-litellm-seat  the PUBLISHED reeflex-litellm SEAT, and the classifier its own floor admits (RFX-326)", self.run_published_seat),
            ("wp-conformance  WordPress live-core harness", self.run_wp),
            ("wp-spec-conformance  SPEC axis vectors, no live core (RFX-131, RFX-164)", self.run_wp_spec),
            ("dep-floors-selftest  the manifest parser, on fixtures, before its verdict is trusted", self.run_dep_floors_selftest),
            ("dep-floors      every DECLARED requirement is bounded above (PR #123 sweep)", self.run_dep_floors),
            ("migration-heads-selftest  scripts/tests: checker-tool correctness (migration heads, dependency floors)", self.run_migration_heads_selftest),
            ("migration-heads  static alembic graph (reeflex-app, if checked out) — single head, no DB", self.run_migration_heads),
            ("test-census     every enumerated test file must YIELD TESTS (RFX-87)", self.run_test_census),
            ("suite-coverage-selftest  the coverage detectors, on fixtures, before their verdict is trusted", self.run_suite_coverage_selftest),
            ("suite-coverage  every check artefact is invoked by something, or says why not (RFX-355)", self.run_suite_coverage),
            ("drift           test files outside every enumerated suite", self.run_drift),
        ]:
            self.emit("--- %s" % header)
            fn()
            self.emit("")

        # skip-ledger runs LAST: it is the only component that reads the other
        # components' statuses, so it cannot be ordered anywhere else.
        allow = set(filter(None, (self.args.allow_skips or "").split(",")))
        _, statuses_so_far = derive_verdict(self.lines, allow)
        self.emit("--- skip-ledger     what was skipped in THIS run, and why (RFX-108)")
        ledger_ok, ledger_lines = audit_skips(statuses_so_far, allow)
        for line in ledger_lines:
            self.emit(line)
        self.component("skip-ledger", "PASS" if ledger_ok else "FAIL",
                       "every skip in this run is accounted for" if ledger_ok
                       else "an --allow-skips key has no registered justification")
        self.emit("")

        verdict, statuses = derive_verdict(self.lines, allow)
        self.emit("GATE SUMMARY")
        for k, s in statuses.items():
            note = " [skip allowed via --allow-skips]" if s == "SKIPPED" and k in allow else ""
            self.emit("  %s: %s%s" % (k, s, note))
        self.emit("")
        self.emit("GATE: %s" % verdict)
        return {"GREEN": 0, "RED": 1, "INCOMPLETE": 3}[verdict]


# --------------------------------------------------------------------------
# Selftest (DoD 5): prove the parsing is anchored and case-sensitive.
# --------------------------------------------------------------------------

def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # opa: only a full, exact, case-sensitive `PASS: n/n` line with n == n passes
    check("opa accepts real summary", parse_opa(0, "data.x: PASS (1ms)\nPASS: 9/9\n")[0])
    check("opa rejects lowercase", not parse_opa(0, "pass: 9/9\n")[0])
    check("opa rejects indented line", not parse_opa(0, "  PASS: 9/9\n")[0])
    check("opa rejects partial pass", not parse_opa(0, "PASS: 8/9\n")[0])
    check("opa rejects embedded word", not parse_opa(0, "all tests PASS: 9/9 today\n")[0])
    check("opa rejects nonzero exit", not parse_opa(1, "PASS: 9/9\n")[0])

    # pytest: a line merely containing "passed" must not flip the gate
    check("pytest accepts real summary", parse_pytest(0, "....\n56 passed in 1.02s\n")[0])
    check("pytest accepts warnings variant", parse_pytest(0, "56 passed, 2 warnings in 3.21s\n")[0])
    ok, detail = parse_pytest(0, "55 passed, 1 skipped in 2.20s\n")
    check("pytest reports in-suite skips", ok and "1 skipped in-suite" in detail)
    check("pytest rejects prose mention", not parse_pytest(0, "the run passed in style\n")[0])
    check("pytest rejects PASSED uppercase", not parse_pytest(0, "56 PASSED in 1.02s\n")[0])
    check("pytest rejects failed-prefix line", not parse_pytest(0, "5 failed, 56 passed in 1.02s\n")[0])
    check("pytest rejects indented summary", not parse_pytest(0, "  56 passed in 1.02s\n")[0])
    check("pytest rejects nonzero exit", not parse_pytest(1, "56 passed in 1.02s\n")[0])

    # n8n: only the runner's own exact summary with 0 failed passes
    check("n8n accepts real summary", parse_n8n(0, "ok - x\n14 passed, 0 failed, 14 total\n")[0])
    check("n8n rejects failures", not parse_n8n(0, "13 passed, 1 failed, 14 total\n")[0])
    check("n8n rejects count mismatch", not parse_n8n(0, "13 passed, 0 failed, 14 total\n")[0])
    check("n8n rejects prose mention", not parse_n8n(0, "all 14 passed, 0 failed, 14 total tests\n")[0])
    check("n8n rejects nonzero exit", not parse_n8n(1, "14 passed, 0 failed, 14 total\n")[0])

    # unittest: needs BOTH `Ran N tests in Xs` AND an anchored OK line
    check("unittest accepts real summary", parse_unittest(0, "Ran 255 tests in 60.953s\n\nOK\n")[0])
    ok, detail = parse_unittest(0, "Ran 255 tests in 60.953s\n\nOK (skipped=1)\n")
    check("unittest reports in-suite skips", ok and "skipped=1 in-suite" in detail)
    check("unittest rejects lowercase ok", not parse_unittest(0, "Ran 5 tests in 1.0s\n\nok\n")[0])
    check("unittest rejects OK-in-prose", not parse_unittest(0, "Ran 5 tests in 1.0s\neverything OK here\n")[0])
    check("unittest rejects FAILED", not parse_unittest(1, "Ran 5 tests in 1.0s\n\nFAILED (failures=2)\n")[0])
    check("unittest rejects missing Ran line", not parse_unittest(0, "\nOK\n")[0])

    # migration-heads: only the checker's own anchored PASS/FAIL line counts
    check("migration-heads accepts real PASS", parse_migration_heads(0, "MIGRATION-HEADS: PASS (1 head: 0011_x)\n")[0])
    check("migration-heads rejects real FAIL even at exit 0",
          not parse_migration_heads(0, "MIGRATION-HEADS: FAIL (2 heads)\n")[0])
    check("migration-heads rejects nonzero exit despite PASS line",
          not parse_migration_heads(1, "MIGRATION-HEADS: PASS (1 head: x)\n")[0])
    check("migration-heads rejects prose mention",
          not parse_migration_heads(0, "well, MIGRATION-HEADS: PASS (1 head: x) I guess\n")[0])
    check("migration-heads rejects exit 0 with no anchored line",
          not parse_migration_heads(0, "some other output\n")[0])

    # dep-floors: only the checker's own anchored PASS/FAIL line counts (PR #123
    # sweep). Same five properties as migration-heads, on purpose — the failure
    # this guards is "the floor check went green because it printed nothing".
    check("dep-floors accepts real PASS",
          parse_dep_floors(0, "DEP-FLOORS: PASS (20 requirements over 7 manifests; 0 unbounded; 1 allowed)\n")[0])
    check("dep-floors rejects real FAIL even at exit 0",
          not parse_dep_floors(0, "DEP-FLOORS: FAIL (20 requirements over 7 manifests; 6 unbounded; 1 allowed)\n")[0])
    check("dep-floors rejects nonzero exit despite PASS line",
          not parse_dep_floors(1, "DEP-FLOORS: PASS (20 requirements over 7 manifests; 0 unbounded; 1 allowed)\n")[0])
    check("dep-floors rejects prose mention",
          not parse_dep_floors(0, "I ran it and DEP-FLOORS: PASS (all fine) honestly\n")[0])
    check("dep-floors rejects exit 0 with no anchored line",
          not parse_dep_floors(0, "checked everything, looks good\n")[0])
    ok, detail = parse_dep_floors(0, "DEP-FLOORS: FAIL (20 requirements over 7 manifests; 6 unbounded; 1 allowed)\n")
    check("dep-floors carries the counts into the component detail",
          not ok and "6 unbounded" in detail)

    # test-census: only the census's own anchored PASS/FAIL line counts (RFX-108)
    check("test-census accepts real PASS",
          parse_test_census(0, "TEST-CENSUS: PASS (44 files, 943 tests collected, 2 waived)\n")[0])
    check("test-census rejects real FAIL even at exit 0",
          not parse_test_census(0, "TEST-CENSUS: FAIL (1 finding(s) [zero-collection])\n")[0])
    check("test-census rejects nonzero exit despite PASS line",
          not parse_test_census(1, "TEST-CENSUS: PASS (44 files)\n")[0])
    check("test-census rejects prose mention",
          not parse_test_census(0, "note: TEST-CENSUS: PASS (all good) probably\n")[0])
    check("test-census rejects exit 0 with no anchored line",
          not parse_test_census(0, "collected some tests\n")[0])

    # suite-coverage (RFX-355): same anchored discipline, and for the same
    # reason — this component's whole subject is a check that was reporting a
    # reassuring word about something it never looked at.
    check("suite-coverage accepts real PASS",
          parse_suite_coverage(0, "SUITE-COVERAGE: PASS (9 wp harness file(s), 28 script(s))\n")[0])
    check("suite-coverage rejects real FAIL even at exit 0",
          not parse_suite_coverage(0, "SUITE-COVERAGE: FAIL (1 artefact(s) unaccounted)\n")[0])
    check("suite-coverage rejects nonzero exit despite PASS line",
          not parse_suite_coverage(1, "SUITE-COVERAGE: PASS (all dispositioned)\n")[0])
    check("suite-coverage rejects prose mention",
          not parse_suite_coverage(0, "note: SUITE-COVERAGE: PASS (all good) probably\n")[0])
    check("suite-coverage rejects exit 0 with no anchored line",
          not parse_suite_coverage(0, "walked the tree, looked fine\n")[0])

    # pypi-content (RFX-300): the artefact is not the tree. Same anchored
    # discipline — the exit code alone cannot flip this component green, because
    # the whole subject of the component is a thing that reports success while
    # being the wrong thing.
    check("pypi-content accepts the anchored PASS line",
          parse_published_content(0, "PUBLISHED-CONTENT: PASS (2 matched)\n")[0])
    check("pypi-content rejects nonzero exit despite PASS line",
          not parse_published_content(1, "PUBLISHED-CONTENT: PASS (2 matched)\n")[0])
    check("pypi-content reports FAIL detail verbatim",
          parse_published_content(1, "PUBLISHED-CONTENT: FAIL (reeflex-mcp==0.1.3)\n")
          == (False, "reeflex-mcp==0.1.3"))
    check("pypi-content rejects prose mention",
          not parse_published_content(0, "note: PUBLISHED-CONTENT: PASS (fine) maybe\n")[0])
    check("pypi-content rejects exit 0 with no anchored line",
          not parse_published_content(0, "compared some wheels\n")[0])

    # entrypoints and pypi-smoke score one `<entry> --help` each, and until
    # 2026-09-21 only ONE of them looked at the output (RFX-149). Both now call
    # this, so the rows below are about the artefact leg as much as the tree leg.
    _USAGE_OUT = "usage: reeflex-holds [-h] {list,approve,reject} ...\n"
    check("entrypoint scorer accepts exit 0 + anchored banner",
          score_entrypoint_help("reeflex-holds", "reeflex-holds", 0, _USAGE_OUT)[0])
    check("entrypoint scorer REJECTS exit 0 with no output at all",
          not score_entrypoint_help("reeflex-holds", "reeflex-holds", 0, "")[0])
    check("entrypoint scorer names the silent-banner failure, not the exit code",
          "no anchored 'usage: reeflex-holds' banner"
          in score_entrypoint_help("reeflex-holds", "reeflex-holds", 0, "")[1])
    check("entrypoint scorer rejects the banner as a mid-line substring",
          not score_entrypoint_help("reeflex-holds", "reeflex-holds", 0,
                                    "error: bad usage: reeflex-holds [-h]\n")[0])
    check("entrypoint scorer rejects a nonzero exit despite a banner",
          not score_entrypoint_help("reeflex-holds", "reeflex-holds", 1, _USAGE_OUT)[0])
    check("entrypoint scorer anchors on the entry point's own name",
          not score_entrypoint_help("reeflex-holds", "reeflex-holds", 0,
                                    "usage: reeflex-mcp [-h]\n")[0])
    # The regression itself, as a row: reeflex-holds==0.1.2 answered --help with
    # exit 0 and zero bytes, and that wheel's `approve` exits 0 in silence.
    check("the 0.1.2 observation (exit 0, zero bytes) fails the published leg",
          not score_entrypoint_help("reeflex-holds", "reeflex-holds", 0, "")[0])
    # The expectation is DATA, and a caller cannot talk it down. An unlisted
    # package is judged as if it declared a banner (fail closed).
    check("an unlisted package is still held to a banner",
          not score_entrypoint_help("not-in-the-list", "not-in-the-list", 0, "")[0])
    check("every PUBLISHED row carries a banner flag the scorer can read",
          all(isinstance(has_usage, bool) for _, _, has_usage in PUBLISHED))
    check("every package this repo publishes is in PUBLISHED",
          set(p for p, _e, _u in PUBLISHED)
          >= {"reeflex-mcp", "reeflex-holds", "reeflex-claude"})
    check("every PUBLISHED row with a banner flag is held to it",
          all(score_entrypoint_help(p, e, 0, "")[0] is not True
              for p, e, u in PUBLISHED if u))
    # AND THE ROWS ABOVE CANNOT SEE A CALLER DROP THE CALL. Every check so far
    # scores the scorer; all of them stay green if `run_pypi_smoke` goes back to
    # `for pkg, entry, _ in PUBLISHED` and its own `if code != 0`, which is
    # exactly the state this fix found. So score the callers too.
    check("entrypoints actually calls the shared scorer",
          "score_entrypoint_help" in Gate.run_entrypoints.__code__.co_names)
    check("pypi-smoke actually calls the shared scorer",
          "score_entrypoint_help" in Gate.run_pypi_smoke.__code__.co_names)
    check("neither leg keeps a private exit-code-only verdict",
          not any("USAGE_RE_TMPL" in fn.__code__.co_names
                  for fn in (Gate.run_entrypoints, Gate.run_pypi_smoke)))
    # claude-corpus-live: the live arm's verdict, same discipline (RFX-303).
    # The FAIL cases matter more than the PASS one here: this component's whole
    # job is to go red on a disagreement between the two planes, and it spent
    # its existence being run by nothing at all.
    _CL_PASS = ("CORPUS-LIVE: PASS (85 cases vs http://127.0.0.1:8099: 0 destructions "
                "allowed, 0 live-vs-oracle divergences, 0 everyday blocked)\n")
    _CL_FAIL = ("CORPUS-LIVE: FAIL (85 cases vs http://127.0.0.1:8099: 0 destructions "
                "allowed, 1 live-vs-oracle divergences, 0 everyday blocked)\n")
    check("corpus-live accepts real PASS", parse_corpus_live(0, _CL_PASS)[0])
    check("corpus-live rejects real FAIL even at exit 0",
          not parse_corpus_live(0, _CL_FAIL)[0])
    check("corpus-live rejects nonzero exit despite PASS line",
          not parse_corpus_live(1, _CL_PASS)[0])
    check("corpus-live rejects prose mention",
          not parse_corpus_live(0, "we think CORPUS-LIVE: PASS (probably)\n")[0])
    check("corpus-live rejects a lowercase imitation",
          not parse_corpus_live(0, "corpus-live: pass (85 cases)\n")[0])
    check("corpus-live rejects exit 0 with no anchored line — a run that died "
          "before comparing anything",
          not parse_corpus_live(0, "### core=http://127.0.0.1:8099\n")[0])
    ok, detail = parse_corpus_live(2, _CL_FAIL)
    check("corpus-live carries the divergence count into the component detail",
          not ok and "1 live-vs-oracle divergences" in detail)
    check("claude-corpus-live's skip is registered with a written reason",
          "claude-corpus-live" in SKIP_REGISTRY)

    # pypi-behaviour: three-valued, because "could not install" is not "is fine"
    # (RFX-241). Same anchoring properties as the others, plus the SKIP arm.
    check("pypi-behaviour accepts real PASS",
          parse_published_classifier(0, "PUBLISHED-CLASSIFIER: PASS (reeflex-claude==0.2.0; "
                                        "78 cases scored (floor 40); 0 fail-open)\n")[0] == "PASS")
    check("pypi-behaviour rejects real FAIL even at exit 0",
          parse_published_classifier(0, "PUBLISHED-CLASSIFIER: FAIL (reeflex-claude==0.1.7; "
                                        "42 fail-open)\n")[0] == "FAIL")
    check("pypi-behaviour rejects nonzero exit despite PASS line",
          parse_published_classifier(1, "PUBLISHED-CLASSIFIER: PASS (all clean)\n")[0] == "FAIL")
    check("pypi-behaviour rejects prose mention",
          parse_published_classifier(0, "I think PUBLISHED-CLASSIFIER: PASS (fine) really\n")[0]
          == "FAIL")
    check("pypi-behaviour rejects exit 0 with no anchored line",
          parse_published_classifier(0, "installed the wheel, looked ok\n")[0] == "FAIL")
    check("pypi-behaviour carries the counts into the component detail",
          "42 fail-open" in parse_published_classifier(
              0, "PUBLISHED-CLASSIFIER: FAIL (reeflex-claude==0.1.7; 42 fail-open)\n")[1])
    check("pypi-behaviour reports an unreachable index as SKIPPED, not PASS",
          parse_published_classifier(3, "PUBLISHED-CLASSIFIER: SKIP (not installable)\n")[0]
          == "SKIPPED")
    check("pypi-behaviour refuses a SKIP line that did not exit 3",
          parse_published_classifier(0, "PUBLISHED-CLASSIFIER: SKIP (not installable)\n")[0]
          == "FAIL")

    # RFX-326. The seat arm's parser, including the one failure mode that is
    # specific to having two arms: each must read ONLY its own anchor, or a
    # green line from one component silently becomes the other's verdict.
    check("pypi-litellm-seat accepts real PASS",
          parse_published_seat(0, "PUBLISHED-LITELLM-SEAT: PASS (reeflex-litellm==0.1.0; "
                                  "96 cases scored)\n")[0] == "PASS")
    check("pypi-litellm-seat reports FAIL verbatim",
          parse_published_seat(1, "PUBLISHED-LITELLM-SEAT: FAIL (10 fail-open)\n")[0]
          == "FAIL")
    check("pypi-litellm-seat refuses exit 0 with no anchored line",
          parse_published_seat(0, "installed the seat, looked ok\n")[0] == "FAIL")
    check("pypi-litellm-seat reports an unreachable index as SKIPPED, not PASS",
          parse_published_seat(3, "PUBLISHED-LITELLM-SEAT: SKIP (not installable)\n")[0]
          == "SKIPPED")
    check("pypi-litellm-seat does NOT read the classifier arm's anchored line",
          parse_published_seat(0, "PUBLISHED-CLASSIFIER: PASS (all clean)\n")[0] == "FAIL")
    check("pypi-behaviour does NOT read the seat arm's anchored line",
          parse_published_classifier(0, "PUBLISHED-LITELLM-SEAT: PASS (all clean)\n")[0]
          == "FAIL")

    # skip-ledger: an allowance without a written justification is refused (RFX-108)
    reg = {"known": "a registered reason"}
    ok, lines = audit_skips({"a": "PASS", "known": "SKIPPED"}, {"known"}, reg)
    check("skip-ledger passes a registered, used allowance", ok)
    check("skip-ledger prints the reason for every skip",
          any("why: a registered reason" in l for l in lines))
    ok, lines = audit_skips({"a": "PASS", "mystery": "SKIPPED"}, {"mystery"}, reg)
    check("skip-ledger REFUSES an unregistered --allow-skips key", not ok)
    check("...and says so", any("not in SKIP_REGISTRY" in l for l in lines))
    ok, lines = audit_skips({"known": "PASS"}, {"known"}, reg)
    check("skip-ledger WARNs on a stale allowance without failing", ok)
    check("...and names it", any("is STALE" in l for l in lines))
    ok, lines = audit_skips({"a": "PASS"}, set(), reg)
    check("skip-ledger says plainly when nothing was skipped",
          ok and any("nothing was skipped" in l for l in lines))
    ok, lines = audit_skips({"a": "SKIPPED"}, set(), reg)
    check("skip-ledger flags a NOT-ALLOWED skip in the ledger text",
          any("NOT ALLOWED" in l for l in lines))
    check("...and reports the missing justification honestly",
          any("no registered justification" in l for l in lines))
    check("every key in the real SKIP_REGISTRY carries a non-empty reason",
          all(isinstance(v, str) and len(v) > 20 for v in SKIP_REGISTRY.values()))

    # transcript re-parse: only exact COMPONENT lines count
    v, _ = derive_verdict(["COMPONENT a: PASS (x)", "COMPONENT b: PASS"], set())
    check("verdict GREEN on all pass", v == "GREEN")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: FAIL (boom)"], set())
    check("verdict RED on any fail", v == "RED")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: SKIPPED (no tool)"], set())
    check("verdict INCOMPLETE on skip", v == "INCOMPLETE")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: SKIPPED (no tool)"], {"b"})
    check("verdict GREEN when skip allowed", v == "GREEN")
    v, _ = derive_verdict(["component a: pass", "This line mentions PASS"], set())
    check("verdict RED when transcript unparseable", v == "RED")
    v, _ = derive_verdict(["  COMPONENT a: PASS"], set())
    check("verdict ignores indented component line", v == "RED")

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  selftest %s: %s" % ("PASS" if ok else "FAIL", n))
    if failed:
        print("SELFTEST: FAIL (%d/%d checks failed)" % (len(failed), len(checks)))
        return 1
    print("SELFTEST: PASS (%d checks)" % len(checks))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="gate.py", description="Reeflex uniform preflight gate")
    p.add_argument("--pypi", choices=["run", "delegated", "skip"], default="run",
                   help="PyPI smoke: run inline (default), delegated (CI runs smoke-pypi.yml "
                        "as a sibling workflow_call job), or skip (flagged, forces INCOMPLETE)")
    p.add_argument("--allow-skips", default="",
                   help="comma-separated component keys whose SKIP does not force INCOMPLETE "
                        "(printed in the summary; use for structurally unrunnable suites)")
    p.add_argument("--core-url", default="",
                   help="live reeflex-core URL for the WordPress conformance harness")
    p.add_argument("--selftest", action="store_true",
                   help="run the anchored-parsing selftest and exit")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.selftest:
        sys.exit(selftest())
    gate = Gate(args)
    try:
        sys.exit(gate.main())
    finally:
        shutil.rmtree(gate.tmp, ignore_errors=True)
