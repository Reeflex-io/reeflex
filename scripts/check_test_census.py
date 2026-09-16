#!/usr/bin/env python3
"""check_test_census.py — static census of what the test suites ACTUALLY run.

WHY THIS EXISTS (RFX-87, and the RFX-105..115 sweep): on 2026-08-21 it came out that
`reeflex-core/tests/test_env_canon.py` — the regression guard PR #89 added for a
LIVE fail-open security hole (R2/R3 evadable by writing the environment as
"Prod", i.e. an irreversible production action allowed with no human) — had
never executed a single assertion. It was written as bare pytest functions with
`@pytest.mark.parametrize`; `gate.py` runs that suite with `unittest discover`,
which imports such a module, finds no `TestCase`, and collects ZERO tests:

    $ python -m unittest discover -s tests -t . -p 'test_env_canon.py' -v
    Ran 0 tests in 0.000s
    OK

Green. Every run. From the day it landed. That was the THIRD instance in two
days of a check that was reassuring us about something it never executed, so
this script exists to make the whole CLASS structurally visible rather than to
fix the one file.

`gate.py`'s `drift` component already refuses a test file that sits OUTSIDE
every enumerated suite root — "a new suite cannot run nowhere". But it only ever
checked that a test file is in a directory some component names. It never
checked that the file YIELDS TESTS. This closes that: location is not
execution.

WHAT IT CHECKS, per enumerated (suite root, runner) pair, statically — `ast`
only, no imports, no test execution, so it cannot be defeated by an import
error and needs none of the suites' dependencies installed:

  1. ZERO-COLLECTION — a `test_*.py` file that yields no tests under the runner
     that root is actually run with. This is the #89 defect exactly. When the
     file DOES define bare `test_*` functions but the root is run with
     `unittest discover`, the diagnosis names that specific mismatch, because
     that is the trap: the file looks completely normal.

  2. EMPTY TEST BODIES — a test whose body is only a docstring / `pass` /
     `...`. It is collected, it is counted, it is green, and it asserts
     nothing. A skipped-but-empty test is worse than either alone: removing
     the skip does not restore any coverage, because there is none to restore.

  3. UNCONDITIONAL SKIPS — `@unittest.skip(...)` / `@pytest.mark.skip(...)`
     with no condition. These never run anywhere, on any machine, forever.
     Conditional skips (`skipUnless`/`skipIf`/`skipif`) are NOT flagged here:
     they are how a suite honestly declines to run without its prerequisite,
     and gate.py already turns the ones that matter into a loud component-level
     SKIP (see `run_core_unittest`'s opa handling).

  4. MODULE-LEVEL SILENCERS (RFX-226) — one statement at the top level of a
     test file that removes the WHOLE file from the run:

         pytest.skip("...", allow_module_level=True)   # ast.Expr(ast.Call)
         pytestmark = pytest.mark.skip("...")          # ast.Assign
         raise unittest.SkipTest("...")                # ast.Raise

     Until RFX-226 none of those three node types was looked at, because
     `collect()` only ever inspected FunctionDef/AsyncFunctionDef/ClassDef. So
     each of them deleted a whole file's tests while the census went on
     counting them as collected: one line on `reeflex-core/tests/test_hil.py`
     took the real runner from `Ran 617` to `Ran 534` — 83 tests, the entire
     HIL suite, reported by unittest as ONE skip — and this script printed the
     baseline transcript, byte for byte, and PASS.

     A silenced file's tests are therefore no longer COUNTED either: the
     printed total is what the runner would run, not what the file defines.
     That is the point of the component — a number that does not move when 83
     tests disappear is not a census.

  5. IN-BODY UNCONDITIONAL SKIPS (RFX-226) — the statement twin of detector 3:

         def test_x(self):
             self.skipTest("...")      # or pytest.skip(...) / raise SkipTest

     Same effect as the decorator, invisible to a detector that only reads
     `decorator_list`, and `_body_is_empty` sees a non-empty body. These stay
     COUNTED (the runner does collect them and reports them as skipped), but
     they are flagged, exactly as their decorator spelling is.

LIMITS OF DETECTORS 4 AND 5, STATED RATHER THAN CLOSED. Both are deliberately
blind to a silencer nested inside an `if`:

    if not _opa_available():
        pytest.skip("OPA not installed", allow_module_level=True)

That is how a suite honestly declines a missing prerequisite and MUST NOT be
flagged — which also means a sabotage spelled `if True:` still evades a static
detector, and a suite that shrinks for a reason no AST models (a deleted file,
a changed `-p` pattern) is not modelled here at all. The only instrument that
would catch those is a recorded total floor compared against the runner's own
`Ran N` (the `tests/suite_census.json` shape in reeflex-app). This script is
static by design; the floor is a separate, complementary instrument.

WAIVERS, AND WHY THEY ARE NOT A BACK DOOR. A finding can be legitimate — a
genuinely platform-specific race, say. Such a case goes in `WAIVERS` below with
a reason AND a ticket reference (the format is enforced: no ticket, no waiver).
A waiver does not hide anything:

  - every waiver is PRINTED in full on every run, passing or failing;
  - the count rides on the anchored summary line, so it is in the gate
    transcript and in CI logs;
  - a waiver whose target no longer exists is a FAILURE, not a silent no-op,
    so waivers cannot rot into permanent blanket permission.

That is the difference between a skip that is *accounted for* and a skip that
is *invisible*. This whole file exists because of the second kind.

USAGE
  python check_test_census.py [<repo-root>]
  python check_test_census.py --selftest    # prove every detector (see gate.py --selftest)

VERDICT — anchored, case-sensitive; parse EXACTLY this line:
  TEST-CENSUS: PASS (...)   exit 0 — every enumerated test file yields tests
  TEST-CENSUS: FAIL (...)   exit 1 — something that should have run did not
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
import tempfile

# The (suite root, runner) pairs, mirroring how gate.py ACTUALLY invokes each
# suite. The runner is the load-bearing half: the same file is 8 tests under
# pytest and 0 tests under `unittest discover`, and #89 died in that gap.
#
# Keep this in step with gate.py's SUITE_ROOTS. Non-Python suites are listed
# with runner=None and are censused for presence only -- `opa test` (rego),
# `npm test` (n8n) and the PHP live-core harnesses have their own collection
# semantics that an ast pass cannot model, and gate.py runs each of them
# directly, as itself, with its own anchored summary parser.
CENSUS_ROOTS = [
    ("reeflex-core/tests", "unittest"),
    ("scripts/tests", "unittest"),
    ("reeflex-mcp/tests", "pytest"),
    ("reeflex-holds/tests", "pytest"),
    ("reeflex-claude/tests", "pytest"),
    ("reeflex-litellm/tests", "pytest"),
]

# (relative path, test name or "" for a whole file) -> "reason (TICKET)"
#
# Every entry is printed on every run and MUST name a ticket. An entry whose
# target has disappeared fails the census -- see the module docstring.
WAIVERS = {
    (
        "reeflex-core/tests/test_telemetry.py",
        "TestTransportTLS.test_tls_emitter_connects_and_delivers",
    ): (
        "Body was emptied when the test was skipped, so it asserts nothing even "
        "un-skipped; TLS byte delivery is currently proven by no test at all "
        "(test_tls_verify_false_no_raise is satisfied by a transport that drops "
        "every payload). Kept visible here until the body is restored. (RFX-109)"
    ),
}

TEST_FILE_PREFIX = "test_"
SKIP_DECORATORS_UNCONDITIONAL = {"skip"}
SKIP_DECORATORS_CONDITIONAL = {"skipUnless", "skipIf", "skipif"}
# Call forms that skip when EXECUTED rather than when decorating: `pytest.skip()`,
# `self.skipTest()`. The conditional names above are decorator-only and never
# appear as a bare statement, so there is no conditional counterpart to exclude.
SKIP_CALLS_UNCONDITIONAL = {"skip", "skipTest"}
# `raise unittest.SkipTest(...)` / `raise SkipTest` -- the unittest spelling.
SKIP_EXCEPTIONS = {"SkipTest"}


class Finding:
    """One thing that does not run, or runs without asserting anything."""

    def __init__(self, kind, path, name, detail):
        # "zero-collection" | "empty-body" | "unconditional-skip" | "module-silenced"
        self.kind = kind
        self.path = path          # repo-relative
        self.name = name          # test name, or "" for a file-level finding
        self.detail = detail

    @property
    def key(self):
        return (self.path, self.name)

    def __str__(self):
        where = "%s::%s" % (self.path, self.name) if self.name else self.path
        return "%s: %s -- %s" % (self.kind, where, self.detail)


# --------------------------------------------------------------------------
# AST helpers
# --------------------------------------------------------------------------

def _decorator_name(node):
    """Last attribute/name of a decorator expression: `unittest.skip(...)` ->
    "skip", `pytest.mark.skipif(...)` -> "skipif". Returns "" if unreadable."""
    if isinstance(node, ast.Call):
        node = node.func
    while isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_testcase_class(node, testcase_aliases):
    """True if a ClassDef inherits (possibly indirectly, via a base defined in
    the same file) from unittest.TestCase.

    `testcase_aliases` accumulates class names in THIS file already known to be
    TestCase subclasses, so the common `class Base(unittest.TestCase)` +
    `class Real(Base)` shape is resolved rather than reported as 0 tests."""
    for base in node.bases:
        if isinstance(base, ast.Attribute) and base.attr == "TestCase":
            return True
        if isinstance(base, ast.Name) and (base.id == "TestCase" or base.id in testcase_aliases):
            return True
    return False


def _body_is_empty(fn):
    """True if the body is only a docstring, `pass` and/or `...` -- i.e. the
    test asserts nothing, whatever its name promises."""
    for stmt in fn.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            # a docstring, or a bare `...`
            if isinstance(stmt.value.value, str) or stmt.value.value is Ellipsis:
                continue
        return False
    return True


def _unconditional_skips(fn):
    """Decorator names on `fn` that disable it outright, everywhere."""
    return [
        name
        for name in (_decorator_name(d) for d in fn.decorator_list)
        if name in SKIP_DECORATORS_UNCONDITIONAL
    ]


def _class_is_skipped(cls):
    return bool(_unconditional_skips(cls))


def _called_name(call):
    """Last attribute/name of a CALL's target: `pytest.skip(...)` -> "skip",
    `self.skipTest(...)` -> "skipTest". "" if unreadable."""
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _raised_exception_name(node):
    """`raise unittest.SkipTest("x")` -> "SkipTest", `raise SkipTest` -> "SkipTest"."""
    exc = node.exc
    if exc is None:                       # bare `raise` -- re-raises, not a skip
        return ""
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Attribute):
        return exc.attr
    if isinstance(exc, ast.Name):
        return exc.id
    return ""


def _mark_names(value):
    """Marker names in a `pytestmark` right-hand side.

    `pytest.mark.skip("x")` -> ["skip"]; `pytest.mark.skipif(c, ...)` ->
    ["skipif"]; a list/tuple of markers -> all of them. The marker may be
    called or not -- `pytestmark = pytest.mark.skip` is valid and silences the
    file just the same."""
    if isinstance(value, (ast.List, ast.Tuple)):
        names = []
        for item in value.elts:
            names.extend(_mark_names(item))
        return names
    if isinstance(value, ast.Call):
        value = value.func
    if isinstance(value, ast.Attribute):
        return [value.attr]
    if isinstance(value, ast.Name):
        return [value.id]
    return []


def _module_silencer(node):
    """RFX-226. A detail string if this MODULE-LEVEL statement removes the whole
    file from the run, else None.

    Only ever called on `tree.body` members, which is what makes the
    conditional form (`if not _opa: pytest.skip(...)`) correctly invisible: the
    silencing call is then a child of an `ast.If`, not a top-level statement.
    See the module docstring for why that limit is deliberate."""

    # 1. `pytest.skip("x", allow_module_level=True)` -- an ast.Expr(ast.Call).
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        name = _called_name(node.value)
        if name in SKIP_CALLS_UNCONDITIONAL:
            flagged = any(kw.arg == "allow_module_level" for kw in node.value.keywords)
            return (
                "module-level `%s(...)`%s -- pytest stops importing the file "
                "here and collects NOTHING from it; the tests below are not "
                "reported as skipped, they simply do not exist for the run"
                % (name, " with allow_module_level=True" if flagged else "")
            )

    # 2. `pytestmark = pytest.mark.skip("x")` -- an ast.Assign.
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        is_pytestmark = any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in targets)
        if is_pytestmark and node.value is not None:
            unconditional = [m for m in _mark_names(node.value)
                             if m in SKIP_DECORATORS_UNCONDITIONAL]
            if unconditional:
                return (
                    "`pytestmark = ...%s(...)` -- every test in the file is "
                    "skipped, unconditionally, on every machine" % unconditional[0]
                )

    # 3. `raise unittest.SkipTest("x")` -- an ast.Raise.
    if isinstance(node, ast.Raise):
        if _raised_exception_name(node) in SKIP_EXCEPTIONS:
            return (
                "module-level `raise SkipTest(...)` -- unittest reports the "
                "WHOLE file as ONE skip, so `Ran N` drops by every test in it "
                "while the run still prints OK"
            )

    return None


def _unconditional_body_skips(fn):
    """RFX-226. Skip STATEMENTS at the top level of a test body -- the twin of
    the decorator detector, and invisible to it.

    Statements nested inside `if`/`try`/`with` are not reached: those are the
    honest conditional form and must not be flagged."""
    found = []
    for stmt in fn.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            name = _called_name(stmt.value)
            if name in SKIP_CALLS_UNCONDITIONAL:
                found.append("%s(...)" % name)
        elif isinstance(stmt, ast.Raise):
            if _raised_exception_name(stmt) in SKIP_EXCEPTIONS:
                found.append("raise SkipTest(...)")
    return found


# --------------------------------------------------------------------------
# Collection model -- what each runner would ACTUALLY pick up
# --------------------------------------------------------------------------

def collect(source, runner):
    """Model one test file's collection under `runner`, statically.

    Returns (tests, functions_seen, findings_for_this_file) where `tests` is
    the list of names the runner would run.

    The rule that matters: `unittest discover` collects `test*` METHODS of
    `TestCase` subclasses (plus a `load_tests` hook) and NOTHING else, while
    pytest collects module-level `test_*` functions and `Test*` classes too.
    Modelling that difference is the entire point of this script."""

    tree = ast.parse(source)
    tests = []
    bare_functions = []
    findings = []
    testcase_aliases = set()
    has_load_tests = False

    # RFX-226: one module-level statement can delete the whole file from the
    # run. Collect the file first anyway -- the count is what makes the finding
    # legible ("83 test(s) silenced") -- then throw the tests away below, so the
    # printed total is what the runner runs rather than what the file defines.
    silencers = []
    for node in tree.body:
        detail = _module_silencer(node)
        if detail:
            silencers.append(detail)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "load_tests":
                has_load_tests = True
                continue
            if not node.name.startswith(TEST_FILE_PREFIX):
                continue
            bare_functions.append(node.name)
            if runner == "pytest":
                tests.append(node.name)
                if _body_is_empty(node):
                    findings.append(("empty-body", node.name,
                                     "body is only a docstring/pass -- collected, green, asserts nothing"))
                for skip in _unconditional_skips(node):
                    findings.append(("unconditional-skip", node.name,
                                     "@%s with no condition -- never runs, on any machine" % skip))
                for call in _unconditional_body_skips(node):
                    findings.append(("unconditional-skip", node.name,
                                     "calls `%s` unconditionally in its body -- collected and "
                                     "counted, asserts nothing, and no decorator says so" % call))
        elif isinstance(node, ast.ClassDef):
            is_tc = _is_testcase_class(node, testcase_aliases)
            if is_tc:
                testcase_aliases.add(node.name)
            # pytest also collects plain `Test*` classes (no TestCase base).
            collected_class = is_tc or (runner == "pytest" and node.name.startswith("Test"))
            if not collected_class:
                continue
            class_skipped = _class_is_skipped(node)
            for sub in node.body:
                if not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # unittest's default prefix is "test"; pytest's is "test_".
                wanted = "test" if is_tc else TEST_FILE_PREFIX
                if not sub.name.startswith(wanted):
                    continue
                qual = "%s.%s" % (node.name, sub.name)
                tests.append(qual)
                if _body_is_empty(sub):
                    findings.append(("empty-body", qual,
                                     "body is only a docstring/pass -- collected, green, asserts nothing"))
                skips = _unconditional_skips(sub)
                if class_skipped:
                    skips.append("skip (on the class)")
                for skip in skips:
                    findings.append(("unconditional-skip", qual,
                                     "@%s with no condition -- never runs, on any machine" % skip))
                for call in _unconditional_body_skips(sub):
                    findings.append(("unconditional-skip", qual,
                                     "calls `%s` unconditionally in its body -- collected and "
                                     "counted, asserts nothing, and no decorator says so" % call))

    if silencers:
        # The file does not run at all, so every per-test finding in it is moot
        # and every one of its tests is zero: report the silencer, and STOP
        # COUNTING what the runner will not collect.
        findings = [
            ("module-silenced", "",
             "%s. %d test(s) in this file are silenced and are NOT in the census count"
             % (detail, len(tests)))
            for detail in silencers
        ]
        tests = []

    return tests, bare_functions, findings, has_load_tests


def census_file(rel_path, source, runner):
    """Every finding for one test file."""
    findings = []
    try:
        tests, bare, raw, has_load_tests = collect(source, runner)
    except SyntaxError as exc:
        return [Finding("zero-collection", rel_path, "",
                        "file does not parse (%s) -- it cannot yield any test" % exc)]

    silenced = any(kind == "module-silenced" for kind, _, _ in raw)

    # A silenced file yields no tests BECAUSE it is silenced; reporting it as
    # zero-collection as well would name the symptom over the cause.
    if not tests and not has_load_tests and not silenced:
        if runner == "unittest" and bare:
            detail = (
                "yields 0 tests under `unittest discover`: %d bare pytest-style "
                "test function(s) (%s) and no unittest.TestCase subclass. This is "
                "the #89 defect -- discover imports the module, collects nothing, "
                "and prints OK." % (len(bare), ", ".join(bare[:4]) + ("..." if len(bare) > 4 else ""))
            )
        else:
            detail = "yields 0 tests under `%s` -- it runs NOWHERE" % runner
        findings.append(Finding("zero-collection", rel_path, "", detail))

    for kind, name, detail in raw:
        findings.append(Finding(kind, rel_path, name, detail))
    return findings


# --------------------------------------------------------------------------
# Census over the tree
# --------------------------------------------------------------------------

def census(repo_root, roots=None):
    """Returns (ok, lines). `lines` includes the anchored TEST-CENSUS verdict."""
    roots = CENSUS_ROOTS if roots is None else roots
    lines = []
    findings = []
    total_files = 0
    total_tests = 0
    missing_roots = []

    for rel_root, runner in roots:
        abs_root = os.path.join(repo_root, rel_root)
        if not os.path.isdir(abs_root):
            missing_roots.append(rel_root)
            continue
        if runner is None:
            lines.append("TEST-CENSUS: NOTE %s is not censused (non-Python suite, run directly by gate.py)"
                         % rel_root)
            continue
        files = sorted(
            f for f in os.listdir(abs_root)
            if f.startswith(TEST_FILE_PREFIX) and f.endswith(".py")
        )
        if not files:
            findings.append(Finding("zero-collection", rel_root, "",
                                    "enumerated suite root contains no test_*.py file at all"))
            continue
        root_tests = 0
        root_silenced = 0
        for name in files:
            rel_path = os.path.join(rel_root, name)
            with open(os.path.join(abs_root, name), encoding="utf-8") as fh:
                source = fh.read()
            file_findings = census_file(rel_path, source, runner)
            findings.extend(file_findings)
            tests, _, _, _ = collect(source, runner) if not any(
                f.kind == "zero-collection" and f.name == "" and "does not parse" in f.detail
                for f in file_findings
            ) else ([], [], [], False)
            total_files += 1
            root_tests += len(tests)
            total_tests += len(tests)
            if any(f.kind == "module-silenced" for f in file_findings):
                root_silenced += 1
        lines.append("TEST-CENSUS: %s (%s) -> %d file(s), %d test(s)%s"
                     % (rel_root, runner, len(files), root_tests,
                        "" if not root_silenced else
                        " (%d file(s) SILENCED at module level -- their tests are not in this count)"
                        % root_silenced))

    for rel_root in missing_roots:
        findings.append(Finding("zero-collection", rel_root, "",
                                "enumerated suite root does not exist -- gate.py names a suite that is not there"))

    # -- waivers: printed always, enforced both ways ------------------------
    waived, unwaived = [], []
    for f in findings:
        if f.key in WAIVERS:
            waived.append(f)
        else:
            unwaived.append(f)

    bad_waivers = []
    for key, reason in sorted(WAIVERS.items()):
        if "(" not in reason or ")" not in reason:
            bad_waivers.append("%s::%s has no ticket reference in its reason" % key)
    stale = sorted(set(WAIVERS) - {f.key for f in findings})
    for key in stale:
        bad_waivers.append(
            "%s::%s is waived but no longer flagged -- remove the waiver "
            "(a waiver that outlives its finding is blanket permission)" % key
        )

    if waived:
        lines.append("")
        lines.append("TEST-CENSUS: %d WAIVED finding(s) -- declared, ticketed, and printed every run:" % len(waived))
        for f in waived:
            lines.append("  WAIVED  %s" % f)
            lines.append("          reason: %s" % WAIVERS[f.key])

    if unwaived:
        lines.append("")
        lines.append("TEST-CENSUS: %d finding(s):" % len(unwaived))
        for f in sorted(unwaived, key=lambda x: (x.kind, x.path, x.name)):
            lines.append("  %s" % f)

    if bad_waivers:
        lines.append("")
        lines.append("TEST-CENSUS: %d broken waiver(s):" % len(bad_waivers))
        for b in bad_waivers:
            lines.append("  %s" % b)

    ok = not unwaived and not bad_waivers
    lines.append("")
    if ok:
        lines.append("TEST-CENSUS: PASS (%d files, %d tests collected, %d waived)"
                     % (total_files, total_tests, len(waived)))
    else:
        parts = []
        if unwaived:
            kinds = sorted({f.kind for f in unwaived})
            parts.append("%d finding(s) [%s]" % (len(unwaived), ", ".join(kinds)))
        if bad_waivers:
            parts.append("%d broken waiver(s)" % len(bad_waivers))
        lines.append("TEST-CENSUS: FAIL (%s)" % "; ".join(parts))
    return ok, lines


# --------------------------------------------------------------------------
# Selftest -- prove every detector, the gate.py --selftest pattern
# --------------------------------------------------------------------------

# The literal shape #89 shipped: parametrized bare functions, no TestCase.
_PYTEST_STYLE = '''
import pytest

@pytest.mark.parametrize("raw", ["Production", "PROD", "prod"])
def test_production_near_misses(raw):
    assert canon(raw) == "production"
'''

_UNITTEST_STYLE = '''
import unittest

class TestCanon(unittest.TestCase):
    def test_near_misses(self):
        self.assertEqual(canon("Prod"), "production")
'''

_INHERITED_STYLE = '''
import unittest

class Base(unittest.TestCase):
    def helper(self):
        pass

class TestReal(Base):
    def test_something(self):
        self.assertTrue(True)
'''

_EMPTY_BODY = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        """[SKIPPED] byte delivery -- see skip message."""
'''

_UNCONDITIONAL_SKIP = '''
import unittest

class TestThing(unittest.TestCase):
    @unittest.skip("flaky on Windows")
    def test_delivers(self):
        self.assertTrue(deliver())
'''

_CONDITIONAL_SKIP = '''
import unittest

class TestThing(unittest.TestCase):
    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_decides(self):
        self.assertTrue(decide())
'''

_LOAD_TESTS = '''
def load_tests(loader, tests, pattern):
    return tests
'''

# -- RFX-226 fixtures: the three module-level silencers, and the conditional
# forms that must stay invisible. Each "fires" fixture is the ONE line added to
# an otherwise healthy file, so the pair proves the detector and not the file.
_MODULE_SKIP_CALL = '''
import pytest

pytest.skip("being rewritten", allow_module_level=True)

def test_production_near_misses():
    assert canon("Prod") == "production"
'''

_MODULE_PYTESTMARK_SKIP = '''
import pytest

pytestmark = pytest.mark.skip("being rewritten")

def test_production_near_misses():
    assert canon("Prod") == "production"
'''

_MODULE_PYTESTMARK_SKIP_LIST = '''
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skip("being rewritten")]

def test_production_near_misses():
    assert canon("Prod") == "production"
'''

_MODULE_RAISE_SKIPTEST = '''
import unittest

raise unittest.SkipTest("being rewritten")

class TestCanon(unittest.TestCase):
    def test_near_misses(self):
        self.assertEqual(canon("Prod"), "production")
'''

# The honest form: a prerequisite the machine may not have. NOT a finding.
_MODULE_SKIP_CONDITIONAL = '''
import pytest

if not _opa_available():
    pytest.skip("OPA binary not installed", allow_module_level=True)

def test_production_near_misses():
    assert canon("Prod") == "production"
'''

_MODULE_PYTESTMARK_SKIPIF = '''
import pytest

pytestmark = pytest.mark.skipif(not _opa_available(), reason="OPA not installed")

def test_production_near_misses():
    assert canon("Prod") == "production"
'''

# Detector 5: the decorator's twin, spelled as a statement.
_IN_BODY_SKIP = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        self.skipTest("flaky here")
        self.assertTrue(deliver())
'''

_IN_BODY_RAISE_SKIPTEST = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        raise unittest.SkipTest("flaky here")
'''

_IN_BODY_SKIP_CONDITIONAL = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        if not self._tls_available:
            self.skipTest("openssl not available")
        self.assertTrue(deliver())
'''


def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # The selftest runs against synthetic trees, where the REAL waivers below
    # are by definition stale -- and a stale waiver is (correctly) a failure.
    # So the whole selftest runs with WAIVERS emptied, and the waiver detectors
    # in section 6 populate it themselves with the fixtures they need.
    _saved_waivers = dict(WAIVERS)
    WAIVERS.clear()
    try:
        return _selftest_body(checks, check)
    finally:
        WAIVERS.clear()
        WAIVERS.update(_saved_waivers)


def _selftest_body(checks, check):

    def findings(source, runner):
        return census_file("t/test_x.py", source, runner)

    def kinds(source, runner):
        return sorted(f.kind for f in findings(source, runner))

    # -- 1. the #89 defect itself, both directions -------------------------
    check("pytest-style file under unittest discover is ZERO-COLLECTION",
          kinds(_PYTEST_STYLE, "unittest") == ["zero-collection"])
    check("the diagnosis names the bare functions and the #89 class",
          "bare pytest-style" in findings(_PYTEST_STYLE, "unittest")[0].detail
          and "#89" in findings(_PYTEST_STYLE, "unittest")[0].detail)
    check("the SAME file under pytest collects fine (the gap is the runner)",
          findings(_PYTEST_STYLE, "pytest") == [])
    check("unittest-style file under unittest discover is clean",
          findings(_UNITTEST_STYLE, "unittest") == [])
    check("a TestCase subclass reached via a local base class still collects",
          findings(_INHERITED_STYLE, "unittest") == [])
    check("collection actually counts the inherited-base test",
          collect(_INHERITED_STYLE, "unittest")[0] == ["TestReal.test_something"])
    check("a load_tests hook is not reported as zero-collection",
          findings(_LOAD_TESTS, "unittest") == [])

    # -- 2. empty bodies ---------------------------------------------------
    check("a docstring-only test body is flagged", kinds(_EMPTY_BODY, "unittest") == ["empty-body"])
    check("a real body is not flagged as empty",
          "empty-body" not in kinds(_UNITTEST_STYLE, "unittest"))

    # -- 3. skips: unconditional flagged, conditional NOT ------------------
    check("an unconditional @unittest.skip is flagged",
          kinds(_UNCONDITIONAL_SKIP, "unittest") == ["unconditional-skip"])
    check("a CONDITIONAL skipUnless is NOT flagged (honest declined prerequisite)",
          findings(_CONDITIONAL_SKIP, "unittest") == [])

    # -- 3b. RFX-226: module-level silencers, both ways --------------------
    check("a module-level pytest.skip(allow_module_level=True) is flagged",
          kinds(_MODULE_SKIP_CALL, "pytest") == ["module-silenced"])
    check("...and its tests STOP being counted (the count is what runs)",
          collect(_MODULE_SKIP_CALL, "pytest")[0] == []
          and collect(_MODULE_SKIP_CALL.replace(
              'pytest.skip("being rewritten", allow_module_level=True)', ''), "pytest")[0]
          == ["test_production_near_misses"])
    check("...and the finding names how many tests it silenced",
          "1 test(s) in this file are silenced" in findings(_MODULE_SKIP_CALL, "pytest")[0].detail)
    check("a `pytestmark = pytest.mark.skip(...)` assignment is flagged",
          kinds(_MODULE_PYTESTMARK_SKIP, "pytest") == ["module-silenced"])
    check("...including when it is one marker in a LIST",
          kinds(_MODULE_PYTESTMARK_SKIP_LIST, "pytest") == ["module-silenced"])
    check("a module-level `raise unittest.SkipTest(...)` is flagged",
          kinds(_MODULE_RAISE_SKIPTEST, "unittest") == ["module-silenced"])
    check("...and the whole TestCase stops being counted (this is the 83-test shape)",
          collect(_MODULE_RAISE_SKIPTEST, "unittest")[0] == [])
    check("a silenced file is NOT also reported as zero-collection (cause, not symptom)",
          all(f.kind == "module-silenced" for f in findings(_MODULE_RAISE_SKIPTEST, "unittest")))
    check("a CONDITIONAL module skip (inside `if`) is NOT flagged",
          findings(_MODULE_SKIP_CONDITIONAL, "pytest") == [])
    check("...and its tests are still counted",
          collect(_MODULE_SKIP_CONDITIONAL, "pytest")[0] == ["test_production_near_misses"])
    check("a `pytestmark = pytest.mark.skipif(...)` is NOT flagged",
          findings(_MODULE_PYTESTMARK_SKIPIF, "pytest") == [])
    check("a healthy file is not flagged as silenced",
          "module-silenced" not in kinds(_UNITTEST_STYLE, "unittest"))

    # -- 3c. RFX-226: the in-body skip STATEMENT, the decorator's twin ------
    check("an unconditional self.skipTest(...) in a test body is flagged",
          kinds(_IN_BODY_SKIP, "unittest") == ["unconditional-skip"])
    check("...and says no decorator declares it",
          "no decorator says so" in findings(_IN_BODY_SKIP, "unittest")[0].detail)
    check("...and the test is STILL counted (the runner does collect it)",
          collect(_IN_BODY_SKIP, "unittest")[0] == ["TestThing.test_delivers"])
    check("an unconditional `raise unittest.SkipTest(...)` in a body is flagged",
          kinds(_IN_BODY_RAISE_SKIPTEST, "unittest") == ["unconditional-skip"])
    check("a skipTest nested inside an `if` is NOT flagged (the real test_telemetry shape)",
          findings(_IN_BODY_SKIP_CONDITIONAL, "unittest") == [])

    # -- 4. an empty enumerated root, and a missing one --------------------
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "empty_root"))
        ok, lines = census(tmp, roots=[("empty_root", "unittest")])
        check("an enumerated root with no test files FAILS", not ok)
        check("...and says so", any("no test_*.py file at all" in l for l in lines))
        ok, lines = census(tmp, roots=[("does_not_exist", "unittest")])
        check("an enumerated root that does not exist FAILS", not ok)

        # -- 5. a real end-to-end census over a written tree ---------------
        root = os.path.join(tmp, "suite")
        os.makedirs(root)
        with open(os.path.join(root, "test_good.py"), "w") as fh:
            fh.write(_UNITTEST_STYLE)
        ok, lines = census(tmp, roots=[("suite", "unittest")])
        check("a healthy root PASSES", ok)
        check("the anchored PASS line is emitted",
              any(l.startswith("TEST-CENSUS: PASS (") for l in lines))
        check("the per-root count is reported",
              any("suite (unittest) -> 1 file(s), 1 test(s)" in l for l in lines))

        # add the #89 shape next to it -> the whole census must go red
        with open(os.path.join(root, "test_env_canon.py"), "w") as fh:
            fh.write(_PYTEST_STYLE)
        ok, lines = census(tmp, roots=[("suite", "unittest")])
        check("one zero-collection file turns the census RED", not ok)
        check("the anchored FAIL line is emitted",
              any(l.startswith("TEST-CENSUS: FAIL (") for l in lines))
        check("FAIL names the offending file",
              any("test_env_canon.py" in l for l in lines))

    # -- 5b. RFX-226 end to end: the printed COUNT must move ---------------
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "suite")
        os.makedirs(root)
        with open(os.path.join(root, "test_good.py"), "w") as fh:
            fh.write(_UNITTEST_STYLE)          # 1 test
        with open(os.path.join(root, "test_hil.py"), "w") as fh:
            fh.write(_UNITTEST_STYLE)          # 1 more -> 2 collected
        ok, lines = census(tmp, roots=[("suite", "unittest")])
        check("two healthy files census as 2 tests", ok and
              any("suite (unittest) -> 2 file(s), 2 test(s)" in l for l in lines))

        # ONE line added to one of them -- the RFX-226 sabotage, in miniature.
        with open(os.path.join(root, "test_hil.py"), "w") as fh:
            fh.write(_MODULE_RAISE_SKIPTEST)
        ok, lines = census(tmp, roots=[("suite", "unittest")])
        check("one silencing line turns the census RED", not ok)
        check("...and the printed count DROPS to what the runner would run",
              any("suite (unittest) -> 2 file(s), 1 test(s)" in l for l in lines))
        check("...and the per-root line says a file was silenced",
              any("SILENCED at module level" in l for l in lines))
        check("...and the FAIL line names the kind",
              any(l.startswith("TEST-CENSUS: FAIL (") and "module-silenced" in l for l in lines))
        check("...and the finding names the file",
              any("test_hil.py" in l for l in lines))

    # -- 6. waivers: enforced both ways ------------------------------------
    if True:
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "suite")
            os.makedirs(root)
            with open(os.path.join(root, "test_x.py"), "w") as fh:
                fh.write(_UNCONDITIONAL_SKIP)
            ok, _ = census(tmp, roots=[("suite", "unittest")])
            check("an unwaived unconditional skip fails the census", not ok)

            WAIVERS[("suite/test_x.py", "TestThing.test_delivers")] = "documented race (RFX-109)"
            ok, lines = census(tmp, roots=[("suite", "unittest")])
            check("a ticketed waiver passes the census", ok)
            check("...and the waiver is PRINTED anyway",
                  any("WAIVED" in l for l in lines) and any("RFX-109" in l for l in lines))
            check("...and counted on the anchored line",
                  any("1 waived" in l for l in lines))

            WAIVERS.clear()
            WAIVERS[("suite/test_x.py", "TestThing.test_delivers")] = "no ticket here"
            ok, lines = census(tmp, roots=[("suite", "unittest")])
            check("a waiver with no ticket reference FAILS", not ok)
            check("...and says why", any("no ticket reference" in l for l in lines))

            WAIVERS.clear()
            WAIVERS[("suite/test_gone.py", "TestGone.test_gone")] = "stale (RFX-109)"
            ok, lines = census(tmp, roots=[("suite", "unittest")])
            check("a STALE waiver (target no longer flagged) FAILS", not ok)
            check("...and says why", any("no longer flagged" in l for l in lines))
            WAIVERS.clear()

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  selftest %s: %s" % ("PASS" if ok else "FAIL", n))
    if failed:
        print("SELFTEST: FAIL (%d/%d checks failed)" % (len(failed), len(checks)))
        return 1
    print("SELFTEST: PASS (%d checks)" % len(checks))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="check_test_census.py",
                                description="static census of what the test suites actually run")
    p.add_argument("repo_root", nargs="?", default=None,
                   help="repo root to census (default: the parent of this script's directory)")
    p.add_argument("--selftest", action="store_true",
                   help="prove every detector on synthetic fixtures and exit")
    args = p.parse_args(sys.argv[1:] if argv is None else argv)
    if args.selftest:
        return selftest()
    repo_root = args.repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok, lines = census(repo_root)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
