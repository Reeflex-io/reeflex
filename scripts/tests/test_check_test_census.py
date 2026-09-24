"""Unit tests for scripts/check_test_census.py's silent-skip detectors (RFX-226).

WHY THIS FILE EXISTS, GIVEN THE SCRIPT ALREADY HAS `--selftest`. The census is
the component that turns "a test did not run" from an inference into a printed
line, and until this ticket it could not see the cheapest way to stop a test
running: ONE module-level statement. `collect()` walked `tree.body` looking only
at FunctionDef/AsyncFunctionDef/ClassDef, so `pytest.skip(...,
allow_module_level=True)` (an `ast.Expr`), `pytestmark = pytest.mark.skip(...)`
(an `ast.Assign`) and `raise unittest.SkipTest(...)` (an `ast.Raise`) each
deleted a whole file's tests while the census printed the unchanged number and
PASS.

`--selftest` is the script self-attesting; gate.py runs it as its own step. This
root is run by `unittest discover -s scripts/tests -t scripts`, i.e. the same
runner the suites themselves are measured with, so the detectors EXECUTE in the
suite too — a detector whose only proof is the tool's own opinion of itself is
the shape RFX-87 was filed about.

THE PROPERTY THAT MATTERS, and it is not "the detector fires": it is that the
printed COUNT moves. A census that flags a file and still counts its tests as
collected leaves the number an auditor reads exactly as wrong as before.

Written as unittest TestCases because bare pytest-style functions here would
collect zero tests and pass forever (RFX-87).
"""

import contextlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_test_census as ctc  # noqa: E402


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORE_TESTS = os.path.join(REPO_ROOT, "reeflex-core", "tests")

HEALTHY_UNITTEST = '''
import unittest

class TestCanon(unittest.TestCase):
    def test_near_misses(self):
        self.assertEqual(canon("Prod"), "production")
'''

HEALTHY_PYTEST = '''
def test_near_misses():
    assert canon("Prod") == "production"
'''


def kinds(source, runner, path="t/test_x.py"):
    return sorted(f.kind for f in ctc.census_file(path, source, runner))


def counted(source, runner):
    return ctc.collect(source, runner)[0]


@contextlib.contextmanager
def no_waivers():
    """The REAL waivers name files in reeflex-core; against a synthetic tree
    every one of them is stale, and a stale waiver is (correctly) a FAILURE. So
    a census over a temp directory runs with WAIVERS emptied -- the same thing
    the script's own `selftest()` does, for the same reason."""
    saved = dict(ctc.WAIVERS)
    ctc.WAIVERS.clear()
    try:
        yield
    finally:
        ctc.WAIVERS.clear()
        ctc.WAIVERS.update(saved)


class TestModuleLevelSilencers(unittest.TestCase):
    """The three node types the collector never looked at."""

    def test_pytest_skip_allow_module_level_is_flagged_and_uncounted(self):
        src = 'import pytest\npytest.skip("x", allow_module_level=True)\n' + HEALTHY_PYTEST
        self.assertEqual(kinds(src, "pytest"), ["module-silenced"])
        self.assertEqual(counted(src, "pytest"), [])
        # ...and without the one line, the same file is healthy and counted.
        self.assertEqual(kinds(HEALTHY_PYTEST, "pytest"), [])
        self.assertEqual(counted(HEALTHY_PYTEST, "pytest"), ["test_near_misses"])

    def test_bare_module_level_pytest_skip_is_flagged_too(self):
        # Without allow_module_level pytest errors instead of skipping, which is
        # loud -- but it still yields no tests, so it is the same finding.
        src = 'import pytest\npytest.skip("x")\n' + HEALTHY_PYTEST
        self.assertEqual(kinds(src, "pytest"), ["module-silenced"])

    def test_pytestmark_skip_assignment_is_flagged(self):
        src = 'import pytest\npytestmark = pytest.mark.skip("x")\n' + HEALTHY_PYTEST
        self.assertEqual(kinds(src, "pytest"), ["module-silenced"])
        self.assertEqual(counted(src, "pytest"), [])

    def test_pytestmark_skip_inside_a_list_is_flagged(self):
        src = ('import pytest\npytestmark = [pytest.mark.slow, pytest.mark.skip("x")]\n'
               + HEALTHY_PYTEST)
        self.assertEqual(kinds(src, "pytest"), ["module-silenced"])

    def test_pytestmark_without_a_call_is_flagged(self):
        src = 'import pytest\npytestmark = pytest.mark.skip\n' + HEALTHY_PYTEST
        self.assertEqual(kinds(src, "pytest"), ["module-silenced"])

    def test_module_level_raise_skiptest_is_flagged(self):
        src = 'import unittest\nraise unittest.SkipTest("x")\n' + HEALTHY_UNITTEST
        self.assertEqual(kinds(src, "unittest"), ["module-silenced"])
        self.assertEqual(counted(src, "unittest"), [])

    def test_bare_name_raise_skiptest_is_flagged(self):
        src = 'from unittest import SkipTest\nraise SkipTest("x")\n' + HEALTHY_UNITTEST
        self.assertEqual(kinds(src, "unittest"), ["module-silenced"])

    def test_the_finding_says_how_many_tests_it_silenced(self):
        src = 'import unittest\nraise unittest.SkipTest("x")\n' + HEALTHY_UNITTEST
        detail = ctc.census_file("t/test_x.py", src, "unittest")[0].detail
        self.assertIn("1 test(s) in this file are silenced", detail)

    def test_a_silenced_file_is_not_also_called_zero_collection(self):
        # Cause, not symptom: "yields 0 tests -- it runs NOWHERE" would send a
        # reader looking for a runner mismatch that is not there.
        src = 'import unittest\nraise unittest.SkipTest("x")\n' + HEALTHY_UNITTEST
        self.assertEqual(kinds(src, "unittest"), ["module-silenced"])


class TestConditionalFormsAreNotFlagged(unittest.TestCase):
    """The honest way to decline a missing prerequisite must stay invisible --
    and this is also the detector's stated limit: `if True:` evades it."""

    def test_module_skip_nested_in_an_if_is_not_flagged(self):
        src = ('import pytest\nif not _opa():\n    pytest.skip("no OPA", allow_module_level=True)\n'
               + HEALTHY_PYTEST)
        self.assertEqual(ctc.census_file("t/test_x.py", src, "pytest"), [])
        self.assertEqual(counted(src, "pytest"), ["test_near_misses"])

    def test_pytestmark_skipif_is_not_flagged(self):
        src = ('import pytest\npytestmark = pytest.mark.skipif(not _opa(), reason="no OPA")\n'
               + HEALTHY_PYTEST)
        self.assertEqual(ctc.census_file("t/test_x.py", src, "pytest"), [])
        self.assertEqual(counted(src, "pytest"), ["test_near_misses"])

    def test_a_raise_that_is_not_a_skip_is_not_flagged(self):
        src = 'raise RuntimeError("boom")\n' + HEALTHY_PYTEST
        self.assertEqual(ctc.census_file("t/test_x.py", src, "pytest"), [])

    def test_a_healthy_file_is_clean_under_both_runners(self):
        self.assertEqual(ctc.census_file("t/test_x.py", HEALTHY_UNITTEST, "unittest"), [])
        self.assertEqual(ctc.census_file("t/test_x.py", HEALTHY_PYTEST, "pytest"), [])


class TestInBodySkipStatements(unittest.TestCase):
    """Detector 3 reads `decorator_list`; the same silence spelled as a
    statement was invisible to it, and `_body_is_empty` sees a full body."""

    def test_unconditional_self_skiptest_is_flagged(self):
        src = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        self.skipTest("later")
        self.assertTrue(deliver())
'''
        self.assertEqual(kinds(src, "unittest"), ["unconditional-skip"])
        # Still counted: the runner DOES collect it and reports it as skipped.
        self.assertEqual(counted(src, "unittest"), ["TestThing.test_delivers"])

    def test_unconditional_raise_skiptest_in_a_body_is_flagged(self):
        src = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        raise unittest.SkipTest("later")
'''
        self.assertEqual(kinds(src, "unittest"), ["unconditional-skip"])

    def test_unconditional_pytest_skip_in_a_bare_function_is_flagged(self):
        src = 'import pytest\n\ndef test_delivers():\n    pytest.skip("later")\n'
        self.assertEqual(kinds(src, "pytest"), ["unconditional-skip"])

    def test_a_skiptest_nested_in_an_if_is_not_flagged(self):
        # The real shape in reeflex-core/tests/test_telemetry.py.
        src = '''
import unittest

class TestThing(unittest.TestCase):
    def test_delivers(self):
        if not self._tls_available:
            self.skipTest("openssl not available")
        self.assertTrue(deliver())
'''
        self.assertEqual(ctc.census_file("t/test_x.py", src, "unittest"), [])


class TestTheCountItself(unittest.TestCase):
    """The census's whole product is a NUMBER. These are about the number."""

    def test_one_silencing_line_moves_the_printed_total(self):
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "suite")
            os.makedirs(root)
            for name in ("test_a.py", "test_b.py"):
                with open(os.path.join(root, name), "w") as fh:
                    fh.write(HEALTHY_UNITTEST)
            ok, lines = ctc.census(tmp, roots=[("suite", "unittest")])
            self.assertTrue(ok, "\n".join(lines))
            self.assertTrue(any("suite (unittest) -> 2 file(s), 2 test(s)" in l for l in lines),
                            "\n".join(lines))

            with open(os.path.join(root, "test_b.py"), "w") as fh:
                fh.write('import unittest\nraise unittest.SkipTest("x")\n' + HEALTHY_UNITTEST)
            ok, lines = ctc.census(tmp, roots=[("suite", "unittest")])
            self.assertFalse(ok, "one silencing line must turn the census RED")
            self.assertTrue(any("suite (unittest) -> 2 file(s), 1 test(s)" in l for l in lines),
                            "\n".join(lines))
            self.assertTrue(any("SILENCED at module level" in l for l in lines), "\n".join(lines))
            self.assertTrue(any(l.startswith("TEST-CENSUS: FAIL (") and "module-silenced" in l
                                for l in lines), "\n".join(lines))

    def test_the_real_core_suite_is_clean_today(self):
        # A detector nobody has seen refuse anything is worth nothing; a
        # detector that refuses the tree it ships with is worth less. Both
        # halves are load-bearing, so both are asserted.
        ok, lines = ctc.census(REPO_ROOT)
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any(l.startswith("TEST-CENSUS: PASS (") for l in lines))

    def test_the_rfx226_sabotage_on_a_real_core_file_is_caught(self):
        # The ticket's own arm, against a file that really exists: inject the
        # one line into the LARGEST file of the core suite and watch its tests
        # leave the count. Nothing here is synthetic except the added line.
        biggest, biggest_n, source = None, 0, ""
        for name in sorted(os.listdir(CORE_TESTS)):
            if not (name.startswith("test_") and name.endswith(".py")):
                continue
            with open(os.path.join(CORE_TESTS, name), encoding="utf-8") as fh:
                src = fh.read()
            n = len(ctc.collect(src, "unittest")[0])
            if n > biggest_n:
                biggest, biggest_n, source = name, n, src
        self.assertIsNotNone(biggest, "reeflex-core/tests has no test file")
        self.assertGreaterEqual(biggest_n, 20, "expected a real victim, got %d tests" % biggest_n)

        sabotaged = 'import unittest\nraise unittest.SkipTest("RFX-226")\n' + source
        findings = ctc.census_file("reeflex-core/tests/" + biggest, sabotaged, "unittest")
        self.assertEqual([f.kind for f in findings], ["module-silenced"])
        self.assertEqual(ctc.collect(sabotaged, "unittest")[0], [])
        self.assertIn("%d test(s) in this file are silenced" % biggest_n, findings[0].detail)


class TestReachAndEnumeration(unittest.TestCase):
    """RFX-87 round 2 (dev-2--147): the two axes on which this census used to
    be NARROWER than gate.py's `drift`, which walks recursively and matches
    `*_test.py` as well.

    Measured on python3.11 before any of this was written, because the whole
    finding is about what the runners really do rather than what they document:

        tests/pkgsub/test_healthy_guard.py   (__init__.py present) -> Ran 1 test
        tests/plainsub/test_healthy_guard.py (no __init__.py)      -> Ran 0 tests, OK
        tests/env_canon_test.py  under discover's default test*.py -> not collected
        all three, under pytest                                    -> collected

    So a file could be enumerated, walked by `drift`, certified as covered, and
    still run nowhere — and #89's defect fits in that gap exactly."""

    def _suite(self, tmp, files, runner):
        root = os.path.join(tmp, "suite")
        os.makedirs(root, exist_ok=True)
        for rel, body in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(body)
        return ctc.census(tmp, roots=[("suite", runner)])

    def test_the_89_defect_one_directory_down_is_caught(self):
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, {
                "test_good.py": HEALTHY_UNITTEST,
                os.path.join("subsuite", "__init__.py"): "",
                os.path.join("subsuite", "test_env_canon.py"): HEALTHY_PYTEST,
            }, "unittest")
            self.assertFalse(ok, "an inert guard in a package subdirectory must be RED:\n"
                                 + "\n".join(lines))
            self.assertTrue(
                any("zero-collection" in l and os.path.join("subsuite", "test_env_canon.py") in l
                    for l in lines),
                "the finding must name the NESTED path:\n" + "\n".join(lines))

    def test_a_healthy_nested_file_is_counted_not_flagged(self):
        # The other half of the same detector: depth alone is not a defect.
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, {
                "test_good.py": HEALTHY_UNITTEST,
                os.path.join("subsuite", "__init__.py"): "",
                os.path.join("subsuite", "test_good_nested.py"): HEALTHY_UNITTEST,
            }, "unittest")
            self.assertTrue(ok, "\n".join(lines))
            self.assertTrue(
                any("suite (unittest) -> 2 file(s) (1 below the root), 2 test(s)" in l
                    for l in lines),
                "both files must be counted:\n" + "\n".join(lines))

    def test_a_non_package_subdirectory_is_runs_nowhere_under_unittest_only(self):
        files = {
            "test_good.py": HEALTHY_UNITTEST,
            os.path.join("plainsub", "test_good_nested.py"): HEALTHY_UNITTEST,
        }
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "unittest")
            self.assertFalse(ok, "\n".join(lines))
            self.assertTrue(any("runs-nowhere" in l and "test_good_nested.py" in l for l in lines),
                            "\n".join(lines))
            self.assertTrue(any("not an importable package" in l for l in lines),
                            "the reason must name the cause, not print '0 tests':\n"
                            + "\n".join(lines))
            self.assertTrue(any("suite (unittest) -> 2 file(s) (1 below the root), 1 test(s)" in l
                                for l in lines),
                            "a file that runs nowhere must not be counted:\n" + "\n".join(lines))
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "pytest")
            self.assertTrue(ok, "pytest DOES recurse into a plain directory, so the same "
                                "tree must be clean under it:\n" + "\n".join(lines))

    def test_a_star_test_py_file_is_runs_nowhere_under_unittest_only(self):
        files = {
            "test_good.py": HEALTHY_UNITTEST,
            "env_canon_test.py": HEALTHY_UNITTEST,
        }
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "unittest")
            self.assertFalse(ok, "\n".join(lines))
            self.assertTrue(any("runs-nowhere" in l and "env_canon_test.py" in l for l in lines),
                            "\n".join(lines))
            self.assertTrue(any("test*.py" in l and "never imports it" in l for l in lines),
                            "the reason must name discover's default pattern:\n" + "\n".join(lines))
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "pytest")
            self.assertTrue(ok, "\n".join(lines))
            self.assertTrue(any("suite (pytest) -> 2 file(s), 2 test(s)" in l for l in lines),
                            "under pytest the file is a real test file and must be counted:\n"
                            + "\n".join(lines))

    def test_a_test_star_py_name_pytest_never_collects_is_runs_nowhere(self):
        """RFX-87 round 3 (dev-3--190). The enumeration is the UNION of both
        runners' patterns, which is what keeps this census from being narrower
        than `drift` -- but the union is wider than either runner alone.

        `testhelper.py` matches `unittest discover`'s default `test*.py` and
        NEITHER of pytest's default `python_files` globs. Measured on pytest
        9.1.1 over exactly these two files: `--collect-only` reported
        `1 test collected`, while this census reported `2 file(s), 2 test(s)` --
        it counted a test the runner that owns the root never runs.

        The pair of roots below is the whole point: identical bytes, opposite
        verdicts, because the question is what the RUNNER reaches."""
        files = {
            "test_good.py": HEALTHY_UNITTEST,
            "testhelper.py": HEALTHY_UNITTEST,
        }
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "pytest")
            self.assertFalse(ok, "a name pytest never collects must be RED under a "
                                 "pytest root:\n" + "\n".join(lines))
            self.assertTrue(any("runs-nowhere" in l and "testhelper.py" in l for l in lines),
                            "\n".join(lines))
            self.assertTrue(
                any("pytest collects" in l and "matches none of them" in l for l in lines),
                "the reason must name PYTEST's globs, not discover's:\n" + "\n".join(lines))
            self.assertTrue(
                any("suite (pytest) -> 2 file(s), 1 test(s)" in l for l in lines),
                "the uncollectable file must NOT be counted -- the total is the "
                "runner's own:\n" + "\n".join(lines))
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, files, "unittest")
            self.assertTrue(ok, "the SAME bytes under a unittest root are reachable -- "
                                "discover's default pattern is `test*.py`:\n" + "\n".join(lines))
            self.assertTrue(any("suite (unittest) -> 2 file(s), 2 test(s)" in l for l in lines),
                            "\n".join(lines))

    def test_the_detectors_apply_inside_a_star_test_py_file_too(self):
        # Enumerating the file is only half of it: it has to be READ.
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, {
                "test_good.py": HEALTHY_UNITTEST,
                "env_canon_test.py": 'import pytest\n\npytestmark = pytest.mark.skip("x")\n\n'
                                     'def test_a():\n    assert True\n',
            }, "pytest")
            self.assertFalse(ok, "\n".join(lines))
            self.assertTrue(any("module-silenced" in l and "env_canon_test.py" in l
                                for l in lines), "\n".join(lines))

    def test_caches_and_vendored_trees_are_not_walked(self):
        with no_waivers(), tempfile.TemporaryDirectory() as tmp:
            ok, lines = self._suite(tmp, {
                "test_good.py": HEALTHY_UNITTEST,
                os.path.join("__pycache__", "test_stale.py"): HEALTHY_PYTEST,
                os.path.join("node_modules", "test_vendored.py"): HEALTHY_PYTEST,
            }, "unittest")
            self.assertTrue(ok, "a cached or vendored copy is not a suite:\n" + "\n".join(lines))
            self.assertTrue(any("suite (unittest) -> 1 file(s), 1 test(s)" in l for l in lines),
                            "\n".join(lines))

    def test_the_real_tree_has_no_file_outside_the_enumeration(self):
        # The census and `drift` must agree about WHICH files exist, or the
        # gap between them is where the next inert guard sits. This compares
        # the two enumerations on the tree as it actually is.
        import fnmatch
        for rel_root, runner in ctc.CENSUS_ROOTS:
            if runner is None:
                continue
            abs_root = os.path.join(REPO_ROOT, rel_root)
            if not os.path.isdir(abs_root):
                continue
            censused = set(ctc.enumerate_test_files(abs_root))
            walked = set()
            for dirpath, dirnames, filenames in os.walk(abs_root):
                dirnames[:] = [d for d in dirnames if d not in ctc.CENSUS_EXCLUDE_DIRS]
                for f in filenames:
                    if any(fnmatch.fnmatch(f, p) for p in ("test_*.py", "*_test.py")):
                        walked.add(os.path.relpath(os.path.join(dirpath, f), abs_root))
            self.assertEqual(walked - censused, set(),
                             "%s: drift walks these and the census does not open them" % rel_root)


class TestTheSelftestStillProvesItself(unittest.TestCase):
    def test_script_selftest_passes(self):
        self.assertEqual(ctc.selftest(), 0)


if __name__ == "__main__":
    unittest.main()
