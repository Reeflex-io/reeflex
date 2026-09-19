"""Unit tests for scripts/check_suite_coverage.py (RFX-355).

WHY THIS FILE EXISTS, GIVEN THE SCRIPT ALREADY HAS `--selftest`. Same reason as
test_check_test_census.py: a detector whose only proof is the tool's own opinion
of itself is the shape RFX-87 was filed about. This root is run by
`unittest discover -s scripts/tests -t scripts`, so these detectors EXECUTE
inside the suite, under a runner that is not the script's own.

AND ONE MORE REASON, SPECIFIC TO THIS CHECK. The thing it certifies — "every
check artefact in this tree is invoked by something" — is exactly the thing that
was false about `drift` for months: a guard can report a reassuring word about a
plane it never looked at. The cases below are therefore written as
BLIND-vs-CAUGHT pairs wherever a pair exists: the same file, in two locations,
or the same name, in prose and in a statement. A single-armed assertion here
would go green for a checker that had stopped reading .py files altogether.

Written as unittest TestCases because bare pytest-style functions here would
collect zero tests and pass forever (RFX-87).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_suite_coverage as csc  # noqa: E402


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

GATE_STUB = '''
class Gate:
    WP_HARNESSES = ["h-one.php"]
    WP_SPEC_HARNESSES = [("h-spec.php", "SPEC x")]
'''

INVOKES = '\nRUN = ["python", "scripts/wired-check.py"]\n'


class FixtureTree:
    """A synthetic repo. Declarations are passed in, never inherited from the
    real tables, so a test can never be satisfied by this tree's own residual.
    """

    def __init__(self, tmp, wp_files=(), scripts=(), gate_body=GATE_STUB,
                 workflow="", nested_workflow=None):
        self.root = tempfile.mkdtemp(dir=tmp)
        os.makedirs(os.path.join(self.root, csc.WP_TESTS_DIR))
        os.makedirs(os.path.join(self.root, "scripts"))
        os.makedirs(os.path.join(self.root, ".github", "workflows"))
        self._write("gate.py", gate_body)
        self._write(os.path.join(".github", "workflows", "ci.yml"), workflow)
        if nested_workflow is not None:
            os.makedirs(os.path.join(self.root, "pkg", ".github", "workflows"))
            self._write(os.path.join("pkg", ".github", "workflows", "ci.yml"),
                        nested_workflow)
        for name in wp_files:
            self._write(os.path.join(csc.WP_TESTS_DIR, name), "<?php\n")
        for name in scripts:
            self._write(os.path.join("scripts", name), "#\n")

    def _write(self, rel, text):
        with open(os.path.join(self.root, rel), "w") as f:
            f.write(text)


class SuiteCoverageTestCase(unittest.TestCase):
    """Base: a temp dir per test, and the module's declaration tables swapped
    for the test's own. The real tables are restored in tearDown — a test that
    leaked them would make every later test measure the wrong tree."""

    WP_FILES = ("h-one.php", "h-spec.php", "wp-stubs.php")
    SCRIPTS = ("wired-check.py", "hand-run-probe.py")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="suite-coverage-tests-")
        self._saved = (dict(csc.WIRED), dict(csc.UNWIRED),
                       dict(csc.WP_SUPPORT), dict(csc.NOT_A_CHECK))
        for table in (csc.WIRED, csc.UNWIRED, csc.WP_SUPPORT, csc.NOT_A_CHECK):
            table.clear()
        csc.WIRED["wired-check.py"] = "gate.py"
        csc.UNWIRED["hand-run-probe.py"] = "run by hand"
        csc.WP_SUPPORT["wp-stubs.php"] = "shared stubs"

    def tearDown(self):
        for table, original in zip((csc.WIRED, csc.UNWIRED, csc.WP_SUPPORT,
                                    csc.NOT_A_CHECK), self._saved):
            table.clear()
            table.update(original)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tree(self, **kw):
        kw.setdefault("wp_files", self.WP_FILES)
        kw.setdefault("scripts", self.SCRIPTS)
        kw.setdefault("gate_body", GATE_STUB + INVOKES)
        return FixtureTree(self.tmp, **kw)

    def failures(self, tree):
        found, _notes, _counts = csc.check(tree.root)
        return found


class TestCleanControl(SuiteCoverageTestCase):

    def test_a_fully_dispositioned_tree_passes(self):
        """The control. Without it every red below is unreadable: a checker
        that failed on everything would satisfy all of them."""
        self.assertEqual(self.failures(self.tree()), [])


class TestTheWordPressPlane(SuiteCoverageTestCase):
    """The RFX-355 shape: a file INSIDE a suite root that nothing invokes,
    because that root is run from a hardcoded literal rather than by
    directory discovery."""

    def test_a_harness_in_the_root_but_in_no_component_list_fails(self):
        tree = self.tree(wp_files=self.WP_FILES + ("conformance-stray.php",))
        found = self.failures(tree)
        self.assertTrue(any("in NO component's harness list" in f for f in found),
                        found)

    def test_a_literal_naming_a_harness_that_is_gone_fails(self):
        """The other direction. A component that names a missing harness is a
        component that stopped running it, and it is silent about that."""
        tree = self.tree(wp_files=("h-spec.php", "wp-stubs.php"))
        found = self.failures(tree)
        self.assertTrue(any("a stale entry" in f for f in found), found)

    def test_the_literals_are_read_from_gate_py_not_transcribed(self):
        """RFX-303's lesson. If the import stops working this check must say so
        and FAIL, never certify a plane it did not read."""
        tree = self.tree(gate_body="this is not python (\n")
        found = self.failures(tree)
        self.assertTrue(any("refuses to certify" in f for f in found), found)

    def test_a_harness_added_to_the_literal_is_then_accepted(self):
        """The fix path a developer takes must actually clear the red — a
        detector nobody can satisfy gets silenced instead of satisfied."""
        gate = GATE_STUB.replace('["h-one.php"]',
                                 '["h-one.php", "conformance-new.php"]')
        tree = self.tree(wp_files=self.WP_FILES + ("conformance-new.php",),
                         gate_body=gate + INVOKES)
        self.assertEqual(self.failures(tree), [])


class TestTheScriptsPlane(SuiteCoverageTestCase):

    def test_a_script_dispositioned_by_nothing_fails(self):
        tree = self.tree(scripts=self.SCRIPTS + ("new-probe.py",))
        found = self.failures(tree)
        self.assertTrue(any("dispositioned by nothing" in f for f in found),
                        found)

    def test_a_declared_unwired_script_that_something_now_invokes_fails(self):
        """A residual that cannot go stale can silence a real red forever
        (RFX-339/RFX-348)."""
        tree = self.tree(workflow="run: python scripts/hand-run-probe.py\n")
        found = self.failures(tree)
        self.assertTrue(any("declaration is stale" in f for f in found), found)

    def test_a_declaration_for_a_file_that_no_longer_exists_fails(self):
        csc.UNWIRED["deleted-probe.py"] = "was run by hand"
        found = self.failures(self.tree())
        self.assertTrue(any("is STALE" in f for f in found), found)


class TestWhatCountsAsBeingNamed(SuiteCoverageTestCase):
    """Prose is not an invocation. Each case is paired with the same name in an
    executed position, so the pair fails if the reader stops reading at all."""

    def test_named_only_in_a_comment_is_not_named(self):
        tree = self.tree(gate_body=GATE_STUB + "\n# wired-check.py\n")
        found = self.failures(tree)
        self.assertTrue(any("does not name it" in f for f in found), found)

    def test_named_only_in_a_docstring_is_not_named(self):
        """The arm that caught this: renaming gate.py's real invocation of
        check_test_census.py left the module docstring behind, and a
        whole-text reading called the tree clean."""
        tree = self.tree(gate_body='"""Runs scripts/wired-check.py."""\n'
                                   + GATE_STUB)
        found = self.failures(tree)
        self.assertTrue(any("does not name it" in f for f in found), found)

    def test_named_in_an_executed_literal_is_named(self):
        tree = self.tree(gate_body='"""Runs nothing in particular."""\n'
                                   + GATE_STUB + INVOKES)
        self.assertEqual(self.failures(tree), [])

    def test_code_text_py_keeps_executed_literals_and_drops_prose(self):
        """The unit underneath the two cases above, asserted directly: the
        same basename, twice, one of which runs."""
        text = csc.code_text_py('"""doc mentions alpha.py"""\n'
                                '# comment mentions beta.py\n'
                                'RUN = "gamma.py"\n')
        self.assertIn("gamma.py", text)
        self.assertNotIn("alpha.py", text)
        self.assertNotIn("beta.py", text)

    def test_an_unparseable_invoker_falls_back_rather_than_naming_nothing(self):
        """Fail-safe direction chosen deliberately: a file that cannot be
        parsed must not silently become a file that invokes nothing, which
        would turn every declaration wired into it red at once."""
        text = csc.code_text_py('def broken(:\n    RUN = "gamma.py"\n')
        self.assertIn("gamma.py", text)


class TestWorkflowRegistrability(SuiteCoverageTestCase):
    """Only a direct child of the repo-root .github/workflows/ is registered by
    GitHub. This tree has two nested ones that never fire."""

    def test_wired_into_a_nested_workflow_file_fails(self):
        csc.WIRED["nested-wired.py"] = "pkg/.github/workflows/ci.yml"
        tree = self.tree(scripts=self.SCRIPTS + ("nested-wired.py",),
                         nested_workflow="run: python scripts/nested-wired.py\n")
        found = self.failures(tree)
        self.assertTrue(any("not a workflow GitHub registers" in f
                            for f in found), found)

    def test_the_same_file_in_the_registrable_location_passes(self):
        csc.WIRED["root-wired.py"] = ".github/workflows/ci.yml"
        tree = self.tree(scripts=self.SCRIPTS + ("root-wired.py",),
                         workflow="run: python scripts/root-wired.py\n")
        self.assertEqual(self.failures(tree), [])

    def test_registrable_truth_table(self):
        self.assertTrue(csc.registrable(".github/workflows/gate.yml"))
        self.assertTrue(csc.registrable(".github/workflows/gate.yaml"))
        self.assertFalse(csc.registrable("pkg/.github/workflows/ci.yml"))
        self.assertFalse(csc.registrable(".github/workflows/archive/old.yml"))
        self.assertFalse(csc.registrable(".github/workflows/README.md"))


class TestTheRealTree(SuiteCoverageTestCase):
    """The declarations this repo actually ships, against this repo's own
    directories — the tables under test here are the REAL ones, so setUp's
    swap is undone first."""

    def setUp(self):
        super().setUp()
        for table, original in zip((csc.WIRED, csc.UNWIRED, csc.WP_SUPPORT,
                                    csc.NOT_A_CHECK), self._saved):
            table.clear()
            table.update(original)

    def test_this_repo_is_fully_dispositioned(self):
        found, _notes, _counts = csc.check(REPO_ROOT)
        self.assertEqual(found, [], "\n".join(found))

    def test_every_declaration_carries_a_reason_a_human_can_read(self):
        """A one-word residual entry is a checkbox. The reason is the whole
        value of declaring something unwired."""
        for table_name in ("UNWIRED", "NOT_A_CHECK", "WP_SUPPORT"):
            for name, reason in getattr(csc, table_name).items():
                self.assertGreater(len(reason), 30,
                                   "%s[%s] has no real reason" % (table_name, name))

    def test_the_selftest_passes_under_a_foreign_runner(self):
        """The script's own --selftest, run as a subprocess: the detectors have
        to hold when nothing of this test module is in the interpreter."""
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "scripts",
                                          "check_suite_coverage.py"), "--selftest"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("SELFTEST: PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
