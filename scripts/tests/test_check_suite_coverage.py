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

import json
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

# The CLEAN npm runner: it executes the one file the default fixture puts in
# the npm suite root. Every pre-existing test below therefore keeps measuring
# what it was written to measure, and not this plane.
N8N_CLEAN_RUNNER = "tsc -p tsconfig.test.json && node dist-test/test/a.test.js"


class FixtureTree:
    """A synthetic repo. Declarations are passed in, never inherited from the
    real tables, so a test can never be satisfied by this tree's own residual.
    """

    def __init__(self, tmp, wp_files=(), scripts=(), gate_body=GATE_STUB,
                 workflow="", nested_workflow=None,
                 n8n_files=("a.test.ts",), n8n_runner=N8N_CLEAN_RUNNER,
                 n8n_package=True):
        self.root = tempfile.mkdtemp(dir=tmp)
        os.makedirs(os.path.join(self.root, csc.WP_TESTS_DIR))
        os.makedirs(os.path.join(self.root, "scripts"))
        os.makedirs(os.path.join(self.root, ".github", "workflows"))
        os.makedirs(os.path.join(self.root, csc.N8N_TESTS_DIR))
        if n8n_package:
            self._write(os.path.join(csc.N8N_DIR, "package.json"),
                        json.dumps({"name": "fixture",
                                    "scripts": {"test": n8n_runner}}))
        for name in n8n_files:
            self._write(os.path.join(csc.N8N_TESTS_DIR, name), "// fixture\n")
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
                       dict(csc.WP_SUPPORT), dict(csc.NOT_A_CHECK),
                       dict(csc.N8N_SUPPORT))
        for table in (csc.WIRED, csc.UNWIRED, csc.WP_SUPPORT, csc.NOT_A_CHECK,
                      csc.N8N_SUPPORT):
            table.clear()
        csc.WIRED["wired-check.py"] = "gate.py"
        csc.UNWIRED["hand-run-probe.py"] = "run by hand"
        csc.WP_SUPPORT["wp-stubs.php"] = "shared stubs"

    def tearDown(self):
        for table, original in zip((csc.WIRED, csc.UNWIRED, csc.WP_SUPPORT,
                                    csc.NOT_A_CHECK, csc.N8N_SUPPORT),
                                   self._saved):
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


class TestTheNpmPlane(SuiteCoverageTestCase):
    """The SECOND root whose runner names its files one at a time. Found on
    2026-09-23, two days after check_suite_coverage.py merged, by running this
    ticket's own arms against the planes it did not cover.

    The npm suite compiles `test/**/*` and then executes ONE literal path, so a
    file this directory acquires is built and run by nothing — while `drift`
    counts it and certifies it as inside an enumerated suite root."""

    def test_a_suite_file_the_runner_never_executes_fails(self):
        tree = self.tree(n8n_files=("a.test.ts", "b.test.ts"))
        found = self.failures(tree)
        self.assertTrue(any("does not execute it" in f for f in found), found)

    def test_the_same_file_named_by_the_runner_passes(self):
        """The caught half's control. Without it a detector that had stopped
        reading scripts.test altogether would satisfy the test above."""
        tree = self.tree(n8n_files=("a.test.ts", "b.test.ts"),
                         n8n_runner="tsc && node dist-test/test/a.test.js "
                                    "&& node dist-test/test/b.test.js")
        self.assertEqual(self.failures(tree), [])

    def test_the_runner_naming_the_typescript_source_is_not_an_execution(self):
        """`node test/a.test.ts` does not run the suite; tsc's OUTPUT is what
        executes. A detector comparing basenames directly would call this
        wired and the file would still run nowhere."""
        tree = self.tree(n8n_runner="tsc && node test/a.test.ts")
        found = self.failures(tree)
        self.assertTrue(any("does not execute it" in f for f in found), found)

    def test_a_runner_token_that_merely_contains_the_name_is_not_it(self):
        """`a.test.js` is a substring of `xa.test.js`. Matching on substrings
        would accept a runner that executes a different file entirely."""
        tree = self.tree(n8n_runner="tsc && node dist-test/test/xa.test.js")
        found = self.failures(tree)
        self.assertTrue(any("does not execute it" in f for f in found), found)

    def test_a_runner_naming_a_file_that_is_gone_fails(self):
        """The other direction, and the shape that matters most: the runner
        still names it, so the suite reads as wired, and there is nothing
        there to run."""
        tree = self.tree(n8n_files=())
        found = self.failures(tree)
        self.assertTrue(any("a stale entry" in f for f in found), found)

    def test_a_declared_support_file_is_exempt(self):
        csc.N8N_SUPPORT["helper.ts"] = "shared fixture, no verdict of its own"
        tree = self.tree(n8n_files=("a.test.ts", "helper.ts"))
        self.assertEqual(self.failures(tree), [])

    def test_a_support_declaration_for_a_missing_file_is_stale(self):
        """A residual list that keeps entries for files that no longer exist
        can silence a real one (RFX-339/RFX-348)."""
        csc.N8N_SUPPORT["helper.ts"] = "shared fixture, no verdict of its own"
        found = self.failures(self.tree())
        self.assertTrue(any("is STALE" in f for f in found), found)

    def test_the_runner_is_read_from_package_json_not_transcribed(self):
        """RFX-303's lesson, applied to the npm authority. A package.json this
        check cannot read is a FAIL, never a quiet pass over a plane it never
        enumerated."""
        tree = self.tree(n8n_package=False)
        found = self.failures(tree)
        self.assertTrue(any("refuses to certify" in f for f in found), found)

    def test_no_scripts_test_at_all_is_a_fail(self):
        tree = self.tree(n8n_runner="")
        found = self.failures(tree)
        self.assertTrue(any("refuses to certify" in f for f in found), found)

    def test_a_tree_with_no_npm_package_is_not_reddened(self):
        """A repo that does not ship this package must not go red for not
        shipping it — that is how a gate gets --allow-skips passed to it."""
        tree = self.tree()
        shutil.rmtree(os.path.join(tree.root, csc.N8N_DIR))
        self.assertEqual(self.failures(tree), [])

    def test_compiled_name_mapping(self):
        self.assertEqual(csc.n8n_compiled_name("a.test.ts"), "a.test.js")
        self.assertEqual(csc.n8n_compiled_name("a.test.js"), "a.test.js")
        self.assertEqual(csc.n8n_compiled_name("helper.mjs"), "helper.mjs")


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
                                    csc.NOT_A_CHECK, csc.N8N_SUPPORT),
                                   self._saved):
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
