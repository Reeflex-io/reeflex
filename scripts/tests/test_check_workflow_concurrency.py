"""A second pair of eyes on check_workflow_concurrency.py — RFX-134.

This file is picked up by BOTH invokers that already exist for scripts/tests:
`gate.yml`'s dep-floors job (`python -m unittest discover -s scripts/tests -t
scripts -v`) and `gate.py`'s `migration-heads-selftest` component. Nothing new
had to be wired for it to run, which is the point of putting it here.

The checker carries its own `--selftest`, and this is deliberately not a copy
of it. `--selftest` proves the READER on fixtures; this proves the two things a
selftest cannot:

  * the verdict the tree actually gets today, through `main()`, including its
    exit code and its anchored verdict line — the contract every caller parses;
  * that the checker still REPORTS the configuration that really shipped. After
    the fix, every assertion about today's tree is an emptiness assertion, and
    an emptiness assertion computed by a reader that stopped reading is green
    for the worst possible reason.

The second one is the arm that matters. It is scored against `ci.yml` exactly
as it stood on e175e4e — the revision whose main-push history contains 13
cancelled runs.
"""

import io
import pathlib
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import check_workflow_concurrency as chk  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# `.github/workflows/ci.yml` EXACTLY as it stood on
# e175e4e527bf361ae510839f040216146fb3ce08, trimmed to the keys this checker
# reads. Kept as a fixture so the reader is scored against the shape that
# really shipped and really cancelled 13 main-push runs.
CI_AS_IT_SHIPPED_ON_E175E4E = """
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
    name: OPA policy tests
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
  python-unit-tests:
    name: Python unit tests
    runs-on: ubuntu-latest
    needs: opa-policy-tests
    steps:
      - name: Checkout
        uses: actions/checkout@v4
"""


class TheReaderStillReportsWhatShipped(unittest.TestCase):
    def test_the_configuration_that_cancelled_13_runs_is_reported(self):
        problems = chk.problems_for(chk.scan(CI_AS_IT_SHIPPED_ON_E175E4E, where="e175e4e"))
        self.assertTrue(
            problems,
            "the reader no longer reports the ci.yml that shipped on e175e4e and "
            "cancelled 13 of its 195 main-push runs, so its silence about "
            "today's tree means nothing",
        )
        self.assertIn("push", problems[0], problems)

    def test_the_offending_block_is_named_precisely(self):
        problems = chk.problems_for(chk.scan(CI_AS_IT_SHIPPED_ON_E175E4E, where="e175e4e"))
        self.assertTrue(
            problems[0].startswith("concurrency.cancel-in-progress"),
            f"the report does not say WHERE the defect is: {problems[0]!r}",
        )

    def test_a_job_name_is_not_mistaken_for_a_concurrency_block(self):
        """The two-job shape above is the one that breaks a naive scanner.

        `python-unit-tests:` and `concurrency:` sit at different indents, and a
        reader that takes the last `key:` it saw would attribute a job-level
        block to the wrong job — or a workflow-level block to a job.
        """
        scanned = chk.scan(CI_AS_IT_SHIPPED_ON_E175E4E, where="e175e4e")
        self.assertEqual([p for p, _ in scanned["cancels"]], ["concurrency"])
        self.assertEqual(
            scanned["events"], ["workflow_dispatch", "push", "pull_request"]
        )


class TodaysTreePasses(unittest.TestCase):
    def test_every_registered_workflow_is_clean(self):
        ok, lines, detail = chk.check(REPO_ROOT)
        self.assertTrue(ok, f"{detail}\n" + "\n".join(lines))

    def test_the_verdict_line_and_exit_code_are_the_documented_contract(self):
        """Callers parse the anchored line; a checker that changes it is a
        checker whose green nobody is reading."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = chk.main([str(REPO_ROOT)])
        out = buf.getvalue()
        self.assertEqual(code, 0, out)
        self.assertIn(chk.VERDICT_PASS, out)
        self.assertNotIn(chk.VERDICT_FAIL, out)

    def test_the_nested_n8n_workflows_are_not_counted(self):
        """`n8n-nodes-reeflex/.github/workflows/` never fires — RFX-184.

        Counting an inert file as guarded is a green tick for a check that
        cannot exist, so the enumeration is non-recursive and this is what
        holds it that way.
        """
        names = [p.name for p in chk.registrable_workflows(REPO_ROOT)]
        nested = REPO_ROOT / "n8n-nodes-reeflex" / ".github" / "workflows"
        if nested.is_dir():
            for path in nested.glob("*.y*ml"):
                self.assertNotIn(
                    str(path),
                    [str(p) for p in chk.registrable_workflows(REPO_ROOT)],
                    f"{path} is not registered by GitHub and must not be counted",
                )
        self.assertIn("gate.yml", names)


class ItFailsClosed(unittest.TestCase):
    def test_an_unreadable_trigger_block_is_an_error_not_a_pass(self):
        with self.assertRaises(chk.CheckError):
            chk.scan("on: [push]\njobs:\n  t:\n    steps: []\n", where="flow")

    def test_a_missing_workflow_directory_is_an_error_not_a_pass(self):
        with self.assertRaises(chk.CheckError):
            chk.registrable_workflows(pathlib.Path("/nonexistent-rfx134"))

    def test_main_reports_error_and_exit_2_rather_than_a_silent_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = chk.main(["/nonexistent-rfx134"])
        self.assertEqual(code, 2)
        self.assertIn(chk.VERDICT_ERROR, buf.getvalue())


class TheSelftestIsItselfRun(unittest.TestCase):
    def test_selftest_passes_here_too(self):
        """gate.yml runs `--selftest` as its own step; if that step is ever
        dropped, this keeps the reader's fixtures being scored."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = chk.selftest()
        self.assertEqual(code, 0, buf.getvalue())

    def test_the_cross_check_says_out_loud_whether_it_ran(self):
        """...and that report must survive INTO THE LOG.

        MEASURED ON THE RUNNER, and it is the reason this test exists. In
        gate.yml's dep-floors job (no `pip install`) the checker's own step
        printed `cross-check against PyYAML SKIPPED (PyYAML not importable
        here)` — exactly as designed. In the preflight-gate job, where the
        package installs mean PyYAML probably IS importable, the line appeared
        nowhere: `redirect_stdout` above swallows it, so the one plane that
        might have run the cross-check reported nothing either way.

        That is the defect this whole ticket is about, committed by its own
        instrument: a check whose result is invisible is indistinguishable
        from a check that did not run. So the status is asserted to exist —
        the selftest cannot quietly stop reporting it — and re-emitted to
        stderr, which the discovery runner does not capture.
        """
        buf = io.StringIO()
        with redirect_stdout(buf):
            chk.selftest()
        out = buf.getvalue()

        ran = "cross-checked" in out
        skipped = "cross-check against PyYAML SKIPPED" in out
        self.assertNotEqual(
            ran,
            skipped,
            "the selftest must report EXACTLY ONE of 'cross-checked ...' or "
            f"'cross-check ... SKIPPED'. It reported neither or both:\n{out}",
        )
        print(
            "  [RFX-134] PyYAML cross-check in this environment: "
            + ("RAN" if ran else "SKIPPED (PyYAML not importable)"),
            file=sys.stderr,
        )


if __name__ == "__main__":
    unittest.main()
