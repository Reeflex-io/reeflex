"""The RFX-97 release gate's exit code must not be forgeable by its own failures.

WHY THIS FILE EXISTS.  `scripts/attack-probe-rfx97-release-gate.py` documents
its exit code as a COUNT of tickets the run could not certify, and RFX-179 put
INCONCLUSIVE into that count precisely so a gate could not report green over
attacks that never ran.  That makes every small value load-bearing: `1` means
one ticket is open, and for this probe the single-ticket case is RFX-84 — a
fabricated human approving a production deletion.

Measured qa--306 (2026-09-22), against a core built from main a5142f2 running
on a spare port, `--json` pointed at a directory that did not exist:

    A release cut from this artefact would close 6 of 6:
      closed            : RFX-127, RFX-133, RFX-138, RFX-84, RFX-85, RFX-86
      still exploitable : none
    FileNotFoundError: [Errno 2] ... '/work/logs/no-such-dir/repro.json'
    probe rc=1

A run in which every known evasion was attacked and closed exited with the code
that means one of them is live.  The console's runner passes `--json "$L.json"`
and records `probe rc=$?` into the same log, so the two readings arrive as the
same line.  The same collision is reachable through `argparse`, which exits 2:
the runner passed stale `--base-url`/`--token` flags on 2026-08-22 and got
exactly that, and 2 is a verdict meaning two tickets are open.

WHAT IS ASSERTED HERE, and it is a direction and not a difference.  It is not
enough that a harness failure exits non-zero — the defect was already non-zero.
The property is that a harness failure exits a value **outside the range a
verdict can occupy**, AND that a genuine verdict is still passed through
unchanged.  A fix that mapped everything to 70 would satisfy the first half and
destroy the gate; `test_a_real_verdict_is_not_swallowed` is the arm that fails
on it.

Offline by construction: `cli()` is exercised with `main` replaced, so none of
this needs a core, a container or a network.  Written as unittest TestCases
because bare pytest-style functions in this tree collect zero tests and pass
forever (RFX-87).
"""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr


PROBE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "attack-probe-rfx97-release-gate.py")


def _load_probe():
    """Import the probe by path — its filename is not a Python identifier.

    The probe reads REEFLEX_PROBE_* at import time and refuses outright if its
    target is production core, so the target is pinned to a loopback address
    for the import: what this file tests must not depend on what happened to
    be exported in the shell that started the suite.
    """
    saved = {k: os.environ.get(k) for k in
             ("REEFLEX_PROBE_BASE", "REEFLEX_PROBE_PACE",
              "REEFLEX_PROBE_RESOLVER_MAP")}
    os.environ["REEFLEX_PROBE_BASE"] = "http://127.0.0.1:1"
    os.environ["REEFLEX_PROBE_PACE"] = "0"
    os.environ.pop("REEFLEX_PROBE_RESOLVER_MAP", None)
    try:
        spec = importlib.util.spec_from_file_location(
            "attack_probe_rfx97_release_gate", PROBE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


probe = _load_probe()


class ReservedCodeIsOutsideTheVerdictRange(unittest.TestCase):
    """The reserved code must not collide with any count the gate can report."""

    def test_reserved_code_cannot_be_a_ticket_count(self):
        # The verdict is a count of DISTINCT TICKETS, which is bounded above by
        # the number of attack rows; comparing against the rows is the
        # conservative direction and stays true if a row is ever added.
        self.assertGreater(
            probe.EXIT_HARNESS_ERROR, len(probe.ATTACKS),
            "EXIT_HARNESS_ERROR must be outside the range of verdict values, "
            "or a harness failure is readable as a finding about the artefact")

    def test_reserved_code_is_not_zero(self):
        self.assertNotEqual(
            0, probe.EXIT_HARNESS_ERROR,
            "a harness failure must never read as a clean gate")


class AHarnessFailureIsNotAVerdict(unittest.TestCase):
    """Every way out of main() that is not a return value exits 70."""

    def _cli_with_main(self, replacement):
        original = probe.main
        probe.main = replacement
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                code = probe.cli()
            return code, err.getvalue()
        finally:
            probe.main = original

    def test_an_uncaught_exception_does_not_exit_inside_the_verdict_range(self):
        """The measured defect: a crash after a clean table exited 1."""
        def boom():
            raise FileNotFoundError(
                2, "No such file or directory", "/work/logs/no-such-dir/x.json")

        code, err = self._cli_with_main(boom)
        self.assertEqual(probe.EXIT_HARNESS_ERROR, code)
        self.assertNotEqual(1, code, "a crash must not read as 'RFX-84 is open'")
        self.assertIn("HARNESS FAILURE", err)

    def test_an_argparse_usage_error_does_not_exit_two(self):
        """argparse exits 2, and 2 means two tickets could not be certified."""
        def usage_error():
            raise SystemExit(2)

        code, err = self._cli_with_main(usage_error)
        self.assertEqual(probe.EXIT_HARNESS_ERROR, code)
        self.assertNotEqual(2, code)
        self.assertIn("HARNESS FAILURE", err)

    def test_a_harness_error_is_reported_as_one(self):
        def unwritable():
            raise probe.HarnessError("could not write the JSON report to /nope")

        code, err = self._cli_with_main(unwritable)
        self.assertEqual(probe.EXIT_HARNESS_ERROR, code)
        self.assertIn("certified nothing", err)

    def test_a_keyboard_interrupt_certifies_nothing(self):
        """An interrupted gate run is not a gate run; BaseException, not Exception."""
        def interrupted():
            raise KeyboardInterrupt()

        code, _ = self._cli_with_main(interrupted)
        self.assertEqual(probe.EXIT_HARNESS_ERROR, code)


class AVerdictStillReachesTheCaller(unittest.TestCase):
    """The complement: the fix must not swallow real findings into 70."""

    def _cli_returning(self, value):
        original = probe.main
        probe.main = lambda: value
        try:
            return probe.cli()
        finally:
            probe.main = original

    def test_a_real_verdict_is_not_swallowed(self):
        # The arm that catches an over-wide fix. If cli() ever routes a normal
        # return through the failure path, the gate stops reporting evasions.
        for verdict in range(0, len(probe.ATTACKS) + 1):
            with self.subTest(verdict=verdict):
                self.assertEqual(verdict, self._cli_returning(verdict))

    def test_a_clean_run_still_exits_zero(self):
        self.assertEqual(0, self._cli_returning(0))


class TheJsonReportFailsWithAType(unittest.TestCase):
    """write_json_report turns an unwritable path into HarnessError, not OSError."""

    def test_a_missing_directory_raises_harness_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "no-such-dir", "report.json")
            with self.assertRaises(probe.HarnessError) as ctx:
                probe.write_json_report(target, {"findings": []})
            # The message must say the verdict survived, because it did: the
            # table is already on stdout by the time this runs.
            self.assertIn("verdict table above is valid", str(ctx.exception))

    def test_a_writable_path_still_writes_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.json")
            probe.write_json_report(target, {"findings": [], "run": "t"})
            self.assertTrue(os.path.exists(target))
            with open(target, encoding="utf-8") as fh:
                self.assertIn("findings", fh.read())


if __name__ == "__main__":
    unittest.main()
