"""Unit tests for scripts/check_core_deployment.py (RFX-309 req 3, RFX-90).

WHAT THESE ASSERT FIRST, AND WHY IT IS FIRST. The tool exists because a check
that could not go red let a production core sit for weeks looking healthy. So
the first thing proved here is not that it passes a good deployment — it is
that it goes RED on every shape of silence:

  * a core that publishes no `holds` block (pre-RFX-309 / pre-v0.2.2)
  * a core that says `resolvable: false` (api-dev, measured 2026-09-20)
  * a build that will not say what commit it is
  * a revision that is not a commit in THIS clone (the reeflex-app trap)
  * a revision on a side branch

and that "we could not look" (ERROR, exit 2) is never filed as "we looked and
it was fine" (PASS, exit 0).

The drift arm is exercised against REAL git repositories built in a temp dir,
not against a mocked `git`: the arm's whole job is to ask a clone a question,
and a mock would assert the question rather than the answer.
"""

import contextlib
import http.server
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_core_deployment as ccd  # noqa: E402


# --- the fixtures, named after the deployments they are copies of -----------

HEALTHZ_CAN_APPROVE = {
    "status": "ok",
    "holds": {"resolvable": True, "reason": "credentials_bound",
              "require_verified_approver": True, "verified_approvers": 1,
              "ttl_seconds": 14400},
}

# Measured on https://api-dev.reeflex.io/healthz, 2026-09-20T05:25Z, by
# dev-1--185. Copied verbatim so this suite fails if the shape core publishes
# ever stops being the shape this tool reads.
HEALTHZ_API_DEV_20260920 = {
    "status": "ok",
    "holds": {"reason": "verification_not_configured",
              "require_verified_approver": True, "resolvable": False,
              "ttl_seconds": 14400, "verified_approvers": 0},
    "ledger": {"durable": True, "path": "/app/audit/ledger.jsonl"},
    "server": {"concurrency": "pool", "workers": 32},
}

HEALTHZ_PRE_RFX309 = {"status": "ok", "ledger": {"durable": True}}


class CapabilityArmGoesRed(unittest.TestCase):
    """RFX-309: can this deployment accept an approval at all?"""

    def test_api_dev_as_measured_fails(self):
        ok, _lines, failures = ccd.capability_arm(HEALTHZ_API_DEV_20260920, "/healthz")
        self.assertFalse(ok)
        self.assertIn("cannot accept an approval", failures[0])
        # the TTL is part of the finding: "raised, never answerable, gone in
        # four hours" is the whole sentence, not just the first clause.
        self.assertIn("14400", failures[0])

    def test_a_core_that_does_not_publish_the_fact_is_not_a_pass(self):
        ok, _lines, failures = ccd.capability_arm(HEALTHZ_PRE_RFX309, "/healthz")
        self.assertFalse(ok)
        self.assertIn("publishes no `holds` block", failures[0])

    def test_resolvable_missing_is_not_a_pass(self):
        ok, _lines, failures = ccd.capability_arm(
            {"status": "ok", "holds": {"reason": "something new"}}, "/healthz")
        self.assertFalse(ok)

    def test_resolvable_must_be_the_boolean_true_not_a_truthy_string(self):
        """`"false"` is truthy in Python and is exactly the shape a hand-rolled
        health shim or a proxy that stringifies JSON would produce. A capability
        check that reads it as "can approve" is the fail-open this tool is
        supposed to notice."""
        for bad in ("true", "false", 1, "yes", None):
            ok, _lines, _f = ccd.capability_arm(
                {"status": "ok", "holds": {"resolvable": bad}}, "/healthz")
            self.assertFalse(ok, "resolvable=%r was read as a pass" % (bad,))

    def test_a_deployment_that_can_approve_passes(self):
        ok, _lines, failures = ccd.capability_arm(HEALTHZ_CAN_APPROVE, "/healthz")
        self.assertTrue(ok, failures)


# --- drift arm, against real repositories ----------------------------------

def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _commit(repo, message, when=None):
    path = pathlib.Path(repo) / "f.txt"
    path.write_text(message, encoding="utf-8")
    env = dict(os.environ)
    if when:
        env["GIT_AUTHOR_DATE"] = when
        env["GIT_COMMITTER_DATE"] = when
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", message],
                   check=True, capture_output=True, text=True, env=env)
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True
                          ).stdout.strip()


class DriftArmAgainstRealRepos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="core-deployment-test-")
        self.repo = pathlib.Path(self.tmp) / "monorepo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.email", "t@rfx.invalid")
        _git(self.repo, "config", "user.name", "t")
        self.first = _commit(self.repo, "one", "2026-09-01T00:00:00+00:00")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _arm(self, body, ref="main", max_age_days=2.0, max_behind=None):
        return ccd.drift_arm(body, "/healthz", self.repo, ref, max_age_days, max_behind)

    def test_a_build_that_will_not_say_what_it_is_is_drift_not_unknown(self):
        ok, _lines, failures = self._arm({"status": "ok"})
        self.assertFalse(ok)
        self.assertIn("no build revision", failures[0])
        self.assertIn("drift by default, not a pass", failures[0])

    def test_an_empty_revision_string_is_the_same_as_absent(self):
        ok, _lines, failures = self._arm({"status": "ok", "revision": "   "})
        self.assertFalse(ok)
        self.assertIn("no build revision", failures[0])

    def test_a_revision_this_clone_never_heard_of_fails_and_names_the_clone(self):
        """The reeflex-app trap, as a test. A correct CORE revision handed to a
        checker pointed at the wrong clone is not 'unknown, pass' and is not a
        silent success — it fails, and the message names the wrong-clone cause
        so the reader does not go hunting for a deleted branch."""
        ok, _lines, failures = self._arm({"status": "ok", "revision": "0" * 40})
        self.assertFalse(ok)
        self.assertIn("not a commit in", failures[0])
        self.assertIn("reeflex-app", failures[0])

    def test_a_side_branch_build_fails(self):
        _git(self.repo, "checkout", "-q", "-b", "side")
        side = _commit(self.repo, "side", "2026-09-02T00:00:00+00:00")
        _git(self.repo, "checkout", "-q", "main")
        ok, _lines, failures = self._arm({"status": "ok", "revision": side})
        self.assertFalse(ok)
        self.assertIn("NOT an ancestor", failures[0])

    def test_deployed_equals_ref_passes_and_reports_zero_behind(self):
        ok, lines, failures = self._arm({"status": "ok", "revision": self.first})
        self.assertTrue(ok, failures)
        self.assertIn("behind       0 commit(s) on main", lines)

    def test_a_stale_deployment_fails_on_AGE_and_names_the_oldest(self):
        """RFX-88 in miniature: what hurt every time was age, not count."""
        _commit(self.repo, "two", "2026-09-02T00:00:00+00:00")
        ok, lines, failures = self._arm({"status": "ok", "revision": self.first})
        self.assertFalse(ok)
        self.assertIn("has been waiting", failures[0])
        self.assertTrue(any(line.startswith("oldest ") for line in lines))

    def test_a_fresh_deployment_within_the_age_budget_passes(self):
        """The control for the test above: the SAME one-commit-behind shape,
        differing only in the commit's date, must PASS — otherwise the age test
        above is passing for the wrong reason."""
        _commit(self.repo, "two")  # now
        ok, _lines, failures = self._arm({"status": "ok", "revision": self.first})
        self.assertTrue(ok, failures)

    def test_a_utc_committer_date_parses(self):
        """git prints `%cI` as `...Z` when the committer timezone is UTC — every
        commit made on a GitHub runner. `datetime.fromisoformat` did not accept
        that until 3.11, and this tool advertises 3.9/3.6 operators. Unfixed,
        the whole check died with a traceback and printed NO verdict line at
        all, so a reader grepping for `CORE-DEPLOYMENT:` got silence."""
        sha = _commit(self.repo, "utc", "2026-09-02T00:00:00+00:00")
        stored = subprocess.run(
            ["git", "-C", str(self.repo), "log", "-1", "--format=%cI", sha],
            check=True, capture_output=True, text=True).stdout.strip()
        self.assertTrue(stored.endswith("Z"), "fixture no longer reproduces the "
                                              "Z spelling (git printed %r)" % stored)
        ok, _lines, failures = self._arm({"status": "ok", "revision": self.first})
        self.assertFalse(ok)
        self.assertIn("has been waiting", failures[0])

    def test_a_subject_containing_the_separator_does_not_vanish_a_commit(self):
        """Dropping an unparseable row would UNDERSTATE the drift — this tool
        failing open on its own arithmetic."""
        _commit(self.repo, "two\x1fwith separator", "2026-09-02T00:00:00+00:00")
        rows = ccd.undeployed(self.repo, self.first, "main")
        self.assertEqual(len(rows), 1)

    def test_max_behind_zero_is_available_for_a_cd_environment(self):
        _commit(self.repo, "two")  # now: inside the age budget
        ok, _lines, failures = self._arm(
            {"status": "ok", "revision": self.first}, max_behind=0)
        self.assertFalse(ok)
        self.assertIn("1 commit(s) undeployed, budget is 0", failures[-1])


class ErrorIsNeverAPass(unittest.TestCase):
    """exit 2 and exit 1 are different answers and must stay different."""

    def test_unreachable_target_is_ERROR_exit_2(self):
        # port 1 on localhost: refused immediately, no network egress, no wait.
        rc = ccd.main(["--target", "http://127.0.0.1:1", "--timeout", "2"])
        self.assertEqual(rc, 2)

    def test_the_two_verdict_strings_are_distinct_and_anchored(self):
        self.assertNotEqual(ccd.VERDICT_FAIL, ccd.VERDICT_ERROR)
        for v in (ccd.VERDICT_PASS, ccd.VERDICT_FAIL, ccd.VERDICT_ERROR):
            self.assertTrue(v.startswith("CORE-DEPLOYMENT: "))

    def test_skipping_both_arms_is_ERROR_not_a_free_pass(self):
        """A check invoked with nothing to check must not print PASS. This is
        the `reeflex-claude check` shape (RFX-147): a green over no work."""
        with self.assertRaises(ccd.CheckError):
            ccd.check(target="http://127.0.0.1:1", repo=pathlib.Path("."),
                      run_drift=False, run_capability=False)


class TheExitCodeTheDailyJobActuallyReads(unittest.TestCase):
    """RFX-396: everything above this line tests the arms, or `check()`, or the
    ERROR path. Until these tests existed the suite reached `main()` in exactly
    ONE place — `test_unreachable_target_is_ERROR_exit_2` — and the `return 2`
    it pins sits ABOVE `return 0 if ok else 1`. So exit 2 was pinned and exit 1
    was not: `return 0 if ok else 1` -> `return 0` left all 194 tests green
    while the tool printed CORE-DEPLOYMENT: FAIL against the live production
    core and told the daily workflow it had succeeded.

    That is this tool's own subject matter one level up — a verdict computed
    and not read — so it is pinned here on the same mechanism the workflow
    uses: the integer `main()` returns.

    The serve-a-body fixture is ~15 lines of `http.server` on 127.0.0.1:0. It
    is NOT Reeflex and nothing Reeflex is started by this suite; it exists
    because exit 1 is only reachable through a target that ANSWERS, and a
    refused connection is exit 2 by design.
    """

    def _serving(self, body):
        """A localhost endpoint returning `body` as JSON. Torn down by the
        test, not by the process exiting."""
        payload = json.dumps(body).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib's spelling
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass  # keep the suite's output readable

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d" % srv.server_port

    def test_a_FAIL_verdict_leaves_main_returning_1(self):
        """The arm RFX-396 is about. api-dev's own measured body, capability
        red: the workflow must see a non-zero exit, not just read the word
        FAIL in a log nobody parses."""
        target = self._serving(HEALTHZ_API_DEV_20260920)
        rc = ccd.main(["--target", target, "--skip-drift", "--timeout", "5"])
        self.assertEqual(rc, 1)

    def test_a_PASS_verdict_leaves_main_returning_0(self):
        """The control, and it is not optional. Without it the test above is
        satisfied by a tool that returns 1 unconditionally — which would break
        the daily job in the other direction and still look guarded."""
        target = self._serving(HEALTHZ_CAN_APPROVE)
        rc = ccd.main(["--target", target, "--skip-drift", "--timeout", "5"])
        self.assertEqual(rc, 0)

    def test_the_FAIL_exit_code_and_the_FAIL_word_travel_together(self):
        """Pinned separately from the exit code on purpose: a tool that prints
        PASS and exits 1, or prints FAIL and exits 0, is wrong in a way a
        single combined assertion would report as one failure and hide half
        of."""
        target = self._serving(HEALTHZ_API_DEV_20260920)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ccd.main(["--target", target, "--skip-drift", "--timeout", "5"])
        self.assertIn(ccd.VERDICT_FAIL, buf.getvalue())
        self.assertNotIn(ccd.VERDICT_PASS, buf.getvalue())


class BothArmsAreActuallyInvoked(unittest.TestCase):
    """RFX-396, the half that is worse than a lost verdict: a dropped arm does
    not merely fail to run, it makes `check()` assert a clean result NAMING the
    arm that never ran ("capability+drift arm(s) clean"), because the summary
    label is derived from the --skip flags rather than from what executed.

    So the flags are not the thing to assert. These record whether the arm
    functions were CALLED.
    """

    def setUp(self):
        self.called = []

        def recorder(name):
            def arm(*args, **kwargs):
                self.called.append(name)
                return True, [], []
            return arm

        for name in ("capability_arm", "drift_arm"):
            patcher = unittest.mock.patch.object(ccd, name, recorder(name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.fetch = unittest.mock.patch.object(
            ccd, "fetch_healthz",
            lambda target, timeout: (HEALTHZ_CAN_APPROVE, target + "/healthz"),
        )
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def test_neither_flag_passed_runs_both_arms(self):
        ok, _lines, _detail = ccd.check(target="http://127.0.0.1:1",
                                        repo=pathlib.Path("."))
        self.assertTrue(ok)
        self.assertEqual(sorted(self.called), ["capability_arm", "drift_arm"])

    def test_skip_capability_runs_only_drift(self):
        """The other side of the same claim: the flags must still WORK. A
        guard that only asserts 'both ran' is satisfied by a tool that has
        stopped honouring --skip-capability entirely."""
        ccd.check(target="http://127.0.0.1:1", repo=pathlib.Path("."),
                  run_capability=False)
        self.assertEqual(self.called, ["drift_arm"])

    def test_skip_drift_runs_only_capability(self):
        ccd.check(target="http://127.0.0.1:1", repo=pathlib.Path("."),
                  run_drift=False)
        self.assertEqual(self.called, ["capability_arm"])


class SelftestProvesItsOwnRedness(unittest.TestCase):
    """`--selftest` is the ONLY gate core-deployment.yml runs before the live
    check, so what binds IT matters.

    `test_selftest_exits_zero` on its own did not bind anything: with
    `CAPABILITY_FIXTURES` emptied, the old `_selftest` scored zero cases, printed
    `CORE-DEPLOYMENT: PASS (selftest: capability arm goes red on 3 of 4
    fixtures, green on 1)` — a hardcoded count over nothing — and returned 0, so
    this class and the CI step both stayed green. Measured dev-2--117
    (RFX-399): full `unittest discover -s scripts/tests` = 201 ran / OK with
    the list emptied.

    So the assertions below are about COVERAGE and about the verdict line being
    DERIVED, not about the exit code alone. Each one is required to fail when
    the fixtures are emptied or an arm is dropped.
    """

    def _selftest_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ccd._selftest()
        return code, buf.getvalue()

    def test_selftest_exits_zero(self):
        code, _out = self._selftest_output()
        self.assertEqual(code, 0)

    def test_it_scores_every_declared_arm(self):
        """The docstring and --help say BOTH arms. Assert the arms actually
        appear in the scored output, so dropping one cannot stay green."""
        _code, out = self._selftest_output()
        for arm in ccd.SELFTEST_ARMS:
            self.assertRegex(
                out, r"(?m)^ok +%s " % re.escape(arm),
                "`--selftest` claims to score the %s arm and no scored line "
                "names it" % arm,
            )

    def test_an_arm_that_scores_no_case_is_ERROR_and_names_the_arm(self):
        """The defect, directly: an empty fixture list must not be a pass."""
        with unittest.mock.patch.object(ccd, "CAPABILITY_FIXTURES", []):
            code, out = self._selftest_output()
        self.assertEqual(code, 2, "a selftest that scored no capability case "
                                  "exited %r, not 2" % code)
        self.assertIn(ccd.VERDICT_ERROR, out)
        self.assertIn("capability arm scored 0 red and 0 green", out)
        self.assertNotIn(ccd.VERDICT_PASS, out)

    def test_an_arm_with_only_green_cases_is_ERROR(self):
        """Coverage is not a count: four cases that can never go red prove
        nothing about redness, which is the whole point of this gate."""
        green_only = [c for c in ccd.CAPABILITY_FIXTURES if c[2] is True]
        self.assertTrue(green_only, "fixture set has no green case to narrow to")
        with unittest.mock.patch.object(ccd, "CAPABILITY_FIXTURES", green_only):
            code, out = self._selftest_output()
        self.assertEqual(code, 2)
        self.assertIn("red and %d green" % len(green_only), out)

    def test_the_verdict_line_counts_what_was_actually_scored(self):
        """A hardcoded '3 of 4' is a count nobody measured. Drop one fixture and
        the printed total must move with it."""
        _code, full = self._selftest_output()
        self.assertIn("(selftest: %d case(s) scored" % (
            len(ccd.CAPABILITY_FIXTURES) + 4), full)

        one_fewer = ccd.CAPABILITY_FIXTURES[:-1]
        with unittest.mock.patch.object(ccd, "CAPABILITY_FIXTURES", one_fewer):
            code, out = self._selftest_output()
        self.assertEqual(code, 0, "narrowing to %d fixtures should still be a "
                                  "valid, passing selftest" % len(one_fewer))
        self.assertIn("(selftest: %d case(s) scored" % (len(one_fewer) + 4), out)
        self.assertNotIn("(selftest: %d case(s) scored" % (
            len(ccd.CAPABILITY_FIXTURES) + 4), out)

    def test_the_drift_arm_fixtures_really_reach_the_drift_arm(self):
        """The scratch repo is the point: without it the drift cases cannot be
        scored at all, and an unbuildable fixture must be ERROR, not a pass."""
        with unittest.mock.patch.object(ccd, "_scratch_repo",
                               side_effect=ccd.CheckError("git is not available")):
            code, out = self._selftest_output()
        self.assertEqual(code, 2)
        self.assertIn(ccd.VERDICT_ERROR, out)
        self.assertIn("git is not available", out)
        self.assertNotIn(ccd.VERDICT_PASS, out)

    def test_the_selftest_removes_its_scratch_repo(self):
        made = []
        real = ccd._scratch_repo

        def spy(root):
            repo = real(root)
            made.append(repo)
            return repo

        with unittest.mock.patch.object(ccd, "_scratch_repo", side_effect=spy):
            self._selftest_output()
        self.assertEqual(len(made), 1)
        self.assertFalse(made[0].exists(),
                         "selftest left %s behind" % made[0])


class TheFixtureMatchesWhatCoreActuallyPublishes(unittest.TestCase):
    """The instrument-honesty arm. This tool reads keys out of core's /healthz;
    if core renames one, every arm above still passes against the fixtures and
    the live check silently starts reporting the wrong thing. So assert the
    key names against core's own producer rather than against a copy."""

    def test_capability_keys_are_the_ones_core_emits(self):
        root = pathlib.Path(__file__).resolve().parent.parent.parent
        principal = root / "reeflex-core" / "app" / "principal.py"
        if not principal.exists():  # pragma: no cover - packaging safety
            self.skipTest("reeflex-core not in this tree")
        source = principal.read_text(encoding="utf-8")
        for key in ("resolvable", "reason", "verified_approvers"):
            self.assertIn('"%s"' % key, source,
                          "check_core_deployment.py reads holds.%s but "
                          "principal.py no longer emits it" % key)

    def test_revision_key_is_the_one_server_emits(self):
        root = pathlib.Path(__file__).resolve().parent.parent.parent
        server = root / "reeflex-core" / "app" / "server.py"
        if not server.exists():  # pragma: no cover - packaging safety
            self.skipTest("reeflex-core not in this tree")
        self.assertIn('_health["revision"]', server.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
