"""
test_posture_rfx325.py -- the narrowed matcher leaves a record.

WHAT IS UNDER TEST (RFX-325).  `reeflex-claude` 0.1.7's `setup` wrote a narrow
PreToolUse matcher; `pip install -U` does not rewrite settings.json and says
nothing; so on every installation made before 0.2.0 an `mcp__*` call runs with
no decision, no audit record and no question put to core -- which qa--222
measured to be byte-for-byte what an installation with NO Reeflex hook
produces.  The owner's decision is WARN AND RUN, so these tests assert two
things at once, and the second is the one that is easy to lose:

  * a narrowing is now RECORDED (once per session, under its own rule id), and
  * a narrowing still does not change any decision.

Run under `unittest discover` (which is what gate.py and CI use for this tree);
every test below is a real TestCase method with assertions, per RFX-87.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude import posture
from reeflex_claude.posture import (
    MATCHER_STAMP_ENV,
    RULE_NARROWED,
    RULE_UNVERIFIED,
    STATE_FULL,
    STATE_NARROWED,
    STATE_UNVERIFIED,
    assess,
    is_full_coverage,
    matchers_in,
    note_once,
    uncovered_examples,
    widen_command,
)
from reeflex_claude.setup_settings import DEFAULT_MATCHER

# 0.1.7's matcher, verbatim -- the population this whole change is about.
OLD_MATCHER = "Bash|Write|Edit|MultiEdit|Read|Glob|Grep|LS|NotebookEdit|WebFetch|WebSearch"

_OUR_COMMAND = "/opt/venv/bin/reeflex-claude hook"


def _settings(matcher, command=_OUR_COMMAND, env=None):
    """A settings.json body wiring our hook under `matcher`."""
    block = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
    if matcher is not _ABSENT:
        block["matcher"] = matcher
    return {"hooks": {"PreToolUse": [block]}, "env": env or {}}


class _Absent:
    pass


_ABSENT = _Absent()


class _Isolated(unittest.TestCase):
    """
    Base: a throwaway HOME, project dir, audit log and state dir, so no test
    reads the developer's real ~/.claude or writes their real audit stream.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.home = root / "home"
        self.project = root / "project"
        (self.home / ".claude").mkdir(parents=True)
        (self.project / ".claude").mkdir(parents=True)
        self.audit_log = root / "audit.jsonl"
        self.state_dir = root / "state"

        self._saved = {}
        for key, value in (
            ("HOME", str(self.home)),
            ("CLAUDE_PROJECT_DIR", str(self.project)),
            ("REEFLEX_CLAUDE_AUDIT_LOG", str(self.audit_log)),
            ("REEFLEX_CLAUDE_STATE_DIR", str(self.state_dir)),
            (MATCHER_STAMP_ENV, None),
        ):
            self._saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.addCleanup(self._restore)
        self.addCleanup(self._tmp.cleanup)

    def _restore(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def write_project(self, body):
        (self.project / ".claude" / "settings.json").write_text(
            json.dumps(body), encoding="utf-8")

    def write_project_local(self, body):
        (self.project / ".claude" / "settings.local.json").write_text(
            json.dumps(body), encoding="utf-8")

    def write_home(self, body):
        (self.home / ".claude" / "settings.json").write_text(
            json.dumps(body), encoding="utf-8")

    def audit_records(self):
        if not self.audit_log.exists():
            return []
        return [json.loads(l) for l in self.audit_log.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# What counts as full coverage
# ---------------------------------------------------------------------------

class TestCoverageArithmetic(unittest.TestCase):

    def test_star_empty_and_absent_are_full_coverage(self):
        self.assertTrue(is_full_coverage("*"))
        self.assertTrue(is_full_coverage(""))
        self.assertTrue(is_full_coverage("   "))
        self.assertTrue(is_full_coverage(None))

    def test_the_0_1_7_matcher_is_not_full_coverage(self):
        self.assertFalse(is_full_coverage(OLD_MATCHER))

    def test_shipped_matcher_is_full_coverage(self):
        # If this ever fails, `setup` has started shipping a narrowing and the
        # whole detector would be comparing a thing to itself.
        self.assertTrue(is_full_coverage(DEFAULT_MATCHER))

    def test_uncovered_is_computed_with_fullmatch_not_search(self):
        """
        MEASURED, not assumed (dev-1--073 evidence `20-matcher-semantics.txt`,
        real `claude` 2.1.268): the matcher is a FULLY ANCHORED regex.
        Matcher `ash` did NOT select tool `Bash`; `Bas` did not either; `Ba.h`
        did; `*` did.  A search-semantics implementation would report `Bash`
        covered by `ash`, so this guards the arithmetic against the wrong
        reading of the same three characters.
        """
        self.assertIn("Task", uncovered_examples("Tas"))
        self.assertIn("Task", uncovered_examples("ask"))
        self.assertNotIn("Task", uncovered_examples("Ta.k"))
        self.assertNotIn("Task", uncovered_examples("Task|Skill"))

    def test_old_matcher_leaves_the_mcp_family_and_the_built_ins_qa_named(self):
        missing = uncovered_examples(OLD_MATCHER)
        for name in ("mcp__<server>__<tool>", "Task", "SlashCommand", "Skill"):
            self.assertIn(name, missing)

    def test_an_uncompilable_matcher_covers_nothing(self):
        # A matcher Claude Code cannot compile gates nothing; saying it covers
        # everything would be the fail-open reading.
        self.assertEqual(uncovered_examples("(unclosed"), list(posture._ILLUSTRATIVE_TOOLS))


class TestMatchersIn(unittest.TestCase):

    def test_finds_our_hook_and_returns_its_blocks_matcher(self):
        self.assertEqual(matchers_in(_settings(OLD_MATCHER)), [OLD_MATCHER])

    def test_absent_matcher_key_is_reported_as_none(self):
        self.assertEqual(matchers_in(_settings(_ABSENT)), [None])

    def test_a_foreign_hook_is_not_ours(self):
        body = _settings(OLD_MATCHER, command="/usr/local/bin/somebody-elses-hook run")
        self.assertEqual(matchers_in(body), [])

    def test_every_block_holding_our_hook_is_returned(self):
        body = _settings(OLD_MATCHER)
        body["hooks"]["PreToolUse"].append({
            "matcher": "*",
            "hooks": [{"type": "command", "command": _OUR_COMMAND, "timeout": 30}],
        })
        self.assertEqual(matchers_in(body), [OLD_MATCHER, "*"])

    def test_malformed_shapes_do_not_raise(self):
        for body in ({}, {"hooks": "nope"}, {"hooks": {"PreToolUse": "nope"}},
                     {"hooks": {"PreToolUse": [None, 7, {"hooks": "nope"}]}}):
            self.assertEqual(matchers_in(body), [])


# ---------------------------------------------------------------------------
# The assessment
# ---------------------------------------------------------------------------

class TestAssess(_Isolated):

    def test_the_upgraded_installation_reads_narrowed(self):
        self.write_project(_settings(OLD_MATCHER))
        a = assess()
        self.assertEqual(a["state"], STATE_NARROWED)
        self.assertEqual(a["evidence"], "settings-file")
        self.assertEqual(a["wired"][0]["matcher"], OLD_MATCHER)
        self.assertFalse(a["wired"][0]["covers_all"])
        self.assertIn("mcp__<server>__<tool>", a["uncovered_examples"])

    def test_a_fresh_install_reads_full(self):
        self.write_project(_settings(DEFAULT_MATCHER))
        self.assertEqual(assess()["state"], STATE_FULL)

    def test_one_match_all_block_is_full_coverage_however_narrow_its_neighbours(self):
        """
        Claude Code takes the UNION of the hook blocks it loads, so a narrow
        block beside a `*` block is not a narrowing -- every tool still
        reaches the hook.  Reporting NARROWED here would cry wolf once per
        session at an installation that is completely fine.
        """
        self.write_project(_settings(OLD_MATCHER))
        self.write_home(_settings(DEFAULT_MATCHER))
        a = assess()
        self.assertEqual(a["state"], STATE_FULL)
        self.assertEqual(len(a["wired"]), 2)

    def test_a_narrowing_in_settings_local_json_is_seen(self):
        self.write_project_local(_settings(OLD_MATCHER))
        self.assertEqual(assess()["state"], STATE_NARROWED)

    def test_no_settings_file_naming_us_reads_unverified_not_full(self):
        """
        The `claude --settings <path>` launch.  Nothing in the hook's payload
        or environment names that path (measured, evidence
        `10-hook-environment.txt`), so coverage is UNKNOWN -- and unknown must
        not collapse into 'fine', which is the direction that loses the
        finding.
        """
        a = assess()
        self.assertEqual(a["state"], STATE_UNVERIFIED)
        self.assertEqual(a["evidence"], "none")
        self.assertEqual(a["wired"], [])

    def test_a_settings_file_with_no_reeflex_hook_still_reads_unverified(self):
        self.write_project({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": "/bin/other"}]}]}})
        self.assertEqual(assess()["state"], STATE_UNVERIFIED)

    def test_the_env_stamp_is_used_when_no_file_names_us(self):
        os.environ[MATCHER_STAMP_ENV] = OLD_MATCHER
        a = assess()
        self.assertEqual(a["state"], STATE_NARROWED)
        self.assertEqual(a["evidence"], "env-stamp")
        self.assertEqual(a["wired"][0]["source"], "env:" + MATCHER_STAMP_ENV)

    def test_a_wide_env_stamp_never_overrides_a_narrow_FILE(self):
        """
        The load-bearing precedence.  A stamp records what `setup` wrote; the
        file records what governs NOW.  Someone who hand-narrows the matcher
        leaves the stamp saying `*`, and trusting it would print a clean bill
        of health over an installation where every mcp__* tool runs ungated --
        the one wrong answer this module must never give.
        """
        self.write_project(_settings(OLD_MATCHER))
        os.environ[MATCHER_STAMP_ENV] = DEFAULT_MATCHER
        a = assess()
        self.assertEqual(a["state"], STATE_NARROWED)
        self.assertEqual(a["evidence"], "settings-file")

    def test_unreadable_and_invalid_files_are_skipped_not_fatal(self):
        (self.project / ".claude" / "settings.json").write_text("{not json", encoding="utf-8")
        self.write_home(_settings(OLD_MATCHER))
        a = assess()
        self.assertEqual(a["state"], STATE_NARROWED)
        self.assertNotIn(str(self.project / ".claude" / "settings.json"), a["scanned"])

    def test_an_oversized_settings_file_is_not_read_on_the_hook_path(self):
        big = _settings(OLD_MATCHER)
        big["padding"] = "x" * (posture._MAX_SETTINGS_BYTES + 10)
        self.write_project(big)
        self.assertEqual(assess()["state"], STATE_UNVERIFIED)


class TestWidenCommand(_Isolated):

    def test_project_narrowing_gets_the_plain_setup_command(self):
        self.write_project(_settings(OLD_MATCHER))
        self.assertEqual(widen_command(assess()), "reeflex-claude setup")

    def test_a_narrowing_only_in_the_home_file_gets_global(self):
        """`setup` rewrites only the file it targets, so the wrong flag leaves
        the narrow entry exactly where it was and the operator re-runs it
        believing they fixed something."""
        self.write_home(_settings(OLD_MATCHER))
        self.assertEqual(widen_command(assess()), "reeflex-claude setup --global")


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

class TestNoteOnce(_Isolated):

    def test_a_narrowed_session_produces_exactly_one_record(self):
        self.write_project(_settings(OLD_MATCHER))
        first = note_once("session-A")
        self.assertIsNotNone(first)
        for _ in range(5):
            self.assertIsNone(note_once("session-A"))
        records = self.audit_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["rule"], RULE_NARROWED)
        self.assertEqual(records[0]["session_id"], "claude:session-A")

    def test_each_session_gets_its_own_record(self):
        self.write_project(_settings(OLD_MATCHER))
        for sid in ("s1", "s2", "s3"):
            note_once(sid)
        self.assertEqual({r["session_id"] for r in self.audit_records()},
                         {"claude:s1", "claude:s2", "claude:s3"})

    def test_a_full_coverage_session_produces_no_record_at_all(self):
        self.write_project(_settings(DEFAULT_MATCHER))
        self.assertIsNone(note_once("session-ok"))
        self.assertEqual(self.audit_records(), [])

    def test_unverified_coverage_gets_its_OWN_rule_id(self):
        """
        'We measured a narrowing' and 'we could not see the matcher' are
        different facts.  One rule id for both would let a reader count a
        --settings launch as a defective installation, or the reverse.
        """
        rec = note_once("session-U")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["rule"], RULE_UNVERIFIED)
        self.assertNotEqual(RULE_UNVERIFIED, RULE_NARROWED)

    def test_the_record_is_not_a_decision_record(self):
        """
        It shares the audit stream with decision records, so a consumer
        filtering on `"decision" in record` -- the pattern reeflex-core's own
        log documents -- must skip it rather than count a narrowing as a
        verdict on a tool call.
        """
        self.write_project(_settings(OLD_MATCHER))
        rec = note_once("session-A")
        self.assertEqual(rec["event"], "adapter_posture")
        self.assertNotIn("decision", rec)
        self.assertNotIn("permission_decision", rec)
        self.assertNotIn("tool_name", rec)

    def test_the_record_names_what_is_wired_what_ships_and_how_to_fix_it(self):
        self.write_project(_settings(OLD_MATCHER))
        rec = note_once("session-A")
        self.assertEqual(rec["matcher"]["shipped"], DEFAULT_MATCHER)
        self.assertEqual(rec["matcher"]["wired"][0]["matcher"], OLD_MATCHER)
        self.assertIn("mcp__<server>__<tool>", rec["matcher"]["uncovered_examples"])
        self.assertEqual(rec["remediation"], "reeflex-claude setup")
        self.assertIn("reeflex-claude setup", rec["reason"])
        # It must say the action was NOT blocked: this is the warn-and-run
        # decision, and a reader of the ledger should not infer enforcement.
        self.assertIn("NOT blocked", rec["reason"])

    def test_an_empty_session_id_records_nothing(self):
        self.write_project(_settings(OLD_MATCHER))
        self.assertIsNone(note_once(""))
        self.assertEqual(self.audit_records(), [])

    def test_a_session_id_full_of_path_separators_does_not_escape_the_state_dir(self):
        self.write_project(_settings(OLD_MATCHER))
        hostile = "../../../../etc/passwd"
        self.assertIsNotNone(note_once(hostile))
        markers = list(self.state_dir.iterdir())
        self.assertEqual(len(markers), 1)
        self.assertNotIn("..", markers[0].name)

    def test_an_unwritable_state_dir_does_not_raise(self):
        """
        The marker is a cache, not the record.  If it cannot be written the
        record repeats -- a duplicate an operator can see -- and nothing
        propagates to the hook.
        """
        self.write_project(_settings(OLD_MATCHER))
        os.environ["REEFLEX_CLAUDE_STATE_DIR"] = "/proc/nonexistent-dev1073/state"
        self.assertIsNotNone(note_once("session-A"))
        self.assertIsNotNone(note_once("session-A"))  # repeats rather than losing it

    def test_an_unwritable_audit_log_does_not_raise(self):
        self.write_project(_settings(OLD_MATCHER))
        os.environ["REEFLEX_CLAUDE_AUDIT_LOG"] = "/proc/nonexistent-dev1073/audit.jsonl"
        note_once("session-A")  # must not raise


# ---------------------------------------------------------------------------
# Warn AND RUN -- the decision the owner took
# ---------------------------------------------------------------------------

class TestTheDecisionIsUnchanged(_Isolated):
    """
    Option (b): a narrowing is recorded and the tool call proceeds exactly as
    it would have.  Without these two tests the change could quietly become
    deny-until-setup, which is the option that was NOT chosen.
    """

    def _run_hook(self, payload, core_url):
        import subprocess
        env = dict(os.environ)
        env["REEFLEX_CORE_URL"] = core_url
        env["REEFLEX_MODE"] = "enforce"
        env["PYTHONPATH"] = _PARENT
        out = subprocess.run(
            [sys.executable, "-m", "reeflex_claude.cli", "hook"],
            input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, timeout=60,
        )
        self.assertEqual(out.returncode, 0, out.stderr.decode()[:400])
        return json.loads(out.stdout.decode().strip().splitlines()[-1])

    def test_a_narrowed_session_still_fails_closed_when_core_is_unreachable(self):
        self.write_project(_settings(OLD_MATCHER))
        verdict = self._run_hook(
            {"session_id": "s-deny", "tool_name": "Bash",
             "tool_input": {"command": "rm -rf /srv/data"}, "cwd": "/tmp"},
            "http://127.0.0.1:9",  # discard port: nothing listens
        )
        self.assertEqual(verdict["hookSpecificOutput"]["permissionDecision"], "deny")
        rules = [r.get("rule") for r in self.audit_records()]
        self.assertIn(RULE_NARROWED, rules)

    def test_the_posture_record_does_not_suppress_the_decision_record(self):
        """Both records land, in that order: the posture record is additive."""
        self.write_project(_settings(OLD_MATCHER))
        self._run_hook(
            {"session_id": "s-both", "tool_name": "Bash",
             "tool_input": {"command": "ls"}, "cwd": "/tmp"},
            "http://127.0.0.1:9",
        )
        records = self.audit_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["rule"], RULE_NARROWED)
        self.assertIn("decision", records[1])
        self.assertEqual(records[1]["tool_name"], "Bash")


# ---------------------------------------------------------------------------
# setup stamps the matcher; status reports it
# ---------------------------------------------------------------------------

class TestSetupStampsTheMatcher(_Isolated):

    def test_setup_writes_the_matcher_into_the_env_block(self):
        """
        Claude Code exports a loaded settings file's `env` block to the hook
        but never names the file -- so for a `--settings <path>` launch the
        stamp is the only channel that survives.  Measured on 2.1.268;
        evidence `10-hook-environment.txt`.
        """
        from reeflex_claude.cli import cmd_setup
        import argparse
        cwd = os.getcwd()
        os.chdir(self.project)
        try:
            args = argparse.Namespace(
                target="project", core_url="http://127.0.0.1:8080", token=None,
                verify_ssl="true", mode="enforce", environment="production")
            rc = cmd_setup(args)
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        written = json.loads((self.project / ".claude" / "settings.json").read_text())
        self.assertEqual(written["env"][MATCHER_STAMP_ENV], DEFAULT_MATCHER)
        self.assertEqual(written["hooks"]["PreToolUse"][0]["matcher"], DEFAULT_MATCHER)


class TestStatusCommand(_Isolated):

    def _status(self, argv):
        import io
        import contextlib
        from reeflex_claude.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def test_status_names_the_narrowing_and_the_exact_fix(self):
        self.write_project(_settings(OLD_MATCHER))
        rc, out = self._status(["status"])
        self.assertIn("COVERAGE: NARROWED", out)
        self.assertIn(OLD_MATCHER, out)
        self.assertIn("reeflex-claude setup", out)
        self.assertIn("mcp__<server>__<tool>", out)

    def test_status_exits_zero_by_default_because_the_decision_was_warn_and_run(self):
        self.write_project(_settings(OLD_MATCHER))
        rc, _ = self._status(["status"])
        self.assertEqual(rc, 0)

    def test_status_strict_exits_one_so_ci_can_gate_on_it(self):
        self.write_project(_settings(OLD_MATCHER))
        rc, _ = self._status(["status", "--strict"])
        self.assertEqual(rc, 1)

    def test_status_strict_exits_zero_on_a_correctly_wired_installation(self):
        self.write_project(_settings(DEFAULT_MATCHER))
        rc, out = self._status(["status", "--strict"])
        self.assertEqual(rc, 0)
        self.assertIn("COVERAGE: every tool reaches the gate", out)

    def test_status_counts_sessions_not_lines(self):
        self.write_project(_settings(OLD_MATCHER))
        for sid in ("a", "b"):
            note_once(sid)
        # a duplicate, which is what a crash between record and marker leaves
        from reeflex_claude.audit import emit_raw
        emit_raw(dict(self.audit_records()[0]))
        rc, out = self._status(["status"])
        self.assertIn("sessions recorded under %s: 2" % RULE_NARROWED, out)

    def test_status_json_is_parseable_and_carries_the_state(self):
        self.write_project(_settings(OLD_MATCHER))
        rc, out = self._status(["status", "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["assessment"]["state"], STATE_NARROWED)
        self.assertEqual(payload["remediation"], "reeflex-claude setup")

    def test_status_says_these_records_do_not_reach_an_attest_report(self):
        """
        The honest limit, in the product's own output rather than only in a
        round report: the evidence connector tails reeflex-core's
        decisions.jsonl, so nothing the adapter writes locally becomes a row
        in an Attest report -- and a tool that never reached the hook produced
        no core decision to tail either.
        """
        self.write_project(_settings(OLD_MATCHER))
        _, out = self._status(["status"])
        self.assertIn("do not reach an Attest report", out)


if __name__ == "__main__":
    unittest.main()
