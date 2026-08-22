"""
test_gate_probe.py -- `reeflex-claude check` must be able to fail for the
reason the customer cares about (RFX-147).

WHAT THIS FILE DEFENDS
======================
Before RFX-147, `check` ran one probe -- unreachable core, assert deny -- and
printed "PASS -- fail-closed verified", exit 0, on an installation where
`kubectl delete namespace production` was ALLOWED with no human. Its exit code
was a statement about the network. These tests pin the properties that make it
a statement about the gate:

  1. An unexpected `allow` on a destructive production payload fails the check.
  2. A deny that came from `reeflex.core/fail_closed` is NOT counted as a pass.
     This is the trap: an unreachable core denies everything, which looks
     exactly like a working gate. If this test is deleted, `check` silently
     goes back to reporting the network.
  3. Observe mode is reported as NOT-ENFORCED, not as a pass.
  4. `--require-gate` CHANGES AN OUTCOME. RFX-145 shipped a documented knob
     (REEFLEX_CLAUDE_STRICT) that could not move a single verdict; a flag whose
     presence cannot change an exit code is the same defect.
  5. A gate that denied EVERYTHING would satisfy (1) and be useless -- the
     benign control catches it -- but being over-strict only warns.

Layer 1 tests classify_probe_output(), which is pure. Layer 2 injects a STUB
hook command so the aggregation and exit codes are tested end-to-end with no
core and no network.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude import gate_probe
from reeflex_claude.cli import _gate_stage

_SUBPROCESS_TIMEOUT = 30

# An address nothing listens on -- keeps every test hermetic no matter what
# REEFLEX_CORE_URL the developer's shell happens to export.
_UNREACHABLE_CORE = "http://127.0.0.1:1"


def _hook_stdout(decision, rule, prefix="Reeflex: synthetic"):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"{prefix} [rule={rule}]",
        }
    })


_DESTRUCTIVE = gate_probe.GATE_PROBES[0]
_BENIGN = next(p for p in gate_probe.GATE_PROBES if p.expect == gate_probe.EXPECT_ALLOWED)


# ---------------------------------------------------------------------------
# Layer 1 -- the outcome table (pure, no subprocess)
# ---------------------------------------------------------------------------

class TestClassifyProbeOutput(unittest.TestCase):

    def _classify(self, stdout, probe=_DESTRUCTIVE, environment="production"):
        return gate_probe.classify_probe_output(probe, stdout, environment)

    def test_allow_on_destructive_production_payload_is_a_failure(self):
        r = self._classify(_hook_stdout("allow", "reeflex.policy/default_allow"))
        self.assertEqual(r.outcome, gate_probe.OUTCOME_UNEXPECTED_ALLOW)
        self.assertTrue(r.is_failure)

    def test_ask_from_the_policy_pack_is_a_pass(self):
        r = self._classify(_hook_stdout("ask", "reeflex.policy/irreversible_broad_prod"))
        self.assertEqual(r.outcome, gate_probe.OUTCOME_PASS)
        self.assertFalse(r.is_failure)

    def test_deny_from_the_policy_pack_is_a_pass(self):
        r = self._classify(_hook_stdout("deny", "reeflex.policy/irreversible_systemic"))
        self.assertEqual(r.outcome, gate_probe.OUTCOME_PASS)

    def test_fail_closed_deny_is_not_evidence_about_the_gate(self):
        """The deny that proves nothing: an unreachable core denies everything."""
        r = self._classify(_hook_stdout(
            "deny", "reeflex.core/fail_closed",
            prefix="Reeflex: core unreachable or error -- failing closed",
        ))
        self.assertEqual(r.outcome, gate_probe.OUTCOME_NOT_EXERCISED)
        self.assertFalse(r.is_failure)
        self.assertFalse(r.is_gate_evidence)

    def test_adapter_level_deny_is_not_evidence_about_the_gate(self):
        r = self._classify(_hook_stdout("deny", "adapter/unsupported_obligation"))
        self.assertEqual(r.outcome, gate_probe.OUTCOME_NOT_EXERCISED)
        self.assertFalse(r.is_gate_evidence)

    def test_observe_mode_allow_is_not_enforced_not_a_pass_and_not_a_failure(self):
        stdout = json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": (
                "Reeflex observe -- would be 'ask' Reeflex: approval required "
                "[rule=reeflex.policy/irreversible_broad_prod]; not enforced (observe mode)"
            ),
        }})
        r = self._classify(stdout)
        self.assertEqual(r.outcome, gate_probe.OUTCOME_NOT_ENFORCED)
        self.assertFalse(r.is_failure)
        self.assertFalse(r.is_gate_evidence)

    def test_non_production_environment_is_not_asserted_rather_than_failed(self):
        r = self._classify(_hook_stdout("allow", "reeflex.policy/default_allow"),
                           environment="dev")
        self.assertEqual(r.outcome, gate_probe.OUTCOME_NOT_ASSERTED)
        self.assertFalse(r.is_failure)
        self.assertIn("'dev'", r.detail)

    def test_benign_control_allowed_is_a_pass(self):
        r = self._classify(_hook_stdout("allow", "reeflex.policy/read_only_internal"),
                           probe=_BENIGN)
        self.assertEqual(r.outcome, gate_probe.OUTCOME_PASS)

    def test_benign_control_denied_warns_but_does_not_fail(self):
        """An operator running a stricter pack must not have their check fail."""
        r = self._classify(_hook_stdout("deny", "reeflex.policy/custom_paranoid"),
                           probe=_BENIGN)
        self.assertEqual(r.outcome, gate_probe.OUTCOME_OVER_STRICT)
        self.assertFalse(r.is_failure)

    def test_unparseable_stdout_is_an_error(self):
        r = self._classify("not json at all")
        self.assertEqual(r.outcome, gate_probe.OUTCOME_ERROR)
        self.assertTrue(r.is_failure)

    def test_corpus_has_a_benign_control_and_several_destructive_probes(self):
        expects = [p.expect for p in gate_probe.GATE_PROBES]
        self.assertIn(gate_probe.EXPECT_ALLOWED, expects,
                      "without a benign control, a gate that denies everything passes")
        self.assertGreaterEqual(expects.count(gate_probe.EXPECT_GATED), 5)
        self.assertEqual(len(set(p.name for p in gate_probe.GATE_PROBES)),
                         len(gate_probe.GATE_PROBES), "probe names must be unique")


# ---------------------------------------------------------------------------
# Layer 1b -- effective configuration
# ---------------------------------------------------------------------------

class TestEffectiveConfig(unittest.TestCase):

    def test_settings_env_overlay_takes_known_string_keys_only(self):
        overlay = gate_probe.settings_env_overlay({"env": {
            "REEFLEX_CORE_URL": "https://core.example",
            "REEFLEX_MODE": "observe",
            "SOMETHING_ELSE": "ignored",
            "REEFLEX_CLAUDE_TIMEOUT": 5,          # not a string -> ignored
        }})
        self.assertEqual(overlay, {
            "REEFLEX_CORE_URL": "https://core.example",
            "REEFLEX_MODE": "observe",
        })

    def test_settings_env_overlay_tolerates_missing_or_malformed_env(self):
        self.assertEqual(gate_probe.settings_env_overlay({}), {})
        self.assertEqual(gate_probe.settings_env_overlay({"env": "nope"}), {})

    def test_settings_env_wins_over_shell_env_because_claude_code_applies_it(self):
        env = gate_probe.build_probe_env({"REEFLEX_CORE_URL": "https://from-settings"})
        self.assertEqual(gate_probe.effective_core_url(env), "https://from-settings")

    def test_mode_and_environment_mirror_the_hook_defaults(self):
        self.assertEqual(gate_probe.effective_mode({}), "enforce")
        self.assertEqual(gate_probe.effective_mode({"REEFLEX_MODE": "OBSERVE"}), "observe")
        self.assertEqual(gate_probe.effective_environment({}), "production")
        self.assertEqual(
            gate_probe.effective_environment({"REEFLEX_CLAUDE_ENVIRONMENT": "nonsense"}),
            "production", "an unrecognised environment must fall back to production")


# ---------------------------------------------------------------------------
# Layer 2 -- aggregation and exit codes, via a STUB hook (no core needed)
# ---------------------------------------------------------------------------

def _write_stub_hook(tmpdir, decision, rule, prefix="Reeflex: synthetic"):
    """
    A hook that answers every payload with one canned verdict, exits 0, and
    speaks the real hookSpecificOutput contract.
    """
    script = Path(tmpdir) / "stub_hook.py"
    script.write_text(
        "import json, sys\n"
        "sys.stdin.read()\n"
        "print(json.dumps({'hookSpecificOutput': {\n"
        "  'hookEventName': 'PreToolUse',\n"
        f"  'permissionDecision': {decision!r},\n"
        f"  'permissionDecisionReason': {prefix + ' [rule=' + rule + ']'!r},\n"
        "}}))\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)]


class TestGateStageAggregation(unittest.TestCase):

    def test_a_permissive_core_makes_the_stage_fail(self):
        with tempfile.TemporaryDirectory() as d:
            hook = _write_stub_hook(d, "allow", "reeflex.policy/default_allow")
            verdict, headline, results = _gate_stage(hook, None)
        self.assertEqual(verdict, "fail")
        self.assertIn("ALLOWED", headline)
        self.assertEqual(
            sum(1 for r in results if r.outcome == gate_probe.OUTCOME_UNEXPECTED_ALLOW),
            sum(1 for p in gate_probe.GATE_PROBES if p.expect == gate_probe.EXPECT_GATED),
        )

    def test_a_gating_core_makes_the_stage_pass(self):
        """The check must be able to go GREEN -- otherwise it is a hardcoded FAIL."""
        with tempfile.TemporaryDirectory() as d:
            # 'ask' for everything: destructive probes gated, benign control
            # over-strict (a warning, not a failure).
            hook = _write_stub_hook(d, "ask", "reeflex.policy/irreversible_broad_prod")
            verdict, headline, results = _gate_stage(hook, None)
        self.assertEqual(verdict, "pass", headline)
        self.assertIn("gate verified", headline)
        self.assertEqual(
            [r.outcome for r in results if r.probe.expect == gate_probe.EXPECT_GATED],
            [gate_probe.OUTCOME_PASS] * 6,
        )

    def test_an_unreachable_core_leaves_the_gate_unverified_not_passed(self):
        with tempfile.TemporaryDirectory() as d:
            hook = _write_stub_hook(
                d, "deny", "reeflex.core/fail_closed",
                prefix="Reeflex: core unreachable or error -- failing closed",
            )
            verdict, headline, _ = _gate_stage(hook, None)
        self.assertEqual(verdict, "unverified", headline)
        self.assertIn("NOT VERIFIED", headline)

    def test_a_hook_that_exits_nonzero_is_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "broken.py"
            script.write_text("import sys; sys.stdin.read(); sys.exit(3)\n", encoding="utf-8")
            verdict, headline, _ = _gate_stage([sys.executable, str(script)], None)
        self.assertEqual(verdict, "fail", headline)


# ---------------------------------------------------------------------------
# Layer 2b -- the CLI contract, including that --require-gate MOVES a verdict
# ---------------------------------------------------------------------------

def _run_check(args, cwd, extra_env=None):
    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = _PARENT + (os.pathsep + existing_pp if existing_pp else "")
    env["REEFLEX_CORE_URL"] = _UNREACHABLE_CORE
    env.pop("REEFLEX_MODE", None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-m", "reeflex_claude.cli", "check"] + args,
        cwd=cwd, input="", capture_output=True, text=True,
        timeout=_SUBPROCESS_TIMEOUT, env=env,
    )
    return proc.stdout, proc.stderr, proc.returncode


class TestCheckCliGateStatement(unittest.TestCase):

    def test_check_always_prints_a_gate_statement(self):
        """No run may leave the reader thinking the gate was verified."""
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_check(["--project"], cwd=d)
        self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("PASS -- fail-closed verified", stdout)
        self.assertIn("GATE NOT VERIFIED", stdout)

    def test_require_gate_changes_the_exit_code_on_the_same_installation(self):
        """
        Anti-RFX-145: a documented knob that cannot move an outcome is a
        defect. Same install, same core, one flag -> different exit code.
        """
        with tempfile.TemporaryDirectory() as d:
            _, _, without = _run_check(["--project"], cwd=d)
            stdout, stderr, with_flag = _run_check(["--project", "--require-gate"], cwd=d)
        self.assertEqual(without, 0)
        self.assertEqual(with_flag, 1, f"stdout={stdout}\nstderr={stderr}")

    def test_skip_gate_says_so_rather_than_implying_a_verified_gate(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_check(["--project", "--skip-gate"], cwd=d)
        self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("GATE NOT CHECKED", stdout)
        self.assertNotIn("gate verified", stdout)

    def test_skip_gate_with_require_gate_still_fails(self):
        with tempfile.TemporaryDirectory() as d:
            _, _, code = _run_check(["--project", "--skip-gate", "--require-gate"], cwd=d)
        self.assertEqual(code, 1)

    def test_observe_mode_is_reported_and_does_not_claim_a_verified_gate(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_check(
                ["--project"], cwd=d, extra_env={"REEFLEX_MODE": "observe"})
        self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
        self.assertIn("mode        : observe", stdout)
        self.assertNotIn("PASS -- gate verified", stdout)

    def test_settings_env_block_is_reported_as_the_probed_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / ".claude"
            claude.mkdir(parents=True)
            (claude / "settings.json").write_text(json.dumps({
                "env": {"REEFLEX_CORE_URL": "http://127.0.0.1:2",
                        "REEFLEX_CLAUDE_ENVIRONMENT": "staging"},
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "reeflex-claude hook", "timeout": 30}]}]},
            }), encoding="utf-8")
            stdout, stderr, code = _run_check(["--project"], cwd=d)
        self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
        # The settings block, not the shell's REEFLEX_CORE_URL, is what the
        # hook will run under -- so it is what check must probe and print.
        self.assertIn("core url    : http://127.0.0.1:2", stdout)
        self.assertIn("environment : staging", stdout)


if __name__ == "__main__":
    unittest.main()
