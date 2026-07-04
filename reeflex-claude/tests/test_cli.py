"""
test_cli.py -- Tests for reeflex_claude.cli: `setup` and `check` subcommands.

Two layers:
  1. Direct unit tests of cli.run_deny_probe() with injected hook commands --
     fast, hermetic, no subprocess-of-a-subprocess PATH dependencies.
  2. End-to-end subprocess tests of `python -m reeflex_claude.cli ...` --
     mirrors what the installed `reeflex-claude` console script does, run
     with an isolated cwd (for --project) and PYTHONPATH (so the package is
     importable without a real pip install), so no test ever writes into the
     real repository's .claude/ directory.

All subprocess calls pass an explicit timeout and redirect stdin through a
pipe (input=...), so stdin is never a TTY inside the child -- the interactive
prompt fallback in cli.py cannot trigger and no test can hang on input().
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.cli import resolve_hook_command, run_deny_probe
from reeflex_claude.setup_settings import DEFAULT_MATCHER, DEFAULT_TIMEOUT, HOOK_COMMAND, is_ours

_SUBPROCESS_TIMEOUT = 20


def _run_cli(args, cwd, extra_env=None):
    """
    Run `python -m reeflex_claude.cli <args>` with cwd isolated from the real
    reeflex-claude checkout, but with the package importable via PYTHONPATH.
    Returns (stdout, stderr, returncode).
    """
    env = dict(os.environ)
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = _PARENT + (os.pathsep + existing_pp if existing_pp else "")
    if extra_env:
        env.update(extra_env)

    proc = subprocess.run(
        [sys.executable, "-m", "reeflex_claude.cli"] + args,
        cwd=cwd,
        input="",              # never a TTY -> no interactive prompt can trigger
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        env=env,
    )
    return proc.stdout, proc.stderr, proc.returncode


# ---------------------------------------------------------------------------
# run_deny_probe -- direct unit tests (broken / healthy hook commands)
# ---------------------------------------------------------------------------

class TestRunDenyProbe(unittest.TestCase):

    def test_healthy_hook_via_module_fallback_passes(self):
        """The real hook module, invoked the same way resolve_hook_command()
        falls back to when the console script is not on PATH, must PASS
        (core forced unreachable inside run_deny_probe -> fail-closed deny)."""
        hook_cmd = [sys.executable, "-m", "reeflex_claude.cli", "hook"]
        env = dict(os.environ)
        env["PYTHONPATH"] = _PARENT
        # run_deny_probe builds its own env from os.environ; patch os.environ
        # for the duration of the call so the child inherits PYTHONPATH.
        old = os.environ.get("PYTHONPATH")
        os.environ["PYTHONPATH"] = _PARENT
        try:
            passed, detail = run_deny_probe(hook_cmd)
        finally:
            if old is None:
                os.environ.pop("PYTHONPATH", None)
            else:
                os.environ["PYTHONPATH"] = old
        self.assertTrue(passed, detail)
        self.assertIn("fail-closed verified", detail)

    def test_resolve_hook_command_fallback_shape_when_not_on_path(self):
        """When 'reeflex-claude' is not resolvable via PATH, fall back to the
        -m reeflex_claude.cli invocation (same code path, no PATH dependency)."""
        import shutil
        which_orig = shutil.which
        try:
            shutil.which = lambda name: None  # noqa: E731 - force "not found"
            cmd = resolve_hook_command()
        finally:
            shutil.which = which_orig
        self.assertEqual(cmd, [sys.executable, "-m", "reeflex_claude.cli", "hook"])

    def test_missing_binary_fails_with_remediation(self):
        passed, detail = run_deny_probe(["definitely-not-a-real-reeflex-claude-binary-xyz"])
        self.assertFalse(passed)
        self.assertIn("not found", detail)

    def test_nonzero_exit_fails_as_fail_open(self):
        broken = [sys.executable, "-c", "import sys; sys.exit(3)"]
        passed, detail = run_deny_probe(broken)
        self.assertFalse(passed)
        self.assertIn("fail-open", detail)
        self.assertIn("exited 3", detail)

    def test_malformed_stdout_fails(self):
        broken = [sys.executable, "-c", "print('not json at all')"]
        passed, detail = run_deny_probe(broken)
        self.assertFalse(passed)
        self.assertIn("could not parse", detail)

    def test_wrong_decision_fails(self):
        broken = [sys.executable, "-c",
                  "import json; print(json.dumps({'hookSpecificOutput': "
                  "{'hookEventName': 'PreToolUse', 'permissionDecision': 'allow', "
                  "'permissionDecisionReason': 'stub'}}))"]
        passed, detail = run_deny_probe(broken)
        self.assertFalse(passed)
        self.assertIn("permissionDecision='allow'", detail)


# ---------------------------------------------------------------------------
# setup -- end-to-end subprocess tests
# ---------------------------------------------------------------------------

class TestCliSetup(unittest.TestCase):

    def test_setup_writes_fresh_settings_json(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_cli(
                ["setup", "--project", "--core-url", "http://127.0.0.1:9000",
                 "--mode", "enforce", "--verify-ssl", "true", "--env", "production"],
                cwd=d,
            )
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")

            settings_path = Path(d) / ".claude" / "settings.json"
            self.assertTrue(settings_path.exists())
            data = json.loads(settings_path.read_text(encoding="utf-8"))

            pretool = data["hooks"]["PreToolUse"]
            self.assertEqual(len(pretool), 1)
            self.assertEqual(pretool[0]["matcher"], DEFAULT_MATCHER)
            self.assertEqual(pretool[0]["hooks"], [
                {"type": "command", "command": HOOK_COMMAND, "timeout": DEFAULT_TIMEOUT}
            ])
            self.assertEqual(data["env"]["REEFLEX_CORE_URL"], "http://127.0.0.1:9000")
            self.assertEqual(data["env"]["REEFLEX_MODE"], "enforce")
            self.assertEqual(data["env"]["REEFLEX_CLAUDE_ENVIRONMENT"], "production")
            self.assertEqual(data["env"]["REEFLEX_VERIFY_SSL"], "true")
            self.assertNotIn("REEFLEX_CORE_TOKEN", data["env"], "no --token given -> not written")

            self.assertIn("Now run: reeflex-claude check", stdout)

    def test_setup_writes_token_with_warning(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_cli(
                ["setup", "--project", "--token", "synthetic-test-token-not-a-secret"],
                cwd=d,
            )
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
            data = json.loads((Path(d) / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(data["env"]["REEFLEX_CORE_TOKEN"], "synthetic-test-token-not-a-secret")
            self.assertIn("PLAINTEXT", stdout)
            # the raw token is never echoed in cli's own "what was written" line
            printed_env_line = [l for l in stdout.splitlines() if "env:" in l][0]
            self.assertNotIn("synthetic-test-token-not-a-secret", printed_env_line)

    def test_setup_merges_into_existing_settings_without_losing_foreign_keys(self):
        with tempfile.TemporaryDirectory() as d:
            claude_dir = Path(d) / ".claude"
            claude_dir.mkdir(parents=True)
            existing = {
                "permissions": {"allow": ["Bash(ls:*)"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "SomeOtherTool",
                         "hooks": [{"type": "command", "command": "echo hi", "timeout": 5}]}
                    ]
                },
                "env": {"FOO": "bar"},
            }
            (claude_dir / "settings.json").write_text(json.dumps(existing), encoding="utf-8")

            stdout, stderr, code = _run_cli(
                ["setup", "--project", "--core-url", "http://example:9000",
                 "--mode", "observe", "--verify-ssl", "false", "--env", "staging"],
                cwd=d,
            )
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")

            data = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))

            # Foreign keys preserved byte-for-byte in value
            self.assertEqual(data["permissions"], {"allow": ["Bash(ls:*)"]})
            self.assertEqual(data["env"]["FOO"], "bar")

            pretool = data["hooks"]["PreToolUse"]
            self.assertEqual(len(pretool), 2, "foreign block preserved, ours appended")
            self.assertEqual(pretool[0]["matcher"], "SomeOtherTool")
            self.assertEqual(pretool[0]["hooks"], [{"type": "command", "command": "echo hi", "timeout": 5}])
            self.assertTrue(is_ours(pretool[1]["hooks"][0]["command"]))

            self.assertEqual(data["env"]["REEFLEX_CORE_URL"], "http://example:9000")
            self.assertEqual(data["env"]["REEFLEX_MODE"], "observe")
            self.assertEqual(data["env"]["REEFLEX_CLAUDE_ENVIRONMENT"], "staging")
            self.assertEqual(data["env"]["REEFLEX_VERIFY_SSL"], "false")

    def test_setup_rerun_updates_in_place_not_duplicated(self):
        with tempfile.TemporaryDirectory() as d:
            _run_cli(["setup", "--project", "--core-url", "http://old:1"], cwd=d)
            stdout, stderr, code = _run_cli(
                ["setup", "--project", "--core-url", "http://new:2"], cwd=d
            )
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
            data = json.loads((Path(d) / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data["hooks"]["PreToolUse"]), 1, "must not duplicate on rerun")
            self.assertEqual(data["env"]["REEFLEX_CORE_URL"], "http://new:2")
            self.assertIn("Updated existing", stdout)

    def test_setup_refuses_corrupt_json_without_destructive_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            claude_dir = Path(d) / ".claude"
            claude_dir.mkdir(parents=True)
            settings_path = claude_dir / "settings.json"
            corrupt_text = "{not valid json at all"
            settings_path.write_text(corrupt_text, encoding="utf-8")

            stdout, stderr, code = _run_cli(
                ["setup", "--project", "--core-url", "http://127.0.0.1:9000"], cwd=d
            )
            self.assertEqual(code, 1)
            self.assertIn("refusing to modify", stderr.lower())

            # File must be byte-identical to before -- no destructive fallback.
            self.assertEqual(settings_path.read_text(encoding="utf-8"), corrupt_text)

    def test_setup_global_target_writes_under_home(self):
        with tempfile.TemporaryDirectory() as home_dir:
            with tempfile.TemporaryDirectory() as cwd_dir:
                stdout, stderr, code = _run_cli(
                    ["setup", "--global", "--core-url", "http://127.0.0.1:9000"],
                    cwd=cwd_dir,
                    extra_env={"HOME": home_dir, "USERPROFILE": home_dir},
                )
                self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
                global_path = Path(home_dir) / ".claude" / "settings.json"
                self.assertTrue(global_path.exists())
                # Must NOT have written into the project cwd
                self.assertFalse((Path(cwd_dir) / ".claude" / "settings.json").exists())


# ---------------------------------------------------------------------------
# check -- end-to-end subprocess tests
# ---------------------------------------------------------------------------

class TestCliCheck(unittest.TestCase):

    def test_check_passes_on_healthy_install_no_settings_file(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr, code = _run_cli(["check", "--project"], cwd=d)
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
            self.assertIn("PASS -- fail-closed verified", stdout)
            self.assertIn("not found", stdout)  # NOTE about missing settings.json

    def test_check_passes_and_confirms_settings_after_setup(self):
        with tempfile.TemporaryDirectory() as d:
            _run_cli(["setup", "--project"], cwd=d)
            stdout, stderr, code = _run_cli(["check", "--project"], cwd=d)
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
            self.assertIn("PASS -- fail-closed verified", stdout)
            self.assertIn("settings OK", stdout)

    def test_check_warns_when_settings_present_but_hook_missing(self):
        with tempfile.TemporaryDirectory() as d:
            claude_dir = Path(d) / ".claude"
            claude_dir.mkdir(parents=True)
            (claude_dir / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}}),
                                                        encoding="utf-8")
            stdout, stderr, code = _run_cli(["check", "--project"], cwd=d)
            self.assertEqual(code, 0, f"stdout={stdout}\nstderr={stderr}")
            self.assertIn("PASS -- fail-closed verified", stdout)
            self.assertIn("does not contain a reeflex-claude PreToolUse hook entry", stdout)


if __name__ == "__main__":
    unittest.main()
