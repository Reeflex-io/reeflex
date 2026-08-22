"""
Regression tests for qa--032: the wired PreToolUse hook must be able to see, and
able to start.

Two independent silent-allow bypasses were measured on a REAL Claude Code
(2.1.240) driving the published reeflex-claude 0.1.7 in enforce mode against a
healthy core, with REEFLEX_CLAUDE_ENVIRONMENT=production:

  1. MATCHER IS AN ALLOWLIST. `setup` wrote
     "Bash|Write|Edit|MultiEdit|Read|Glob|Grep|LS|NotebookEdit|WebFetch|WebSearch".
     Claude Code only invokes the hook for tools whose name matches, so an
     `mcp__*` tool reached no gate at all: an agent performed an irreversible
     "delete 40,000 production rows" MCP call and the adapter produced ZERO
     envelopes, ZERO decisions and ZERO audit records -- in the same session
     where `echo hello` was denied. With the matcher set to "*" the same tool
     produced an audit record and a /v1/decide call.

  2. BARE HOOK COMMAND. `setup` wrote the bare name `reeflex-claude hook`, but a
     PreToolUse hook is spawned with the PATH of the shell that launched Claude
     Code -- not the virtualenv pip installed into. Unresolvable -> non-zero exit
     -> Claude Code runs the tool anyway, silently (measured: 3 debug lines, no
     mention of the hook). `reeflex-claude check` could not catch this because it
     probed a command it resolved ITSELF, which the installing shell can always
     resolve -- so its FileNotFoundError branch was unreachable in the one
     situation it was written for.

These tests pin the properties, not the strings.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.setup_settings import (  # noqa: E402
    DEFAULT_MATCHER,
    hook_command_for_settings,
    is_ours,
    merge_hook_entry,
    wired_hook_command,
)

_SUBPROCESS_TIMEOUT = 20

# Tool names that exist in Claude Code but are absent from the 0.1.7 allowlist.
# Every one of them can carry an irreversible production action.
UNLISTED_BUT_DANGEROUS = [
    "mcp__db__delete_production_rows",
    "mcp__stripe__refund_all_charges",
    "mcp__k8s__delete_namespace",
    "Task",
    "SlashCommand",
    "Skill",
    "KillShell",
    "ToolSearch",
]

_OLD_ALLOWLIST = (
    "Bash|Write|Edit|MultiEdit|Read|Glob|Grep|LS|NotebookEdit|WebFetch|WebSearch"
)


def _run_cli(args, cwd, extra_env=None):
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = _PARENT + (os.pathsep + existing if existing else "")
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-m", "reeflex_claude.cli"] + args,
        cwd=cwd, input="", capture_output=True, text=True,
        timeout=_SUBPROCESS_TIMEOUT, env=env,
    )
    return proc.stdout, proc.stderr, proc.returncode


def _matches(matcher: str, tool_name: str) -> bool:
    """
    Does Claude Code invoke a hook wired with `matcher` for `tool_name`?

    "*" is the wildcard. Anything else is treated as a regex alternation of tool
    names -- which is the whole problem: it can only ever list what we thought of.
    """
    if matcher == "*":
        return True
    import re
    return re.search(matcher, tool_name) is not None


class TestMatcherIsNotAnAllowlist(unittest.TestCase):

    def test_default_matcher_covers_tools_we_have_never_seen(self):
        """The gate cannot be enumerated in advance. FAILS on 0.1.7."""
        for tool in UNLISTED_BUT_DANGEROUS:
            self.assertTrue(
                _matches(DEFAULT_MATCHER, tool),
                f"{tool!r} does not match DEFAULT_MATCHER {DEFAULT_MATCHER!r}, so "
                "Claude Code never invokes the hook for it: no envelope, no "
                "decision, no audit record.",
            )

    def test_the_old_allowlist_really_did_miss_them(self):
        """Guards the test above against becoming vacuous."""
        for tool in UNLISTED_BUT_DANGEROUS:
            self.assertFalse(
                _matches(_OLD_ALLOWLIST, tool),
                f"{tool!r} unexpectedly matches the 0.1.7 allowlist; this test's "
                "premise is wrong and the fixture needs revisiting.",
            )

    def test_setup_wires_the_wildcard_matcher(self):
        with tempfile.TemporaryDirectory() as d:
            _, stderr, code = _run_cli(["setup", "--project"], cwd=d)
            self.assertEqual(code, 0, stderr)
            data = json.loads(
                (Path(d) / ".claude" / "settings.json").read_text(encoding="utf-8")
            )
            self.assertEqual(data["hooks"]["PreToolUse"][0]["matcher"], "*")


class TestWiredCommandCanActuallyStart(unittest.TestCase):

    def test_hook_command_for_settings_is_absolute(self):
        """FAILS on 0.1.7, where setup wired the bare console-script name."""
        cmd = hook_command_for_settings()
        argv0 = cmd.split()[0].strip("'\"")
        self.assertTrue(
            os.path.isabs(argv0),
            f"hook argv[0] {argv0!r} is not absolute; it would be resolved against "
            "the PATH of whatever shell launches Claude Code.",
        )

    def test_setup_writes_a_command_that_resolves(self):
        with tempfile.TemporaryDirectory() as d:
            _, stderr, code = _run_cli(["setup", "--project"], cwd=d)
            self.assertEqual(code, 0, stderr)
            data = json.loads(
                (Path(d) / ".claude" / "settings.json").read_text(encoding="utf-8")
            )
            wired = wired_hook_command(data)
            self.assertIsNotNone(wired)
            argv0 = wired.split()[0].strip("'\"")
            self.assertTrue(
                os.path.isfile(argv0) and os.access(argv0, os.X_OK),
                f"wired argv[0] {argv0!r} is not an executable file",
            )

    def test_check_fails_when_the_wired_command_cannot_start(self):
        """
        The core regression. A settings.json whose hook command does not exist
        is indistinguishable, at runtime, from having no gate at all -- so
        `check` must NOT report PASS. FAILS on 0.1.7 (exit 0, "PASS").
        """
        with tempfile.TemporaryDirectory() as d:
            claude_dir = Path(d) / ".claude"
            claude_dir.mkdir()
            (claude_dir / "settings.json").write_text(json.dumps({
                "hooks": {"PreToolUse": [{
                    "matcher": "*",
                    "hooks": [{
                        "type": "command",
                        # absolute, ours by marker, and certainly not present
                        "command": "/nonexistent/qa032/bin/reeflex-claude hook",
                        "timeout": 30,
                    }],
                }]},
            }), encoding="utf-8")

            stdout, _, code = _run_cli(["check", "--project"], cwd=d)
            self.assertNotEqual(code, 0, f"check reported success:\n{stdout}")
            self.assertIn("FAIL", stdout)
            self.assertIn("/nonexistent/qa032/bin/reeflex-claude", stdout)

    def test_check_warns_when_the_matcher_is_narrowed(self):
        with tempfile.TemporaryDirectory() as d:
            _run_cli(["setup", "--project"], cwd=d)
            path = Path(d) / ".claude" / "settings.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["hooks"]["PreToolUse"][0]["matcher"] = _OLD_ALLOWLIST
            path.write_text(json.dumps(data), encoding="utf-8")

            stdout, _, code = _run_cli(["check", "--project"], cwd=d)
            self.assertEqual(code, 0, "a narrowed matcher is a warning, not a failure")
            self.assertIn("allowlist", stdout)


class TestUpgradeFromTheBareForm(unittest.TestCase):
    """A 0.1.7 user re-running `setup` must end up with ONE hook, not two."""

    def test_is_ours_recognises_every_form_we_have_written(self):
        self.assertTrue(is_ours("reeflex-claude hook"))
        self.assertTrue(is_ours("/opt/venv/bin/reeflex-claude hook"))
        self.assertTrue(is_ours("'/opt/my venv/bin/reeflex-claude' hook"))
        self.assertTrue(is_ours("/usr/bin/python3 -m reeflex_claude.cli hook"))
        self.assertFalse(is_ours("some-other-tool hook"))
        self.assertFalse(is_ours(None))
        self.assertFalse(is_ours("reeflex-claude setup"))

    def test_setup_updates_a_bare_entry_in_place(self):
        settings = {"hooks": {"PreToolUse": [{
            "matcher": _OLD_ALLOWLIST,
            "hooks": [{"type": "command", "command": "reeflex-claude hook", "timeout": 30}],
        }]}}
        replaced = merge_hook_entry(settings)
        self.assertTrue(replaced, "must update the old entry, not append beside it")
        pretool = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(pretool), 1)
        self.assertEqual(len(pretool[0]["hooks"]), 1)
        self.assertEqual(pretool[0]["matcher"], "*")

    def test_setup_updates_a_module_form_entry_in_place(self):
        settings = {"hooks": {"PreToolUse": [{
            "matcher": "*",
            "hooks": [{"type": "command",
                       "command": "/usr/bin/python3.12 -m reeflex_claude.cli hook",
                       "timeout": 30}],
        }]}}
        replaced = merge_hook_entry(settings)
        self.assertTrue(replaced)
        self.assertEqual(len(settings["hooks"]["PreToolUse"]), 1)


if __name__ == "__main__":
    unittest.main()
