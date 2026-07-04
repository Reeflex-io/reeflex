"""
test_setup_settings.py -- Unit tests for reeflex_claude.setup_settings.

Pure logic tests (no subprocess, no network): load/merge/write of Claude Code
settings.json. Uses tempfile.TemporaryDirectory() for filesystem isolation;
no real ~/.claude or ./.claude is touched.
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

from reeflex_claude.setup_settings import (
    DEFAULT_MATCHER,
    DEFAULT_TIMEOUT,
    HOOK_COMMAND,
    SettingsError,
    has_hook_entry,
    is_ours,
    load_settings,
    merge_env,
    merge_hook_entry,
    write_settings,
)


class TestIsOurs(unittest.TestCase):

    def test_matches_our_command(self):
        self.assertTrue(is_ours("reeflex-claude hook"))

    def test_matches_our_command_with_extra_args(self):
        self.assertTrue(is_ours("reeflex-claude hook --verbose"))

    def test_does_not_match_foreign_command(self):
        self.assertFalse(is_ours("echo hi"))

    def test_non_string_is_not_ours(self):
        self.assertFalse(is_ours(None))
        self.assertFalse(is_ours(123))


class TestLoadSettings(unittest.TestCase):

    def test_missing_file_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            self.assertEqual(load_settings(path), {})

    def test_empty_file_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            path.write_text("", encoding="utf-8")
            self.assertEqual(load_settings(path), {})

    def test_whitespace_only_file_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            path.write_text("   \n  ", encoding="utf-8")
            self.assertEqual(load_settings(path), {})

    def test_valid_json_object_is_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
            self.assertEqual(load_settings(path), {"foo": "bar"})

    def test_corrupt_json_raises_settings_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(SettingsError):
                load_settings(path)

    def test_non_object_top_level_raises_settings_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            path.write_text(json.dumps(["a", "list", "not", "an", "object"]), encoding="utf-8")
            with self.assertRaises(SettingsError):
                load_settings(path)


class TestMergeHookEntry(unittest.TestCase):

    def test_appends_when_absent_fresh_settings(self):
        settings = {}
        replaced = merge_hook_entry(settings)
        self.assertFalse(replaced)
        pretool = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(pretool), 1)
        self.assertEqual(pretool[0]["matcher"], DEFAULT_MATCHER)
        self.assertEqual(pretool[0]["hooks"], [
            {"type": "command", "command": HOOK_COMMAND, "timeout": DEFAULT_TIMEOUT}
        ])

    def test_replaces_existing_entry_in_place(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "OldMatcher",
                        "hooks": [{"type": "command", "command": "reeflex-claude hook", "timeout": 5}],
                    }
                ]
            }
        }
        replaced = merge_hook_entry(settings)
        self.assertTrue(replaced)
        pretool = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(pretool), 1, "must not duplicate -- update in place")
        self.assertEqual(pretool[0]["matcher"], DEFAULT_MATCHER)
        self.assertEqual(pretool[0]["hooks"][0]["timeout"], DEFAULT_TIMEOUT)
        self.assertEqual(pretool[0]["hooks"][0]["command"], HOOK_COMMAND)

    def test_preserves_foreign_blocks_and_keys(self):
        settings = {
            "permissions": {"allow": ["Bash(ls:*)"]},
            "model": "some-model",
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "SomeOtherTool",
                        "hooks": [{"type": "command", "command": "echo hi", "timeout": 5}],
                    }
                ]
            },
        }
        replaced = merge_hook_entry(settings)
        self.assertFalse(replaced)

        # Foreign top-level keys untouched
        self.assertEqual(settings["permissions"], {"allow": ["Bash(ls:*)"]})
        self.assertEqual(settings["model"], "some-model")

        # Foreign PreToolUse block untouched
        pretool = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(pretool), 2)
        self.assertEqual(pretool[0]["matcher"], "SomeOtherTool")
        self.assertEqual(pretool[0]["hooks"], [{"type": "command", "command": "echo hi", "timeout": 5}])

        # Our new block appended
        self.assertEqual(pretool[1]["matcher"], DEFAULT_MATCHER)
        self.assertTrue(is_ours(pretool[1]["hooks"][0]["command"]))

    def test_raises_if_hooks_key_wrong_type(self):
        settings = {"hooks": "not-an-object"}
        with self.assertRaises(SettingsError):
            merge_hook_entry(settings)

    def test_raises_if_pretooluse_key_wrong_type(self):
        settings = {"hooks": {"PreToolUse": "not-a-list"}}
        with self.assertRaises(SettingsError):
            merge_hook_entry(settings)


class TestHasHookEntry(unittest.TestCase):

    def test_false_on_empty_settings(self):
        self.assertFalse(has_hook_entry({}))

    def test_true_after_merge(self):
        settings = {}
        merge_hook_entry(settings)
        self.assertTrue(has_hook_entry(settings))

    def test_false_when_only_foreign_hooks_present(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "X", "hooks": [{"type": "command", "command": "echo hi", "timeout": 5}]}
                ]
            }
        }
        self.assertFalse(has_hook_entry(settings))


class TestMergeEnv(unittest.TestCase):

    def test_creates_env_block_when_absent(self):
        settings = {}
        merge_env(settings, {"REEFLEX_CORE_URL": "http://x"})
        self.assertEqual(settings["env"], {"REEFLEX_CORE_URL": "http://x"})

    def test_preserves_foreign_env_keys(self):
        settings = {"env": {"FOO": "bar"}}
        merge_env(settings, {"REEFLEX_CORE_URL": "http://x"})
        self.assertEqual(settings["env"], {"FOO": "bar", "REEFLEX_CORE_URL": "http://x"})

    def test_overwrites_only_our_keys_on_rerun(self):
        settings = {"env": {"FOO": "bar", "REEFLEX_CORE_URL": "http://old"}}
        merge_env(settings, {"REEFLEX_CORE_URL": "http://new"})
        self.assertEqual(settings["env"], {"FOO": "bar", "REEFLEX_CORE_URL": "http://new"})

    def test_raises_if_env_key_wrong_type(self):
        settings = {"env": "not-an-object"}
        with self.assertRaises(SettingsError):
            merge_env(settings, {"REEFLEX_CORE_URL": "http://x"})


class TestWriteSettings(unittest.TestCase):

    def test_creates_parent_dirs_and_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nested" / "dir" / "settings.json"
            write_settings(path, {"hello": "world"})
            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"hello": "world"})

    def test_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "settings.json"
            write_settings(path, {"a": 1})
            write_settings(path, {"b": 2})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"b": 2})


if __name__ == "__main__":
    unittest.main()
