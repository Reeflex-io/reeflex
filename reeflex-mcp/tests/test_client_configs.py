"""
test_client_configs.py -- unit tests for reeflex_mcp.client_configs (Track 5,
design doc section 13): load/write, backup/restore, ownership marker.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reeflex_mcp import client_configs


def _tmp_json_path(data=None) -> Path:
    tmpdir = tempfile.mkdtemp()
    path = Path(tmpdir) / "config.json"
    if data is not None:
        path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestLoadClientConfig(unittest.TestCase):
    def test_missing_file_returns_empty_dict(self) -> None:
        path = Path(tempfile.mkdtemp()) / "does-not-exist.json"
        self.assertEqual(client_configs.load_client_config(path), {})

    def test_empty_file_returns_empty_dict(self) -> None:
        path = _tmp_json_path()
        path.write_text("", encoding="utf-8")
        self.assertEqual(client_configs.load_client_config(path), {})

    def test_valid_json_loaded(self) -> None:
        path = _tmp_json_path({"mcpServers": {"fs": {"command": "npx"}}})
        data = client_configs.load_client_config(path)
        self.assertEqual(data["mcpServers"]["fs"]["command"], "npx")

    def test_invalid_json_raises_and_never_writes(self) -> None:
        path = _tmp_json_path()
        path.write_text("{not valid json", encoding="utf-8")
        with self.assertRaises(client_configs.ClientConfigError):
            client_configs.load_client_config(path)

    def test_non_object_top_level_raises(self) -> None:
        path = _tmp_json_path()
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaises(client_configs.ClientConfigError):
            client_configs.load_client_config(path)


class TestWriteClientConfig(unittest.TestCase):
    def test_write_then_read_back(self) -> None:
        path = Path(tempfile.mkdtemp()) / "sub" / "config.json"
        client_configs.write_client_config(path, {"mcpServers": {"x": {"command": "y"}}})
        self.assertEqual(client_configs.load_client_config(path)["mcpServers"]["x"]["command"], "y")


class TestGetMcpServers(unittest.TestCase):
    def test_present_dict(self) -> None:
        self.assertEqual(client_configs.get_mcp_servers({"mcpServers": {"a": {}}}), {"a": {}})

    def test_absent_returns_empty(self) -> None:
        self.assertEqual(client_configs.get_mcp_servers({}), {})

    def test_wrong_type_returns_empty(self) -> None:
        self.assertEqual(client_configs.get_mcp_servers({"mcpServers": "not-a-dict"}), {})


class TestBackupRestore(unittest.TestCase):
    def test_make_backup_missing_source_returns_none(self) -> None:
        path = Path(tempfile.mkdtemp()) / "nope.json"
        self.assertIsNone(client_configs.make_backup(path))

    def test_make_backup_copies_file(self) -> None:
        path = _tmp_json_path({"mcpServers": {"a": {}}})
        backup = client_configs.make_backup(path)
        self.assertIsNotNone(backup)
        self.assertTrue(backup.exists())
        self.assertEqual(json.loads(backup.read_text()), {"mcpServers": {"a": {}}})

    def test_make_backup_never_overwrites_existing_backup(self) -> None:
        path = _tmp_json_path({"mcpServers": {"a": {}}})
        client_configs.make_backup(path)
        # Simulate the file being rewritten (e.g. by setup) BEFORE a second
        # make_backup call -- the backup must still hold the ORIGINAL content.
        path.write_text(json.dumps({"mcpServers": {"reeflex-mcp": {}}}), encoding="utf-8")
        client_configs.make_backup(path)
        backup = client_configs.backup_path(path)
        self.assertEqual(json.loads(backup.read_text()), {"mcpServers": {"a": {}}})

    def test_restore_backup_no_backup_returns_false(self) -> None:
        path = _tmp_json_path({"mcpServers": {}})
        self.assertFalse(client_configs.restore_backup(path))

    def test_restore_backup_restores_original(self) -> None:
        path = _tmp_json_path({"mcpServers": {"a": {"command": "orig"}}})
        client_configs.make_backup(path)
        path.write_text(json.dumps({"mcpServers": {"reeflex-mcp": {}}}), encoding="utf-8")
        restored = client_configs.restore_backup(path)
        self.assertTrue(restored)
        self.assertEqual(json.loads(path.read_text())["mcpServers"]["a"]["command"], "orig")

    def test_has_backup(self) -> None:
        path = _tmp_json_path({"mcpServers": {}})
        self.assertFalse(client_configs.has_backup(path))
        client_configs.make_backup(path)
        self.assertTrue(client_configs.has_backup(path))


class TestIsOurs(unittest.TestCase):
    def test_reserved_name_is_ours(self) -> None:
        self.assertTrue(client_configs.is_ours("reeflex-mcp", {"command": "anything"}))

    def test_foreign_name_with_foreign_command_is_not_ours(self) -> None:
        self.assertFalse(client_configs.is_ours("filesystem", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}))

    def test_renamed_entry_recognized_by_command_substring(self) -> None:
        self.assertTrue(client_configs.is_ours("my-gateway", {"command": "/usr/local/bin/reeflex-mcp"}))

    def test_renamed_entry_recognized_by_module_invocation(self) -> None:
        self.assertTrue(
            client_configs.is_ours("my-gateway", {"command": "python", "args": ["-m", "reeflex_mcp", "--transport", "stdio"]})
        )

    def test_non_dict_entry_is_not_ours_unless_reserved_name(self) -> None:
        self.assertFalse(client_configs.is_ours("filesystem", "not-a-dict"))
        self.assertTrue(client_configs.is_ours("reeflex-mcp", "not-a-dict"))


class TestGatewayEntry(unittest.TestCase):
    def test_shape(self) -> None:
        entry = client_configs.gateway_entry(config_path="/x/reeflex-mcp.yaml")
        self.assertIn("command", entry)
        self.assertIn("args", entry)
        self.assertIn("--config", entry["args"])
        self.assertIn("/x/reeflex-mcp.yaml", entry["args"])

    def test_own_output_is_recognized_as_ours(self) -> None:
        entry = client_configs.gateway_entry(config_path="/x/reeflex-mcp.yaml")
        self.assertTrue(client_configs.is_ours("reeflex-mcp", entry))


class TestStandardProfiles(unittest.TestCase):
    def test_three_profiles(self) -> None:
        profiles = client_configs.standard_profiles()
        self.assertEqual({p.key for p in profiles}, {"claude-desktop", "mcp-json", "claude-settings"})

    def test_resolve_profile(self) -> None:
        p = client_configs.resolve_profile("mcp-json")
        self.assertEqual(p.key, "mcp-json")

    def test_resolve_unknown_profile_raises(self) -> None:
        with self.assertRaises(ValueError):
            client_configs.resolve_profile("nonexistent")


if __name__ == "__main__":
    unittest.main()
