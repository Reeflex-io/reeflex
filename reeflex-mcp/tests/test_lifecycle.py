"""
test_lifecycle.py -- unit tests for reeflex_mcp.lifecycle (Track 5, design
doc section 13): derive_upstream_entry, import_profile (setup/import), and
check_drift (doctor).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reeflex_mcp import client_configs, lifecycle, registry


def _tmp_client_config(data: dict) -> Path:
    tmpdir = tempfile.mkdtemp()
    path = Path(tmpdir) / "claude_desktop_config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _tmp_reeflex_yaml_path() -> str:
    return str(Path(tempfile.mkdtemp()) / "reeflex-mcp.yaml")


class TestDeriveUpstreamEntry(unittest.TestCase):
    def test_stdio_entry(self) -> None:
        entry, warnings = lifecycle.derive_upstream_entry(
            "filesystem", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
            environment="staging",
        )
        self.assertEqual(entry["name"], "filesystem")
        self.assertEqual(entry["command"], ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"])
        self.assertEqual(entry["target"], {"system": "filesystem", "environment": "staging"})
        self.assertTrue(entry["required"])
        self.assertEqual(warnings, [])

    def test_stdio_entry_no_args(self) -> None:
        entry, _warnings = lifecycle.derive_upstream_entry("x", {"command": "myserver"}, environment="production")
        self.assertEqual(entry["command"], ["myserver"])

    def test_stdio_entry_with_env_copies_and_warns(self) -> None:
        entry, warnings = lifecycle.derive_upstream_entry(
            "x", {"command": "myserver", "env": {"API_KEY": "secret123"}}, environment="production"
        )
        self.assertEqual(entry["env"], {"API_KEY": "secret123"})
        self.assertTrue(any("review it for any inline secret" in w for w in warnings))

    def test_http_entry(self) -> None:
        entry, warnings = lifecycle.derive_upstream_entry(
            "github", {"url": "https://mcp.internal/github"}, environment="production"
        )
        self.assertEqual(entry["url"], "https://mcp.internal/github")
        self.assertEqual(warnings, [])

    def test_http_entry_with_headers_warns_and_does_not_copy(self) -> None:
        entry, warnings = lifecycle.derive_upstream_entry(
            "github", {"url": "https://mcp.internal/github", "headers": {"Authorization": "Bearer sk-abc123"}},
            environment="production",
        )
        self.assertNotIn("headers", entry)
        self.assertNotIn("auth", entry)
        joined = " ".join(warnings)
        self.assertIn("NOT copied", joined)
        self.assertIn("secrets by-reference", joined)
        # the actual secret value must never appear in a warning string either
        self.assertNotIn("sk-abc123", joined)

    def test_neither_command_nor_url_raises(self) -> None:
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.derive_upstream_entry("x", {}, environment="production")

    def test_target_system_defaults_to_name(self) -> None:
        entry, _w = lifecycle.derive_upstream_entry("my-server", {"command": "x"}, environment="production")
        self.assertEqual(entry["target"]["system"], "my-server")

    def test_required_false_when_requested(self) -> None:
        entry, _w = lifecycle.derive_upstream_entry("x", {"command": "y"}, environment="production", required=False)
        self.assertFalse(entry["required"])


class TestSanitizeUpstreamName(unittest.TestCase):
    def test_clean_name_unchanged(self) -> None:
        name, warning = lifecycle.sanitize_upstream_name("filesystem")
        self.assertEqual(name, "filesystem")
        self.assertIsNone(warning)

    def test_double_underscore_sanitized_with_warning(self) -> None:
        name, warning = lifecycle.sanitize_upstream_name("my__server")
        self.assertEqual(name, "my_server")
        self.assertIsNotNone(warning)


class TestImportProfileSetup(unittest.TestCase):
    """The `setup`-style call: only_name=None, imports EVERY foreign entry."""

    def test_imports_all_foreign_servers_and_rewrites_client(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
                "github": {"url": "https://mcp.internal/github"},
            }
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()

        result = lifecycle.import_profile(
            profile, reeflex_config_path=reeflex_yaml, default_environment="staging", interactive=False
        )

        self.assertEqual(sorted(result.imported), ["filesystem", "github"])
        self.assertIsNotNone(result.backup_path)
        self.assertTrue(Path(result.backup_path).exists())

        # reeflex-mcp.yaml has both upstreams now
        raw = registry.load_raw_yaml(reeflex_yaml)
        names = {u["name"] for u in raw["upstreams"]}
        self.assertEqual(names, {"filesystem", "github"})

        # client config rewritten to ONLY the gateway entry
        rewritten = client_configs.load_client_config(client_path)
        servers = client_configs.get_mcp_servers(rewritten)
        self.assertEqual(list(servers.keys()), [client_configs.OWNERSHIP_NAME])

        # backup holds the TRUE original
        backup_data = json.loads(Path(result.backup_path).read_text())
        self.assertEqual(set(backup_data["mcpServers"].keys()), {"filesystem", "github"})

    def test_already_configured_is_a_clean_no_op(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml")}
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()

        result = lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)
        self.assertTrue(result.already_configured)
        self.assertEqual(result.imported, [])

    def test_no_mcp_servers_at_all_is_a_no_op(self) -> None:
        client_path = _tmp_client_config({})
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()
        result = lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)
        self.assertEqual(result.imported, [])
        self.assertIsNone(result.backup_path)

    def test_idempotent_rerun_after_setup_is_a_no_op(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "server-filesystem"]}}
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()

        first = lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)
        self.assertEqual(first.imported, ["filesystem"])

        second = lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)
        self.assertTrue(second.already_configured)

    def test_invalid_json_raises_and_writes_nothing(self) -> None:
        client_path = _tmp_client_config({"mcpServers": {}})
        client_path.write_text("{not valid", encoding="utf-8")
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()

        with self.assertRaises(client_configs.ClientConfigError):
            lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)
        self.assertFalse(Path(reeflex_yaml).exists())

    def test_import_preserves_other_top_level_client_config_keys(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {"filesystem": {"command": "npx"}},
            "someOtherClientSetting": {"theme": "dark"},
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()
        lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, interactive=False)

        rewritten = client_configs.load_client_config(client_path)
        self.assertEqual(rewritten["someOtherClientSetting"], {"theme": "dark"})


class TestImportProfileNamedImport(unittest.TestCase):
    """The `import <name>` style call: only_name=<the one drifted server>."""

    def test_imports_only_named_server_keeps_others(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {
                client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml"),
                "filesystem": {"command": "npx", "args": ["-y", "server-filesystem"]},
                "other-foreign": {"command": "something-else"},
            }
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()

        result = lifecycle.import_profile(
            profile, reeflex_config_path=reeflex_yaml, only_name="filesystem", interactive=False
        )
        self.assertEqual(result.imported, ["filesystem"])

        rewritten = client_configs.load_client_config(client_path)
        servers = client_configs.get_mcp_servers(rewritten)
        # filesystem removed; gateway entry preserved; the OTHER foreign
        # entry untouched (surgical, not a full setup rewrite).
        self.assertNotIn("filesystem", servers)
        self.assertIn(client_configs.OWNERSHIP_NAME, servers)
        self.assertIn("other-foreign", servers)

    def test_named_server_not_present_raises(self) -> None:
        client_path = _tmp_client_config({"mcpServers": {"filesystem": {"command": "npx"}}})
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.import_profile(profile, reeflex_config_path=reeflex_yaml, only_name="github", interactive=False)

    def test_named_server_that_is_already_ours_raises(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml")}
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        reeflex_yaml = _tmp_reeflex_yaml_path()
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.import_profile(
                profile, reeflex_config_path=reeflex_yaml, only_name=client_configs.OWNERSHIP_NAME, interactive=False
            )


class TestCheckDrift(unittest.TestCase):
    def test_no_drift_when_only_gateway_entry_present(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml")}
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        findings = lifecycle.check_drift([profile])
        self.assertEqual(findings, [])

    def test_no_drift_when_no_mcp_servers_key(self) -> None:
        client_path = _tmp_client_config({})
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        self.assertEqual(lifecycle.check_drift([profile]), [])

    def test_foreign_server_detected(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {
                client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml"),
                "sneaky-direct-server": {"command": "python", "args": ["evil.py"]},
            }
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        findings = lifecycle.check_drift([profile])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "foreign_server")
        self.assertEqual(findings[0].server_name, "sneaky-direct-server")
        self.assertIn("reeflex-mcp import sneaky-direct-server", findings[0].message)

    def test_gateway_missing_detected_alongside_foreign_server(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {"filesystem": {"command": "npx"}}
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        findings = lifecycle.check_drift([profile])
        kinds = {f.kind for f in findings}
        self.assertIn("foreign_server", kinds)
        self.assertIn("gateway_missing", kinds)

    def test_invalid_json_reported_as_finding_not_raised(self) -> None:
        client_path = _tmp_client_config({"mcpServers": {}})
        client_path.write_text("{not valid", encoding="utf-8")
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        findings = lifecycle.check_drift([profile])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "invalid_config")

    def test_nonexistent_file_is_skipped_silently(self) -> None:
        path = Path(tempfile.mkdtemp()) / "does-not-exist.json"
        profile = client_configs.ClientProfile("test", "Test Client", path)
        self.assertEqual(lifecycle.check_drift([profile]), [])

    def test_multiple_foreign_servers_all_reported(self) -> None:
        client_path = _tmp_client_config({
            "mcpServers": {
                client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(config_path="x.yaml"),
                "a": {"command": "x"},
                "b": {"command": "y"},
            }
        })
        profile = client_configs.ClientProfile("test", "Test Client", client_path)
        findings = lifecycle.check_drift([profile])
        names = {f.server_name for f in findings}
        self.assertEqual(names, {"a", "b"})


if __name__ == "__main__":
    unittest.main()
