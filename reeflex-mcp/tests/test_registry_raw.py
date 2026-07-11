"""
test_registry_raw.py -- unit tests for reeflex_mcp.registry's raw YAML
read/write helpers (Track 5: load_raw_yaml / write_raw_yaml /
upsert_upstream_raw / remove_upstream_raw), used by `setup`/`add`/`import`
to programmatically edit reeflex-mcp.yaml.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reeflex_mcp import registry


def _tmp_yaml_path() -> str:
    return str(Path(tempfile.mkdtemp()) / "reeflex-mcp.yaml")


class TestLoadRawYaml(unittest.TestCase):
    def test_missing_file_returns_fresh_default(self) -> None:
        raw = registry.load_raw_yaml(_tmp_yaml_path())
        self.assertEqual(raw, {"mode": "observe", "upstreams": []})

    def test_valid_file_loaded(self) -> None:
        path = _tmp_yaml_path()
        Path(path).write_text("mode: enforce\nupstreams:\n  - name: fs\n    command: [python, x.py]\n    target: {system: fs, environment: dev}\n", encoding="utf-8")
        raw = registry.load_raw_yaml(path)
        self.assertEqual(raw["mode"], "enforce")
        self.assertEqual(raw["upstreams"][0]["name"], "fs")

    def test_invalid_yaml_raises(self) -> None:
        path = _tmp_yaml_path()
        Path(path).write_text("upstreams: [unclosed\n", encoding="utf-8")
        with self.assertRaises(registry.ConfigError):
            registry.load_raw_yaml(path)

    def test_non_mapping_raises(self) -> None:
        path = _tmp_yaml_path()
        Path(path).write_text("- just\n- a\n- list\n", encoding="utf-8")
        with self.assertRaises(registry.ConfigError):
            registry.load_raw_yaml(path)

    def test_upstreams_not_a_list_raises(self) -> None:
        path = _tmp_yaml_path()
        Path(path).write_text("upstreams: not-a-list\n", encoding="utf-8")
        with self.assertRaises(registry.ConfigError):
            registry.load_raw_yaml(path)

    def test_empty_file_returns_fresh_default(self) -> None:
        path = _tmp_yaml_path()
        Path(path).write_text("", encoding="utf-8")
        raw = registry.load_raw_yaml(path)
        self.assertEqual(raw, {"mode": "observe", "upstreams": []})


class TestWriteRawYaml(unittest.TestCase):
    def test_write_then_load_round_trips(self) -> None:
        path = _tmp_yaml_path()
        raw = {"mode": "observe", "upstreams": [{"name": "fs", "command": ["python", "x.py"], "target": {"system": "fs", "environment": "dev"}}]}
        registry.write_raw_yaml(path, raw)
        loaded = registry.load_raw_yaml(path)
        self.assertEqual(loaded, raw)

    def test_creates_parent_directories(self) -> None:
        path = str(Path(tempfile.mkdtemp()) / "nested" / "dir" / "reeflex-mcp.yaml")
        registry.write_raw_yaml(path, {"mode": "observe", "upstreams": []})
        self.assertTrue(Path(path).exists())

    def test_written_file_is_valid_via_load_config(self) -> None:
        # Full round trip through the VALIDATING loader too (not just the raw one).
        path = _tmp_yaml_path()
        raw = {
            "mode": "observe",
            "upstreams": [{"name": "fs", "command": ["python", "x.py"], "target": {"system": "fs", "environment": "dev"}, "required": True}],
        }
        registry.write_raw_yaml(path, raw)
        gw_config = registry.load_config(path)
        self.assertEqual(gw_config.upstreams[0].name, "fs")


class TestUpsertUpstreamRaw(unittest.TestCase):
    def test_appends_new_entry(self) -> None:
        raw = {"upstreams": []}
        replaced = registry.upsert_upstream_raw(raw, {"name": "fs", "command": ["x"]})
        self.assertFalse(replaced)
        self.assertEqual(len(raw["upstreams"]), 1)

    def test_replaces_existing_entry_by_name(self) -> None:
        raw = {"upstreams": [{"name": "fs", "command": ["old"]}]}
        replaced = registry.upsert_upstream_raw(raw, {"name": "fs", "command": ["new"]})
        self.assertTrue(replaced)
        self.assertEqual(len(raw["upstreams"]), 1)
        self.assertEqual(raw["upstreams"][0]["command"], ["new"])

    def test_idempotent_second_call_same_entry(self) -> None:
        raw = {"upstreams": []}
        entry = {"name": "fs", "command": ["x"]}
        registry.upsert_upstream_raw(raw, entry)
        registry.upsert_upstream_raw(raw, entry)
        self.assertEqual(len(raw["upstreams"]), 1)

    def test_does_not_touch_other_entries(self) -> None:
        raw = {"upstreams": [{"name": "gh", "url": "https://x"}]}
        registry.upsert_upstream_raw(raw, {"name": "fs", "command": ["x"]})
        names = {u["name"] for u in raw["upstreams"]}
        self.assertEqual(names, {"gh", "fs"})

    def test_missing_upstreams_key_created(self) -> None:
        raw: dict = {}
        registry.upsert_upstream_raw(raw, {"name": "fs", "command": ["x"]})
        self.assertEqual(raw["upstreams"][0]["name"], "fs")


class TestRemoveUpstreamRaw(unittest.TestCase):
    def test_removes_existing(self) -> None:
        raw = {"upstreams": [{"name": "fs"}, {"name": "gh"}]}
        removed = registry.remove_upstream_raw(raw, "fs")
        self.assertTrue(removed)
        self.assertEqual([u["name"] for u in raw["upstreams"]], ["gh"])

    def test_removes_nonexistent_returns_false(self) -> None:
        raw = {"upstreams": [{"name": "fs"}]}
        removed = registry.remove_upstream_raw(raw, "nope")
        self.assertFalse(removed)
        self.assertEqual(len(raw["upstreams"]), 1)

    def test_missing_upstreams_key_returns_false(self) -> None:
        raw: dict = {}
        self.assertFalse(registry.remove_upstream_raw(raw, "fs"))


if __name__ == "__main__":
    unittest.main()
