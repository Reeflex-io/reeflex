"""
test_mappings.py -- unit tests for reeflex_mcp.mappings (Track 4: declarative
per-server mappings, design doc section 8): the loader, validation, partial
axes / CORE_AXIS_DEFAULTS fill, magnitude-from-arg, and the 3 shipped starter
mapping files (filesystem/github/postgres).
"""

from __future__ import annotations

import ast
import os
import pathlib
import tempfile
import unittest

from reeflex_mcp import mappings


def _find_core_envelope_py() -> pathlib.Path | None:
    """Locate reeflex-core/app/envelope.py by walking up to the monorepo root.

    Returns None when it is not there -- a standalone reeflex-mcp install has
    no core source tree and there is nothing to cross-check.
    """
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "reeflex-core" / "app" / "envelope.py"
        if candidate.is_file():
            return candidate
    return None


def _parse_axis_defaults(path: pathlib.Path) -> dict[str, str]:
    """Read `_AXIS_DEFAULTS` out of core's source with `ast` -- parse, never
    import: this test must not depend on core being importable, and must not
    execute core's module-level code to learn one dict literal."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        targets = (
            [node.target] if isinstance(node, ast.AnnAssign)
            else node.targets if isinstance(node, ast.Assign)
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "_AXIS_DEFAULTS":
                return ast.literal_eval(node.value)
    raise AssertionError(
        "_AXIS_DEFAULTS not found as a module-level assignment in %s -- the "
        "cross-check cannot silently pass on a parse miss" % (path,)
    )


def _write_yaml(text: str) -> str:
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(text)
    fh.close()
    return fh.name


def _write_dir(files: dict[str, str]) -> str:
    tmpdir = tempfile.mkdtemp()
    for name, text in files.items():
        with open(os.path.join(tmpdir, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    return tmpdir


_MINIMAL_SYSTEM = """\
tools:
  read_thing:
    verb: read
    axes: { reversibility: reversible, blast_radius: single, externality: internal }
  delete_thing:
    verb: delete
    axes: { reversibility: irreversible, blast_radius: broad, externality: internal }
magnitude:
  from_arg: ids
"""


class TestLoadMappingsDir(unittest.TestCase):
    def test_nonexistent_directory_returns_empty_registry(self) -> None:
        reg = mappings.load_mappings_dir("/no/such/directory/at/all")
        self.assertEqual(reg.systems, frozenset())
        self.assertIsNone(reg.classify("anything", "read_thing", {}))

    def test_loads_one_system_file(self) -> None:
        d = _write_dir({"widgets.yaml": _MINIMAL_SYSTEM})
        reg = mappings.load_mappings_dir(d)
        self.assertEqual(reg.systems, frozenset({"widgets"}))
        self.assertEqual(reg.tool_names("widgets"), frozenset({"read_thing", "delete_thing"}))

    def test_loads_multiple_system_files(self) -> None:
        d = _write_dir({"widgets.yaml": _MINIMAL_SYSTEM, "gadgets.yaml": _MINIMAL_SYSTEM})
        reg = mappings.load_mappings_dir(d)
        self.assertEqual(reg.systems, frozenset({"widgets", "gadgets"}))

    def test_ignores_non_yaml_files(self) -> None:
        d = _write_dir({"widgets.yaml": _MINIMAL_SYSTEM, "README.md": "not a mapping"})
        reg = mappings.load_mappings_dir(d)
        self.assertEqual(reg.systems, frozenset({"widgets"}))


class TestClassify(unittest.TestCase):
    def setUp(self) -> None:
        d = _write_dir({"widgets.yaml": _MINIMAL_SYSTEM})
        self.reg = mappings.load_mappings_dir(d)

    def test_mapped_tool_returns_classification_and_magnitude(self) -> None:
        result = self.reg.classify("widgets", "delete_thing", {"ids": ["a", "b", "c"]})
        self.assertIsNotNone(result)
        cls, count = result
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "broad")
        self.assertEqual(cls["externality"], "internal")
        self.assertEqual(count, 3)

    def test_magnitude_defaults_to_one_when_arg_absent(self) -> None:
        _cls, count = self.reg.classify("widgets", "delete_thing", {})
        self.assertEqual(count, 1)

    def test_magnitude_defaults_to_one_when_arg_not_a_list(self) -> None:
        _cls, count = self.reg.classify("widgets", "delete_thing", {"ids": "not-a-list"})
        self.assertEqual(count, 1)

    def test_unmapped_tool_returns_none(self) -> None:
        self.assertIsNone(self.reg.classify("widgets", "frobnicate", {}))

    def test_unmapped_system_returns_none(self) -> None:
        self.assertIsNone(self.reg.classify("unknown_system", "read_thing", {}))


class TestPartialAxesFillWithCoreDefaults(unittest.TestCase):
    def test_missing_axis_filled_from_core_defaults(self) -> None:
        yaml_text = """\
tools:
  half_specified:
    verb: update
    axes: { reversibility: recoverable }
"""
        d = _write_dir({"sys1.yaml": yaml_text})
        reg = mappings.load_mappings_dir(d)
        cls, _count = reg.classify("sys1", "half_specified", {})
        self.assertEqual(cls["reversibility"], "recoverable")  # explicitly given
        # NOT given -- must match core's own _AXIS_DEFAULTS exactly, not some
        # other invented "conservative" value.
        self.assertEqual(cls["blast_radius"], mappings.CORE_AXIS_DEFAULTS["blast_radius"])
        self.assertEqual(cls["externality"], mappings.CORE_AXIS_DEFAULTS["externality"])

    def test_no_axes_at_all_fills_all_three_from_core_defaults(self) -> None:
        yaml_text = """\
tools:
  bare:
    verb: execute
"""
        d = _write_dir({"sys2.yaml": yaml_text})
        reg = mappings.load_mappings_dir(d)
        cls, _count = reg.classify("sys2", "bare", {})
        self.assertEqual(cls["reversibility"], mappings.CORE_AXIS_DEFAULTS["reversibility"])
        self.assertEqual(cls["blast_radius"], mappings.CORE_AXIS_DEFAULTS["blast_radius"])
        self.assertEqual(cls["externality"], mappings.CORE_AXIS_DEFAULTS["externality"])

    def test_core_axis_defaults_match_core_envelope_py(self) -> None:
        """The pinned intent -- what this package believes core's floor is.

        This half is a statement of intent, not a drift detector: both sides of
        the comparison live in reeflex-mcp. The version of this test that
        shipped before RFX-129 was ONLY this half, while its docstring claimed
        "if core's defaults ever change, THIS test should fail loudly rather
        than silently drift" -- it could not, and when core's externality
        default moved it would have stayed green. The detector is the second
        test below, which reads core.
        """
        self.assertEqual(
            mappings.CORE_AXIS_DEFAULTS,
            {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "outbound"},
        )

    def test_core_axis_defaults_are_read_out_of_core_source_not_asserted(self) -> None:
        """RFX-129: actually READ reeflex-core/app/envelope.py and compare.

        The two packages are not installed together, so this locates core's
        source by walking up to the monorepo root and parses the assignment
        with `ast` -- no import of core, no execution of it. Outside the
        monorepo (a standalone wheel) core's source is genuinely absent and
        there is nothing to compare, which is the one case where skipping is
        honest; the pinned-literal test above still runs there.
        """
        core_envelope = _find_core_envelope_py()
        if core_envelope is None:
            self.skipTest(
                "reeflex-core/app/envelope.py not present (standalone install, "
                "not the monorepo) -- nothing to cross-check against"
            )
        core_defaults = _parse_axis_defaults(core_envelope)
        self.assertEqual(
            core_defaults,
            mappings.CORE_AXIS_DEFAULTS,
            "reeflex_mcp.mappings.CORE_AXIS_DEFAULTS has drifted from "
            "reeflex-core/app/envelope.py _AXIS_DEFAULTS (%s). This gateway "
            "FILLS the axes it does not have a mapping for, so core never sees "
            "the axis as missing and never applies its own coercion -- a drift "
            "here is a partial mapping silently governed by the wrong floor "
            "(RFX-129)." % (core_envelope,),
        )


class TestValidation(unittest.TestCase):
    def test_not_a_mapping_raises(self) -> None:
        d = _write_dir({"bad.yaml": "- just\n- a\n- list\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_missing_tools_key_raises(self) -> None:
        d = _write_dir({"bad.yaml": "magnitude: { from_arg: x }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_empty_tools_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools: {}\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_invalid_yaml_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  x: [unclosed\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_unknown_verb_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: obliterate }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_missing_verb_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { axes: { reversibility: reversible } }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_invalid_axis_value_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read, axes: { reversibility: sort-of } }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_unknown_axis_key_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read, axes: { made_up_axis: internal } }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_unknown_tool_entry_key_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read, extra_field: 1 }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_unknown_top_level_key_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read }\nbogus_key: 1\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_magnitude_without_from_arg_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read }\nmagnitude: {}\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_tool_entry_not_a_mapping_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: not-a-mapping\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)

    def test_axes_not_a_mapping_raises(self) -> None:
        d = _write_dir({"bad.yaml": "tools:\n  t: { verb: read, axes: not-a-mapping }\n"})
        with self.assertRaises(mappings.MappingError):
            mappings.load_mappings_dir(d)


class TestStarterMappings(unittest.TestCase):
    """The 3 shipped starter mappings (filesystem/github/postgres) -- real
    tool names, loaded from the package's own bundled directory."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = mappings.load_mappings_dir()  # default -> bundled starters

    def test_all_three_starters_present(self) -> None:
        self.assertEqual(self.reg.systems, frozenset({"filesystem", "github", "postgres"}))

    # -- filesystem: real @modelcontextprotocol/server-filesystem tool names --

    def test_filesystem_read_multiple_files_magnitude_from_paths(self) -> None:
        cls, count = self.reg.classify("filesystem", "read_multiple_files", {"paths": ["a.txt", "b.txt"]})
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(count, 2)

    def test_filesystem_write_file_is_irreversible(self) -> None:
        # real tool annotation destructiveHint:true -- see mappings/filesystem.yaml
        cls, _count = self.reg.classify("filesystem", "write_file", {"path": "x", "content": "y"})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["reversibility"], "irreversible")

    def test_filesystem_has_no_delete_tool(self) -> None:
        # honest limitation -- the real reference server has none.
        self.assertNotIn("delete_file", self.reg.tool_names("filesystem"))

    def test_filesystem_unmapped_tool_falls_through(self) -> None:
        self.assertIsNone(self.reg.classify("filesystem", "some_future_tool", {}))

    # -- github: real modelcontextprotocol/servers-archived tool names -------

    def test_github_push_files_magnitude_from_files(self) -> None:
        cls, count = self.reg.classify("github", "push_files", {"files": [{"path": "a"}, {"path": "b"}, {"path": "c"}]})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["externality"], "outbound")
        self.assertEqual(count, 3)

    def test_github_merge_pull_request_is_irreversible_broad_outbound(self) -> None:
        cls, _count = self.reg.classify("github", "merge_pull_request", {"owner": "a", "repo": "b", "pull_number": 1})
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "broad")
        self.assertEqual(cls["externality"], "outbound")

    def test_github_has_no_delete_repository_tool(self) -> None:
        # honest limitation -- verified against the real server: no delete
        # tool exists at all.
        self.assertNotIn("delete_repository", self.reg.tool_names("github"))

    def test_github_reads_are_internal(self) -> None:
        cls, _count = self.reg.classify("github", "search_repositories", {"query": "x"})
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["externality"], "internal")

    # -- postgres: real crystaldba/postgres-mcp tool names --------------------

    def test_postgres_execute_sql_conservative_delete_classification(self) -> None:
        cls, count = self.reg.classify("postgres", "execute_sql", {"sql": "SELECT 1"})
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "broad")
        self.assertEqual(count, 1)  # no magnitude rule -- opaque SQL string, see HONEST NOTE

    def test_postgres_reads_are_reversible(self) -> None:
        cls, _count = self.reg.classify("postgres", "list_schemas", {})
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["reversibility"], "reversible")

    def test_postgres_has_no_magnitude_rule(self) -> None:
        # documented: no real structured/countable argument exists for this
        # server's write tool -- see mappings/postgres.yaml's HONEST NOTE.
        _cls, count = self.reg.classify("postgres", "execute_sql", {"sql": "x", "unrelated_list": [1, 2, 3]})
        self.assertEqual(count, 1)  # not magnitude-from-arg'd even though a list IS present


if __name__ == "__main__":
    unittest.main()
