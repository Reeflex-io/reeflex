"""
test_normalize.py -- unit tests for reeflex_mcp.normalize: the Track 2
heuristic-only envelope builder, plus the 4-tier resolution (declarative
mapping -> MCP annotations -> name-heuristic -> conservative default) via
classify_call() / build_envelope(mapping_registry=..., annotations=...).

BUG 2 fix coverage: option A (widened `_READ_PREFIXES`) and option B (the
MCP-annotations tier) -- see normalize.py's module docstring.
"""

from __future__ import annotations

import tempfile
import unittest

import mcp.types as types

from reeflex_mcp import mappings, normalize


def _mapping_registry(yaml_text: str, system: str = "sys1") -> mappings.MappingRegistry:
    tmpdir = tempfile.mkdtemp()
    with open(f"{tmpdir}/{system}.yaml", "w", encoding="utf-8") as fh:
        fh.write(yaml_text)
    return mappings.load_mappings_dir(tmpdir)


class TestMagnitudeCount(unittest.TestCase):
    def test_no_list_arg_defaults_to_one(self) -> None:
        self.assertEqual(normalize.magnitude_count({"path": "/tmp/x"}), 1)

    def test_empty_arguments(self) -> None:
        self.assertEqual(normalize.magnitude_count({}), 1)

    def test_first_list_arg_used(self) -> None:
        self.assertEqual(normalize.magnitude_count({"paths": ["a", "b", "c"]}), 3)

    def test_empty_list_floors_to_one(self) -> None:
        self.assertEqual(normalize.magnitude_count({"paths": []}), 1)


class TestBlastRadiusThresholds(unittest.TestCase):
    def test_single(self) -> None:
        self.assertEqual(normalize._blast_radius_for_count(1), "single")

    def test_scoped(self) -> None:
        self.assertEqual(normalize._blast_radius_for_count(2), "scoped")
        self.assertEqual(normalize._blast_radius_for_count(20), "scoped")

    def test_broad(self) -> None:
        self.assertEqual(normalize._blast_radius_for_count(21), "broad")
        self.assertEqual(normalize._blast_radius_for_count(1000), "broad")


class TestClassifyHeuristic(unittest.TestCase):
    def test_delete_prefix(self) -> None:
        cls = normalize.classify("delete_file", {"path": "/x"})
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "single")

    def test_remove_prefix(self) -> None:
        cls = normalize.classify("remove_record", {"ids": [1, 2, 3]})
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["blast_radius"], "scoped")

    def test_drop_prefix(self) -> None:
        cls = normalize.classify("drop_table", {})
        self.assertEqual(cls["verb"], "delete")

    def test_send_prefix(self) -> None:
        cls = normalize.classify("send_email", {"to": "a@b.com"})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["externality"], "outbound")

    def test_post_prefix(self) -> None:
        cls = normalize.classify("post_message", {})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["externality"], "outbound")

    def test_create_prefix(self) -> None:
        cls = normalize.classify("create_issue", {})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["externality"], "outbound")

    def test_push_prefix(self) -> None:
        cls = normalize.classify("push_branch", {})
        self.assertEqual(cls["verb"], "create")
        self.assertEqual(cls["externality"], "outbound")

    def test_get_prefix(self) -> None:
        cls = normalize.classify("get_file", {})
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["reversibility"], "reversible")

    def test_list_prefix(self) -> None:
        cls = normalize.classify("list_files", {})
        self.assertEqual(cls["verb"], "read")

    def test_read_prefix(self) -> None:
        cls = normalize.classify("read_file", {})
        self.assertEqual(cls["verb"], "read")

    def test_search_prefix(self) -> None:
        cls = normalize.classify("search_index", {})
        self.assertEqual(cls["verb"], "read")

    # -- BUG 2 fix, option A: widened _READ_PREFIXES -----------------------

    def test_count_prefix_is_read(self) -> None:
        cls = normalize.classify("count_records", {})
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["reversibility"], "reversible")

    def test_fetch_prefix_is_read(self) -> None:
        cls = normalize.classify("fetch_user", {})
        self.assertEqual(cls["verb"], "read")

    def test_query_prefix_is_read(self) -> None:
        cls = normalize.classify("query_database", {})
        self.assertEqual(cls["verb"], "read")

    def test_describe_prefix_is_read(self) -> None:
        cls = normalize.classify("describe_table", {})
        self.assertEqual(cls["verb"], "read")

    def test_find_prefix_is_read(self) -> None:
        cls = normalize.classify("find_records", {})
        self.assertEqual(cls["verb"], "read")

    def test_select_prefix_is_read(self) -> None:
        cls = normalize.classify("select_rows", {})
        self.assertEqual(cls["verb"], "read")

    def test_bare_get_camelcase_is_read(self) -> None:
        cls = normalize.classify("getUserProfile", {})
        self.assertEqual(cls["verb"], "read")

    def test_bare_list_camelcase_is_read(self) -> None:
        cls = normalize.classify("listActiveUsers", {})
        self.assertEqual(cls["verb"], "read")

    def test_ambiguous_update_still_hits_conservative_floor(self) -> None:
        # update_* is deliberately NOT in _READ_PREFIXES -- ambiguous/
        # mutating-capable prefixes stay on the restrictive floor.
        cls = normalize.classify("update_records", {})
        self.assertEqual(cls["verb"], "execute")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")

    def test_destructive_name_still_hits_delete_bucket(self) -> None:
        cls = normalize.classify("delete_user", {})
        self.assertEqual(cls["verb"], "delete")

    def test_apply_migration_still_hits_conservative_floor(self) -> None:
        cls = normalize.classify("apply_migration", {})
        self.assertEqual(cls["verb"], "execute")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")

    def test_asymmetry_guard_mutating_token_containing_get_not_downgraded(self) -> None:
        # "get" appears after the leading token, not as a prefix -- the
        # asymmetry (startswith, not substring) must hold: this destructive-
        # looking name is NOT misread as safe by the widened read set.
        cls = normalize.classify("update_get_x", {})
        self.assertEqual(cls["verb"], "execute")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")

    def test_unmatched_conservative_default(self) -> None:
        cls = normalize.classify("frobnicate_widget", {})
        self.assertEqual(cls["verb"], "execute")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")
        self.assertEqual(cls["externality"], "internal")

    def test_unmatched_blast_radius_is_fixed_not_magnitude_derived(self) -> None:
        # brief section 8: the execute floor is FIXED at systemic, regardless
        # of how many list-arg items are present.
        cls = normalize.classify("frobnicate_widget", {"items": [1, 2, 3, 4, 5]})
        self.assertEqual(cls["blast_radius"], "systemic")


class TestClassifyFromAnnotations(unittest.TestCase):
    """BUG 2 fix, option B: `_classify_from_annotations()` -- the tier
    between the declarative mapping and the name-heuristic."""

    def test_read_only_hint_true_classifies_read(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        result = normalize._classify_from_annotations(ann, count=1)
        self.assertIsNotNone(result)
        cls, tier = result
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["reversibility"], "reversible")
        self.assertEqual(tier, "annotation:read")

    def test_read_only_hint_true_even_with_floor_looking_name_via_classify_call(self) -> None:
        # A tool NAMED like a genuine unknown (would hit the conservative
        # floor by name alone) but server-annotated readOnlyHint=True must
        # classify read -- the annotation is authoritative over the name.
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _count, tier = normalize.classify_call(None, "sys1", "frobnicate_widget", {}, ann)
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(tier, "annotation:read")

    def test_destructive_hint_true_classifies_destructive(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=True)
        result = normalize._classify_from_annotations(ann, count=1)
        self.assertIsNotNone(result)
        cls, tier = result
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(tier, "annotation:destructive")

    def test_read_only_hint_wins_over_destructive_hint(self) -> None:
        # Per MCP spec, destructiveHint is only meaningful when
        # readOnlyHint == false -- readOnlyHint=True settles it regardless.
        ann = types.ToolAnnotations(readOnlyHint=True, destructiveHint=True)
        result = normalize._classify_from_annotations(ann, count=1)
        cls, tier = result
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(tier, "annotation:read")

    def test_annotations_none_returns_none(self) -> None:
        self.assertIsNone(normalize._classify_from_annotations(None, count=1))

    def test_annotations_present_but_hints_unset_returns_none(self) -> None:
        # MCP spec: readOnlyHint defaults False, destructiveHint defaults
        # True WHEN ABSENT -- but absence (Python None here) must NOT be
        # read as an actionable signal in either direction; fall through.
        ann = types.ToolAnnotations()
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1))

    def test_destructive_hint_explicitly_false_with_no_readonly_returns_none(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=False)
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1))

    def test_blast_radius_derived_from_count_for_read_bucket(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _tier = normalize._classify_from_annotations(ann, count=5)
        self.assertEqual(cls["blast_radius"], "scoped")


class TestBuildEnvelope(unittest.TestCase):
    def _build(self, **overrides):
        kwargs = dict(
            session_id="mcp-gateway:abc123",
            agent_id="agent:mcp-client",
            on_behalf_of=None,
            upstream_name="fs",
            target_system="filesystem",
            target_environment="staging",
            tool_name="delete_file",
            arguments={"path": "/data/x.txt"},
        )
        kwargs.update(overrides)
        return normalize.build_envelope(**kwargs)

    def test_empty_session_id_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._build(session_id="")

    def test_required_fields_present(self) -> None:
        env = self._build()
        self.assertEqual(env["reeflex_version"], "0.1")
        self.assertEqual(env["action"]["verb"], "delete")
        self.assertEqual(env["target"]["environment"], "staging")
        self.assertIn("reversibility", env["axes"])
        self.assertIn("blast_radius", env["axes"])
        self.assertIn("externality", env["axes"])
        self.assertEqual(env["agent"]["session_id"], "mcp-gateway:abc123")
        self.assertFalse(env["approval"]["present"])

    def test_ability_preserves_backend_op(self) -> None:
        env = self._build()
        self.assertEqual(env["action"]["ability"], "filesystem/delete_file")
        self.assertEqual(env["action"]["namespace"], "filesystem")

    def test_magnitude_from_list_arg(self) -> None:
        env = self._build(tool_name="delete_files", arguments={"paths": ["a", "b", "c", "d"]})
        self.assertEqual(env["magnitude"]["count"], 4)
        self.assertEqual(env["axes"]["blast_radius"], "scoped")

    def test_meta_has_stub_signature_and_nonce(self) -> None:
        env = self._build()
        self.assertTrue(env["meta"]["signature"].startswith("ed25519:stub:"))
        self.assertTrue(env["meta"]["nonce"])
        self.assertTrue(env["meta"]["timestamp"].endswith("Z"))

    def test_nonces_are_unique_per_call(self) -> None:
        env1 = self._build()
        env2 = self._build()
        self.assertNotEqual(env1["meta"]["nonce"], env2["meta"]["nonce"])

    def test_ref_guessed_from_id_arg(self) -> None:
        env = self._build(tool_name="delete_post", arguments={"id": "post:42"})
        self.assertEqual(env["target"]["ref"], "post:42")

    def test_ref_none_when_no_plausible_arg(self) -> None:
        env = self._build(tool_name="delete_everything", arguments={"confirm": True})
        self.assertIsNone(env["target"]["ref"])

    def test_on_behalf_of_passthrough(self) -> None:
        env = self._build(on_behalf_of="user:alice")
        self.assertEqual(env["agent"]["on_behalf_of"], "user:alice")

    def test_classification_source_defaults_to_heuristic_tag(self) -> None:
        # No mapping_registry given -- Track 2 behavior, but the context tag
        # now names the specific heuristic bucket (Track 4).
        env = self._build(tool_name="delete_file")
        self.assertEqual(env["context"]["classification_source"], "heuristic:delete")

    def test_classification_source_default_bucket(self) -> None:
        env = self._build(tool_name="frobnicate_widget")
        self.assertEqual(env["context"]["classification_source"], "heuristic:default")

    def test_mapping_registry_overrides_heuristic(self) -> None:
        # "delete_thing" would normally hit the heuristic's delete_* bucket;
        # a declarative mapping for it must win instead (tier 1 over tier 2).
        reg = _mapping_registry(
            "tools:\n  delete_thing: { verb: read, axes: { reversibility: reversible, "
            "blast_radius: single, externality: internal } }\n",
            system="filesystem",
        )
        env = self._build(
            target_system="filesystem", tool_name="delete_thing", arguments={}, mapping_registry=reg
        )
        self.assertEqual(env["action"]["verb"], "read")  # NOT delete -- mapping won
        self.assertEqual(env["axes"]["reversibility"], "reversible")
        self.assertEqual(env["context"]["classification_source"], "mapping")

    def test_mapping_registry_present_but_tool_unmapped_falls_through(self) -> None:
        reg = _mapping_registry(
            "tools:\n  some_other_tool: { verb: read }\n", system="filesystem"
        )
        env = self._build(
            target_system="filesystem", tool_name="delete_file", arguments={}, mapping_registry=reg
        )
        # filesystem.yaml (in this temp registry) doesn't mention delete_file
        # -- falls through to the heuristic's delete_* bucket.
        self.assertEqual(env["action"]["verb"], "delete")
        self.assertEqual(env["context"]["classification_source"], "heuristic:delete")

    def test_annotations_classify_read_over_floor_looking_name(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        env = self._build(tool_name="frobnicate_widget", arguments={}, annotations=ann)
        self.assertEqual(env["action"]["verb"], "read")
        self.assertEqual(env["axes"]["reversibility"], "reversible")
        self.assertEqual(env["context"]["classification_source"], "annotation:read")

    def test_annotations_classify_destructive(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=True)
        env = self._build(tool_name="frobnicate_widget", arguments={}, annotations=ann)
        self.assertEqual(env["action"]["verb"], "delete")
        self.assertEqual(env["context"]["classification_source"], "annotation:destructive")

    def test_mapping_wins_over_conflicting_annotation(self) -> None:
        # Declarative mapping is an operator override -- must win even
        # against a server-declared annotation that would say otherwise.
        reg = _mapping_registry(
            "tools:\n  delete_thing: { verb: execute, axes: { reversibility: irreversible, "
            "blast_radius: systemic, externality: internal } }\n",
            system="filesystem",
        )
        ann = types.ToolAnnotations(readOnlyHint=True)  # would say "read" if consulted
        env = self._build(
            target_system="filesystem",
            tool_name="delete_thing",
            arguments={},
            mapping_registry=reg,
            annotations=ann,
        )
        self.assertEqual(env["action"]["verb"], "execute")  # mapping won, not the annotation
        self.assertEqual(env["context"]["classification_source"], "mapping")

    def test_annotations_absent_falls_to_widened_heuristic(self) -> None:
        env = self._build(tool_name="fetch_widget", arguments={}, annotations=None)
        self.assertEqual(env["action"]["verb"], "read")
        self.assertEqual(env["context"]["classification_source"], "heuristic:read")

    def test_annotations_absent_genuine_unknown_still_floors(self) -> None:
        env = self._build(tool_name="frobnicate_widget", arguments={}, annotations=None)
        self.assertEqual(env["action"]["verb"], "execute")
        self.assertEqual(env["axes"]["reversibility"], "irreversible")
        self.assertEqual(env["axes"]["blast_radius"], "systemic")
        self.assertEqual(env["context"]["classification_source"], "heuristic:default")


class TestClassifyCall(unittest.TestCase):
    def test_mapping_tier_wins_over_heuristic(self) -> None:
        reg = _mapping_registry(
            "tools:\n  delete_notes: { verb: execute, axes: { reversibility: recoverable, "
            "blast_radius: single, externality: internal } }\n",
            system="notes",
        )
        cls, count, tier = normalize.classify_call(reg, "notes", "delete_notes", {"names": ["a", "b"]})
        self.assertEqual(tier, "mapping")
        self.assertEqual(cls["verb"], "execute")  # mapping's choice, not the heuristic's "delete"
        # No `magnitude:` rule in this mapping file -> count is always 1, by
        # design (mappings.py never silently guesses at a list argument the
        # operator did not explicitly name -- see mappings/postgres.yaml's
        # HONEST NOTE and test_mappings.py::test_postgres_has_no_magnitude_rule
        # for the same behavior pinned from the loader side).
        self.assertEqual(count, 1)

    def test_heuristic_tier_when_no_mapping_for_tool(self) -> None:
        reg = _mapping_registry("tools:\n  unrelated_tool: { verb: read }\n", system="notes")
        cls, _count, tier = normalize.classify_call(reg, "notes", "delete_notes", {})
        self.assertEqual(tier, "heuristic:delete")
        self.assertEqual(cls["verb"], "delete")

    def test_heuristic_default_tier_when_nothing_matches(self) -> None:
        cls, _count, tier = normalize.classify_call(None, "notes", "frobnicate_widget", {})
        self.assertEqual(tier, "heuristic:default")
        self.assertEqual(cls["verb"], "execute")

    def test_none_registry_behaves_like_track_2(self) -> None:
        cls, count, tier = normalize.classify_call(None, "notes", "read_note", {"name": "alpha"})
        self.assertEqual(tier, "heuristic:read")
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(count, 1)

    def test_mapping_present_for_different_system_does_not_apply(self) -> None:
        reg = _mapping_registry(
            "tools:\n  delete_notes: { verb: read }\n", system="widgets"  # a DIFFERENT system
        )
        cls, _count, tier = normalize.classify_call(reg, "notes", "delete_notes", {})
        self.assertEqual(tier, "heuristic:delete")  # mapping is for 'widgets', not 'notes' -- no match
        self.assertEqual(cls["verb"], "delete")

    # -- BUG 2 fix, option B: annotation tier precedence ---------------------

    def test_annotation_tier_wins_over_name_heuristic(self) -> None:
        # "frobnicate_widget" alone would hit the conservative floor -- a
        # server-declared readOnlyHint=True must win instead (tier 2 over 3).
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _count, tier = normalize.classify_call(None, "notes", "frobnicate_widget", {}, ann)
        self.assertEqual(tier, "annotation:read")
        self.assertEqual(cls["verb"], "read")

    def test_mapping_tier_wins_over_annotation_tier(self) -> None:
        reg = _mapping_registry(
            "tools:\n  delete_notes: { verb: execute }\n", system="notes"
        )
        ann = types.ToolAnnotations(readOnlyHint=True)  # would say "read" if consulted
        cls, _count, tier = normalize.classify_call(reg, "notes", "delete_notes", {}, ann)
        self.assertEqual(tier, "mapping")
        self.assertEqual(cls["verb"], "execute")

    def test_annotation_absent_falls_through_to_heuristic(self) -> None:
        cls, _count, tier = normalize.classify_call(None, "notes", "delete_notes", {}, None)
        self.assertEqual(tier, "heuristic:delete")
        self.assertEqual(cls["verb"], "delete")

    def test_annotation_absent_genuine_unknown_falls_to_floor(self) -> None:
        cls, _count, tier = normalize.classify_call(None, "notes", "frobnicate_widget", {}, None)
        self.assertEqual(tier, "heuristic:default")
        self.assertEqual(cls["verb"], "execute")


if __name__ == "__main__":
    unittest.main()
