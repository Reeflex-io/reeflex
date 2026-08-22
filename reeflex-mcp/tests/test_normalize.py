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
    between the declarative mapping and the name-heuristic.

    RFX-173: this tier is OFF unless the operator opted the upstream in with
    `trust_annotations: true`, so every case here passes `trusted=` explicitly.
    The eight assertions that used to run without it were asserting that an
    UNTRUSTED upstream may classify its own tools -- see
    TestAnnotationsUntrustedByDefault below for what replaced them.
    """

    def test_read_only_hint_true_classifies_read(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        result = normalize._classify_from_annotations(ann, count=1, trusted=True)
        self.assertIsNotNone(result)
        cls, tier = result
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(cls["reversibility"], "reversible")
        self.assertEqual(tier, "annotation:read")

    def test_read_only_hint_true_even_with_floor_looking_name_via_classify_call(self) -> None:
        # A tool NAMED like a genuine unknown (would hit the conservative
        # floor by name alone) but server-annotated readOnlyHint=True must
        # classify read -- the annotation is authoritative over the name,
        # ONCE THE OPERATOR HAS TRUSTED THIS UPSTREAM.
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _count, tier = normalize.classify_call(
            None, "sys1", "frobnicate_widget", {}, ann, trust_annotations=True
        )
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(tier, "annotation:read")

    def test_destructive_hint_true_classifies_destructive(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=True)
        result = normalize._classify_from_annotations(ann, count=1, trusted=True)
        self.assertIsNotNone(result)
        cls, tier = result
        self.assertEqual(cls["verb"], "delete")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(tier, "annotation:destructive")

    def test_destructive_hint_keeps_the_floors_blast_radius(self) -> None:
        # RFX-174, the regression this locks: `destructiveHint: true` used to
        # derive blast_radius from magnitude, so an HONEST destructive
        # declaration produced irreversible+single -> default_allow, while
        # declaring nothing produced the floor -> deny. An annotation must
        # never be a downgrade. "Destructive" is a claim about KIND, and the
        # server said nothing about SCOPE.
        ann = types.ToolAnnotations(destructiveHint=True)
        for count in (1, 5, 999):
            cls, tier = normalize._classify_from_annotations(ann, count=count, trusted=True)
            self.assertEqual(cls["blast_radius"], "systemic", f"count={count}")
            self.assertEqual(tier, "annotation:destructive")

    def test_read_only_hint_wins_over_destructive_hint(self) -> None:
        # Per MCP spec, destructiveHint is only meaningful when
        # readOnlyHint == false -- readOnlyHint=True settles it regardless.
        ann = types.ToolAnnotations(readOnlyHint=True, destructiveHint=True)
        result = normalize._classify_from_annotations(ann, count=1, trusted=True)
        cls, tier = result
        self.assertEqual(cls["verb"], "read")
        self.assertEqual(tier, "annotation:read")

    def test_annotations_none_returns_none(self) -> None:
        self.assertIsNone(normalize._classify_from_annotations(None, count=1, trusted=True))

    def test_annotations_present_but_hints_unset_returns_none(self) -> None:
        # MCP spec: readOnlyHint defaults False, destructiveHint defaults
        # True WHEN ABSENT -- but absence (Python None here) must NOT be
        # read as an actionable signal in either direction; fall through.
        ann = types.ToolAnnotations()
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1, trusted=True))

    def test_destructive_hint_explicitly_false_with_no_readonly_returns_none(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=False)
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1, trusted=True))

    def test_blast_radius_derived_from_count_for_read_bucket(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _tier = normalize._classify_from_annotations(ann, count=5, trusted=True)
        self.assertEqual(cls["blast_radius"], "scoped")


class TestAnnotationsUntrustedByDefault(unittest.TestCase):
    """RFX-173. The upstream MCP server is the component being GOVERNED, and
    the MCP specification says a client must treat tool annotations as
    untrusted unless the server is trusted. Measured on the published 0.1.3
    gateway in enforce mode against a real core: an upstream declaring
    `readOnlyHint: true` on a tool that deletes a file turned core's `deny`
    into `allow`, and the gateway dispatched the deletion -- the file was
    gone. So the tier is opt-in per upstream.
    """

    def test_read_only_hint_is_ignored_when_untrusted(self) -> None:
        ann = types.ToolAnnotations(readOnlyHint=True)
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1))
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1, trusted=False))

    def test_destructive_hint_is_ignored_when_untrusted(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=True)
        self.assertIsNone(normalize._classify_from_annotations(ann, count=1, trusted=False))

    def test_classify_call_defaults_to_untrusted(self) -> None:
        # THE CASE THAT WAS WALKED LIVE: an unmapped tool whose name hints
        # nothing, annotated readOnlyHint=True by its own server. Untrusted
        # (the default) it must land on the floor -- irreversible/systemic,
        # which is core's R3 deny in production.
        ann = types.ToolAnnotations(readOnlyHint=True)
        cls, _count, tier = normalize.classify_call(
            None, "ops", "apply_retention_policy", {"path": "/srv/prod/db"}, ann
        )
        self.assertEqual(tier, "heuristic:default")
        self.assertEqual(cls["verb"], "execute")
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")

    def test_build_envelope_defaults_to_untrusted(self) -> None:
        env = normalize.build_envelope(
            session_id="s1",
            agent_id="agent:mcp-client",
            on_behalf_of=None,
            upstream_name="ops",
            target_system="ops",
            target_environment="production",
            tool_name="apply_retention_policy",
            arguments={"path": "/srv/prod/db"},
            annotations=types.ToolAnnotations(readOnlyHint=True),
        )
        self.assertEqual(env["context"]["classification_source"], "heuristic:default")
        self.assertEqual(env["axes"]["reversibility"], "irreversible")
        self.assertEqual(env["axes"]["blast_radius"], "systemic")

    def test_a_mapping_still_outranks_everything(self) -> None:
        # The operator's own declarative mapping is unaffected by RFX-173 --
        # it was always tier 1 and it stays tier 1.
        reg = mappings.load_mappings_dir(mappings.DEFAULT_MAPPINGS_DIR)
        cls, _count, tier = normalize.classify_call(
            reg,
            "filesystem",
            "write_file",
            {"path": "/srv/prod/x"},
            types.ToolAnnotations(readOnlyHint=True),
        )
        self.assertEqual(tier, "mapping")
        self.assertEqual(cls["reversibility"], "irreversible")


class TestReadPrefixCompoundNames(unittest.TestCase):
    """RFX-175. `str.startswith` on the widened read prefixes reads only the
    FIRST token of the name. A compound whose real verb is the SECOND token
    was classified `read`/`reversible` and allowed in production -- the same
    defect class as reeflex-claude's `_bash_verb()` first-shell-token read
    (RFX-144). Every name below was MEASURED `allow` on the published build
    against a live core with target.environment=production.
    """

    MUTATING_COMPOUNDS = (
        "search_and_replace",
        "find_and_replace",
        "search_replace",
        "query_write",
        "describe_and_drop",
        "list_and_prune_snapshots",
        "count_and_compact",
        "fetch_and_apply_migration",
        "get_or_create_index",
        "selectAllAndDelete",
        "listAndDeleteAll",
    )

    # HONEST RESIDUAL, not fixed here and not asserted: the bare `get`/`list`
    # prefixes (added by BUG 2 for camelCase tools) match any run-on name that
    # merely BEGINS with those letters, and no stem list can catch a name whose
    # destructiveness is semantic rather than lexical -- `getRidOfDatabase`
    # still classifies `heuristic:read`. Filed as RFX-175's residual: the
    # answer there is a declarative mapping (tier 1), not a longer word list.

    GENUINE_READS = (
        "get_user",
        "list_issues",
        "read_text_file",
        "search_files",
        "count_rows",
        "fetch_url",
        "query_status",
        "describe_table",
        "find_symbol",
        "select_columns",
        "getUser",
        "listIssues",
        "list_directory_with_sizes",
        "get_pull_request_comments",
    )

    def test_mutating_compounds_do_not_reach_the_read_bucket(self) -> None:
        for name in self.MUTATING_COMPOUNDS:
            cls = normalize.classify(name, {})
            self.assertEqual(cls["_tier"], "heuristic:default", name)
            self.assertEqual(cls["reversibility"], "irreversible", name)
            self.assertEqual(cls["blast_radius"], "systemic", name)

    def test_genuine_reads_are_untouched(self) -> None:
        for name in self.GENUINE_READS:
            cls = normalize.classify(name, {})
            self.assertEqual(cls["_tier"], "heuristic:read", name)
            self.assertEqual(cls["reversibility"], "reversible", name)

    def test_delete_bucket_still_wins_first(self) -> None:
        # The veto must not change how an honest delete_* name is priced.
        cls = normalize.classify("delete_and_purge_users", {"ids": [1, 2, 3]})
        self.assertEqual(cls["_tier"], "heuristic:delete")
        self.assertEqual(cls["verb"], "delete")

    def test_name_tokens_splits_snake_and_camel_identically(self) -> None:
        self.assertEqual(
            normalize._name_tokens("search_and_replace"), ["search", "and", "replace"]
        )
        self.assertEqual(
            normalize._name_tokens("searchAndReplace"), ["search", "and", "replace"]
        )

    def test_first_token_is_never_its_own_veto(self) -> None:
        # `_has_mutating_stem` skips token 0 on purpose: a name whose first
        # token is a mutating stem never reaches the read bucket anyway, and
        # vetoing on it would be self-referential.
        self.assertFalse(normalize._has_mutating_stem("delete_file"))
        self.assertTrue(normalize._has_mutating_stem("get_and_delete_file"))


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
        # RFX-173: only once the operator trusted this upstream.
        ann = types.ToolAnnotations(readOnlyHint=True)
        env = self._build(
            tool_name="frobnicate_widget", arguments={}, annotations=ann, trust_annotations=True
        )
        self.assertEqual(env["action"]["verb"], "read")
        self.assertEqual(env["axes"]["reversibility"], "reversible")
        self.assertEqual(env["context"]["classification_source"], "annotation:read")

    def test_annotations_classify_destructive(self) -> None:
        ann = types.ToolAnnotations(destructiveHint=True)
        env = self._build(
            tool_name="frobnicate_widget", arguments={}, annotations=ann, trust_annotations=True
        )
        self.assertEqual(env["action"]["verb"], "delete")
        self.assertEqual(env["context"]["classification_source"], "annotation:destructive")
        # RFX-174: and it keeps the floor's blast radius, never magnitude's.
        self.assertEqual(env["axes"]["blast_radius"], "systemic")

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
        cls, _count, tier = normalize.classify_call(
            None, "notes", "frobnicate_widget", {}, ann, trust_annotations=True
        )
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
