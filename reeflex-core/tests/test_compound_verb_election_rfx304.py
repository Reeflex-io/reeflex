"""
test_compound_verb_election_rfx304.py — RFX-304: a compound verb elects its
MOST-GUARDED word, not its first.

THE DEFECT, as measured on the deployed v0.2.1 (= the code this test guards).
`findOneAndDelete` — MongoDB's own operation name, and the honest thing a
customer-written integration passes through as `action.verb` — split to
[find, one, and, delete].  `find` hit _VERB_CANON first, so an irreversible
PRODUCTION deletion was:

    decided   reeflex.policy/read_only_internal   (R1: verb==read + internal)
    audited   {"action": {"verb": "read", ...}}   positively asserting a read
    charged   nothing by R5's deletions budget

Live on api-dev, one control and one arm in the same minute: verb `delete`
raised a hold on call 21; verb `findOneAndDelete` was still being allowed at
call 25.  A human was asked after 200 such deletions (objects_touched, the
remaining backstop) instead of after 20.

THREE SURFACES, because the first fix alone would have left two of them:
  1. `_canonicalize_verb`  — the election itself.
  2. `_delete_signal_from_ability` — the documented cross-check for "the verb
     says read but the ability says delete" read only the ability's FIRST
     token, so it was silent on `mongodb/findOneAndDelete` too.  A defence in
     depth that shares its blind spot is not depth.
  3. `_verb_is_declared` — mirrored the last resort, so provenance recorded
     `action.verb` as DECLARED precisely when core had guessed it.

WHAT THIS DELIBERATELY DOES NOT CLAIM.  `action.verb` is asserted by the
adapter and core cannot verify it; a caller that writes `verb: "read"` over a
delete still evades the deletions budget, and the ability cross-check is one
signal, not a proof.  This closes the HONEST spelling — the compound a real
backend emits — and the ability's later words.  Only signed envelopes (SPEC
§6, roadmap) close the deliberate case.

ASSERT THE TRIP CALL NUMBER, NOT "A HOLD HAPPENED" (qa--213 §8).  An arm that
stops allowing at the same call as its neighbours is a suspect, not a
confirmation: the budget test below pins call 21 on both the arm and its
control, and pins that a genuine read never trips at all.

NOTE ON STYLE: unittest.TestCase, not bare pytest functions — gate.py runs
this suite with `unittest discover`, where a module of plain `def test_*`
functions contributes ZERO tests.
"""

from __future__ import annotations

import unittest

from app import ledger
from app.envelope import (
    _SPEC_VERBS,
    _VERB_CANON,
    _VERB_GUARD_RANK,
    validate_and_fill_defaults,
)


def _env(verb, count=1, ability="eval/synthetic", environment="production",
         session="s-rfx304", reversibility="irreversible"):
    return {
        "agent": {"id": "agent:test", "session_id": session},
        "action": {"namespace": "t", "verb": verb, "ability": ability},
        "target": {"environment": environment},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": "single",
            "externality": "internal",
        },
    }


def _filled(raw, **kw):
    return validate_and_fill_defaults(_env(raw, **kw))


def _verb(raw, **kw):
    return _filled(raw, **kw)["action"]["verb"]


class TestTheFiledDefect(unittest.TestCase):
    """The five arms qa--213 measured escaping on the deployed build."""

    # Every one of these was recorded as verb "read" and decided
    # read_only_internal on v0.2.1, in this exact envelope.
    ESCAPED_ON_LIVE = [
        "findOneAndDelete",
        "getAndDelete",
        "query_and_purge",
        "export_and_destroy",
        "list_and_remove",
    ]

    def test_arms_that_escaped_on_live_now_canonicalize_to_delete(self):
        for raw in self.ESCAPED_ON_LIVE:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), "delete")

    def test_none_of_them_can_still_reach_r1(self):
        # R1 is `verb == "read"` AND externality internal. The verb half is
        # what this fix owns; assert it directly rather than through a rule.
        for raw in self.ESCAPED_ON_LIVE:
            with self.subTest(verb=raw):
                self.assertNotEqual(_verb(raw, ability=None), "read")


class TestElectionIsMostGuardedNotFirst(unittest.TestCase):
    """Real compound operation names, from reeflex-mcp's own test corpus.

    These are the names the OTHER layer's ticket (RFX-175) already calls real
    MCP tool names — not names invented for this test.
    """

    CASES = [
        # (compound, canonical verb a human reading the name would give)
        ("selectAllAndDelete", "delete"),
        ("listAndDeleteAll", "delete"),
        ("list_and_prune_snapshots", "delete"),
        ("get_and_delete_file", "delete"),
        ("describe_and_drop", "delete"),
        ("delete_and_purge_users", "delete"),
        ("search_and_replace", "update"),
        ("searchAndReplace", "update"),
        ("find_and_replace", "update"),
        ("query_write", "update"),
        ("fetch_and_apply_migration", "execute"),
        ("get_or_create_index", "create"),
    ]

    def test_compound_names_resolve_to_the_word_that_matters(self):
        for raw, expected in self.CASES:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), expected)

    def test_a_delete_whose_leading_word_is_not_a_read_is_caught_too(self):
        # A read-veto ("don't believe a read prefix") would miss all three:
        # their leading word is already a non-read verb, and each is still a
        # delete that R5 must charge.
        for raw in ("move_to_trash", "copy_and_delete", "update_and_purge"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), "delete")

    def test_the_election_can_only_elect_a_word_the_canon_KNOWS(self):
        """RESIDUAL, pinned so it is a known gap and not a surprise.

        The election reads _VERB_CANON. A mutating word the canon has no entry
        for is invisible to it, so it resolves to `read` and reaches R1.
        Measured against reeflex-mcp's own `_MUTATING_STEMS`: 42 of its 51
        stems were in this canon and NONE of the 51 maps to `read`, so the
        election does not mistake a known mutation for a read; the 9 that were
        absent were `expire, reset, restore, rotate, overwrite, commit,
        compact, vacuum, install`.

        THE EXPECTATION MOVED, AND THIS IS THAT DAY (RFX-308, #160). The
        version of this test that shipped with #158 said "this test fails the
        day someone adds one, which is the moment to move the expectation",
        and asserted `count_and_compact` -> `read`. RFX-308 added seven of the
        nine — expire, reset, rotate, overwrite, compact, vacuum, restore —
        all to `delete`, so `count_and_compact` now elects `compact` and is a
        `delete`. That half of the residual is CLOSED, and it is asserted here
        rather than deleted, so a later change that silently un-adds those
        words reddens this test instead of passing it.

        AND THE EXPECTATION MOVED A SECOND TIME (RFX-324). The paragraph this
        replaces said the residual survives for `commit` and `install`, "and
        closing it wants a rule about UNKNOWN words in the election, not more
        vocabulary". It was never two words: the election skips EVERY word the
        canon does not know, so the residual was the whole complement of the
        canon — `get_and_redact`, `describe_and_decommission`,
        `list_and_unmount` and nine more were ALLOWED under R1 as decisions,
        irreversible and in production, measured on caf2cd6. RFX-324 closed it
        with the narrow half of that rule: a leading `read` does not survive an
        explicit conjunction followed by a word the canon does not know (the
        WIDE reading breaks 34 of 36 genuine reads — see
        test_conjunction_veto_rfx324.py, which owns the arms, the cost column
        and the residual that is still open).

        Both words are asserted at their NEW value here rather than deleted,
        so removing the conjunction clause reddens this test too.
        """
        # Closed by RFX-308: the word is in the canon, so the election sees it.
        self.assertEqual(_verb("count_and_compact", ability=None), "delete")
        # Closed by RFX-324: the conjunction veto sends both to the
        # irreversible default instead of handing out R1.
        self.assertEqual(_verb("count_and_install", ability=None), "delete")
        self.assertEqual(_verb("count_and_commit", ability=None), "delete")

    def test_the_escape_is_not_only_about_delete(self):
        # Same defect, other verbs: on v0.2.1 both of these were recorded
        # `read` and decided read_only_internal.
        self.assertEqual(_verb("get_and_transfer", ability=None), "transact")
        self.assertEqual(_verb("fetch_and_send_report", ability=None), "emit")


class TestVerbFirstConventionPreserved(unittest.TestCase):
    """The cases the last resort was ADDED for must not move.

    Ties go to the earliest word, so a verb-first name resolves exactly as it
    did before — this is the half that keeps the fix from being a pile of
    wrong-escalations.
    """

    UNCHANGED = [
        ("DeleteObject", "delete"), ("DeleteBucket", "delete"),
        ("delete_backup_policy", "delete"),
        ("GetObject", "read"), ("ListObjects", "read"), ("ListBuckets", "read"),
        ("PutObject", "update"), ("CreateBucket", "create"),
        ("RunInstances", "execute"),
        # The wrong-escalation controls qa--213 named in the fix shape: the
        # past-tense/adjectival forms are absent from _VERB_CANON on purpose,
        # so these contain no delete-mapping word and stay reads.
        ("list_deleted_objects", "read"), ("listDeletedObjects", "read"),
        ("get_deleted_items", "read"), ("list_revoked_certs", "read"),
        ("count_dropped_frames", "read"),
        # Genuine reads from reeflex-mcp's corpus.
        ("search_files", "read"), ("search_index", "read"),
        ("query_database", "read"), ("count_records", "read"),
        ("read_text_file", "read"), ("list_directory_with_sizes", "read"),
        ("get_pull_request_comments", "read"), ("listActiveUsers", "read"),
        ("getUserProfile", "read"), ("find_records", "read"),
        ("find_symbol", "read"), ("select_columns", "read"),
    ]

    def test_names_that_resolved_correctly_before_still_do(self):
        for raw, expected in self.UNCHANGED:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), expected)

    def test_a_single_word_verb_is_never_touched_by_the_election(self):
        # The election only runs on a compound; one word is a lookup, and an
        # unknown single word still lands on the reversibility default.
        self.assertEqual(_verb("delete", ability=None), "delete")
        self.assertEqual(_verb("Purge", ability=None), "delete")
        self.assertEqual(_verb("list", ability=None), "read")
        self.assertEqual(_verb("frobnicate", ability=None), "delete")
        self.assertEqual(
            _verb("frobnicate", ability=None, reversibility="reversible"),
            "update",
        )


class TestAReadIsOnlyElectedFromTheLEADINGWord(unittest.TestCase):
    """The election must not be WEAKER than the fallback it replaces.

    Found by dev-1--080's census, measured on two cores one file apart, same
    image and same policy: with the rank table alone, a compound whose
    operative verb the canon does not know resolved to `read` as soon as the
    name contained an incidental read NOUN — "log", "index", "status",
    "query".  origin/main lands those on the reversibility default (`delete` /
    `update`); the election handed them R1:

        compact_event_log          irreversible  main: delete   election: read
        vacuum_audit_log           irreversible  main: delete   election: read
        rebuild_search_index       irreversible  main: delete   election: read
        refresh_materialized_status              main: delete   election: read

    Operation names are verb-first, which is the convention the last resort
    exists to exploit.  A read word LEADING is the operation; a read word
    after a leading word we do not recognize is its object.  So `read` is
    electable from the leading word only, and everything the last resort was
    added for is unaffected (TestVerbFirstConventionPreserved, above, is the
    other half of this assertion).
    """

    # (name, IRREVERSIBLE expectation, REVERSIBLE expectation)
    #
    # The reversible column was a single hardcoded "update" until RFX-308
    # (#160) put `compact` and `vacuum` in the canon. For those two the
    # leading word is no longer unknown, so they no longer reach the
    # reversibility default at all — they elect their own word and resolve
    # `delete` on BOTH arms. That is the fix RFX-308 exists for (a reversible
    # production vacuum was recorded an `update` and charged the deletions
    # budget nothing), and it is strictly more guarded than the `update` this
    # column used to assert, so the expectation moves rather than the code.
    # The four rows whose leading word is still unknown are untouched, which
    # is what keeps this table a measurement of the election and not of
    # RFX-308's vocabulary.
    LEADING_WORD_UNKNOWN = [
        ("compact_event_log", "delete", "delete"),
        ("vacuum_audit_log", "delete", "delete"),
        ("rebuild_search_index", "delete", "update"),
        ("refresh_materialized_status", "delete", "update"),
        ("frobnicate_and_list", "delete", "update"),
        ("zorp_query", "delete", "update"),
    ]

    def test_an_incidental_read_noun_does_not_make_a_compound_a_read(self):
        for raw, expected, _ in self.LEADING_WORD_UNKNOWN:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), expected)

    def test_and_it_lands_on_the_inert_default_when_reversible(self):
        for raw, _, expected in self.LEADING_WORD_UNKNOWN:
            with self.subTest(verb=raw):
                self.assertEqual(
                    _verb(raw, ability=None, reversibility="reversible"),
                    expected,
                )

    def test_and_none_of_them_is_ever_a_read_on_either_arm(self):
        # The invariant the row-by-row expectations above are an instance of,
        # asserted separately so it cannot be weakened by editing a cell:
        # `read` is the one member that would hand out R1.
        for raw, _, _rev in self.LEADING_WORD_UNKNOWN:
            for reversibility in ("irreversible", "reversible"):
                with self.subTest(verb=raw, reversibility=reversibility):
                    self.assertNotEqual(
                        _verb(raw, ability=None, reversibility=reversibility),
                        "read",
                    )

    def test_a_leading_read_word_is_still_the_operation(self):
        # The verb-first names this election exists to serve, including the
        # three-word forms where the later words are unknown.
        for raw in ("GetObject", "ListBuckets", "query_status",
                    "list_deleted_objects", "get_pull_request_comments",
                    "list_directory_with_sizes", "search_files"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), "read")

    def test_a_known_non_read_word_still_wins_wherever_it_sits(self):
        # The guard only suppresses a non-leading READ; it does not touch the
        # election itself.
        self.assertEqual(_verb("truncate_and_count", ability=None), "delete")
        self.assertEqual(_verb("findOneAndDelete", ability=None), "delete")
        self.assertEqual(_verb("get_and_transfer", ability=None), "transact")


class TestTheEscalationCostIsRealAndPinned(unittest.TestCase):
    """The price of the election, asserted rather than left for a surprise.

    A genuine read whose name embeds a destructive word now escalates. That is
    the deliberate bias — the same one reeflex-mcp's RFX-175 fix took — and it
    belongs in the suite so that anyone who decides the trade is wrong finds
    the exact cases here instead of in a customer's traffic.

    Measured over reeflex-mcp's 39 real tool names the escalation count is
    ZERO; these are names built to carry the shape.
    """

    def test_a_read_only_name_embedding_a_destructive_word_escalates(self):
        for raw in ("list_trash", "check_delete_permission",
                    "describe_clear_policy", "get_kill_switch_state"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, ability=None), "delete")

    def test_the_escalation_is_a_hold_not_a_deny(self):
        # It costs a hold only once a deletions budget is exceeded, and the
        # verb is the only thing that moves: the axes the terminal R3 reads are
        # the caller's own, untouched.
        filled = _filled("list_trash", ability=None)
        self.assertEqual(filled["axes"]["reversibility"], "irreversible")
        self.assertEqual(filled["axes"]["blast_radius"], "single")


class TestAbilityCrossCheckNoLongerSharesTheBlindSpot(unittest.TestCase):
    """qa--213 §4.1: the one cross-check written for this class could not see
    it, because it resolved the ability by the same leading-word rule."""

    def test_the_most_honest_ability_id_now_signals(self):
        # verb read + ability mongodb/findOneAndDelete: on v0.2.1 the guard
        # was silent, because the ability's first token is `find` too.
        self.assertEqual(_verb("read", ability="mongodb/findOneAndDelete"), "delete")
        self.assertEqual(_verb("read", ability="files/get-and-delete-file"), "delete")
        self.assertEqual(_verb("read", ability="db/select-all-and-drop"), "delete")

    def test_past_tense_and_object_names_still_do_not_false_positive(self):
        # The narrowness that mattered is kept: this reads the CANON, which
        # has no past-tense entries, not a stem prefix match.
        for ability in ("s3/list-deleted-objects", "wp/get-deleted-posts",
                        "api/list-removals", "vault/list-revoked-certs"):
            with self.subTest(ability=ability):
                self.assertEqual(_verb("read", ability=ability), "read")

    def test_only_the_operation_segment_is_read_not_the_namespace(self):
        # A tenant or vendor namespace that happens to be a delete word must
        # not price every call it makes as a delete.
        self.assertEqual(_verb("read", ability="purge-inc/get-widget"), "read")
        self.assertEqual(_verb("read", ability="trash/list-items"), "read")

    def test_cross_check_still_only_escalates(self):
        self.assertEqual(_verb("delete", ability="wordpress/read-post"), "delete")
        self.assertEqual(_verb("remove", ability="s3/GetObject"), "delete")


class TestProvenanceStopsCallingAGuessADeclaration(unittest.TestCase):
    """qa--213 §4.2. `_verb_is_declared` mirrored the last resort, so the
    audit line asserted the adapter DECLARED a verb core had guessed out of
    one word of a compound.

    NO VERDICT MOVES HERE and the test says so: reeflex.rego's
    `r0_classification_inputs` is {axes.reversibility, axes.blast_radius,
    target.environment} — `action.verb` is excluded by design, because R2/R3
    do not read it. What moves is the record.
    """

    def _undeclared(self, raw, **kw):
        return _filled(raw, **kw)["provenance"]["undeclared"]

    def test_a_compound_core_had_to_guess_is_reported_as_a_guess(self):
        for raw in ("findOneAndDelete", "DeleteObject", "search_and_replace",
                    "list_deleted_objects"):
            with self.subTest(verb=raw):
                self.assertIn("action.verb", self._undeclared(raw, ability=None))

    def test_a_verb_the_caller_spelled_whole_is_still_a_declaration(self):
        # Exact, folded, and separator/camel-folded spellings are recognitions
        # of the caller's own string end to end, not guesses.
        for raw in ("delete", "Delete", "DELETE", "purge", "Purge",
                    "hard-delete", "hard delete", "soft_delete", "list", "get"):
            with self.subTest(verb=raw):
                self.assertNotIn("action.verb", self._undeclared(raw, ability=None))

    def test_an_unknown_verb_was_and_remains_a_guess(self):
        self.assertIn("action.verb", self._undeclared("frobnicate", ability=None))

    def test_the_guess_does_not_change_the_verdict_inputs_r0_reads(self):
        # The three fields R0 actually reads must be unaffected by this change:
        # a fully-declared envelope stays fully declared apart from the verb.
        undeclared = self._undeclared("findOneAndDelete", ability=None)
        self.assertEqual(
            [f for f in undeclared if f != "action.verb"], [],
            "only action.verb may newly appear in provenance.undeclared",
        )


class TestGuardRankIsTotalAndOrdered(unittest.TestCase):
    """The rank table is a reading of the shipped pack. Pin both ends of it,
    so a future edit cannot quietly make `read` competitive again."""

    def test_every_canonical_verb_has_a_rank(self):
        # A canon value with no rank is a KeyError inside the election, i.e. a
        # 500 on a decision. The vocabulary is closed; keep it covered.
        self.assertTrue(_SPEC_VERBS <= set(_VERB_GUARD_RANK))
        self.assertTrue(set(_VERB_CANON.values()) <= set(_VERB_GUARD_RANK))

    def test_read_is_strictly_the_least_guarded(self):
        # R1 (`verb == "read"`) is the only ALLOW a verb unlocks, and R7
        # exempts `verb != "read"`.
        for verb in _SPEC_VERBS - {"read"}:
            with self.subTest(verb=verb):
                self.assertGreater(_VERB_GUARD_RANK[verb], _VERB_GUARD_RANK["read"])

    def test_delete_is_strictly_the_most_guarded(self):
        # budgets.rego's `deletions` dimension charges `verb == "delete"` and
        # nothing else.
        for verb in _SPEC_VERBS - {"delete"}:
            with self.subTest(verb=verb):
                self.assertGreater(_VERB_GUARD_RANK["delete"], _VERB_GUARD_RANK[verb])


class TestDeletionsBudgetActuallyCharges(unittest.TestCase):
    """The half that makes the guarantee real: the cumulative key R5 reads.

    Canonicalizing the verb is worth nothing unless
    `cumulative.count_by_verb.delete` moves — that is the number
    budgets.rego compares against the limit.
    """

    SESSION = "s-rfx304-budget"

    def setUp(self):
        ledger.clear_session(self.SESSION)

    tearDown = setUp

    def _append(self, verb, count=1):
        ledger.append_entry(self.SESSION, validate_and_fill_defaults(
            _env(verb, count=count, ability=None, session=self.SESSION)))

    def _delete_count(self):
        return ledger.compute_cumulative(
            self.SESSION, 3600)["count_by_verb"].get("delete", 0)

    def test_the_arm_trips_at_call_21_exactly_like_its_control(self):
        # budgets.rego deletions: limit 20, compared prior + current, strict >.
        # So the first call whose (prior + 1) exceeds 20 is call 21, and an arm
        # that trips at any OTHER call number is not this guard working.
        for verb in ("delete", "findOneAndDelete", "move_to_trash"):
            with self.subTest(verb=verb):
                ledger.clear_session(self.SESSION)
                trip = None
                for call in range(1, 26):
                    prior = self._delete_count()
                    if trip is None and prior + 1 > 20:
                        trip = call
                    self._append(verb)
                self.assertEqual(trip, 21)

    def test_a_genuine_read_still_charges_the_deletions_budget_nothing(self):
        for _ in range(25):
            self._append("list_deleted_objects")
        self.assertEqual(self._delete_count(), 0)

    def test_the_arm_accumulated_under_the_canonical_key_not_its_own(self):
        for _ in range(5):
            self._append("findOneAndDelete")
        cumulative = ledger.compute_cumulative(self.SESSION, 3600)
        self.assertEqual(cumulative["count_by_verb"].get("delete"), 5)
        self.assertEqual(
            [k for k in cumulative["count_by_verb"] if k != "delete"], [],
            "no non-canonical verb key may survive into the cumulative object",
        )


if __name__ == "__main__":
    unittest.main()
