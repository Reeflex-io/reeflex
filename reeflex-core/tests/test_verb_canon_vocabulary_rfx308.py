"""
test_verb_canon_vocabulary_rfx308.py — the nine mutating words core's verb
canon had no entry for, and the direction the widening must not move in.

WHAT WAS MEASURED, on the deployed v0.2.1 (image sha256:2f18d19f…, whose
`app/envelope.py` is byte-identical to origin/main), one /v1/decide per word
with only `action.verb` varying and the canonical verb read back out of the
container's own audit line:

    verb "vacuum"  irreversible -> recorded `delete`   (F6's guarded default)
    verb "vacuum"  REVERSIBLE   -> recorded `update`   (the policy-inert one)
    ability "db/vacuum-rows" + verb "read" -> recorded `read`,
                                    decided reeflex.policy/read_only_internal

so each of expire, reset, restore, rotate, overwrite, commit, compact, vacuum
and install was indistinguishable from `frobnicate`, and 25 reversible
`expire`/`overwrite`/`vacuum` calls in one session charged R5's deletions
budget nothing (the canonical-`delete` control in the same run held on 21).

THE RULE THIS MODULE PINS, which is the part that is easy to get backwards: an
unrecognized IRREVERSIBLE verb already resolves to `delete`, so a word may only
JOIN the canon with a mapping at least as guarded as what it resolves to today
— in practice `delete`, or not at all.  RFX-308's own "shape of a fix" proposed
`compact/vacuum -> update` and `restore -> create`; those would have taken an
irreversible production `overwrite` OUT of the deletions budget.  Two of the
nine (`commit`, `install`) name no destruction, so they are deliberately still
absent and their residual is pinned below rather than quietly closed.

THE RFX-304 ELECTION (PR #158) LANDED FIRST, AND TWO ASSERTIONS HERE DID NOT
SURVIVE IT.  This module was written against a main where #158 was still
unmerged, and its original body claimed every assertion held both under the
leading-word fallback and under the most-guarded-word election.  Measured on
the merge (dev-2--067), two did not:

  * `check_rotation_schedule` resolves `execute`, not `read` — #158 elects
    `schedule` (rank 1) over the leading `check` (rank 0).  NOT caused by
    these seven words: `rotation` has no canon entry and the bare `rotate`
    does not appear in the name.  Reverting `envelope.py` to main and keeping
    only this file reproduces it, which is the control that assigns the cause.
    Filed RFX-330.
  * ability `db/get-vacuum-progress` escalates a declared `read` to `delete`.
    That one IS caused by this widening, and it is the cost the design note
    already prices for `show_vacuum_progress`.

Both are asserted below in their measured form, under their own names, rather
than removed — a wrong expectation deleted is a cost nothing measures.  The
other names whose reading differs between fallback and election
(`get_reset_token_status` is a read on main and a delete under the election)
are still not asserted here; they are reported in dev-1--080's evidence, where
the before/after is measured against a real core rather than modelled.

NOTE ON STYLE: unittest.TestCase classes, not bare `def test_*` functions —
gate.py runs this suite with `unittest discover`, where a module of plain
functions contributes ZERO tests.
"""

from __future__ import annotations

import unittest

from app.envelope import _VERB_CANON, validate_and_fill_defaults
from app import ledger


# The nine words reeflex-mcp's _MUTATING_STEMS knows.  Seven now resolve here;
# two are deliberately absent, which is itself asserted below.
SEVEN_ADDED = ("expire", "reset", "rotate", "overwrite", "compact",
               "vacuum", "restore")
TWO_LEFT_OUT = ("commit", "install")


def _env(verb, count=1, ability="eval/synthetic", environment="dev",
         reversibility="irreversible"):
    return {
        "agent": {"id": "agent:test", "session_id": "s-rfx308-1"},
        "action": {"namespace": "t", "verb": verb, "ability": ability},
        "target": {"environment": environment},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": "single",
            "externality": "internal",
        },
    }


def _verb(raw, ability="eval/synthetic", reversibility="irreversible"):
    env = _env(raw, ability=ability, reversibility=reversibility)
    return validate_and_fill_defaults(env)["action"]["verb"]


class TestTheSevenWordsNowNameTheirOperation(unittest.TestCase):
    """A word an operator uses for a destruction is priced as one.

    The REVERSIBLE arm is the one that moves: it used to land on `update`,
    which no budget charges, so a session could `expire` or `vacuum` without
    limit while the same session's `delete` held on call 21.
    """

    def test_seven_words_resolve_to_delete_on_the_reversible_arm(self):
        # Pre-fix this arm returned "update" for all seven.
        for word in SEVEN_ADDED:
            for rev in ("reversible", "recoverable"):
                with self.subTest(verb=word, reversibility=rev):
                    self.assertEqual(_verb(word, reversibility=rev), "delete")

    def test_seven_words_resolve_to_delete_on_the_irreversible_arm_too(self):
        # Unchanged in VALUE (the default already elected `delete`) and changed
        # in KIND: it is now the word's meaning rather than a guess, which is
        # what provenance and the audit line record.
        for word in SEVEN_ADDED:
            with self.subTest(verb=word):
                self.assertEqual(_verb(word, reversibility="irreversible"),
                                 "delete")

    def test_case_and_separator_spellings_fold_the_same_way(self):
        for raw in ("Vacuum", "VACUUM", " overwrite ", "Reset", "ROTATE"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"),
                                 "delete")

    def test_the_widening_lowers_no_existing_reading(self):
        """No word in the canon resolves to something LESS guarded than the
        default it would have got — for the seven this ticket added.

        This is the invariant that makes the change safe to land on its own:
        `delete` is the most-guarded member, so neither arm can move down.
        """
        for word in SEVEN_ADDED:
            with self.subTest(verb=word):
                self.assertEqual(_VERB_CANON[word], "delete")


class TestTheTwoWordsLeftOutAreLeftOutDELIBERATELY(unittest.TestCase):
    """`commit` and `install` name no destruction, so they earn no `delete`.

    Mapping them to `transact`/`execute` — their honest meaning — would LOWER
    the guard their irreversible use gets today.  The residual that leaves is
    named in the envelope.py note: under the RFX-304 election a compound like
    `count_and_install` still elects `count` -> `read`.  Closing that wants a
    rule about UNKNOWN words in the election, not more vocabulary.

    If a later round decides otherwise, this test is the place the expectation
    has to be moved deliberately.
    """

    def test_commit_and_install_have_no_canon_entry(self):
        for word in TWO_LEFT_OUT:
            with self.subTest(verb=word):
                self.assertNotIn(word, _VERB_CANON)

    def test_their_irreversible_use_still_lands_on_the_guarded_default(self):
        for word in TWO_LEFT_OUT:
            with self.subTest(verb=word):
                self.assertEqual(_verb(word, reversibility="irreversible"),
                                 "delete")

    def test_their_reversible_use_is_the_inert_default_as_before(self):
        for word in TWO_LEFT_OUT:
            with self.subTest(verb=word):
                self.assertEqual(_verb(word, reversibility="reversible"),
                                 "update")


class TestAbilityCrossCheckSeesTheseWordsNow(unittest.TestCase):
    """The mislabel cross-check resolves the ability through the SAME map.

    So the gap was shared: an adapter that labelled the verb `read` and named
    the operation honestly — `db/expire-rows` — signalled nothing, and the
    action was decided reeflex.policy/read_only_internal.
    """

    def test_an_ability_naming_one_of_the_seven_escalates_a_read_verb(self):
        for word in SEVEN_ADDED:
            with self.subTest(ability_word=word):
                self.assertEqual(_verb("read", ability="db/%s-rows" % word),
                                 "delete")

    def test_past_tense_and_noun_forms_still_do_not_false_positive(self):
        # The forms a READ operation actually uses. They have no canon entry,
        # which is the same reason "s3/list-deleted-objects" does not signal.
        for ability in ("db/expired-rows", "db/compaction-stats",
                        "iam/rotation-schedule", "pkg/installed-list",
                        "s3/list-expired-objects"):
            with self.subTest(ability=ability):
                self.assertEqual(_verb("read", ability=ability), "read")

    def test_an_ability_carrying_the_BARE_word_escalates_even_when_it_reads(self):
        """The cost of the widening, on the ability path, named not hidden.

        `db/get-vacuum-progress` was written into the list above as a form
        that "still does not false positive". It is not one, and the list's
        own stated principle is why: that principle is *past-tense and noun
        forms have no canon entry*, and this ability carries the BARE verb
        `vacuum`, which after RFX-308 does. Measured, it escalates a declared
        `read` to `delete`.

        This is the acknowledged cost, not a surprise — the same escalation
        the design note prices for `show_vacuum_progress`, one of the four
        adversarial read-only names it counts. It costs a HOLD once the
        operator's deletions budget is spent, it names its reason, and the
        adapter removes it by declaring a canonical verb. Asserted here so the
        cost is measured by the suite rather than described in a comment.
        """
        self.assertEqual(_verb("read", ability="db/get-vacuum-progress"),
                         "delete")

    def test_the_cross_check_still_only_escalates(self):
        self.assertEqual(_verb("delete", ability="db/vacuum-rows"), "delete")
        self.assertEqual(_verb("expire", ability="db/read-rows",
                               reversibility="reversible"), "delete")


class TestReadOnlyNamesThatMerelyCONTAINTheseWords(unittest.TestCase):
    """The cost side, bounded where it can be bounded.

    A compound built from a read verb and one of these words as a NOUN stays a
    read under both the leading-word fallback and the RFX-304 election, because
    the noun forms have no entry.  These are the names an operator writes for a
    genuine read, and a wrong DENY on them would be the expensive failure.
    """

    def test_noun_and_past_tense_compounds_stay_reads(self):
        for name in ("list_expired_sessions", "list_installed_packages",
                     "get_compaction_stats",
                     "list_commits", "describe_restoration_plan"):
            with self.subTest(verb=name):
                self.assertEqual(_verb(name, reversibility="reversible"),
                                 "read")

    def test_check_rotation_schedule_is_NOT_a_read_and_these_words_are_not_why(self):
        """Measured on the merge, and it belongs to RFX-304, not to RFX-308.

        `check_rotation_schedule` was written into the list above as a noun
        form that stays a read. It does not: it resolves `execute`. The cause
        is not this ticket's vocabulary — `rotation` has no canon entry, and
        the bare `rotate` this PR adds does not appear in the name. It is the
        RFX-304 election (#158, on main since `3e78749`) electing the most
        guarded word it knows: `check` -> read (rank 0) and `schedule` ->
        execute (rank 1), so `execute` wins.

        So the claim in this module's original body — that every assertion
        here holds both under the leading-word fallback and under the #158
        election — is false for this one name, and it was false the moment
        #158 landed, with or without these seven words. The control that
        shows it: with `envelope.py` reverted to main and only this test file
        applied, this name still resolves `execute`.

        The behaviour is inside #158's declared escalation bias rather than
        outside it, so this is an assertion correction and not a product
        change. Filed as RFX-330 for the separate question of whether a
        non-leading `schedule` should elect `execute` over a leading `check`.
        """
        self.assertEqual(_verb("check_rotation_schedule",
                               reversibility="reversible"), "execute")
        # And the reason, asserted so a later canon edit cannot make this
        # test pass for a different reason than the one documented above.
        self.assertNotIn("rotation", _VERB_CANON)
        self.assertEqual(_VERB_CANON.get("schedule"), "execute")


class TestTheDeletionsBudgetActuallyCharges(unittest.TestCase):
    """The half that makes the fragmented attack fail.

    Canonicalizing is only worth something if the key the policy reads —
    cumulative.count_by_verb.delete — accumulates.  Measured live: 25
    reversible `overwrite` calls in one session never tripped, while the
    canonical `delete` control tripped on call 21.
    """

    def setUp(self):
        self.session = "s-rfx308-frag"
        ledger.clear_session(self.session)

    tearDown = setUp

    def _append(self, verb, count, reversibility="reversible"):
        env = validate_and_fill_defaults({
            "agent": {"id": "agent:test", "session_id": self.session},
            "action": {"namespace": "t", "verb": verb, "ability": "t/x"},
            "target": {"environment": "dev"},
            "magnitude": {"count": count},
            "axes": {"reversibility": reversibility,
                     "blast_radius": "single", "externality": "internal"},
        })
        ledger.append_entry(self.session, env)

    def test_reversible_destructive_words_accumulate_under_the_delete_key(self):
        # 7 x count=3 = 21 reversible destructions under seven spellings.
        # Before: every one of them landed on "update" and .delete was absent.
        for verb in SEVEN_ADDED:
            self._append(verb, 3)
        cumulative = ledger.compute_cumulative(self.session, 3600)
        self.assertEqual(cumulative["count_by_verb"].get("delete"), 21)
        self.assertEqual(
            [k for k in cumulative["count_by_verb"] if k != "delete"], [],
            "no non-canonical verb key may survive into the cumulative object",
        )

    def test_the_budget_of_20_is_now_reached_by_these_spellings(self):
        # budgets.rego: deletions limit 20, prior + current, strict '>'.
        for _ in range(4):
            self._append("overwrite", 5)
        prior = ledger.compute_cumulative(self.session, 3600)
        self.assertEqual(prior["count_by_verb"]["delete"], 20)
        self.assertGreater(prior["count_by_verb"]["delete"] + 1, 20)

    def test_a_read_that_merely_names_one_of_them_charges_nothing(self):
        for verb in ("list_expired_sessions", "get_compaction_stats"):
            self._append(verb, 50)
        cumulative = ledger.compute_cumulative(self.session, 3600)
        self.assertNotIn("delete", cumulative["count_by_verb"])
        self.assertEqual(cumulative["count_by_verb"].get("read"), 100)


if __name__ == "__main__":
    unittest.main()
