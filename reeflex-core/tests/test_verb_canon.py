"""
test_verb_canon.py — F6/RFX-CORE-3: action.verb canonicalization (fail-closed).

Regression guard for the R5 evasion where the cumulative delete budget could
be walked past by spelling the delete differently. R5 keys on the EXACT literal
"delete" on both sides:

    budgets.rego current_for("deletions")     input.action.verb == "delete"
    budgets.rego cumulative_for("deletions")  cumulative.count_by_verb.delete
    ledger.py    count_by_verb[verb]          the verb string VERBATIM

so "Delete", "DELETE", "remove", "destroy", "purge", "drop", "truncate", "rm",
"delete " and "delete​" each accumulated under their own ledger key and
never reached the budget — verdict R4 default_allow, unbounded (confirmed live
on api-dev v0.1.13: 10 of 11 spellings never tripped across 30 deletes; only
the exact "delete" held, at 25).

Two layers are covered here:
  1. envelope-level  — validate_and_fill_defaults() yields the canonical verb.
  2. ledger-level    — the cumulative key the policy reads actually moves,
                       which is the part that makes the FRAGMENTED attack fail.
Neither needs OPA.

NOTE ON STYLE: these are unittest.TestCase classes, not bare pytest functions,
because gate.py runs this suite with `unittest discover` — a module of plain
`def test_*` functions is imported and contributes ZERO tests there.
"""

from __future__ import annotations

import unittest

from app.envelope import validate_and_fill_defaults, ValidationError
from app import ledger


def _env(verb, count=1, ability="eval/synthetic", environment="dev"):
    return {
        "agent": {"id": "agent:test", "session_id": "s-verb-1"},
        "action": {"namespace": "t", "verb": verb, "ability": ability},
        "target": {"environment": environment},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": "irreversible",
            "blast_radius": "single",
            "externality": "internal",
        },
    }


def _verb(raw, ability="eval/synthetic"):
    return validate_and_fill_defaults(_env(raw, ability=ability))["action"]["verb"]


class TestDeleteSpellingsCanonicalize(unittest.TestCase):
    """Every spelling that evaded R5 on live must now canonicalize to "delete"."""

    # Exactly the spellings the live probe confirmed evaded, plus the rest of
    # the synonym surface. scripts/attack-probe-r5-fragmented.py replays these.
    EVADED_ON_LIVE = [
        "Delete", "DELETE", "remove", "destroy", "purge", "drop",
        "truncate", "rm", "hard_delete", "delete​",
    ]

    MORE_SYNONYMS = [
        "delete", "delete ", " delete", "delete\n", "delete\t", "  DeLeTe  ",
        "del", "erase", "wipe", "unlink", "expunge", "prune", "obliterate",
        "nuke", "shred", "discard", "trash", "revoke", "deprovision",
        "terminate", "kill", "teardown", "uninstall", "deregister",
        "bulk_delete", "delete_all", "delete_many", "batch_delete",
        "force_delete", "soft_delete",
        # compound separators all fold to the same alias
        "hard-delete", "hard delete", "hard.delete", "harddelete",
        "BULK-DELETE", "delete/all",
        # unicode: fullwidth (NFKC) and a BOM
        "ｄｅｌｅｔｅ", "﻿delete",
    ]

    def test_spellings_that_evaded_on_live_now_canonicalize(self):
        for raw in self.EVADED_ON_LIVE:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), "delete")

    def test_wider_synonym_surface_canonicalizes(self):
        for raw in self.MORE_SYNONYMS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), "delete")


class TestUnknownVerbFailsClosed(unittest.TestCase):
    """An out-of-enum verb coerces to a SPEC member, never passed through.

    The fallback is conditional on the (already canonicalized) reversibility
    axis: irreversible -> "delete", otherwise -> "update". See the
    "WHICH DEFAULT AN UNRECOGNIZED VERB GETS" note in envelope.py.
    """

    UNKNOWN = ("frobnicate", "zorp", "xyzzy-the-widget", "verb")

    def _verb_rev(self, raw, reversibility):
        env = _env(raw)
        env["axes"]["reversibility"] = reversibility
        return validate_and_fill_defaults(env)["action"]["verb"]

    def test_unknown_irreversible_verb_coerces_to_delete(self):
        for raw in self.UNKNOWN:
            with self.subTest(verb=raw):
                self.assertEqual(self._verb_rev(raw, "irreversible"), "delete")

    def test_unknown_reversible_verb_coerces_to_policy_inert_update(self):
        # Must NOT be billed to the deletions budget: this is the benign
        # long-tail action objects_touched (limit 200) exists to accumulate,
        # not the deletions budget (limit 20).
        for raw in self.UNKNOWN:
            for rev in ("reversible", "recoverable"):
                with self.subTest(verb=raw, reversibility=rev):
                    self.assertEqual(self._verb_rev(raw, rev), "update")

    def test_unknown_verb_never_coerces_to_read(self):
        # "read" is the one member that would hand out R1 (allow).
        for raw in self.UNKNOWN:
            for rev in ("irreversible", "reversible", "recoverable", "bogus"):
                with self.subTest(verb=raw, reversibility=rev):
                    self.assertNotEqual(self._verb_rev(raw, rev), "read")

    def test_missing_or_garbage_axes_lands_an_unknown_verb_on_delete(self):
        # F1 coerces an absent/garbage reversibility to "irreversible", so the
        # guarded default applies without the caller having to declare anything.
        for axes in (None, {}, {"reversibility": "Irreversible"},
                     {"reversibility": ["x"]}, {"reversibility": "nonsense"}):
            with self.subTest(axes=axes):
                env = _env("frobnicate")
                env["axes"] = axes
                self.assertEqual(
                    validate_and_fill_defaults(env)["action"]["verb"], "delete"
                )

    def test_unknown_verb_is_never_passed_through_verbatim(self):
        # The point of the fix: OPA must never see a value outside SPEC section 3.
        spec_verbs = {"read", "create", "update", "delete",
                      "execute", "transact", "emit"}
        for raw in ("frobnicate", "Delete", "remove", "list", "PAY", "​"):
            with self.subTest(verb=raw):
                self.assertIn(_verb(raw), spec_verbs)

    def test_verb_that_normalizes_to_empty_still_fails_closed(self):
        # "​" is a zero-width space: it normalizes away to "". It is a
        # non-empty string so it passes the structural check, then coerces to
        # the conservative default rather than reaching OPA as "".
        self.assertEqual(_verb("​"), "delete")

    def test_absent_and_empty_verb_still_hard_reject(self):
        bad = _env("delete")
        del bad["action"]["verb"]
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(bad)
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(_env(""))


class TestNonDeleteVerbsPreserved(unittest.TestCase):
    """The generous alias table is what keeps the wrong-DENY trade-off cheap.

    Coercing unknown -> delete would otherwise count ordinary reads against the
    deletions budget. These aliases cost nothing security-wise (a caller that
    wants to be classified non-delete can always just write "read"), and they
    prevent spurious holds for honest adapters.
    """

    CASES = [
        ("read", "read"), ("READ", "read"), ("list", "read"), ("get", "read"),
        ("select", "read"), ("query", "read"), ("describe", "read"),
        ("ls", "read"), ("export", "read"), ("download", "read"),
        ("create", "create"), ("insert", "create"), ("add", "create"),
        ("upload", "create"), ("clone", "create"), ("provision", "create"),
        ("update", "update"), ("modify", "update"), ("patch", "update"),
        ("rename", "update"), ("PUT", "update"), ("enable", "update"),
        ("execute", "execute"), ("run", "execute"), ("deploy", "execute"),
        ("apply", "execute"), ("restart", "execute"), ("migrate", "execute"),
        ("transact", "transact"), ("refund", "transact"), ("pay", "transact"),
        ("charge", "transact"), ("transfer", "transact"),
        ("emit", "emit"), ("send", "emit"), ("publish", "emit"),
        ("notify", "emit"), ("email", "emit"), ("broadcast", "emit"),
    ]

    def test_non_delete_verbs_map_to_their_own_spec_member(self):
        for raw, expected in self.CASES:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), expected)

    def test_camelcase_api_operation_names_resolve_to_their_verb(self):
        # AWS/S3-style operation names carried in action.verb. Without camel
        # splitting these all hit the conservative default and every GetObject
        # would be billed to the deletions budget -- a wrong-DENY at scale.
        for raw, expected in (
            ("DeleteObject", "delete"), ("DeleteBucket", "delete"),
            ("GetObject", "read"), ("ListObjects", "read"),
            ("PutObject", "update"), ("CreateBucket", "create"),
            ("listDeletedObjects", "read"), ("RunInstances", "execute"),
        ):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), expected)

    def test_read_alias_still_reads_so_freeze_and_r1_behave(self):
        # decide._is_read_verb() and R1 both key on "read"; an adapter emitting
        # "list" must not become a delete, or a freeze would deny its reads.
        for raw in ("list", "get", "query", "search", "describe", "inspect"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), "read")


class TestAbilityCrossCheck(unittest.TestCase):
    """A delete mislabelled as a read is caught by its own ability id.

    Narrow by construction: last "/" segment, FIRST token only.
    """

    def test_delete_ability_escalates_a_non_delete_verb(self):
        self.assertEqual(_verb("read", ability="wordpress/delete-post"), "delete")
        self.assertEqual(_verb("update", ability="s3/DeleteObject"), "delete")
        self.assertEqual(_verb("read", ability="db/drop_table"), "delete")

    def test_past_tense_and_object_names_do_not_false_positive(self):
        # First token is "list"/"get", so these stay reads -- the case that
        # would otherwise manufacture a wrong-DENY.
        self.assertEqual(_verb("read", ability="s3/list-deleted-objects"), "read")
        self.assertEqual(_verb("read", ability="wp/get-deleted-posts"), "read")
        self.assertEqual(_verb("read", ability="api/list-removals"), "read")

    def test_cross_check_only_escalates_never_relaxes(self):
        # A delete verb with an innocuous ability stays a delete.
        self.assertEqual(_verb("delete", ability="wordpress/read-post"), "delete")
        self.assertEqual(_verb("remove", ability="s3/GetObject"), "delete")

    def test_missing_or_odd_ability_is_harmless(self):
        for ability in (None, "", 123, [], {}, "/", "---"):
            with self.subTest(ability=ability):
                env = _env("read")
                env["action"]["ability"] = ability
                self.assertEqual(
                    validate_and_fill_defaults(env)["action"]["verb"], "read"
                )


class TestLedgerKeyActuallyMoves(unittest.TestCase):
    """The half that makes the FRAGMENTED attack fail.

    Canonicalizing the verb is only useful if the cumulative key the policy
    reads (cumulative.count_by_verb.delete) actually accumulates. This asserts
    the ledger side end-to-end, which is what the live repro exercised.
    """

    def setUp(self):
        self.session = "s-frag-test"
        ledger.clear_session(self.session)

    tearDown = setUp

    def _append(self, verb, count):
        env = validate_and_fill_defaults({
            "agent": {"id": "agent:test", "session_id": self.session},
            "action": {"namespace": "t", "verb": verb, "ability": "t/x"},
            "target": {"environment": "dev"},
            "magnitude": {"count": count},
            "axes": {"reversibility": "irreversible",
                     "blast_radius": "single", "externality": "internal"},
        })
        ledger.append_entry(self.session, env)

    def test_synonyms_accumulate_under_the_delete_key(self):
        # The live attack: 6 x count=5 = 30 deletes under mixed spellings.
        for verb in ("remove", "Delete", "destroy", "rm", "purge", "DELETE"):
            self._append(verb, 5)
        cumulative = ledger.compute_cumulative(self.session, 3600)
        # Before the fix this was {"remove":5,"Delete":5,...} and .delete was absent.
        self.assertEqual(cumulative["count_by_verb"].get("delete"), 30)
        self.assertEqual(
            [k for k in cumulative["count_by_verb"] if k != "delete"], [],
            "no non-canonical verb key may survive into the cumulative object",
        )

    def test_delete_budget_of_20_is_now_reached_by_synonyms(self):
        # budgets.rego: deletions limit 20, compared as prior + current.
        for _ in range(4):
            self._append("remove", 5)
        prior = ledger.compute_cumulative(self.session, 3600)
        self.assertEqual(prior["count_by_verb"]["delete"], 20)
        # The 5th fragmented call is the one that must now exceed the budget.
        self.assertGreater(prior["count_by_verb"]["delete"] + 5, 20)

    def test_reads_do_not_contribute_to_the_delete_key(self):
        for verb in ("read", "list", "get", "select"):
            self._append(verb, 50)
        cumulative = ledger.compute_cumulative(self.session, 3600)
        self.assertNotIn("delete", cumulative["count_by_verb"])
        self.assertEqual(cumulative["count_by_verb"].get("read"), 200)


class TestEnvironmentCanonUnweakened(unittest.TestCase):
    """Routing #89's environment canon through the shared normalizer must not
    weaken it, and should remove its invisible-character wrong-DENY."""

    def _envt(self, environment):
        e = _env("delete", environment=environment)
        return validate_and_fill_defaults(e)["target"]["environment"]

    def test_production_near_misses_still_coerce_to_production(self):
        for raw in ("production", "Production", "PROD", "prod", "prd", "live",
                    "production ", "  Production  ", "﻿production"):
            with self.subTest(env=raw):
                self.assertEqual(self._envt(raw), "production")

    def test_unrecognized_still_coerces_to_production(self):
        self.assertEqual(self._envt("frobnitz-custom-env"), "production")

    def test_invisible_char_no_longer_escalates_a_non_prod_tier(self):
        # Was "production" (a wrong-DENY) because the zero-width char made the
        # alias lookup miss; now folds to its real tier.
        self.assertEqual(self._envt("dev​"), "dev")
        self.assertEqual(self._envt("staging\n"), "staging")


if __name__ == "__main__":
    unittest.main()
