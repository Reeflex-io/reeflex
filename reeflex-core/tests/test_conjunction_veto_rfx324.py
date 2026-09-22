"""
test_conjunction_veto_rfx324.py — RFX-324: a leading read word does not make a
SECOND operation a read.

THE DEFECT, measured as a DECISION on `caf2cd6` and not as a string.  RFX-304
made a compound elect its most-guarded KNOWN word and dev-1--080 added "a
`read` may only be elected from the LEADING word".  Both leave one shape open:
a compound whose leading word is a genuine read and whose operative verb the
canon does not know still elects the leading read.  envelope.py's RFX-308 note
records it as two words (`commit`, `install`).  It is not two words — the
election skips EVERY word the canon does not know, so the residual is the whole
complement of the canon.

    envelope: irreversible / scoped / internal / production, deletions budget 20

    verb "get_and_redact"             allow  reeflex.policy/read_only_internal
    verb "list_and_anonymize"         allow  reeflex.policy/read_only_internal
    verb "describe_and_decommission"  allow  reeflex.policy/read_only_internal
    verb "list_and_unmount"           allow  reeflex.policy/read_only_internal
    ... 14 of 14 arms allowed, none stopping within 26 calls in one session
    verb "delete" (control)           require_approval at call 21

i.e. GDPR erasure, account lifecycle and infra teardown — spelled the way an
HONEST adapter names them, which is the integration this canon exists to serve
— decided by the one rule that hands out an allow, written into the permanent
audit line as `verb: "read"`, and charged nothing by the budget that prices
destruction.

WHY THE TESTS BELOW ARE IN TWO LAYERS.  The pre-existing suite pins this
surface at the canonicalisation layer and says why:

    "R1 is `verb == "read"` AND externality internal.  The verb half is what
     this fix owns; assert it directly rather than through a rule."
    (test_compound_verb_election_rfx304.py)

That is a reasonable boundary for a verb fix and it is also how a residual of
this class survived being "pinned": `_verb(...) == "read"` is a different claim
from "an irreversible production erasure is ALLOWED with no human in it", and
only the second one is the product's promise.  So this module asserts the verb
AND drives `app.decide.process` over the real pack for the same names.

THE COST IS PINNED TOO, BOTH DIRECTIONS.  The rule this file adds is narrow on
purpose.  envelope.py's own note proposes the wide one ("an unknown word
outranking `read`"); scored through the shipped elector over 130 names — the
82-name census in `code-reports/dev-1--080-evidence` plus 12 arms in four
spellings — the wide rule closes the same 48 arm spellings and turns 34 of the
36 names that census declares reads into the irreversible default, including
`GetObject`, `search_files`, `query_database` and `read_text_file`.  The
narrow rule closes 48 and moves none of the 36.  TestTheCostOfTheNarrowRule
below is that second column, so a later widening cannot be made quietly.

WHAT THIS DID NOT CLOSE — AND WHAT RFX-350 THEN DID.  A second operation named
WITHOUT a conjunction after a leading read word (`get_subject_erasure`) still
elected the read, and `TestTheResidualThisDoesNotClose` pinned that as the
limit it was.  RFX-350 closed it; that class is now
`TestAnElectedReadDoesNotSurviveIrreversible`, which records the closure AND
its price.

That price is why several tables in this module now pass
`reversibility="reversible"` where they used to take `_env`'s default.  It is
not a weakening and it is not cosmetic: those rows are DECLARED READS, so the
reversible arm is the envelope they actually carry, and on the irreversible arm
core no longer elects `read` at all.  Every one of those tables has a matching
irreversible-arm assertion immediately after it, so the move is pinned from
both sides rather than quietly made.

NOTE ON STYLE: unittest.TestCase, not bare pytest functions — gate.py runs this
suite with `unittest discover`, where a module of plain `def test_*` functions
contributes ZERO tests.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.decide import process  # noqa: E402
from app.envelope import (  # noqa: E402
    _VERB_CANON,
    _VERB_CONJUNCTIONS,
    validate_and_fill_defaults,
)

# The 12 operations qa--229 measured escaping, each in the four spellings an
# adapter actually emits.  `_split_words` folds all four, so an arm measured in
# one spelling says nothing about the other three — and all four escaped.
ARM_OPERATIONS = [
    "count_and_install", "count_and_commit", "get_and_redact",
    "list_and_anonymize", "query_and_scrub", "get_and_archive",
    "list_and_deactivate", "get_and_suspend", "describe_and_decommission",
    "list_and_retire", "search_and_quarantine", "list_and_unmount",
]


def _spellings(snake: str) -> list[str]:
    parts = snake.split("_")
    camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
    return [snake, camel, "-".join(parts), ".".join(parts)]


ARMS = [spelled for op in ARM_OPERATIONS for spelled in _spellings(op)]

_SESSION_SEQ = [0]


def _env(verb, count=1, ability=None, reversibility="irreversible",
         blast_radius="scoped", session=None):
    """The envelope that ISOLATES THE VERB, and why each field is what it is.

    `blast_radius: scoped`   R2 needs `broad` and R3 needs `systemic`, so
                             neither fires and no rule reads anything but the
                             verb and the budget.  qa--229's first attempt used
                             `single`/count 1, where a canonical `delete` is
                             allowed too — its refusal control caught that the
                             arms were measuring nothing.
    `ability` absent         an `ability` in the `eval/*` namespace trips R7
                             (`authority_change_prod`) on call 1, which would
                             refuse every arm for a reason that is not this
                             fix.  The two cases that DO pass an ability pass a
                             realistic one, and say so.
    """
    _SESSION_SEQ[0] += 1
    action = {"namespace": "t", "verb": verb}
    if ability is not None:
        action["ability"] = ability
    return {
        "agent": {"id": "agent:rfx324",
                  "session_id": session or "sess-rfx324-%d" % _SESSION_SEQ[0]},
        "action": action,
        "target": {"environment": "production"},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": "internal",
        },
    }


def _verb(raw, **kw):
    return validate_and_fill_defaults(_env(raw, **kw))["action"]["verb"]


def _opa_available() -> bool:
    return bool(os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa"))


class TestTheOperativeVerbsAreNotInTheCanon(unittest.TestCase):
    """The arms below only test the ELECTION while these stay unknown.

    If a later round adds `redact` or `install` to _VERB_CANON, every arm in
    this module starts passing for a reason that has nothing to do with the
    conjunction rule — a green that measures vocabulary instead of behaviour.
    """

    OPERATIVE = ["install", "commit", "redact", "anonymize", "scrub", "archive",
                 "deactivate", "suspend", "decommission", "retire",
                 "quarantine", "unmount"]

    def test_none_of_the_operative_verbs_is_in_the_canon(self):
        for word in self.OPERATIVE:
            with self.subTest(word=word):
                self.assertNotIn(word, _VERB_CANON)

    def test_the_conjunctions_are_not_verbs_either(self):
        # A conjunction that were also a canon member would be elected as a
        # verb and the veto would never see it.
        for word in _VERB_CONJUNCTIONS:
            with self.subTest(word=word):
                self.assertNotIn(word, _VERB_CANON)


class TestTheResidualAsAVerb(unittest.TestCase):
    """48 spellings, all of which resolved to `read` on caf2cd6."""

    def test_no_arm_is_a_read_on_either_reversibility(self):
        for raw in ARMS:
            for reversibility in ("irreversible", "reversible"):
                with self.subTest(verb=raw, reversibility=reversibility):
                    self.assertNotEqual(
                        _verb(raw, reversibility=reversibility), "read")

    def test_an_irreversible_arm_lands_on_the_guarded_default(self):
        # The veto returns None, so the caller falls through to the
        # reversibility default — `delete`, which is the member R5's deletions
        # budget prices.
        for raw in ARMS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), "delete")

    def test_a_reversible_arm_lands_on_the_inert_default_not_on_read(self):
        # Stated rather than hidden: on the reversible arm the fall-through is
        # `update`, which no rule reads.  The gain there is that the audit line
        # stops positively asserting a read, not a budget charge.
        for raw in ARMS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"),
                                 "update")


class TestTheVetoIsNarrow(unittest.TestCase):
    """It fires on a conjunction with an UNKNOWN word after it, and nowhere else."""

    def test_a_conjunction_between_two_known_reads_is_still_a_read(self):
        # Scored on the REVERSIBLE arm since RFX-350: these are reads, so that
        # is the envelope they carry.  RFX-350's clause fires on the axis, so
        # on an irreversible envelope even an all-known-reads compound lands on
        # the guarded default -- asserted immediately below rather than left to
        # be discovered.
        for raw in ("list_and_count", "get_and_list", "read_and_query"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"), "read")

    def test_and_on_the_irreversible_arm_even_those_land_on_the_default(self):
        for raw in ("list_and_count", "get_and_list", "read_and_query"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="irreversible"), "delete")

    def test_a_known_non_read_after_the_conjunction_still_wins(self):
        # The veto only ever suppresses an elected `read`; it does not touch
        # the election itself.
        for raw, expected in (("get_or_create_index", "create"),
                              ("get_and_transfer", "transact"),
                              ("fetch_and_send_report", "emit"),
                              ("fetch_and_apply_migration", "execute"),
                              ("search_and_replace", "update"),
                              ("findOneAndDelete", "delete"),
                              ("list_and_prune_snapshots", "delete")):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw), expected)

    def test_a_read_with_no_conjunction_is_untouched(self):
        # The names the last resort exists to serve: extra words that are an
        # object noun phrase, not a second operation.  On the REVERSIBLE arm
        # since RFX-350 -- see TestAnElectedReadDoesNotSurviveIrreversible.
        for raw in ("GetObject", "ListBuckets", "query_status",
                    "list_deleted_objects", "get_pull_request_comments",
                    "list_directory_with_sizes", "search_files",
                    "read_text_file", "getUserProfile"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"), "read")

    def test_or_and_then_are_covered_not_just_and(self):
        for raw in ("get_or_redact", "list_then_purge", "fetch_then_scrub"):
            with self.subTest(verb=raw):
                self.assertNotEqual(_verb(raw), "read")


class TestTheCostOfTheNarrowRule(unittest.TestCase):
    """The names a customer reads with, which must NOT move.

    Sourced, not invented: every name here is declared a read by dev-1--080's
    census (`code-reports/dev-1--080-evidence/*-census.json`) AND resolves to
    `read` on the shipped tree this change is measured against.  The census
    also contains 11 names it declares reads that the SHIPPED tree already
    escalates (`list_trash`, `get_overwrite_policy`, ...); those are RFX-304's
    and RFX-308's documented escalation cost, they are not this rule's, and
    they are deliberately absent here so this table cannot be read as
    endorsing them.
    """

    STILL_READS = [
        # reeflex-mcp's own corpus
        "count_records", "fetch_url", "find_records", "find_symbol",
        "getUserProfile", "get_pull_request_comments", "listActiveUsers",
        "list_directory_with_sizes", "list_issues", "query_database",
        "query_status", "read_text_file", "search_files", "search_index",
        "select_columns",
        # the AWS/S3-shaped names the last resort was added for
        "GetObject", "ListBuckets",
        # qa-213's wrong-escalation controls
        "get_deleted_items", "list_deleted_objects",
        # dev-1--080's adversarial reads: a destructive word in a NOUN form
        "count_dropped_frames", "get_compaction_stats", "list_commits",
        "list_expired_sessions", "list_installed_packages", "list_revoked_certs",
    ]

    def test_every_genuine_read_in_the_census_is_still_a_read(self):
        # RFX-350 MOVED THIS ASSERTION FROM ONE ARM TO THE OTHER, and that is
        # the whole cost of RFX-350's fix — read the class docstring above and
        # `TestAnElectedReadDoesNotSurviveIrreversible` below before changing it
        # back.  These names are declared READS, so the envelope they travel on
        # is the REVERSIBLE one; this table used to be scored on the
        # irreversible arm only because RFX-324's rule did not read that axis
        # and the irreversible arm was where `read` vs `delete` was observable.
        for raw in self.STILL_READS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"), "read")

    def test_the_table_is_not_empty_and_covers_the_real_corpus(self):
        # A cost column that someone empties is a cost column that passes.
        self.assertGreaterEqual(len(self.STILL_READS), 25)
        self.assertIn("search_files", self.STILL_READS)
        self.assertIn("GetObject", self.STILL_READS)

    def test_and_on_the_irreversible_arm_every_one_of_them_now_MOVES(self):
        """RFX-350's cost, pinned as a NUMBER so it cannot grow unnoticed.

        Not a regression and not hidden: a caller asserting that `GetObject`
        CANNOT BE UNDONE is the contradiction RFX-350's clause refuses to let
        R1 win, and the clause fires on the axis, not on the name.  If a later
        round narrows that clause, this test fails and says so.
        """
        moved = [raw for raw in self.STILL_READS
                 if _verb(raw, reversibility="irreversible") != "read"]
        self.assertEqual(sorted(moved), sorted(self.STILL_READS))
        # ...and every one of them lands on the GUARDED default, not on an
        # inert one -- the deletions budget is the point.
        for raw in self.STILL_READS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="irreversible"),
                                 "delete")


class TestAnElectedReadDoesNotSurviveIrreversible(unittest.TestCase):
    """RFX-350, the residual RFX-324 left open — CLOSED, and how.

    This class replaces `TestTheResidualThisDoesNotClose`, whose docstring
    said: "WHEN THIS TEST FAILS, the residual has been closed — check the cost
    table in TestTheCostOfTheNarrowRule first, then update this assertion."
    Both were done; the cost table is updated directly above.

    THE ASYMMETRY THAT WAS OPEN.  `get_subject_erasure` elected `get`, so on an
    irreversible production envelope it was decided `read_only_internal` and
    charged nothing by the deletions budget, while the SAME operation named
    `subject_erasure` — one word shorter — landed on the guarded default.
    Prefixing a read word to a destruction's name de-escalated it, and the
    caller supplies the name.

    WHAT CLOSED IT is not a better reading of the NAME.  Every rule that reads
    only the name was measured and rejected: the wide unknown-word veto (FIX A,
    23 further declared reads broken on BOTH arms), and — new in RFX-350 — a
    morphological rule deriving `erasure` -> `erase`, which reaches 1 of the 12
    arm operations and escalates `get_tags`, `get_writer` and `get_formats` to
    pay for it.  The clause that closed it reads the reversibility AXIS: core
    does not hand out `read`, the only value that unlocks R1, as its OWN GUESS
    about an action the caller says cannot be undone.
    """

    # The twelve operations, spelled WITHOUT a conjunction.  Four are
    # nominalisations and eight are bare unknown verbs, deliberately: an arm
    # set made only of `-ion`/`-ure` words would measure a morphological rule
    # against its own definition.
    ARMS_350 = [
        "get_subject_erasure", "get_account_deactivation",
        "list_cluster_decommission", "describe_tenant_retirement",
        "query_record_anonymization", "get_volume_unmount",
        "search_index_quarantine", "list_user_scrub", "get_backup_archive",
        "describe_node_commit", "count_package_install", "get_document_redact",
    ]

    def test_a_second_operation_without_a_conjunction_no_longer_elects_the_read(self):
        for raw in self.ARMS_350:
            for spelled in _spellings(raw):
                with self.subTest(verb=spelled):
                    self.assertEqual(_verb(spelled), "delete")

    def test_the_one_word_asymmetry_is_gone(self):
        # The pair that states the defect in two lines.
        self.assertEqual(_verb("subject_erasure"), "delete")
        self.assertEqual(_verb("get_subject_erasure"), "delete")

    def test_a_DECLARED_read_is_untouched_on_either_arm(self):
        # The line this clause draws: a caller's own canon word is a
        # DECLARATION and survives; an election is core's GUESS and does not.
        # The deliberate mislabel (`verb: "read"` over a delete) is NOT what
        # this closes -- `_delete_signal_from_ability` and R6 are that defence.
        for raw in ("read", "list", "get", "query", "describe", "search"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="irreversible"), "read")
                self.assertEqual(_verb(raw, reversibility="reversible"), "read")

    def test_the_same_names_on_a_REVERSIBLE_envelope_are_unchanged(self):
        # The control that separates this fix from FIX A.  If these move, the
        # clause has stopped reading the axis and started reading the name.
        for raw in ("GetObject", "search_files", "query_database",
                    "read_text_file", "getUserProfile",
                    "list_directory_with_sizes", "get_pull_request_comments",
                    "list_commits", "get_subject_erasure"):
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"), "read")

    def test_RFX_324_stays_closed(self):
        # The conjunction veto is untouched by RFX-350 and must keep working on
        # its own, including on the reversible arm where the new clause never
        # fires at all.
        for raw in ARM_OPERATIONS:
            with self.subTest(verb=raw):
                self.assertEqual(_verb(raw, reversibility="reversible"), "update")


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestTheArmsAreRefusedAsADECISION(unittest.TestCase):
    """The claim the string assertions above do not make.

    Controls run in the same class, because an arm without one measures
    nothing: a canonical `delete` must be refused (the instrument can see a
    refusal) and a genuine `list` must be allowed (R1 is reachable, so an
    `allow` on an arm would have been a real R1 allow).
    """

    # R5's deletions budget is 20 and charges `verb == "delete"` only;
    # `objects_touched` is 200, so count=45 separates the two verbs in ONE
    # call without tripping the dimension that charges every action.
    COUNT = 45

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = {k: os.environ.get(k) for k in
                      ("REEFLEX_HOLDS_PATH", "REEFLEX_AUDIT_LOG",
                       "REEFLEX_LEDGER_PATH")}
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._tmp.name, "holds.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self._tmp.name, "audit.jsonl")
        os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(self._tmp.name, "ledger.jsonl")
        import app.holds as holds_mod
        import app.ledger as ledger_mod
        holds_mod._reset(os.environ["REEFLEX_HOLDS_PATH"])
        # The module is imported before setUp runs, so the ledger still holds a
        # cursor into the PREVIOUS case's file; without this, a trip-call number
        # measures whatever the last test spent.
        ledger_mod._reset_for_tests()

    def tearDown(self):
        for k, v in self._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def _decide(self, verb, **kw):
        return process(_env(verb, count=self.COUNT, **kw))[1]

    def test_0_the_controls_prove_the_instrument_can_see_both_verdicts(self):
        refused = self._decide("delete")
        self.assertEqual(refused["decision"], "require_approval", refused)
        self.assertEqual(refused["rule"], "reeflex.policy/session_delete_budget")
        allowed = self._decide("list")
        self.assertEqual(allowed["decision"], "allow", allowed)
        self.assertEqual(allowed["rule"], "reeflex.policy/read_only_internal")

    def test_1_no_arm_is_allowed_by_read_only_internal(self):
        for raw in ARMS:
            with self.subTest(verb=raw):
                resp = self._decide(raw)
                self.assertNotEqual(resp["rule"],
                                    "reeflex.policy/read_only_internal", resp)
                self.assertNotEqual(resp["decision"], "allow", resp)

    def test_2_an_honest_ability_id_does_not_rescue_the_arm_either(self):
        # The `ability` cross-check resolves its segment through the same
        # canon, so an adapter naming the operation honestly signalled nothing
        # before this change.  Pinned because it is the field an integrator is
        # told to fill in.
        for raw, ability in (("get_and_redact", "gdpr/redact-subject-data"),
                             ("count_and_install", "pkg/install-agent")):
            with self.subTest(verb=raw):
                resp = self._decide(raw, ability=ability)
                self.assertNotEqual(resp["decision"], "allow", resp)

    def test_3_the_arm_trips_the_deletions_budget_at_the_same_call_as_delete(self):
        # ASSERT THE TRIP CALL NUMBER, NOT "A HOLD HAPPENED" (qa--213 §8): an
        # arm that stops at a different call from its control is being stopped
        # by something else.
        def trip(verb):
            session = "sess-rfx324-trip-%s" % verb
            for n in range(1, 27):
                resp = process(_env(verb, count=1, session=session))[1]
                if resp["decision"] != "allow":
                    return n, resp["rule"]
            return None, None

        control_call, control_rule = trip("delete")
        self.assertEqual(control_call, 21)
        self.assertEqual(control_rule, "reeflex.policy/session_delete_budget")
        for raw in ("get_and_redact", "describe_and_decommission",
                    "count_and_install"):
            with self.subTest(verb=raw):
                self.assertEqual(trip(raw), (control_call, control_rule))
        # ...and a genuine read still never trips it.
        self.assertEqual(trip("list"), (None, None))

    def test_4_a_genuine_read_is_still_allowed_after_the_change(self):
        # RFX-350: on the envelope a genuine read actually carries.  `_env`
        # defaults to irreversible to ISOLATE THE VERB (see its docstring), and
        # that default is what made this control read `GetObject` as a read on
        # an envelope asserting GetObject cannot be undone.
        for raw in ("GetObject", "search_files", "list_directory_with_sizes"):
            with self.subTest(verb=raw):
                resp = self._decide(raw, reversibility="reversible")
                self.assertEqual(resp["decision"], "allow", resp)
                self.assertEqual(resp["rule"],
                                 "reeflex.policy/read_only_internal")

    def test_5_the_RFX_350_arms_are_refused_as_a_DECISION(self):
        # The claim the string assertions do not make: 12 of 12 were ALLOWED
        # under read_only_internal on `a9ea130`, none of them stopping within
        # 26 calls in one session.
        for raw in TestAnElectedReadDoesNotSurviveIrreversible.ARMS_350:
            with self.subTest(verb=raw):
                resp = self._decide(raw)
                self.assertNotEqual(resp["decision"], "allow", resp)
                self.assertEqual(resp["rule"],
                                 "reeflex.policy/session_delete_budget")


if __name__ == "__main__":
    unittest.main()
