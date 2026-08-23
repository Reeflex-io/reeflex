"""
test_holds_vocabulary_rfx211_rfx218.py — the holds surface must refuse a word it
does not know, instead of answering it with a confident wrong answer.

WHAT THESE GUARD
================
RFX-211 and RFX-218 are the read and write halves of one defect: an enumerated
parameter whose "everything else" arm produced a wrong answer rather than a
refusal. Measured on origin/main 759b83f, 16 of 16 arms:

    GET /v1/holds?status=all        -> 200 {"items":[],"count":0}   FALSE ALL-CLEAR
    GET /v1/holds?status=resolved   -> 200 {"items":[],"count":0}   FALSE ALL-CLEAR
    GET /v1/holds?status=Pending    -> 200 {"items":[],"count":0}   FALSE ALL-CLEAR
    GET /v1/holds?cursor=<bogus>    -> 200 page 1 again, silently
    GET /v1/holds?limit=banana      -> 200 limit silently became 100
    holds.resolve_hold(id,"approved",...) -> status "rejected", silently

`all` and `resolved` are not invented near-misses: both are VALID vocabulary on
reeflex-app's own /app/api/v1/holds (which 422s an unknown status), and the
published reeflex-holds MCP `list_holds` tool forwards `status` with no
validation, so an agent asking "what is held?" reaches for exactly those words.

Nothing here changes which actions are allowed -- this is the instrument, not
the gate. What it changes is whether the instrument can report zero when the
answer is not zero (RFX-65 is the precedent for why that matters).

STYLE, AND WHY IT IS NOT NEGOTIABLE
===================================
`unittest.TestCase`, like every other file in this directory, because gate.py
runs this suite with `unittest discover` -- which IMPORTS a module of bare
pytest functions and collects ZERO tests from it, silently. That is RFX-87: for
weeks the regression guard for a merged security fix reported green without
executing a single assertion. A pytest-style file here would be a guard that
does not guard.

THE OTHER TRAP THIS FILE IS WRITTEN AGAINST
===========================================
qa--018's finding on RFX-87: "the assertion is sound; the inventory it is
pointed at is short, so the guard is green about a field class it never looked
at." A test that iterates a hand-written list of statuses has that shape --
forget to extend the list and the guard silently stops covering the new value.
So TestStatusVocabularyIsNotAShortInventory does not read the list at all: it
EXERCISES every state transition holds.py implements, collects the statuses
actually written to the store, and asserts the observed set EQUALS
HOLD_STATUSES. Adding a sixth status makes that test fail until it is declared,
and the API then accepts it.
"""

from __future__ import annotations

import http.server
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.holds import (
    HOLD_STATUSES,
    LIST_STATUS_FILTERS,
    MAX_LIST_LIMIT,
    RESOLVE_DECISIONS,
    UnknownCursor,
)
import app.holds as holds_mod


def _envelope(session: str = "s-vocab") -> dict:
    return {
        "agent": {"id": "agent:vocab-test", "session_id": session},
        "action": {"namespace": "t", "verb": "delete", "ability": "t/delete"},
        "target": {"environment": "production"},
        "magnitude": {"count": 3},
        "axes": {
            "reversibility": "irreversible",
            "blast_radius": "broad",
            "externality": "internal",
        },
    }


# Words that are NOT in core's status vocabulary but that a real caller sends.
# Each is here for a measured reason, not as filler.
NON_MEMBER_STATUSES = (
    "resolved",           # valid on reeflex-app's holds API; core's word is `approved`
    "resolution_failed",  # ditto
    "Pending",            # case variant
    "PENDING",
    "pending ",           # trailing space -- RFX-86's evasion shape, one surface over
    " pending",
    "approve",            # the resolve verb, not a status -- an easy confusion
    "banana",             # control: unambiguous nonsense
    "",                   # empty string is not "no filter"
)


class _HoldsStoreTestCase(unittest.TestCase):
    """A private, empty holds store per test -- never the shared default file.

    The default holds path is shared across every core on this box, so a test
    that wrote there would redden other sessions' suites.
    """

    def setUp(self) -> None:
        tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_vocab_"
        )
        tmp.close()
        os.unlink(tmp.name)
        self._path = tmp.name
        self.addCleanup(self._cleanup)
        os.environ["REEFLEX_HOLDS_PATH"] = self._path
        holds_mod._reset(self._path)

    def _cleanup(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass

    def _hold(self, session: str = "s-vocab") -> str:
        rec = holds_mod.create_hold(
            _envelope(session), "reeflex.policy/irreversible_broad_prod"
        )
        return rec["id"]


# ===========================================================================
# RFX-218 -- the WRITE half: resolve_hold()'s vocabulary
# ===========================================================================

class TestResolveDecisionVocabulary(_HoldsStoreTestCase):
    """`resolve_hold()` must not silently reject a caller that asked to approve."""

    def test_the_two_accepted_words_still_work(self) -> None:
        """The control. A fix that refuses everything is not a fix."""
        for word, want in (("approve", "approved"), ("reject", "rejected")):
            with self.subTest(decision=word):
                out = holds_mod.resolve_hold(
                    self._hold(f"s-{word}"), word, "human", "supervisor:leo", None
                )
                self.assertIsNotNone(out)
                self.assertEqual(
                    out["status"], want,
                    f"resolve_hold({word!r}) must yield status {want!r}",
                )

    def test_the_documented_literal_no_longer_rejects_silently(self) -> None:
        """RFX-218 exactly: the docstring said "approved" and that REJECTED.

        Reproduced on main: resolve_hold(id, "approved", ...) returned a normal
        hold dict with status "rejected" -- no error, no warning, and
        indistinguishable from a deliberate rejection by a human.
        """
        hold_id = self._hold("s-approved")
        with self.assertRaises(ValueError) as ctx:
            holds_mod.resolve_hold(hold_id, "approved", "human", "supervisor:leo", None)
        self.assertIn("approve", str(ctx.exception))

        # And the hold is UNTOUCHED -- the refusal must not have written a
        # rejection on its way out.
        after = holds_mod.get_hold(hold_id)
        self.assertEqual(
            after["status"], "pending",
            "a refused resolve must leave the hold pending, not rejected",
        )

    def test_every_non_member_raises_rather_than_coercing(self) -> None:
        """The whole "everything else" arm, not just the spelling that was filed.

        RFX-218's fix shape: "a two-valued parameter where one arm is
        'everything else' is the defect, and the next wrong spelling
        ('Approve', 'approved ') lands the same way."

        `rejected`, `no` and `""` are included deliberately: on main they
        coerced to a rejection, which HAPPENED to match a rejecting caller's
        intent. That coincidence is why the bug survived, so the guard must
        cover the arm and not only the visibly-wrong outcomes.
        """
        for word in ("approved", "Approve", "APPROVE", "approve ", " approve",
                     "rejected", "Reject", "no", "yes", "deny", "", "1"):
            with self.subTest(decision=word):
                hold_id = self._hold(f"s-{word!r}")
                with self.assertRaises(ValueError):
                    holds_mod.resolve_hold(hold_id, word, "human", "supervisor:leo", None)
                self.assertEqual(
                    holds_mod.get_hold(hold_id)["status"], "pending",
                    f"resolve_hold({word!r}) must not have changed the hold",
                )

    def test_deny_is_refused_and_that_is_a_deliberate_cross_surface_note(self) -> None:
        """reeflex-app's holds UI validates `approve|deny`; core's word is `reject`.

        Measured, not assumed: reeflex_app/web/holds.py raises
        HTTPException(422, "decision must be 'approve' or 'deny'").

        The two surfaces genuinely use different words for the same act. This
        test pins that core refuses `deny` LOUDLY rather than treating it as the
        rejection it looks like -- because guessing would be the same defect
        again, one layer up. The divergence itself is reported, not papered
        over here; unifying the two vocabularies is a cross-repo change and is
        not this ticket.
        """
        hold_id = self._hold("s-deny")
        with self.assertRaises(ValueError):
            holds_mod.resolve_hold(hold_id, "deny", "human", "supervisor:leo", None)

    def test_vocabulary_matches_what_the_http_handler_validates(self) -> None:
        """RFX-218's actual lesson, asserted structurally.

        "The endpoint already validates; the helper should not disagree with it
        about the vocabulary." So read the handler's accepted set out of
        server.py and require it to be exactly RESOLVE_DECISIONS -- if someone
        widens one and not the other, the two disagree again.
        """
        import inspect

        from app import server

        src = inspect.getsource(server._DecideHandler._handle_resolve_hold)
        self.assertIn(
            'decision not in ("approve", "reject")', src,
            "server.py's resolve handler no longer validates the set this "
            "module accepts -- the helper and the endpoint have diverged again",
        )
        self.assertEqual(tuple(RESOLVE_DECISIONS), ("approve", "reject"))


# ===========================================================================
# RFX-211 -- the READ half: list_holds()'s vocabulary
# ===========================================================================

class TestListStatusVocabulary(_HoldsStoreTestCase):
    """An unrecognised `status` must not read as "nothing is held"."""

    def test_every_declared_filter_is_accepted(self) -> None:
        """The control, over the DECLARED set rather than a copy of it."""
        self._hold()
        for st in LIST_STATUS_FILTERS:
            with self.subTest(status=st):
                items, _ = holds_mod.list_holds(status=st)
                self.assertIsInstance(items, list)

    def test_all_means_no_filter_and_not_an_empty_list(self) -> None:
        """RFX-211's fix shape: "either accept `all` as a synonym for no filter
        or reject it -- but not silently return empty." This implementation
        accepts it, so it must mean what it says."""
        self._hold("s-a")
        self._hold("s-b")
        unfiltered, _ = holds_mod.list_holds()
        with_all, _ = holds_mod.list_holds(status="all")
        self.assertEqual(len(unfiltered), 2)
        self.assertEqual(
            [h["id"] for h in with_all], [h["id"] for h in unfiltered],
            "status='all' must return exactly the unfiltered set",
        )

    def test_every_non_member_raises_rather_than_returning_empty(self) -> None:
        self._hold()
        for word in NON_MEMBER_STATUSES:
            with self.subTest(status=word):
                with self.assertRaises(ValueError) as ctx:
                    holds_mod.list_holds(status=word)
                # The refusal must name the set, so a caller can fix it without
                # reading our source.
                self.assertIn("pending", str(ctx.exception))

    def test_none_still_means_no_filter(self) -> None:
        """Guard against over-tightening: omitting the filter is not an error."""
        self._hold()
        items, _ = holds_mod.list_holds(status=None)
        self.assertEqual(len(items), 1)


class TestListCursorVocabulary(_HoldsStoreTestCase):
    """An unrecognised `cursor` must not silently serve page 1 again."""

    def _three(self) -> list[str]:
        return [self._hold(f"s-{i}") for i in range(3)]

    def test_a_valid_cursor_still_pages(self) -> None:
        """The control, and it is the one that would catch an over-tightening."""
        self._three()
        page1, nxt = holds_mod.list_holds(limit=1)
        self.assertEqual(len(page1), 1)
        self.assertIsNotNone(nxt)
        page2, _ = holds_mod.list_holds(limit=1, cursor=nxt)
        self.assertEqual(len(page2), 1)
        self.assertNotEqual(
            page2[0]["id"], page1[0]["id"], "a valid cursor must advance the page"
        )

    def test_an_unknown_cursor_raises_instead_of_restarting(self) -> None:
        """Reproduced on main: `if cursor_positions:` with no else, so a cursor
        matching no hold was dropped and page 1 came back with HTTP 200."""
        ids = self._three()
        for cursor, why in (
            ("no-such-hold-id", "nonsense"),
            (ids[0][::-1], "a real id, reversed -- the typo shape"),
            ("", "empty string"),
        ):
            with self.subTest(cursor=why):
                if cursor == "":
                    # An empty cursor is falsy and has always meant "no cursor";
                    # pinning that so the fix does not accidentally change it.
                    items, _ = holds_mod.list_holds(limit=1, cursor=cursor)
                    self.assertEqual(len(items), 1)
                    continue
                with self.assertRaises(UnknownCursor):
                    holds_mod.list_holds(limit=1, cursor=cursor)

    def test_the_filtered_set_race_is_distinguishable_from_a_typo(self) -> None:
        """The documented COST of this fix, pinned so it stays deliberate.

        A cursor can legitimately fall out of a FILTERED result set between
        pages. That now raises rather than silently restarting -- but the
        message must say which case it is, or an operator cannot tell a race
        from a bad cursor.
        """
        ids = self._three()
        holds_mod.resolve_hold(ids[0], "approve", "human", "supervisor:leo", None)

        # `ids[0]` still exists, but is no longer `pending`.
        with self.assertRaises(UnknownCursor) as ctx:
            holds_mod.list_holds(status="pending", cursor=ids[0])
        self.assertIn("no longer matches this filter", str(ctx.exception))

        with self.assertRaises(UnknownCursor) as ctx2:
            holds_mod.list_holds(status="pending", cursor="no-such-hold-id")
        self.assertIn("no hold has that id", str(ctx2.exception))


class TestListLimitVocabulary(_HoldsStoreTestCase):
    """An out-of-range or non-integer `limit` must not be silently rewritten."""

    def test_valid_limits_are_accepted(self) -> None:
        self._hold()
        for n in (1, 10, 100, MAX_LIST_LIMIT):
            with self.subTest(limit=n):
                items, _ = holds_mod.list_holds(limit=n)
                self.assertIsInstance(items, list)

    def test_out_of_range_and_non_integer_limits_raise(self) -> None:
        self._hold()
        for bad in (0, -1, -5, MAX_LIST_LIMIT + 1, 10 ** 9, "100", None, 1.5, True):
            with self.subTest(limit=bad):
                with self.assertRaises(ValueError):
                    holds_mod.list_holds(limit=bad)  # type: ignore[arg-type]


# ===========================================================================
# The anti-short-inventory guard (qa--018's finding on RFX-87)
# ===========================================================================

class TestStatusVocabularyIsNotAShortInventory(_HoldsStoreTestCase):
    """HOLD_STATUSES must equal the statuses this module can actually write.

    This deliberately does NOT iterate HOLD_STATUSES to check them off. It
    drives every state transition holds.py implements, collects what actually
    landed in the store, and compares the two sets. A sixth status therefore
    cannot be added without this failing -- which is the difference between a
    guard and an inventory somebody forgot to extend.
    """

    def test_observed_statuses_equal_the_declared_vocabulary(self) -> None:
        observed: set[str] = set()

        # pending -- create
        pending_id = self._hold("s-pending")
        observed.add(holds_mod.get_hold(pending_id)["status"])

        # approved -- resolve(approve)
        approved_id = self._hold("s-approved")
        observed.add(
            holds_mod.resolve_hold(approved_id, "approve", "human", "leo", None)["status"]
        )

        # rejected -- resolve(reject)
        rejected_id = self._hold("s-rejected")
        observed.add(
            holds_mod.resolve_hold(rejected_id, "reject", "human", "leo", None)["status"]
        )

        # consumed -- an approved hold that gets spent
        observed.add(holds_mod.mark_consumed(approved_id)["status"])

        # expired -- a pending hold past its deadline, folded on the next read.
        # Expiry is LAZY, so it takes an observation to happen at all.
        prev_ttl = os.environ.get("REEFLEX_HOLD_TTL_SECONDS")
        os.environ["REEFLEX_HOLD_TTL_SECONDS"] = "0"
        try:
            expired_id = self._hold("s-expired")
            observed.add(holds_mod.get_hold(expired_id)["status"])
        finally:
            if prev_ttl is None:
                os.environ.pop("REEFLEX_HOLD_TTL_SECONDS", None)
            else:
                os.environ["REEFLEX_HOLD_TTL_SECONDS"] = prev_ttl

        self.assertEqual(
            observed, set(HOLD_STATUSES),
            "HOLD_STATUSES and the statuses this module actually writes have "
            "diverged. If a new status was added, declare it in HOLD_STATUSES "
            "so GET /v1/holds?status= accepts it; if one was removed, drop it. "
            "A short inventory makes every test above green about a value it "
            "never looked at (qa--018 on RFX-87).",
        )

    def test_the_query_filter_set_is_the_status_set_plus_only_all(self) -> None:
        """LIST_STATUS_FILTERS must not drift away from HOLD_STATUSES."""
        self.assertEqual(
            set(LIST_STATUS_FILTERS) - set(HOLD_STATUSES), {"all"},
            "the only accepted filter that is not a real status is the 'all' synonym",
        )
        self.assertEqual(set(HOLD_STATUSES) - set(LIST_STATUS_FILTERS), set())


# ===========================================================================
# The HTTP plane -- the same refusals, as named 400s
# ===========================================================================

class TestHoldsQueryHTTP(unittest.TestCase):
    """`GET /v1/holds` must answer 400, not 200-with-an-empty-list.

    In-process HTTP server on an ephemeral port, following TestHoldsAPI in
    test_hil.py. 127.0.0.1 only.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from app.server import _DecideHandler

        tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_vocab_http_"
        )
        tmp.close()
        os.unlink(tmp.name)
        cls._path = tmp.name
        os.environ["REEFLEX_HOLDS_PATH"] = cls._path
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)
        holds_mod._reset(cls._path)

        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        cls._base = f"http://127.0.0.1:{cls._srv.server_address[1]}"
        threading.Thread(target=cls._srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(cls._path)
        except FileNotFoundError:
            pass

    def setUp(self) -> None:
        with open(self._path, "w", encoding="utf-8"):
            pass
        holds_mod._reset(self._path)
        holds_mod.create_hold(_envelope(), "reeflex.policy/irreversible_broad_prod")

    def _get(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self._base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_unfiltered_and_valid_filters_still_answer_200(self) -> None:
        code, body = self._get("/v1/holds")
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 1)
        code, body = self._get("/v1/holds?status=pending")
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 1)

    def test_status_all_returns_the_set_not_an_empty_list(self) -> None:
        """The measured headline: `all` answered 200 count=0 with a hold present."""
        code, body = self._get("/v1/holds?status=all")
        self.assertEqual(code, 200)
        self.assertEqual(
            body["count"], 1,
            "status=all must mean 'no filter'; returning 0 with a hold present "
            "is the false all-clear RFX-211 filed",
        )

    def test_unrecognised_status_is_a_named_400_naming_the_accepted_set(self) -> None:
        for word in ("banana", "resolved", "Pending", "pending "):
            with self.subTest(status=word):
                code, body = self._get(
                    f"/v1/holds?status={urllib.request.quote(word)}"
                )
                self.assertEqual(
                    code, 400,
                    f"status={word!r} must be refused, not answered with an empty list",
                )
                self.assertEqual(body["reason"], "status: unrecognised")
                self.assertIn("pending", body["accepted"])

    def test_unknown_cursor_is_a_named_400(self) -> None:
        code, body = self._get("/v1/holds?cursor=no-such-hold-id")
        self.assertEqual(code, 400)
        self.assertEqual(body["reason"], "cursor: unknown")

    def test_bad_limit_is_a_named_400(self) -> None:
        for raw, reason in (("banana", "limit: not an integer"),
                            ("0", "limit: out of range"),
                            ("-5", "limit: out of range"),
                            (str(MAX_LIST_LIMIT + 1), "limit: out of range")):
            with self.subTest(limit=raw):
                code, body = self._get(f"/v1/holds?limit={raw}")
                self.assertEqual(code, 400, f"limit={raw!r} must be refused")
                self.assertEqual(body["reason"], reason)

    def test_an_empty_status_query_is_refused_not_treated_as_no_filter(self) -> None:
        """`?status=` -- parse_qs drops blank values, so this reaches the handler
        as no filter at all. Pinned because it is the one case where "silently
        ignored" is the EXISTING and correct behaviour, and a future tightening
        of parse_qs would change it without anyone noticing."""
        code, body = self._get("/v1/holds?status=")
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 1)


if __name__ == "__main__":
    unittest.main()
