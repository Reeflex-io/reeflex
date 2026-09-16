"""
test_ledger_charges_the_floor_rfx293.py — RFX-293. R5's cumulative term is
priced by the POLICY, not by the caller.

THE DEFECT, as measured on the published ghcr.io/reeflex-io/reeflex-core:v0.2.1
image (dev-1--071, and filed by dev-3--069 from the WordPress adapter). One
session per arm, `users/delete`, 45 accounts destroyed per call,
target.environment=staging so R2/R3 cannot preempt and only R5 can hold:

  arm                              magnitude.count  first non-allow  accounts deleted
                                                                     before the gate asked
  A  users/delete ids[3001..3045]        45          call  1                0
  B  users/delete role=subscriber         1          call 12              495

Same ability, same object kind, same 45 accounts per call, same session shape.
The arms differed only in how much the caller disclosed.

WHY. RFX-143 made budgets.rego charge the action being DECIDED
max(magnitude.count, count_floor[axes.blast_radius]) -- so arm B's current term
was 10, not 1. But ledger.py::append_entry recorded the RAW magnitude.count, so
the CUMULATIVE term kept summing 1s: the trip is the first i where
10 + (i-1) > 20, i.e. 12. Half a fix measures as a fix at call 1 and as nothing
at all by call 12.

WHAT THESE TESTS PIN

  T_history_is_priced_by_the_policy
    Drive the REAL decide.process() path (no mocking of OPA) and walk one
    session until the budget holds. broad + count=1 now trips at call 3 --
    floor 10 against limit 20, `>` strict -- where it tripped at 12 before.

  T_under_declaring_buys_no_extra_calls
    The ticket's class, stated without a literal: at one blast radius, a
    session that declares `count: 1` may not get MORE calls than one that
    declares the floor honestly. Before this fix it got four times as many.
    The floor is read out of the policy (opa.evaluate_ledger_charge), never
    copied into this file.

  T_single_and_scoped_do_not_move
    count_floor leaves single/scoped at 1 deliberately (they are what our
    adapters emit for ordinary work). Ordinary sessions must trip exactly
    where they always did: call 21.

  T_the_floor_is_not_mirrored_in_python
    THE CONTROL FOR THE FIX ITSELF. Copy the policy dir, edit count_floor.broad
    10 -> 4 in budgets.rego, change NO Python, and the ledger entry and the trip
    point both follow the edited table. A Python copy of the floor table -- the
    unchecked mirror RFX-216 is about -- would keep charging 10 and fail this.

  T_a_charge_core_cannot_compute_denies
    Fail-closed direction. A policy that does not answer `ledger_charge` must
    produce a refusal, NOT a silent fall back to the caller's own count.

  T_an_approved_resubmission_is_priced_too
    The second ledger writer. decide.py's approved-hold resubmission allows
    without asking OPA for a verdict, but it still spends budget, so it asks
    for the charge alone and records that.

Run:
  cd reeflex-core
  python -m unittest tests.test_ledger_charges_the_floor_rfx293 -v
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod
from app.decide import process, _WINDOW_SECONDS
from app.opa import OpaEvalError, evaluate_ledger_charge

# budgets.rego default_budgets.deletions.limit, and `exceeded_dimensions` uses
# a strict `>`. Stated here as the INSTRUMENT's independent arithmetic: these
# tests derive expected trip points from it rather than from any Python copy of
# the floors, which are read out of the policy where they live.
DELETIONS_LIMIT = 20


def _fresh_session(tag: str) -> str:
    return f"rfx293_{tag}_{uuid.uuid4().hex[:12]}"


def _envelope(
    *,
    session_id: str,
    blast_radius: str,
    count: int | None = 1,
    verb: str = "delete",
    environment: str = "staging",
    reversibility: str = "recoverable",
) -> dict:
    """A delete whose ONLY possible holder is R5.

    `recoverable` + staging so R2 (irreversible+broad+prod) and R3
    (irreversible+systemic) cannot fire -- RFX-167's trap is a conjunction
    masking the dimension being measured, and at `broad`/production R2 holds
    every arm at call 1 and this whole dimension is invisible.
    """
    env: dict = {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:rfx293-test-runner",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id,
        },
        "action": {"namespace": "test", "verb": verb, "ability": f"test/{verb}"},
        "target": {"kind": "row", "ref": None, "environment": environment},
        "params": {},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": "internal",
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-09-16T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }
    if count is not None:
        env["magnitude"] = {"count": count}
    return env


def _walk(session_id: str, *, limit: int = 40, **kw) -> tuple[int | None, dict]:
    """Fire the same action repeatedly on ONE session until it stops allowing.

    Fresh nonce per call (the replay guard is keyed on the envelope, the ledger
    on the session, and this measurement needs one of each) and a fresh session
    per walk (dev-1--041 lost a finding to a reused session id reading the
    previous run's cumulative).
    """
    last: dict = {}
    for i in range(1, limit + 1):
        status, resp = process(_envelope(session_id=session_id, **kw))
        last = resp
        if resp.get("decision") != "allow":
            return i, resp
    return None, last


def _policy_floor(blast_radius: str) -> int:
    """The floor budgets.rego charges at this blast radius, read FROM the
    policy. Not a literal, and not a Python copy of count_floor: asking the
    same rule the product asks is what keeps this test honest if an operator
    retunes the table."""
    return evaluate_ledger_charge(
        _envelope(session_id="rfx293_probe", blast_radius=blast_radius, count=1)
    )


# ---------------------------------------------------------------------------
# T_history_is_priced_by_the_policy
# ---------------------------------------------------------------------------

class TestTheHistoryIsPricedByThePolicy(unittest.TestCase):

    def test_broad_under_declared_delete_trips_on_the_floor_arithmetic(self) -> None:
        """broad + count=1: floor 10 per call against a limit of 20, strict `>`
        -> allow, allow, HOLD. This measured 12 before the ledger recorded the
        charge, i.e. 11 calls of a whole-table delete before the gate asked."""
        floor = _policy_floor("broad")
        expected = 1
        spent = 0
        while spent + floor <= DELETIONS_LIMIT:
            spent += floor
            expected += 1

        session = _fresh_session("broad1")
        trip, resp = _walk(session, blast_radius="broad", count=1)

        print(
            f"\n[T_history_priced_by_policy] floor={floor} limit={DELETIONS_LIMIT} "
            f"trip=call {trip} rule={resp.get('rule')}"
        )
        self.assertEqual(
            expected, trip,
            "a broad delete declaring count=1 must be charged the broad floor "
            "on the CUMULATIVE term too; tripping later than %s means the "
            "history is still being summed from the caller's own number"
            % expected,
        )
        self.assertEqual("require_approval", resp.get("decision"))
        self.assertEqual("reeflex.policy/session_delete_budget", resp.get("rule"))

    def test_the_ledger_entry_carries_the_charge_not_the_declared_count(self) -> None:
        """One call, then read the cumulative the NEXT call would be decided
        against. This is the actual number RFX-293 is about."""
        floor = _policy_floor("broad")
        session = _fresh_session("entry")
        status, resp = process(
            _envelope(session_id=session, blast_radius="broad", count=1)
        )
        self.assertEqual(200, status)
        self.assertEqual("allow", resp.get("decision"), resp)

        cumulative = ledger_mod.compute_cumulative(session, _WINDOW_SECONDS)
        print(
            f"\n[T_entry_carries_charge] declared count=1 -> "
            f"count_by_verb.delete={cumulative['count_by_verb'].get('delete')} "
            f"total_count={cumulative['total_count']} (floor {floor})"
        )
        self.assertEqual(floor, cumulative["count_by_verb"].get("delete"))
        self.assertEqual(floor, cumulative["total_count"])

    def test_an_honest_count_above_the_floor_is_still_recorded_in_full(self) -> None:
        """The floor is a floor, not a replacement: an adapter that enumerates
        45 deletions must not be re-priced down to 10 by this change."""
        session = _fresh_session("honest")
        process(_envelope(session_id=session, blast_radius="broad", count=45))
        cumulative = ledger_mod.compute_cumulative(session, _WINDOW_SECONDS)
        self.assertEqual(45, cumulative["count_by_verb"].get("delete"))


# ---------------------------------------------------------------------------
# T_under_declaring_buys_no_extra_calls
# ---------------------------------------------------------------------------

class TestUnderDeclaringBuysNoExtraCalls(unittest.TestCase):

    def test_declaring_one_buys_no_more_calls_than_declaring_the_floor(self) -> None:
        """RFX-165/RFX-174's class, on the dimension where it survived: at one
        blast radius, saying less must not buy more. No literal trip point --
        the two arms are compared to each other, so this keeps its meaning if
        an operator retunes the floors or the limit."""
        floor = _policy_floor("broad")
        self.assertGreater(floor, 1, "this test is vacuous at a floor of 1")

        quiet_trip, _ = _walk(
            _fresh_session("quiet"), blast_radius="broad", count=1
        )
        honest_trip, _ = _walk(
            _fresh_session("honest"), blast_radius="broad", count=floor
        )
        print(
            f"\n[T_no_extra_calls] count=1 trips at {quiet_trip}; "
            f"count={floor} trips at {honest_trip}"
        )
        self.assertEqual(
            honest_trip, quiet_trip,
            "an under-declared count bought %s calls where an honest one bought "
            "%s -- the cumulative term is still measuring candour"
            % (quiet_trip, honest_trip),
        )

    def test_an_omitted_magnitude_block_is_charged_the_same(self) -> None:
        """The F2 fill of 1 is the cheapest value in the domain; it must not be
        cheaper than stating 1, and neither may be cheaper than the floor."""
        floor = _policy_floor("broad")
        absent_trip, _ = _walk(
            _fresh_session("absent"), blast_radius="broad", count=None
        )
        stated_trip, _ = _walk(
            _fresh_session("stated"), blast_radius="broad", count=floor
        )
        self.assertEqual(stated_trip, absent_trip)


# ---------------------------------------------------------------------------
# T_single_and_scoped_do_not_move
# ---------------------------------------------------------------------------

class TestOrdinaryTrafficDoesNotMove(unittest.TestCase):
    """`scoped` is the everyday value our adapters emit for ordinary work, so a
    change here retunes every session. count_floor leaves single and scoped at
    1 deliberately, and this is the regression guard on that."""

    def test_single_and_scoped_still_trip_at_the_limit_plus_one(self) -> None:
        for blast in ("single", "scoped"):
            with self.subTest(blast_radius=blast):
                self.assertEqual(
                    1, _policy_floor(blast),
                    "the floor at %r moved; the trip point below is about to "
                    "change for every ordinary session" % blast,
                )
                trip, resp = _walk(
                    _fresh_session(blast), blast_radius=blast, count=1, limit=30
                )
                self.assertEqual(DELETIONS_LIMIT + 1, trip)
                self.assertEqual("require_approval", resp.get("decision"))


# ---------------------------------------------------------------------------
# T_the_floor_is_not_mirrored_in_python
# ---------------------------------------------------------------------------

class TestTheFloorIsNotMirroredInPython(unittest.TestCase):
    """THE CONTROL ON THE FIX. RFX-216 is a detector that compared its own
    literal to itself and could therefore detect nothing. The obvious way to
    make the ledger charge the floor -- copy count_floor into ledger.py -- would
    pass every other test in this file and be exactly that defect: two tables,
    one of them invisible to the policy author who edits budgets.rego.

    So: edit the Rego, change no Python, and require the recorded charge to
    follow the edit.
    """

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="rfx293-policy-")
        self._tmp_policy_dir = pathlib.Path(self._tmpdir) / "policy"
        shutil.copytree(_repo_root / "policy", self._tmp_policy_dir)

        budgets = self._tmp_policy_dir / "budgets.rego"
        text = budgets.read_text(encoding="utf-8")
        edited = text.replace('\t"broad": 10,', '\t"broad": 4,')
        self.assertNotEqual(
            text, edited,
            "count_floor's broad entry was not found to edit -- this control "
            "is measuring nothing",
        )
        budgets.write_text(edited, encoding="utf-8")

        self._orig_policy_dir = os.environ.get("REEFLEX_POLICY_DIR")
        os.environ["REEFLEX_POLICY_DIR"] = str(self._tmp_policy_dir)

    def tearDown(self) -> None:
        if self._orig_policy_dir is None:
            os.environ.pop("REEFLEX_POLICY_DIR", None)
        else:
            os.environ["REEFLEX_POLICY_DIR"] = self._orig_policy_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_the_recorded_charge_follows_the_rego_table(self) -> None:
        session = _fresh_session("mirror")
        process(_envelope(session_id=session, blast_radius="broad", count=1))
        cumulative = ledger_mod.compute_cumulative(session, _WINDOW_SECONDS)
        print(
            "\n[T_not_a_python_mirror] count_floor.broad edited 10 -> 4; "
            f"ledger recorded {cumulative['count_by_verb'].get('delete')}"
        )
        self.assertEqual(
            4, cumulative["count_by_verb"].get("delete"),
            "the ledger recorded a charge the edited policy does not name -- "
            "the floor table has been mirrored somewhere outside budgets.rego",
        )

    def test_the_trip_point_follows_the_rego_table(self) -> None:
        """4 per call against a limit of 20: allow x5, hold on the 6th."""
        trip, resp = _walk(_fresh_session("mirror2"), blast_radius="broad", count=1)
        self.assertEqual(6, trip)
        self.assertEqual("reeflex.policy/session_delete_budget", resp.get("rule"))


# ---------------------------------------------------------------------------
# T_a_charge_core_cannot_compute_denies
# ---------------------------------------------------------------------------

class TestAChargeCoreCannotComputeDenies(unittest.TestCase):
    """Fail-closed, in the direction that matters: a charge core cannot read is
    never quietly downgraded to the caller's own count. That substitution is
    the defect, not the remedy."""

    def test_coerce_rejects_everything_that_is_not_a_count(self) -> None:
        from app.opa import _coerce_charge

        for bad in (None, True, False, "10", "", [], {}, 0, -5):
            with self.subTest(value=bad):
                with self.assertRaises(OpaEvalError):
                    _coerce_charge(bad)

    def test_a_policy_that_does_not_answer_the_charge_refuses(self) -> None:
        tmpdir = tempfile.mkdtemp(prefix="rfx293-nocharge-")
        self.addCleanup(shutil.rmtree, tmpdir, True)
        policy_dir = pathlib.Path(tmpdir) / "policy"
        shutil.copytree(_repo_root / "policy", policy_dir)

        budgets = policy_dir / "budgets.rego"
        text = budgets.read_text(encoding="utf-8")
        edited = text.replace("default ledger_charge := 20", "").replace(
            "ledger_charge := charged_count", ""
        )
        self.assertNotEqual(text, edited, "ledger_charge was not found to remove")
        budgets.write_text(edited, encoding="utf-8")

        orig = os.environ.get("REEFLEX_POLICY_DIR")
        os.environ["REEFLEX_POLICY_DIR"] = str(policy_dir)
        try:
            session = _fresh_session("nocharge")
            status, resp = process(
                _envelope(session_id=session, blast_radius="broad", count=1)
            )
        finally:
            if orig is None:
                os.environ.pop("REEFLEX_POLICY_DIR", None)
            else:
                os.environ["REEFLEX_POLICY_DIR"] = orig

        print(
            f"\n[T_charge_fails_closed] status={status} decision={resp.get('decision')} "
            f"rule={resp.get('rule')}"
        )
        self.assertNotEqual(
            "allow", resp.get("decision"),
            "a policy that cannot price the action allowed it anyway",
        )
        self.assertEqual(500, status)


# ---------------------------------------------------------------------------
# T_an_approved_resubmission_is_priced_too
# ---------------------------------------------------------------------------

class TestAnApprovedResubmissionIsPricedToo(unittest.TestCase):
    """decide.py has TWO ledger writers. The second one allows an action
    WITHOUT consulting OPA for a verdict -- a human already approved it -- but
    it still spends session budget, so it must still be recorded at the price
    the policy charges rather than at the count the caller declared."""

    def test_the_resubmitted_action_is_recorded_at_the_policy_charge(self) -> None:
        import app.holds as holds_mod

        floor = _policy_floor("broad")
        session = _fresh_session("resub")

        # An irreversible broad production delete -- R2 holds it at call 1.
        env = _envelope(
            session_id=session,
            blast_radius="broad",
            count=1,
            environment="production",
            reversibility="irreversible",
        )
        status1, resp1 = process(env)
        self.assertEqual(200, status1)
        self.assertEqual("require_approval", resp1.get("decision"), resp1)
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(
            hold_id, "approve", "human", "supervisor:leo", "approved, synthetic"
        )

        resubmit = dict(env)
        resubmit["meta"] = dict(env["meta"])
        resubmit["meta"]["nonce"] = uuid.uuid4().hex
        resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status2, resp2 = process(resubmit)
        self.assertEqual(200, status2)
        self.assertEqual("allow", resp2.get("decision"), resp2)
        self.assertEqual("reeflex.policy/approved_resubmission", resp2.get("rule"))

        cumulative = ledger_mod.compute_cumulative(session, _WINDOW_SECONDS)
        print(
            "\n[T_resubmission_priced] two calls, both declaring count=1 -> "
            f"count_by_verb.delete={cumulative['count_by_verb'].get('delete')} "
            f"(2 x floor {floor})"
        )
        self.assertEqual(
            2 * floor, cumulative["count_by_verb"].get("delete"),
            "the approved resubmission was recorded at the caller's declared "
            "count; a session can then buy a whole budget back with one "
            "approval",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
