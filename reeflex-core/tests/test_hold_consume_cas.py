"""
test_hold_consume_cas.py — CAS (compare-and-set) hardening tests for
holds.mark_consumed() and its caller in decide.py.

Covers the concurrency hardening: mark_consumed() now performs its
status-check and consume-append atomically under holds.py's module lock, so
an approved single-use hold cannot be double-consumed by two concurrent
resubmissions — the losing racer gets None back and decide.py denies it
(reeflex_hold_already_consumed) instead of allowing a double-execution of an
approved-once irreversible action.

None of these tests require OPA: the approval-resubmission branch in
decide.process() returns before OPA is ever consulted (Step 4, before
Step 7's evaluate() call), so this whole test file runs unconditionally.

Test classes:
  TestMarkConsumedCAS               direct unit tests on holds.mark_consumed()
                                    itself: first consume succeeds, second
                                    consume on the same (now-consumed) hold
                                    is refused (None), and consume on a
                                    pending / rejected / expired / unknown
                                    hold is refused (None).
  TestSerialResubmissionRegression  no-regression check: a normal (non-
                                    racing) approved resubmission still
                                    allows exactly once end-to-end through
                                    decide.process().
  TestDeterministicCASRefusalPath   decide.py's handling of a mark_consumed()
                                    CAS refusal (None return), proven
                                    deterministically via monkeypatch (not
                                    dependent on thread scheduling) —
                                    asserts the deny reason, rule,
                                    decision_id, and the audit record
                                    carrying both decision_id and
                                    parent_decision_id.
  TestConcurrentResubmissionCAS     the actual race test that would have
                                    caught the pre-CAS bug: two threads,
                                    synchronized with a Barrier, both drive
                                    decide.process() resubmission on the
                                    SAME approved hold_id at once. Exactly
                                    one must allow and the other must deny
                                    reeflex_hold_already_consumed — repeated
                                    across 20 iterations (fresh hold each
                                    time) so the invariant is proven across
                                    scheduling variance, not just once.

Run:
  cd reeflex-core
  python -m unittest tests.test_hold_consume_cas -v
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import uuid

# Make app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.holds as holds_mod
from app.decide import process


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    return f"cas_sess_{uuid.uuid4().hex[:12]}"


def _base_envelope(
    *,
    verb: str = "delete",
    environment: str = "production",
    reversibility: str = "irreversible",
    blast_radius: str = "broad",
    externality: str = "internal",
    count: int = 42,
    session_id: str | None = None,
    namespace: str = "test",
    agent_id: str = "agent:cas-test",
    approval: dict | None = None,
) -> dict:
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": agent_id,
            "on_behalf_of": "user:synthetic",
            "session_id": session_id or _fresh_session(),
        },
        "action": {
            "namespace": namespace,
            "verb": verb,
            "ability": f"{namespace}/{verb}",
        },
        "target": {
            "kind": "entity",
            "ref": None,
            "environment": environment,
        },
        "params": {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": externality,
        },
        "approval": approval if approval is not None else {"present": False},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-07-04T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


def _read_jsonl(path: str) -> list[dict]:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ===========================================================================
# TestMarkConsumedCAS — direct unit tests on holds.mark_consumed()
# ===========================================================================

class TestMarkConsumedCAS(unittest.TestCase):
    """Direct unit tests on holds.mark_consumed() — the CAS guard itself."""

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_cas_unit_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        holds_mod._reset(self._tmp.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_first_consume_succeeds_second_consume_refused(self) -> None:
        """First mark_consumed() on an approved hold succeeds; the SECOND
        call on the same (now-consumed) hold is refused (None) -- proving
        the single-use guarantee holds even called serially, twice."""
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        holds_mod.resolve_hold(rec["id"], "approve", "human", "leo", None)

        first = holds_mod.mark_consumed(rec["id"])
        print(f"\n[CAS/unit] first mark_consumed -> {first}")
        self.assertIsNotNone(first, "first consume on an approved hold must succeed")
        self.assertEqual(first["status"], "consumed")
        self.assertIsNotNone(first.get("consumed_ts"))

        second = holds_mod.mark_consumed(rec["id"])
        print(f"[CAS/unit] second mark_consumed -> {second}")
        self.assertIsNone(
            second, "CAS must refuse a second consume on an already-consumed hold"
        )

        # The JSONL file must have exactly 3 event records: created, resolved,
        # consumed -- NOT a duplicate "consumed" append for the refused call.
        lines = _read_jsonl(self._tmp.name)
        self.assertEqual(
            len(lines), 3,
            f"expected exactly 3 event records (no duplicate consumed append "
            f"on CAS refusal), got {len(lines)}: {lines}"
        )
        event_types = [r["event_type"] for r in lines]
        self.assertEqual(event_types, ["created", "resolved", "consumed"])

    def test_consume_on_pending_hold_refused(self) -> None:
        """A hold that was never approved (still pending) -> mark_consumed
        returns None."""
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        result = holds_mod.mark_consumed(rec["id"])
        self.assertIsNone(
            result, "CAS must refuse consume on a pending (not-yet-approved) hold"
        )

    def test_consume_on_rejected_hold_refused(self) -> None:
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        holds_mod.resolve_hold(rec["id"], "reject", "human", "leo", "too risky")
        result = holds_mod.mark_consumed(rec["id"])
        self.assertIsNone(result, "CAS must refuse consume on a rejected hold")

    def test_consume_on_expired_hold_refused(self) -> None:
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        # Force expiry the same way test_hil.py's lazy-expiry test does:
        # mutate the in-memory index directly, then read via get_hold() to
        # trigger the lazy fold to status=expired.
        with holds_mod._lock:
            holds_mod._index[rec["id"]]["expires_ts"] = "2000-01-01T00:00:00Z"
        hold = holds_mod.get_hold(rec["id"])
        self.assertEqual(hold["status"], "expired", "setup: hold did not expire")

        result = holds_mod.mark_consumed(rec["id"])
        self.assertIsNone(result, "CAS must refuse consume on an expired hold")

    def test_consume_on_unknown_hold_id_refused(self) -> None:
        result = holds_mod.mark_consumed("0" * 32)
        self.assertIsNone(result)


# ===========================================================================
# TestSerialResubmissionRegression — no-regression happy path
# ===========================================================================

class TestSerialResubmissionRegression(unittest.TestCase):
    """A normal (non-racing) approved resubmission must still allow exactly
    once end-to-end through decide.process() after the CAS guard lands."""

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_cas_serial_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        holds_mod._reset(self._tmp.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_serial_resubmission_allows_and_consumes_exactly_once(self) -> None:
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        holds_mod.resolve_hold(rec["id"], "approve", "human", "supervisor:leo", "ok")

        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": rec["id"]}

        status, resp = process(env_resub)
        print(f"\n[CAS/serial] status={status} resp={json.dumps(resp)}")

        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "allow")
        self.assertEqual(resp.get("rule"), "reeflex.policy/approved_resubmission")

        hold_after = holds_mod.get_hold(rec["id"])
        self.assertEqual(hold_after["status"], "consumed")


# ===========================================================================
# TestDeterministicCASRefusalPath — decide.py's None-handling, no timing
# dependency (monkeypatch mark_consumed to simulate a losing CAS racer)
# ===========================================================================

class TestDeterministicCASRefusalPath(unittest.TestCase):
    """Deterministic (non-racy) proof that decide.py denies on a CAS refusal.

    Monkeypatches holds.mark_consumed() to return None -- exactly what the
    real CAS guard returns to a losing racer -- so the decide.py branch is
    exercised without depending on actual thread scheduling.
    """

    def setUp(self) -> None:
        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_cas_mp_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_cas_mp_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        for p in (self._tmp_holds.name, self._tmp_audit.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def test_none_from_mark_consumed_denies_already_consumed(self) -> None:
        env = _base_envelope()
        rec = holds_mod.create_hold(
            env, "reeflex.policy/irreversible_broad_prod",
            decision_id="parent-deadbeef",
        )
        holds_mod.resolve_hold(rec["id"], "approve", "human", "supervisor:leo", "ok")

        original_mark_consumed = holds_mod.mark_consumed

        def _simulate_losing_racer(*_a, **_kw):
            return None  # exactly what the real CAS returns to a losing racer

        holds_mod.mark_consumed = _simulate_losing_racer
        try:
            env_resub = dict(env)
            env_resub["meta"] = dict(env["meta"])
            env_resub["meta"]["nonce"] = uuid.uuid4().hex
            env_resub["approval"] = {"present": True, "hold_id": rec["id"]}
            session_id = env_resub["agent"]["session_id"]
            status, resp = process(env_resub)
        finally:
            holds_mod.mark_consumed = original_mark_consumed

        print(f"\n[CAS/deterministic_refusal] status={status} resp={json.dumps(resp)}")

        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertEqual(resp.get("reason"), "reeflex_hold_already_consumed")
        self.assertEqual(resp.get("rule"), "reeflex.core/hold_validation")
        self.assertTrue(resp.get("decision_id"), "decision_id missing on CAS-refused deny")

        # Audit must carry BOTH decision_id (this refused transit) and
        # parent_decision_id (the hold's creating decision_id), plus hold_id
        # and envelope_hash -- exactly like the other enriched audit calls.
        records = _read_jsonl(self._tmp_audit.name)
        matching = [r for r in records if r.get("session_id") == session_id]
        self.assertTrue(matching, "no audit record for this session_id")
        audit_rec = matching[-1]
        print(f"[CAS/deterministic_refusal] audit={json.dumps(audit_rec)}")
        self.assertEqual(audit_rec.get("decision_id"), resp.get("decision_id"))
        self.assertEqual(audit_rec.get("parent_decision_id"), "parent-deadbeef")
        self.assertEqual(audit_rec.get("hold_id"), rec["id"])
        self.assertTrue(audit_rec.get("envelope_hash"))


# ===========================================================================
# TestConcurrentResubmissionCAS — the race test that would have caught the
# pre-CAS bug
# ===========================================================================

class TestConcurrentResubmissionCAS(unittest.TestCase):
    """Two threads race decide.process() resubmission on the SAME approved
    hold_id.  Exactly one must allow; the other must deny
    reeflex_hold_already_consumed -- never two allows (that would be the
    double-execution bug this hardening fixes).  Repeated across
    ITERATIONS fresh holds so the invariant is proven across scheduling
    variance rather than asserted on a single lucky (or unlucky) run.
    """

    ITERATIONS = 20
    JOIN_TIMEOUT = 10.0
    BARRIER_TIMEOUT = 10.0

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_cas_race_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        holds_mod._reset(self._tmp.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def _race_once(self, iteration: int) -> tuple[tuple[int, dict], tuple[int, dict]]:
        """Create + approve one fresh hold, race two concurrent
        resubmissions against it, and return both (status, resp) results.

        Synchronization: a Barrier(2) gates the ENTRY to the real
        holds.mark_consumed() (via a thin wrapper installed for the duration
        of this race) rather than gating process() itself.  This pins the
        race at exactly the scenario under test: both threads must first
        pass `_validate_approval()`'s six checks while the hold is still
        "approved" (neither has consumed yet, since neither has reached the
        real mark_consumed()) -- only THEN do both hit the barrier and,
        released together, race the CAS inside mark_consumed() itself.  This
        makes the loser's denial land deterministically on the CAS refusal
        path (reeflex_hold_already_consumed) rather than on the earlier
        already-consumed status check in _validate_approval() (which would
        also correctly deny, with reason reeflex_hold_consumed, if the loser
        happened to read the hold store after the winner had already
        finished consuming -- a real but different, less interesting race
        window that the barrier below removes for the purpose of this
        assertion).

        Bounded/anti-hang: both threads are joined with a timeout and the
        test fails loudly (not silently) if either does not finish.
        """
        env = _base_envelope(
            session_id=f"cas_race_sess_{iteration}_{uuid.uuid4().hex[:8]}",
        )
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        holds_mod.resolve_hold(rec["id"], "approve", "human", "supervisor:leo", "ok")

        barrier = threading.Barrier(2)
        original_mark_consumed = holds_mod.mark_consumed

        def _synced_mark_consumed(hold_id: str):
            # Both racing callers arrive here only AFTER _validate_approval()
            # has already passed them (status still "approved" at that
            # point) -- decide.py calls mark_consumed() strictly after the
            # validation chain succeeds.  Blocking here until both threads
            # arrive, then calling the REAL (CAS-guarded) mark_consumed(),
            # forces the actual compare-and-set race to decide the winner.
            try:
                barrier.wait(timeout=self.BARRIER_TIMEOUT)
            except threading.BrokenBarrierError:
                pass  # proceed anyway -- the CAS invariant must hold regardless
            return original_mark_consumed(hold_id)

        holds_mod.mark_consumed = _synced_mark_consumed

        results: list[tuple[int, dict] | None] = [None, None]

        def _worker(idx: int) -> None:
            env_local = dict(env)
            env_local["meta"] = dict(env["meta"])
            # Distinct nonce per thread -- avoids the (unrelated) nonce-replay
            # guard tripping and confounding the CAS race we're testing.
            env_local["meta"]["nonce"] = uuid.uuid4().hex
            env_local["approval"] = {"present": True, "hold_id": rec["id"]}
            results[idx] = process(env_local)

        t1 = threading.Thread(target=_worker, args=(0,))
        t2 = threading.Thread(target=_worker, args=(1,))
        try:
            t1.start()
            t2.start()
            t1.join(timeout=self.JOIN_TIMEOUT)
            t2.join(timeout=self.JOIN_TIMEOUT)
        finally:
            holds_mod.mark_consumed = original_mark_consumed

        self.assertFalse(
            t1.is_alive(), f"iteration {iteration}: worker thread 1 did not finish (hang)"
        )
        self.assertFalse(
            t2.is_alive(), f"iteration {iteration}: worker thread 2 did not finish (hang)"
        )
        self.assertIsNotNone(results[0], f"iteration {iteration}: thread 1 produced no result")
        self.assertIsNotNone(results[1], f"iteration {iteration}: thread 2 produced no result")
        return results[0], results[1]  # type: ignore[return-value]

    def test_concurrent_resubmission_exactly_one_allow(self) -> None:
        total_allow = 0
        total_deny_already_consumed = 0

        for i in range(self.ITERATIONS):
            (status_a, resp_a), (status_b, resp_b) = self._race_once(i)
            decisions = [resp_a.get("decision"), resp_b.get("decision")]
            reasons = [resp_a.get("reason"), resp_b.get("reason")]

            print(
                f"[CAS/race iter={i}] "
                f"a=(status={status_a}, decision={resp_a.get('decision')}, reason={resp_a.get('reason')}) "
                f"b=(status={status_b}, decision={resp_b.get('decision')}, reason={resp_b.get('reason')})"
            )

            self.assertEqual(status_a, 200, f"iteration {i}: thread a unexpected status")
            self.assertEqual(status_b, 200, f"iteration {i}: thread b unexpected status")

            allow_count = decisions.count("allow")
            deny_count = decisions.count("deny")

            self.assertEqual(
                allow_count, 1,
                f"iteration {i}: expected EXACTLY ONE allow, got {allow_count} "
                f"(decisions={decisions}) -- CAS guard failed, double-consume / "
                f"double-execution possible"
            )
            self.assertEqual(
                deny_count, 1,
                f"iteration {i}: expected exactly one deny, got {deny_count} "
                f"(decisions={decisions})"
            )

            deny_reason = reasons[decisions.index("deny")]
            self.assertEqual(
                deny_reason, "reeflex_hold_already_consumed",
                f"iteration {i}: the losing racer must be denied with "
                f"reeflex_hold_already_consumed, got reason={deny_reason!r}"
            )

            total_allow += allow_count
            total_deny_already_consumed += deny_count

        print(
            f"[CAS/race SUMMARY] iterations={self.ITERATIONS} "
            f"total_allow={total_allow} "
            f"total_deny_already_consumed={total_deny_already_consumed}"
        )
        self.assertEqual(
            total_allow, self.ITERATIONS,
            "exactly one allow per iteration must hold across ALL iterations"
        )
        self.assertEqual(
            total_deny_already_consumed, self.ITERATIONS,
            "exactly one reeflex_hold_already_consumed deny per iteration must "
            "hold across ALL iterations"
        )


if __name__ == "__main__":
    unittest.main()
