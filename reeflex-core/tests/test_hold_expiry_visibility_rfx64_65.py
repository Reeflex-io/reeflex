"""
test_hold_expiry_visibility_rfx64_65.py — the two core-side links that make a
hold NOBODY ANSWERS visible downstream (RFX-64, RFX-65).

Measured before these tests existed (qa--010 §1.3/§1.4, on the live product):

  * A hold's DEADLINE was known only to core. `decide.py` put `expires_ts` on
    the /v1/decide HTTP RESPONSE but `audit.record()` never wrote it, so every
    consumer of the audited stream (the evidence connector's tail, a SIEM, the
    portal inbox it feeds) had to either guess a TTL — which drifts from this
    core's REEFLEX_HOLD_TTL_SECONDS — or show the hold as pending forever.
  * The denial that says an action was refused BECAUSE ITS HOLD TIMED OUT
    (`reeflex_hold_expired`) carried NO hold_id: `decide.py`'s fail_resp branch
    called `_try_audit(...)` without one. So the one record that names the
    timeout could not be attached to the hold it was about, and an Art.14
    report said "raised but never resolved" instead of "timed out".
  * `_append_expired_event()` stamped `expired_ts`/`resolved_ts` with the
    OBSERVATION time. Three real production holds from July flipped at one
    instant in August (the first time anything happened to list them), so the
    append-only Art.14 stream claimed they timed out 30 days after their actual
    deadlines. An append-only evidence stream that records the wrong time is
    worse than one that records nothing.

Test cases:
  TestExpiresTsOnAuditRecord     the require_approval audit line carries
                                 expires_ts, BYTE-EQUAL to the response's; no
                                 expires_ts key on a non-hold decision.
  TestHoldIdOnExpiredDenial      the reeflex_hold_expired denial names the hold
                                 (hold_id + parent_decision_id from the hold's
                                 creating decision); a denial about a hold this
                                 store does NOT hold (reeflex_hold_not_found)
                                 carries no hold_id — no phantom holds.
  TestExpiryRecordsTheDeadline   the `expired` hold record and the
                                 hold_resolution event state the DEADLINE as
                                 the expiry time and the detection time
                                 separately (expired_ts / observed_ts).

OPA-dependent tests are skipped if OPA is unavailable (same pattern as
test_audit_enrichment_v0113.py). The pure holds.py tests do not need OPA.

Run:
  cd reeflex-core
  python -m unittest tests.test_hold_expiry_visibility_rfx64_65 -v
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.holds as holds_mod
from app.decide import process

from tests.test_audit_enrichment_v0113 import (  # reuse, never re-implement
    _base_envelope,
    _hold_resolution_records_for,
    _opa_available,
    _read_audit_records,
    _require_approval_env,
)


def _decision_records() -> list[dict]:
    """Audit lines that are DECISION records (no "event" key — audit.py's
    documented discriminator), oldest first."""
    return [r for r in _read_audit_records() if "event" not in r]


def _decision_record_by_id(decision_id: str) -> dict:
    matching = [r for r in _decision_records() if r.get("decision_id") == decision_id]
    assert matching, f"no decision audit record for decision_id={decision_id}"
    return matching[-1]


class _IsolatedStreams(unittest.TestCase):
    """Temp audit log + temp hold store per test — the same setUp/tearDown
    shape as test_audit_enrichment_v0113.py, so neither the repo's real
    audit/decisions.jsonl nor its holds.jsonl is ever touched by a test."""

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_rfx6465_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_rfx6465_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLD_TTL_SECONDS", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestExpiresTsOnAuditRecord(_IsolatedStreams):
    """RFX-64/FLAG A: the deadline must be ON the audited line, not only in the
    HTTP response — otherwise the only party that can see a hold's deadline is
    core itself, and the human's inbox can never know the hold went stale."""

    def test_require_approval_audit_line_carries_the_response_expires_ts(self) -> None:
        env = _require_approval_env()
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "require_approval")
        self.assertTrue(resp.get("hold_id"))
        self.assertTrue(resp.get("expires_ts"))

        rec = _decision_record_by_id(resp["decision_id"])
        print(f"\n[T_expires_ts/audit] resp.expires_ts={resp['expires_ts']!r}\n"
              f"  audit={json.dumps(rec)}")

        self.assertEqual(
            rec.get("expires_ts"), resp["expires_ts"],
            "the audited deadline must be the SAME string the response returned — "
            "one hold, one deadline, no second source of truth",
        )
        self.assertEqual(rec.get("hold_id"), resp["hold_id"])

    def test_expires_ts_tracks_the_configured_ttl_not_a_hardcoded_one(self) -> None:
        """The value is read from the hold record, so a deployment that sets
        REEFLEX_HOLD_TTL_SECONDS gets ITS deadline on the audit line. This is
        the whole reason the field has to travel: a downstream consumer that
        guessed a default 4h TTL would be wrong on this deployment."""
        os.environ["REEFLEX_HOLD_TTL_SECONDS"] = "60"
        before = time.time()
        status, resp = process(_require_approval_env())
        self.assertEqual(status, 200)
        rec = _decision_record_by_id(resp["decision_id"])
        expires_epoch = holds_mod._epoch_from_iso(rec["expires_ts"])
        print(f"\n[T_expires_ts/ttl60] audit.expires_ts={rec['expires_ts']!r} "
              f"delta={expires_epoch - before:.0f}s")
        self.assertGreater(expires_epoch, 0.0, "expires_ts must be parsable ISO8601 UTC")
        # 60s TTL: the deadline is ~1 minute out, nowhere near the 4h default.
        self.assertLess(expires_epoch - before, 120)
        self.assertGreater(expires_epoch - before, 30)

    def test_no_expires_ts_key_on_a_decision_that_created_no_hold(self) -> None:
        status, resp = process(_base_envelope())  # read-only -> allow
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "allow")
        rec = _decision_record_by_id(resp["decision_id"])
        print(f"\n[T_expires_ts/allow] audit={json.dumps(rec)}")
        self.assertNotIn("expires_ts", rec,
                         "additive field: absent (key omitted) when no hold exists")
        self.assertNotIn("hold_id", rec)


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestHoldIdOnExpiredDenial(_IsolatedStreams):
    """RFX-64's missing closing link: the denial that refuses an action because
    its hold timed out has to NAME that hold."""

    def _raise_approve_and_expire(self) -> tuple[str, str]:
        """Raise a real hold, have a human approve it, then push its deadline
        into the past. Returns (hold_id, creating_decision_id)."""
        status, resp = process(_require_approval_env())
        self.assertEqual(status, 200)
        hold_id = resp["hold_id"]
        creating_decision_id = resp["decision_id"]
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor-a")
        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = "2000-01-01T00:00:00Z"
        return hold_id, creating_decision_id

    def test_expired_denial_names_the_hold_and_its_creating_decision(self) -> None:
        hold_id, creating_decision_id = self._raise_approve_and_expire()

        env = _require_approval_env()
        env["approval"] = {"present": True, "hold_id": hold_id}
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "deny")
        # get_hold() inside _validate_approval performs the lazy expiry check,
        # so check 2 (status != approved) sees `expired` and returns this reason
        # before check 3's is_expired() is reached. Same fact, one reason.
        self.assertEqual(resp["reason"], "reeflex_hold_expired")
        self.assertEqual(resp["rule"], "reeflex.core/hold_validation")

        rec = _decision_record_by_id(resp["decision_id"])
        print(f"\n[T_denial/expired] resp={json.dumps(resp)}\n  audit={json.dumps(rec)}")

        self.assertEqual(
            rec.get("hold_id"), hold_id,
            "qa--010 §1.3: this line carried NO hold_id, so nothing downstream "
            "could attach the timeout to the hold it was about",
        )
        self.assertEqual(
            rec.get("parent_decision_id"), creating_decision_id,
            "stitches the refusal back to the request that was originally gated",
        )
        self.assertEqual(rec.get("decision"), "deny")

    def test_denial_about_a_hold_that_does_not_exist_carries_no_hold_id(self) -> None:
        """No phantom holds: a hold_id on an audit line always names a hold
        this store actually holds. An envelope can claim any string."""
        env = _require_approval_env()
        env["approval"] = {"present": True, "hold_id": "deadbeef" * 4}
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "deny")
        self.assertEqual(resp["reason"], "reeflex_hold_not_found")

        rec = _decision_record_by_id(resp["decision_id"])
        print(f"\n[T_denial/not_found] audit={json.dumps(rec)}")
        self.assertNotIn("hold_id", rec)
        self.assertNotIn("parent_decision_id", rec)

    def test_rejected_hold_denial_also_names_the_hold(self) -> None:
        """Same branch, a different refusal: the whole fail_resp family now
        names the hold it was decided against, not just the expiry case."""
        status, resp = process(_require_approval_env())
        hold_id = resp["hold_id"]
        holds_mod.resolve_hold(hold_id, "reject", "human", "supervisor-a", "not now")

        env = _require_approval_env()
        env["approval"] = {"present": True, "hold_id": hold_id}
        status, resp2 = process(env)
        self.assertEqual(resp2["decision"], "deny")
        self.assertEqual(resp2["reason"], "reeflex_hold_rejected")
        rec = _decision_record_by_id(resp2["decision_id"])
        print(f"\n[T_denial/rejected] audit={json.dumps(rec)}")
        self.assertEqual(rec.get("hold_id"), hold_id)


class TestExpiryRecordsTheDeadline(_IsolatedStreams):
    """RFX-65 second half. No OPA needed — this is holds.py's own bookkeeping."""

    _DEADLINE = "2026-07-19T21:20:31Z"  # the shape of qa--010's real July holds

    def _hold_records(self) -> list[dict]:
        with open(self._tmp_holds.name, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_expired_event_states_the_deadline_and_the_detection_separately(self) -> None:
        rec = holds_mod.create_hold(
            _require_approval_env(), "reeflex.policy/irreversible_broad_prod",
            decision_id=uuid.uuid4().hex,
        )
        hold_id = rec["id"]
        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = self._DEADLINE

        observed_after = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hold = holds_mod.get_hold(hold_id)  # the observation that detects expiry
        self.assertEqual(hold.get("status"), "expired")

        expired_events = [r for r in self._hold_records() if r.get("event_type") == "expired"]
        print(f"\n[T_expiry/hold_store] expired={json.dumps(expired_events, indent=2)}")
        self.assertEqual(len(expired_events), 1)
        ev = expired_events[0]
        self.assertEqual(
            ev["expired_ts"], self._DEADLINE,
            "WHEN IT TIMED OUT is the hold's own expires_ts, not when we looked",
        )
        self.assertGreaterEqual(ev["observed_ts"], observed_after)
        self.assertEqual(ev["ts"], ev["observed_ts"],
                         "`ts` stays the append time so the file keeps write order")
        self.assertNotEqual(ev["expired_ts"], ev["observed_ts"])

    def test_art14_hold_resolution_event_carries_the_deadline_as_resolved_ts(self) -> None:
        """The Art.14 evidence line is the one an auditor reads. Before this
        fix it said a July hold timed out in August."""
        rec = holds_mod.create_hold(
            _require_approval_env(), "reeflex.policy/irreversible_broad_prod",
            decision_id=uuid.uuid4().hex,
        )
        hold_id = rec["id"]
        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = self._DEADLINE

        holds_mod.get_hold(hold_id)
        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_expiry/art14] events={json.dumps(events, indent=2)}")

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["resolution"], "expired")
        self.assertEqual(
            ev["resolved_ts"], self._DEADLINE,
            "the audited resolution time IS the deadline the human missed",
        )
        self.assertTrue(ev.get("observed_ts"), "the detection lag stays visible, as lag")
        self.assertGreater(ev["observed_ts"], ev["resolved_ts"])
        self.assertEqual(ev["decided_by"], "system:reeflex-core")

    def test_no_observed_ts_key_when_detection_is_the_resolution_moment(self) -> None:
        """A human approve/reject is decided and recorded at the same instant,
        so there is no lag to report — the additive key stays absent rather
        than duplicating resolved_ts."""
        rec = holds_mod.create_hold(
            _require_approval_env(), "reeflex.policy/irreversible_broad_prod",
            decision_id=uuid.uuid4().hex,
        )
        holds_mod.resolve_hold(rec["id"], "approve", "human", "supervisor-a")
        events = _hold_resolution_records_for(rec["id"])
        print(f"\n[T_expiry/no_lag] events={json.dumps(events, indent=2)}")
        self.assertEqual(len(events), 1)
        self.assertNotIn("observed_ts", events[0])

    def test_hold_with_no_expires_ts_falls_back_to_the_observation_time(self) -> None:
        """Pre-TTL records carry no deadline. The fallback is the observation
        time (the only real datum available) — never a guessed offset from
        created_ts, which would invent a deadline this store never set."""
        rec = holds_mod.create_hold(
            _require_approval_env(), "reeflex.policy/irreversible_broad_prod",
            decision_id=uuid.uuid4().hex,
        )
        hold_id = rec["id"]
        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = ""
        holds_mod._append_expired_event(hold_id)

        ev = [r for r in self._hold_records() if r.get("event_type") == "expired"][0]
        print(f"\n[T_expiry/no_deadline] expired={json.dumps(ev)}")
        self.assertEqual(ev["expired_ts"], ev["observed_ts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
