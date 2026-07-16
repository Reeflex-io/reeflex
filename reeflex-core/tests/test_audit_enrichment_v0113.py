"""
test_audit_enrichment_v0113.py — v0.1.13 audit enrichment tests for reeflex-core.

Covers the ADDITIVE Attest evidence fields:
  1. agent_id + action.target_system present on every decision audit record.
  2. hold_resolution audit events ("event": "hold_resolution") emitted on the
     SAME decisions.jsonl stream, with all five fields (hold_id, resolution,
     decided_by, decision_id, resolved_ts), for:
       - approved  (via decide.py's mark_consumed() success path)
       - rejected  (via holds.resolve_hold())
       - expired   (via holds._append_expired_event(), lazy detection)
  3. Backward compatibility: existing decision-record consumers still parse;
     the `decision` field and existing keys are unchanged.

Test cases:
  TestDecisionRecordEnrichment   agent_id / action.target_system present;
                                  action.environment unchanged; decision
                                  field byte-identical to the response.
  TestHoldResolutionApproved     full E2E: require_approval -> approve ->
                                  resubmit -> allow; hold_resolution
                                  "approved" event carries the RESUBMISSION's
                                  decision_id, decided_by from the approval.
  TestHoldResolutionRejected     holds.resolve_hold() reject -> hold_resolution
                                  "rejected" event, decision_id == "".
  TestHoldResolutionExpired      lazy expiry detection (get_hold on a hold
                                  whose expires_ts was force-mutated to the
                                  past) -> hold_resolution "expired" event,
                                  decided_by == "system:reeflex-core" sentinel.
  TestBackwardCompat             decision records keep parsing with NO "event"
                                  key; hold_resolution records ARE distinguishable
                                  by "event" == "hold_resolution".

OPA-dependent tests are skipped if OPA is unavailable (same pattern as
test_hil.py / test_traceability.py). The pure holds.py tests (rejected,
expired) do NOT require OPA.

Run:
  cd reeflex-core
  python -m pytest tests/test_audit_enrichment_v0113.py -v
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
import uuid

# Make app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.decide import process
import app.holds as holds_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    return f"v0113_sess_{uuid.uuid4().hex[:12]}"


def _base_envelope(
    *,
    verb: str = "read",
    environment: str = "staging",
    reversibility: str = "reversible",
    blast_radius: str = "single",
    externality: str = "internal",
    count: int = 1,
    session_id: str | None = None,
    namespace: str = "test",
    agent_id: str = "agent:v0113-test-runner",
    target_system: str | None = "wordpress-prod-db",
    approval: dict | None = None,
) -> dict:
    target: dict = {
        "kind": "entity",
        "ref": None,
        "environment": environment,
    }
    if target_system is not None:
        target["system"] = target_system
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
        "target": target,
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
            "timestamp": "2026-07-15T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


def _require_approval_env(session_id: str | None = None, **overrides) -> dict:
    """An envelope that fires reeflex.policy/irreversible_broad_prod."""
    kwargs = dict(
        verb="delete",
        environment="production",
        reversibility="irreversible",
        blast_radius="broad",
        externality="internal",
        count=42,
        session_id=session_id,
    )
    kwargs.update(overrides)
    return _base_envelope(**kwargs)


def _find_opa_bin() -> str | None:
    """Return the path to an OPA binary, or None if unavailable."""
    import subprocess

    candidates: list[str] = []
    env_bin = os.environ.get("REEFLEX_OPA_BIN", "")
    if env_bin:
        candidates.append(env_bin)
    candidates.append("opa")
    _repo_root_local = pathlib.Path(__file__).resolve().parent.parent
    for name in ("opa.exe", "opa"):
        local = _repo_root_local / name
        if local.exists():
            candidates.append(str(local))

    for candidate in candidates:
        try:
            r = subprocess.run([candidate, "version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                os.environ["REEFLEX_OPA_BIN"] = candidate
                return candidate
        except Exception:
            continue
    return None


def _opa_available() -> bool:
    return _find_opa_bin() is not None


def _audit_path() -> pathlib.Path:
    env_path = os.environ.get("REEFLEX_AUDIT_LOG", "")
    if env_path:
        return pathlib.Path(env_path)
    return pathlib.Path(_repo_root) / "audit" / "decisions.jsonl"


def _read_audit_records() -> list[dict]:
    path = _audit_path()
    if not path.exists():
        return []
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _last_audit_record_for(session_id: str) -> dict:
    matching = [
        r for r in _read_audit_records()
        if r.get("session_id") == session_id and "event" not in r
    ]
    assert matching, f"no decision audit record for session_id={session_id}"
    return matching[-1]


def _hold_resolution_records_for(hold_id: str) -> list[dict]:
    return [
        r for r in _read_audit_records()
        if r.get("event") == "hold_resolution" and r.get("hold_id") == hold_id
    ]


# ===========================================================================
# TestDecisionRecordEnrichment
# ===========================================================================

class TestDecisionRecordEnrichment(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_audit_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp.name

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_agent_id_and_target_system_present_on_allow(self) -> None:
        env = _base_envelope(
            verb="read", environment="staging",
            agent_id="agent:enrichment-test", target_system="s3-eu-west-1",
        )
        session_id = env["agent"]["session_id"]
        status, resp = process(env)
        self.assertEqual(status, 200)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_enrich/allow] resp={json.dumps(resp)}\n  audit={json.dumps(rec)}")

        self.assertEqual(rec.get("agent_id"), "agent:enrichment-test")
        self.assertEqual(rec.get("action", {}).get("target_system"), "s3-eu-west-1")
        # Pre-existing environment key must be UNCHANGED (additive, not renamed).
        self.assertEqual(rec.get("action", {}).get("environment"), "staging")
        # The decision field itself must be byte-identical to the wire response.
        self.assertEqual(rec.get("decision"), resp.get("decision"))

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_target_system_absent_defaults_to_empty_string(self) -> None:
        """Additive default: an envelope without target.system still audits cleanly."""
        env = _base_envelope(verb="read", environment="staging", target_system=None)
        session_id = env["agent"]["session_id"]
        status, resp = process(env)
        self.assertEqual(status, 200)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_enrich/absent] audit={json.dumps(rec)}")
        self.assertEqual(rec.get("action", {}).get("target_system"), "")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_agent_id_absent_defaults_to_empty_string(self) -> None:
        env = _base_envelope(verb="read", environment="staging")
        del env["agent"]["id"]
        session_id = env["agent"]["session_id"]
        status, resp = process(env)
        self.assertEqual(status, 200)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_enrich/agent_absent] audit={json.dumps(rec)}")
        self.assertEqual(rec.get("agent_id"), "")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_existing_fields_unchanged_full_record_shape(self) -> None:
        """Lock the full decision-record shape (backward compat for existing
        consumers) alongside the new additive keys."""
        env = _base_envelope(verb="read", environment="staging")
        session_id = env["agent"]["session_id"]
        status, resp = process(env)
        rec = _last_audit_record_for(session_id)
        print(f"\n[T_enrich/full_shape] audit={json.dumps(rec, indent=2)}")

        for key in (
            "ts", "session_id", "agent_id", "action", "magnitude_count",
            "cumulative_injected", "decision", "rule", "reason",
            "decision_id", "envelope_hash",
        ):
            self.assertIn(key, rec, f"expected key '{key}' missing from decision record")
        for key in ("namespace", "verb", "ability", "environment", "target_system"):
            self.assertIn(key, rec["action"], f"expected action.{key} missing")
        # No "event" key on a plain decision record (distinguishes it from
        # a hold_resolution event).
        self.assertNotIn("event", rec)


# ===========================================================================
# TestHoldResolutionApproved — E2E: require_approval -> approve -> resubmit
# ===========================================================================

class TestHoldResolutionApproved(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_approved_hold_resolution_event_on_resolve(self) -> None:
        env = _require_approval_env()
        status1, resp1 = process(env)
        self.assertEqual(resp1.get("decision"), "require_approval")
        hold_id = resp1["hold_id"]

        # Before the human decides: no hold_resolution event.
        self.assertEqual(_hold_resolution_records_for(hold_id), [],
                          "no hold_resolution event before the approve decision")

        # The human APPROVES -> the Art.14 evidence event fires HERE, at the
        # decision point (resolve time), regardless of any later consumption.
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo",
                                "approved for v0.1.13 test")

        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_hold_resolution/approved@resolve] events={json.dumps(events, indent=2)}")
        self.assertEqual(len(events), 1, "exactly one hold_resolution event at approve time")
        ev = events[0]
        self.assertEqual(ev.get("event"), "hold_resolution")
        self.assertEqual(ev.get("hold_id"), hold_id)
        self.assertEqual(ev.get("resolution"), "approved")
        self.assertEqual(ev.get("decided_by"), "human:supervisor:leo")
        self.assertEqual(ev.get("decision_id"), "",
                          "decision_id is empty at resolve time (no transit yet); "
                          "the resubmission's decision record carries this hold_id")
        self.assertTrue(ev.get("resolved_ts"), "resolved_ts must be populated")

        # Consuming the approval (resubmission -> allow) must NOT add a 2nd event.
        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": hold_id}
        status2, resp2 = process(env_resub)
        self.assertEqual(resp2.get("decision"), "allow")

        events_after = _hold_resolution_records_for(hold_id)
        self.assertEqual(len(events_after), 1,
                          "consumption must not emit an additional hold_resolution event")


# ===========================================================================
# TestHoldResolutionRejected — pure holds.py, no OPA required
# ===========================================================================

class TestHoldResolutionRejected(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def test_rejected_hold_resolution_event(self) -> None:
        env = _require_approval_env()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod",
                                     decision_id=uuid.uuid4().hex)
        hold_id = rec["id"]

        updated = holds_mod.resolve_hold(hold_id, "reject", "human", "supervisor:leo",
                                          "rejecting for v0.1.13 test")
        self.assertEqual(updated.get("status"), "rejected")

        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_hold_resolution/rejected] updated_hold={json.dumps(updated, default=str)}\n"
              f"  hold_resolution events={json.dumps(events, indent=2)}")

        self.assertEqual(len(events), 1, "exactly one hold_resolution event expected")
        ev = events[0]
        self.assertEqual(ev.get("event"), "hold_resolution")
        self.assertEqual(ev.get("hold_id"), hold_id)
        self.assertEqual(ev.get("resolution"), "rejected")
        self.assertEqual(ev.get("decided_by"), "human:supervisor:leo")
        self.assertEqual(ev.get("decision_id"), "",
                          "no /v1/decide transit is associated with a rejection")
        self.assertTrue(ev.get("resolved_ts"), "resolved_ts must be populated")

    def test_approve_emits_hold_resolution_at_resolve_time(self) -> None:
        """The 'approved' event fires at the human decision point
        (resolve_hold approve), symmetric with 'rejected' -- so an
        approved-but-never-consumed hold is still evidenced (Art.14)."""
        env = _require_approval_env()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod",
                                     decision_id=uuid.uuid4().hex)
        hold_id = rec["id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")

        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_hold_resolution/approve@resolve] events={json.dumps(events)}")
        self.assertEqual(len(events), 1,
                          "resolve_hold(approve) must emit exactly one hold_resolution")
        ev = events[0]
        self.assertEqual(ev.get("resolution"), "approved")
        self.assertEqual(ev.get("decided_by"), "human:supervisor:leo")
        self.assertEqual(ev.get("decision_id"), "",
                          "no /v1/decide transit at approve time")
        self.assertTrue(ev.get("resolved_ts"), "resolved_ts must be populated")


# ===========================================================================
# TestHoldResolutionExpired — lazy expiry detection, no OPA required
# ===========================================================================

class TestHoldResolutionExpired(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def test_expired_hold_resolution_event_on_lazy_detection(self) -> None:
        """Lazy expiry semantics: NOT detected on a background sweep -- only
        when the hold is next observed (get_hold/list_holds) past its
        expires_ts. This test forces that observation directly, same
        pattern as test_hil.py's test_lazy_expiry_appends_expired_record."""
        env = _require_approval_env()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod",
                                     decision_id=uuid.uuid4().hex)
        hold_id = rec["id"]

        # Force expiry into the past directly in the in-memory index.
        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = "2000-01-01T00:00:00Z"

        # get_hold() triggers the lazy expiry check.
        hold = holds_mod.get_hold(hold_id)
        self.assertEqual(hold.get("status"), "expired")

        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_hold_resolution/expired] hold={json.dumps(hold, default=str)}\n"
              f"  hold_resolution events={json.dumps(events, indent=2)}")

        self.assertEqual(len(events), 1, "exactly one hold_resolution event expected")
        ev = events[0]
        self.assertEqual(ev.get("event"), "hold_resolution")
        self.assertEqual(ev.get("hold_id"), hold_id)
        self.assertEqual(ev.get("resolution"), "expired")
        self.assertEqual(ev.get("decided_by"), "system:reeflex-core",
                          "expiry has no deciding principal -- documented sentinel value")
        self.assertEqual(ev.get("decision_id"), "",
                          "no /v1/decide transit is associated with an expiry detection")
        self.assertTrue(ev.get("resolved_ts"), "resolved_ts must be populated")

    def test_expired_event_fires_only_once_on_repeated_observation(self) -> None:
        """A second get_hold() on an already-expired hold must NOT emit a
        second hold_resolution event (duplicate-expiry guard in
        _append_expired_event)."""
        env = _require_approval_env()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod",
                                     decision_id=uuid.uuid4().hex)
        hold_id = rec["id"]

        with holds_mod._lock:
            holds_mod._index[hold_id]["expires_ts"] = "2000-01-01T00:00:00Z"

        holds_mod.get_hold(hold_id)
        holds_mod.get_hold(hold_id)  # second observation

        events = _hold_resolution_records_for(hold_id)
        print(f"\n[T_hold_resolution/expired_once] events={json.dumps(events)}")
        self.assertEqual(len(events), 1,
                          "hold_resolution 'expired' must fire exactly once, "
                          "not once per observation")


# ===========================================================================
# TestBackwardCompat — legacy decision-record consumers keep working
# ===========================================================================

class TestBackwardCompat(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_v0113_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_decision_record_and_hold_resolution_coexist_on_one_stream(self) -> None:
        """A single JSONL stream carries both shapes; a naive consumer that
        filters on `"decision" in record` sees only decision records, and one
        that filters on `record.get("event") == "hold_resolution"` sees only
        resolution events -- both without any schema migration."""
        env = _require_approval_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")

        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": hold_id}
        _, resp2 = process(env_resub)
        self.assertEqual(resp2.get("decision"), "allow")

        all_records = _read_audit_records()
        decision_records = [r for r in all_records if "event" not in r]
        resolution_records = [r for r in all_records if r.get("event") == "hold_resolution"]

        print(f"\n[T_backward_compat] total={len(all_records)} "
              f"decisions={len(decision_records)} resolutions={len(resolution_records)}")

        self.assertGreaterEqual(len(decision_records), 2,
                                 "expected at least the require_approval + allow decision records")
        self.assertEqual(len(resolution_records), 1,
                          "expected exactly the one 'approved' hold_resolution event")
        # Every decision record still has the original required keys.
        for rec in decision_records:
            for key in ("session_id", "decision", "rule", "reason", "decision_id"):
                self.assertIn(key, rec)


if __name__ == "__main__":
    unittest.main()
