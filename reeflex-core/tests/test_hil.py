"""
test_hil.py — HIL Phase 1 tests for reeflex-core.

Tests cover T1 (holds.py), T2 (decide.py freeze + approval), T3 (holds API in
server.py), and T4 (webhook.py).

All tests use STDLIB ONLY (unittest, http.server, threading, json, os, uuid,
tempfile, pathlib, time, urllib.request, queue).

No OPA is required for the hold-store, freeze, and webhook tests.  OPA-dependent
tests (hold creation from real require_approval verdict) are skipped if OPA is
absent (same pattern as the existing test suite).

Run:
  cd reeflex-core
  python -m unittest tests.test_hil -v
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

# Make app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    return f"hil_sess_{uuid.uuid4().hex[:12]}"


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
    agent_id: str = "agent:test-hil",
    approval: dict | None = None,
) -> dict:
    base = {
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
    return base


def _find_opa_bin() -> str | None:
    """Return the path to an OPA binary, or None if unavailable.

    Search order:
      1. REEFLEX_OPA_BIN env var (explicit override)
      2. 'opa' on PATH
      3. opa.exe in the repo root (reeflex-core/opa.exe) — present in this repo
    """
    import subprocess

    candidates: list[str] = []

    # 1. Explicit env override
    env_bin = os.environ.get("REEFLEX_OPA_BIN", "")
    if env_bin:
        candidates.append(env_bin)

    # 2. 'opa' on PATH
    candidates.append("opa")

    # 3. Local opa.exe next to the repo root (reeflex-core/)
    _repo_root_local = pathlib.Path(__file__).resolve().parent.parent
    for name in ("opa.exe", "opa"):
        local = _repo_root_local / name
        if local.exists():
            candidates.append(str(local))

    for candidate in candidates:
        try:
            r = subprocess.run(
                [candidate, "version"], capture_output=True, timeout=5
            )
            if r.returncode == 0:
                # Pin the binary for the rest of this test session so opa.py
                # uses the same binary that the availability check found.
                os.environ["REEFLEX_OPA_BIN"] = candidate
                return candidate
        except Exception:
            continue

    return None


def _opa_available() -> bool:
    """Return True if an OPA binary is callable (checks local repo copy too)."""
    return _find_opa_bin() is not None


# ===========================================================================
# T1 — HOLD STORE UNIT TESTS (holds.py, no OPA, no server)
# ===========================================================================

class TestHoldStore(unittest.TestCase):
    """Unit tests for app/holds.py — no OPA, no HTTP server."""

    def setUp(self) -> None:
        # Point every test at a fresh temp file
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_hil_test_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)  # remove so holds.py creates it fresh

        import app.holds as holds_mod
        self._holds = holds_mod
        holds_mod._reset(self._tmp.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    # ---- canonical_hash ----

    def test_canonical_hash_deterministic(self) -> None:
        """canonical_hash returns the same hex for the same envelope, 10 times."""
        env = _base_envelope()
        hashes = [self._holds.canonical_hash(env) for _ in range(10)]
        self.assertEqual(len(set(hashes)), 1, "canonical_hash is not deterministic")

    def test_canonical_hash_is_hex_string(self) -> None:
        env = _base_envelope()
        h = self._holds.canonical_hash(env)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64, f"sha256 hex should be 64 chars, got {len(h)}")

    def test_canonical_hash_differs_for_different_envelopes(self) -> None:
        env1 = _base_envelope(verb="read")
        env2 = _base_envelope(verb="delete")
        self.assertNotEqual(
            self._holds.canonical_hash(env1),
            self._holds.canonical_hash(env2),
        )

    def test_canonical_hash_order_independent(self) -> None:
        """canonical_hash is stable regardless of dict key insertion order."""
        # Use envelopes with action/axes/magnitude/target fields (the allowlist)
        env_a = _base_envelope(verb="delete", blast_radius="broad")
        env_b = _base_envelope(verb="delete", blast_radius="broad")
        # Change insertion order of axes sub-dict
        env_b["axes"] = {
            "externality": env_a["axes"]["externality"],
            "blast_radius": env_a["axes"]["blast_radius"],
            "reversibility": env_a["axes"]["reversibility"],
        }
        self.assertEqual(
            self._holds.canonical_hash(env_a),
            self._holds.canonical_hash(env_b),
        )

    def test_canonical_hash_stable_across_resubmission(self) -> None:
        """The hash must be identical for original and resubmission envelopes.

        Original has approval={present:False}; resubmission adds hold_id.
        Both must produce the same hash because approval is excluded from the
        allowlist projection (action/axes/magnitude/target only).
        This is the correctness invariant that makes the happy path work.
        """
        original = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            count=42,
        )
        resubmit = dict(original)
        resubmit["approval"] = {"present": True, "hold_id": "deadbeef" * 4}
        resubmit["meta"] = dict(original["meta"])
        resubmit["meta"]["nonce"] = uuid.uuid4().hex  # new nonce

        h_orig  = self._holds.canonical_hash(original)
        h_resub = self._holds.canonical_hash(resubmit)
        self.assertEqual(
            h_orig, h_resub,
            "canonical_hash MUST be stable across resubmission — happy path broken"
        )

    def test_canonical_hash_differs_when_action_changes(self) -> None:
        """Modifying the action (e.g. count) must produce a different hash (design §13)."""
        env_orig = _base_envelope(verb="delete", count=42)
        env_mod  = _base_envelope(verb="delete", count=99)
        self.assertNotEqual(
            self._holds.canonical_hash(env_orig),
            self._holds.canonical_hash(env_mod),
            "canonical_hash must differ when magnitude.count changes"
        )

    def test_canonical_hash_allowlist_excludes_agent(self) -> None:
        """Changing agent.id must NOT change the hash (agent excluded from allowlist)."""
        env_a = _base_envelope(verb="delete", agent_id="agent:alice")
        env_b = _base_envelope(verb="delete", agent_id="agent:bob")
        # Same action fields -> same hash despite different agents
        self.assertEqual(
            self._holds.canonical_hash(env_a),
            self._holds.canonical_hash(env_b),
            "agent.id should not affect canonical_hash"
        )

    # ---- create_hold ----

    def test_create_hold_returns_record(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self.assertIsInstance(rec, dict)
        self.assertIn("id", rec)
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["rule_id"], "reeflex.policy/irreversible_broad_prod")
        self.assertIsNotNone(rec["created_ts"])
        self.assertIsNotNone(rec["expires_ts"])
        self.assertIsNotNone(rec["envelope_hash"])

    def test_create_hold_envelope_hash_matches(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        expected_hash = self._holds.canonical_hash(env)
        self.assertEqual(rec["envelope_hash"], expected_hash)

    def test_create_hold_id_is_hex(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold_id = rec["id"]
        # uuid4 hex = 32 chars, no dashes
        self.assertEqual(len(hold_id), 32, f"id should be 32 hex chars: {hold_id!r}")
        int(hold_id, 16)  # should not raise

    def test_create_hold_file_written(self) -> None:
        env = _base_envelope()
        self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        path = pathlib.Path(self._tmp.name)
        self.assertTrue(path.exists(), "holds.jsonl not created")
        lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertGreaterEqual(len(lines), 1)
        rec = json.loads(lines[-1])
        self.assertEqual(rec["event_type"], "created")
        self.assertEqual(rec["status"], "pending")

    def test_create_hold_readback_proof(self) -> None:
        """The written record can be read back and has matching id."""
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        # Read from file
        with open(self._tmp.name, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        written = json.loads(lines[-1])
        self.assertEqual(written["id"], rec["id"])

    # ---- get_hold ----

    def test_get_hold_returns_record(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold = self._holds.get_hold(rec["id"])
        self.assertIsNotNone(hold)
        self.assertEqual(hold["id"], rec["id"])
        self.assertEqual(hold["status"], "pending")

    def test_get_hold_unknown_id_returns_none(self) -> None:
        hold = self._holds.get_hold("0" * 32)
        self.assertIsNone(hold)

    # ---- list_holds ----

    def test_list_holds_returns_all_pending(self) -> None:
        env1 = _base_envelope()
        env2 = _base_envelope(verb="delete")
        r1 = self._holds.create_hold(env1, "reeflex.policy/irreversible_broad_prod")
        r2 = self._holds.create_hold(env2, "reeflex.policy/session_delete_budget")
        items, cursor = self._holds.list_holds(status="pending")
        ids = {h["id"] for h in items}
        self.assertIn(r1["id"], ids)
        self.assertIn(r2["id"], ids)
        self.assertIsNone(cursor)

    def test_list_holds_status_filter(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        # Approve the hold
        self._holds.resolve_hold(
            rec["id"], "approve", "human", "leo", "test approve"
        )
        approved, _ = self._holds.list_holds(status="approved")
        pending, _ = self._holds.list_holds(status="pending")
        approved_ids = {h["id"] for h in approved}
        pending_ids = {h["id"] for h in pending}
        self.assertIn(rec["id"], approved_ids)
        self.assertNotIn(rec["id"], pending_ids)

    def test_list_holds_pagination(self) -> None:
        for i in range(5):
            self._holds.create_hold(
                _base_envelope(verb=f"delete_{i}"),
                "reeflex.policy/irreversible_broad_prod",
            )
        page1, cursor = self._holds.list_holds(limit=3)
        self.assertEqual(len(page1), 3)
        self.assertIsNotNone(cursor, "next_cursor should be set when there are more items")
        page2, cursor2 = self._holds.list_holds(limit=3, cursor=cursor)
        self.assertEqual(len(page2), 2)
        self.assertIsNone(cursor2)
        # No overlap
        ids1 = {h["id"] for h in page1}
        ids2 = {h["id"] for h in page2}
        self.assertEqual(ids1 & ids2, set(), "pages must not overlap")

    # ---- resolve_hold ----

    def test_resolve_hold_approve(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        updated = self._holds.resolve_hold(
            rec["id"], "approve", "human", "leo.david", "looks good"
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["decided_by"], "human:leo.david")
        self.assertIsNotNone(updated["decided_ts"])
        self.assertEqual(updated["reason"], "looks good")

    def test_resolve_hold_reject(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        updated = self._holds.resolve_hold(
            rec["id"], "reject", "human", "leo.david", "too risky"
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "rejected")

    def test_resolve_hold_event_sourced(self) -> None:
        """The JSONL file must have TWO records after create + resolve."""
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self._holds.resolve_hold(rec["id"], "approve", "human", "leo", None)
        with open(self._tmp.name, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        self.assertEqual(len(lines), 2, "expected 2 event records (created + resolved)")
        event_types = [json.loads(l)["event_type"] for l in lines]
        self.assertEqual(event_types, ["created", "resolved"])

    def test_resolve_hold_unknown_id_returns_none(self) -> None:
        result = self._holds.resolve_hold(
            "0" * 32, "approve", "human", "leo", None
        )
        self.assertIsNone(result)

    # ---- mark_consumed ----

    def test_mark_consumed(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self._holds.resolve_hold(rec["id"], "approve", "human", "leo", None)
        updated = self._holds.mark_consumed(rec["id"])
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "consumed")
        self.assertIsNotNone(updated.get("consumed_ts"))

    def test_mark_consumed_event_sourced(self) -> None:
        """Three event records: created + resolved + consumed."""
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self._holds.resolve_hold(rec["id"], "approve", "human", "leo", None)
        self._holds.mark_consumed(rec["id"])
        with open(self._tmp.name, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        self.assertEqual(len(lines), 3, f"expected 3 event records, got {len(lines)}")

    # ---- expiry ----

    def test_is_expired_future_ts_returns_false(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold = self._holds.get_hold(rec["id"])
        self.assertFalse(self._holds.is_expired(hold), "new hold should not be expired")

    def test_is_expired_past_ts_returns_true(self) -> None:
        hold_mock = {
            "id": "abc123",
            "status": "pending",
            "expires_ts": "2000-01-01T00:00:00Z",  # far in the past
        }
        self.assertTrue(self._holds.is_expired(hold_mock))

    def test_lazy_expiry_appends_expired_record(self) -> None:
        """Manually set expires_ts to the past; get_hold should trigger expiry."""
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")

        # Directly mutate the in-memory index to set an expired timestamp
        with self._holds._lock:
            self._holds._index[rec["id"]]["expires_ts"] = "2000-01-01T00:00:00Z"

        # get_hold should detect expiry and append an expired event
        hold = self._holds.get_hold(rec["id"])
        self.assertEqual(hold["status"], "expired", f"expected expired, got {hold['status']}")

        # File should have a "expired" event record
        with open(self._tmp.name, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        event_types = [json.loads(l).get("event_type") for l in lines]
        self.assertIn("expired", event_types, f"no expired event in {event_types}")

    # ---- boot load / index rebuild ----

    def test_index_rebuilt_on_reset(self) -> None:
        """Create two holds, reset (rebuilds index from JSONL), then get_hold still works."""
        env1 = _base_envelope()
        rec1 = self._holds.create_hold(env1, "reeflex.policy/irreversible_broad_prod")
        env2 = _base_envelope(verb="delete")
        rec2 = self._holds.create_hold(env2, "reeflex.policy/session_delete_budget")

        # Reset: re-point at same file (rebuild from JSONL)
        self._holds._reset(self._tmp.name)

        hold1 = self._holds.get_hold(rec1["id"])
        hold2 = self._holds.get_hold(rec2["id"])
        self.assertIsNotNone(hold1, "hold1 not found after rebuild")
        self.assertIsNotNone(hold2, "hold2 not found after rebuild")
        self.assertEqual(hold1["status"], "pending")
        self.assertEqual(hold2["status"], "pending")

    def test_index_rebuild_preserves_resolved_state(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self._holds.resolve_hold(rec["id"], "approve", "human", "leo", "ok")

        # Rebuild
        self._holds._reset(self._tmp.name)
        hold = self._holds.get_hold(rec["id"])
        self.assertIsNotNone(hold)
        self.assertEqual(hold["status"], "approved")
        self.assertEqual(hold["decided_by"], "human:leo")


# ===========================================================================
# T2a — FREEZE LOGIC TESTS (decide.py, no OPA needed for deny path)
# ===========================================================================

class TestFreeze(unittest.TestCase):
    """Freeze logic in decide.py.

    Non-read verbs with REEFLEX_FREEZE=true -> deny "frozen by operator".
    Read verbs pass through (result = fail_closed when OPA absent — that is
    the correct behaviour: the test verifies the freeze guard doesn't block reads).
    """

    def setUp(self) -> None:
        os.environ.pop("REEFLEX_FREEZE", None)
        # Reset freeze state
        import app.decide as decide_mod
        decide_mod._last_freeze_state = None

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_FREEZE", None)
        import app.decide as decide_mod
        decide_mod._last_freeze_state = None

    def test_freeze_on_non_read_verb_denies(self) -> None:
        """REEFLEX_FREEZE=true + delete verb -> deny 'frozen by operator'."""
        os.environ["REEFLEX_FREEZE"] = "true"
        from app.decide import process
        env = _base_envelope(verb="delete", environment="staging")
        status, resp = process(env)
        print(f"\n[T_freeze/delete] status={status} resp={json.dumps(resp)}")
        self.assertEqual(status, 200, f"freeze deny should be 200, got {status}")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertEqual(resp.get("rule"), "reeflex.policy/frozen")
        self.assertIn("frozen", resp.get("reason", ""))

    def test_freeze_on_execute_verb_denies(self) -> None:
        os.environ["REEFLEX_FREEZE"] = "true"
        from app.decide import process
        env = _base_envelope(verb="execute", environment="production")
        status, resp = process(env)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertEqual(resp.get("rule"), "reeflex.policy/frozen")

    def test_freeze_on_read_verb_passes_through(self) -> None:
        """REEFLEX_FREEZE=true + read verb -> passes through to normal eval.

        If OPA is absent, expect fail_closed (deny) — but NOT 'frozen'.
        If OPA present, expect allow.
        """
        os.environ["REEFLEX_FREEZE"] = "true"
        from app.decide import process
        env = _base_envelope(
            verb="read",
            environment="staging",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        status, resp = process(env)
        print(f"\n[T_freeze/read_passthrough] status={status} resp={json.dumps(resp)}")
        # Must NOT be the frozen rule
        self.assertNotEqual(
            resp.get("rule"), "reeflex.policy/frozen",
            "FREEZE: read verb must NOT be blocked by freeze guard"
        )
        # Decision must be allow (OPA present) or fail_closed deny (OPA absent)
        self.assertIn(resp.get("decision"), ("allow", "deny"))

    def test_freeze_off_does_not_deny(self) -> None:
        """REEFLEX_FREEZE unset: delete in staging -> not frozen (may be allow or OPA-based)."""
        # freeze is off
        from app.decide import process
        env = _base_envelope(
            verb="delete",
            environment="staging",
            reversibility="recoverable",
            blast_radius="scoped",
            externality="internal",
        )
        status, resp = process(env)
        # Must NOT be the frozen rule
        self.assertNotEqual(
            resp.get("rule"), "reeflex.policy/frozen",
            "No-freeze: delete must not be frozen"
        )

    def test_freeze_all_case_variants(self) -> None:
        """REEFLEX_FREEZE accepts 'true', '1', 'yes' as truthy."""
        from app.decide import process
        for val in ("true", "1", "yes", "TRUE", "YES"):
            with self.subTest(val=val):
                import app.decide as decide_mod
                decide_mod._last_freeze_state = None
                os.environ["REEFLEX_FREEZE"] = val
                env = _base_envelope(verb="delete", environment="staging")
                _, resp = process(env)
                self.assertEqual(
                    resp.get("rule"), "reeflex.policy/frozen",
                    f"FREEZE='{val}' did not freeze a non-read verb"
                )

    def test_freeze_false_values_do_not_freeze(self) -> None:
        """REEFLEX_FREEZE=false or empty -> freeze is off."""
        from app.decide import process
        for val in ("false", "0", "no", "", "False"):
            with self.subTest(val=val):
                import app.decide as decide_mod
                decide_mod._last_freeze_state = None
                if val == "":
                    os.environ.pop("REEFLEX_FREEZE", None)
                else:
                    os.environ["REEFLEX_FREEZE"] = val
                env = _base_envelope(
                    verb="delete",
                    environment="staging",
                    reversibility="recoverable",
                    blast_radius="scoped",
                    externality="internal",
                )
                _, resp = process(env)
                self.assertNotEqual(
                    resp.get("rule"), "reeflex.policy/frozen",
                    f"FREEZE='{val}' incorrectly froze a non-read verb"
                )

    def test_freeze_response_has_obligations_and_modulation(self) -> None:
        """Frozen response must include obligations (list) and modulation (None)."""
        os.environ["REEFLEX_FREEZE"] = "true"
        from app.decide import process
        env = _base_envelope(verb="delete")
        _, resp = process(env)
        self.assertIn("obligations", resp)
        self.assertIsInstance(resp["obligations"], list)
        self.assertIsNone(resp.get("modulation"))


# ===========================================================================
# T2b/T2c — HOLD APPROVAL IN DECISION PATH (require OPA for require_approval)
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available — skipping hold-approval tests")
class TestHoldApprovalDecisionPath(unittest.TestCase):
    """Tests for hold creation and approval validation in decide.process().

    Requires OPA. These tests pass when OPA is available; they are skipped
    when OPA is absent (which is the CI environment baseline).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_hil_holds_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = self._tmp.name

        import app.holds as holds_mod
        holds_mod._reset(self._tmp.name)

        import app.ledger as ledger_mod
        self._ledger = ledger_mod

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def _require_approval_env(self, session_id: str | None = None) -> dict:
        return _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
            session_id=session_id,
        )

    def test_require_approval_creates_hold(self) -> None:
        """require_approval verdict -> hold created, hold_id in response."""
        import app.holds as holds_mod
        from app.decide import process

        env = self._require_approval_env()
        status, resp = process(env)
        print(f"\n[T_hold_create] status={status} resp={json.dumps(resp)}")

        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "require_approval")
        self.assertIn("hold_id", resp, "hold_id missing from require_approval response")
        self.assertIn("expires_ts", resp, "expires_ts missing from require_approval response")

        hold_id = resp["hold_id"]
        hold = holds_mod.get_hold(hold_id)
        self.assertIsNotNone(hold, f"hold {hold_id} not in store")
        self.assertEqual(hold["status"], "pending")
        self.assertEqual(hold["rule_id"], "reeflex.policy/irreversible_broad_prod")

    def test_approved_hold_resubmission_allows(self) -> None:
        """After a hold is approved, resubmitting with the hold_id -> allow.

        canonical_hash uses an ALLOWLIST (action, axes, magnitude, target) so
        the approval carrier field is excluded from the hash.  The resubmit
        envelope — identical action fields, new nonce, approval={present:True,
        hold_id:...} — produces the SAME hash as the original and MUST allow.
        """
        import app.holds as holds_mod
        from app.decide import process

        # Step 1: submit -> require_approval + hold created
        env = self._require_approval_env()
        status1, resp1 = process(env)
        self.assertEqual(status1, 200)
        self.assertEqual(resp1.get("decision"), "require_approval",
                         f"Expected require_approval, got: {resp1}")
        hold_id = resp1["hold_id"]
        print(f"\n[T_hold_resubmit/step1] require_approval hold_id={hold_id}")

        # Step 2: approve the hold (different principal, not the agent)
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo",
                               "approved by supervisor")
        hold_after_approve = holds_mod.get_hold(hold_id)
        self.assertEqual(hold_after_approve["status"], "approved",
                         "hold must be approved after resolve_hold")

        # Step 3: resubmit — same action fields, new nonce, approval={present:True, hold_id}
        # The canonical hash covers {action, axes, magnitude, target} only, so
        # swapping the approval field does NOT change the hash.
        env_resubmit = dict(env)
        env_resubmit["meta"] = dict(env["meta"])
        env_resubmit["meta"]["nonce"] = uuid.uuid4().hex
        env_resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status3, resp3 = process(env_resubmit)
        print(f"\n[T_hold_resubmit/step3] status={status3} resp={json.dumps(resp3)}")

        self.assertEqual(status3, 200, f"Unexpected HTTP status: {status3}")
        self.assertEqual(resp3.get("decision"), "allow",
                         f"Expected allow after approved resubmission, got: {resp3}")
        self.assertEqual(resp3.get("rule"), "reeflex.policy/approved_resubmission")

        # Step 4: hold must now be consumed
        hold_after_consume = holds_mod.get_hold(hold_id)
        self.assertEqual(hold_after_consume["status"], "consumed",
                         "hold must be consumed after successful resubmission")

    def test_hold_not_found_denies(self) -> None:
        """Approval referencing a nonexistent hold_id -> deny reeflex_hold_not_found."""
        from app.decide import process

        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
            approval={"present": True, "hold_id": "0" * 32},
        )
        status, resp = process(env)
        print(f"\n[T_hold_not_found] status={status} resp={json.dumps(resp)}")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("reeflex_hold_not_found", resp.get("reason", ""))

    def test_hold_not_approved_denies(self) -> None:
        """Approval referencing a PENDING (not yet approved) hold -> deny."""
        import app.holds as holds_mod
        from app.decide import process

        env = self._require_approval_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        # Resubmit WITHOUT approving first
        env_resub = dict(env)
        env_resub["approval"] = {"present": True, "hold_id": hold_id}
        env_resub["meta"] = dict(env_resub["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex

        status, resp = process(env_resub)
        print(f"\n[T_hold_not_approved] status={status} resp={json.dumps(resp)}")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("reeflex_hold_not_approved", resp.get("reason", ""))

    def test_hold_consumed_denies_replay(self) -> None:
        """Consuming a hold twice must deny on the second attempt."""
        import app.holds as holds_mod
        from app.decide import process

        env = self._require_approval_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        # Approve and consume
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor", None)
        holds_mod.mark_consumed(hold_id)

        # Try to reuse
        env_resub = dict(env)
        env_resub["approval"] = {"present": True, "hold_id": hold_id}
        env_resub["meta"] = dict(env_resub["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex

        status, resp = process(env_resub)
        print(f"\n[T_hold_consumed] status={status} resp={json.dumps(resp)}")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("reeflex_hold_consumed", resp.get("reason", ""))


# ===========================================================================
# T_E2E — END-TO-END HOLD APPROVAL TRACE (decide.process() + holds.py + OPA)
#
# Exercises the complete lifecycle in one test per case, each asserting the
# exact decision at every step.  Requires OPA.
#
# Case a: bulk-delete -> require_approval + hold created
# Case b: approved hold + resubmit -> allow + hold consumed
# Case c: third resubmit (same consumed hold_id) -> deny reeflex_hold_consumed
# Case d: resubmit with action diff (count 5 vs 50) -> deny reeflex_hold_envelope_mismatch
# Case e: actor==approver guard -> deny reeflex_hold_actor_is_approver
# Case f: all six checks in a single sequential trace (a→f combined)
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available — skipping E2E trace tests")
class TestHILEndToEndTrace(unittest.TestCase):
    """End-to-end HIL happy path and guard traces.

    Each test uses a fresh holds file and a fresh session so there is no
    cross-test state leakage.  All HTTP calls use urllib with explicit timeouts.
    All thread joins are bounded.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_e2e_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = self._tmp.name

        import app.holds as holds_mod
        holds_mod._reset(self._tmp.name)

        # Reset nonce store so tests in this class don't collide
        import app.envelope as env_mod
        with env_mod._nonce_lock:
            env_mod._seen_nonces.clear()

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        os.environ.pop("REEFLEX_FREEZE", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    # ---- envelope factory for bulk-delete (irreversible+broad+prod, count 50) ----

    def _bulk_delete_env(
        self,
        session_id: str | None = None,
        agent_id: str = "agent:wordpress",
        approval: dict | None = None,
        count: int = 50,
    ) -> dict:
        """Return a bulk-delete envelope that OPA will score require_approval."""
        return _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=count,
            session_id=session_id or _fresh_session(),
            agent_id=agent_id,
            approval=approval,
        )

    # ------------------------------------------------------------------
    # Case a: POST /v1/decide with bulk-delete -> require_approval + hold
    # ------------------------------------------------------------------

    def test_a_bulk_delete_requires_approval(self) -> None:
        """A bulk-delete (irreversible+broad+prod, count=50) -> require_approval.

        Response MUST contain hold_id and expires_ts.  The hold record in the
        store MUST be status=pending with rule=irreversible_broad_prod.
        """
        import app.holds as holds_mod
        from app.decide import process

        env = self._bulk_delete_env()
        status, resp = process(env)

        print(f"\n[E2E/a] status={status} decision={resp.get('decision')} hold_id={resp.get('hold_id')}")

        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "require_approval",
                         f"Case a: expected require_approval, got: {resp}")
        self.assertIn("hold_id", resp, "Case a: hold_id missing from require_approval response")
        self.assertIn("expires_ts", resp, "Case a: expires_ts missing from require_approval response")

        hold_id = resp["hold_id"]
        hold = holds_mod.get_hold(hold_id)
        self.assertIsNotNone(hold, f"Case a: hold {hold_id} not found in store")
        self.assertEqual(hold["status"], "pending")
        self.assertEqual(hold["rule_id"], "reeflex.policy/irreversible_broad_prod")

    # ------------------------------------------------------------------
    # Case b: resolve -> resubmit -> allow + consumed
    # ------------------------------------------------------------------

    def test_b_approved_resubmit_allows_and_consumes(self) -> None:
        """Approve a hold and resubmit: decision=allow, hold status=consumed.

        This is the core happy path that was broken before the canonical_hash
        fix.  canonical_hash excludes the approval field, so the resubmit
        envelope (approval={present:True, hold_id:...}) produces the same hash
        as the original (approval={present:False}).
        """
        import app.holds as holds_mod
        from app.decide import process

        # Step b.1: first submission -> require_approval
        env = self._bulk_delete_env()
        _, resp1 = process(env)
        self.assertEqual(resp1["decision"], "require_approval")
        hold_id = resp1["hold_id"]
        expires_ts = resp1["expires_ts"]

        print(f"\n[E2E/b.1] require_approval hold_id={hold_id} expires_ts={expires_ts}")

        # Step b.2: resolve (approve) as a human supervisor — NOT the agent
        holds_mod.resolve_hold(hold_id, "approve", "human", "human:leo", "looks fine")
        hold = holds_mod.get_hold(hold_id)
        self.assertEqual(hold["status"], "approved")

        print(f"[E2E/b.2] hold resolved status=approved decided_by={hold['decided_by']}")

        # Step b.3: resubmit — identical action, new nonce, approval={present:True,hold_id}
        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": hold_id}

        status3, resp3 = process(env_resub)
        print(f"[E2E/b.3] resubmit status={status3} decision={resp3.get('decision')}")

        self.assertEqual(status3, 200)
        self.assertEqual(resp3["decision"], "allow",
                         f"Case b: approved resubmission must return allow, got: {resp3}")
        self.assertEqual(resp3["rule"], "reeflex.policy/approved_resubmission")

        # Step b.4: hold must be consumed
        hold_consumed = holds_mod.get_hold(hold_id)
        self.assertEqual(hold_consumed["status"], "consumed",
                         "Case b: hold must be consumed after successful resubmission")
        print(f"[E2E/b.4] hold status={hold_consumed['status']} consumed_ts={hold_consumed.get('consumed_ts')}")

    # ------------------------------------------------------------------
    # Case c: third resubmit with same hold_id -> deny reeflex_hold_consumed
    # ------------------------------------------------------------------

    def test_c_consumed_hold_replay_denied(self) -> None:
        """A second resubmit with an already-consumed hold_id -> deny reeflex_hold_consumed."""
        import app.holds as holds_mod
        from app.decide import process

        env = self._bulk_delete_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "human:leo", None)

        # First resubmit -> allow (consume the hold)
        env_resub1 = dict(env)
        env_resub1["meta"] = dict(env["meta"])
        env_resub1["meta"]["nonce"] = uuid.uuid4().hex
        env_resub1["approval"] = {"present": True, "hold_id": hold_id}
        _, resp2 = process(env_resub1)
        self.assertEqual(resp2["decision"], "allow", f"First resubmit must allow: {resp2}")

        # Second resubmit (same hold_id) -> deny reeflex_hold_consumed
        env_resub2 = dict(env)
        env_resub2["meta"] = dict(env["meta"])
        env_resub2["meta"]["nonce"] = uuid.uuid4().hex
        env_resub2["approval"] = {"present": True, "hold_id": hold_id}
        status3, resp3 = process(env_resub2)

        print(f"\n[E2E/c] consumed replay status={status3} decision={resp3.get('decision')} reason={resp3.get('reason')}")

        self.assertEqual(status3, 200)
        self.assertEqual(resp3["decision"], "deny",
                         f"Case c: replay of consumed hold must deny, got: {resp3}")
        self.assertIn("reeflex_hold_consumed", resp3["reason"],
                      f"Case c: reason must be reeflex_hold_consumed, got: {resp3['reason']}")

    # ------------------------------------------------------------------
    # Case d: different action (count=5 vs count=50) -> envelope_mismatch
    # ------------------------------------------------------------------

    def test_d_envelope_mismatch_denied(self) -> None:
        """A resubmit whose action differs (count=5 vs count=50) -> envelope_mismatch.

        Design §13: 'a modified ACTION cannot ride an old approval.'
        The canonical_hash covers magnitude.count, so count=5 produces a
        different hash than the stored count=50 hash.
        """
        import app.holds as holds_mod
        from app.decide import process

        # Create hold for count=50
        env_50 = self._bulk_delete_env(count=50)
        _, resp1 = process(env_50)
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "human:leo", None)

        # Resubmit with count=5 (different action)
        env_5 = self._bulk_delete_env(
            session_id=env_50["agent"]["session_id"],
            count=5,
        )
        env_5["meta"] = dict(env_5["meta"])
        env_5["meta"]["nonce"] = uuid.uuid4().hex
        env_5["approval"] = {"present": True, "hold_id": hold_id}

        status, resp = process(env_5)
        print(f"\n[E2E/d] mismatch status={status} decision={resp.get('decision')} reason={resp.get('reason')}")

        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "deny",
                         f"Case d: action mismatch must deny, got: {resp}")
        self.assertIn("reeflex_hold_envelope_mismatch", resp["reason"],
                      f"Case d: reason must be reeflex_hold_envelope_mismatch, got: {resp['reason']}")

    # ------------------------------------------------------------------
    # Case e: actor == approver -> deny reeflex_hold_actor_is_approver
    # ------------------------------------------------------------------

    def test_e_actor_is_approver_denied(self) -> None:
        """If the resolver's id == the agent's id, resubmit must deny actor_is_approver.

        The check fires at resubmit time (decide.py check 6), not at resolve time
        (that is the server.py check 4).  This test exercises the decide.py path:
        resolve_hold is called directly (bypassing server validation), then the
        resubmit is sent via decide.process() where check 6 catches the match.
        """
        import app.holds as holds_mod
        from app.decide import process

        agent_id = "agent:bad-actor"
        env = self._bulk_delete_env(agent_id=agent_id)
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        # Resolve as the SAME identity as the agent (bypassing server guard)
        # decided_by will be "human:agent:bad-actor"
        # Check 6 in decide.py compares actor_id ("agent:bad-actor") to the
        # identity part of decided_by: decided_by="human:agent:bad-actor" ->
        # approver_id = "agent:bad-actor" -> match -> deny.
        holds_mod.resolve_hold(hold_id, "approve", "human", "agent:bad-actor", None)

        # Resubmit
        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": hold_id}

        status, resp = process(env_resub)
        print(f"\n[E2E/e] actor_is_approver status={status} decision={resp.get('decision')} reason={resp.get('reason')}")

        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "deny",
                         f"Case e: actor_is_approver must deny, got: {resp}")
        self.assertIn("reeflex_hold_actor_is_approver", resp["reason"],
                      f"Case e: reason must be reeflex_hold_actor_is_approver, got: {resp['reason']}")

    # ------------------------------------------------------------------
    # Case f: full sequential trace a->e in one test (single session)
    # ------------------------------------------------------------------

    def test_f_full_sequential_trace(self) -> None:
        """Single test that exercises the full lifecycle a->e in sequence.

        This is the primary proof: one trace shows all six steps produce the
        exact expected decisions in order.
        """
        import app.holds as holds_mod
        from app.decide import process

        session_id = _fresh_session()

        # ---- f.a: bulk-delete -> require_approval ----
        env = self._bulk_delete_env(session_id=session_id, count=50)
        status_a, resp_a = process(env)
        hold_id = resp_a.get("hold_id")
        expires_ts = resp_a.get("expires_ts")

        print(f"\n[E2E/f.a] status={status_a} decision={resp_a['decision']} hold_id={hold_id}")
        self.assertEqual(resp_a["decision"], "require_approval", f"f.a failed: {resp_a}")
        self.assertIsNotNone(hold_id, "f.a: hold_id must be present")
        self.assertIsNotNone(expires_ts, "f.a: expires_ts must be present")

        # ---- f.b: resolve (approve) as human:leo ----
        holds_mod.resolve_hold(hold_id, "approve", "human", "human:leo", "full trace approval")
        hold_b = holds_mod.get_hold(hold_id)
        print(f"[E2E/f.b] hold status={hold_b['status']} decided_by={hold_b['decided_by']}")
        self.assertEqual(hold_b["status"], "approved", "f.b: hold must be approved")

        # ---- f.c: resubmit with approval -> allow + consumed ----
        env_c = dict(env)
        env_c["meta"] = dict(env["meta"])
        env_c["meta"]["nonce"] = uuid.uuid4().hex
        env_c["approval"] = {"present": True, "hold_id": hold_id}

        status_c, resp_c = process(env_c)
        hold_c = holds_mod.get_hold(hold_id)

        print(f"[E2E/f.c] status={status_c} decision={resp_c['decision']} hold_status={hold_c['status']}")
        self.assertEqual(resp_c["decision"], "allow",
                         f"f.c: approved resubmission must allow, got: {resp_c}")
        self.assertEqual(resp_c["rule"], "reeflex.policy/approved_resubmission")
        self.assertEqual(hold_c["status"], "consumed", "f.c: hold must be consumed")

        # ---- f.d: third resubmit (same hold_id) -> deny reeflex_hold_consumed ----
        env_d = dict(env)
        env_d["meta"] = dict(env["meta"])
        env_d["meta"]["nonce"] = uuid.uuid4().hex
        env_d["approval"] = {"present": True, "hold_id": hold_id}

        status_d, resp_d = process(env_d)
        print(f"[E2E/f.d] status={status_d} decision={resp_d['decision']} reason={resp_d['reason']}")
        self.assertEqual(resp_d["decision"], "deny", f"f.d: replay must deny, got: {resp_d}")
        self.assertIn("reeflex_hold_consumed", resp_d["reason"],
                      f"f.d: must be reeflex_hold_consumed, got: {resp_d['reason']}")

        # ---- f.e: different action (count=5) with a FRESH approved hold -> mismatch ----
        # Create a new hold for count=50, approve it, then resubmit with count=5
        env_for_e = self._bulk_delete_env(session_id=_fresh_session(), count=50)
        _, resp_e1 = process(env_for_e)
        hold_id_e = resp_e1["hold_id"]
        holds_mod.resolve_hold(hold_id_e, "approve", "human", "human:leo", None)

        env_e = self._bulk_delete_env(
            session_id=env_for_e["agent"]["session_id"],
            count=5,  # DIFFERENT from count=50
        )
        env_e["meta"] = dict(env_e["meta"])
        env_e["meta"]["nonce"] = uuid.uuid4().hex
        env_e["approval"] = {"present": True, "hold_id": hold_id_e}

        status_e, resp_e = process(env_e)
        print(f"[E2E/f.e] status={status_e} decision={resp_e['decision']} reason={resp_e['reason']}")
        self.assertEqual(resp_e["decision"], "deny",
                         f"f.e: action mismatch must deny, got: {resp_e}")
        self.assertIn("reeflex_hold_envelope_mismatch", resp_e["reason"],
                      f"f.e: must be reeflex_hold_envelope_mismatch, got: {resp_e['reason']}")

        # ---- f.f: actor==approver -> deny reeflex_hold_actor_is_approver ----
        agent_id_f = "agent:self-approver"
        env_for_f = self._bulk_delete_env(
            session_id=_fresh_session(), agent_id=agent_id_f, count=50
        )
        _, resp_f1 = process(env_for_f)
        hold_id_f = resp_f1["hold_id"]
        holds_mod.resolve_hold(hold_id_f, "approve", "human", agent_id_f, None)

        env_f = dict(env_for_f)
        env_f["meta"] = dict(env_for_f["meta"])
        env_f["meta"]["nonce"] = uuid.uuid4().hex
        env_f["approval"] = {"present": True, "hold_id": hold_id_f}

        status_f, resp_f = process(env_f)
        print(f"[E2E/f.f] status={status_f} decision={resp_f['decision']} reason={resp_f['reason']}")
        self.assertEqual(resp_f["decision"], "deny",
                         f"f.f: actor_is_approver must deny, got: {resp_f}")
        self.assertIn("reeflex_hold_actor_is_approver", resp_f["reason"],
                      f"f.f: must be reeflex_hold_actor_is_approver, got: {resp_f['reason']}")

        print(f"\n[E2E/f] FULL TRACE COMPLETE — all six steps passed.")


# ===========================================================================
# T3 — HOLDS API HTTP TESTS (server.py)
# ===========================================================================

class TestHoldsAPI(unittest.TestCase):
    """HTTP-layer tests for GET /v1/holds and POST /v1/holds/{id}/resolve."""

    _srv: http.server.HTTPServer
    _base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        from app.server import _DecideHandler
        cls._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_hil_api_"
        )
        cls._tmp.close()
        os.unlink(cls._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = cls._tmp.name
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)

        import app.holds as holds_mod
        holds_mod._reset(cls._tmp.name)

        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        port = cls._srv.server_address[1]
        cls._base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        t.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(cls._tmp.name)
        except FileNotFoundError:
            pass

    def setUp(self) -> None:
        # Fresh holds store for each test: truncate the file then reload
        import app.holds as holds_mod
        # Truncate file to empty (remove all prior records)
        with open(self.__class__._tmp.name, "w", encoding="utf-8") as fh:
            pass
        holds_mod._reset(self.__class__._tmp.name)

    # ---- helpers ----

    def _get(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self._base_url}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _post(self, path: str, body: dict) -> tuple[int, dict]:
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(f"{self._base_url}{path}", data=payload, method="POST")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", str(len(payload)))
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _create_hold(self) -> dict:
        """Directly create a hold in the store and return the record."""
        import app.holds as holds_mod
        env = _base_envelope(verb="delete", environment="production")
        return holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")

    # ---- GET /v1/holds ----

    def test_list_holds_returns_200(self) -> None:
        status, body = self._get("/v1/holds")
        self.assertEqual(status, 200, f"expected 200, got {status}: {body}")
        self.assertIn("items", body)
        self.assertIsInstance(body["items"], list)

    def test_list_holds_with_status_filter(self) -> None:
        rec = self._create_hold()
        status, body = self._get("/v1/holds?status=pending")
        self.assertEqual(status, 200)
        ids = [h["id"] for h in body["items"]]
        self.assertIn(rec["id"], ids)

    def test_list_holds_empty_when_no_holds(self) -> None:
        status, body = self._get("/v1/holds")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])

    # ---- GET /v1/holds/{id} ----

    def test_get_hold_returns_200(self) -> None:
        rec = self._create_hold()
        status, body = self._get(f"/v1/holds/{rec['id']}")
        self.assertEqual(status, 200, f"expected 200, got {status}: {body}")
        self.assertEqual(body["id"], rec["id"])
        self.assertEqual(body["status"], "pending")

    def test_get_hold_unknown_returns_404(self) -> None:
        status, body = self._get(f"/v1/holds/{'0' * 32}")
        self.assertEqual(status, 404, f"expected 404, got {status}: {body}")
        self.assertIn("error", body)

    def test_get_hold_includes_envelope(self) -> None:
        rec = self._create_hold()
        status, body = self._get(f"/v1/holds/{rec['id']}")
        self.assertEqual(status, 200)
        self.assertIn("envelope", body, "hold detail must include envelope")
        self.assertIn("action", body["envelope"])

    # ---- POST /v1/holds/{id}/resolve ----

    def test_resolve_approve_returns_200(self) -> None:
        rec = self._create_hold()
        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {
                "decision": "approve",
                "principal": {"type": "human", "id": "supervisor:leo"},
                "reason": "looks fine",
            },
        )
        print(f"\n[T_holds_api/resolve_approve] status={status} body={json.dumps(body)}")
        self.assertEqual(status, 200, f"expected 200, got {status}: {body}")
        self.assertEqual(body.get("status"), "approved")
        self.assertEqual(body.get("decided_by"), "human:supervisor:leo")

    def test_resolve_reject_returns_200(self) -> None:
        rec = self._create_hold()
        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {
                "decision": "reject",
                "principal": {"type": "human", "id": "supervisor:leo"},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "rejected")

    def test_resolve_unknown_hold_returns_404(self) -> None:
        status, body = self._post(
            f"/v1/holds/{'0' * 32}/resolve",
            {"decision": "approve", "principal": {"type": "human", "id": "leo"}},
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_resolve_invalid_decision_returns_400(self) -> None:
        rec = self._create_hold()
        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {"decision": "maybe", "principal": {"type": "human", "id": "leo"}},
        )
        self.assertEqual(status, 400)

    def test_resolve_missing_principal_returns_400(self) -> None:
        rec = self._create_hold()
        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {"decision": "approve"},
        )
        self.assertEqual(status, 400)

    def test_resolve_already_approved_returns_409(self) -> None:
        rec = self._create_hold()
        # First resolution
        self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {"decision": "approve", "principal": {"type": "human", "id": "leo"}},
        )
        # Second resolution attempt
        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {"decision": "approve", "principal": {"type": "human", "id": "leo"}},
        )
        self.assertEqual(status, 409, f"expected 409 for double-resolve, got {status}: {body}")
        self.assertIn("not_resolvable", body.get("error", ""))

    def test_resolve_non_resolvable_rule_returns_403(self) -> None:
        """A hold with rule_id containing 'irreversible_systemic_prod' -> 403."""
        import app.holds as holds_mod
        env = _base_envelope()
        # Directly create a hold with the non-resolvable rule
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_systemic_prod")

        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {"decision": "approve", "principal": {"type": "human", "id": "leo"}},
        )
        print(f"\n[T_holds_api/non_resolvable] status={status} body={json.dumps(body)}")
        self.assertEqual(status, 403, f"expected 403 for non-resolvable rule, got {status}: {body}")
        self.assertEqual(body.get("error"), "rule_not_resolvable")

    def test_resolve_actor_is_approver_returns_403(self) -> None:
        """Principal.id == agent.id -> 403 actor_is_approver."""
        import app.holds as holds_mod
        env = _base_envelope(agent_id="agent:test-hil")
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")

        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {
                "decision": "approve",
                "principal": {"type": "human", "id": "agent:test-hil"},  # same as agent.id
            },
        )
        print(f"\n[T_holds_api/actor_is_approver] status={status} body={json.dumps(body)}")
        self.assertEqual(status, 403, f"expected 403 actor_is_approver, got {status}: {body}")
        self.assertEqual(body.get("error"), "actor_is_approver")

    def test_resolve_agent_type_allowed_by_policy(self) -> None:
        """With policy allowing agent type, agent principal can resolve."""
        import app.holds as holds_mod
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")

        # Set resolution policy to allow agents for this rule
        policy = {
            "default": ["human"],
            "irreversible_broad_prod": ["human", "agent", "automation"],
        }
        os.environ["REEFLEX_RESOLUTION_POLICY"] = json.dumps(policy)
        try:
            status, body = self._post(
                f"/v1/holds/{rec['id']}/resolve",
                {
                    "decision": "approve",
                    "principal": {"type": "agent", "id": "auto-approver:ci"},
                },
            )
        finally:
            os.environ.pop("REEFLEX_RESOLUTION_POLICY", None)
        print(f"\n[T_holds_api/agent_allowed] status={status} body={json.dumps(body)}")
        self.assertEqual(status, 200, f"agent principal should be allowed: {body}")
        self.assertEqual(body.get("status"), "approved")

    def test_resolve_agent_type_blocked_by_policy(self) -> None:
        """With default policy (human only), agent type -> 403."""
        import app.holds as holds_mod
        env = _base_envelope()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        os.environ.pop("REEFLEX_RESOLUTION_POLICY", None)  # default = human-only

        status, body = self._post(
            f"/v1/holds/{rec['id']}/resolve",
            {
                "decision": "approve",
                "principal": {"type": "agent", "id": "ci-bot"},
            },
        )
        print(f"\n[T_holds_api/agent_blocked] status={status} body={json.dumps(body)}")
        self.assertEqual(status, 403, f"agent should be blocked by default policy: {body}")
        self.assertEqual(body.get("error"), "principal_type_not_allowed")

    # ---- Auth on holds routes ----

    def test_holds_routes_require_auth_when_token_set(self) -> None:
        """When REEFLEX_AUTH_TOKEN is set, /v1/holds requires Bearer token."""
        import app.holds as holds_mod
        rec = holds_mod.create_hold(
            _base_envelope(), "reeflex.policy/irreversible_broad_prod"
        )
        os.environ["REEFLEX_AUTH_TOKEN"] = "test-hil-token-xyz"
        try:
            # GET /v1/holds without auth -> 401
            status, body = self._get("/v1/holds")
            self.assertEqual(status, 401, f"expected 401 without auth, got {status}: {body}")

            # GET /v1/holds/{id} without auth -> 401
            status2, body2 = self._get(f"/v1/holds/{rec['id']}")
            self.assertEqual(status2, 401, f"expected 401 for get_hold, got {status2}: {body2}")
        finally:
            os.environ.pop("REEFLEX_AUTH_TOKEN", None)


# ===========================================================================
# T4 — WEBHOOK MODULE TESTS (webhook.py)
# ===========================================================================

class TestWebhookModule(unittest.TestCase):
    """Tests for app/webhook.py — fire-and-forget invariant."""

    def tearDown(self) -> None:
        import app.webhook as wh_mod
        wh_mod.reset_emitter()
        os.environ.pop("REEFLEX_WEBHOOK_URL", None)

    # ---- disabled (no URL) ----

    def test_fire_no_url_is_noop_and_no_raise(self) -> None:
        """fire() with no REEFLEX_WEBHOOK_URL must not raise and do nothing."""
        from app.webhook import fire, reset_emitter
        reset_emitter()  # no URL
        try:
            fire("hold.created", {"hold_id": "abc123", "rule_id": "test"})
        except Exception as exc:
            self.fail(f"fire() raised with no URL: {exc}")

    def test_disabled_emitter_start_stop_no_raise(self) -> None:
        """start()/stop() on a disabled emitter must not raise."""
        from app.webhook import WebhookEmitter
        em = WebhookEmitter()  # no URL
        try:
            em.start()
            em.stop(timeout_s=0.1)
        except Exception as exc:
            self.fail(f"start/stop raised on disabled emitter: {exc}")

    def test_fire_returns_immediately_when_disabled(self) -> None:
        """fire() on a disabled emitter must return in < 10ms."""
        from app.webhook import WebhookEmitter
        em = WebhookEmitter()
        t0 = time.perf_counter()
        em.fire("hold.created", {"hold_id": "abc", "rule_id": "test"})
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 10.0, f"fire() took {elapsed_ms:.2f}ms when disabled")

    # ---- enabled + fake HTTP server ----

    def _start_fake_http_server(self) -> tuple[int, list, threading.Event]:
        """Start a minimal HTTP server that accepts POST and records bodies.

        Returns (port, received_list, delivery_event).
        """
        received: list[bytes] = []
        delivery_event = threading.Event()
        lock = threading.Lock()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                with lock:
                    received.append(body)
                self.send_response(200)
                self.end_headers()
                delivery_event.set()

            def log_message(self, *_a: object) -> None:
                pass  # suppress log noise

        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self._fake_srv = srv
        return port, received, delivery_event

    def _stop_fake_server(self) -> None:
        if hasattr(self, "_fake_srv"):
            self._fake_srv.shutdown()

    def test_fire_delivers_to_url(self) -> None:
        """fire() with a valid URL delivers a POST to the server."""
        from app.webhook import WebhookEmitter

        port, received, event = self._start_fake_http_server()
        try:
            em = WebhookEmitter(url=f"http://127.0.0.1:{port}/hook")
            em.start()
            em.fire("hold.created", {"hold_id": "abc123", "rule_id": "r/test"})
            delivered = event.wait(3.0)
            em.stop(timeout_s=2.0)
            self.assertTrue(delivered, "Webhook delivery event not set within 3s")
            self.assertEqual(len(received), 1)
            payload = json.loads(received[0].decode("utf-8"))
            self.assertEqual(payload.get("event"), "hold.created")
            self.assertEqual(payload.get("hold_id"), "abc123")
        finally:
            self._stop_fake_server()

    def test_fire_payload_has_ts(self) -> None:
        """Webhook payload must include a 'ts' field."""
        from app.webhook import WebhookEmitter

        port, received, event = self._start_fake_http_server()
        try:
            em = WebhookEmitter(url=f"http://127.0.0.1:{port}/hook")
            em.start()
            em.fire("hold.resolved", {"hold_id": "xyz", "status": "approved"})
            event.wait(3.0)
            em.stop(timeout_s=2.0)
            if received:
                payload = json.loads(received[0].decode("utf-8"))
                self.assertIn("ts", payload, "Webhook payload missing 'ts' field")
        finally:
            self._stop_fake_server()

    def test_fire_non_blocking_on_unreachable_url(self) -> None:
        """fire() aimed at a closed port must return in < 50ms."""
        from app.webhook import WebhookEmitter
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        em = WebhookEmitter(url=f"http://127.0.0.1:{closed_port}/hook")
        em.start()
        t0 = time.perf_counter()
        em.fire("hold.created", {"hold_id": "abc"})
        elapsed_ms = (time.perf_counter() - t0) * 1000
        em.stop(timeout_s=1.0)
        self.assertLess(
            elapsed_ms, 50.0,
            f"fire() took {elapsed_ms:.2f}ms on unreachable URL — INVARIANT VIOLATED"
        )

    def test_fire_does_not_raise_on_unreachable(self) -> None:
        """fire() must not raise even when the webhook URL is unreachable."""
        from app.webhook import WebhookEmitter
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        em = WebhookEmitter(url=f"http://127.0.0.1:{closed_port}/hook")
        em.start()
        try:
            em.fire("freeze.flipped", {"freeze_on": True})
        except Exception as exc:
            self.fail(f"fire() raised on unreachable URL — INVARIANT VIOLATED: {exc}")
        finally:
            em.stop(timeout_s=1.0)

    def test_queue_overflow_increments_dropped_counter(self) -> None:
        """Overflowing the webhook queue increments dropped_events."""
        from app.webhook import WebhookEmitter, get_dropped_count
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        em = WebhookEmitter(url=f"http://127.0.0.1:{closed_port}/hook")
        # Do NOT start worker — queue fills up without draining
        baseline = get_dropped_count()
        maxsize = em._QUEUE_MAXSIZE
        for i in range(maxsize + 20):
            em._enqueue({"event": f"test_{i}"})
        after = get_dropped_count()
        self.assertGreaterEqual(
            after - baseline, 20,
            f"Expected >= 20 dropped events, got {after - baseline}"
        )

    def test_module_level_fire_does_not_raise(self) -> None:
        """Module-level fire() must not raise under any circumstance."""
        from app.webhook import fire
        os.environ.pop("REEFLEX_WEBHOOK_URL", None)
        try:
            fire("hold.expired", {"hold_id": "abc", "rule_id": "test"})
            fire("freeze.flipped", {"freeze_on": False})
        except Exception as exc:
            self.fail(f"module-level fire() raised: {exc}")

    def test_reset_emitter_stops_old_starts_new(self) -> None:
        """reset_emitter() returns a new WebhookEmitter without hanging."""
        from app.webhook import WebhookEmitter, reset_emitter
        em1 = reset_emitter(url="http://127.0.0.1:1/unused")
        em1.start()
        em2 = reset_emitter()  # no URL -> disabled
        self.assertIsInstance(em2, WebhookEmitter)


# ===========================================================================
# T_schema — Hold record schema completeness
# ===========================================================================

class TestHoldRecordSchema(unittest.TestCase):
    """Verify that a freshly created hold has all required fields."""

    REQUIRED_FIELDS = {
        "id", "created_ts", "expires_ts", "envelope", "envelope_hash",
        "rule_id", "status", "decided_by", "decided_ts", "reason", "consumed_ts",
    }

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_schema_test_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        import app.holds as holds_mod
        holds_mod._reset(self._tmp.name)
        self._holds = holds_mod

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_created_hold_has_all_required_fields(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        for field in self.REQUIRED_FIELDS:
            self.assertIn(field, rec, f"Hold record missing required field: {field!r}")

    def test_created_hold_status_is_pending(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/test_rule")
        self.assertEqual(rec["status"], "pending")

    def test_created_hold_decided_fields_are_none(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/test_rule")
        self.assertIsNone(rec["decided_by"])
        self.assertIsNone(rec["decided_ts"])
        self.assertIsNone(rec["consumed_ts"])

    def test_created_hold_expires_after_created(self) -> None:
        env = _base_envelope()
        rec = self._holds.create_hold(env, "reeflex.policy/test_rule")
        # expires_ts must be lexicographically after created_ts
        self.assertGreater(
            rec["expires_ts"], rec["created_ts"],
            "expires_ts must be after created_ts"
        )


# ===========================================================================
# T_GAP — Three coverage-gap tests (added 2026-07-04)
#
# GAP A (T_gap_a): reject-then-resubmit via decide path
#   Create hold directly, resolve as REJECT, resubmit with approval -> deny
#   reason=reeflex_hold_rejected.
#
# GAP B (T_gap_b): full HTTP E2E happy path (4 steps over real server)
#   Step 1: POST /v1/decide bulk-delete -> require_approval + hold_id
#   Step 2: POST /v1/holds/{id}/resolve -> 200 approved
#   Step 3: POST /v1/decide same action + approval -> allow
#   Step 4: POST /v1/decide same hold_id again -> deny reeflex_hold_consumed
#
# GAP C (T_gap_c, T5.3): expired-hold resubmit via decide path
#   Create hold directly (approved), mutate expires_ts to the past, resubmit
#   with approval -> deny reason=reeflex_hold_expired.
#
# Anti-hang rules:
#   - All urllib calls have timeout=3
#   - Server threads are daemon threads with bounded join
#   - No unbounded recv
# ===========================================================================


class TestGapA_RejectThenResubmit(unittest.TestCase):
    """GAP A — reject-then-resubmit (decide path, no OPA required).

    Design: _validate_approval check 2 detects status == 'rejected' and
    returns deny with reason 'reeflex_hold_rejected'.

    Hold is created directly via holds.create_hold() (no OPA needed for
    hold creation).  The resubmit goes through decide.process() which hits
    the approval validation path before any OPA call.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_gap_a_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = self._tmp.name

        import app.holds as holds_mod
        holds_mod._reset(self._tmp.name)
        self._holds = holds_mod

        # Clear nonce store so this test class does not collide with others
        import app.envelope as env_mod
        with env_mod._nonce_lock:
            env_mod._seen_nonces.clear()

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_gap_a_rejected_hold_resubmit_denies_with_reason(self) -> None:
        """Create hold, resolve as REJECT, resubmit -> deny reeflex_hold_rejected.

        Key assertions:
          1. Hold created and stored with status=pending.
          2. resolve_hold(reject) sets status=rejected.
          3. decide.process() with approval={present:True, hold_id} returns
             decision=deny and reason contains 'reeflex_hold_rejected'.
        """
        from app.decide import process

        # Step 1: create the envelope and hold directly (no OPA needed)
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold_id = rec["id"]

        # Assert hold created with status=pending
        hold = self._holds.get_hold(hold_id)
        self.assertIsNotNone(hold, "hold must exist after create_hold")
        self.assertEqual(hold["status"], "pending",
                         f"GAP A: hold must be pending after creation, got {hold['status']}")

        # Step 2: resolve as REJECT
        updated = self._holds.resolve_hold(hold_id, "reject", "human", "supervisor:leo", "too risky")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "rejected",
                         f"GAP A: hold must be rejected after resolve_hold(reject), got {updated['status']}")

        # Step 3: resubmit with approval={present:True, hold_id}
        env_resubmit = dict(env)
        env_resubmit["meta"] = dict(env["meta"])
        env_resubmit["meta"]["nonce"] = uuid.uuid4().hex
        env_resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status, resp = process(env_resubmit)

        print(
            f"\n[GAP_A] reject-resubmit status={status} "
            f"decision={resp.get('decision')} reason={resp.get('reason')}"
        )

        self.assertEqual(status, 200,
                         f"GAP A: expect HTTP 200, got {status}: {resp}")
        self.assertEqual(resp.get("decision"), "deny",
                         f"GAP A: rejected hold resubmission must deny, got: {resp}")
        self.assertIn(
            "reeflex_hold_rejected", resp.get("reason", ""),
            f"GAP A: reason must contain 'reeflex_hold_rejected', got: {resp.get('reason')!r}"
        )


@unittest.skipUnless(_opa_available(), "OPA binary not available — skipping GAP B HTTP E2E tests")
class TestGapB_FullHttpE2E(unittest.TestCase):
    """GAP B — Full HTTP E2E happy path (4 steps, all via urllib, real server).

    Steps:
      1. POST /v1/decide bulk-delete -> 200 require_approval + hold_id + expires_ts
      2. POST /v1/holds/{id}/resolve {decision:approve, principal:{type:human,id:leo}} -> 200 approved
      3. POST /v1/decide same action + approval={present:True, hold_id} -> 200 allow
      4. POST /v1/decide same action + same hold_id (already consumed) -> 200 deny reeflex_hold_consumed

    Uses the in-process HTTP server from TestHoldsAPI.  No auth token (matches
    TestHoldsAPI default).  All urllib calls have timeout=3s.
    Server thread is a daemon with bounded join.
    """

    _srv: http.server.HTTPServer
    _base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        from app.server import _DecideHandler

        cls._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_gap_b_e2e_"
        )
        cls._tmp.close()
        os.unlink(cls._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = cls._tmp.name
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)

        import app.holds as holds_mod
        holds_mod._reset(cls._tmp.name)

        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        port = cls._srv.server_address[1]
        cls._base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=cls._srv.serve_forever, daemon=True)
        t.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(cls._tmp.name)
        except FileNotFoundError:
            pass

    def setUp(self) -> None:
        import app.holds as holds_mod
        # Fresh holds store for each test: wipe the JSONL, rebuild the index
        with open(self.__class__._tmp.name, "w", encoding="utf-8") as fh:
            pass
        holds_mod._reset(self.__class__._tmp.name)

        # Clear nonce store to prevent replay-rejection across subtests
        import app.envelope as env_mod
        with env_mod._nonce_lock:
            env_mod._seen_nonces.clear()

    # ---- HTTP helpers (all calls have explicit timeout=3s) ----

    def _post(self, path: str, body: dict) -> tuple[int, dict]:
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base_url}{path}", data=payload, method="POST"
        )
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", str(len(payload)))
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _bulk_delete_envelope(
        self,
        approval: dict | None = None,
        nonce: str | None = None,
    ) -> dict:
        """Return a bulk-delete envelope (irreversible+broad+prod, count=50)."""
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=50,
            session_id=_fresh_session(),
            agent_id="agent:wordpress",
            approval=approval,
        )
        if nonce is not None:
            env["meta"] = dict(env["meta"])
            env["meta"]["nonce"] = nonce
        return env

    def test_gap_b_full_http_e2e_happy_path_and_consumed_deny(self) -> None:
        """4-step HTTP E2E: require_approval -> resolve -> allow -> deny consumed.

        All four calls go over the real in-process HTTP server via urllib.
        No direct process() calls.

        Key assertions per step:
          Step 1: HTTP 200, decision=require_approval, hold_id present, expires_ts present
          Step 2: HTTP 200, status=approved
          Step 3: HTTP 200, decision=allow
          Step 4: HTTP 200, decision=deny, reason contains reeflex_hold_consumed
        """
        # ---- Step 1: POST /v1/decide -> require_approval ----
        env_original = self._bulk_delete_envelope()
        status1, resp1 = self._post("/v1/decide", env_original)

        print(
            f"\n[GAP_B/step1] status={status1} decision={resp1.get('decision')} "
            f"hold_id={resp1.get('hold_id')} expires_ts={resp1.get('expires_ts')}"
        )

        self.assertEqual(status1, 200,
                         f"GAP B step 1: expected HTTP 200, got {status1}: {resp1}")
        self.assertEqual(resp1.get("decision"), "require_approval",
                         f"GAP B step 1: expected require_approval, got: {resp1}")
        self.assertIn("hold_id", resp1,
                      f"GAP B step 1: hold_id missing from require_approval response: {resp1}")
        self.assertIn("expires_ts", resp1,
                      f"GAP B step 1: expires_ts missing from require_approval response: {resp1}")

        hold_id = resp1["hold_id"]
        expires_ts = resp1["expires_ts"]
        self.assertIsNotNone(hold_id, "GAP B step 1: hold_id must not be None")
        self.assertIsNotNone(expires_ts, "GAP B step 1: expires_ts must not be None")

        # ---- Step 2: POST /v1/holds/{id}/resolve -> approved ----
        resolve_body = {
            "decision": "approve",
            "principal": {"type": "human", "id": "leo"},
        }
        status2, resp2 = self._post(f"/v1/holds/{hold_id}/resolve", resolve_body)

        print(f"[GAP_B/step2] status={status2} hold_status={resp2.get('status')}")

        self.assertEqual(status2, 200,
                         f"GAP B step 2: expected HTTP 200, got {status2}: {resp2}")
        self.assertEqual(resp2.get("status"), "approved",
                         f"GAP B step 2: expected status=approved, got: {resp2}")

        # ---- Step 3: POST /v1/decide (same action + approval) -> allow ----
        # Build resubmit envelope: same action fields, new nonce, approval={present:True, hold_id}
        env_resubmit = dict(env_original)
        env_resubmit["meta"] = dict(env_original["meta"])
        env_resubmit["meta"]["nonce"] = uuid.uuid4().hex
        env_resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status3, resp3 = self._post("/v1/decide", env_resubmit)

        print(
            f"[GAP_B/step3] status={status3} decision={resp3.get('decision')} "
            f"rule={resp3.get('rule')}"
        )

        self.assertEqual(status3, 200,
                         f"GAP B step 3: expected HTTP 200, got {status3}: {resp3}")
        self.assertEqual(resp3.get("decision"), "allow",
                         f"GAP B step 3: approved resubmission must return allow, got: {resp3}")

        # ---- Step 4: POST /v1/decide same hold_id again -> deny consumed ----
        env_replay = dict(env_original)
        env_replay["meta"] = dict(env_original["meta"])
        env_replay["meta"]["nonce"] = uuid.uuid4().hex
        env_replay["approval"] = {"present": True, "hold_id": hold_id}

        status4, resp4 = self._post("/v1/decide", env_replay)

        print(
            f"[GAP_B/step4] status={status4} decision={resp4.get('decision')} "
            f"reason={resp4.get('reason')}"
        )

        self.assertEqual(status4, 200,
                         f"GAP B step 4: expected HTTP 200, got {status4}: {resp4}")
        self.assertEqual(resp4.get("decision"), "deny",
                         f"GAP B step 4: replay of consumed hold must deny, got: {resp4}")
        self.assertIn(
            "reeflex_hold_consumed", resp4.get("reason", ""),
            f"GAP B step 4: reason must contain 'reeflex_hold_consumed', got: {resp4.get('reason')!r}"
        )


class TestGapC_ExpiredHoldResubmit(unittest.TestCase):
    """GAP C (T5.3) — expired-hold resubmit via decide path (no OPA required).

    Design: create hold directly (approved), mutate its expires_ts to a past
    timestamp via the in-memory index (same technique as test_lazy_expiry),
    then resubmit with approval={present:True, hold_id}.

    decide.process() approval path:
      - Check 2: status==approved -> passes (hold is approved, not pending)
      - Check 3: is_expired(hold) -> True -> deny reeflex_hold_expired

    Note: is_expired() does a direct clock check and does NOT mutate state,
    so the approved status remains; only the expiry check fires.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_gap_c_"
        )
        self._tmp.close()
        os.unlink(self._tmp.name)
        os.environ["REEFLEX_HOLDS_PATH"] = self._tmp.name

        import app.holds as holds_mod
        holds_mod._reset(self._tmp.name)
        self._holds = holds_mod

        # Clear nonce store
        import app.envelope as env_mod
        with env_mod._nonce_lock:
            env_mod._seen_nonces.clear()

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp.name)
        except FileNotFoundError:
            pass

    def test_gap_c_expired_approved_hold_resubmit_denies(self) -> None:
        """Expired approved hold resubmit -> deny reeflex_hold_expired.

        Key assertions:
          1. Hold created, approved, and confirmed status=approved.
          2. expires_ts forced to a past timestamp in the index.
          3. decide.process() with approval={present:True, hold_id} returns
             decision=deny and reason contains 'reeflex_hold_expired'.
        """
        from app.decide import process

        # Step 1: create envelope and hold directly
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        rec = self._holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold_id = rec["id"]

        # Step 2: approve the hold
        updated = self._holds.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "approved",
                         f"GAP C: hold must be approved, got {updated['status']}")

        # Step 3: force the hold expired by mutating expires_ts in the index
        # (same technique as test_lazy_expiry — direct mutation under _lock)
        with self._holds._lock:
            self._holds._index[hold_id]["expires_ts"] = "2000-01-01T00:00:00Z"

        # Confirm expiry is detected by is_expired()
        hold_after_mutate = self._holds.get_hold(hold_id)
        # Note: get_hold's lazy expiry fires only for status==pending; for approved
        # it returns the hold as-is.  We rely on is_expired() in _validate_approval.
        self.assertTrue(
            self._holds.is_expired(hold_after_mutate),
            f"GAP C: is_expired must be True after mutating expires_ts to past, "
            f"hold={hold_after_mutate}"
        )

        # Step 4: resubmit with approval={present:True, hold_id}
        env_resubmit = dict(env)
        env_resubmit["meta"] = dict(env["meta"])
        env_resubmit["meta"]["nonce"] = uuid.uuid4().hex
        env_resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status, resp = process(env_resubmit)

        print(
            f"\n[GAP_C] expired-hold resubmit status={status} "
            f"decision={resp.get('decision')} reason={resp.get('reason')}"
        )

        self.assertEqual(status, 200,
                         f"GAP C: expect HTTP 200, got {status}: {resp}")
        self.assertEqual(resp.get("decision"), "deny",
                         f"GAP C: expired hold resubmission must deny, got: {resp}")
        self.assertIn(
            "reeflex_hold_expired", resp.get("reason", ""),
            f"GAP C: reason must contain 'reeflex_hold_expired', got: {resp.get('reason')!r}"
        )


# ===========================================================================
# Main
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
