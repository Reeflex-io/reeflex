"""
test_traceability.py — decision_id / hold_id / envelope_hash / parent_decision_id /
traceparent traceability tests for reeflex-core.

Covers the ADDITIVE traceability feature: every /v1/decide transit gets a
primary key (`decision_id`) so audit / SIEM / holds records join on exact
keys instead of ts+session heuristics.

Test cases:
  TestDecisionIdBasics         decision_id present (allow/deny/fail-closed),
                                unique across calls, absent on 400 reject
  TestEnvelopeHashReuse         envelope_hash in the audit record ==
                                holds.canonical_hash(envelope) (same key)
  TestAuditEnrichment           audit record carries decision_id / envelope_hash
                                / hold_id (on require_approval hold-creation)
  TestSiemEnrichment            SIEM (syslog JSON) event carries decision_id /
                                envelope_hash / hold_id
  TestHoldStoresDecisionId      holds.create_hold(decision_id=...) is stored
                                and returned by get_hold()
  TestParentDecisionId          resubmission parent_decision_id: adapter-passed
                                (approval.parent_decision_id) AND hold-fallback
  TestTraceparentPassthrough    context.traceparent echoed verbatim when
                                present; omitted when absent
  TestCefTraceabilityExtensions CEF format: externalId/envelopeHash always
                                present; holdId/parentDecisionId/traceparent
                                conditional
  TestAuditorE2E                full real flow: require_approval (hold
                                created) -> approve -> resubmit -> allow;
                                JOIN by decision_id across SIEM event, audit
                                line, hold record, and parent decision
  TestWireResponseContract      envelope_hash / hold_id / parent_decision_id /
                                traceparent are NEVER on the wire response
                                (audit/SIEM/hold-only fields); decision_id IS
  TestFreezeCarriesDecisionId   decision_id present on the REEFLEX_FREEZE=true
                                frozen-deny path
  TestHoldMachineryFailClosed   decision_id present when holds.create_hold()
                                / holds.mark_consumed() themselves raise
                                (hold_creation_failed / hold_consume_failed)

OPA-dependent tests (anything that reaches a real require_approval / allow /
deny verdict through the shared policy pack) are skipped if OPA is
unavailable (same pattern as test_hil.py / test_decide.py). The
fail-closed test does NOT require OPA (it deliberately breaks it).

Run:
  cd reeflex-core
  python -m unittest tests.test_traceability -v
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
import uuid

# Make app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.decide import process
from app.telemetry import (
    format_decision_cef,
    reset_emitter,
)
import app.holds as holds_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    return f"trace_sess_{uuid.uuid4().hex[:12]}"


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
    approval: dict | None = None,
    context: dict | None = None,
) -> dict:
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:trace-test-runner",
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
        "context": context if context is not None else {},
        "meta": {
            "timestamp": "2026-07-11T00:00:00Z",
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
    """Return the audit log path using the same env-var logic as audit.py."""
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
    matching = [r for r in _read_audit_records() if r.get("session_id") == session_id]
    assert matching, f"no audit record for session_id={session_id}"
    return matching[-1]


# ---------------------------------------------------------------------------
# Fake UDP syslog collector (bounded timeouts; anti-hang throughout)
# ---------------------------------------------------------------------------

class _FakeUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data: bytes = self.request[0]
        with self.server._lock:
            self.server.received.append(data)
        self.server.delivery_event.set()


class _FakeUDPServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.received: list[bytes] = []
        self._lock = threading.Lock()
        self.delivery_event = threading.Event()
        super().__init__((host, port), _FakeUDPHandler)


def _start_server_thread(server: socketserver.BaseServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _stop_server(server: socketserver.BaseServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def _wait_for_n_datagrams(srv: _FakeUDPServer, n: int, timeout_s: float = 3.0) -> list[dict]:
    """Wait (bounded) until >= n datagrams arrive; return them parsed as JSON."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with srv._lock:
            if len(srv.received) >= n:
                break
        time.sleep(0.02)
    with srv._lock:
        raw = list(srv.received)
    events = []
    for datagram in raw:
        body = datagram.decode("utf-8", errors="replace")
        # RFC 5424 header ends before the JSON MSG body starts with '{'
        idx = body.find("{")
        assert idx != -1, f"no JSON body found in datagram: {body[:200]}"
        events.append(json.loads(body[idx:]))
    return events


# ===========================================================================
# TestDecisionIdBasics
# ===========================================================================

class TestDecisionIdBasics(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
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
    def test_decision_id_present_on_allow(self) -> None:
        env = _base_envelope(verb="read", environment="staging")
        status, resp = process(env)
        print(f"\n[T_decision_id/allow] status={status} decision_id={resp.get('decision_id')}")
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "allow")
        self.assertTrue(resp.get("decision_id"), "decision_id missing from allow response")
        self.assertEqual(len(resp["decision_id"]), 32, "decision_id must be a uuid4 hex (32 chars)")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_decision_id_present_on_deny(self) -> None:
        env = _base_envelope(
            verb="execute", environment="production",
            reversibility="irreversible", blast_radius="systemic", externality="physical",
        )
        status, resp = process(env)
        print(f"\n[T_decision_id/deny] status={status} decision_id={resp.get('decision_id')}")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertTrue(resp.get("decision_id"), "decision_id missing from deny response")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_decision_id_unique_across_calls(self) -> None:
        """10 independent calls -> 10 distinct decision_id values."""
        ids = set()
        for _ in range(10):
            env = _base_envelope(verb="read", environment="staging")
            _, resp = process(env)
            ids.add(resp.get("decision_id"))
        print(f"\n[T_decision_id/unique] ids={ids}")
        self.assertEqual(len(ids), 10, "decision_id must be unique per /v1/decide call")

    def test_decision_id_absent_on_structural_400_reject(self) -> None:
        """A structurally invalid envelope (400) is NOT a Decision -- no decision_id."""
        status, resp = process({"action": {}})  # missing required fields
        print(f"\n[T_decision_id/400] status={status} resp={resp}")
        self.assertEqual(status, 400)
        self.assertNotIn("decision_id", resp,
                         "decision_id must not appear on a structural validation reject")

    def test_decision_id_present_on_fail_closed(self) -> None:
        """OPA unavailable -> deny, fail-closed -- decision_id must still be present."""
        original = os.environ.get("REEFLEX_OPA_BIN")
        os.environ["REEFLEX_OPA_BIN"] = "/nonexistent/path/to/opa_binary_xyz"
        try:
            env = _base_envelope(verb="delete", environment="production",
                                  reversibility="irreversible", blast_radius="broad")
            status, resp = process(env)
        finally:
            if original is None:
                os.environ.pop("REEFLEX_OPA_BIN", None)
            else:
                os.environ["REEFLEX_OPA_BIN"] = original

        print(f"\n[T_decision_id/fail_closed] status={status} resp={json.dumps(resp)}")
        self.assertEqual(status, 500)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertTrue(resp.get("decision_id"), "decision_id missing on fail-closed decision")


# ===========================================================================
# TestEnvelopeHashReuse — the audit record's envelope_hash == holds.canonical_hash
# ===========================================================================

class TestEnvelopeHashReuse(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
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
    def test_audit_envelope_hash_matches_canonical_hash(self) -> None:
        env = _base_envelope(verb="read", environment="staging")
        session_id = env["agent"]["session_id"]
        status, resp = process(env)
        self.assertEqual(status, 200)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_envelope_hash] audit record={json.dumps(rec, indent=2)}")

        expected_hash = holds_mod.canonical_hash(env)
        self.assertEqual(rec.get("envelope_hash"), expected_hash,
                         "audit envelope_hash must equal holds.canonical_hash(envelope) -- "
                         "the SAME join key used by hold records")


# ===========================================================================
# TestAuditEnrichment
# ===========================================================================

class TestAuditEnrichment(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_holds_"
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
    def test_audit_record_carries_decision_id_and_envelope_hash_on_allow(self) -> None:
        env = _base_envelope(verb="read", environment="staging")
        session_id = env["agent"]["session_id"]
        _, resp = process(env)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_audit_enrich/allow] resp={json.dumps(resp)}\n  audit={json.dumps(rec)}")
        self.assertEqual(rec.get("decision_id"), resp.get("decision_id"))
        self.assertTrue(rec.get("envelope_hash"))
        self.assertNotIn("hold_id", rec, "hold_id must be absent on a plain allow")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_audit_record_carries_hold_id_on_require_approval(self) -> None:
        env = _require_approval_env()
        session_id = env["agent"]["session_id"]
        _, resp = process(env)
        self.assertEqual(resp.get("decision"), "require_approval")

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_audit_enrich/hold] resp={json.dumps(resp)}\n  audit={json.dumps(rec)}")
        self.assertEqual(rec.get("decision_id"), resp.get("decision_id"))
        self.assertEqual(rec.get("hold_id"), resp.get("hold_id"))
        self.assertTrue(rec.get("envelope_hash"))

        # And the hold itself must name the decision that created it.
        hold = holds_mod.get_hold(resp["hold_id"])
        self.assertEqual(hold.get("decision_id"), resp.get("decision_id"))


# ===========================================================================
# TestSiemEnrichment
# ===========================================================================

class TestSiemEnrichment(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

        self._srv = _FakeUDPServer("127.0.0.1", 0)
        self._port = self._srv.server_address[1]
        self._t = _start_server_thread(self._srv)
        self._emitter = reset_emitter(
            enabled=True, address=f"127.0.0.1:{self._port}", protocol="udp", fmt="json",
        )
        self._emitter.start()

    def tearDown(self) -> None:
        self._emitter.stop(timeout_s=2.0)
        _stop_server(self._srv, self._t)
        reset_emitter(enabled=False)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp_holds.name)
        except FileNotFoundError:
            pass

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_siem_event_carries_decision_id_and_envelope_hash(self) -> None:
        env = _base_envelope(verb="read", environment="staging")
        _, resp = process(env)

        events = _wait_for_n_datagrams(self._srv, 1)
        print(f"\n[T_siem_enrich/allow] resp={json.dumps(resp)}\n  siem={json.dumps(events[-1])}")
        self.assertEqual(events[-1].get("decision_id"), resp.get("decision_id"))
        self.assertTrue(events[-1].get("envelope_hash"))
        self.assertNotIn("hold_id", events[-1], "hold_id must be absent on a plain allow SIEM event")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_siem_event_carries_hold_id_on_require_approval(self) -> None:
        env = _require_approval_env()
        _, resp = process(env)

        events = _wait_for_n_datagrams(self._srv, 1)
        print(f"\n[T_siem_enrich/hold] resp={json.dumps(resp)}\n  siem={json.dumps(events[-1])}")
        self.assertEqual(events[-1].get("decision_id"), resp.get("decision_id"))
        self.assertEqual(events[-1].get("hold_id"), resp.get("hold_id"))


# ===========================================================================
# TestHoldStoresDecisionId — pure holds.py, no OPA / no decide.process()
# ===========================================================================

class TestHoldStoresDecisionId(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_holds_"
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

    def test_create_hold_stores_decision_id(self) -> None:
        env = _require_approval_env()
        d_id = uuid.uuid4().hex
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod",
                                     decision_id=d_id)
        print(f"\n[T_hold_decision_id] created hold={json.dumps(rec)}")
        self.assertEqual(rec.get("decision_id"), d_id)

        fetched = holds_mod.get_hold(rec["id"])
        self.assertEqual(fetched.get("decision_id"), d_id,
                         "get_hold() must return the decision_id recorded at creation")

    def test_create_hold_decision_id_defaults_to_empty_string(self) -> None:
        """Additive default: an older caller that omits decision_id keeps working."""
        env = _require_approval_env()
        rec = holds_mod.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self.assertEqual(rec.get("decision_id"), "")


# ===========================================================================
# TestParentDecisionId — adapter-passed vs hold-fallback resolution
# ===========================================================================

class TestParentDecisionId(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        try:
            os.unlink(self._tmp_holds.name)
        except FileNotFoundError:
            pass

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_parent_decision_id_fallback_from_hold(self) -> None:
        """Adapter does NOT pass parent_decision_id -- core resolves it from the
        decision_id recorded on the consumed hold."""
        env = _require_approval_env()
        _, resp1 = process(env)
        original_decision_id = resp1["decision_id"]
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")

        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {"present": True, "hold_id": hold_id}  # no parent_decision_id

        _, resp2 = process(env_resub)
        print(f"\n[T_parent_fallback] original_decision_id={original_decision_id} "
              f"resubmit_resp={json.dumps(resp2)}")

        self.assertEqual(resp2.get("decision"), "allow")
        self.assertEqual(resp2.get("parent_decision_id"), original_decision_id,
                         "parent_decision_id must fall back to the hold's creating decision_id")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_parent_decision_id_adapter_passed_wins(self) -> None:
        """Adapter passes approval.parent_decision_id explicitly -- core uses
        that value verbatim rather than the hold-fallback."""
        env = _require_approval_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]

        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")

        adapter_supplied_parent = f"adapter-supplied-{uuid.uuid4().hex}"
        env_resub = dict(env)
        env_resub["meta"] = dict(env["meta"])
        env_resub["meta"]["nonce"] = uuid.uuid4().hex
        env_resub["approval"] = {
            "present": True,
            "hold_id": hold_id,
            "parent_decision_id": adapter_supplied_parent,
        }

        _, resp2 = process(env_resub)
        print(f"\n[T_parent_adapter_passed] adapter_supplied={adapter_supplied_parent} "
              f"resubmit_resp={json.dumps(resp2)}")

        self.assertEqual(resp2.get("decision"), "allow")
        self.assertEqual(resp2.get("parent_decision_id"), adapter_supplied_parent,
                         "adapter-supplied approval.parent_decision_id must win over the "
                         "hold-fallback")


# ===========================================================================
# TestTraceparentPassthrough
# ===========================================================================

class TestTraceparentPassthrough(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
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
    def test_traceparent_echoed_verbatim_when_present(self) -> None:
        tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        env = _base_envelope(verb="read", environment="staging",
                             context={"traceparent": tp})
        session_id = env["agent"]["session_id"]
        _, resp = process(env)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_traceparent/present] audit={json.dumps(rec)}")
        self.assertEqual(rec.get("traceparent"), tp,
                         "traceparent must be echoed UNTOUCHED into the audit record")

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_traceparent_absent_when_not_provided(self) -> None:
        env = _base_envelope(verb="read", environment="staging")  # context={} -- no traceparent
        session_id = env["agent"]["session_id"]
        _, resp = process(env)

        rec = _last_audit_record_for(session_id)
        print(f"\n[T_traceparent/absent] audit={json.dumps(rec)}")
        self.assertNotIn("traceparent", rec,
                         "traceparent key must be OMITTED when the envelope did not carry one")


# ===========================================================================
# TestCefTraceabilityExtensions — pure formatter-level, no socket, no OPA
# ===========================================================================

class TestCefTraceabilityExtensions(unittest.TestCase):

    def _sample_event(self, **extra) -> dict:
        event = {
            "ts": "2026-07-11T12:00:00Z",
            "event": "decision",
            "verdict": "allow",
            "rule_id": "reeflex.policy/test_rule",
            "verb": "read",
            "ability": "test/read",
            "axes": {"reversibility": "reversible", "blast_radius": "single",
                     "externality": "internal"},
            "magnitude_count": 1,
            "session_id": "sess_cef_trace_0001",
            "agent_id": "agent:test-runner",
            "on_behalf_of": "user:synthetic",
            "environment": "staging",
            "mode": "enforce",
            "decision_latency_ms": 3,
            "reason": "synthetic",
            "reeflex_version": "0.1",
            "epoch_ms": 1751544000000,
        }
        event.update(extra)
        return event

    def test_cef_always_includes_external_id_and_envelope_hash(self) -> None:
        event = self._sample_event(decision_id="abc123", envelope_hash="deadbeef" * 8)
        cef = format_decision_cef(event, version="0.1")
        ext = cef.split("|", 7)[-1]
        print(f"\n[T_cef/always] ext={ext}")
        self.assertIn("externalId=abc123", ext)
        self.assertIn(f"envelopeHash={'deadbeef' * 8}", ext)

    def test_cef_omits_hold_and_parent_and_traceparent_when_absent(self) -> None:
        event = self._sample_event(decision_id="abc123", envelope_hash="hash1")
        cef = format_decision_cef(event, version="0.1")
        ext = cef.split("|", 7)[-1]
        print(f"\n[T_cef/omit] ext={ext}")
        self.assertNotIn("holdId=", ext)
        self.assertNotIn("parentDecisionId=", ext)
        self.assertNotIn("traceparent=", ext)

    def test_cef_includes_hold_and_parent_and_traceparent_when_present(self) -> None:
        event = self._sample_event(
            decision_id="abc123", envelope_hash="hash1",
            hold_id="hold789", parent_decision_id="parent456",
            traceparent="00-trace-span-01",
        )
        cef = format_decision_cef(event, version="0.1")
        ext = cef.split("|", 7)[-1]
        print(f"\n[T_cef/include] ext={ext}")
        self.assertIn("holdId=hold789", ext)
        self.assertIn("parentDecisionId=parent456", ext)
        self.assertIn("traceparent=00-trace-span-01", ext)


# ===========================================================================
# TestAuditorE2E — THE full stitched chain
#
# require_approval (creates hold) -> approve -> resubmit (allow) -- then
# JOIN by decision_id across the SIEM event, the audit line, the hold
# record, and the parent decision.  Prints the joined records so the
# stitched story is visible in the test output.
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available -- skipping E2E trace")
class TestAuditorE2E(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_e2e_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_e2e_holds_"
        )
        self._tmp_holds.close()
        os.unlink(self._tmp_holds.name)
        holds_mod._reset(self._tmp_holds.name)

        self._srv = _FakeUDPServer("127.0.0.1", 0)
        self._port = self._srv.server_address[1]
        self._t = _start_server_thread(self._srv)
        self._emitter = reset_emitter(
            enabled=True, address=f"127.0.0.1:{self._port}", protocol="udp", fmt="json",
        )
        self._emitter.start()

    def tearDown(self) -> None:
        self._emitter.stop(timeout_s=2.0)
        _stop_server(self._srv, self._t)
        reset_emitter(enabled=False)
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        for p in (self._tmp_audit.name, self._tmp_holds.name):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def test_full_chain_decision_hold_approval_redecision(self) -> None:
        # ------------------------------------------------------------------
        # Step 1: original submission -> require_approval, hold created
        # ------------------------------------------------------------------
        env = _require_approval_env()
        session_id = env["agent"]["session_id"]
        status1, resp1 = process(env)
        self.assertEqual(status1, 200)
        self.assertEqual(resp1.get("decision"), "require_approval")

        original_decision_id = resp1["decision_id"]
        hold_id = resp1["hold_id"]
        self.assertTrue(original_decision_id)
        self.assertTrue(hold_id)

        siem_events_1 = _wait_for_n_datagrams(self._srv, 1)
        original_siem = siem_events_1[-1]
        original_audit = _last_audit_record_for(session_id)
        hold_after_create = holds_mod.get_hold(hold_id)

        # ------------------------------------------------------------------
        # Step 2: approve the hold (a different principal than the actor)
        # ------------------------------------------------------------------
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo",
                               "approved for E2E traceability test")

        # ------------------------------------------------------------------
        # Step 3: resubmit -- same action fields, new nonce, approval
        # references the hold_id (no adapter-supplied parent_decision_id,
        # exercising the hold-fallback resolution path).
        # ------------------------------------------------------------------
        env_resubmit = dict(env)
        env_resubmit["meta"] = dict(env["meta"])
        env_resubmit["meta"]["nonce"] = uuid.uuid4().hex
        env_resubmit["approval"] = {"present": True, "hold_id": hold_id}

        status3, resp3 = process(env_resubmit)
        self.assertEqual(status3, 200)
        self.assertEqual(resp3.get("decision"), "allow")

        resubmit_decision_id = resp3["decision_id"]
        self.assertTrue(resubmit_decision_id)

        siem_events_2 = _wait_for_n_datagrams(self._srv, 2)
        resubmit_siem = siem_events_2[-1]
        resubmit_audit = _last_audit_record_for(session_id)
        hold_after_consume = holds_mod.get_hold(hold_id)

        # ------------------------------------------------------------------
        # PRINT the joined records -- the stitched story, visible in output
        # ------------------------------------------------------------------
        print("\n" + "=" * 78)
        print("[AUDITOR E2E] Full decision -> hold -> approval -> re-decision chain")
        print("=" * 78)
        print(f"\n[1] ORIGINAL DECISION (require_approval) response:\n"
              f"    {json.dumps(resp1, indent=4)}")
        print(f"\n[2] ORIGINAL DECISION -- audit record:\n"
              f"    {json.dumps(original_audit, indent=4)}")
        print(f"\n[3] ORIGINAL DECISION -- SIEM event:\n"
              f"    {json.dumps(original_siem, indent=4)}")
        print(f"\n[4] HOLD RECORD (after creation):\n"
              f"    {json.dumps(hold_after_create, indent=4, default=str)}")
        print(f"\n[5] HOLD RECORD (after resolve + consume):\n"
              f"    {json.dumps(hold_after_consume, indent=4, default=str)}")
        print(f"\n[6] RESUBMISSION DECISION (allow) response:\n"
              f"    {json.dumps(resp3, indent=4)}")
        print(f"\n[7] RESUBMISSION DECISION -- audit record:\n"
              f"    {json.dumps(resubmit_audit, indent=4)}")
        print(f"\n[8] RESUBMISSION DECISION -- SIEM event:\n"
              f"    {json.dumps(resubmit_siem, indent=4)}")
        print("\n" + "-" * 78)
        print("[AUDITOR E2E] JOIN KEYS:")
        print(f"    original.decision_id       = {original_decision_id}")
        print(f"    hold.decision_id           = {hold_after_create.get('decision_id')}")
        print(f"    resubmit.parent_decision_id= {resubmit_audit.get('parent_decision_id')}")
        print(f"    hold_id (created)          = {hold_id}")
        print(f"    resubmit.hold_id (consumed)= {resubmit_audit.get('hold_id')}")
        print(f"    original.envelope_hash     = {original_audit.get('envelope_hash')}")
        print(f"    resubmit.envelope_hash     = {resubmit_audit.get('envelope_hash')}")
        print("-" * 78)

        # ------------------------------------------------------------------
        # ASSERT the key chain holds
        # ------------------------------------------------------------------
        # a) the hold names the decision that created it
        self.assertEqual(hold_after_create.get("decision_id"), original_decision_id)

        # b) the resubmission's parent_decision_id == the original decision_id
        #    == the hold's creating decision_id (all three equal)
        self.assertEqual(resp3.get("parent_decision_id"), original_decision_id)
        self.assertEqual(resubmit_audit.get("parent_decision_id"), original_decision_id)
        self.assertEqual(resubmit_siem.get("parent_decision_id"), original_decision_id)

        # c) the consumed hold_id on resubmission matches the hold created originally
        self.assertEqual(resubmit_audit.get("hold_id"), hold_id)
        self.assertEqual(resubmit_siem.get("hold_id"), hold_id)
        self.assertEqual(original_audit.get("hold_id"), hold_id)
        self.assertEqual(original_siem.get("hold_id"), hold_id)

        # d) decision_id on each record matches its own response's decision_id
        self.assertEqual(original_audit.get("decision_id"), original_decision_id)
        self.assertEqual(original_siem.get("decision_id"), original_decision_id)
        self.assertEqual(resubmit_audit.get("decision_id"), resubmit_decision_id)
        self.assertEqual(resubmit_siem.get("decision_id"), resubmit_decision_id)

        # e) original and resubmission decision_id are DIFFERENT transits
        self.assertNotEqual(original_decision_id, resubmit_decision_id)

        # f) envelope_hash is stable across original and resubmission (same
        #    action/axes/magnitude/target -- only approval + nonce differ) and
        #    equals holds.canonical_hash() of the original envelope
        expected_hash = holds_mod.canonical_hash(env)
        self.assertEqual(original_audit.get("envelope_hash"), expected_hash)
        self.assertEqual(resubmit_audit.get("envelope_hash"), expected_hash)

        # g) the hold is now consumed
        self.assertEqual(hold_after_consume.get("status"), "consumed")

        print("\n[AUDITOR E2E] All join assertions PASSED -- chain is fully navigable.\n")


# ===========================================================================
# TestWireResponseContract — enrichment fields are audit/SIEM/hold-only;
# decision_id (and only decision_id / parent_decision_id) are on the wire
# ===========================================================================

class TestWireResponseContract(unittest.TestCase):
    """Lock the /v1/decide response contract explicitly: envelope_hash,
    hold_id (on a plain allow, i.e. no hold involved), and traceparent are
    enrichment fields for audit/SIEM/hold records ONLY -- they must never
    leak onto the wire response. decision_id IS part of the wire contract
    (added to the response dict in every branch)."""

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_envelope_hash_and_other_enrichment_keys_absent_from_wire_response(self) -> None:
        tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        env = _base_envelope(verb="read", environment="staging",
                             context={"traceparent": tp})
        status, resp = process(env)
        print(f"\n[T_wire_contract] status={status} resp={json.dumps(resp)}")

        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "allow")

        # decision_id IS part of the wire contract.
        self.assertIn("decision_id", resp)

        # envelope_hash / hold_id / parent_decision_id / traceparent are
        # audit + SIEM + hold-record enrichment ONLY -- never on the wire.
        for key in ("envelope_hash", "hold_id", "parent_decision_id", "traceparent"):
            self.assertNotIn(
                key, resp,
                f"'{key}' must NOT appear on the /v1/decide wire response "
                f"(audit/SIEM/hold-only field) -- got response: {resp}"
            )


# ===========================================================================
# TestFreezeCarriesDecisionId — REEFLEX_FREEZE=true frozen-deny path
# ===========================================================================

class TestFreezeCarriesDecisionId(unittest.TestCase):
    """decision_id must be present even on the freeze-operator deny path,
    which returns before OPA is ever consulted (no OPA dependency)."""

    def setUp(self) -> None:
        os.environ.pop("REEFLEX_FREEZE", None)
        import app.decide as decide_mod
        self._decide_mod = decide_mod
        decide_mod._last_freeze_state = None

        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_FREEZE", None)
        os.environ.pop("REEFLEX_AUDIT_LOG", None)
        self._decide_mod._last_freeze_state = None
        try:
            os.unlink(self._tmp_audit.name)
        except FileNotFoundError:
            pass

    def test_decision_id_present_on_frozen_deny(self) -> None:
        os.environ["REEFLEX_FREEZE"] = "true"
        env = _base_envelope(verb="delete", environment="staging")
        session_id = env["agent"]["session_id"]
        status, resp = process(env)

        print(f"\n[T_freeze/decision_id] status={status} resp={json.dumps(resp)}")
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertEqual(resp.get("rule"), "reeflex.policy/frozen")
        self.assertTrue(resp.get("decision_id"), "decision_id missing on frozen-deny response")

        rec = _last_audit_record_for(session_id)
        self.assertEqual(rec.get("decision_id"), resp.get("decision_id"))
        self.assertTrue(rec.get("envelope_hash"))


# ===========================================================================
# TestHoldMachineryFailClosed — decision_id present when holds.py itself
# raises (hold_creation_failed / hold_consume_failed fail-closed branches)
# ===========================================================================

class TestHoldMachineryFailClosed(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp_audit = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_audit_"
        )
        self._tmp_audit.close()
        os.unlink(self._tmp_audit.name)
        os.environ["REEFLEX_AUDIT_LOG"] = self._tmp_audit.name

        self._tmp_holds = tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, prefix="reeflex_trace_holds_"
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
    def test_decision_id_present_on_hold_creation_failed(self) -> None:
        """Monkeypatch holds.create_hold() to raise -- decide.py's Step 9
        except-branch (hold_creation_failed, fail-closed 500) must still
        carry decision_id in both the response and the audit record."""
        original_create_hold = holds_mod.create_hold

        def _raise_create_hold(*_a, **_kw):
            raise RuntimeError("synthetic create_hold failure for test")

        holds_mod.create_hold = _raise_create_hold
        try:
            env = _require_approval_env()
            session_id = env["agent"]["session_id"]
            status, resp = process(env)
        finally:
            holds_mod.create_hold = original_create_hold

        print(f"\n[T_fail_closed/hold_creation_failed] status={status} resp={json.dumps(resp)}")
        self.assertEqual(status, 500)
        self.assertEqual(resp.get("rule"), "reeflex.core/hold_creation_failed")
        self.assertTrue(resp.get("decision_id"), "decision_id missing on hold_creation_failed")

        rec = _last_audit_record_for(session_id)
        self.assertEqual(rec.get("decision_id"), resp.get("decision_id"))

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_decision_id_present_on_hold_consume_failed(self) -> None:
        """Monkeypatch holds.mark_consumed() to raise on a valid, approved
        resubmission -- decide.py's fail-closed 'reeflex_hold_consume_failed'
        deny must still carry decision_id in both response and audit."""
        env = _require_approval_env()
        _, resp1 = process(env)
        hold_id = resp1["hold_id"]
        holds_mod.resolve_hold(hold_id, "approve", "human", "supervisor:leo", "ok")

        original_mark_consumed = holds_mod.mark_consumed

        def _raise_mark_consumed(*_a, **_kw):
            raise RuntimeError("synthetic mark_consumed failure for test")

        holds_mod.mark_consumed = _raise_mark_consumed
        try:
            env_resub = dict(env)
            env_resub["meta"] = dict(env["meta"])
            env_resub["meta"]["nonce"] = uuid.uuid4().hex
            env_resub["approval"] = {"present": True, "hold_id": hold_id}
            session_id = env_resub["agent"]["session_id"]
            status, resp = process(env_resub)
        finally:
            holds_mod.mark_consumed = original_mark_consumed

        print(f"\n[T_fail_closed/hold_consume_failed] status={status} resp={json.dumps(resp)}")
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertEqual(resp.get("reason"), "reeflex_hold_consume_failed")
        self.assertTrue(resp.get("decision_id"), "decision_id missing on hold_consume_failed")

        rec = _last_audit_record_for(session_id)
        self.assertEqual(rec.get("decision_id"), resp.get("decision_id"))


if __name__ == "__main__":
    unittest.main()
