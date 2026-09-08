"""
test_holds_push.py -- the seat ASKS a human, it does not merely record that it
did.

WHAT THIS FILE IS FOR
=====================
`POST /api/v1/evidence` stores `hold.hold_id` on an evidence row.  It does NOT
create a `pending_holds` row, and `pending_holds` is what the approval inbox
reads and what the Approve control hangs off.  Measured 2026-09-08 inside the
deployed `reeflex-app:main-dbfe954` container: `PendingHold(` is constructed in
exactly one place in that codebase and it is the `/api/v1/holds` handler.

So before this ticket, a `require_approval` at the gateway produced: a hold in
core, an evidence row saying a human was asked, a wait of up to
`reeflex_hold_wait` seconds, and NO HUMAN ANYWHERE WHO COULD ANSWER.  The
timeout that followed was indistinguishable, in every record, from a human who
had looked and declined to decide.

The tests below pin four things, and each of them is a thing that would
otherwise be easy to break without any test going red:

  1. the payload matches holds-v1's CLOSED allowlist, and a field this package
     grows later cannot reach the wire by accident;
  2. the announcement happens BEFORE the wait, not after enforcement like
     every other record this package writes -- an announcement after the wait
     is a question asked after hanging up;
  3. it never raises and never changes a verdict, at the default (off) and on
     every failure path;
  4. its outcome is RECORDED, because "a human was asked" and "the inbox was
     unreachable" must not read the same in a report.

MUTATION CONTROLS.  Four tests here are written as A/B pairs against a
deliberately broken variant, because "the field is absent" and "the call was
not made" both pass trivially on a no-op.  Each is marked `CONTROL:`.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import stubcore
from conftest import PAYMENTS_CALLER, caller

from reeflex_litellm import enforce, evidence, normalize, tenancy

# The gate credentials the tenancy map REFERENCES BY NAME. Repeated-byte hex,
# 32 bytes, obviously synthetic: the point of the map's by-reference rule is
# that a real value never lands in a file like this one.
GATE_TOKEN = "rfx_gate_TESTONLY_not_a_real_token"
SIGNING_KEY_HEX = "ab" * 32


class StubGate:
    """A stand-in for reeflex-app's `/api/v1/holds` route.

    Records the full request -- headers included -- because the thing under
    test is partly WHICH CREDENTIAL signed the batch, and that is only visible
    in the headers.
    """

    def __init__(self, status=200, body=None):
        self.status = status
        self.body = body if body is not None else {"stored": 1, "duplicates": 0}
        self.calls = []
        self._lock = threading.Lock()
        self._server = None

    def start(self) -> str:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                with gate._lock:
                    gate.calls.append({
                        "path": self.path,
                        "raw": raw,
                        "authorization": self.headers.get("Authorization"),
                        "timestamp": self.headers.get("X-Reeflex-Timestamp"),
                        "signature": self.headers.get("X-Reeflex-Signature"),
                        "at": time.monotonic(),
                    })
                    status, body = gate.status, gate.body
                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        host, port = self._server.server_address[:2]
        return "http://%s:%d" % (host, port)

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


@pytest.fixture
def gate():
    g = StubGate()
    g.url = g.start()
    try:
        yield g
    finally:
        g.stop()


@pytest.fixture
def holds_tenant(monkeypatch, install_map, gate):
    """A one-tenant map whose `holds_url` points at the stub gate."""
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_PAYMENTS", GATE_TOKEN)
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_PAYMENTS", SIGNING_KEY_HEX)
    raw = {
        "version": 1,
        "tenants": {"acme-payments": {
            "org": "acme-payments",
            "environment": "production",
            "evidence": {
                "ingest_url": gate.url + "/api/v1/evidence",
                "holds_url": gate.url + "/api/v1/holds",
                "gate_token_env": "RFX_TEST_GATE_TOKEN_PAYMENTS",
                "signing_key_env": "RFX_TEST_SIGNING_KEY_PAYMENTS",
            }}},
        "bind": {"team_id": {"team_pay": "acme-payments"},
                 "key_alias": {"payments-bot": "acme-payments"}},
    }
    install_map(raw)
    return tenancy.resolve(caller(**PAYMENTS_CALLER)).tenant


def a_call():
    return normalize.normalize_tool_call(stubcore.tool_call(
        "call_1", "run_shell", {"command": 'psql -c "DROP TABLE customers"'}))


def rule_it(tenant, hold_wait=0.0):
    return enforce.rule_one_call(
        a_call(), session_id="s1", model="mock-tools", tenant=tenant,
        hold_wait=hold_wait, gateway_routing={"gateway": "litellm"})


# ---------------------------------------------------------------------------
# 1. the payload, against holds-v1's closed allowlist
# ---------------------------------------------------------------------------

def _minimal_kwargs(**over):
    kw = dict(hold_id="h1", decision_id="d" * 32, verb="delete",
              target_environment="production",
              rule="reeflex.policy/irreversible_broad_prod",
              envelope_hash="e" * 64, created_ts="2026-09-08T08:00:00Z")
    kw.update(over)
    return kw


def test_hold_record_carries_only_holds_v1_fields():
    rec = evidence.hold_record(**_minimal_kwargs(
        target_system="litellm-gateway", magnitude_count=1,
        agent_id="agent:litellm-gateway/acme-payments/mock-tools",
        reason="Reeflex: irreversible broad change [rule=...]",
        expires_ts="2026-09-08T12:00:00Z"))
    assert set(rec) <= evidence.HOLD_TOP_LEVEL_FIELDS
    # Every required field present, and `sig_alg` set by us per §5.
    for f in evidence.HOLD_REQUIRED_FIELDS:
        assert rec[f]
    assert rec["sig_alg"] == evidence.SIG_ALG_V1


@pytest.mark.parametrize("missing", evidence.HOLD_REQUIRED_FIELDS)
def test_hold_record_refuses_to_build_without_a_required_field(missing):
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.hold_record(**_minimal_kwargs(**{missing: ""}))
    assert missing in str(exc.value)


def test_hold_record_drops_a_bad_magnitude_rather_than_sending_it():
    # The server 422s the WHOLE BATCH on a bad field, which would take other
    # actions' holds out of a human's inbox. An unusable optional value is
    # therefore omitted, not forwarded.
    for bad in (-1, True, "1", 1.5, None):
        rec = evidence.hold_record(**_minimal_kwargs(magnitude_count=bad))
        assert "magnitude_count" not in rec, bad
    assert evidence.hold_record(
        **_minimal_kwargs(magnitude_count=0))["magnitude_count"] == 0


def test_CONTROL_an_unknown_key_is_refused_before_the_request():
    """CONTROL: the allowlist has to REJECT something, or it proves nothing.

    `gateway_routing` is the exact field this package would most plausibly
    grow onto this wire, and holds-v1 has no home for it.
    """
    rec = evidence.hold_record(**_minimal_kwargs())
    rec["gateway_routing"] = {"model": "mock-tools"}
    with pytest.raises(evidence.EvidenceConfigError) as exc:
        evidence.assert_hold_is_spec_clean(rec)
    assert "gateway_routing" in str(exc.value)
    assert "closed" in str(exc.value)


def test_a_ledger_line_projects_onto_a_clean_hold_record(holds_tenant, stub):
    stub.answer_hold(hold_id="h-777")
    out = rule_it(holds_tenant)
    rec = evidence.hold_record_from_ledger(out.ledger, hold_id="h-777")
    assert set(rec) <= evidence.HOLD_TOP_LEVEL_FIELDS
    assert rec["hold_id"] == "h-777"
    assert rec["target_environment"] == "production"
    assert rec["agent_id"].endswith("/acme-payments/mock-tools")


# ---------------------------------------------------------------------------
# 2. WHEN the announcement happens -- the load-bearing property
# ---------------------------------------------------------------------------

def test_the_hold_is_announced_BEFORE_the_wait_for_an_answer(
        holds_tenant, stub, gate, monkeypatch):
    """The whole point. Announcing after the wait is asking after hanging up.

    Measured on the clock, not argued: the stub gate stamps `time.monotonic()`
    when the push arrives, and `await_hold` is wrapped to stamp when the wait
    began. `wait_seconds=1.0` so the two stamps cannot collide inside the
    timer's resolution.
    """
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-order")
    waited_at = []
    real = enforce._core.await_hold

    def timed(hold_id, wait_seconds=None, **kw):
        waited_at.append(time.monotonic())
        return real(hold_id, wait_seconds=wait_seconds, **kw)

    monkeypatch.setattr(enforce._core, "await_hold", timed)
    out = rule_it(holds_tenant, hold_wait=1.0)

    assert out.hold_announced == evidence.ANNOUNCE_SENT
    assert waited_at, "await_hold was never called -- the test is vacuous"
    assert len(gate.calls) == 1, "no push reached the inbox at all"
    assert gate.calls[0]["at"] < waited_at[0], (
        "the hold reached the inbox at %.6f but the seat had already started "
        "waiting for an answer at %.6f" % (gate.calls[0]["at"], waited_at[0]))


def test_CONTROL_the_wait_still_happens_when_nothing_is_announced(
        holds_tenant, stub, gate, monkeypatch):
    """CONTROL for the ordering test above.

    The ordering test compares two timestamps; if the push were absent it
    would fail on `len(gate.calls) == 1` rather than on the ordering, and if
    the WAIT were absent it would fail on `waited_at`. This test pins that the
    wait happens INDEPENDENTLY of the announcement -- switch off, still
    exactly one wait, still zero pushes -- so the ordering the other test
    measures is produced by the announcement and by nothing else.
    """
    # switch deliberately NOT set
    stub.answer_hold(hold_id="h-order-control")
    waits = []
    real = enforce._core.await_hold
    monkeypatch.setattr(
        enforce._core, "await_hold",
        lambda hold_id, wait_seconds=None, **kw: (
            waits.append(1) or real(hold_id, wait_seconds=wait_seconds, **kw)))
    out = rule_it(holds_tenant, hold_wait=1.0)
    assert len(waits) == 1
    assert gate.calls == []
    assert out.hold_announced == evidence.ANNOUNCE_OFF


# ---------------------------------------------------------------------------
# 3. never raises, never changes a verdict
# ---------------------------------------------------------------------------

def test_default_is_off_and_off_means_no_network_call(holds_tenant, stub, gate):
    """The default must not start writing into somebody's approval queue."""
    stub.answer_hold(hold_id="h-off")
    out = rule_it(holds_tenant)
    assert out.hold_announced == evidence.ANNOUNCE_OFF
    assert gate.calls == [], "a push was made with the switch off"
    assert out.allowed is False
    assert out.refusal["error"] == enforce.ERROR_HOLD_TIMEOUT
    # and the caller is TOLD that nobody was asked
    assert "no approval inbox is configured" in out.refusal["reason"]


@pytest.mark.parametrize("status", [422, 401, 500, 503])
def test_a_failing_inbox_never_changes_the_verdict(holds_tenant, stub, gate,
                                                   monkeypatch, status):
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    gate.status = status
    gate.body = {"detail": "no"}
    stub.answer_hold(hold_id="h-fail")
    out = rule_it(holds_tenant)
    assert out.hold_announced == evidence.ANNOUNCE_FAILED
    # Same outcome as with no inbox at all: refused, hold named, nothing
    # consumed. An inbox outage must not become a governance outage.
    assert out.allowed is False
    assert out.refusal["error"] == enforce.ERROR_HOLD_TIMEOUT
    assert out.refusal["hold_id"] == "h-fail"
    assert "could NOT be delivered" in out.refusal["reason"]


def test_an_unreachable_inbox_never_raises(holds_tenant, stub, monkeypatch,
                                           install_map):
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_PAYMENTS", GATE_TOKEN)
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_PAYMENTS", SIGNING_KEY_HEX)
    dead = "http://127.0.0.1:%d/api/v1/holds" % stubcore.unused_port()
    install_map({
        "version": 1,
        "tenants": {"acme-payments": {
            "org": "acme-payments", "environment": "production",
            "evidence": {"ingest_url": dead, "holds_url": dead,
                         "gate_token_env": "RFX_TEST_GATE_TOKEN_PAYMENTS",
                         "signing_key_env": "RFX_TEST_SIGNING_KEY_PAYMENTS"}}},
        "bind": {"key_alias": {"payments-bot": "acme-payments"}},
    })
    tenant = tenancy.resolve(caller(key_alias="payments-bot")).tenant
    stub.answer_hold(hold_id="h-dead")
    out = rule_it(tenant)
    assert out.hold_announced == evidence.ANNOUNCE_FAILED
    assert out.allowed is False


def test_a_tenant_with_no_holds_url_fails_loudly_not_silently(
        holds_tenant, stub, monkeypatch, install_map):
    """A silent skip here means a human is never asked. It must be named."""
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_PAYMENTS", GATE_TOKEN)
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_PAYMENTS", SIGNING_KEY_HEX)
    install_map({
        "version": 1,
        "tenants": {"acme-payments": {
            "org": "acme-payments", "environment": "production",
            "evidence": {"ingest_url": "https://app.invalid/api/v1/evidence",
                         "gate_token_env": "RFX_TEST_GATE_TOKEN_PAYMENTS",
                         "signing_key_env": "RFX_TEST_SIGNING_KEY_PAYMENTS"}}},
        "bind": {"key_alias": {"payments-bot": "acme-payments"}},
    })
    tenant = tenancy.resolve(caller(key_alias="payments-bot")).tenant
    result = evidence.push_holds([evidence.hold_record(**_minimal_kwargs())],
                                 tenant)
    assert result.ok is False
    assert "evidence.holds_url" in (result.error or "")


def test_an_allow_and_a_deny_announce_nothing(holds_tenant, stub, gate,
                                              monkeypatch):
    """Only a hold asks a human. Nothing else may touch the inbox."""
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_allow()
    out = rule_it(holds_tenant)
    assert out.allowed is True
    assert out.hold_announced is None
    stub.answer_deny()
    out = rule_it(holds_tenant)
    assert out.allowed is False
    assert out.hold_announced is None
    assert gate.calls == []


# ---------------------------------------------------------------------------
# 4. what was sent, and what was NOT
# ---------------------------------------------------------------------------

def test_the_batch_is_signed_with_the_tenants_own_credentials(
        holds_tenant, stub, gate, monkeypatch):
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-signed")
    rule_it(holds_tenant)
    assert len(gate.calls) == 1
    call = gate.calls[0]
    assert call["path"] == "/api/v1/holds"
    assert call["authorization"] == "Bearer %s" % GATE_TOKEN
    # §5: HMAC-SHA256 over "<ts>.\n" + the canonical body, and the signature
    # is recomputed here rather than trusted.
    ts = int(call["timestamp"])
    assert abs(ts - int(time.time())) < 300
    expected = evidence.sign(call["raw"], ts, bytes.fromhex(SIGNING_KEY_HEX))
    assert call["signature"] == "%s=%s" % (evidence.SIG_ALG_V1, expected)
    body = json.loads(call["raw"].decode("utf-8"))
    assert isinstance(body, list) and len(body) == 1
    assert set(body[0]) <= evidence.HOLD_TOP_LEVEL_FIELDS


def test_no_prompt_no_arguments_no_credential_on_the_holds_wire(
        holds_tenant, stub, gate, monkeypatch):
    """The inbox row says WHAT was held, not what the model was talking about.

    The tool arguments are a decision input and they stay in the envelope core
    holds. They are not sent to the approval inbox, and neither is any
    credential material -- including the gate token, which travels in a header
    and must not also be echoed into the body.
    """
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-clean")
    rule_it(holds_tenant)
    raw = gate.calls[0]["raw"].decode("utf-8")
    for forbidden in ("DROP TABLE", "psql", "command",
                      GATE_TOKEN, SIGNING_KEY_HEX):
        assert forbidden not in raw, forbidden


def test_the_ledger_records_whether_a_human_was_actually_asked(
        holds_tenant, stub, gate, monkeypatch):
    """`hold_announced` is the field that stops a report over-reading a hold.

    A report that counts holds as Art.14 human oversight must be able to tell
    a hold somebody was shown from a hold nobody was told about.
    """
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-ledger")
    out = rule_it(holds_tenant)
    assert out.ledger["hold_announced"] == evidence.ANNOUNCE_SENT

    gate.status = 500
    out = rule_it(holds_tenant)
    assert out.ledger["hold_announced"] == evidence.ANNOUNCE_FAILED

    monkeypatch.delenv("REEFLEX_LITELLM_HOLDS_PUSH")
    out = rule_it(holds_tenant)
    assert out.ledger["hold_announced"] == evidence.ANNOUNCE_OFF

    stub.answer_allow()
    out = rule_it(holds_tenant)
    assert out.ledger["hold_announced"] is None


def test_the_announced_hold_names_the_same_hold_core_raised(
        holds_tenant, stub, gate, monkeypatch):
    """The join key. A row in the inbox that names a different hold than the
    one core is holding is worse than no row: a human would approve something
    that releases nothing."""
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-join-key")
    out = rule_it(holds_tenant)
    sent = json.loads(gate.calls[0]["raw"].decode("utf-8"))[0]
    assert sent["hold_id"] == "h-join-key" == out.hold_id
    assert sent["envelope_hash"] == out.ledger["envelope_hash"]
    assert sent["decision_id"] == out.ledger["decision_id"]


def test_expires_ts_is_forwarded_when_core_supplies_one_and_omitted_otherwise(
        holds_tenant, stub, gate, monkeypatch):
    monkeypatch.setenv("REEFLEX_LITELLM_HOLDS_PUSH", "true")
    stub.answer_hold(hold_id="h-exp")   # the stub sets expires_ts
    rule_it(holds_tenant)
    sent = json.loads(gate.calls[0]["raw"].decode("utf-8"))[0]
    assert sent["expires_ts"] == "2026-09-08T12:00:00Z"

    # A core that does not emit one: the field is ABSENT, not derived from a
    # local TTL. The app leaves a deadline-less hold open, which is the right
    # handling of "unknown" -- but inventing a deadline here would put a
    # fabricated expiry in front of a human.
    gate.calls.clear()
    stub.decide_default = (200, {"decision": "require_approval",
                                 "reason": "needs a human",
                                 "rule": "reeflex.policy/irreversible_broad_prod",
                                 "hold_id": "h-noexp",
                                 "decision_id": stubcore.DECISION_ID})
    rule_it(holds_tenant)
    sent = json.loads(gate.calls[0]["raw"].decode("utf-8"))[0]
    assert "expires_ts" not in sent
