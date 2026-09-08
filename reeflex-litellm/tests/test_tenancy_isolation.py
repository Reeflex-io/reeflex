"""
THE ISOLATION PROOF (RFX-243): two departments behind one gateway.

WHAT IS BEING PROVED, AND WHERE EACH HALF IS ENFORCED
=====================================================
"Two keys' decisions land in two orgs and neither can read the other's holds"
is TWO mechanisms in two different codebases. Saying which is which is the
point of this docstring, because a test that blurs them would let the adapter
take credit for a database's work.

  1. THE ACTOR IDENTITY -- enforced HERE, in this adapter.
     `agent.id` and `agent.session_id` carry the tenant org. Core's hold check
     8 (RFX-138) compares the requester's agent block against the one the human
     approved, and R5's cumulative budget keys on `session_id`. So the org
     segment is what makes one department's approval unspendable by another's
     agent, and one department's budget unchargeable to another's session.
     This file measures those strings on the envelopes that actually reach
     core, from the stub's own request log.

  2. THE EVIDENCE ORG -- enforced by the SERVER, not by this adapter.
     EVIDENCE-INGEST-SPEC-v1 §3 resolves `(gate_id, org_id)` from the gate
     TOKEN, server-side, and §4 has no org field at all: "a record may not name
     a different org" because a record cannot name one. Postgres row-level
     security on `org_id` in **reeflex-app** is what keeps two orgs' evidence
     and holds apart once stored.

     So what this adapter can be held to is: it presents the RIGHT TENANT'S
     GATE TOKEN, and it never puts an org in the payload. Both are measured
     below, from a capture server that records the Authorization header.

WHAT THIS SUITE CANNOT SEE, STATED PLAINLY
==========================================
It does not exercise reeflex-app's RLS, and it does not exercise core's hold
check 8. Those live in those repos' suites. A green run here means this seat
presents two distinct credentials and two distinct actor identities -- it does
NOT by itself mean the server enforced separation. The end-to-end walk in the
round's report is where the two halves are joined.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from reeflex_litellm import enforce, evidence, guardrail, normalize, tenancy

import conftest
import stubcore


# ---------------------------------------------------------------------------
# A capture server for the evidence ingest
# ---------------------------------------------------------------------------

class IngestCapture:
    """Records what the adapter PRESENTS to an evidence gate.

    Deliberately records the Authorization header, because that -- not any
    field in the body -- is what selects the org server-side (§3).
    """

    def __init__(self):
        self.posts = []          # list of (authorization, timestamp, sig, body)
        self._lock = threading.Lock()
        self._server = None

    def start(self) -> str:
        cap = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                with cap._lock:
                    cap.posts.append({
                        "authorization": self.headers.get("Authorization"),
                        "timestamp": self.headers.get("X-Reeflex-Timestamp"),
                        "signature": self.headers.get("X-Reeflex-Signature"),
                        "raw": raw,
                        "records": json.loads(raw.decode("utf-8")) if raw else None,
                    })
                body = b'{"accepted":1,"rejected":0}'
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        host, port = self._server.server_address[:2]
        return "http://%s:%d/api/v1/evidence" % (host, port)

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


PAYMENTS_TOKEN = "rfx_gate_payments_TESTONLY"
MARKETING_TOKEN = "rfx_gate_marketing_TESTONLY"
PAYMENTS_KEY = "11" * 32          # 32 bytes hex -- §5's derived signing key
MARKETING_KEY = "22" * 32


@pytest.fixture
def two_gates(monkeypatch):
    """Both tenants pointed at one capture server, with per-tenant credentials.

    One URL on purpose: if the adapter got isolation right only because the two
    tenants had different hostnames, that would not be isolation. The ONLY
    thing distinguishing the two batches is the credential.
    """
    cap = IngestCapture()
    url = cap.start()
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["tenants"]["acme-payments"]["evidence"]["ingest_url"] = url
    raw["tenants"]["acme-marketing"]["evidence"]["ingest_url"] = url
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP", json.dumps(raw))
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_PAYMENTS", PAYMENTS_TOKEN)
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_PAYMENTS", PAYMENTS_KEY)
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_MARKETING", MARKETING_TOKEN)
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_MARKETING", MARKETING_KEY)
    monkeypatch.setenv("REEFLEX_LITELLM_EVIDENCE_PUSH", "true")
    tenancy.reset_cache()
    try:
        yield cap
    finally:
        cap.stop()
        tenancy.reset_cache()


def a_tool_call(name="run_shell", args=None, call_id="call_1"):
    return stubcore.tool_call(call_id, name,
                              args if args is not None
                              else {"command": "rm -rf ./build"})


def run_hook(caller_kwargs, response, model="mock-tools"):
    g = guardrail.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    return asyncio.run(g.async_post_call_success_hook(
        {"model": model}, conftest.caller(**caller_kwargs), response))


# ---------------------------------------------------------------------------
# 1. Two keys -> two orgs, in the identity that reaches core
# ---------------------------------------------------------------------------

def test_two_keys_send_two_different_orgs_to_core(stub, tenancy_map):
    """THE HEADLINE. The same tool call, from two virtual keys, produces two
    envelopes whose actor identity differs by org -- measured on the bodies
    core actually received, not on anything this adapter merely intended."""
    stub.answer_allow()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))

    assert len(stub.requests) == 2
    pay, mkt = stub.requests[0], stub.requests[1]

    assert pay["agent"]["id"] == "agent:litellm-gateway/acme-payments/mock-tools"
    assert mkt["agent"]["id"] == "agent:litellm-gateway/acme-marketing/mock-tools"
    assert pay["agent"]["id"] != mkt["agent"]["id"]
    assert pay["context"]["tenancy"]["org"] == "acme-payments"
    assert mkt["context"]["tenancy"]["org"] == "acme-marketing"


def test_two_departments_using_the_SAME_session_name_do_not_share_a_budget(
        stub, tenancy_map):
    """R5's cumulative budget keys on `agent.session_id`. Two teams that both
    call their nightly job `nightly` would otherwise spend one budget, and the
    first team's bulk run would deny the second team's."""
    stub.answer_allow()
    g = guardrail.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    for caller_kwargs in (conftest.PAYMENTS_CALLER, conftest.MARKETING_CALLER):
        asyncio.run(g.async_post_call_success_hook(
            {"model": "mock-tools", "user": "nightly"},
            conftest.caller(**caller_kwargs),
            stubcore.chat_response([a_tool_call()])))

    sessions = [r["agent"]["session_id"] for r in stub.requests]
    assert sessions == ["litellm:acme-payments:nightly",
                        "litellm:acme-marketing:nightly"]
    assert sessions[0] != sessions[1]


def test_the_tenants_declared_environment_reaches_the_decision(stub,
                                                               tenancy_map):
    """`environment` is an R2/R3 decision input. Payments declares production,
    marketing declares staging -- so the SAME action is priced against two
    different policy branches, which is the whole point of per-tenant config."""
    stub.answer_allow()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))
    assert stub.requests[0]["target"]["environment"] == "production"
    assert stub.requests[1]["target"]["environment"] == "staging"


def test_each_tenants_own_principal_is_named_not_a_proxy_wide_one(stub,
                                                                 tenancy_map):
    """`on_behalf_of` is who a human approver is told they are acting for. One
    proxy-wide principal would name the wrong person on a department's action."""
    stub.answer_allow()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))
    assert stub.requests[0]["agent"]["on_behalf_of"] == \
        "payments-oncall@acme.example"
    assert stub.requests[1]["agent"]["on_behalf_of"] == "growth@acme.example"


# ---------------------------------------------------------------------------
# 2. Holds: one department's approval is not the other's
# ---------------------------------------------------------------------------

def test_a_hold_raised_by_one_department_names_that_department_as_the_actor(
        stub, tenancy_map):
    """Core's hold check 8 (RFX-138) binds an approval to the agent block the
    human approved. This asserts the two departments arrive as two DIFFERENT
    parties, which is the precondition for that check to separate them.

    NOTE ON SCOPE: core's enforcement of check 8 is core's own test. What is
    measured here is that this adapter hands core two distinguishable actors
    for the identical tool call -- before RFX-243 it handed over one.
    """
    stub.answer_hold(hold_id="hold-pay")
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))

    holds_for = {r["agent"]["id"]: r for r in stub.requests}
    assert set(holds_for) == {
        "agent:litellm-gateway/acme-payments/mock-tools",
        "agent:litellm-gateway/acme-marketing/mock-tools"}


def test_the_marketing_agent_cannot_present_itself_as_the_payments_agent(
        tenancy_map):
    """The adapter gives the caller NO way to choose its own org: the org comes
    from `user_api_key_dict`, which litellm populates from its own
    authentication and the caller cannot set (see test_litellm_contract.py).

    Asserted at the envelope layer: a marketing key that ALSO sends every
    payments-looking hint a caller can control still resolves to marketing.
    """
    call = normalize.normalize_tool_call(a_tool_call())
    marketing = tenancy.resolve(conftest.caller(
        team_id="team_mkt",
        # Everything below is caller-influenced and none of it is a bind
        # dimension: end_user_id and org_id are recorded, never matched on.
        end_user_id="payments-oncall@acme.example",
        org_id="acme-payments",
        user_id="acme-payments")).tenant
    assert marketing.org == "acme-marketing"

    env = enforce._envelope.build_gateway_envelope(
        session_id="s", model="m", call=call, tenant=marketing)
    assert env["agent"]["id"] == "agent:litellm-gateway/acme-marketing/m"
    assert "acme-payments" not in env["agent"]["id"]
    assert "acme-payments" not in env["agent"]["session_id"]


# ---------------------------------------------------------------------------
# 3. The evidence gate: two orgs means two CREDENTIALS, not two payload fields
# ---------------------------------------------------------------------------

def test_two_departments_evidence_is_signed_with_two_different_gate_tokens(
        stub, two_gates):
    """WHERE THE EVIDENCE ISOLATION ACTUALLY LIVES.

    §3 resolves `(gate_id, org_id)` from the token server-side. So presenting
    the correct per-tenant token IS the adapter's whole obligation, and getting
    it wrong is how one department's decisions would land in another's org --
    silently, because the payload has no org field to contradict it.
    """
    stub.answer_deny()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))

    assert len(two_gates.posts) == 2, "expected one batch per tenant"
    auths = [p["authorization"] for p in two_gates.posts]
    assert auths == ["Bearer %s" % PAYMENTS_TOKEN,
                     "Bearer %s" % MARKETING_TOKEN]
    assert auths[0] != auths[1]


def test_each_batch_is_signed_with_that_tenants_own_signing_key(stub,
                                                                two_gates):
    """A batch signed with the wrong tenant's key would be REJECTED by the
    gate (§5), so a credential mix-up must not be able to look successful.
    Verified by recomputing the HMAC with the tenant's key over the exact bytes
    that were sent."""
    stub.answer_deny()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))

    for post, key_hex in ((two_gates.posts[0], PAYMENTS_KEY),
                          (two_gates.posts[1], MARKETING_KEY)):
        expected = evidence.sign(post["raw"], int(post["timestamp"]),
                                 bytes.fromhex(key_hex))
        assert post["signature"] == "hmac-sha256=%s" % expected

    # And the control: the OTHER tenant's key does not verify the same bytes.
    wrong = evidence.sign(two_gates.posts[0]["raw"],
                          int(two_gates.posts[0]["timestamp"]),
                          bytes.fromhex(MARKETING_KEY))
    assert two_gates.posts[0]["signature"] != "hmac-sha256=%s" % wrong


def test_no_evidence_record_carries_an_org_FIELD(stub, two_gates):
    """§4 has no org field, and that is the design: a client that could name an
    org could name someone else's. This asserts the adapter does not smuggle
    one in -- so the server's `(gate_id, org_id)` resolution is the only source
    of truth, and reeflex-app's RLS on `org_id` has nothing to contradict.

    THE ORG STRING DOES TRAVEL, AND ONLY IN ONE PLACE: inside `agent_id`
    (`agent:litellm-gateway/<org>/<model>`), which IS a §4 field and is an
    actor LABEL, not a tenancy assertion -- the server does not read it to
    decide where the record is stored. That is deliberate: it is the one
    adapter-controlled field that reaches an Attest report, so a report row
    sourced from this seat can say which department acted. Pinned here so the
    distinction between "a label" and "a claim about storage" stays explicit.
    """
    stub.answer_deny()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))

    for record in two_gates.posts[0]["records"]:
        for key in ("org", "org_id", "tenant", "tenancy", "gateway_routing"):
            assert key not in record, (
                "%r reached the §4 wire; the server would answer 422" % key)
        # The org appears in the payload ONLY as part of agent_id.
        leaked = [k for k, v in record.items()
                  if k != "agent_id" and "acme-payments" in json.dumps(v)]
        assert leaked == [], (
            "the org name reached §4 field(s) %s -- the record now asserts a "
            "tenancy the server is supposed to derive from the token" % leaked)
        assert record["agent_id"] == \
            "agent:litellm-gateway/acme-payments/mock-tools"


def test_a_tenant_with_no_evidence_credentials_pushes_nothing_and_still_enforces(
        stub, monkeypatch, tmp_path):
    """An operator who has not registered a gate yet must still get ENFORCEMENT.
    Evidence is a record of a decision, not a precondition for making one --
    the opposite ordering would let an unregistered gate silently allow."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    del raw["tenants"]["acme-payments"]["evidence"]
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP", json.dumps(raw))
    monkeypatch.setenv("REEFLEX_LITELLM_EVIDENCE_PUSH", "true")
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("REEFLEX_LITELLM_LEDGER_PATH", str(ledger))
    tenancy.reset_cache()

    stub.answer_deny()
    out = run_hook(conftest.PAYMENTS_CALLER,
                   stubcore.chat_response([a_tool_call()]))

    from reeflex_litellm import response as R
    assert R.refused_payloads(out)[0]["error"] == "reeflex_denied"
    # The local ledger still has the record, so the decision is not lost.
    lines = [json.loads(l) for l in
             ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    assert lines[0]["enforcement_stage"] == "refused_at_gateway"


def test_one_tenants_ledger_lines_all_name_that_tenant(stub, monkeypatch,
                                                       tmp_path, tenancy_map):
    """The adapter's own ledger DOES carry the org (it is local, and §4's
    closed schema does not apply to it). Two departments writing to one ledger
    file must still be separable by an operator reading it."""
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("REEFLEX_LITELLM_LEDGER_PATH", str(ledger))
    stub.answer_deny()
    run_hook(conftest.PAYMENTS_CALLER, stubcore.chat_response([a_tool_call()]))
    run_hook(conftest.MARKETING_CALLER, stubcore.chat_response([a_tool_call()]))

    lines = [json.loads(l) for l in
             ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert [l["tenant_org"] for l in lines] == ["acme-payments",
                                                "acme-marketing"]
    assert lines[0]["gateway_routing"]["tenant"]["org"] == "acme-payments"
    assert lines[1]["gateway_routing"]["tenant"]["org"] == "acme-marketing"


# ---------------------------------------------------------------------------
# 4. The unmapped caller, end to end through the hook
# ---------------------------------------------------------------------------

def test_an_unmapped_key_is_refused_and_core_is_never_called(stub, tenancy_map):
    """Fail-closed, and the `stub.requests == []` half is the load-bearing one:
    a refusal that still reached core would already have charged a budget and
    written an audit line under whichever org the envelope named."""
    stub.answer_allow()
    out = run_hook({"team_id": "team_nobody", "key_alias": "rogue"},
                   stubcore.chat_response([a_tool_call()]))

    from reeflex_litellm import response as R
    payloads = R.refused_payloads(out)
    assert payloads[0]["error"] == "reeflex_tenant_unmapped"
    assert payloads[0]["stage"] == "refused_at_gateway"
    assert stub.requests == []


def test_an_unmapped_key_still_gets_its_PROSE_answer(stub, tenancy_map):
    """A gateway that refused plain text from an unmapped key would be a text
    guardrail, and this seat rules on ACTIONS. Tenancy is not even resolved for
    a response with no tool calls."""
    stub.answer_allow()
    resp = stubcore.chat_response([], content="here is a summary")
    out = run_hook({"team_id": "team_nobody"}, resp)
    assert out["choices"][0]["message"]["content"] == "here is a summary"
    assert stub.requests == []


def test_every_call_on_a_multi_call_response_is_refused_for_an_unmapped_key(
        stub, tenancy_map):
    """Not just the first one. A partial refusal would release the rest."""
    stub.answer_allow()
    resp = stubcore.chat_response([
        a_tool_call(call_id="c1"),
        a_tool_call(name="read_file", args={"path": "/etc/hosts"},
                    call_id="c2"),
    ])
    out = run_hook({"team_id": "team_nobody"}, resp)

    from reeflex_litellm import response as R
    payloads = R.refused_payloads(out)
    assert len(payloads) == 2
    assert {p["error"] for p in payloads} == {"reeflex_tenant_unmapped"}
    assert out["choices"][0]["message"]["tool_calls"] in (None, [])
    assert stub.requests == []
