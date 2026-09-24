"""
The connector: LiteLLM's Generic Guardrail API, answered by the same decision.

WHAT THESE TESTS ARE EVIDENCE FOR, AND WHAT THEY ARE NOT
========================================================
They pin the CONNECTOR'S OWN behaviour: the translation between LiteLLM's
guardrail vocabulary and ours, the failure posture, and the one property that
makes this transport different from the in-process seat -- a refusal refuses the
whole response, because `GenericGuardrailAPIResponse` has no field through which
a modified tool-call list could come back.

They are not evidence that LiteLLM calls this endpoint, nor that a customer's
proxy is wired to it. That is measured against a real proxy and a real
`ghcr.io/berriai/litellm` image; the transcripts are in the round's evidence
directory and the numbers are in the doc.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from reeflex_litellm import connector

import stubcore


# ---------------------------------------------------------------------------
# Payload builders -- the wire shape, as litellm 1.101.0 sends it
# ---------------------------------------------------------------------------

def wire_tool_call(call_id="call_1", name="run_shell",
                   arguments=None):
    """One tool call in the shape `_convert_tool_call_to_dict()` produces."""
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(
                arguments if arguments is not None
                else {"command": "rm -rf /var/lib/pgsql"}),
        },
    }


def payload(tool_calls=None, *, input_type="response", texts=None,
            team_id="team_pay", key_alias="payments-bot",
            key_hash=None, model="mock-tools", **extra):
    """A `GenericGuardrailAPIRequest` body.

    The metadata keys are litellm's own, not ours:
    `GenericGuardrailAPIMetadata` has exactly the eight `user_api_key_*` fields
    and no others, and `user_api_key_hash` is the hashed token.
    """
    body = {
        "input_type": input_type,
        "litellm_call_id": "c1a2b3",
        "litellm_trace_id": "t9",
        "litellm_version": "1.101.0",
        "model": model,
        "texts": texts if texts is not None else ["Working on it."],
        "request_data": {
            "user_api_key_hash": key_hash,
            "user_api_key_alias": key_alias,
            "user_api_key_team_id": team_id,
        },
    }
    if tool_calls is not None:
        body["tool_calls"] = tool_calls
    body.update(extra)
    return body


def refusals_in(answer):
    """The structured refusals a client parses out of `blocked_reason`."""
    reason = answer.get("blocked_reason") or ""
    start = reason.find('{"reeflex"')
    assert start >= 0, "blocked_reason carries no structured payload: %r" % reason
    return json.loads(reason[start:])["reeflex"]["refused"]


# ---------------------------------------------------------------------------
# The decision: allow / deny
# ---------------------------------------------------------------------------

def test_an_allowed_tool_call_is_action_none(stub, tenancy_map):
    stub.answer_allow()
    answer = connector.decide_payload(
        payload([wire_tool_call(name="read_file",
                                arguments={"path": "/etc/hosts"})]),
        hold_wait=0.0)
    assert answer == {"action": connector.ACTION_NONE}
    assert len(stub.requests) == 1


def test_a_denied_tool_call_is_action_blocked_with_the_structured_refusal(
        stub, tenancy_map):
    stub.answer_deny()
    answer = connector.decide_payload(payload([wire_tool_call()]),
                                      hold_wait=0.0)
    assert answer["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(answer)
    assert refusal["error"] == "reeflex_denied"
    assert refusal["rule"] == "reeflex.policy/irreversible_systemic_prod"
    assert refusal["tool_call_id"] == "call_1"
    assert refusal["tool"] == "run_shell"


def test_the_refusal_says_refused_at_gateway_and_not_prevented(stub,
                                                               tenancy_map):
    """The claim this adapter is allowed to make about a gateway refusal.

    A gateway sees a tool call PROPOSED. Running the seat in its own container
    does not move it into the execution path, so the stage string is the same
    one the in-process seat emits, and it is part of the payload contract.
    """
    stub.answer_deny()
    answer = connector.decide_payload(payload([wire_tool_call()]),
                                      hold_wait=0.0)
    [refusal] = refusals_in(answer)
    assert refusal["stage"] == "refused_at_gateway"
    assert "prevented" not in json.dumps(answer).lower()


def test_one_denied_call_blocks_the_WHOLE_response(stub, tenancy_map):
    """THE difference between this transport and the in-process seat.

    `GenericGuardrailAPIResponse` (litellm 1.101.0) carries `action`,
    `blocked_reason`, `texts`, `images`, `tools`, `stream_holdback_chars` --
    and no `tool_calls`. `_build_guardrail_return_inputs()` copies back only
    texts/images/tools/stream_holdback_chars. So there is no field through
    which "keep call 1, drop call 2" could be expressed, and answering NONE
    while naming a refusal in the text would RELEASE the denied call.

    Stricter than the in-process seat, never weaker. If this test ever has to
    be relaxed, the doc's "what your agent sees" section has to change with it.
    """
    stub.decide_queue = [
        (200, {"decision": "allow", "reason": "ok",
               "rule": "reeflex.policy/read_only_internal",
               "decision_id": stubcore.DECISION_ID}),
        (200, {"decision": "deny", "reason": "no",
               "rule": "reeflex.policy/irreversible_systemic_prod",
               "decision_id": stubcore.DECISION_ID}),
    ]
    answer = connector.decide_payload(
        payload([wire_tool_call("call_1", "read_file", {"path": "/etc/hosts"}),
                 wire_tool_call("call_2")]),
        hold_wait=0.0)
    assert answer["action"] == connector.ACTION_BLOCKED
    refused = refusals_in(answer)
    assert [r["tool_call_id"] for r in refused] == ["call_2"]
    assert len(stub.requests) == 2, "both calls were decided, not just the first"


def test_a_response_with_no_tool_call_is_untouched_and_core_is_not_called(
        stub, tenancy_map):
    answer = connector.decide_payload(payload(None), hold_wait=0.0)
    assert answer == {"action": connector.ACTION_NONE}
    assert stub.requests == []


def test_prose_flows_even_from_a_caller_no_map_binds(stub):
    """No tenancy map at all, and a text answer still passes.

    Same rule as the in-process seat: this is an ACTION gate, not a text
    guardrail. A gateway that refused prose because a key is unmapped would be
    refusing the thing it does not rule on.
    """
    answer = connector.decide_payload(payload(None), hold_wait=0.0)
    assert answer == {"action": connector.ACTION_NONE}


# ---------------------------------------------------------------------------
# Tenancy
# ---------------------------------------------------------------------------

def test_an_unmapped_caller_is_blocked_and_core_is_never_asked(stub,
                                                               tenancy_map):
    answer = connector.decide_payload(
        payload([wire_tool_call()], team_id="team_nobody", key_alias=None),
        hold_wait=0.0)
    assert answer["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(answer)
    assert refusal["error"] == "reeflex_tenant_unmapped"
    assert stub.requests == [], "no decision may land in another org's evidence"


def test_the_team_id_on_the_generic_wire_resolves_the_org(stub, tenancy_map):
    stub.answer_allow()
    connector.decide_payload(
        payload([wire_tool_call()], team_id="team_mkt", key_alias=None),
        hold_wait=0.0)
    env = stub.requests[0]
    assert env["agent"]["id"] == "agent:litellm-gateway/acme-marketing/mock-tools"
    assert env["agent"]["session_id"].startswith("litellm:acme-marketing:")


def test_key_alias_beats_team_id_exactly_as_it_does_in_process(stub,
                                                               tenancy_map):
    stub.answer_allow()
    connector.decide_payload(
        payload([wire_tool_call()], team_id="team_mkt",
                key_alias="payments-bot"),
        hold_wait=0.0)
    assert (stub.requests[0]["agent"]["id"]
            == "agent:litellm-gateway/acme-payments/mock-tools")


def test_a_raw_credential_in_the_hash_field_is_not_recorded(stub, tenancy_map):
    """`user_api_key_hash` is a sha256 hex for a proxy-issued virtual key.

    A `custom_auth` deployment can put anything there. The shape test from
    `safe_key_hash()` still applies on this wire, so a raw `sk-` credential
    neither binds a tenant nor reaches a ledger row.
    """
    identity = connector._tenancy.read_identity_from_gateway_metadata(
        {"user_api_key_hash": "sk-live-not-a-digest",
         "user_api_key_team_id": "team_pay"})
    assert identity.key_hash is None
    assert identity.key_material_withheld is True
    assert "sk-live" not in identity.describe()
    assert "sk-live" not in json.dumps(identity.as_record())


# ---------------------------------------------------------------------------
# Holds
# ---------------------------------------------------------------------------

def test_a_hold_that_nobody_decides_blocks_and_names_the_hold(stub,
                                                              tenancy_map):
    stub.answer_hold(hold_id="hold-77")
    answer = connector.decide_payload(payload([wire_tool_call()]),
                                      hold_wait=0.0)
    assert answer["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(answer)
    assert refusal["hold_id"] == "hold-77"
    assert refusal["error"] in ("reeflex_hold_timeout", "reeflex_rejected")


def test_a_hold_approved_while_the_request_waits_answers_none(stub,
                                                              tenancy_map):
    """The whole point of holding an HTTP response open.

    The connector blocks its own HTTP response while a human decides; LiteLLM
    is simply waiting on a slow guardrail. How long it may wait before litellm's
    own read timeout fires is a measured number, and it is in the doc.
    """
    stub.decide_queue = [
        (200, {"decision": "require_approval", "reason": "needs a human",
               "rule": "reeflex.policy/irreversible_broad_prod",
               "obligations": [], "hold_id": "hold-88",
               "decision_id": stubcore.DECISION_ID}),
        (200, {"decision": "allow", "reason": "approved hold resubmission",
               "rule": "reeflex.policy/approved_resubmission",
               "obligations": [], "decision_id": stubcore.DECISION_ID}),
    ]
    stub.hold_status = "pending"
    threading.Timer(0.3, stub.approve).start()
    answer = connector.decide_payload(payload([wire_tool_call()]),
                                      hold_wait=5.0)
    assert answer == {"action": connector.ACTION_NONE}


# ---------------------------------------------------------------------------
# Failure posture
# ---------------------------------------------------------------------------

def test_core_unreachable_blocks_the_response(tenancy_map, monkeypatch):
    monkeypatch.setenv("REEFLEX_CORE_URL", "http://127.0.0.1:1")
    answer = connector.decide_payload(payload([wire_tool_call()]),
                                      hold_wait=0.0)
    assert answer["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(answer)
    assert refusal["rule"] == "reeflex.core/fail_closed"


def test_our_own_bug_blocks_in_the_BODY_and_not_with_a_5xx():
    """Why the status code is never 502/503/504, and not even 500 here.

    litellm classifies {502, 503, 504} as "unreachable", and that is the class
    `unreachable_fallback: fail_open` releases. A connector that signalled its
    own internal error with one of those codes would hand the release decision
    to a customer's config toggle. `fail_on_error: false` does the same for
    every other error status. So an internal failure is expressed as a 200 with
    `action: BLOCKED`, which no litellm setting can turn into a pass.
    """
    answer = connector.blocked_for_internal_error(RuntimeError("boom"))
    assert answer["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(answer)
    assert refusal["rule"] == "reeflex.core/fail_closed"
    assert refusal["stage"] == "refused_at_gateway"


def test_a_pre_call_request_rules_on_nothing_and_says_so(stub, tenancy_map):
    """`mode: pre_call` cannot see an action, and must not look governed.

    The answer is NONE -- blocking every request would be worse and would not
    be governance either -- but it is counted, so `/healthz` can tell an
    operator their guardrail is wired to a hook that rules on nothing.
    """
    before = connector.COUNTERS.as_dict()["pre_call_requests"]
    answer = connector.decide_payload(
        payload([wire_tool_call()], input_type="request"), hold_wait=0.0)
    assert answer == {"action": connector.ACTION_NONE}
    assert stub.requests == []
    assert connector.COUNTERS.as_dict()["pre_call_requests"] == before + 1


# ---------------------------------------------------------------------------
# The session a budget is charged against
# ---------------------------------------------------------------------------

def test_the_sanitised_header_placeholder_is_not_used_as_a_session():
    """litellm forwards "[present]" instead of the value of a header outside
    its allowlist. Using it would give every caller behind one proxy the same
    session id, and therefore one shared R5 cumulative budget."""
    got = connector.session_id(
        {"request_headers": {"x-reeflex-session": "[present]"},
         "litellm_call_id": "call-abc"})
    assert got == "call-abc"


def test_a_forwarded_session_header_value_is_used_when_it_arrives():
    got = connector.session_id(
        {"request_headers": {"X-Reeflex-Session": "nightly-batch"},
         "litellm_call_id": "call-abc"})
    assert got == "nightly-batch"


def test_extra_body_beats_every_other_session_source():
    got = connector.session_id({
        "additional_provider_specific_params": {"reeflex_session": "S-1"},
        "request_headers": {"x-reeflex-session": "hdr"},
        "request_data": {"user_api_key_end_user_id": "eu"},
        "litellm_call_id": "call-abc"})
    assert got == "S-1"


def test_the_openai_user_field_is_the_fallback_litellm_does_carry():
    got = connector.session_id(
        {"request_data": {"user_api_key_end_user_id": "alice"},
         "litellm_call_id": "call-abc"})
    assert got == "alice"


def test_two_orgs_sending_one_session_id_do_not_share_a_budget(stub,
                                                               tenancy_map):
    stub.answer_allow()
    for team in ("team_pay", "team_mkt"):
        connector.decide_payload(
            payload([wire_tool_call()], team_id=team, key_alias=None,
                    additional_provider_specific_params={
                        "reeflex_session": "nightly"}),
            hold_wait=0.0)
    ids = [r["agent"]["session_id"] for r in stub.requests]
    assert ids == ["litellm:acme-payments:nightly",
                   "litellm:acme-marketing:nightly"]


def test_ONE_org_renaming_its_session_gets_a_fresh_budget_namespace(
        stub, tenancy_map):
    """The complement of the test above, on THIS transport's own sources.

    `test_ONE_department_renaming_its_session_gets_a_fresh_budget_namespace`
    (RFX-243) pins this for the in-process seat, whose caller-reachable sources
    are the session header and the OpenAI `user` field. The connector has a
    different precedence, so the limit has to be pinned against the sources the
    connector actually reads or it is pinned on one transport only -- which is
    how the declaration ended up one file short in the first place.

    Two arms, because two different steps of the precedence are caller-
    reachable and a guard over one of them says nothing about the other:
    step 1, `reeflex_session` (which a caller can send through `extra_body`, as
    the docstring says in its own words), and step 3, `user_api_key_end_user_id`
    (litellm's home for the OpenAI `user` field).

    Both halves are pinned in each arm so neither can drift silently: the
    session segment follows the caller (the limit) and the org segment does not
    move (the guarantee that still holds).
    """
    stub.answer_allow()
    names = ("nightly", "nightly-2", "nightly-3")

    # Arm 1 -- step 1, the caller's `extra_body`.
    for name in names:
        connector.decide_payload(
            payload([wire_tool_call()], team_id="team_pay", key_alias=None,
                    additional_provider_specific_params={
                        "reeflex_session": name}),
            hold_wait=0.0)

    # Arm 2 -- step 3, the caller's OpenAI `user` field. `request_data` is
    # rebuilt rather than passed through `**extra`, which would REPLACE the
    # whole block and take `user_api_key_team_id` -- and therefore the tenant
    # this test is asserting about -- with it.
    for name in names:
        body = payload([wire_tool_call()], team_id="team_pay", key_alias=None)
        body["request_data"] = dict(body["request_data"],
                                    user_api_key_end_user_id=name)
        connector.decide_payload(body, hold_wait=0.0)

    ids = [r["agent"]["session_id"] for r in stub.requests]
    assert ids == ["litellm:acme-payments:nightly",
                   "litellm:acme-payments:nightly-2",
                   "litellm:acme-payments:nightly-3",
                   "litellm:acme-payments:nightly",
                   "litellm:acme-payments:nightly-2",
                   "litellm:acme-payments:nightly-3"]
    # The limit, per arm: three distinct budget namespaces from one key.
    assert len(set(ids[:3])) == 3
    assert len(set(ids[3:])) == 3
    # The guarantee that still holds: the org segment never moved, in either
    # arm, so the rotation cannot reach another department's budget.
    assert {s.split(":")[1] for s in ids} == {"acme-payments"}


# ---------------------------------------------------------------------------
# What the routing block can and cannot say on this transport
# ---------------------------------------------------------------------------

def test_the_routing_block_records_what_this_wire_carries_and_no_more(
        stub, tenancy_map):
    """An honest gap, recorded as a gap.

    The generic wire carries no `_hidden_params`, so `api_base`, the deployment
    id and the provider are not knowable here -- and `placement` is therefore
    `undeclared` rather than guessed. The in-process seat does carry them. That
    is a real difference in evidence completeness between the two paths and the
    doc states it.
    """
    stub.answer_allow()
    connector.decide_payload(payload([wire_tool_call()]), hold_wait=0.0)
    routing = stub.requests[0]["context"]["gateway_routing"]
    assert routing["transport"] == "generic_guardrail_api"
    assert routing["api_base_host"] is None
    assert routing["deployment_id"] is None
    assert routing["placement"] == "undeclared"
    assert routing["tenant"]["org"] == "acme-payments"


# ---------------------------------------------------------------------------
# The HTTP layer
# ---------------------------------------------------------------------------

@pytest.fixture
def server():
    srv = connector.build_server(host="127.0.0.1", port=0, token="t0ken")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def post(url, body, token="t0ken", path=connector.ENDPOINT_PATH):
    req = urllib.request.Request(
        url + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"x-api-key": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_the_endpoint_path_is_the_one_litellm_appends(server, stub,
                                                      tenancy_map):
    """`api_base` + `/beta/litellm_basic_guardrail_api`, appended by
    `GenericGuardrailAPI.__init__` when the configured base does not already
    end in it."""
    stub.answer_allow()
    status, body = post(server, payload([wire_tool_call()]))
    assert (status, body["action"]) == (200, connector.ACTION_NONE)


def test_any_other_path_is_a_404_and_not_a_decision(server):
    status, _ = post(server, {}, path="/decide")
    assert status == 404


def test_a_request_without_the_token_is_refused(server, stub, tenancy_map):
    stub.answer_allow()
    status, _ = post(server, payload([wire_tool_call()]), token=None)
    assert status == 401
    assert stub.requests == [], "an unauthenticated caller never reaches core"


def test_a_wrong_token_is_refused(server):
    status, _ = post(server, payload([wire_tool_call()]), token="not-it")
    assert status == 401


def test_the_server_never_answers_502_503_or_504(server, stub, tenancy_map):
    """Every status this server can produce, and none of them is the
    'unreachable' class litellm's fail_open releases on."""
    stub.answer_deny()
    seen = {post(server, payload([wire_tool_call()]))[0],
            post(server, {}, path="/nope")[0],
            post(server, payload([wire_tool_call()]), token="wrong")[0]}
    assert seen == {200, 404, 401}


def test_an_internal_error_in_the_HANDLER_blocks_over_real_HTTP(server,
                                                                monkeypatch):
    """The WIRING of the fail-closed posture, not the payload builder.

    `test_our_own_bug_blocks_in_the_BODY_and_not_with_a_5xx` calls
    `blocked_for_internal_error()` directly. That proves the payload this
    connector WOULD send; it never goes through `_Handler`, so it says nothing
    about whether the handler sends it. Measured (RFX-333, filed by qa--227,
    reproduced round dev-1--168 on `caf2cd6`): replacing the one line
    `answer = blocked_for_internal_error(exc)` with `{"action": ACTION_NONE}`
    releases a governed `rm -rf /var/lib/pgsql` over real HTTP and the whole
    suite still reports 399 passed, 2 skipped, exit 0 -- byte-identical to the
    control.

    The `except` branch is only reachable through the transport, so this test
    drives the running server with `decide_payload` raising. `rule` is asserted
    rather than just `action`, because tenancy and core-unreachable refusals are
    also 200 + BLOCKED and would satisfy a weaker assertion.
    """
    def raise_our_own_bug(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(connector, "decide_payload", raise_our_own_bug)

    status, body = post(server, payload([wire_tool_call()]))

    # Never 5xx: litellm classes {502, 503, 504} as "unreachable", and that is
    # the class `unreachable_fallback: fail_open` releases.
    assert status == 200
    assert body["action"] == connector.ACTION_BLOCKED
    [refusal] = refusals_in(body)
    assert refusal["rule"] == "reeflex.core/fail_closed"
    assert refusal["stage"] == "refused_at_gateway"


def test_a_body_larger_than_the_cap_is_413_not_a_decision(server):
    big = payload([wire_tool_call(arguments={"command": "x" * 200})])
    big["texts"] = ["y" * (connector.DEFAULT_MAX_BODY + 10)]
    status, _ = post(server, big)
    assert status == 413


def test_a_body_that_is_not_json_is_400(server):
    req = urllib.request.Request(
        server + connector.ENDPOINT_PATH, data=b"not json",
        headers={"Content-Type": "application/json", "x-api-key": "t0ken"})
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("expected 400")
    except urllib.error.HTTPError as e:
        assert e.code == 400


# --- the early-return paths, on a REUSED connection -------------------------
#
# Every test above opens a fresh connection per request, because that is what
# `urllib` does -- and that is exactly why they all passed while the 401 path
# was desynchronising the socket.  litellm's client is httpx, which POOLS
# connections, so the reused connection is the NORMAL case in production and
# the one-shot connection is the artificial one.

def _post_keepalive(url, bodies, token):
    """N POSTs down ONE connection; returns [(status, first 40 body bytes)]."""
    import http.client
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    out = []
    try:
        for body in bodies:
            raw = json.dumps(body).encode()
            conn.request("POST", connector.ENDPOINT_PATH, body=raw,
                         headers={"Content-Type": "application/json",
                                  "Content-Length": str(len(raw)),
                                  **({"x-api-key": token} if token else {})})
            resp = conn.getresponse()
            out.append((resp.status, resp.read()[:40]))
    finally:
        conn.close()
    return out


def test_a_rejected_request_does_not_desynchronise_a_pooled_connection(server):
    """RFX-326: three bad-token POSTs down one connection are three 401s.

    Before the fix the answer was 401, then 400 carrying
    `BaseHTTPRequestHandler`'s HTML error page -- the unread request body of
    request 1 being parsed as the request LINE of request 2 -- then 401 again
    as the parser resynchronised.  An operator who has set the wrong token, the
    likeliest first-run mistake, was shown a malformed-request error instead of
    the 401 that names the cause.
    """
    seen = _post_keepalive(server, [payload([wire_tool_call()])] * 3,
                           token="not-it")
    assert [s for s, _ in seen] == [401, 401, 401], seen
    assert not any(b.lstrip().startswith(b"<") for _, b in seen), \
        "an HTML error page means the request parser lostframing: %r" % (seen,)


def test_a_404_does_not_desynchronise_a_pooled_connection(server):
    """The same defect on the other early return that skips the body."""
    import http.client
    from urllib.parse import urlsplit
    parts = urlsplit(server)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        raw = json.dumps(payload([wire_tool_call()])).encode()
        for path, expected in (("/nope", 404), ("/nope", 404)):
            conn.request("POST", path, body=raw,
                         headers={"Content-Type": "application/json",
                                  "Content-Length": str(len(raw)),
                                  "x-api-key": "t0ken"})
            resp = conn.getresponse()
            got, body = resp.status, resp.read()
            assert got == expected, (path, got, body[:80])
            assert not body.lstrip().startswith(b"<"), body[:80]
    finally:
        conn.close()


def test_a_good_token_on_a_reused_connection_is_the_control(server, stub,
                                                            tenancy_map):
    """Without this, "three 401s" could be a server that answers 401 to
    everything.  Three GOVERNED decisions down one connection, all 200."""
    stub.answer_allow()
    seen = _post_keepalive(server, [payload([wire_tool_call()])] * 3,
                           token="t0ken")
    assert [s for s, _ in seen] == [200, 200, 200], seen
    assert len(stub.requests) == 3, "each request was really decided"


def test_healthz_answers_without_a_token_and_withholds_the_topology(server):
    with urllib.request.urlopen(server + "/healthz", timeout=10) as r:
        body = json.loads(r.read())
    assert body["status"] == "ok"
    assert body["service"] == "reeflex-connector"
    assert body["auth_required"] is True
    assert body["endpoint"] == connector.ENDPOINT_PATH
    assert "core_url" not in body
    assert "counters" not in body


def test_healthz_with_the_token_reports_the_counters_and_the_core_it_asks(
        server, tenancy_map):
    req = urllib.request.Request(server + "/healthz",
                                 headers={"x-api-key": "t0ken"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read())
    assert body["tenancy"] == {"loaded": True, "orgs": 2}
    assert "core_url" in body
    assert "pre_call_requests" in body["counters"]


# ---------------------------------------------------------------------------
# The answer shape, checked against litellm's own parser when it is installed
# ---------------------------------------------------------------------------

def test_the_answer_parses_as_litellms_own_response_model():
    """Asserts against the REAL parser, or skips loudly.

    A hand-written expectation of another project's schema is a guess; this
    runs `GenericGuardrailAPIResponse.from_dict` over our answers so the
    contract is pinned by the code that will actually read them.
    """
    try:
        from litellm.types.proxy.guardrails.guardrail_hooks.generic_guardrail_api import (  # noqa: E501
            GenericGuardrailAPIResponse)
    except Exception:  # pragma: no cover - litellm is an optional extra
        pytest.skip("litellm is not installed: install the `proxy` extra to "
                    "run the contract tests against litellm's own parser")

    allowed = GenericGuardrailAPIResponse.from_dict(
        {"action": connector.ACTION_NONE})
    assert allowed.action == "NONE"

    blocked = GenericGuardrailAPIResponse.from_dict(
        connector._blocked([{"error": "reeflex_denied", "rule": "r",
                             "reason": "because", "tool_call_id": "call_1",
                             "tool": "run_shell",
                             "stage": "refused_at_gateway"}]))
    assert blocked.action == "BLOCKED"
    assert "reeflex_denied" in blocked.blocked_reason
    # The fields litellm would copy back into the response. We set none of
    # them: `texts` is the assistant's prose and this seat does not rewrite
    # prose, and there is no tool-call field to set.
    assert blocked.texts is None and blocked.tools is None
