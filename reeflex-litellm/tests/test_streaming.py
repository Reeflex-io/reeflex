"""
THE streaming test: a denied tool call is not in ANY chunk the caller receives.

Driven through the guardrail's OWN streaming hook --
`async_post_call_streaming_iterator_hook`, the async generator LiteLLM's proxy
iterates -- fed the chunk sequence a provider actually sends, and asserted on
the CHUNKS THAT CAME OUT.  Not on the internal Outcome objects, for the reason
`test_denied_never_reaches_caller.py` gives at the top: an adapter that computes
a perfect refusal and then yields the original chunks would satisfy every other
assertion in this file.

WHAT THIS FILE CANNOT SEE, AND WHAT COVERS IT
=============================================
It drives the hook directly, so it does not measure that LiteLLM will ever CALL
it (`test_litellm_contract.py` does, off the installed litellm's own capability
detection) and it does not read a socket, so it cannot see a chunk that is
correct as an object and wrong once serialized (`proxy/stream_walk.py` does,
against a real proxy, on the raw SSE bytes).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from reeflex_litellm import core, streaming as S
from reeflex_litellm.guardrail import ReeflexActionGuardrail

import stubcore
from conftest import PAYMENTS_CALLER, caller


@pytest.fixture(autouse=True)
def _mapped(tenancy_map):
    yield


# ---------------------------------------------------------------------------
# The chunk sequence a provider actually sends.
#
# Built here rather than imported from the mock model so that the SPLIT POINTS
# are an input to the test: `arguments` is fragmented at an arbitrary index, and
# the dangerous half of a command is usually in the last fragment.  A test that
# only ever saw whole arguments would pass against an adapter that ruled on the
# first fragment.
# ---------------------------------------------------------------------------

def frame(delta, finish=None, cid="chatcmpl-1"):
    return {"id": cid, "object": "chat.completion.chunk", "created": 1,
            "model": "mock-tools",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}


def tool_frames(index, call_id, name, arguments, pieces=3):
    """One tool call, its `arguments` split across `pieces` frames."""
    out = [frame({"tool_calls": [{"index": index, "id": call_id,
                                  "type": "function",
                                  "function": {"name": name,
                                               "arguments": ""}}]})]
    step = max(len(arguments) // pieces, 1)
    cuts = [arguments[i:i + step] for i in range(0, len(arguments), step)]
    for piece in cuts:
        out.append(frame({"tool_calls": [
            {"index": index, "function": {"arguments": piece}}]}))
    return out


def stream_of(*calls, prose=None):
    """role frame, optional prose, the tool frames, the finish frame."""
    chunks = [frame({"role": "assistant", "content": None})]
    if prose:
        chunks.append(frame({"content": prose}))
    for i, (call_id, name, args) in enumerate(calls):
        chunks.extend(tool_frames(i, call_id, name, json.dumps(args)))
    chunks.append(frame({}, "tool_calls" if calls else "stop"))
    return chunks


async def _aiter(chunks):
    for c in chunks:
        yield c


def drive(chunks, data=None, key=None, **kw):
    """Run the streaming hook over `chunks`; return the list it yielded."""
    kw.setdefault("reeflex_hold_wait", 0.0)
    g = ReeflexActionGuardrail(**kw)

    async def go():
        out = []
        async for c in g.async_post_call_streaming_iterator_hook(
                user_api_key_dict=(caller(**PAYMENTS_CALLER) if key is None
                                   else key),
                response=_aiter(chunks),
                request_data=(data if data is not None
                              else {"model": "mock-tools", "stream": True,
                                    "litellm_call_id": "req-1"})):
            out.append(c)
        return out

    return asyncio.run(go())


def assembled(chunks):
    """The tool calls a compliant client assembles from these chunks."""
    slots, order = {}, []
    for c in chunks:
        for choice in c.get("choices") or []:
            for e in (choice.get("delta") or {}).get("tool_calls") or []:
                i = e.get("index", 0)
                if i not in slots:
                    slots[i] = {"id": None, "name": None, "arguments": ""}
                    order.append(i)
                slots[i]["id"] = slots[i]["id"] or e.get("id")
                fn = e.get("function") or {}
                slots[i]["name"] = slots[i]["name"] or fn.get("name")
                slots[i]["arguments"] += fn.get("arguments") or ""
    return [slots[i] for i in order]


def content_of(chunks):
    return "".join(
        (choice.get("delta") or {}).get("content") or ""
        for c in chunks for choice in c.get("choices") or [])


def refusals_of(chunks):
    out = []
    for line in content_of(chunks).splitlines():
        if not line.strip().startswith("{"):
            continue
        block = (json.loads(line) or {}).get("reeflex") or {}
        out.extend(block.get("refused") or [])
    return out


def finishes(chunks):
    return [c["finish_reason"] for ch in chunks
            for c in ch.get("choices") or [] if c.get("finish_reason")]


DESTRUCTIVE = ("call_1", "run_shell", {"command": "rm -rf /"})
BENIGN = ("call_2", "read_file", {"path": "/etc/hosts"})


# ---------------------------------------------------------------------------
# THE assertion
# ---------------------------------------------------------------------------

def test_a_denied_call_is_in_no_chunk_the_caller_receives(stub):
    stub.answer_deny()

    out = drive(stream_of(DESTRUCTIVE))

    wire = json.dumps(out, sort_keys=True)
    assert "rm -rf /" not in wire, (
        "the denied command is in a chunk the caller receives: %s" % wire)
    assert assembled(out) == [], (
        "a client assembling these chunks still gets a tool call: %r"
        % (assembled(out),))
    assert refusals_of(out)[0]["error"] == "reeflex_denied"
    assert refusals_of(out)[0]["stage"] == "refused_at_gateway"
    assert finishes(out) == ["stop"], (
        "every call was refused, so the response is no longer asking the "
        "client to call tools: %r" % (finishes(out),))


def test_not_one_fragment_of_a_denied_argument_escapes(stub):
    """The half-argument case, which is the whole difficulty of this path.

    The command is split across many frames.  An adapter that released frames
    as they arrived and only decided at the end would have leaked all but the
    last -- and `"rm -rf /" not in wire` would still PASS, because no single
    fragment contains the whole string.

    So the measurement is the TOTAL of every `function.arguments` fragment in
    every yielded chunk.  It has to be empty, at every split point.  (A
    substring scan was tried first and was void: a four-character fragment like
    `{"co` also occurs in the JSON key `"choices"`, so the test failed on a
    build that was correct.)
    """
    stub.answer_deny()
    args = json.dumps({"command": "rm -rf /"})

    for pieces in range(1, len(args) + 1):
        stub.answer_deny()
        chunks = ([frame({"role": "assistant", "content": None})]
                  + tool_frames(0, "call_1", "run_shell", args, pieces=pieces)
                  + [frame({}, "tool_calls")])

        out = drive(chunks)

        escaped = "".join(
            (e.get("function") or {}).get("arguments") or ""
            for c in out for choice in c.get("choices") or []
            for e in (choice.get("delta") or {}).get("tool_calls") or [])
        assert escaped == "", (
            "split into %d pieces, %r of the denied arguments reached the "
            "caller" % (pieces, escaped))


def test_an_allowed_call_is_yielded_as_the_very_same_objects(stub):
    """Identity, not equality.

    A rewrite that produced an equal-looking copy would be indistinguishable
    from a pass-through by `==` and would still be a rewrite -- and a caller
    that had already read `_hidden_params` off the original object would be
    reading something else.  `is` is the assertion that says the seat did
    nothing.
    """
    stub.answer_allow()
    chunks = stream_of(BENIGN)

    out = drive(chunks)

    assert [id(c) for c in out] == [id(c) for c in chunks]
    assert assembled(out) == [{"id": "call_2", "name": "read_file",
                               "arguments": '{"path": "/etc/hosts"}'}]
    assert refusals_of(out) == []


def test_a_response_with_no_tool_call_never_reaches_core(stub):
    stub.answer_deny()  # would refuse if it were ever asked
    chunks = stream_of(prose="Here is some prose and no action.")

    out = drive(chunks)

    assert [id(c) for c in out] == [id(c) for c in chunks]
    assert stub.requests == [], (
        "core was called for a response carrying no action: %r" % stub.requests)


def test_prose_is_yielded_before_the_decision_is_taken(stub):
    """Text does not wait behind a governance round trip.

    Asserted by consuming the generator one item at a time and checking that
    the prose frame arrives while core has not yet been called.  A test that
    collected the whole list first could not tell an immediate yield from a
    yield at the end.
    """
    stub.answer_deny()
    chunks = stream_of(DESTRUCTIVE, prose="thinking out loud")

    g = ReeflexActionGuardrail(reeflex_hold_wait=0.0)

    async def go():
        seen = []
        gen = g.async_post_call_streaming_iterator_hook(
            user_api_key_dict=caller(**PAYMENTS_CALLER),
            response=_aiter(chunks),
            request_data={"model": "mock-tools", "stream": True})
        async for c in gen:
            seen.append(c)
            if content_of([c]) == "thinking out loud":
                # The decision has not been taken at this point...
                assert stub.requests == []
                break
        await gen.aclose()
        return seen

    seen = asyncio.run(go())
    assert content_of(seen) == "thinking out loud"


def test_the_refusal_goes_on_a_new_line_after_prose_that_already_streamed(stub):
    """Parity with response.apply_refusals(), which appends after existing text.

    The prose has ALREADY left the gateway by the time the refusal is written,
    so the newline has to be decided from what was released, not from what is
    in the buffer.
    """
    stub.answer_deny()

    out = drive(stream_of(DESTRUCTIVE, prose="here you go"))

    assert content_of(out).startswith("here you go\n{")
    assert refusals_of(out)[0]["error"] == "reeflex_denied"


def test_one_denied_and_one_allowed_call_on_the_same_response(stub):
    stub.decide_queue = [
        (200, {"decision": "deny", "reason": "no", "obligations": [],
               "rule": "reeflex.policy/irreversible_systemic_prod",
               "decision_id": stubcore.DECISION_ID}),
        (200, {"decision": "allow", "reason": "ok", "obligations": [],
               "rule": "reeflex.policy/read_only_internal",
               "decision_id": stubcore.DECISION_ID}),
    ]

    out = drive(stream_of(DESTRUCTIVE, BENIGN))

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert assembled(out) == [{"id": "call_2", "name": "read_file",
                               "arguments": '{"path": "/etc/hosts"}'}]
    assert [r["tool"] for r in refusals_of(out)] == ["run_shell"]
    assert finishes(out) == ["tool_calls"], (
        "one call survived, so the client still has a tool to call: %r"
        % (finishes(out),))


def test_core_unreachable_fails_closed_on_the_streaming_path(stub, monkeypatch):
    monkeypatch.setenv("REEFLEX_CORE_URL",
                       "http://127.0.0.1:%d" % stubcore.unused_port())

    out = drive(stream_of(DESTRUCTIVE))

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert refusals_of(out)[0]["error"] == "reeflex_unavailable"
    assert refusals_of(out)[0]["rule"] == core.FAIL_CLOSED_RULE


def test_an_unmapped_caller_is_refused_before_core_is_asked(stub):
    out = drive(stream_of(DESTRUCTIVE), key=caller(team_id="team_nobody"))

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert refusals_of(out)[0]["error"] == "reeflex_tenant_unmapped"
    assert stub.requests == [], (
        "a caller with no org reached core anyway: %r" % stub.requests)


def test_a_hold_withholds_the_chunks_and_a_rejection_refuses_them(stub):
    stub.answer_hold()
    stub.hold_status = "rejected"

    out = drive(stream_of(DESTRUCTIVE), reeflex_hold_wait=1.0)

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert refusals_of(out)[0]["error"] == "reeflex_rejected"
    assert refusals_of(out)[0]["hold_id"] == "hold-1"


def test_a_hold_approved_by_a_human_releases_the_chunks(stub):
    """The RELEASE path, with the approval arriving while the hook waits.

    `hold_status` is flipped from a timer thread, so the hook really does poll
    a hold that was pending when it started -- a test that pre-set "approved"
    would never exercise the wait at all.
    """
    import threading

    stub.answer_hold()
    stub.hold_status = "pending"

    def approve():
        stub.hold_status = "approved"
        # The resubmission with the approval attached must come back ALLOW;
        # core, not the hold status, is what releases the call.
        stub.answer_allow()

    t = threading.Timer(0.4, approve)
    t.start()
    try:
        out = drive(stream_of(("call_9", "acme_deployer", {"target": "prod"})),
                    reeflex_hold_wait=15.0)
    finally:
        t.cancel()

    assert refusals_of(out) == [], (
        "the approved call was refused anyway: %r" % refusals_of(out))
    assert assembled(out) == [{"id": "call_9", "name": "acme_deployer",
                               "arguments": '{"target": "prod"}'}]
    assert finishes(out) == ["tool_calls"]
    # WITHOUT THESE TWO THE TEST IS VACUOUS.  "The call came out" is also what
    # a gateway with no seat at all produces, so the assertions above pass on
    # the pre-fix build.  What distinguishes a RELEASE from a pass-through is
    # that core was asked twice -- the decision that raised the hold, and the
    # resubmission carrying the approval -- and that the second one carried it.
    assert len(stub.requests) == 2, (
        "a release is two calls to core; saw %d" % len(stub.requests))
    assert stub.requests[0]["approval"]["present"] is False
    assert stub.requests[1]["approval"] == {
        "present": True, "hold_id": "hold-1", "by": None, "role": None}
    assert (stub.requests[1]["meta"]["nonce"]
            != stub.requests[0]["meta"]["nonce"]), (
        "the resubmission reused the spent nonce and core would 400 it")


def test_the_streamed_and_the_buffered_path_produce_the_same_refusal(stub):
    """Path parity: the same action, decided twice, must read the same.

    This is the assertion that would go red if the streaming path grew its own
    refusal vocabulary -- which is how an evidence pipeline ends up with two
    names for one thing.
    """
    from reeflex_litellm import response as R

    stub.answer_deny()
    streamed = refusals_of(drive(stream_of(DESTRUCTIVE)))

    stub.answer_deny()
    g = ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    buffered_response = asyncio.run(g.async_post_call_success_hook(
        {"model": "mock-tools"}, caller(**PAYMENTS_CALLER),
        stubcore.chat_response([stubcore.tool_call(
            "call_1", "run_shell", {"command": "rm -rf /"})])))
    buffered = R.refused_payloads(buffered_response)

    assert streamed == buffered, (
        "streamed %s\nbuffered %s" % (json.dumps(streamed, sort_keys=True),
                                      json.dumps(buffered, sort_keys=True)))


def test_a_bug_in_the_hook_refuses_rather_than_releasing(stub, monkeypatch):
    """Fail closed on OUR OWN failure, not just on core's.

    `_emit_stream` is broken deliberately.  The buffered fragments must not be
    handed over just because the code that was supposed to rule on them threw.
    """
    stub.answer_allow()

    def boom(*_a, **_k):
        raise RuntimeError("deliberate")

    monkeypatch.setattr(ReeflexActionGuardrail, "_rule_on_stream", boom)

    out = drive(stream_of(DESTRUCTIVE))

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert refusals_of(out)[0]["error"] == "reeflex_unavailable"
    assert refusals_of(out)[0]["rule"] == core.FAIL_CLOSED_RULE


def test_the_client_hanging_up_is_not_swallowed(stub):
    """GeneratorExit must propagate, and no buffered fragment may be yielded.

    A hook that caught the disconnect and "finished the job" would keep the
    proxy's event loop busy on a request nobody is listening to -- and would do
    it holding chunks it had not ruled on.
    """
    stub.answer_allow()

    async def go():
        g = ReeflexActionGuardrail(reeflex_hold_wait=0.0)
        gen = g.async_post_call_streaming_iterator_hook(
            user_api_key_dict=caller(**PAYMENTS_CALLER),
            response=_aiter(stream_of(DESTRUCTIVE)),
            request_data={"model": "mock-tools", "stream": True})
        first = await gen.__anext__()      # the role frame
        await gen.aclose()                 # the client goes away
        return first

    first = asyncio.run(go())
    assert content_of([first]) == ""
    assert stub.requests == [], (
        "core was asked about a request the caller had already abandoned")


# ---------------------------------------------------------------------------
# streaming.py on its own -- the assembly, without a decision anywhere near it
# ---------------------------------------------------------------------------

def test_the_accumulator_rebuilds_arguments_split_at_any_point():
    args = json.dumps({"command": "rm -rf /var/lib/data", "sudo": True})
    for pieces in range(1, len(args) + 1):
        acc = S.ToolCallAccumulator()
        for chunk in tool_frames(0, "call_1", "run_shell", args, pieces=pieces):
            acc.feed(chunk)
        (_, call), = acc.assembled()
        assert call["function"]["arguments"] == args, (
            "split into %d pieces, reassembled as %r" % (pieces,
                                                         call["function"]["arguments"]))
        assert call["function"]["name"] == "run_shell"
        assert call["id"] == "call_1"


def test_the_accumulator_keeps_arrival_order_not_numeric_order():
    acc = S.ToolCallAccumulator()
    for chunk in tool_frames(7, "call_b", "b_tool", "{}"):
        acc.feed(chunk)
    for chunk in tool_frames(1, "call_a", "a_tool", "{}"):
        acc.feed(chunk)
    assert [i for i, _ in acc.assembled()] == [7, 1]


def test_a_call_whose_id_never_arrived_still_gets_one():
    """A refusal keyed on an empty tool_call_id is not a usable refusal."""
    acc = S.ToolCallAccumulator()
    acc.feed(frame({"tool_calls": [
        {"index": 0, "function": {"name": "run_shell", "arguments": "{}"}}]}))
    (_, call), = acc.assembled()
    assert call["id"] == "stream_tool_call_0"


def test_a_chunk_with_no_readable_tool_call_is_a_pass_through():
    for odd in (b"keep-alive", "a bare string", {"no": "choices"}, None,
                {"choices": [{"delta": {"content": "hi"}}]}):
        assert S.chunk_tool_indices(odd) == set(), repr(odd)


def test_stripping_leaves_an_allowed_fragment_in_a_mixed_chunk():
    mixed = frame({"tool_calls": [
        {"index": 0, "function": {"arguments": "A"}},
        {"index": 1, "function": {"arguments": "B"}}]})

    out, carries = S.strip_tool_indices(mixed, {0})

    assert carries is True
    assert S.chunk_tool_indices(out) == {1}
    assert S.chunk_tool_indices(mixed) == {0, 1}, "the original was mutated"


def test_a_chunk_that_only_carried_refused_fragments_is_dropped():
    only = frame({"tool_calls": [{"index": 0, "function": {"arguments": "A"}}]})
    _, carries = S.strip_tool_indices(only, {0})
    assert carries is False


def test_a_refusal_chunk_borrows_the_stream_s_identity():
    template = frame({"tool_calls": [{"index": 0,
                                      "function": {"arguments": "x"}}]},
                     "tool_calls", cid="chatcmpl-abc")
    template["usage"] = {"total_tokens": 9}

    out = S.build_refusal_chunk(template, "NOTICE")

    assert out["id"] == "chatcmpl-abc"
    assert out["choices"][0]["delta"]["content"] == "NOTICE"
    assert out["choices"][0]["delta"]["tool_calls"] is None
    assert out["choices"][0]["finish_reason"] is None
    assert out["usage"] is None, (
        "a synthesized frame added a second usage block to the stream")


def test_a_chunk_the_accumulator_cannot_read_drops_the_whole_tail(stub,
                                                                  monkeypatch):
    """The fail-open this path exists to prevent.

    If `feed()` throws, the call that chunk belonged to may not be in the
    assembled list at all -- so its index is in no `denied` set, and a rewrite
    that only strips what it was told to strip would RELEASE its fragments.
    The tail is dropped instead, and the client is told the response ended.
    """
    stub.answer_allow()

    def boom(self, chunk):
        raise RuntimeError("unreadable chunk")

    monkeypatch.setattr(S.ToolCallAccumulator, "feed", boom)

    out = drive(stream_of(DESTRUCTIVE))

    assert "rm -rf /" not in json.dumps(out, sort_keys=True)
    assert assembled(out) == []
    assert refusals_of(out)[0]["error"] == "reeflex_unavailable"
    assert finishes(out) == ["stop"], (
        "the tail was dropped without ending the stream: %r" % (finishes(out),))
    assert stub.requests == [], (
        "core was asked about calls the adapter could not even read")
