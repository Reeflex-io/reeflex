"""
Assertions about LITELLM'S contract, not about this package.

These only mean something with `litellm` installed, which is the `proxy` extra
and NOT what the repo gate installs (see pyproject.toml for why).  So they skip
when it is absent -- and the FIRST thing each one asserts is that the base class
in play is litellm's real `CustomGuardrail`, never the stand-in
`reeflex_litellm.guardrail` falls back to.  Without that assertion a green run
here could mean "the shim passed", which is exactly the kind of instrument error
that makes a suite worthless.

Run them with:  pip install -e '.[proxy]' && pytest tests/test_litellm_contract.py
"""

from __future__ import annotations

import asyncio
import inspect
import json

import pytest

litellm = pytest.importorskip(
    "litellm", reason="litellm is the `proxy` extra; install it to exercise "
                      "the gateway contract (`pip install -e '.[proxy]'`)")

from reeflex_litellm import guardrail as G  # noqa: E402
from reeflex_litellm import response as R  # noqa: E402
from reeflex_litellm import tenancy as T  # noqa: E402

import stubcore  # noqa: E402


def real_caller(via_virtual_key=True, **kw):
    """A REAL `UserAPIKeyAuth`, populated the way the PROXY populates it.

    The rest of the suite uses a plain dict (conftest.caller) so it can run
    without litellm. This builds the genuine pydantic model, which is the only
    way to know `tenancy._get()` reads the real object and not just a Mapping
    that happens to share its field names.

    `via_virtual_key` MUST be assigned after construction, not passed in:
    litellm declares it `exclude=True` and its model validator POPS it from
    validated input, precisely so a custom auth handler or a JWT claim cannot
    forge it. Passing it to the constructor silently yields False -- which is
    how the first version of this helper made every key_hash lookup miss.
    See test_the_proxy_strips_a_forged_via_virtual_key_from_caller_input.
    """
    from litellm.proxy._types import UserAPIKeyAuth
    kw.setdefault("api_key", "x" * 64)  # a sha256-shaped hashed token
    obj = UserAPIKeyAuth(**kw)
    obj.via_virtual_key = via_virtual_key
    return obj


def test_the_class_under_test_subclasses_litellms_real_custom_guardrail():
    from litellm.integrations.custom_guardrail import CustomGuardrail
    assert G.LITELLM_AVAILABLE is True
    assert issubclass(G.ReeflexActionGuardrail, CustomGuardrail)
    assert G._Base is CustomGuardrail


def test_the_hook_signature_is_the_one_the_proxy_awaits():
    """litellm/proxy/utils.py calls
    `callback.async_post_call_success_hook(user_api_key_dict=..., data=...,
    response=...)` by KEYWORD. A positional-only signature would never be
    called, and nothing would fail loudly."""
    sig = inspect.signature(
        G.ReeflexActionGuardrail.async_post_call_success_hook)
    assert {"data", "user_api_key_dict", "response"} <= set(sig.parameters)
    assert inspect.iscoroutinefunction(
        G.ReeflexActionGuardrail.async_post_call_success_hook)


def test_the_class_does_NOT_define_apply_guardrail():
    """The proxy routes a guardrail that defines `apply_guardrail` through its
    unified text-scanning wrapper instead of calling the hook directly
    (`if "apply_guardrail" in type(callback).__dict__`). This seat rules on
    actions, so it must stay on the direct path."""
    assert "apply_guardrail" not in G.ReeflexActionGuardrail.__dict__


def test_the_guardrail_is_instantiable_the_way_the_registry_does_it():
    """`initialize_custom_guardrail()` calls the class with guardrail_name=,
    event_hook=<mode>, default_on= AND every remaining litellm_params key. A
    signature that rejects an unexpected kwarg fails at proxy STARTUP."""
    from litellm.types.guardrails import GuardrailEventHooks
    g = G.ReeflexActionGuardrail(
        guardrail_name="reeflex-action-gate",
        event_hook=GuardrailEventHooks.post_call.value,
        default_on=True,
        reeflex_hold_wait=0,
        # a key the registry might pass through that this class never asked for
        api_base=None,
    )
    assert g.guardrail_name == "reeflex-action-gate"


def test_a_real_model_response_object_is_mutable_by_the_rewrite(stub, tenancy_map):
    """The rewrite sets attributes on the response object. If litellm's pydantic
    models refused assignment, every dict-shaped test would still pass and the
    proxy would return the denied call."""
    from litellm.types.utils import (ChatCompletionMessageToolCall, Choices,
                                     Function, Message, ModelResponse)

    tc = ChatCompletionMessageToolCall(
        id="call_1", type="function",
        function=Function(name="run_shell",
                          arguments=json.dumps({"command": "rm -rf /"})))
    resp = ModelResponse(
        id="chatcmpl-1", model="mock-tools", object="chat.completion",
        choices=[Choices(index=0, finish_reason="tool_calls",
                         message=Message(role="assistant", content=None,
                                         tool_calls=[tc]))])

    assert R.has_tool_calls(resp) is True
    stub.answer_deny()

    g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    out = asyncio.run(g.async_post_call_success_hook(
        {"model": "mock-tools", "litellm_call_id": "req-1"},
        real_caller(team_id="team_pay"), resp))

    assert out.choices[0].message.tool_calls in (None, [])
    assert out.choices[0].finish_reason == "stop"
    assert "rm -rf /" not in out.model_dump_json()
    # `reeflex_denied`, NOT `reeflex_tenant_unmapped`: this asserts the call
    # reached core and was refused on POLICY. Without the distinction a tenancy
    # misconfiguration would look like a working guardrail.
    assert R.refused_payloads(out)[0]["error"] == "reeflex_denied"


def test_a_real_model_response_with_an_allowed_call_is_untouched(stub, tenancy_map):
    """The control for the row above."""
    from litellm.types.utils import (ChatCompletionMessageToolCall, Choices,
                                     Function, Message, ModelResponse)

    tc = ChatCompletionMessageToolCall(
        id="call_1", type="function",
        function=Function(name="read_file",
                          arguments=json.dumps({"path": "/etc/hosts"})))
    resp = ModelResponse(
        id="chatcmpl-1", model="mock-tools", object="chat.completion",
        choices=[Choices(index=0, finish_reason="tool_calls",
                         message=Message(role="assistant", content=None,
                                         tool_calls=[tc]))])
    stub.answer_allow()

    g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    out = asyncio.run(g.async_post_call_success_hook(
        {"model": "mock-tools"}, real_caller(team_id="team_pay"), resp))

    assert len(out.choices[0].message.tool_calls) == 1
    assert out.choices[0].message.tool_calls[0].function.name == "read_file"
    assert out.choices[0].finish_reason == "tool_calls"
    assert R.refused_payloads(out) == []


def test_post_call_is_a_mode_litellm_recognises():
    from litellm.types.guardrails import GuardrailEventHooks
    assert "post_call" in [e.value for e in GuardrailEventHooks]


# -- tenancy: the fields this adapter reads are litellm's, not ours (RFX-243) --

def test_every_field_tenancy_reads_exists_on_the_real_user_api_key_auth():
    """tenancy.read_identity() reads ten named attributes off the proxy's auth
    result. If litellm renamed one, `_get()` would return None, the identity
    would go unrecognised and EVERY call behind that key would be refused --
    a total outage that no dict-based test could ever see, because the dict
    double would still have the old name."""
    from litellm.proxy._types import UserAPIKeyAuth
    fields = set(UserAPIKeyAuth.model_fields)
    for name in ("api_key", "token", "key_alias", "team_id", "team_alias",
                 "org_id", "organization_alias", "user_id", "end_user_id",
                 "via_virtual_key"):
        assert name in fields, (
            "litellm's UserAPIKeyAuth no longer has %r -- tenancy.read_identity"
            " would silently read None for it" % name)


def test_the_master_key_alias_constant_matches_litellms_own():
    """tenancy.MASTER_KEY_ALIAS is hardcoded so the module imports without
    litellm. This is the pin that makes the copy safe: a rename upstream turns
    every master-key request into an unrecognised identity, and this goes red
    instead."""
    from litellm.constants import LITELLM_PROXY_MASTER_KEY_ALIAS
    assert T.MASTER_KEY_ALIAS == LITELLM_PROXY_MASTER_KEY_ALIAS


def test_the_dict_double_the_rest_of_the_suite_uses_agrees_with_the_real_model():
    """conftest.caller() is a dict stand-in for UserAPIKeyAuth. If it drifted,
    every tenancy test would be exercising a shape the proxy never sends.
    Asserted by resolving BOTH through the same code path and comparing the
    identity that comes out."""
    import conftest
    real = real_caller(team_id="team_pay", key_alias="payments-bot",
                       api_key="b" * 64)
    fake = conftest.caller(team_id="team_pay", key_alias="payments-bot",
                           api_key="b" * 64)
    assert T.read_identity(real).as_record() == T.read_identity(fake).as_record()


def test_the_proxy_strips_a_forged_via_virtual_key_from_caller_input():
    """WHY tenancy.safe_key_hash() may trust this marker at all.

    `via_virtual_key` is the precondition for recording a key identifier. It is
    only trustworthy because litellm declares it `exclude=True` and POPS it in
    a model validator, so a custom auth handler, a JWT claim or a key-metadata
    splat cannot set it -- only the proxy's own DB virtual-key / master-key auth
    paths do, by post-construction assignment.

    If a litellm release ever accepted it as validated input, a caller could
    forge it, and this adapter would record a key identifier it has no reason
    to believe. That is a tenancy-binding forgery, so it is pinned here.
    """
    from litellm.proxy._types import UserAPIKeyAuth
    forged = UserAPIKeyAuth(api_key="c" * 64, via_virtual_key=True)
    assert forged.via_virtual_key is False, (
        "litellm now accepts via_virtual_key as caller input -- a forged value "
        "would make tenancy.safe_key_hash() trust an unvalidated credential")
    assert T.read_identity(forged).key_hash is None
    assert T.read_identity(forged).key_material_withheld is True


def test_the_real_model_never_carries_a_raw_credential_in_api_key():
    """A defence-in-depth reading of litellm's own validator: a raw `sk-` key
    passed as validated input is hashed to 64 hex before the object exists, so
    `api_key` is not raw credential material on this path. tenancy.py still
    shape-tests it, because a custom_auth handler assigning the attribute AFTER
    construction bypasses the validator entirely -- the check is cheap and the
    failure mode (a live credential in an evidence ledger) outlives the request.
    """
    from litellm.proxy._types import UserAPIKeyAuth
    obj = UserAPIKeyAuth(api_key="sk-a-real-looking-secret-value")
    assert obj.api_key != "sk-a-real-looking-secret-value"
    assert T._SHA256_HEX.match(obj.api_key)


def test_a_hashed_virtual_key_from_litellms_own_hasher_matches_the_map_dimension():
    """The map's `key_hash` dimension must hold exactly what litellm's
    `hash_token()` produces, and `tenancy.digest()` is what the CLI tells an
    operator to compute. If the two disagree every key_hash binding silently
    matches nothing and falls through to the team (or to a refusal)."""
    from litellm.proxy.utils import hash_token
    assert T.digest("sk-operator-key-1") == hash_token(token="sk-operator-key-1")


def test_an_unmapped_real_caller_is_refused_through_the_real_objects(stub,
                                                                    tenancy_map):
    """THE FAIL-CLOSED DEFAULT, through litellm's genuine types.

    A key the proxy authenticated but the tenancy map does not bind gets every
    tool call removed and replaced with `reeflex_tenant_unmapped` -- and core is
    never called, so nothing lands in another department's evidence. The
    `stub.requests == []` assertion is the load-bearing half: a refusal that
    still POSTed to core would have already charged an R5 budget and written an
    audit line under some org.
    """
    from litellm.types.utils import (ChatCompletionMessageToolCall, Choices,
                                     Function, Message, ModelResponse)
    tc = ChatCompletionMessageToolCall(
        id="call_1", type="function",
        function=Function(name="read_file",
                          arguments=json.dumps({"path": "/etc/hosts"})))
    resp = ModelResponse(
        id="chatcmpl-1", model="mock-tools", object="chat.completion",
        choices=[Choices(index=0, finish_reason="tool_calls",
                         message=Message(role="assistant", content=None,
                                         tool_calls=[tc]))])
    stub.answer_allow()  # core WOULD allow -- the refusal is tenancy's alone

    g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    out = asyncio.run(g.async_post_call_success_hook(
        {"model": "mock-tools"}, real_caller(team_id="team_nobody_bound"), resp))

    assert out.choices[0].message.tool_calls in (None, [])
    payload = R.refused_payloads(out)[0]
    assert payload["error"] == "reeflex_tenant_unmapped"
    assert payload["rule"] == "reeflex.litellm/tenancy_unmapped"
    assert stub.requests == [], (
        "core was called for a caller with no org: the decision has already "
        "been recorded somewhere by the time we refused")


def test_a_missing_auth_object_is_refused_not_defaulted(stub, tenancy_map):
    """`user_api_key_dict=None` is what an unauthenticated or oddly-configured
    proxy hands the hook. It must refuse, not fall back to a default org."""
    stub.answer_allow()
    g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    resp = stubcore.chat_response(
        [stubcore.tool_call("call_1", "read_file", {"path": "/etc/hosts"})])
    out = asyncio.run(g.async_post_call_success_hook(
        {"model": "mock-tools"}, None, resp))
    assert R.refused_payloads(out)[0]["error"] == "reeflex_tenant_unmapped"
    assert stub.requests == []


# ---------------------------------------------------------------------------
# The STREAMING contract (RFX-242).
#
# Every assertion below is read off the INSTALLED litellm, not off its docs.
# The hook is only ever called if litellm's own capability detection finds it,
# and that detection is a leaf-class `__dict__` check with two exits -- so
# "the method exists" is not the same claim as "the proxy will call it".
# ---------------------------------------------------------------------------

def test_the_streaming_hook_signature_is_the_one_the_proxy_awaits():
    """`ProxyLogging.async_post_call_streaming_iterator_hook` calls it with
    KEYWORD arguments `user_api_key_dict=`, `response=`, `request_data=`, and
    iterates the result. So the parameter NAMES are part of the contract, and
    it must be an async GENERATOR -- a coroutine returning a list would be
    awaited nowhere and `async for` would raise."""
    fn = G.ReeflexActionGuardrail.async_post_call_streaming_iterator_hook
    sig = inspect.signature(fn)
    assert {"user_api_key_dict", "response", "request_data"} <= set(sig.parameters)
    assert inspect.isasyncgenfunction(fn), (
        "the proxy does `async for chunk in <this>`; a plain coroutine breaks "
        "the stream rather than governing it")


def test_litellms_own_capability_detection_finds_this_guardrail():
    """The proxy SKIPS the whole iterator chain unless some callback overrides
    the hook, and it decides that with `"async_post_call_streaming_iterator_hook"
    in type(cb).__dict__` (proxy/utils.py, `_callback_capabilities`).

    Asserted through litellm's own function with our guardrail registered,
    rather than by re-implementing the check here: a re-implementation would
    keep passing after litellm changed the rule."""
    from litellm.proxy.utils import ProxyLogging

    g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
    previous = litellm.callbacks
    try:
        litellm.callbacks = [g]
        caps = ProxyLogging._callback_capabilities()
        assert caps.has_iterator_override is True
        assert [c for c, kind in caps.iterator_overrides
                if c is g and kind == "override"], (
            "litellm found no iterator override for this guardrail, so the "
            "streaming path would run ungoverned: %r" % (caps.iterator_overrides,))
    finally:
        litellm.callbacks = previous
        ProxyLogging._callback_capabilities_cache.clear()


def test_defining_the_streaming_hook_suppresses_the_after_delivery_pass():
    """The defect this removes, expressed as litellm's own condition.

    Before this hook existed, a streamed response was reassembled after
    delivery and run through `async_post_call_success_hook` by
    `ProxyBaseLLMRequestProcessing._run_deferred_stream_guardrails` -- whose
    docstring says "This is audit-only -- content has already been delivered to
    the client". So a streamed `rm -rf /` produced a `deny` in core's audit log
    AND reached the caller.

    That pass skips any callback for which
    `"async_post_call_streaming_iterator_hook" in type(cb).__dict__`. This test
    pins the source text of that condition, so the day litellm changes it, the
    build says so instead of quietly deciding every streamed action twice."""
    import inspect as _inspect
    from litellm.proxy import common_request_processing as crp

    src = _inspect.getsource(
        crp.ProxyBaseLLMRequestProcessing._run_deferred_stream_guardrails)
    assert '"async_post_call_streaming_iterator_hook" in type(cb).__dict__' in src
    assert "audit-only" in src
    assert ("async_post_call_streaming_iterator_hook"
            in G.ReeflexActionGuardrail.__dict__)


def test_a_real_model_response_stream_is_governed_and_rewritten(stub, tenancy_map):
    """The rewrite, on litellm's REAL chunk objects.

    The rest of the streaming suite drives plain dicts. This one builds
    `ModelResponseStream` / `StreamingChoices` / `Delta` and asserts the copy,
    the strip and the synthesized refusal frame all survive contact with
    pydantic -- which is where a rewrite that works on dicts and silently
    no-ops on models would be caught."""
    from litellm.types.utils import (ChatCompletionDeltaToolCall, Delta,
                                     Function, ModelResponseStream,
                                     StreamingChoices)

    def chunk(delta, finish=None):
        return ModelResponseStream(
            id="chatcmpl-1", model="mock-tools",
            choices=[StreamingChoices(index=0, delta=delta,
                                      finish_reason=finish)])

    def tc(index, args, call_id=None, name=None):
        return ChatCompletionDeltaToolCall(
            index=index, id=call_id, type="function",
            function=Function(name=name, arguments=args))

    args = json.dumps({"command": "rm -rf /"})
    chunks = [
        chunk(Delta(role="assistant", content=None)),
        chunk(Delta(tool_calls=[tc(0, "", "call_1", "run_shell")])),
        chunk(Delta(tool_calls=[tc(0, args[:9])])),
        chunk(Delta(tool_calls=[tc(0, args[9:])])),
        chunk(Delta(), "tool_calls"),
    ]
    stub.answer_deny()

    async def _aiter():
        for c in chunks:
            yield c

    async def go():
        g = G.ReeflexActionGuardrail(reeflex_hold_wait=0.0)
        return [c async for c in
                g.async_post_call_streaming_iterator_hook(
                    user_api_key_dict=real_caller(team_id="team_pay"),
                    response=_aiter(),
                    request_data={"model": "mock-tools", "stream": True})]

    out = asyncio.run(go())

    wire = "".join(c.model_dump_json() for c in out)
    assert "rm -rf /" not in wire, wire
    assert all(not (ch.delta.tool_calls or []) for c in out for ch in c.choices), (
        "a tool-call fragment survived on a real ModelResponseStream")
    content = "".join(ch.delta.content or "" for c in out for ch in c.choices)
    refused = json.loads(content)["reeflex"]["refused"]
    assert refused[0]["stage"] == "refused_at_gateway"
    assert [ch.finish_reason for c in out for ch in c.choices
            if ch.finish_reason] == ["stop"]
    assert all(c.id == "chatcmpl-1" for c in out), (
        "a synthesized frame carries a different completion id than the "
        "stream it was inserted into")
