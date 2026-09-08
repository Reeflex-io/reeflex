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

import stubcore  # noqa: E402


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


def test_a_real_model_response_object_is_mutable_by_the_rewrite(stub):
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
        {"model": "mock-tools", "litellm_call_id": "req-1"}, None, resp))

    assert out.choices[0].message.tool_calls in (None, [])
    assert out.choices[0].finish_reason == "stop"
    assert "rm -rf /" not in out.model_dump_json()
    assert R.refused_payloads(out)[0]["error"] == "reeflex_denied"


def test_a_real_model_response_with_an_allowed_call_is_untouched(stub):
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
        {"model": "mock-tools"}, None, resp))

    assert len(out.choices[0].message.tool_calls) == 1
    assert out.choices[0].message.tool_calls[0].function.name == "read_file"
    assert out.choices[0].finish_reason == "tool_calls"
    assert R.refused_payloads(out) == []


def test_post_call_is_a_mode_litellm_recognises():
    from litellm.types.guardrails import GuardrailEventHooks
    assert "post_call" in [e.value for e in GuardrailEventHooks]
