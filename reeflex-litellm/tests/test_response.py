"""Reading tool calls off a response, and putting refusals back."""

from __future__ import annotations

import json

from reeflex_litellm import enforce, normalize, response as R

import stubcore


def resp(*calls, content=None):
    return stubcore.chat_response(list(calls), content=content)


def a_refusal(call_id="call_1", tool="run_shell"):
    call = normalize.normalize_tool_call(
        stubcore.tool_call(call_id, tool, {"command": "rm -rf /"}))
    return enforce.refusal(call, "reeflex_denied",
                           "reeflex.policy/irreversible_systemic_prod",
                           "Reeflex: no.")


def test_a_response_with_no_tool_calls_is_not_an_action():
    r = stubcore.chat_response([], content="here is some prose",
                               finish_reason="stop")
    assert R.has_tool_calls(r) is False
    before = json.dumps(r, sort_keys=True)
    R.apply_refusals(r, 0, [], [])
    assert json.dumps(r, sort_keys=True) == before


def test_a_denied_call_is_removed_from_tool_calls():
    denied = stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf /"})
    r = resp(denied)
    R.apply_refusals(r, 0, [], [a_refusal()])
    assert r["choices"][0]["message"]["tool_calls"] is None


def test_an_allowed_call_survives_bit_for_bit_beside_a_denied_one():
    allowed = stubcore.tool_call("call_a", "read_file", {"path": "/etc/hosts"})
    denied = stubcore.tool_call("call_b", "run_shell", {"command": "rm -rf /"})
    original_allowed = json.loads(json.dumps(allowed))
    r = resp(allowed, denied)
    R.apply_refusals(r, 0, [allowed], [a_refusal("call_b")])
    kept = r["choices"][0]["message"]["tool_calls"]
    assert len(kept) == 1
    assert kept[0] == original_allowed


def test_the_refusal_is_readable_json_in_the_message_the_model_gets_back():
    r = resp(stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf /"}))
    R.apply_refusals(r, 0, [], [a_refusal()])
    payloads = R.refused_payloads(r)
    assert len(payloads) == 1
    assert payloads[0]["error"] == "reeflex_denied"
    assert payloads[0]["stage"] == "refused_at_gateway"
    assert payloads[0]["rule"] == "reeflex.policy/irreversible_systemic_prod"


def test_existing_prose_is_kept_and_the_refusal_appended():
    r = resp(stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf /"}),
             content="I will clean up the build directory.")
    R.apply_refusals(r, 0, [], [a_refusal()])
    content = r["choices"][0]["message"]["content"]
    assert content.startswith("I will clean up the build directory.")
    assert R.refused_payloads(r)[0]["error"] == "reeflex_denied"


def test_finish_reason_flips_to_stop_when_nothing_is_left_to_call():
    """Otherwise an OpenAI-compliant client sees finish_reason 'tool_calls'
    with nothing to call, and the refusal reads as a malformed response."""
    r = resp(stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf /"}))
    assert r["choices"][0]["finish_reason"] == "tool_calls"
    R.apply_refusals(r, 0, [], [a_refusal()])
    assert r["choices"][0]["finish_reason"] == "stop"


def test_finish_reason_stays_tool_calls_when_a_call_survives():
    allowed = stubcore.tool_call("call_a", "read_file", {"path": "/etc/hosts"})
    r = resp(allowed, stubcore.tool_call("call_b", "run_shell",
                                         {"command": "rm -rf /"}))
    R.apply_refusals(r, 0, [allowed], [a_refusal("call_b")])
    assert r["choices"][0]["finish_reason"] == "tool_calls"


def test_apply_refusals_is_a_no_op_when_there_are_no_refusals():
    allowed = stubcore.tool_call("call_a", "read_file", {"path": "/etc/hosts"})
    r = resp(allowed)
    before = json.dumps(r, sort_keys=True)
    R.apply_refusals(r, 0, [allowed], [])
    assert json.dumps(r, sort_keys=True) == before


def test_a_choice_index_that_does_not_exist_is_survivable():
    r = resp(stubcore.tool_call("call_1", "run_shell", {"command": "ls"}))
    R.apply_refusals(r, 9, [], [a_refusal()])  # must not raise


# -- object-shaped responses ------------------------------------------------

class _Msg:
    def __init__(self, tool_calls, content=None):
        self.role = "assistant"
        self.content = content
        self.tool_calls = tool_calls


class _Choice:
    def __init__(self, message, finish_reason="tool_calls"):
        self.index = 0
        self.message = message
        self.finish_reason = finish_reason


class _Resp:
    def __init__(self, choices, model="mock-tools"):
        self.model = model
        self.choices = choices


def test_the_same_code_path_rewrites_an_object_shaped_response():
    """LiteLLM hands the hook a pydantic ModelResponse in-process. If the
    rewrite only worked on dicts, the suite would be green against a shape the
    proxy never produces."""
    call = stubcore.tool_call("call_1", "run_shell", {"command": "rm -rf /"})
    r = _Resp([_Choice(_Msg([call]))])
    assert R.has_tool_calls(r) is True
    R.apply_refusals(r, 0, [], [a_refusal()])
    assert r.choices[0].message.tool_calls is None
    assert r.choices[0].finish_reason == "stop"
    assert R.refused_payloads(r)[0]["stage"] == "refused_at_gateway"
