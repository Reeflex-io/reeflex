"""
response.py -- read the tool calls off a chat-completion response, and put the
refusals back.

Works on BOTH shapes the same response takes in a LiteLLM proxy: the pydantic
`ModelResponse` the hook receives in-process, and the plain nested dict the same
response becomes on the wire (and in a test fixture).  Every read goes through
`_get` and every write through `_set`, so there is one code path, not two.

HOW A DENIED TOOL CALL IS REMOVED
=================================
The denied call is DELETED from `choices[i].message.tool_calls`.  That is the
part that matters: the executable instruction is not in the response the caller
receives, so a client that simply executes what it is given has nothing to
execute.

The structured refusal is then appended to `choices[i].message.content` as one
JSON object:

    {"reeflex": {"version": 1, "refused": [ <refusal>, ... ]}}

WHY `content` AND NOT A `role: "tool"` MESSAGE.  A tool result is a message the
CLIENT sends on the NEXT request; a gateway sitting on the response path cannot
insert one into a conversation it does not own.  What it can do is put the
refusal in the assistant message the client is about to append to its own
history -- which is exactly where the model reads it on the following turn.  So
the refusal is a tool result in effect (the model sees why its call did not
happen) without pretending to be one in shape.

WHEN EVERY TOOL CALL ON A CHOICE IS REFUSED, `finish_reason` FLIPS from
"tool_calls" to "stop" and `tool_calls` is set to None.  Without that, an
OpenAI-compliant client sees `finish_reason: "tool_calls"` with nothing to call
and either loops or errors -- the refusal would read as a malformed response
rather than as a refusal.

WHAT THIS MODULE DOES NOT TOUCH
===============================
A response with no tool calls is returned byte for byte unchanged.  This seat
rules on ACTIONS; it does not read, mask, rewrite or score prose.  A text answer
is not an action and passes through even when core is unreachable -- see the
README: with core down, text still flows and actions do not.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def get_choices(response: Any) -> list:
    choices = _get(response, "choices")
    if not choices:
        return []
    try:
        return list(choices)
    except TypeError:
        return []


def get_tool_calls(choice: Any) -> list:
    message = _get(choice, "message")
    if message is None:
        return []
    tcs = _get(message, "tool_calls")
    if not tcs:
        return []
    try:
        return list(tcs)
    except TypeError:
        return []


def has_tool_calls(response: Any) -> bool:
    return any(get_tool_calls(c) for c in get_choices(response))


def apply_refusals(response: Any, choice_index: int, keep: list,
                   refusals: list) -> Any:
    """Rewrite one choice: `keep` becomes its tool_calls, `refusals` its notice.

    `keep` is the SUBSET of the original tool-call objects that were allowed --
    the original objects, not copies, so an allowed call is bit-for-bit what the
    model produced.  Returns the same response object, mutated.
    """
    choices = get_choices(response)
    if choice_index >= len(choices):
        return response
    choice = choices[choice_index]
    message = _get(choice, "message")
    if message is None:
        return response

    if not refusals:
        return response

    _set(message, "tool_calls", keep if keep else None)

    existing = _get(message, "content")
    notice = json.dumps({"reeflex": {"version": 1, "refused": refusals}},
                        sort_keys=True)
    if isinstance(existing, str) and existing.strip():
        _set(message, "content", existing.rstrip() + "\n" + notice)
    else:
        _set(message, "content", notice)

    if not keep:
        _set(choice, "finish_reason", "stop")

    return response


def refused_payloads(response: Any) -> list:
    """Every refusal recorded on a response, across all choices.

    Reads back what `apply_refusals` wrote -- used by the tests and the live
    walk so the assertion is on the response a caller receives, not on the
    Outcome objects the adapter produced internally.
    """
    out = []
    for choice in get_choices(response):
        message = _get(choice, "message")
        if message is None:
            continue
        content = _get(message, "content")
        if not isinstance(content, str):
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except (ValueError, TypeError):
                continue
            block = parsed.get("reeflex") if isinstance(parsed, dict) else None
            if isinstance(block, dict) and isinstance(block.get("refused"), list):
                out.extend(block["refused"])
    return out


# ---------------------------------------------------------------------------
# dict / pydantic shims
# ---------------------------------------------------------------------------

def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _set(obj: Any, key: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[key] = value
        return
    setattr(obj, key, value)
