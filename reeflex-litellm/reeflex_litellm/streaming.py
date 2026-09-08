"""
streaming.py -- assembling a tool call out of SSE deltas, and putting the
refusal back into the stream.

WHY THIS MODULE EXISTS SEPARATELY FROM guardrail.py
===================================================
Everything here is pure: dicts and objects in, dicts and objects out, no
network, no event loop and NO IMPORT OF LITELLM.  That is what lets the suite
measure the hard part -- reassembling a tool call whose `arguments` arrive split
across an arbitrary number of frames -- without a proxy, and it is why the
LiteLLM-contract tests can stay narrow.

THE PROBLEM THE STREAMING PATH POSES, WHICH THE BUFFERED PATH DOES NOT
======================================================================
On the buffered path the adapter is handed a finished response: every tool call
is complete, so it can be normalized, priced and ruled on before anything is
returned.  A stream has no such moment.  `function.arguments` arrives as a
sequence of fragments --

    {"tool_calls":[{"index":0,"id":"call_0","function":{"name":"run_shell","arguments":""}}]}
    {"tool_calls":[{"index":0,"function":{"arguments":"{\\"command\\":"}}]}
    {"tool_calls":[{"index":0,"function":{"arguments":" \\"rm -rf /\\"}"}}]}

-- and the dangerous half of an action is usually in the last fragment.  Ruling
on a partial argument string is worse than not ruling at all: it prices an
action nobody proposed.

So the rule this module implements is: A TOOL CALL IS NOT DECIDED UNTIL IT IS
COMPLETE, AND NO FRAGMENT OF IT LEAVES THE GATEWAY BEFORE THE DECISION.

WHAT IS WITHHELD, AND WHAT IS NOT
=================================
Text deltas that carry no tool call stream through UNTOUCHED and immediately --
this seat rules on actions and does not read, mask, score or delay prose.

From the first chunk carrying a `tool_calls` delta, everything is buffered
until the upstream stream ends.  Not only the tool-call chunks: the chunk
carrying `finish_reason` arrives with an EMPTY delta, and letting that through
early would deliver "the answer is finished" to a client before the tool calls
it is finishing with.  Ordering is part of the contract, so the buffer closes
over the tail of the stream, not over a subset of it.

WHY THE WHOLE RESPONSE IS DECIDED AT ONCE RATHER THAN CALL BY CALL
==================================================================
A response carrying two tool calls could have the first one decided while the
second is still arriving.  It is not done that way, on purpose: the buffered
path decides the calls of one response IN ORDER, and R5's cumulative budget is
charged in that order, so a streamed response that decided them in a different
order (or concurrently) could reach a different verdict than the same response
buffered.  Parity with the buffered path is worth more here than the few tens
of milliseconds, and the parity is asserted in the suite rather than assumed.

WHAT COMES BACK OUT
===================
  * every call allowed  -> the buffered chunks are yielded VERBATIM, the same
    objects in the same order.  A caller cannot tell the seat was there, which
    is the property the suite asserts against a hook-off proxy;
  * some call refused   -> the refused call's fragments are removed from the
    chunks that carried them, and ONE synthetic chunk is inserted carrying the
    same structured refusal payload as the buffered path
    (`{"reeflex": {"version": 1, "refused": [...]}}`, `stage:
    refused_at_gateway`) as a content delta;
  * every call refused  -> as above, and `finish_reason` flips from
    "tool_calls" to "stop", for the same reason response.py flips it on the
    buffered path: a client that is told to call tools and given none either
    loops or errors.

The refusal goes in `content` rather than in a `role: "tool"` message for the
reason response.py gives at length: a gateway on the response path cannot
insert a message into a conversation it does not own.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Optional


# ---------------------------------------------------------------------------
# dict / pydantic shims.
#
# Deliberately a local copy of response.py's pair rather than an import of its
# privates: a streaming chunk is a DIFFERENT shape (`choices[i].delta`, not
# `choices[i].message`) and the two readers should be free to diverge without
# one quietly changing the other.
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


def _choices(chunk: Any) -> list:
    choices = _get(chunk, "choices")
    if not choices:
        return []
    try:
        return list(choices)
    except TypeError:
        return []


def _tool_call_deltas(choice: Any) -> list:
    delta = _get(choice, "delta")
    if delta is None:
        return []
    tcs = _get(delta, "tool_calls")
    if not tcs:
        return []
    try:
        return list(tcs)
    except TypeError:
        return []


# ---------------------------------------------------------------------------
# Reading a chunk
# ---------------------------------------------------------------------------

def chunk_tool_indices(chunk: Any) -> set:
    """Every tool-call index this chunk carries a fragment for.

    NEVER raises.  A chunk this function cannot read -- a keep-alive ping, a
    provider extension, a raw string -- reports NO indices, which makes it a
    pass-through.  That is the right default here and only here: a chunk with
    no readable tool call carries no action, and withholding unreadable prose
    would make the seat a text guardrail.
    """
    out = set()
    try:
        for choice in _choices(chunk):
            for entry in _tool_call_deltas(choice):
                idx = _get(entry, "index")
                out.add(idx if isinstance(idx, int) else 0)
    except Exception:  # pragma: no cover - defensive
        return out
    return out


def chunk_has_tool_call(chunk: Any) -> bool:
    return bool(chunk_tool_indices(chunk))


def chunk_content(chunk: Any) -> str:
    """The text this chunk would append to the assistant message."""
    out = []
    try:
        for choice in _choices(chunk):
            delta = _get(choice, "delta")
            if delta is None:
                continue
            content = _get(delta, "content")
            if isinstance(content, str):
                out.append(content)
    except Exception:  # pragma: no cover - defensive
        return ""
    return "".join(out)


def chunk_finish_reason(chunk: Any) -> Optional[str]:
    try:
        for choice in _choices(chunk):
            reason = _get(choice, "finish_reason")
            if isinstance(reason, str) and reason:
                return reason
    except Exception:  # pragma: no cover - defensive
        return None
    return None


# ---------------------------------------------------------------------------
# Assembling the calls
# ---------------------------------------------------------------------------

class ToolCallAccumulator:
    """Rebuild whole OpenAI tool calls out of the fragments in a stream.

    `id`, `type` and `function.name` are taken from the first fragment that
    carries them; `function.arguments` is the CONCATENATION of every fragment,
    in arrival order, as a string.  Nothing is parsed here -- the JSON string is
    what goes to `normalize.normalize_tool_call()`, exactly as on the buffered
    path, so a malformed argument string is normalized (and ruled on) rather
    than dropped.

    Order is the order the indices FIRST appeared, not numeric order: an
    index is a provider's label, and the order the caller sees is the order the
    fragments arrived.
    """

    __slots__ = ("_calls", "_order")

    def __init__(self):
        self._calls = {}
        self._order = []

    def feed(self, chunk: Any) -> set:
        """Absorb one chunk.  Returns the indices it contributed to."""
        touched = set()
        for choice in _choices(chunk):
            for entry in _tool_call_deltas(choice):
                idx = _get(entry, "index")
                idx = idx if isinstance(idx, int) else 0
                touched.add(idx)
                slot = self._calls.get(idx)
                if slot is None:
                    slot = self._calls[idx] = {"id": None, "type": None,
                                               "name": None, "arguments": ""}
                    self._order.append(idx)
                call_id = _get(entry, "id")
                if isinstance(call_id, str) and call_id and not slot["id"]:
                    slot["id"] = call_id
                call_type = _get(entry, "type")
                if isinstance(call_type, str) and call_type and not slot["type"]:
                    slot["type"] = call_type
                fn = _get(entry, "function")
                if fn is None:
                    continue
                name = _get(fn, "name")
                if isinstance(name, str) and name and not slot["name"]:
                    slot["name"] = name
                args = _get(fn, "arguments")
                if isinstance(args, str) and args:
                    slot["arguments"] += args
        return touched

    def indices(self) -> list:
        return list(self._order)

    def assembled(self) -> list:
        """[(index, tool_call_dict)] in arrival order.

        The dict is the shape the buffered path hands to
        `normalize.normalize_tool_call()`, so ONE normalizer sees both paths.
        A call whose id never arrived gets one derived from its index rather
        than an empty string: the refusal payload keys on `tool_call_id`, and a
        refusal that names no call is not a usable refusal.
        """
        out = []
        for idx in self._order:
            slot = self._calls[idx]
            out.append((idx, {
                "id": slot["id"] or ("stream_tool_call_%d" % idx),
                "type": slot["type"] or "function",
                "function": {"name": slot["name"] or "",
                             "arguments": slot["arguments"]},
            }))
        return out


# ---------------------------------------------------------------------------
# Rewriting a chunk
# ---------------------------------------------------------------------------

def _copy_chunk(chunk: Any) -> Any:
    """A deep copy of a chunk, whatever it is.

    `model_copy(deep=True)` for the pydantic `ModelResponseStream` LiteLLM
    actually delivers, `copy.deepcopy` for anything else.  A copy is used
    rather than mutation in place because the caller may still hold the
    original -- and because an ALLOWED call must be able to yield the untouched
    object.
    """
    model_copy = getattr(chunk, "model_copy", None)
    if callable(model_copy):
        try:
            return model_copy(deep=True)
        except Exception:  # pragma: no cover - defensive
            pass
    return copy.deepcopy(chunk)


def strip_tool_indices(chunk: Any, drop: set):
    """Remove the fragments for `drop` from a chunk.

    Returns `(new_chunk, still_carries_something)`.  The second value is False
    when the chunk existed ONLY to carry refused fragments -- no text, no
    finish_reason -- in which case the caller drops it entirely rather than
    emitting an empty frame.

    A chunk touching both an allowed and a refused call keeps the allowed
    fragment.  Providers send one call per chunk in practice, so this path is
    defensive; it is implemented rather than assumed away because "in practice"
    is how a fail-open gets shipped.
    """
    if not drop or not (chunk_tool_indices(chunk) & drop):
        return chunk, True

    out = _copy_chunk(chunk)
    carries = False
    for choice in _choices(out):
        delta = _get(choice, "delta")
        if delta is not None:
            kept = []
            for entry in _tool_call_deltas(choice):
                idx = _get(entry, "index")
                idx = idx if isinstance(idx, int) else 0
                if idx not in drop:
                    kept.append(entry)
            _set(delta, "tool_calls", kept or None)
            if kept:
                carries = True
            content = _get(delta, "content")
            if isinstance(content, str) and content:
                carries = True
        if _get(choice, "finish_reason"):
            carries = True
    return out, carries


def set_finish_reason(chunk: Any, reason: str) -> Any:
    """Set the finish_reason on EVERY choice of a copy of `chunk`.

    Every choice, not only the ones that already had one: the two callers are
    the "all calls refused, so this is a `stop` not a `tool_calls`" rewrite of
    the provider's own final frame, and the synthesized final frame the
    fail-closed path emits when it has dropped the tail.  The second has no
    finish_reason to overwrite, and a conditional version silently produced a
    stream that never ended.
    """
    out = _copy_chunk(chunk)
    for choice in _choices(out):
        _set(choice, "finish_reason", reason)
    return out


def refusal_notice(refusals: list, lead_newline: bool) -> str:
    """The text a refusal chunk carries.

    Byte-for-byte the payload `response.apply_refusals()` writes on the
    buffered path -- same key order (`sort_keys=True`), same `version`, same
    refusal dicts -- so an evidence pipeline, a client and a test read ONE
    shape regardless of which path produced it.  `lead_newline` reproduces the
    buffered path's rule that the notice goes on its own line after any prose
    the assistant already produced.
    """
    notice = json.dumps({"reeflex": {"version": 1, "refused": refusals}},
                        sort_keys=True)
    return ("\n" + notice) if lead_newline else notice


def build_refusal_chunk(template: Any, text: str) -> Any:
    """A chunk carrying `text` as a content delta and nothing else.

    Built by COPYING a chunk the provider actually sent, so it is the same
    type, with the same `id`, `model` and `created`, as the frames around it.
    Constructing a fresh `ModelResponseStream` here would drag litellm into
    this module and would still have to guess at those fields; a client that
    sees a refusal frame with a different `id` than the rest of the stream is
    entitled to discard it.

    `usage` is cleared when the template carried one: a synthesized frame must
    not add a second usage block to a stream, which a billing reader would
    add to the first.
    """
    out = _copy_chunk(template)
    for choice in _choices(out):
        delta = _get(choice, "delta")
        if delta is None:
            continue
        _set(delta, "content", text)
        _set(delta, "tool_calls", None)
        _set(delta, "role", None)
        _set(choice, "finish_reason", None)
    if _get(out, "usage") is not None:
        _set(out, "usage", None)
    return out
