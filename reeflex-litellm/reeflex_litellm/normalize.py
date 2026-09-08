"""
normalize.py -- the NORMALIZE step (SPEC §6) for an LLM-gateway backend.

WHAT THIS MODULE IS, AND WHAT IT IS DELIBERATELY NOT
====================================================
This module does NOT classify.  It contains no axis, no verb, no tier and no
danger signature.  Its only job is to express ONE OpenAI-shaped tool call --

    {"id": "call_1", "type": "function",
     "function": {"name": "run_shell",
                  "arguments": "{\\"cmd\\": \\"rm -rf /var/lib/data\\"}"}}

-- in the vocabulary the ONE Reeflex classifier already speaks
(`reeflex_claude.classify.classify(tool_name, tool_input)`), then hand it over.

There is exactly one classifier in this repo and this package does not add a
second one.  Every axis a gateway envelope carries is computed by
`reeflex_claude.classify`, so a fix to the pricing of an action lands in one
place and reaches every seat -- the Claude Code hook, the MCP gateway and this
gateway alike.

WHY NORMALIZATION IS A SEPARATE PROBLEM AT A GATEWAY
====================================================
The Claude Code hook knows its tool names: there are about a dozen and they are
fixed by the harness.  A gateway does not.  Every application behind the proxy
declares its own tool schema, so the same shell execution arrives as `Bash`,
`run_shell`, `execute_command`, `terminal`, `sh`, `bash_tool` or
`acme_infra_runner`, and the argument holding the command is called `command`,
`cmd`, `script`, `shell_command` or `code`.

Two rules govern everything below, both of them lessons paid for already:

  RFX-144/145/146 -- PRICE THE ACTION, NOT THE PHRASING.  A mapping is allowed
  only when it is FAITHFUL: when the gateway call really does carry the thing
  the mapped classifier reads.  We never SYNTHESIZE the input a classifier
  wants.  In particular a tool called `delete_file(path=...)` is NOT rewritten
  into a fake `rm -- <path>` command string to make the Bash classifier fire:
  that would put a command the model never proposed into
  `context.command_preview`, i.e. into the line a human reads in the audit
  record.  It goes down the unknown path instead (see below), which asks a
  human.

  FAIL CONSERVATIVE ON A MISMATCH.  When the NAME says one thing and the
  ARGUMENTS say another -- `run_shell` arriving with no command-shaped argument
  at all -- we do not guess.  Name and argument shape must AGREE, or the call is
  unmapped.

WHAT AN UNMAPPED CALL COSTS, MEASURED
=====================================
An unmapped call is handed to the classifier under its own gateway tool name,
which lands in `classify`'s unknown-tool path.  Measured against the published
`ghcr.io/reeflex-io/reeflex-core:v0.2.0` (digest sha256:58a0a531dfa1…) on
2026-09-08:

    unknown tool -> irreversible / broad / outbound
                 -> HTTP 200 require_approval [reeflex.policy/irreversible_broad_prod]

So an unmapped tool call is a HOLD, not a deny and not an allow -- it asks a
human.  That is the honest answer for an action this adapter cannot price, and
it is why the built-in table below is deliberately small: a wrong mapping is a
mispriced action, while a missing mapping is a question.  Operators widen the
table for their own tool names with REEFLEX_LITELLM_TOOL_MAP rather than having
this module guess from a name it has never seen.

THE ONE THING THE GATEWAY TOOL NAME ALWAYS REACHES
==================================================
Whether or not a call is mapped, its gateway tool name is emitted as
`action.ability` = `litellm/<gateway tool name>` (see envelope.py).  That is
load-bearing in two ways, both verified against core:

  1. core's own verb canon reads it.  `envelope._delete_signal_from_ability()`
     takes the first token of the last "/"-separated segment, so
     `litellm/delete_file` sets `action.verb = "delete"` inside core even
     though this adapter never claimed a verb for it -- which is what puts the
     call on R5's deletion budget.
  2. core's audit line carries `action.ability`, not `target.ref` and not
     `params`.  So the gateway tool name is what a human sees in the record.

CONFIGURATION
=============
  REEFLEX_LITELLM_TOOL_MAP  JSON object, or a path to a file containing one,
                            mapping a gateway tool name to a classifier tool
                            name: {"acme_infra_runner": "Bash"}.  Highest
                            precedence -- an operator's declaration beats every
                            heuristic here.  Values are validated against
                            KNOWN_CLASSIFIER_TOOLS; an unknown value is ignored
                            (and the call stays unmapped) rather than silently
                            becoming the unknown path under a name that looks
                            deliberate.
                            Re-read on every call, so a map edit needs no proxy
                            restart.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

# The classifier tool names `reeflex_claude.classify.classify()` routes on.
# Anything outside this set goes down its unknown-tool path.
KNOWN_CLASSIFIER_TOOLS = frozenset({
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch",
})

# ---------------------------------------------------------------------------
# Argument aliases.
#
# The KEY the classifier reads is on the left; the gateway spellings we accept
# for it are on the right, IN PRECEDENCE ORDER.  These are aliases only: the
# VALUE is passed through byte for byte, never rewritten, so the command the
# classifier prices is the command the model proposed.
# ---------------------------------------------------------------------------
_COMMAND_KEYS = ("command", "cmd", "shell_command", "script", "bash_command",
                 "code", "commandline", "command_line")
_PATH_KEYS = ("file_path", "path", "filename", "file", "target_path",
              "filepath", "dest", "destination")
_CONTENT_KEYS = ("content", "text", "data", "body", "contents", "new_content")
_URL_KEYS = ("url", "uri", "link", "endpoint", "address")
_QUERY_KEYS = ("query", "q", "search", "search_query", "pattern")

# ---------------------------------------------------------------------------
# Name heuristics.  Substring match on the lowercased gateway tool name.
#
# Each entry is (substrings, classifier tool, required argument shape).  The
# required shape is what makes the mapping FAITHFUL -- see the module docstring.
# Order matters: the first entry whose name AND shape both match wins.
# ---------------------------------------------------------------------------
_SHELL_NAMES = ("shell", "bash", "terminal", "console", "exec", "command",
                "run_code", "run_script", "sh_tool", "subprocess")
_WRITE_NAMES = ("write_file", "create_file", "save_file", "put_file",
                "write", "create_document", "upload_file")
_EDIT_NAMES = ("edit", "patch", "apply_diff", "modify_file", "update_file",
               "replace_in_file", "str_replace")
_READ_NAMES = ("read_file", "read", "cat_file", "get_file", "view_file",
               "list_dir", "list_files", "list_directory", "glob", "grep",
               "search_files", "find_file", "ls_tool")
_FETCH_NAMES = ("http_request", "fetch_url", "fetch", "browse", "curl",
                "web_get", "request_url", "open_url")
_SEARCH_NAMES = ("web_search", "search_web", "google", "bing", "internet_search")


class NormalizedCall:
    """One gateway tool call expressed in the classifier's vocabulary.

    Attributes:
      call_id        the gateway's tool_call id (opaque; echoed in refusals)
      gateway_tool   the tool name the model actually asked for
      tool_name      the classifier tool name to route on.  Equal to
                     `gateway_tool` when unmapped -- which is what puts the call
                     on classify()'s unknown-tool path.
      tool_input     the dict handed to classify(); values are the model's,
                     only the KEYS are renamed to what the classifier reads
      mapped         True if a faithful mapping was found
      mapping_source "operator_map" | "name_and_shape" | "unmapped"
      arguments_ok   False if `function.arguments` was not parseable JSON
    """

    __slots__ = ("call_id", "gateway_tool", "tool_name", "tool_input",
                 "mapped", "mapping_source", "arguments_ok", "raw_arguments")

    def __init__(self, call_id, gateway_tool, tool_name, tool_input, mapped,
                 mapping_source, arguments_ok, raw_arguments):
        self.call_id = call_id
        self.gateway_tool = gateway_tool
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.mapped = mapped
        self.mapping_source = mapping_source
        self.arguments_ok = arguments_ok
        self.raw_arguments = raw_arguments

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("NormalizedCall(call_id=%r, gateway_tool=%r, tool_name=%r, "
                "mapped=%r, source=%r, arguments_ok=%r)"
                % (self.call_id, self.gateway_tool, self.tool_name,
                   self.mapped, self.mapping_source, self.arguments_ok))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_tool_call(tool_call: Any) -> NormalizedCall:
    """Express one OpenAI-shaped tool call in the classifier's vocabulary.

    Accepts either a plain dict or an object with `.id` / `.function.name` /
    `.function.arguments` attributes (LiteLLM returns pydantic models, and the
    same response arrives as plain dicts over the wire).

    NEVER raises.  A tool call this function cannot read at all still yields a
    NormalizedCall -- unmapped, `arguments_ok=False` -- because a call the
    adapter cannot parse must still be RULED ON, not skipped.  Skipping is the
    fail-open.
    """
    call_id = _get(tool_call, "id") or ""
    fn = _get(tool_call, "function") or {}
    gateway_tool = str(_get(fn, "name") or "") or "unknown"

    raw_args = _get(fn, "arguments")
    args, arguments_ok = _parse_arguments(raw_args)

    tool_name, source = _map_tool(gateway_tool, args)
    if tool_name is None:
        # Unmapped: hand the gateway's own tool name to the classifier, which
        # routes it down the unknown-tool path (-> a hold, measured; see the
        # module docstring).  We do NOT invent a classifier tool for it.
        return NormalizedCall(call_id, gateway_tool, gateway_tool, dict(args),
                              False, "unmapped", arguments_ok,
                              raw_args if isinstance(raw_args, str) else None)

    return NormalizedCall(call_id, gateway_tool, tool_name,
                          _project_input(tool_name, args), True, source,
                          arguments_ok,
                          raw_args if isinstance(raw_args, str) else None)


def normalize_tool_calls(tool_calls: Any) -> list:
    """Normalize every tool call on a response.  Order is preserved."""
    if not tool_calls:
        return []
    try:
        items = list(tool_calls)
    except TypeError:
        return []
    return [normalize_tool_call(tc) for tc in items]


def operator_tool_map() -> dict:
    """Read REEFLEX_LITELLM_TOOL_MAP.  Returns {} when unset or unreadable.

    Re-read on every call on purpose: an operator adding a tool name to the map
    should not have to restart the proxy.  A malformed map is IGNORED rather
    than fatal -- a typo in a config file must not take the gateway's governance
    seat offline, and an ignored map leaves every call unmapped, which asks a
    human rather than allowing anything.
    """
    raw = os.environ.get("REEFLEX_LITELLM_TOOL_MAP", "").strip()
    if not raw:
        return {}
    if not raw.startswith("{"):
        try:
            with open(raw, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    out = {}
    for k, v in parsed.items():
        if isinstance(k, str) and isinstance(v, str) and v in KNOWN_CLASSIFIER_TOOLS:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(obj: Any, key: str) -> Any:
    """Read `key` from a dict OR an attribute off a pydantic model."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _parse_arguments(raw: Any) -> tuple:
    """(args_dict, ok).  `function.arguments` is a JSON STRING on the wire."""
    if isinstance(raw, dict):
        return raw, True
    if raw is None or raw == "":
        # An argument-less tool call is legitimate (`get_time()`), not an error.
        return {}, True
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return {}, False
        if isinstance(parsed, dict):
            return parsed, True
        # A non-object arguments payload (a bare string or list) is a shape this
        # adapter cannot read.  Not an allow.
        return {}, False
    return {}, False


def _first(args: dict, keys: tuple) -> Optional[str]:
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def _map_tool(gateway_tool: str, args: dict) -> tuple:
    """(classifier_tool_or_None, mapping_source)."""
    op = operator_tool_map()
    if gateway_tool in op:
        return op[gateway_tool], "operator_map"

    name = gateway_tool.lower()

    # Shell execution: the mapping is faithful only if a command string is here.
    if _matches(name, _SHELL_NAMES) and _first(args, _COMMAND_KEYS):
        return "Bash", "name_and_shape"

    # An argument that IS a shell command, under any tool name.  This is the one
    # shape-only rule, and it is safe in the conservative direction: it can only
    # ever move a call from the unknown path onto the real command it carries.
    if _first(args, ("command", "cmd", "shell_command")) and not _matches(
            name, _READ_NAMES + _WRITE_NAMES + _EDIT_NAMES):
        return "Bash", "name_and_shape"

    # Edit before Write: "update_file" contains neither, but "write" is a
    # substring of nothing in _EDIT_NAMES, while several edit names would also
    # match a naive write rule.
    if _matches(name, _EDIT_NAMES) and _first(args, _PATH_KEYS):
        return "Edit", "name_and_shape"

    if _matches(name, _WRITE_NAMES) and _first(args, _PATH_KEYS):
        return "Write", "name_and_shape"

    if _matches(name, _SEARCH_NAMES) and _first(args, _QUERY_KEYS):
        return "WebSearch", "name_and_shape"

    if _matches(name, _FETCH_NAMES) and _first(args, _URL_KEYS):
        return "WebFetch", "name_and_shape"

    if _matches(name, _READ_NAMES) and (_first(args, _PATH_KEYS)
                                        or _first(args, _QUERY_KEYS)):
        return "Read", "name_and_shape"

    return None, "unmapped"


def _matches(name: str, needles: tuple) -> bool:
    return any(n in name for n in needles)


def _project_input(tool_name: str, args: dict) -> dict:
    """Rename the KEYS the classifier reads.  Values are never rewritten.

    Unrecognized arguments are carried through untouched so nothing is lost from
    `params`/`context` -- the classifier ignores keys it does not read.
    """
    out = dict(args)
    if tool_name == "Bash":
        cmd = _first(args, _COMMAND_KEYS)
        if cmd is not None:
            out["command"] = cmd
    elif tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Read"):
        path = _first(args, _PATH_KEYS)
        if path is not None:
            out["file_path"] = path
        content = _first(args, _CONTENT_KEYS)
        if content is not None:
            out["content"] = content
    elif tool_name == "WebFetch":
        url = _first(args, _URL_KEYS)
        if url is not None:
            out["url"] = url
    elif tool_name == "WebSearch":
        q = _first(args, _QUERY_KEYS)
        if q is not None:
            out["query"] = q
    return out
