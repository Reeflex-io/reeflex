"""
mapping.py -- express one OpenHands ``ActionEvent`` as a Reeflex Action
Envelope (SPEC §2).  Pure: no network, no I/O.

WHAT THIS MODULE IS, AND WHAT IT IS DELIBERATELY NOT
====================================================
It does not price actions.  The pricing (verb, reversibility, blast radius,
externality, danger signature) is `reeflex_claude.classify.classify()`, the
one Reeflex classifier, which the Claude Code hook and the LiteLLM seat also
use.  This module's job is the same one `reeflex_litellm.normalize` does for a
gateway: express an OpenHands action in the vocabulary that classifier already
speaks, FAITHFULLY -- the value the classifier reads is the value the agent
proposed, byte for byte, never a synthesized stand-in.

    OpenHands action                         classifier tool  input
    ---------------------------------------  ---------------  ------------------
    terminal / execute_bash  (command)       Bash             {command}
    file_editor / str_replace_editor view    Read             {file_path}
                                     create  Write            {file_path, content}
                     str_replace / insert /  Edit             {file_path, old/new}
                                  undo_edit
    glob / grep                              Glob / Grep      {pattern, path}
    browser_navigate (url)                   WebFetch         {url}
    browser_get_content / get_state / ...    WebFetch         {}   (reads the open page)
    task_tracker                             TodoWrite        {}   (the agent's own list)
    MCP tool <name>                          mcp__openhands__<name>  (its arguments)
    anything else                            openhands__<tool_name>  (its arguments)

The last two rows land on the classifier's unknown-tool path, which prices an
action it cannot read as irreversible / broad / outbound -- in production that
is a HOLD (a question to a human), not an allow and not a deny.  That includes
`browser_click` and `browser_type`: a click can submit a form, and nothing on
the event says which clicks do.  An operator who knows a tool widens this with
``tool_map`` (an OpenHands tool name -> a classifier tool name), which wins over
every row above.

TWO OVERLAYS, AND BOTH CAN ONLY TIGHTEN
=======================================
1. NETWORK SHELL -> outbound.  The classifier puts a plain `curl <url>` GET in
   its EXECUTE bucket, whose documented externality is `internal`; only an
   upload (`curl -d`, `--upload-file`, `wget --post-data`) is EMIT/outbound.  A
   shell command whose words include a network client, or which carries a
   `scheme://` URL, does leave the machine, so this seat raises externality to
   `outbound`.  It never lowers anything, never touches the verb, and never
   claims `physical` (reeflex-mcp's convention: outbound, never physical).
2. MCP annotations.  `destructiveHint: true` raises reversibility to
   `irreversible` and blast radius to at least `broad`; `openWorldHint: true`
   raises externality to `outbound`.  `readOnlyHint: true` is the one hint that
   would LOWER a price, and it is ignored unless the operator passes
   ``trust_mcp_annotations=True`` -- the MCP spec calls annotations untrusted
   and the server is the governed party (reeflex-mcp RFX-173 measured a
   `readOnlyHint: true` on a destructive tool turning a deny into an allow).
   The hints themselves are passed through in `context.mcp_annotations`, so the
   audit record shows what the server claimed.

Both overlays name themselves in `context.overlays`, so a reader of the
decision can see which axis was moved by this seat rather than the classifier.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from reeflex_claude.classify import classify as _classify

REEFLEX_VERSION = "0.1"
NAMESPACE = "openhands"
AGENT_KIND = "agent:openhands"

ENVIRONMENTS = ("production", "staging", "dev")

TERMINAL_TOOLS = frozenset({"terminal", "execute_bash", "bash"})
FILE_EDITOR_TOOLS = frozenset({"file_editor", "str_replace_editor",
                               "planning_file_editor"})
# Browser tools that only READ the page already open in the agent's browser.
BROWSER_READ_TOOLS = frozenset({
    "browser_get_state", "browser_get_content", "browser_scroll",
    "browser_list_tabs", "browser_switch_tab", "browser_go_back",
    "browser_get_storage",
})
SESSION_LOCAL_TOOLS = frozenset({"task_tracker"})

# The classifier tool names `reeflex_claude.classify.classify()` routes on.
# An operator's `tool_map` value must be one of these (anything else would put
# the call on the unknown path under a name that looks deliberate).
KNOWN_CLASSIFIER_TOOLS = frozenset({
    "Bash", "Write", "Edit", "MultiEdit", "Read", "Glob", "Grep", "LS",
    "WebFetch", "WebSearch", "TodoWrite",
})

# Network clients whose presence as a command word means the command talks to
# another machine.  Matched as WHOLE shell words (after stripping a path), so
# `curly.py` and `./sshd_config_check` do not match.
NETWORK_COMMANDS = frozenset({
    "curl", "wget", "http", "https", "httpie", "xh", "nc", "ncat", "netcat",
    "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "lftp", "aria2c",
    "nslookup", "dig", "host", "ping", "traceroute",
})
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"]+")

_REV_ORDER = ("reversible", "recoverable", "irreversible")
_BLAST_ORDER = ("single", "scoped", "broad", "systemic")
_EXT_ORDER = ("internal", "outbound")  # `physical` is never emitted here


class MappedAction:
    """One OpenHands action, expressed for the classifier and priced by it.

    Attributes:
      tool_name          the OpenHands tool name on the event
      classifier_tool    the classifier tool name it was routed to
      classifier_input   the dict handed to classify()
      mapping_source     operator_map | builtin | mcp | unmapped
      cls                classify()'s output, after the overlays
      overlays           names of the overlays that moved an axis
      mcp_annotations    the MCP tool's declared hints, if any
    """

    __slots__ = ("tool_name", "classifier_tool", "classifier_input",
                 "mapping_source", "cls", "overlays", "mcp_annotations")

    def __init__(self, tool_name, classifier_tool, classifier_input,
                 mapping_source, cls, overlays, mcp_annotations):
        self.tool_name = tool_name
        self.classifier_tool = classifier_tool
        self.classifier_input = classifier_input
        self.mapping_source = mapping_source
        self.cls = cls
        self.overlays = overlays
        self.mcp_annotations = mcp_annotations

    @property
    def read_only(self) -> bool:
        return self.cls.get("verb") == "read"


# ---------------------------------------------------------------------------
# Reading an ActionEvent without importing openhands-tools
# ---------------------------------------------------------------------------

def action_fields(event: Any) -> dict:
    """The action's own fields, as plain data.  Duck-typed on purpose: the
    concrete action classes live in `openhands-tools`, which this package does
    not require, and an MCP action is a dynamically created model."""
    action = getattr(event, "action", None)
    if action is None:
        return {}
    if hasattr(action, "model_dump"):
        try:
            data = action.model_dump(mode="json")
        except Exception:  # pragma: no cover - defensive
            data = {}
    elif isinstance(action, Mapping):
        data = dict(action)
    else:  # pragma: no cover - defensive
        data = {}
    data.pop("kind", None)
    return data


def is_mcp_action(event: Any) -> bool:
    action = getattr(event, "action", None)
    return type(action).__name__ == "MCPToolAction"


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def route(event: Any, tool_map: Optional[Mapping[str, str]] = None
          ) -> tuple[str, dict, str]:
    """(classifier tool, classifier input, mapping source) for one event."""
    tool_name = getattr(event, "tool_name", "") or ""
    fields = action_fields(event)

    if tool_map and tool_name in tool_map and tool_map[tool_name] in KNOWN_CLASSIFIER_TOOLS:
        return tool_map[tool_name], _input_for(tool_map[tool_name], fields), "operator_map"

    if is_mcp_action(event):
        data = fields.get("data")
        return ("mcp__openhands__" + tool_name,
                dict(data) if isinstance(data, Mapping) else {}, "mcp")

    if tool_name in TERMINAL_TOOLS and isinstance(fields.get("command"), str):
        if fields.get("is_input"):
            # Keystrokes sent to a process that is already running.  What
            # they do depends on that process, which the event does not name,
            # so this goes down the unknown path (a question), not the Bash
            # classifier (which would read "y" as a command word).
            return "openhands__terminal_input", {"input": fields["command"]}, "unmapped"
        return "Bash", {"command": fields["command"]}, "builtin"

    if tool_name in FILE_EDITOR_TOOLS:
        sub = fields.get("command")
        path = fields.get("path")
        if sub == "view":
            return "Read", {"file_path": path}, "builtin"
        if sub == "create":
            return "Write", {"file_path": path,
                             "content": fields.get("file_text") or ""}, "builtin"
        if sub in ("str_replace", "insert", "undo_edit"):
            return "Edit", {"file_path": path,
                            "old_string": fields.get("old_str") or "",
                            "new_string": fields.get("new_str") or ""}, "builtin"

    if tool_name == "glob":
        return "Glob", {"pattern": fields.get("pattern"), "path": fields.get("path")}, "builtin"
    if tool_name == "grep":
        return "Grep", {"pattern": fields.get("pattern"), "path": fields.get("path")}, "builtin"

    if tool_name == "browser_navigate" and isinstance(fields.get("url"), str):
        return "WebFetch", {"url": fields["url"]}, "builtin"
    if tool_name in BROWSER_READ_TOOLS:
        return "WebFetch", {}, "builtin"

    if tool_name in SESSION_LOCAL_TOOLS:
        return "TodoWrite", {}, "builtin"

    return "openhands__" + (tool_name or "unknown"), fields, "unmapped"


def _input_for(classifier_tool: str, fields: dict) -> dict:
    """Rename an operator-mapped tool's argument KEYS to what the classifier
    reads.  Values pass through unchanged."""
    def first(*keys):
        for k in keys:
            if isinstance(fields.get(k), str):
                return fields[k]
        return None
    if classifier_tool == "Bash":
        return {"command": first("command", "cmd", "script") or ""}
    if classifier_tool in ("Read", "Write", "Edit", "MultiEdit"):
        return {"file_path": first("file_path", "path", "filename"),
                "content": first("content", "file_text", "text") or "",
                "old_string": first("old_str", "old_string") or "",
                "new_string": first("new_str", "new_string") or ""}
    if classifier_tool in ("WebFetch", "WebSearch"):
        return {"url": first("url", "uri"), "query": first("query", "q")}
    return dict(fields)


# ---------------------------------------------------------------------------
# Overlays (tighten only)
# ---------------------------------------------------------------------------

def _raise(order: tuple, current: str, floor: str) -> str:
    if current not in order:
        return current
    return order[max(order.index(current), order.index(floor))]


def _command_words(command: str) -> list[str]:
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    out = []
    for w in words:
        for part in re.split(r"[;&|()`$]+", w):
            if part:
                out.append(part.rsplit("/", 1)[-1])
    return out


def shell_touches_network(command: str) -> bool:
    if _URL_RE.search(command or ""):
        return True
    return any(w in NETWORK_COMMANDS for w in _command_words(command or ""))


def apply_overlays(cls: dict, classifier_tool: str, classifier_input: dict,
                   annotations: Optional[Mapping[str, Any]],
                   trust_mcp_annotations: bool) -> tuple[dict, list[str]]:
    cls = dict(cls)
    overlays: list[str] = []

    if classifier_tool == "Bash" and shell_touches_network(classifier_input.get("command", "")):
        if cls.get("externality") != "outbound" and cls.get("externality") in _EXT_ORDER:
            cls["externality"] = "outbound"
            overlays.append("network_shell:outbound")

    if annotations:
        ro = annotations.get("readOnlyHint") is True
        destructive = annotations.get("destructiveHint") is True and not ro
        if trust_mcp_annotations and ro:
            # The ONE downgrade, and only on the operator's say-so.
            cls.update(verb="read", reversibility="reversible", blast_radius="single",
                       externality="outbound" if annotations.get("openWorldHint") is True
                       else "internal", classification_tier="benign")
            overlays.append("mcp_annotation:read_only(trusted)")
        if destructive:
            before = (cls.get("reversibility"), cls.get("blast_radius"))
            cls["reversibility"] = _raise(_REV_ORDER, cls.get("reversibility", ""), "irreversible")
            cls["blast_radius"] = _raise(_BLAST_ORDER, cls.get("blast_radius", ""), "broad")
            if (cls["reversibility"], cls["blast_radius"]) != before:
                overlays.append("mcp_annotation:destructive")
        if annotations.get("openWorldHint") is True and cls.get("externality") == "internal":
            cls["externality"] = "outbound"
            overlays.append("mcp_annotation:open_world")
    return cls, overlays


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_action(event: Any, *, tool_map: Optional[Mapping[str, str]] = None,
               annotations: Optional[Mapping[str, Any]] = None,
               trust_mcp_annotations: bool = False) -> MappedAction:
    classifier_tool, classifier_input, source = route(event, tool_map)
    cls = _classify(classifier_tool, classifier_input)
    cls, overlays = apply_overlays(cls, classifier_tool, classifier_input,
                                   annotations, trust_mcp_annotations)
    return MappedAction(
        tool_name=getattr(event, "tool_name", "") or "",
        classifier_tool=classifier_tool,
        classifier_input=classifier_input,
        mapping_source=source,
        cls=cls,
        overlays=overlays,
        mcp_annotations=dict(annotations) if annotations else None,
    )


def build_envelope(mapped: MappedAction, *, session_id: str, agent_id: str,
                   environment: str, on_behalf_of: Optional[str] = None,
                   cwd: Optional[str] = None, org_id: Optional[str] = None) -> dict:
    """A Reeflex Action Envelope for one mapped action.

    `agent.id` carries the session, as reeflex-claude's does (RFX-138): core
    binds a human approval to (agent.id, agent.on_behalf_of), and a constant
    agent id would let one conversation spend an approval granted to another.
    """
    if not session_id:
        raise ValueError("session_id missing or empty -- fail-closed required")
    if environment not in ENVIRONMENTS:
        raise ValueError("environment must be one of %s" % (ENVIRONMENTS,))
    cls = mapped.cls
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    preview = cls.get("command_preview") or cls.get("file_path") or ""
    nonce = hashlib.sha256(("%s:%s:%s:%s:%d" % (
        session_id, ts, mapped.tool_name, preview, time.monotonic_ns())
    ).encode("utf-8")).hexdigest()[:32]

    context = {
        "tool_name": mapped.tool_name,
        "command_preview": cls.get("command_preview"),
        "file_path": cls.get("file_path"),
        "danger_signature": cls.get("danger_signature"),
        "classification_tier": cls.get("classification_tier"),
        "classifier_tool": mapped.classifier_tool,
        "mapping_source": mapped.mapping_source,
    }
    if mapped.overlays:
        context["overlays"] = list(mapped.overlays)
    if mapped.mcp_annotations:
        context["mcp_annotations"] = mapped.mcp_annotations
    if cwd:
        context["cwd"] = cwd
    if org_id:
        # A label only.  Tenancy is decided by the credential the gate sees,
        # never by a field the caller writes.
        context["org_label"] = org_id

    params = {"tool_name": mapped.tool_name,
              "verb_source": "openhands:%s->%s" % (mapped.tool_name, mapped.classifier_tool)}
    extra = cls.get("params_extra")
    if isinstance(extra, dict):
        for k, v in extra.items():
            params.setdefault(k, v)

    return {
        "reeflex_version": REEFLEX_VERSION,
        "agent": {
            "id": "%s/%s/%s" % (AGENT_KIND, agent_id, session_id),
            "on_behalf_of": on_behalf_of,
            "session_id": "openhands:" + session_id,
        },
        "action": {
            "namespace": NAMESPACE,
            "verb": cls["verb"],
            "ability": "%s/%s" % (NAMESPACE, mapped.tool_name or "unknown"),
        },
        "target": {
            "kind": cls.get("target_kind") or "resource",
            "ref": cls.get("target_ref"),
            "environment": environment,
        },
        "params": params,
        "magnitude": {"count": max(int(cls.get("magnitude_count", 1) or 1), 1)},
        "axes": {
            "reversibility": cls["reversibility"],
            "blast_radius": cls["blast_radius"],
            "externality": cls["externality"],
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": context,
        "meta": {"timestamp": ts, "nonce": nonce,
                 "signature": "ed25519:stub:%s" % nonce[:16]},
    }
