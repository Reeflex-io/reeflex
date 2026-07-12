"""
normalize.py -- build a Reeflex Action Envelope (SPEC section 2) from a
`tools/call` the gateway intercepted.

THE 3-TIER RESOLUTION (Track 4, design doc section 8) -- see `classify_call()`:

  1. declarative mapping   -- mappings.MappingRegistry.classify(), for the
                               upstream's target.system + this exact tool
                               name (mappings/<system>.yaml -- see
                               mappings.py). source tag "mapping".
  2. name-heuristic         -- `classify()` below (Track 2, kept verbatim as
                               the fallback for anything a mapping doesn't
                               name). source tag "heuristic:<bucket>".
  3. conservative default   -- the SAME `classify()` function's own
                               catch-all bucket, fired when no name-prefix
                               matches either. source tag "heuristic:default".

`build_envelope()` takes an optional `mapping_registry` -- when given, tier 1
is tried first via `classify_call()`; when None (or no match), behavior is
identical to Track 2 (heuristic only). The resolved tier is recorded at
`context.classification_source` on every envelope (design doc section 8:
"Log which tier classified each call" -- helps the GIGO story + debugging).

Heuristic table (design doc section 8 / brief section 8, verbatim):

    tool name prefix                    -> verb      | reversibility  | externality
    ---------------------------------------------------------------------------
    delete_* / remove_* / drop_*        -> delete     | irreversible   | (internal)
    send_* / post_* / create_* / push_* -> create     | (recoverable)  | outbound
    get_* / list_* / read_* / search_*  -> read        | reversible    | (internal)
    <anything else>                     -> execute (conservative default)
                                            axes forced to the restrictive floor:
                                            irreversible / systemic / internal

Values in parentheses above are NOT dictated verbatim by the brief; they are
this module's conservative, documented completion of the two axes the brief
did not spell out per bucket (see _AXES_BY_BUCKET below). `blast_radius` for
the three matched buckets is derived from `magnitude.count` via the same
single/scoped/broad thresholds used by the WordPress reference adapter
(reeflex-spec/ADAPTER-EXAMPLES.md section A); the unmatched (`execute`)
bucket's blast_radius is fixed at "systemic" per the brief's literal
"restrictive floor" text, not magnitude-derived.

`magnitude.count`: "from a plausible list-arg count else 1" (brief section
8) -- the first argument value that is a list, or 1.

This module is pure: no network, no I/O, no side effects.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .mappings import MappingRegistry

_REEFLEX_VERSION = "0.1"
_NAMESPACE_PREFIX = ""  # namespace == target_system (see build_envelope)

# Prefixes checked in this order; first match wins.
_DELETE_PREFIXES = ("delete_", "remove_", "drop_")
_CREATE_PREFIXES = ("send_", "post_", "create_", "push_")
_READ_PREFIXES = ("get_", "list_", "read_", "search_")

# Axis completion per matched bucket (the axis NOT dictated verbatim by the
# brief for that bucket). blast_radius is computed separately from magnitude
# (see _blast_radius_for_count), except for "execute" which is fixed.
_AXES_BY_BUCKET: dict[str, dict[str, str]] = {
    "delete": {"reversibility": "irreversible", "externality": "internal"},
    "create": {"reversibility": "recoverable", "externality": "outbound"},
    "read": {"reversibility": "reversible", "externality": "internal"},
}

# The brief's literal "restrictive floor" for the unmatched/unmapped bucket.
_EXECUTE_AXES = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "internal",
}

# Argument keys opportunistically used as target.ref when present and stringy
# (heuristic best-effort only -- Track 4 mappings do this properly per tool).
_REF_ARG_PRIORITY = ("id", "path", "name", "ref", "key")


def classify(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return {"verb", "reversibility", "blast_radius", "externality", "_tier"}
    for one (unmapped) tool call, using the name-prefix heuristic above.

    Pure name-based matching, case-sensitive on the literal prefixes (MCP
    tool names are conventionally snake_case; this is not a general NLP
    classifier -- see the module docstring on Track 4's mapping layer for
    where a smarter/declarative decision would slot in instead of this).

    `_tier` is an internal-only key (popped by classify_call() before the
    result is used) identifying which bucket fired -- "heuristic:delete" /
    "heuristic:create" / "heuristic:read" / "heuristic:default".
    """
    count = magnitude_count(arguments)

    if tool_name.startswith(_DELETE_PREFIXES):
        axes = dict(_AXES_BY_BUCKET["delete"])
        axes["blast_radius"] = _blast_radius_for_count(count)
        return {"verb": "delete", "_tier": "heuristic:delete", **axes}

    if tool_name.startswith(_CREATE_PREFIXES):
        axes = dict(_AXES_BY_BUCKET["create"])
        axes["blast_radius"] = _blast_radius_for_count(count)
        return {"verb": "create", "_tier": "heuristic:create", **axes}

    if tool_name.startswith(_READ_PREFIXES):
        axes = dict(_AXES_BY_BUCKET["read"])
        axes["blast_radius"] = _blast_radius_for_count(count)
        return {"verb": "read", "_tier": "heuristic:read", **axes}

    # Conservative default (SPEC section 2: unknown -> safe-conservative,
    # never omitted). Fixed floor, not magnitude-derived (brief section 8).
    return {"verb": "execute", "_tier": "heuristic:default", **_EXECUTE_AXES}


def classify_call(
    mapping_registry: MappingRegistry | None,
    target_system: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> tuple[dict[str, str], int, str]:
    """The Track 4 3-tier resolution (design doc section 8). Returns
    (classification, magnitude_count, source_tag).

    classification has exactly {"verb", "reversibility", "blast_radius",
    "externality"} -- ready to drop straight into build_envelope()'s action/
    axes. source_tag is one of "mapping" / "heuristic:<bucket>" /
    "heuristic:default" -- see the module docstring.
    """
    if mapping_registry is not None:
        mapped = mapping_registry.classify(target_system, tool_name, arguments)
        if mapped is not None:
            cls, count = mapped
            return cls, count, "mapping"

    cls = dict(classify(tool_name, arguments))
    tier = cls.pop("_tier")
    count = magnitude_count(arguments)
    return cls, count, tier


def magnitude_count(arguments: dict[str, Any]) -> int:
    """First list-valued argument's length, else 1. Never < 1."""
    if isinstance(arguments, dict):
        for value in arguments.values():
            if isinstance(value, list):
                return max(len(value), 1)
    return 1


def _blast_radius_for_count(count: int) -> str:
    """single (1) / scoped (2-20) / broad (>20) -- same thresholds as the
    WordPress reference adapter (reeflex-spec/ADAPTER-EXAMPLES.md section A)."""
    if count > 20:
        return "broad"
    if count > 1:
        return "scoped"
    return "single"


def _guess_ref(arguments: dict[str, Any]) -> str | None:
    """Best-effort target.ref from a plausible identifier argument; None if
    none found (nullable per SPEC section 2 -- never guessed wrong on purpose,
    just omitted)."""
    if not isinstance(arguments, dict):
        return None
    for key in _REF_ARG_PRIORITY:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return None


def build_envelope(
    *,
    session_id: str,
    agent_id: str,
    on_behalf_of: str | None,
    upstream_name: str,
    target_system: str,
    target_environment: str,
    tool_name: str,
    arguments: dict[str, Any],
    mapping_registry: MappingRegistry | None = None,
) -> dict[str, Any]:
    """Build a signed Action Envelope (SPEC section 2) for one `tools/call`.

    tool_name is the REAL upstream tool name (the `<upstream>__` namespace
    prefix already stripped by the caller -- see gateway.py). session_id MUST
    be non-empty (core rejects an empty/missing agent.session_id -- SPEC
    section 4.1 / section 7); this function does not itself default it, the
    caller (gateway.py section 10 session derivation) is responsible for
    always supplying one.

    mapping_registry (Track 4, design doc section 8): when given, a
    declarative mapping for target_system + tool_name takes precedence over
    the heuristic -- see classify_call(). Omitted/None reproduces Track 2's
    heuristic-only behavior exactly.
    """
    if not session_id:
        raise ValueError("session_id is required (SPEC section 4.1/7) -- fail-closed")

    cls, count, classification_source = classify_call(mapping_registry, target_system, tool_name, arguments)

    agent = {
        "id": agent_id,
        "on_behalf_of": on_behalf_of,
        "session_id": session_id,
    }

    action = {
        "namespace": target_system,
        "verb": cls["verb"],
        "ability": f"{target_system}/{tool_name}",
    }

    target = {
        "kind": tool_name,
        "ref": _guess_ref(arguments),
        "environment": target_environment,
    }

    # params: small, structured passthrough -- the raw call arguments plus the
    # upstream name (not backend-specific enough to be its own field, but
    # useful for audit/debugging). Do NOT dump anything beyond the call's own
    # arguments (no full upstream responses, no secrets).
    params = {
        "upstream": upstream_name,
        "tool_name": tool_name,
        "arguments": arguments if isinstance(arguments, dict) else {},
    }

    magnitude = {"count": count}

    axes = {
        "reversibility": cls["reversibility"],
        "blast_radius": cls["blast_radius"],
        "externality": cls["externality"],
    }

    approval = {"present": False, "hold_id": None}

    context = {
        "gateway": "reeflex-mcp",
        "upstream": upstream_name,
        # Track 4 (design doc section 8): "mapping" | "heuristic:<bucket>" |
        # "heuristic:default" -- which tier classified THIS call.
        "classification_source": classification_source,
    }

    ts = _now_utc()
    nonce = _make_nonce(session_id, ts, upstream_name, tool_name)
    meta = {
        "timestamp": ts,
        "nonce": nonce,
        # Envelope signing is a stub across the project pending Vault-backed
        # key management (SPEC section 6 implementation-status note) -- same
        # stub shape as reeflex-claude/envelope.py and reeflex-mock/adapter.py.
        "signature": f"ed25519:stub:{nonce[:16]}",
    }

    return {
        "reeflex_version": _REEFLEX_VERSION,
        "agent": agent,
        "action": action,
        "target": target,
        "params": params,
        "magnitude": magnitude,
        "axes": axes,
        "approval": approval,
        "trajectory_ref": None,
        "context": context,
        "meta": meta,
    }


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_nonce(session_id: str, ts: str, upstream_name: str, tool_name: str) -> str:
    """Replay-resistant nonce -- sha256 of identifying fields + monotonic_ns
    + a uuid4, hex[:32]. mirrors reeflex-claude/envelope.py's shape but adds
    the uuid4 component: `time.monotonic_ns()` alone was observed to return
    the SAME value for two back-to-back calls on this Windows build (coarse
    clock tick), which would have produced a duplicate nonce -- core's nonce
    replay guard (app/envelope.py _check_nonce) would then reject the second
    call as "replay: nonce already seen". The uuid4 component guarantees
    uniqueness independent of clock resolution."""
    raw = f"{session_id}:{ts}:{upstream_name}:{tool_name}:{time.monotonic_ns()}:{uuid.uuid4().hex}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
