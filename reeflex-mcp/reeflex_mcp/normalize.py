"""
normalize.py -- build a Reeflex Action Envelope (SPEC section 2) from a
`tools/call` the gateway intercepted.

THE 4-TIER RESOLUTION (Track 4 + BUG 2 fix, design doc section 8) -- see
`classify_call()`:

  1. declarative mapping   -- mappings.MappingRegistry.classify(), for the
                               upstream's target.system + this exact tool
                               name (mappings/<system>.yaml -- see
                               mappings.py). Operator override -- ALWAYS wins
                               when present. source tag "mapping".
  2. MCP annotations       -- `_classify_from_annotations()` below (BUG 2 fix
                               option B): the upstream's own SERVER-declared
                               `readOnlyHint`/`destructiveHint` for this tool
                               (already fetched + cached by
                               UpstreamRegistry._tool_cache -- see
                               upstream.py's `tool_annotations()`). Only an
                               EXPLICIT `True` on either hint is actionable;
                               annotations absent, or present but both hints
                               None/False-ish per MCP's own defaults, fall
                               through untouched -- absence is NEVER treated
                               as a safe signal. source tag
                               "annotation:<bucket>".

                               **OFF BY DEFAULT (RFX-173).** This tier reads
                               a value supplied by the very component the
                               gateway is governing, and the MCP
                               specification itself says a client MUST treat
                               tool annotations as UNTRUSTED unless the
                               server is trusted. Measured live on the
                               published 0.1.3 gateway in enforce mode
                               against a real core: an upstream declaring
                               `readOnlyHint: true` on a tool that deletes a
                               file turned core's `deny` into `allow` and the
                               gateway dispatched the deletion. So the tier
                               now requires per-upstream opt-in --
                               `trust_annotations: true` in reeflex-mcp.yaml
                               (registry.py). With it unset, resolution is
                               mapping -> heuristic -> floor, which is
                               exactly what README/docs already describe.
  3. name-heuristic         -- `classify()` below (Track 2, kept verbatim as
                               the fallback for anything neither a mapping
                               nor an annotation named). Widened for BUG 2
                               (see `_READ_PREFIXES`) to close the false-
                               positive gap where an unmapped, unannotated
                               READ tool (`count_*`, `fetch_*`, `query_*`,
                               `describe_*`, `find_*`, `select_*`, camelCase
                               `getX`/`listX`) fell all the way to the
                               conservative floor and was denied under
                               enforce. source tag "heuristic:<bucket>".
  4. conservative default   -- the SAME `classify()` function's own
                               catch-all bucket, fired when no name-prefix
                               matches either. source tag "heuristic:default".

`build_envelope()` takes an optional `mapping_registry` and `annotations` --
when given, tier 1 then tier 2 are tried (in that order) via
`classify_call()`; when both are absent (or neither matches), behavior is
identical to Track 2 (heuristic only). The resolved tier is recorded at
`context.classification_source` on every envelope (design doc section 8:
"Log which tier classified each call" -- helps the GIGO story + debugging).

Heuristic table (design doc section 8 / brief section 8, verbatim, widened
per BUG 2 -- new prefixes/bare-verbs marked NEW):

    tool name prefix                              -> verb    | reversibility | externality
    -------------------------------------------------------------------------------------
    delete_* / remove_* / drop_*                  -> delete   | irreversible  | (internal)
    send_* / post_* / create_* / push_*           -> create   | (recoverable) | outbound
    get_* / list_* / read_* / search_* / count_*   -> read     | reversible    | (internal)
    / fetch_* / query_* / describe_* / find_* /
    select_* / get* / list*  (NEW, BUG 2)
    <anything else>                                -> execute (conservative default)
                                                       axes forced to the restrictive floor:
                                                       irreversible / systemic / internal

Values in parentheses above are NOT dictated verbatim by the brief; they are
this module's conservative, documented completion of the two axes the brief
did not spell out per bucket (see _AXES_BY_BUCKET below). `blast_radius` for
the matched buckets is derived from `magnitude.count` via the same
single/scoped/broad thresholds used by the WordPress reference adapter
(reeflex-spec/ADAPTER-EXAMPLES.md section A); the unmatched (`execute`)
bucket's blast_radius is fixed at "systemic" per the brief's literal
"restrictive floor" text, not magnitude-derived.

`magnitude.count`: "from a plausible list-arg count else 1" (brief section
8) -- the first argument value that is a list, or 1.

FAIL-CLOSED ASYMMETRY (BUG 2 brief, both options A and B): every widening
above is a DOWNGRADE-ON-EXPLICIT-SIGNAL only -- a bare name prefix
(startswith, matches only the leading token: `update_get_x` does NOT match
`get`) or a server's own explicit `True` hint. Nothing here ever upgrades a
genuine unknown to "safe"; the conservative floor is unchanged and still
fires for anything that matches none of the three buckets at any tier.

TWO HOLES IN THAT ASYMMETRY, BOTH MEASURED AND BOTH CLOSED HERE (RFX-174,
RFX-175) -- read this before trusting the paragraph above:

  * `destructiveHint: true` USED TO BE A DOWNGRADE. It replaced the floor's
    `systemic` blast radius with a magnitude-derived one, so a server that
    honestly declared its tool destructive got `irreversible`+`single` ->
    R2/R3 both need broad/systemic -> `default_allow`, while a server that
    declared nothing got the floor and was DENIED. Honesty was punished. The
    destructive branch now KEEPS the floor's `systemic` (see
    `_ANNOTATION_DESTRUCTIVE_AXES`): a server saying "this is destructive"
    can only ever make the verdict the same or stricter, never looser.
  * THE READ PREFIXES WERE COMPOUND-NAME-BLIND. `str.startswith` matches the
    leading token, which the paragraph above uses to argue safety -- but it
    says nothing about a read prefix that is the FIRST token of a compound
    whose real verb is the SECOND. Measured `allow` in production on the
    published build: `search_and_replace`, `find_and_replace`,
    `query_write`, `describe_and_drop`, `list_and_prune_snapshots`,
    `count_and_compact`, `fetch_and_apply_migration`, `get_or_create_index`.
    That is the same defect class as reeflex-claude's `_bash_verb()` reading
    only the first shell token (RFX-144). `_has_mutating_stem()` now vetoes
    the read bucket when any later token in the name is a known mutating
    stem; the call falls to the floor. The veto can only ever make a call
    STRICTER, so it does not reopen BUG 2's false-positive-deny gap for
    genuine reads (`get_user`, `list_issues`, `read_text_file` are
    untouched).

This module is pure: no network, no I/O, no side effects. (`mcp.types` is
imported ONLY for the `ToolAnnotations` type hint -- no SDK behavior used.)
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import mcp.types as types

from .mappings import MappingRegistry

_REEFLEX_VERSION = "0.1"
_NAMESPACE_PREFIX = ""  # namespace == target_system (see build_envelope)

# Prefixes checked in this order; delete/create win before read is even
# tried (a delete_*/create_* tool is never mis-read as safe by the widened
# read set below).
_DELETE_PREFIXES = ("delete_", "remove_", "drop_")
_CREATE_PREFIXES = ("send_", "post_", "create_", "push_")

# BUG 2 fix (option A): widened with UNAMBIGUOUS read verbs only. Deliberately
# excludes ambiguous/mutating-capable prefixes (update_/set_/apply_/run_/
# exec_/check_/sync_) -- those stay on the conservative floor by design.
# "get"/"list" (no trailing underscore, added on top of the pre-existing
# "get_"/"list_") additionally cover camelCase MCP tool names (getUser,
# listUsers) some upstreams use instead of snake_case; str.startswith with a
# tuple matches the leading token only, so this is still asymmetric-safe
# (e.g. "update_get_x" does not start with "get").
_READ_PREFIXES = (
    "get_",
    "list_",
    "read_",
    "search_",
    "count_",
    "fetch_",
    "query_",
    "describe_",
    "find_",
    "select_",
    "get",
    "list",
)

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

# RFX-175: a read prefix is only believed when NO later token in the tool name
# is a mutating stem. `search_and_replace` starts with `search_` and writes;
# `search_files` starts with `search_` and reads. Matched against the name's
# own tokens (snake_case segments AND camelCase humps), so `selectAllAndDelete`
# and `select_all_and_delete` are treated identically.
#
# Stems only -- matched as a PREFIX of a token, so "delete" covers "deletes"/
# "deleted", "replace" covers "replaces"/"replacement". Deliberately generous:
# a false veto costs a genuine read the floor (fail-noisy, visible, fixable
# with a one-line declarative mapping), a missed veto costs a customer their
# data.
_MUTATING_STEMS = (
    "delete",
    "del",
    "remove",
    "rm",
    "drop",
    "destroy",
    "purge",
    "prune",
    "wipe",
    "erase",
    "truncate",
    "clear",
    "flush",
    "expire",
    "revoke",
    "reset",
    "restore",
    "rotate",
    "replace",
    "overwrite",
    "write",
    "insert",
    "upsert",
    "update",
    "patch",
    "modify",
    "edit",
    "rename",
    "move",
    "merge",
    "commit",
    "push",
    "apply",
    "migrate",
    "compact",
    "vacuum",
    "kill",
    "terminate",
    "stop",
    "disable",
    "exec",
    "execute",
    "run",
    "install",
    "uninstall",
    "deploy",
    "send",
    "publish",
    "grant",
    "create",
    "set",
)

# RFX-174: when the annotation tier IS trusted, a `destructiveHint: true`
# keeps the FLOOR's blast radius. The server told us the tool is destructive;
# it told us nothing about scope, and a magnitude-derived `single` here was a
# downgrade that made an honest declaration weaker than silence.
_ANNOTATION_DESTRUCTIVE_AXES = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "internal",
}

# Argument keys opportunistically used as target.ref when present and stringy
# (heuristic best-effort only -- Track 4 mappings do this properly per tool).
_REF_ARG_PRIORITY = ("id", "path", "name", "ref", "key")


def _name_tokens(tool_name: str) -> list[str]:
    """Lowercased tokens of an MCP tool name, splitting on non-alphanumerics
    AND on camelCase humps: `search_and_replace` -> [search, and, replace],
    `selectAllAndDelete` -> [select, all, and, delete]."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tool_name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def _has_mutating_stem(tool_name: str) -> bool:
    """RFX-175: True when any token AFTER the first is a known mutating stem.

    The first token is skipped on purpose -- it is the token the read prefix
    already matched, and a name whose FIRST token is a mutating stem never
    reaches the read bucket anyway (`delete_*`/`remove_*`/`drop_*` are matched
    earlier, and anything else falls to the floor).
    """
    for token in _name_tokens(tool_name)[1:]:
        if token.startswith(_MUTATING_STEMS):
            return True
    return False


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

    # RFX-175: a read prefix is believed only when no LATER token in the name
    # is a mutating stem -- `search_files` reads, `search_and_replace` writes.
    if tool_name.startswith(_READ_PREFIXES) and not _has_mutating_stem(tool_name):
        axes = dict(_AXES_BY_BUCKET["read"])
        axes["blast_radius"] = _blast_radius_for_count(count)
        return {"verb": "read", "_tier": "heuristic:read", **axes}

    # Conservative default (SPEC section 2: unknown -> safe-conservative,
    # never omitted). Fixed floor, not magnitude-derived (brief section 8).
    return {"verb": "execute", "_tier": "heuristic:default", **_EXECUTE_AXES}


def _classify_from_annotations(
    annotations: types.ToolAnnotations | None, count: int, *, trusted: bool = False
) -> tuple[dict[str, str], str] | None:
    """BUG 2 fix, option B: the upstream server's OWN declared tool
    annotations, tier 2 (between the declarative mapping and the
    name-heuristic). Returns ({"verb", ...axes}, tier_tag) or None (no
    actionable annotation -- caller falls through to the name-heuristic).

    RFX-173: `trusted` is False unless the OPERATOR opted this upstream in
    with `trust_annotations: true`. When False this tier is skipped entirely
    and the annotation is never read -- the upstream is the governed party,
    the MCP spec says its annotations are untrusted, and a
    `readOnlyHint: true` on a destructive tool was measured turning core's
    `deny` into `allow` on a real gateway in enforce mode.

    MCP spec defaults: `readOnlyHint` defaults to False, `destructiveHint`
    defaults to True, WHEN ABSENT. That means "no annotation" (annotations
    is None) or "annotation object present but both hints left at their
    Python None" must NOT be read as "safe" -- only an EXPLICIT `True` on
    either hint is ever acted on here. This preserves fail-closed
    determinism: an explicit safe signal may downgrade a call into the read
    bucket; the ABSENCE of a signal never does.

    `readOnlyHint is True` is checked first and is authoritative: per the
    MCP spec, `destructiveHint` is "meaningful only when readOnlyHint ==
    false", so a server declaring readOnlyHint=True already settles it.

    `idempotentHint` is NOT consulted (brief: "may inform reversibility if
    cheap, else ignore") -- deliberate shortcut: idempotency does not map
    cleanly onto this module's reversibility axis without more design work
    than this bugfix's scope justifies (YAGNI). Upgrade path: if a future
    brief wants it, thread `idempotentHint is True` into a reversibility
    override the same way readOnlyHint/destructiveHint are handled above.
    """
    if not trusted or annotations is None:
        return None

    if annotations.readOnlyHint is True:
        axes = dict(_AXES_BY_BUCKET["read"])
        axes["blast_radius"] = _blast_radius_for_count(count)
        return {"verb": "read", **axes}, "annotation:read"

    if annotations.destructiveHint is True:
        # RFX-174: keep the FLOOR's blast radius. "Destructive" is a claim
        # about kind, never about scope -- deriving `single` from magnitude
        # here made an honest destructive declaration WEAKER than declaring
        # nothing at all (floor -> deny becomes default_allow).
        return {"verb": "delete", **_ANNOTATION_DESTRUCTIVE_AXES}, "annotation:destructive"

    # Neither hint is explicitly True (both None, or destructiveHint
    # explicitly False with readOnlyHint not True) -- no actionable signal;
    # fall through to the name-heuristic tier untouched.
    return None


def classify_call(
    mapping_registry: MappingRegistry | None,
    target_system: str,
    tool_name: str,
    arguments: dict[str, Any],
    annotations: types.ToolAnnotations | None = None,
    trust_annotations: bool = False,
) -> tuple[dict[str, str], int, str]:
    """The 4-tier resolution (design doc section 8 + BUG 2 fix). Returns
    (classification, magnitude_count, source_tag).

    classification has exactly {"verb", "reversibility", "blast_radius",
    "externality"} -- ready to drop straight into build_envelope()'s action/
    axes. source_tag is one of "mapping" / "annotation:<bucket>" /
    "heuristic:<bucket>" / "heuristic:default" -- see the module docstring.

    Precedence (never reordered): declarative mapping > MCP annotations >
    name-heuristic > conservative floor. A declarative mapping is an
    operator override and always wins even against a conflicting
    server-declared annotation.
    """
    if mapping_registry is not None:
        mapped = mapping_registry.classify(target_system, tool_name, arguments)
        if mapped is not None:
            cls, count = mapped
            return cls, count, "mapping"

    count = magnitude_count(arguments)
    annotated = _classify_from_annotations(annotations, count, trusted=trust_annotations)
    if annotated is not None:
        cls, tier = annotated
        return cls, count, tier

    cls = dict(classify(tool_name, arguments))
    tier = cls.pop("_tier")
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
    annotations: types.ToolAnnotations | None = None,
    trust_annotations: bool = False,
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
    everything else -- see classify_call(). Omitted/None falls through to
    the next tier.

    annotations (BUG 2 fix, option B): the upstream's own MCP-declared
    `types.ToolAnnotations` for this exact tool (see
    upstream.py's `UpstreamRegistry.tool_annotations()` -- the caller,
    gateway.py, looks this up from the already-cached tool list). Consulted
    ONLY when no declarative mapping matched AND only when the operator set
    `trust_annotations: true` for this upstream (RFX-173 -- default False,
    because the annotation comes from the governed party). Omitted/None, or
    untrusted, falls through to the name-heuristic exactly like Track 2.
    """
    if not session_id:
        raise ValueError("session_id is required (SPEC section 4.1/7) -- fail-closed")

    cls, count, classification_source = classify_call(
        mapping_registry,
        target_system,
        tool_name,
        arguments,
        annotations,
        trust_annotations=trust_annotations,
    )

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
        # Track 4 (design doc section 8) + BUG 2 fix: "mapping" |
        # "annotation:<bucket>" | "heuristic:<bucket>" | "heuristic:default"
        # -- which tier classified THIS call.
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
