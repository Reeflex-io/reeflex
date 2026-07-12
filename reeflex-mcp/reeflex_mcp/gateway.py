"""
gateway.py -- the MCP "front": a single FastMCP server exposing the union of
every connected upstream's tools (namespaced `<upstream>__<tool>`), gating
every `tools/call` through reeflex-core, dual transport (stdio | streamable-
HTTP). Everything else (`initialize`, `tools/list`, notifications, unknown
methods) passes through unmodified -- Track 2 does not proxy resources/
prompts (see "Track 2 scope note" below); no client in this build's E2E
target advertises any, and the gateway simply never claims that capability,
which is a form of "pass through unmodified" rather than gating anything.

WHY THE LOW-LEVEL SERVER HANDLERS, NOT `@mcp.tool()`
-----------------------------------------------------
FastMCP's own `@mcp.tool()` decorator infers a JSON schema from a Python
function's type hints -- it assumes a FIXED, statically-known tool set (this
is exactly right for reeflex-holds, which has 4 fixed tools). This gateway's
tool set is discovered at runtime from N upstreams and must pass upstream
JSON schemas through verbatim ("zero hardcoded tool knowledge" -- design doc
section 6). The MCP Python SDK's supported way to do this is to register
handlers directly on the low-level `Server` a FastMCP instance wraps
(`FastMCP._mcp_server`, a `mcp.server.lowlevel.Server`) via its own
`list_tools()` / `call_tool()` decorators -- confirmed by reading
`FastMCP._setup_handlers()` (mcp/server/fastmcp/server.py) while building
this package: FastMCP registers `self._mcp_server.list_tools()(self.list_tools)`
and `self._mcp_server.call_tool(validate_input=False)(self.call_tool)` itself,
storing the handler in a plain dict (`Server.request_handlers[RequestType]`).
Calling those same decorators again with OUR handlers overwrites the entry
(last registration wins, verified against `Server.list_tools`/`call_tool`
source) -- FastMCP is still used for its transport plumbing (`streamable_http_app()`,
`run_stdio_async()`), we just replace how it answers `tools/list`/`tools/call`.

SECTION 21.1 -- THE HTTP-FRONT LIFESPAN FIX (verified against mcp 1.28.1 /
starlette 1.3.1 source while building this package, not just trusted from the
spike notes):
  - `FastMCP(lifespan=...)` becomes the LOW-LEVEL `Server`'s `self.lifespan`,
    entered inside `Server.run()` (`async with self.lifespan(self) as ...`).
  - `StreamableHTTPSessionManager._handle_stateful_request` calls
    `self.app.run(...)` (i.e. `Server.run()`) ONCE PER NEW HTTP SESSION (a
    fresh task per session id). So `FastMCP(lifespan=...)` fires per-session
    on streamable-HTTP -- confirmed, not just asserted.
  - The Starlette app's OWN ASGI lifespan (`Starlette(..., lifespan=lambda
    app: self.session_manager.run())`, set on `app.router.lifespan_context`
    by `Router.__init__`) is entered exactly ONCE by the ASGI server (uvicorn)
    for the whole process's lifetime -- this is the process-level lifespan
    that must own upstream connect/close.
  - Fix: never pass `lifespan=` to FastMCP. Build the app via
    `mcp.streamable_http_app()`, save `app.router.lifespan_context`, and
    replace it with a wrapper that connects all upstreams before entering the
    original lifespan and closes them after it exits. See `run_streamable_http()`.

TRACK 3 -- full enforce-mode verdict -> MCP mapping + hold/resubmission
------------------------------------------------------------------------
`observe` mode is UNCHANGED from Track 2 (design doc section 15: observe must
never break traffic) -- `_handle_call_tool` still just calls core, always
forwards, fails OPEN, and tags `gateway_correlation_id` only.

`enforce` mode is now the FULL design doc section 9 mapping, wired to core's
landed `decision_id`/`parent_decision_id` traceability (ADDENDUM v1.3 section
22, commit 92abbcb):
  - allow            -> forward; tag core's `decision_id` (+ `parent_decision_id`
                        when core returns one, i.e. on an approved resubmission)
                        on the result `_meta`, alongside `gateway_correlation_id`.
  - deny             -> `CallToolResult(isError=True)`, text carries `rule` +
                        `reason` + `decision_id`. Never forwarded.
  - require_approval -> `CallToolResult(isError=True)`, text carries `hold_id`
                        + `expires_ts` + `decision_id` + the instruction to
                        resolve via reeflex-holds then retry. The gateway
                        remembers this hold (`holds_tracker.PendingHoldTracker`,
                        keyed by `(session_id, canonical.canonical_hash(envelope))`
                        -- the SAME projection core binds a hold's approval to,
                        SPEC section 5.1) so the client's retry of the exact
                        same action is recognized as a resubmission.
  - core unreachable/error -> FAIL CLOSED (block), same as Track 2.

RESUBMISSION, discovered empirically (not assumed from the brief) while
building this track's E2E against the landed core code
(reeflex-core/app/decide.py `_validate_approval`): a resubmission
(`approval.present=true`) is NEVER re-evaluated by OPA/cumulative logic --
`_validate_approval`'s six-check chain is the ENTIRE decision for that
request. Critically, **a resubmission whose hold is still `pending` (not yet
resolved by a human) returns `deny` with reason `"reeflex_hold_not_approved"`
and rule `"reeflex.core/hold_validation"` -- NOT `require_approval` again.**
The gateway must recognize this specific (rule, reason) pair when it still
has a locally-tracked pending hold for this action and re-surface the SAME
hold (never spawn a duplicate, never treat it as a terminal denial) --
anything else (rejected/expired/consumed/envelope-mismatch/actor-is-approver/
any ordinary policy deny) is a genuine terminal deny, and clears the local
pending-hold entry. See `_classify_enforce_verdict` for the pure (I/O-free,
directly unit-testable) mapping logic, and `_handle_call_tool` for where its
`store_pending`/`clear_pending` instructions are applied and the actual
upstream dispatch happens.

Core never executes -- the gateway executes the underlying tool call only
after core returns `allow` (original or resubmitted).

TRACK 4 -- declarative mappings (design doc section 8)
--------------------------------------------------------
The Gateway loads ONE `mappings.MappingRegistry` at construction (`self.mappings`,
via `registry.effective_mappings_dir()` -- YAML `mappings_dir:` key, or
`REEFLEX_MCP_MAPPINGS_DIR` env, or this package's own bundled filesystem/
github/postgres starters) and passes it into every `normalize.build_envelope()`
call, in BOTH modes. This is the only Track 4 change to the call path itself
-- the 3-tier resolution (declarative mapping -> name-heuristic -> conservative
default) lives in normalize.py/mappings.py; the gateway just supplies the
registry and logs which tier fired (stderr, `classification_source`) for the
GIGO story / debugging (design doc section 8: "Log which tier classified
each call").

TRACK 5.1 -- obligations, read/honor-known/fail-closed-unknown (design doc
ADDENDUM v1.5 section 25; SPEC section 5/7 minimum #5)
------------------------------------------------------------------------
Conformance-verifier finding: nothing read `decision["obligations"]` at all
-- SPEC section 5: "An adapter that ignores an obligation is non-conformant."
Fixed here, wired to the SAME point in both modes where the verdict is
already known:
  enforce: right after `_classify_enforce_verdict()` returns action=="forward"
    (i.e. the verdict was allow, original OR approved_resubmission) and
    BEFORE `_dispatch_and_tag()` -- `_apply_enforce_obligations()` iterates
    `decision["obligations"]`; a KNOWN obligation (obligations.py's
    registry) is applied via its handler, an UNKNOWN one blocks the call
    right there (isError, never dispatched) -- the gateway never silently
    forwards past an obligation it cannot honor.
  observe: `_record_observed_obligations()` logs every obligation on every
    decision (any verdict -- observe forwards regardless of verdict anyway)
    as "would-honor", then the existing always-forward behavior proceeds
    unchanged. Recording, not applying: observe never enforces ANYTHING, so
    it must not actually invoke a handler's side effects for a call that
    might not really be authorized -- but logging is how it avoids
    SILENTLY DROPPING the obligation, which is what SPEC section 5 actually
    forbids.
See obligations.py for the handler registry / dispatch mechanism itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from . import canonical, config, core_client, mappings, normalize
from . import obligations as obligations_mod
from . import registry as regcfg
from .holds_tracker import PendingHold, PendingHoldTracker
from .upstream import UpstreamBootError, UpstreamRegistry, UpstreamUnavailableError

_INSTRUCTIONS = (
    "Reeflex MCP gateway. Exposes the union of every configured upstream's "
    "tools, namespaced '<upstream>__<tool>'. Every tools/call is normalized "
    "into a Reeflex Action Envelope and submitted to reeflex-core's "
    "/v1/decide before being forwarded -- zero LLM anywhere near that "
    "decision. In the default 'observe' mode the verdict is recorded but "
    "never blocks; 'enforce' mode applies it: allow forwards, deny blocks, "
    "require_approval holds (resolve via reeflex-holds, then retry the same "
    "call), and reeflex-core being unreachable fails closed."
)


# ---------------------------------------------------------------------------
# Front-session registry -- section 21.3: tools/list_changed re-emit is NOT
# automatic; the gateway must track its own connected front sessions.
# ---------------------------------------------------------------------------


class FrontSessionRegistry:
    """Every ServerSession that has called `tools/list` at least once (i.e.
    every real front connection). Used only to re-broadcast
    `notifications/tools/list_changed` when an upstream's tool set changes."""

    def __init__(self) -> None:
        self._sessions: set[Any] = set()

    def register(self, session: Any) -> None:
        self._sessions.add(session)

    async def broadcast_tools_list_changed(self) -> None:
        dead = []
        for session in list(self._sessions):
            try:
                await session.send_tool_list_changed()
            except Exception:  # noqa: BLE001 -- a dead/closing session, prune it
                dead.append(session)
        for session in dead:
            self._sessions.discard(session)


# ---------------------------------------------------------------------------
# Result helpers -- section 21.4: isError must be propagated, never flattened
# ---------------------------------------------------------------------------


def _error_result(message: str, *, gateway_correlation_id: str | None = None) -> types.CallToolResult:
    meta = {"gateway_correlation_id": gateway_correlation_id} if gateway_correlation_id else None
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
        _meta=meta,
    )


def _tag_result(
    result: types.CallToolResult,
    gateway_correlation_id: str,
    *,
    decision_id: str | None = None,
    parent_decision_id: str | None = None,
) -> types.CallToolResult:
    """A NEW CallToolResult carrying the upstream's content/isError/
    structuredContent completely unmodified, plus correlation/decision ids
    merged into _meta. isError is never re-derived here -- whatever the
    upstream set (True or False) is what ships back to the front client.

    decision_id/parent_decision_id (Track 3, design doc section 22): core's
    OWN traceability id for this /v1/decide transit -- tagged here (allow
    path only) alongside the gateway-local `gateway_correlation_id`, exactly
    as the brief specifies. parent_decision_id is present only on an approved
    resubmission (core's own response only carries it there)."""
    merged_meta = dict(result.meta or {})
    merged_meta["gateway_correlation_id"] = gateway_correlation_id
    if decision_id:
        merged_meta["decision_id"] = decision_id
    if parent_decision_id:
        merged_meta["parent_decision_id"] = parent_decision_id
    return types.CallToolResult(
        content=result.content,
        structuredContent=result.structuredContent,
        isError=result.isError,
        _meta=merged_meta,
    )


# ---------------------------------------------------------------------------
# Enforce-mode verdict mapping -- pure (no I/O), directly unit-testable.
# Track 3 / design doc section 9, wired to section 22 (decision_id/
# parent_decision_id) and the empirically-discovered resubmission semantics
# (see module docstring).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnforceOutcome:
    action: str  # "forward" | "block"
    message: str | None  # error text for the front client, set iff action == "block"
    decision_id: str
    parent_decision_id: str | None
    store_pending: PendingHold | None  # caller should tracker.put(...) this, if set
    clear_pending: bool  # caller should tracker.clear(...), if True


# ---------------------------------------------------------------------------
# The Gateway
# ---------------------------------------------------------------------------


class Gateway:
    def __init__(self, gw_config: regcfg.GatewayConfig):
        self.gw_config = gw_config
        self.mode = regcfg.effective_mode(gw_config)
        self.front_sessions = FrontSessionRegistry()
        self.upstreams = UpstreamRegistry(
            list(gw_config.upstreams),
            on_tools_changed=self.front_sessions.broadcast_tools_list_changed,
        )
        # section 10: stdio front = one connection = one agent = one
        # session_id, minted per gateway process start (stable for its life).
        self._stdio_session_id = f"mcp-gateway:{uuid.uuid4().hex}"

        # Track 3: enforce-mode hold/resubmission tracking (process-local,
        # best-effort -- see holds_tracker.py module docstring). Unused in
        # observe mode.
        self.pending_holds = PendingHoldTracker()

        # Track 4 (design doc section 8): loaded ONCE at construction, used
        # by every tools/call regardless of mode -- see module docstring.
        self.mappings = mappings.load_mappings_dir(regcfg.effective_mappings_dir(gw_config))

        self.mcp = FastMCP("reeflex-mcp", instructions=_INSTRUCTIONS)
        self._wire_handlers()
        self._wire_admin()

    # -- wiring --------------------------------------------------------

    def _wire_handlers(self) -> None:
        server = self.mcp._mcp_server  # low-level Server -- see module docstring

        @server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:  # noqa: ANN202
            try:
                session = server.request_context.session
                self.front_sessions.register(session)
            except LookupError:
                pass
            return self.upstreams.aggregated_tools()

        @server.call_tool(validate_input=False)
        async def handle_call_tool(name: str, arguments: dict) -> types.CallToolResult:  # noqa: ANN202
            return await self._handle_call_tool(name, arguments or {})

    def _wire_admin(self) -> None:
        """Track 5 (design doc section 13) `add`/`import` hot-reload: a
        minimal admin HTTP route, streamable-HTTP front ONLY (registered via
        `custom_route()`, so it is inert on stdio -- `mcp.streamable_http_app()`
        is the only thing that ever turns custom routes into a servable ASGI
        route; stdio's `run_stdio_async()` never touches them). stdio has
        exactly one client anyway, and a config change there needs a client
        restart regardless (which restarts the gateway too -- the same
        natural trigger point `doctor`'s drift check runs at).

        NOT file-watching (design doc section 13's YAGNI call, honored here
        too): this fires ONLY when explicitly POSTed to by the `add`/`import`
        CLI commands -- no timer, no background thread, no polling.

        Scope, deliberately narrow: adds NEWLY-named upstreams found in a
        freshly-reloaded reeflex-mcp.yaml. Does NOT remove upstreams, does
        NOT reconfigure existing ones (mode/mappings_dir changes need a
        restart) -- "add", not "reconfigure".

        Optional shared-token gate (REEFLEX_MCP_ADMIN_TOKEN): if set, the
        request must carry a matching 'Authorization: Bearer <token>' header.
        This route reconnects upstream processes on request, a meaningfully
        privileged operation -- unset (the default) means no auth, matching
        this project's other optional-auth knobs (e.g. reeflex-core's own
        REEFLEX_AUTH_TOKEN); acceptable for a gateway bound to 127.0.0.1 (the
        config default) -- widening REEFLEX_MCP_HOST without setting this
        token is the operator's own risk to take, not this gateway's default.
        """
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        @self.mcp.custom_route("/admin/reload", methods=["POST"])
        async def admin_reload(request: Request) -> JSONResponse:  # noqa: ANN202
            expected = os.environ.get("REEFLEX_MCP_ADMIN_TOKEN", "").strip()
            if expected:
                auth_header = request.headers.get("authorization", "")
                provided = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
                if not hmac.compare_digest(provided, expected):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)

            try:
                fresh_config = regcfg.load_config(self.gw_config.source_path)
            except regcfg.ConfigError as exc:
                return JSONResponse({"error": "invalid_config", "detail": str(exc)}, status_code=400)

            # Diff against SUCCESSFULLY-CONNECTED names, not merely "known"
            # ones -- a previously-failed hot-add (e.g. a typo'd command)
            # still occupies a registry slot and must remain retryable on
            # the next reload, once the operator fixes reeflex-mcp.yaml.
            up = self.upstreams.up_upstream_names()
            new_specs = [u for u in fresh_config.upstreams if u.name not in up]
            if not new_specs:
                return JSONResponse({"added": [], "failed": [], "note": "no new upstreams found in config"})

            added: list[str] = []
            failed: list[dict] = []
            for spec in new_specs:
                ok, err = await self.upstreams.connect_one(
                    spec, connect_timeout=config.upstream_connect_timeout_seconds()
                )
                if ok:
                    added.append(spec.name)
                else:
                    failed.append({"name": spec.name, "error": err})

            if added:
                await self.front_sessions.broadcast_tools_list_changed()

            return JSONResponse({"added": added, "failed": failed})

    # -- section 10: session/agent derivation ---------------------------

    def _derive_session_and_agent(self) -> tuple[str, str, str | None]:
        """Returns (session_id, agent_id, on_behalf_of). session_id is NEVER
        empty (core requires it -- SPEC section 4.1/7).

        Honest limitation (documented, not hidden): this is the section-10/14
        SCAFFOLD. Full mTLS-based client identity is a future upgrade; today
        an HTTP front client is identified either by a configured bearer
        token (registry.py `clients:`) or, failing that, by the transport's
        own `Mcp-Session-Id` -- stable per connection, but anonymous.
        """
        try:
            ctx = self.mcp._mcp_server.request_context
        except LookupError:
            ctx = None

        http_request = getattr(ctx, "request", None) if ctx is not None else None
        if http_request is None:
            # stdio front -- process-scoped identity (section 10.1).
            return self._stdio_session_id, "agent:mcp-client", None

        bearer = None
        auth_header = http_request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            bearer = auth_header[7:].strip()

        if bearer:
            mapped = regcfg.session_id_for_token(self.gw_config, bearer)
            if mapped:
                # Configured identity: use it for both fields (registry.py's
                # `clients:` schema does not yet carry a separate display
                # name -- a future config extension, not built here).
                return mapped, mapped, None

        transport_session_id = http_request.headers.get("mcp-session-id", "").strip()
        if transport_session_id:
            return f"mcp-http:{transport_session_id}", "agent:mcp-client", None

        # Extremely unlikely (would mean tools/call arrived before a session
        # id was ever minted) -- still never empty: a random, unstable id
        # rather than silently reusing another connection's identity.
        return f"mcp-http:unmapped:{uuid.uuid4().hex}", "agent:mcp-client", None

    # -- the decide hook (Track 2 acceptance) ---------------------------

    async def _decide(self, envelope: dict) -> tuple[dict | None, str | None]:
        """POST /v1/decide off the event loop thread. Returns (decision, note).
        decision is None on ANY failure (note explains why) -- callers must
        treat None as "core unreachable/error", never invent an allow."""
        try:
            decision = await asyncio.wait_for(
                asyncio.to_thread(core_client.decide, envelope),
                timeout=config.core_timeout_seconds() + 1.0,
            )
            return decision, None
        except (core_client.CoreConnectionError, core_client.CoreAPIError) as exc:
            return None, str(exc)
        except asyncio.TimeoutError:
            return None, "reeflex-core call timed out"
        except Exception as exc:  # noqa: BLE001 -- never let a decide-path bug crash the call
            return None, f"unexpected error calling reeflex-core: {exc}"

    def _apply_mode_observe(self, decision: dict | None, note: str | None) -> tuple[str, str | None]:
        """observe mode -- UNCHANGED from Track 2 (design doc section 15:
        observe must never break traffic). Returns (action, block_reason);
        action is ALWAYS "forward" here -- kept as a small function (rather
        than inlined) purely for parity with the enforce-side mapping and so
        it stays independently unit-testable."""
        if decision is None:
            print(
                f"[reeflex-mcp] WARN: observe mode -- reeflex-core unreachable/error, "
                f"forwarding anyway (fail-open): {note}",
                file=sys.stderr,
            )
        return "forward", None

    def _classify_enforce_verdict(
        self,
        decision: dict | None,
        note: str | None,
        pending: PendingHold | None,
    ) -> EnforceOutcome:
        """Pure verdict -> outcome mapping for enforce mode (design doc
        section 9, wired to section 22's decision_id/parent_decision_id).
        No I/O, no mutation of self.pending_holds -- the caller applies
        store_pending/clear_pending. See module docstring for the full
        allow/deny/require_approval mapping and the empirically-discovered
        "still pending" resubmission case.
        """
        if decision is None:
            # core unreachable/error -> FAIL CLOSED. Never forward.
            return EnforceOutcome(
                action="block",
                message=f"reeflex-mcp: reeflex-core unreachable -- failing closed: {note}",
                decision_id="",
                parent_decision_id=None,
                store_pending=None,
                clear_pending=False,
            )

        verdict = decision.get("decision")
        decision_id = decision.get("decision_id") or ""
        rule = decision.get("rule", "unknown")
        reason = decision.get("reason", "")

        if verdict == "allow":
            parent_decision_id = decision.get("parent_decision_id") or None
            return EnforceOutcome(
                action="forward",
                message=None,
                decision_id=decision_id,
                parent_decision_id=parent_decision_id,
                store_pending=None,
                # Clear any pending entry for this action -- an approved
                # resubmission just consumed it (core marked the hold
                # "consumed" on its side too); a fresh non-hold allow has no
                # pending entry to clear either way (clear() is a no-op miss).
                clear_pending=(pending is not None),
            )

        if verdict == "require_approval":
            hold_id = decision.get("hold_id") or ""
            expires_ts = decision.get("expires_ts") or ""
            new_pending = (
                PendingHold(hold_id=hold_id, decision_id=decision_id, expires_ts=expires_ts, rule=rule, reason=reason)
                if hold_id
                else None
            )
            message = (
                f"reeflex-mcp: held for approval -- {reason} [rule={rule}] "
                f"hold_id={hold_id} expires_ts={expires_ts} decision_id={decision_id}. "
                "Resolve via reeflex-holds (list_holds -> resolve_hold), then retry this exact call."
            )
            return EnforceOutcome(
                action="block",
                message=message,
                decision_id=decision_id,
                parent_decision_id=None,
                store_pending=new_pending,
                clear_pending=False,
            )

        if verdict == "deny":
            if pending is not None and rule == "reeflex.core/hold_validation" and reason == "reeflex_hold_not_approved":
                # Discovered empirically (Track 3 E2E against the landed core
                # code, decide.py `_validate_approval`): a resubmission whose
                # hold is still pending denies with THIS exact (rule, reason)
                # pair -- it does NOT return require_approval again. Re-surface
                # the SAME hold (never spawn a duplicate); this is NOT a
                # terminal denial, so the local pending entry is kept.
                message = (
                    f"reeflex-mcp: still held for approval (not yet resolved) -- "
                    f"hold_id={pending.hold_id} expires_ts={pending.expires_ts} "
                    f"decision_id={decision_id} (original decision_id={pending.decision_id}). "
                    "Resolve via reeflex-holds (list_holds -> resolve_hold), then retry this exact call."
                )
                return EnforceOutcome(
                    action="block",
                    message=message,
                    decision_id=decision_id,
                    parent_decision_id=None,
                    store_pending=None,
                    clear_pending=False,
                )
            # Terminal deny: rejected/expired/consumed/envelope-mismatch/
            # actor-is-approver/an ordinary policy deny (including
            # "reeflex.policy/frozen" -- relayed transparently, no
            # gateway-side freeze logic)/R3 systemic-irreversible-prod, etc.
            message = f"reeflex-mcp: denied -- {reason} [rule={rule}] decision_id={decision_id}"
            return EnforceOutcome(
                action="block",
                message=message,
                decision_id=decision_id,
                parent_decision_id=None,
                store_pending=None,
                clear_pending=(pending is not None),
            )

        # Unknown/unexpected decision value -- fail closed, never guess allow.
        return EnforceOutcome(
            action="block",
            message=f"reeflex-mcp: unknown decision value {verdict!r} from reeflex-core -- failing closed "
                     f"decision_id={decision_id}",
            decision_id=decision_id,
            parent_decision_id=None,
            store_pending=None,
            clear_pending=(pending is not None),
        )

    # -- Track 5.1: obligations (design doc section 25 / SPEC section 5) ----

    def _apply_enforce_obligations(
        self,
        decision: dict | None,
        *,
        envelope: dict,
        upstream_name: str,
        tool_name: str,
        gateway_correlation_id: str,
    ) -> str | None:
        """Called ONLY when the enforce-mode verdict was allow (original or
        approved_resubmission) -- i.e. right before the call would be
        dispatched. Iterates `decision["obligations"]` (SPEC section 5, a
        list of strings): a KNOWN one is applied via its registered handler
        (obligations.py); an UNKNOWN one means "block, do not dispatch" --
        returns the block reason string in that case, or None if every
        obligation was honored (safe to forward). Deterministic
        string-dispatch only (obligations.apply_known()) -- no LLM, no
        interpretation of an unrecognized string as if it might be a
        near-match of a known one.
        """
        if decision is None:
            return None  # unreachable in practice (caller only invokes this on a real allow)
        raw_obligations = decision.get("obligations") or []
        if not isinstance(raw_obligations, list):
            raw_obligations = []  # defensive: never trust the shape blindly; SPEC says list[str]
        decision_id = decision.get("decision_id", "") or ""

        for obligation in raw_obligations:
            if not isinstance(obligation, str) or not obligation:
                continue
            ctx = obligations_mod.ObligationContext(
                obligation=obligation,
                envelope=envelope,
                decision=decision,
                gateway_correlation_id=gateway_correlation_id,
                upstream_name=upstream_name,
                tool_name=tool_name,
            )
            try:
                obligations_mod.apply_known(obligation, ctx)
            except obligations_mod.UnknownObligationError:
                # NEVER silently forward past an obligation we cannot honor
                # (SPEC section 5: "An adapter that ignores an obligation is
                # non-conformant") -- fail closed, same spirit as an
                # unreachable core or an unknown Decision value above.
                return (
                    f"reeflex-mcp: unsupported obligation '{obligation}' -- cannot honor, "
                    f"failing closed decision_id={decision_id}"
                )
        return None

    def _record_observed_obligations(
        self,
        decision: dict | None,
        *,
        upstream_name: str,
        tool_name: str,
        gateway_correlation_id: str,
    ) -> None:
        """observe mode: RECORD every obligation on every decision (any
        verdict -- observe forwards regardless of verdict already) as
        "would-honor", then the caller's existing always-forward behavior
        proceeds unchanged. This is what keeps observe from "ignoring" an
        obligation in SPEC section 5's sense without making observe mode
        enforce anything -- handlers are NOT invoked here (their side
        effects should only fire for a call that is REALLY being allowed,
        which observe mode never actually decides)."""
        if decision is None:
            return
        raw_obligations = decision.get("obligations") or []
        if not isinstance(raw_obligations, list) or not raw_obligations:
            return
        print(
            f"[reeflex-mcp] observe mode -- would-honor obligation(s) for "
            f"{upstream_name}__{tool_name} (gateway_correlation_id={gateway_correlation_id}): "
            f"{list(raw_obligations)}",
            file=sys.stderr,
        )

    # -- tools/call handling ---------------------------------------------

    async def _handle_call_tool(self, name: str, arguments: dict) -> types.CallToolResult:
        resolved = self.upstreams.resolve(name)
        if resolved is None:
            return _error_result(f"reeflex-mcp: unknown tool or upstream unavailable: {name!r}")
        upstream_name, tool_name = resolved
        target_system, target_environment = self.upstreams.target_for(upstream_name)
        session_id, agent_id, on_behalf_of = self._derive_session_and_agent()

        try:
            envelope = normalize.build_envelope(
                session_id=session_id,
                agent_id=agent_id,
                on_behalf_of=on_behalf_of,
                upstream_name=upstream_name,
                target_system=target_system,
                target_environment=target_environment,
                tool_name=tool_name,
                arguments=arguments,
                mapping_registry=self.mappings,
            )
        except Exception as exc:  # noqa: BLE001 -- fail closed on a broken envelope, never dispatch blind
            return _error_result(f"reeflex-mcp: failed to normalize action: {exc}")

        gateway_correlation_id = envelope["meta"]["nonce"]
        # Track 4 (design doc section 8): "Log which tier classified each
        # call" -- helps the GIGO story + debugging.
        print(
            f"[reeflex-mcp] classified {name!r} via "
            f"{envelope['context']['classification_source']!r} -> verb={envelope['action']['verb']!r}",
            file=sys.stderr,
        )

        if self.mode == "observe":
            # Track 2 behavior, UNCHANGED (per the coordinator's explicit
            # Track 3 instruction: "observe stays the default day-1 -- leave
            # it"). No pending-hold tracking, no approval attach -- just
            # decide (for the audit trail) and always forward.
            decision, note = await self._decide(envelope)
            self._apply_mode_observe(decision, note)
            # Track 5.1 (design doc section 25): RECORD obligations, never
            # apply/enforce them here -- observe must never break traffic,
            # but recording is what keeps it from silently dropping them.
            self._record_observed_obligations(
                decision,
                upstream_name=upstream_name,
                tool_name=tool_name,
                gateway_correlation_id=gateway_correlation_id,
            )
            return await self._dispatch_and_tag(upstream_name, tool_name, arguments, gateway_correlation_id)

        # -- enforce mode: Track 3 full verdict -> MCP mapping -------------
        action_hash = canonical.canonical_hash(envelope)
        pending = self.pending_holds.get(session_id, action_hash)
        if pending is not None:
            envelope["approval"] = {
                "present": True,
                "hold_id": pending.hold_id,
                "parent_decision_id": pending.decision_id,
            }

        decision, note = await self._decide(envelope)
        outcome = self._classify_enforce_verdict(decision, note, pending)

        if outcome.store_pending is not None:
            self.pending_holds.put(session_id, action_hash, outcome.store_pending)
        if outcome.clear_pending:
            self.pending_holds.clear(session_id, action_hash)

        if outcome.action == "block":
            return _error_result(outcome.message or "reeflex-mcp: blocked", gateway_correlation_id=gateway_correlation_id)

        # Track 5.1 (design doc section 25 / SPEC section 5+7#5): the verdict
        # was allow (original OR approved_resubmission) -- honor obligations
        # BEFORE dispatching. A known one is applied; an unknown one blocks
        # the call right here, before any upstream dispatch happens.
        obligation_block_reason = self._apply_enforce_obligations(
            decision,
            envelope=envelope,
            upstream_name=upstream_name,
            tool_name=tool_name,
            gateway_correlation_id=gateway_correlation_id,
        )
        if obligation_block_reason is not None:
            return _error_result(obligation_block_reason, gateway_correlation_id=gateway_correlation_id)

        return await self._dispatch_and_tag(
            upstream_name,
            tool_name,
            arguments,
            gateway_correlation_id,
            decision_id=outcome.decision_id or None,
            parent_decision_id=outcome.parent_decision_id,
        )

    async def _dispatch_and_tag(
        self,
        upstream_name: str,
        tool_name: str,
        arguments: dict,
        gateway_correlation_id: str,
        *,
        decision_id: str | None = None,
        parent_decision_id: str | None = None,
    ) -> types.CallToolResult:
        """Dispatch to the upstream (with timeout) and tag the result. Shared
        by both observe's always-forward path and enforce's allow path."""
        try:
            result = await self.upstreams.dispatch(
                upstream_name, tool_name, arguments, timeout=config.call_timeout_seconds()
            )
        except UpstreamUnavailableError as exc:
            return _error_result(
                f"reeflex-mcp: upstream unavailable: {exc}", gateway_correlation_id=gateway_correlation_id
            )
        except asyncio.TimeoutError:
            return _error_result(
                f"reeflex-mcp: upstream call timed out after {config.call_timeout_seconds()}s",
                gateway_correlation_id=gateway_correlation_id,
            )
        except Exception as exc:  # noqa: BLE001 -- never let a raw upstream exception crash the front
            return _error_result(
                f"reeflex-mcp: upstream call failed: {exc}", gateway_correlation_id=gateway_correlation_id
            )

        return _tag_result(
            result, gateway_correlation_id, decision_id=decision_id, parent_decision_id=parent_decision_id
        )


# ---------------------------------------------------------------------------
# Run functions -- one process-level upstream connect, either transport
# ---------------------------------------------------------------------------


async def run_stdio(gateway: Gateway) -> None:
    """stdio front: the whole process (connect + serve) runs in ONE event
    loop, so connect-then-serve here is already process-scoped correctly --
    no lifespan wrap needed (section 21.1 only bites on streamable-HTTP)."""
    await gateway.upstreams.connect_all(connect_timeout=config.upstream_connect_timeout_seconds())
    try:
        await gateway.mcp.run_stdio_async()
    finally:
        await gateway.upstreams.close_all()


async def run_streamable_http(gateway: Gateway, *, host: str, port: int) -> None:
    """streamable-HTTP front: THE section 21.1 fix -- see module docstring.
    Mirrors `FastMCP.run_streamable_http_async()` but with upstream
    connect/close wrapped around the Starlette app's own ASGI lifespan
    instead of FastMCP's per-session `lifespan=` kwarg (which this gateway
    never sets)."""
    import uvicorn

    app = gateway.mcp.streamable_http_app()
    inner_lifespan = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def process_lifespan(asgi_app):
        await gateway.upstreams.connect_all(connect_timeout=config.upstream_connect_timeout_seconds())
        try:
            async with inner_lifespan(asgi_app) as state:
                yield state
        finally:
            await gateway.upstreams.close_all()

    app.router.lifespan_context = process_lifespan

    uv_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uv_config)
    await server.serve()


__all__ = [
    "Gateway",
    "FrontSessionRegistry",
    "EnforceOutcome",
    "UpstreamBootError",
    "run_stdio",
    "run_streamable_http",
]
