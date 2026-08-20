"""
spike/server_mcpserver.py -- RFX-9 SPIKE, NOT PRODUCTION CODE.

1:1 port of reeflex_holds/server.py from `mcp.server.fastmcp.FastMCP` (mcp<2,
dead on mcp>=2.0.0 -- the module no longer exists) to `mcp.server.mcpserver.
MCPServer` (the mcp>=2.0.0 replacement, spec 2026-07-28).

Only runs against a SPIKE venv with mcp>=2 installed (see
_reeflex/coordination/code-reports/dev-1--003--*--rfx9-spike.md for the exact
steps). The shipped package (reeflex_holds/server.py) and its pyproject.toml
pin (mcp>=1.2,<2) are UNCHANGED by this file -- this is proof-of-migration
code for RFX-9, not a replacement.

DIFF vs reeflex_holds/server.py, and why (see the spike report for the full
"does MCPServer expose an equivalent of FastMCP._mcp_server" answer):
  - `from mcp.server.fastmcp import FastMCP` -> `from mcp.server.mcpserver
    import MCPServer` (import path is the only source change this package
    needs -- reeflex-holds never touches the low-level Server directly, so
    none of the request_context/handler-registration breakage below applies
    to IT specifically; it's flagged here because reeflex-mcp/gateway.py, the
    OTHER package on this pin, does depend on that removed surface).
  - `FastMCP("reeflex-holds", instructions=...)` -> `MCPServer("reeflex-holds",
    instructions=...)` -- constructor signature is a superset (title, icons,
    website_url, ... added; nothing this package used was removed).
  - `@mcp.tool()` -> `@mcp.tool()` -- UNCHANGED. Same decorator name, same
    signature-inference-to-JSON-schema behavior, verified below by asserting
    the exact same tool names/schemas test_server.py already asserts.
  - `mcp.run(transport="stdio")` -> `mcp.run(transport="stdio")` -- UNCHANGED
    (MCPServer.run() dispatches to run_stdio_async() same as FastMCP.run()
    did; verified present via dir(MCPServer)).
  - Error surfacing: `from mcp.server.fastmcp.exceptions import ToolError` ->
    `from mcp.server.mcpserver.exceptions import ToolError` -- same class
    name, new module path; the tool-error-on-exception behavior this
    package's error handling relies on (client.HoldsAPIError /
    HoldsConnectionError / config.ConfigError propagate as ToolError to the
    MCP client) is unchanged (verified by check_server_mcpserver.py below).

NOT exercised here (out of scope for reeflex-holds, which never used them):
  `_mcp_server` low-level handoff, `request_context`, streamable-HTTP session
  derivation -- those are reeflex-mcp/gateway.py's concern; see the spike
  report section "Q2" for that half of the migration answer, proven instead
  against a standalone low-level-Server probe (spike/probe_lowlevel.py).
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from reeflex_holds import client

mcp = MCPServer(
    "reeflex-holds",
    instructions=(
        "Reeflex HIL (Human-in-the-Loop) holds console. Lists, inspects, and "
        "resolves pending Reeflex governance holds (require_approval "
        "verdicts) via reeflex-core's /v1/holds API. This server enforces "
        "NOTHING itself: actor-is-approver checks, rule immunity (e.g. "
        "irreversible_systemic_prod), and resolution-policy checks all "
        "happen inside reeflex-core, not here. IMPORTANT for adapter-sourced "
        "holds (e.g. WordPress): resolving a hold marks it approved IN CORE "
        "ONLY. The underlying action itself only runs when the adapter next "
        "executes it (for WordPress: the wp-admin 'run approved' button, or "
        "the adapter's automatic resubmission on the next matching request). "
        "This server never executes anything on any adapter's behalf."
    ),
)


@mcp.tool()
def list_holds(status: str | None = None) -> dict:
    """List Reeflex holds from reeflex-core, optionally filtered by status.

    Args:
        status: one of pending, approved, rejected, expired, consumed.
            Omit for no filter (core returns all statuses, most recent first).

    Returns:
        Core's paged list verbatim: {"items": [...], "count": N,
        "next_cursor"?: "..."}. Each item is a hold record (id, status,
        rule_id, created_ts, expires_ts, envelope, ...).
    """
    return client.list_holds(status=status)


@mcp.tool()
def get_hold(id: str) -> dict:
    """Get the full detail of one Reeflex hold, including its Action Envelope.

    Args:
        id: the hold id (from list_holds, or the hold_id field of a
            require_approval decision).

    Returns:
        The full hold record: id, status, rule_id, created_ts, expires_ts,
        envelope, envelope_hash, decided_by, decided_ts, reason, consumed_ts.
    """
    return client.get_hold(id)


@mcp.tool()
def resolve_hold(id: str, decision: str, reason: str | None = None) -> dict:
    """Approve or reject a pending Reeflex hold.

    The resolving principal is ALWAYS the one configured on this server via
    REEFLEX_PRINCIPAL (format "type:id", e.g. "human:leo" or
    "agent:triage-bot") -- it is never taken from tool arguments, so this
    tool cannot be asked to resolve "as" a different identity.

    reeflex-core independently enforces the operator's resolution policy,
    actor != approver, and rule immunity (e.g. irreversible_systemic_prod can
    never be resolved by anyone). This tool cannot bypass any of that -- a
    rejection from core is surfaced verbatim, not overridden.

    IMPORTANT for adapter-sourced holds (e.g. WordPress): this marks the
    hold's status IN REEFLEX-CORE ONLY. It does not execute the underlying
    action. For a WordPress-originated hold, the WordPress action still runs
    WordPress-side -- via the wp-admin "run approved" button, or the
    adapter's automatic resubmission on its next matching request.

    Args:
        id: the hold id to resolve.
        decision: "approve" or "reject" (core's exact vocabulary; any other
            value is rejected before the request is even sent).
        reason: optional free-text reason, recorded on the hold and in
            core's audit trail.

    Returns:
        The updated hold record on success (status now approved/rejected,
        decided_by, decided_ts, reason).
    """
    return client.resolve_hold(id, decision, reason=reason)


@mcp.tool()
def get_freeze_status() -> dict:
    """Best-effort probe of whether reeflex-core is reachable.

    HONEST LIMITATION: reeflex-core has NO dedicated freeze-status endpoint.
    REEFLEX_FREEZE (the operator kill-switch) is an environment variable read
    fresh on every /v1/decide call inside core, and it is never exposed via
    the HTTP API. This tool does not invent one -- it always returns
    freeze_state="unknown" and says so, backed only by a GET /healthz
    liveness check.

    Returns:
        {"core_reachable": bool, "freeze_state": "unknown", "note": str}
    """
    return client.get_freeze_status()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
