"""
server.py -- the reeflex-holds MCP server: the AIL/HIL socket.

Exposes reeflex-core's HIL holds API (list/get/resolve) plus a best-effort
reachability probe as MCP tools over stdio, using the official MCP Python SDK
(FastMCP) -- see reeflex-holds/README.md "Why the mcp SDK".

THIN CONSUMER, by design (HIL Phase 2 T3 brief): this server enforces NOTHING
itself. Every governance decision -- actor != approver, R3/systemic immunity,
which principal types may resolve which rule -- happens inside reeflex-core
(app/server.py's validation chain). This module only forwards HTTP calls
(client.py) and relays reeflex-core's response, success or error, to the MCP
client. It never retries a rejection, never overrides a decision, and never
accepts a resolving identity from a tool argument -- only from the server's
own REEFLEX_PRINCIPAL configuration (config.py), so an MCP client cannot
resolve a hold "as" an arbitrary identity by simply asking to.

Run: `python -m reeflex_holds` (stdio transport -- the only transport this
package implements; see README for the Claude Desktop wiring).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import client

mcp = FastMCP(
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
