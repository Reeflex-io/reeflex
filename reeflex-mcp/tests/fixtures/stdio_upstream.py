"""
stdio_upstream.py -- a throwaway, trivial stdio MCP server used ONLY as a
Track-2 E2E fixture (see the adapter-builder's final report for how it's
wired into reeflex-mcp.yaml). Not part of the reeflex-mcp package itself.

Four tools, deliberately named to exercise the normalize.py heuristic:
  read_note(name)      -> "read_*"   heuristic bucket (verb=read)
  delete_note(name)    -> "delete_*" heuristic bucket (verb=delete, irreversible),
                          magnitude 1 (no list arg) -> blast_radius=single
  delete_notes(names)  -> same bucket, but `names` is a list arg -> magnitude
                          = len(names), so a large batch drives blast_radius
                          to "broad" -- with target.environment=production
                          (see the e2e reeflex-mcp.yaml) this is what exercises
                          core's R2 (irreversible+broad+prod -> require_approval).
  frobnicate_widget(name) -> matches NONE of the heuristic prefixes -> falls
                          to the conservative "execute" default (axes forced
                          to irreversible/systemic/internal) -- with
                          target.environment=production this exercises core's
                          R3 (irreversible+systemic+prod -> deny, even with
                          approval) -- a Track-3 E2E fixture for the "denied
                          call is blocked, never dispatched" acceptance case
                          (proven by the gateway's response being ITS OWN
                          "reeflex-mcp: denied --..." text, never this
                          function's return value -- see gateway.py
                          _classify_enforce_verdict/_handle_call_tool, which
                          structurally never calls upstreams.dispatch() on a
                          "block" outcome).

Run: python tests/fixtures/stdio_upstream.py
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-notes")

_NOTES = {"alpha": "first note", "beta": "second note"}


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note by name."""
    return _NOTES.get(name, f"<no note named {name!r}>")


@mcp.tool()
def delete_note(name: str) -> str:
    """Delete a note by name (irreversible)."""
    existed = _NOTES.pop(name, None) is not None
    return f"deleted={existed}"


@mcp.tool()
def delete_notes(names: list[str]) -> str:
    """Delete several notes by name in one call (irreversible, bulk)."""
    count = 0
    for name in names:
        if _NOTES.pop(name, None) is not None:
            count += 1
    return f"deleted_count={count}_of_requested={len(names)}"


@mcp.tool()
def frobnicate_widget(name: str) -> str:
    """Deliberately unclassifiable tool name (Track-3 R3-deny fixture). If
    this return value ever reaches the front client, the gateway failed to
    block a denied call -- it should always be intercepted before dispatch."""
    return f"frobnicated={name}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
