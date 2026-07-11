"""
_doctor_upstream.py -- a trivial, built-in stdio MCP server used ONLY by
`reeflex-mcp check`'s fail-closed self-probe (cli.py). Ships as part of the
installed package (unlike tests/fixtures/, which is dev-only) so `check`
works standalone in a clean `pip install reeflex-mcp` environment, with no
external dependency (no npx, no network) -- mirrors how reeflex-claude's
`check` subcommand needs nothing beyond the installed package itself.

One deliberately destructive-sounding tool (`delete_thing`) so the probe
exercises the SAME heuristic bucket (delete_* -> irreversible) a real
dangerous call would use. The tool's own body is a no-op decoy: `check`
forces an unreachable reeflex-core, so this tool must NEVER actually run --
if it does, that IS the fail-open bug the probe exists to catch.

Not a public API -- leading underscore, no docs, never imported by anything
except cli.py's check probe.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reeflex-mcp-doctor-upstream")


@mcp.tool()
def delete_thing(name: str) -> str:
    """Decoy destructive tool -- must never execute during the check probe."""
    return f"DECOY EXECUTED for {name!r} -- if you see this in a check run, the fail-closed probe FAILED."


if __name__ == "__main__":
    mcp.run(transport="stdio")
