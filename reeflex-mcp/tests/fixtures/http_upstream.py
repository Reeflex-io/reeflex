"""
http_upstream.py -- a throwaway, trivial streamable-HTTP MCP server used ONLY
as a Track-2 E2E fixture (proving the gateway's HTTP-upstream client path,
D4 in the design doc). Not part of the reeflex-mcp package itself.

Two tools, deliberately named to exercise the normalize.py heuristic:
  list_widgets()          -> "list_*"   heuristic bucket (verb=read)
  create_widget(name)     -> "create_*" heuristic bucket (verb=create, outbound)

Run: python tests/fixtures/http_upstream.py --port 8091
"""

from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP

_WIDGETS: list[str] = ["widget-1", "widget-2"]


def build(host: str = "127.0.0.1", port: int = 8091) -> FastMCP:
    mcp = FastMCP("fixture-widgets", host=host, port=port)

    @mcp.tool()
    def list_widgets() -> list[str]:
        """List all widgets."""
        return list(_WIDGETS)

    @mcp.tool()
    def create_widget(name: str) -> str:
        """Create a new widget."""
        _WIDGETS.append(name)
        return f"created={name}"

    return mcp


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()

    app = build(host=args.host, port=args.port)
    app.run(transport="streamable-http")
