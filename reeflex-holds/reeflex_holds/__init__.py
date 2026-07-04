"""
reeflex_holds -- MCP server exposing reeflex-core's Human-in-the-Loop (HIL)
holds API (list / get / resolve) as MCP tools for any MCP client (Claude
Desktop, an MCP-capable agent, etc.).

HIL Phase 2 T3: the "AIL socket" -- an Agent/Approver-in-the-Loop surface
built on the standard MCP protocol rather than a bespoke integration per
client.

This package is a THIN CONSUMER of reeflex-core's holds API. It carries no
policy logic of its own -- see client.py and server.py module docstrings for
the full guarantee list. Entry point: `python -m reeflex_holds` (stdio).
"""

__version__ = "0.1.0"
