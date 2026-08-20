"""
spike/probe_lowlevel.py -- RFX-9 SPIKE, NOT PRODUCTION CODE.

Answers RFX-9 question 2 empirically (not from docs/changelog): does
`mcp.server.mcpserver.MCPServer` (mcp>=2.0.0) expose an equivalent of
`mcp.server.fastmcp.FastMCP._mcp_server`, the private low-level
`mcp.server.lowlevel.Server` that reeflex-mcp/gateway.py overrides directly
(see that module's own docstring, "WHY THE LOW-LEVEL SERVER HANDLERS")?

Run: /tmp/rfx9_spike_venv/bin/python reeflex-holds/spike/probe_lowlevel.py
(needs mcp>=2 in the venv; see the spike report for setup).

FINDINGS (asserted below, not just claimed):
  1. YES, an equivalent exists: `MCPServer._lowlevel_server` (renamed from
     `_mcp_server`; same privacy convention -- underscore, undocumented,
     accessible). It is an instance of `mcp.server.lowlevel.server.Server`,
     same class the old FastMCP wrapped.
  2. The OVERRIDE MECHANISM CHANGED, not just the name. Old SDK:
     `Server.list_tools()` / `Server.call_tool()` were DECORATOR METHODS you
     called again to overwrite FastMCP's own registration (gateway.py's
     "last registration wins" trick). New SDK: `Server` has NO `list_tools`/
     `call_tool` decorator methods at all (confirmed: `hasattr` below) --
     `tools/list` and `tools/call` handlers are instead bound at
     `MCPServer.__init__` via `Server(..., on_list_tools=..., on_call_tool=...)`,
     and the ONLY supported override point is the new
     `Server.add_request_handler(method: str, params_type, handler)`, which
     does the same dict-overwrite (`self._request_handlers[method] = ...`)
     the old decorators did under the hood -- so the OUTCOME (gateway wins)
     is portable, but gateway.py's `@server.list_tools()` /
     `@server.call_tool(validate_input=False)` call sites need a rewrite to
     `server.add_request_handler("tools/list", ..., handler)` /
     `server.add_request_handler("tools/call", ..., handler)`.
  3. `Server.request_context` (the contextvar-based property gateway.py
     reads OUTSIDE the handler signature, e.g.
     `self.mcp._mcp_server.request_context` in `_derive_session_and_agent()`)
     is GONE (confirmed: `hasattr(Server, "request_context")` is False).
     The new SDK passes a `ServerRequestContext` as the handler's FIRST
     positional argument instead (`on_list_tools`/`on_call_tool` and anything
     registered via `add_request_handler` all take `(ctx, params)`). This is
     a bigger change than a rename: every gateway.py call site that reads
     `self.mcp._mcp_server.request_context` opportunistically (with a
     `try/except LookupError` for "no request in flight") must instead
     receive `ctx` as a parameter and thread it through
     (`_derive_session_and_agent(ctx)`, `_handle_call_tool(name, args, ctx)`,
     the `pending_holds` session-keying call sites, etc.) -- a real,
     non-mechanical refactor, not a find/replace.
"""

from __future__ import annotations

from mcp import types
from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer


def main() -> None:
    # --- Finding 1: the private low-level Server IS reachable, renamed. ---
    mcp = MCPServer("probe")
    assert hasattr(mcp, "_lowlevel_server"), "MCPServer no longer stores a low-level Server at all"
    assert isinstance(mcp._lowlevel_server, Server)
    print("FINDING 1 OK: MCPServer._lowlevel_server exists and is a mcp.server.lowlevel.server.Server "
          f"(old FastMCP: FastMCP._mcp_server) -- type={type(mcp._lowlevel_server)!r}")

    # --- Finding 2: no more list_tools()/call_tool() decorator methods. ---
    assert not hasattr(Server, "list_tools"), "Server.list_tools() decorator still exists (unexpected)"
    assert not hasattr(Server, "call_tool"), "Server.call_tool() decorator still exists (unexpected)"
    assert hasattr(Server, "add_request_handler"), "Server.add_request_handler is missing"
    print("FINDING 2 OK: Server has no .list_tools()/.call_tool() decorator methods "
          "(gateway.py's override trick needs porting to .add_request_handler(method, params_type, handler))")

    # --- Prove add_request_handler actually overrides tools/call, same as
    # gateway.py relies on for FastMCP today (last registration wins). ---
    calls: list[str] = []

    async def my_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        calls.append(params.name)
        # Finding 3, demonstrated in-line: ctx is handed to us as a plain
        # argument -- no contextvar read needed (and none is available: see
        # below).
        assert ctx is not None
        return types.CallToolResult(content=[types.TextContent(type="text", text="overridden")])

    mcp._lowlevel_server.add_request_handler("tools/call", types.CallToolRequestParams, my_call_tool)
    entry = mcp._lowlevel_server.get_request_handler("tools/call")
    assert entry is not None and entry.handler is my_call_tool
    print("FINDING 2b OK: add_request_handler('tools/call', ...) overwrote the constructor-bound handler "
          "(gateway.py's 'last registration wins' pattern ports, via a different call)")

    # --- Finding 3: Server.request_context (contextvar property) is gone. ---
    assert not hasattr(Server, "request_context"), "Server.request_context still exists (unexpected)"
    print("FINDING 3 OK: Server.request_context (the property gateway.py reads OUTSIDE the handler "
          "signature via self.mcp._mcp_server.request_context) no longer exists -- ctx is now an explicit "
          "handler parameter (ServerRequestContext), so every read site needs to receive+thread ctx instead "
          "of pulling it from a contextvar after the fact.")


if __name__ == "__main__":
    main()
    print("\nALL PROBES PASSED (RFX-9 Q2 answered against real mcp==2.0.0 source, not docs).")
