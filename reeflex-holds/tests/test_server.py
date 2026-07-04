"""
test_server.py -- unit tests for reeflex_holds.server (the FastMCP wiring).

These tests do NOT hit the network: reeflex_holds.client's public functions
are monkeypatched so we can assert exactly what server.py forwards to them,
and how it relays client results/errors back through the MCP tool-call API.
Network-level correctness of client.py itself is covered by test_client.py.

Uses FastMCP's own `call_tool` / `list_tools` methods directly (async;
driven here via asyncio.run) -- this exercises the exact tool registration
and invocation path a real MCP client (Claude Desktop, etc.) goes through.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from reeflex_holds import client  # noqa: E402
from reeflex_holds import server as holds_server  # noqa: E402

mcp = holds_server.mcp


def _call(name: str, args: dict) -> dict:
    """Call an MCP tool and parse its JSON text content into a dict."""
    result = asyncio.run(mcp.call_tool(name, args))
    content = result[0] if isinstance(result, tuple) else result
    text = content[0].text
    return json.loads(text)


class _PatchClientFn(unittest.TestCase):
    """Base class: monkeypatch one or more reeflex_holds.client functions,
    restoring the originals in tearDown regardless of test outcome."""

    def setUp(self) -> None:
        self._originals: dict[str, object] = {}

    def _patch(self, name: str, fn) -> None:
        if name not in self._originals:
            self._originals[name] = getattr(client, name)
        setattr(client, name, fn)

    def tearDown(self) -> None:
        for name, fn in self._originals.items():
            setattr(client, name, fn)


# ---------------------------------------------------------------------------
# Tool registration shape
# ---------------------------------------------------------------------------

class TestToolRegistration(unittest.TestCase):
    def test_tool_names(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        names = {t.name for t in tools}
        self.assertEqual(names, {"list_holds", "get_hold", "resolve_hold", "get_freeze_status"})

    def test_get_hold_requires_id(self) -> None:
        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
        self.assertEqual(tools["get_hold"].inputSchema.get("required"), ["id"])

    def test_resolve_hold_requires_id_and_decision_only(self) -> None:
        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
        schema = tools["resolve_hold"].inputSchema
        self.assertEqual(set(schema.get("required", [])), {"id", "decision"})
        # Anti-impersonation guarantee: no "principal" argument is exposed --
        # the resolving identity can only come from REEFLEX_PRINCIPAL server-side.
        self.assertNotIn("principal", schema.get("properties", {}))

    def test_list_holds_status_is_optional(self) -> None:
        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
        schema = tools["list_holds"].inputSchema
        self.assertNotIn("status", schema.get("required", []))


# ---------------------------------------------------------------------------
# list_holds forwarding
# ---------------------------------------------------------------------------

class TestListHoldsTool(_PatchClientFn):
    def test_forwards_status_argument(self) -> None:
        captured = {}

        def fake_list_holds(status=None):
            captured["status"] = status
            return {"items": [], "count": 0}

        self._patch("list_holds", fake_list_holds)
        result = _call("list_holds", {"status": "pending"})
        self.assertEqual(captured["status"], "pending")
        self.assertEqual(result, {"items": [], "count": 0})

    def test_omitted_status_forwards_none(self) -> None:
        captured = {}

        def fake_list_holds(status=None):
            captured["status"] = status
            return {"items": [], "count": 0}

        self._patch("list_holds", fake_list_holds)
        _call("list_holds", {})
        self.assertIsNone(captured["status"])


# ---------------------------------------------------------------------------
# get_hold forwarding + error propagation
# ---------------------------------------------------------------------------

class TestGetHoldTool(_PatchClientFn):
    def test_forwards_id_and_returns_hold(self) -> None:
        captured = {}

        def fake_get_hold(hold_id):
            captured["hold_id"] = hold_id
            return {"id": hold_id, "status": "pending"}

        self._patch("get_hold", fake_get_hold)
        result = _call("get_hold", {"id": "abc123"})
        self.assertEqual(captured["hold_id"], "abc123")
        self.assertEqual(result["id"], "abc123")

    def test_holds_api_error_surfaces_as_tool_error(self) -> None:
        def fake_get_hold(hold_id):
            raise client.HoldsAPIError(404, {"error": "not_found", "hold_id": hold_id}, "http://x")

        self._patch("get_hold", fake_get_hold)
        with self.assertRaises(ToolError) as ctx:
            asyncio.run(mcp.call_tool("get_hold", {"id": "nope"}))
        self.assertIn("not_found", str(ctx.exception))

    def test_connection_error_surfaces_as_tool_error(self) -> None:
        def fake_get_hold(hold_id):
            raise client.HoldsConnectionError("reeflex-core unreachable at http://x: refused")

        self._patch("get_hold", fake_get_hold)
        with self.assertRaises(ToolError) as ctx:
            asyncio.run(mcp.call_tool("get_hold", {"id": "abc123"}))
        self.assertIn("unreachable", str(ctx.exception))


# ---------------------------------------------------------------------------
# resolve_hold forwarding (id, decision, reason -- NOT principal)
# ---------------------------------------------------------------------------

class TestResolveHoldTool(_PatchClientFn):
    def test_forwards_id_decision_reason(self) -> None:
        captured = {}

        def fake_resolve_hold(hold_id, decision, reason=None):
            captured.update(hold_id=hold_id, decision=decision, reason=reason)
            return {"id": hold_id, "status": "approved"}

        self._patch("resolve_hold", fake_resolve_hold)
        result = _call("resolve_hold", {"id": "abc123", "decision": "approve", "reason": "looks fine"})
        self.assertEqual(captured, {"hold_id": "abc123", "decision": "approve", "reason": "looks fine"})
        self.assertEqual(result["status"], "approved")

    def test_reason_optional(self) -> None:
        captured = {}

        def fake_resolve_hold(hold_id, decision, reason=None):
            captured["reason"] = reason
            return {"id": hold_id, "status": "rejected"}

        self._patch("resolve_hold", fake_resolve_hold)
        _call("resolve_hold", {"id": "abc123", "decision": "reject"})
        self.assertIsNone(captured["reason"])

    def test_config_error_surfaces_as_tool_error(self) -> None:
        from reeflex_holds import config

        def fake_resolve_hold(hold_id, decision, reason=None):
            raise config.ConfigError("REEFLEX_PRINCIPAL is not set.")

        self._patch("resolve_hold", fake_resolve_hold)
        with self.assertRaises(ToolError) as ctx:
            asyncio.run(mcp.call_tool("resolve_hold", {"id": "abc123", "decision": "approve"}))
        self.assertIn("REEFLEX_PRINCIPAL", str(ctx.exception))

    def test_core_rejection_actor_is_approver_surfaces_verbatim(self) -> None:
        def fake_resolve_hold(hold_id, decision, reason=None):
            raise client.HoldsAPIError(
                403,
                {"error": "actor_is_approver", "reason": "actor cannot approve its own action"},
                "http://x",
            )

        self._patch("resolve_hold", fake_resolve_hold)
        with self.assertRaises(ToolError) as ctx:
            asyncio.run(mcp.call_tool("resolve_hold", {"id": "abc123", "decision": "approve"}))
        self.assertIn("actor_is_approver", str(ctx.exception))


# ---------------------------------------------------------------------------
# get_freeze_status forwarding
# ---------------------------------------------------------------------------

class TestGetFreezeStatusTool(_PatchClientFn):
    def test_forwards_to_client_and_never_claims_a_known_state(self) -> None:
        def fake_get_freeze_status():
            return {"core_reachable": True, "freeze_state": "unknown", "note": "best-effort only"}

        self._patch("get_freeze_status", fake_get_freeze_status)
        result = _call("get_freeze_status", {})
        self.assertEqual(result["freeze_state"], "unknown")
        self.assertTrue(result["core_reachable"])


if __name__ == "__main__":
    unittest.main()
