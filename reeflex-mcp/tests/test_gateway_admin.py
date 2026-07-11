"""
test_gateway_admin.py -- tests for Gateway._wire_admin()'s /admin/reload
route (Track 5, design doc section 13): the `add`/`import` hot-reload
mechanism, reusing the Track-2 FrontSessionRegistry to broadcast
tools/list_changed. Streamable-HTTP front only (see gateway.py's module
docstring for why stdio doesn't need this).
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import mcp.types as types
from starlette.testclient import TestClient

from reeflex_mcp import registry, upstream as upstream_mod
from reeflex_mcp.gateway import Gateway


class _FakeConnection(upstream_mod.UpstreamConnection):
    def __init__(self, name, target_system, target_environment, *, tools=None):
        super().__init__(name, target_system, target_environment)
        self._tools = tools or ["read_thing"]
        self.connected = False

    async def connect(self) -> None:
        self.connected = True

    async def list_tools(self):
        return [
            types.Tool(name=t, description=f"{t} tool", inputSchema={"type": "object", "properties": {}})
            for t in self._tools
        ]

    async def call_tool(self, tool_name, arguments):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")], isError=False)

    async def close(self) -> None:
        pass


def _write_yaml(path: str, upstream_names: list[str]) -> None:
    lines = ["mode: observe", "upstreams:"]
    for name in upstream_names:
        lines.append(f"  - name: {name}")
        lines.append(f'    command: ["python", "{name}.py"]')
        lines.append(f"    target: {{ system: {name}, environment: staging }}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestAdminReloadRoute(unittest.TestCase):
    def setUp(self) -> None:
        self.yaml_path = str(Path(tempfile.mkdtemp()) / "reeflex-mcp.yaml")
        _write_yaml(self.yaml_path, ["fs"])
        gw_config = registry.load_config(self.yaml_path)
        self.gateway = Gateway(gw_config)

        self._original_build_connection = upstream_mod.build_connection
        self._fakes: dict[str, _FakeConnection] = {}

        def fake_build(spec, *, on_list_changed):
            conn = _FakeConnection(spec.name, spec.target_system, spec.target_environment)
            self._fakes[spec.name] = conn
            return conn

        upstream_mod.build_connection = fake_build

        # Simulate the REAL boot sequence (run_streamable_http() always
        # calls connect_all() before serving) -- without this, "fs" would
        # never be marked up, and up_upstream_names() would (correctly)
        # treat it as "new" on the very first reload, which is not what
        # these tests are exercising (found live while demonstrating this
        # feature -- see the Track 5 report).
        asyncio.run(self.gateway.upstreams.connect_all(connect_timeout=5.0))

    def tearDown(self) -> None:
        upstream_mod.build_connection = self._original_build_connection

    def test_reload_with_no_new_upstreams_is_a_no_op(self) -> None:
        app = self.gateway.mcp.streamable_http_app()
        with TestClient(app) as client:
            resp = client.post("/admin/reload")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["added"], [])
        self.assertEqual(body["failed"], [])

    def test_reload_connects_new_upstream_and_broadcasts_list_changed(self) -> None:
        broadcasts = []
        self.gateway.front_sessions.broadcast_tools_list_changed = _record_and_noop(broadcasts)

        # Simulate `add`/`import` having appended a NEW upstream to the file
        # on disk WHILE the gateway is already running.
        _write_yaml(self.yaml_path, ["fs", "gh"])

        app = self.gateway.mcp.streamable_http_app()
        with TestClient(app) as client:
            resp = client.post("/admin/reload")

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["added"], ["gh"])
        self.assertEqual(body["failed"], [])
        self.assertEqual(len(broadcasts), 1)

        names = sorted(t.name for t in self.gateway.upstreams.aggregated_tools())
        self.assertIn("gh__read_thing", names)

    def test_reload_retries_a_previously_failed_hot_add(self) -> None:
        # Regression (found live while demonstrating this feature): a hot-add
        # that fails once (e.g. a bad command) must be retryable on the NEXT
        # reload, once the operator fixes reeflex-mcp.yaml -- diffing against
        # "known" upstreams (attempted, not necessarily connected) would
        # silently skip it forever.
        class _FailingConnection(_FakeConnection):
            async def connect(self):
                raise RuntimeError("simulated bad command")

        def fake_build_failing(spec, *, on_list_changed):
            conn = _FailingConnection(spec.name, spec.target_system, spec.target_environment)
            self._fakes[spec.name] = conn
            return conn

        upstream_mod.build_connection = fake_build_failing
        _write_yaml(self.yaml_path, ["fs", "gh"])

        # ONE lifespan (StreamableHTTPSessionManager.run() may only be
        # entered once per app instance) -- both reload attempts happen as
        # two sequential requests within it, exactly like two real POSTs
        # against one long-running gateway process.
        app = self.gateway.mcp.streamable_http_app()
        with TestClient(app) as client:
            first = client.post("/admin/reload")
            self.assertEqual(first.status_code, 200)
            self.assertEqual(first.json()["added"], [])
            self.assertEqual(first.json()["failed"], [{"name": "gh", "error": "simulated bad command"}])

            # Operator fixes the command (simulated: swap in a working fake)
            # and asks for another reload -- must retry "gh", not skip it.
            def fake_build_working(spec, *, on_list_changed):
                conn = _FakeConnection(spec.name, spec.target_system, spec.target_environment)
                self._fakes[spec.name] = conn
                return conn

            upstream_mod.build_connection = fake_build_working

            second = client.post("/admin/reload")
            self.assertEqual(second.status_code, 200)
            self.assertEqual(second.json()["added"], ["gh"])
            self.assertEqual(second.json()["failed"], [])

    def test_reload_with_invalid_config_returns_400(self) -> None:
        Path(self.yaml_path).write_text("upstreams: not-a-list\n", encoding="utf-8")
        app = self.gateway.mcp.streamable_http_app()
        with TestClient(app) as client:
            resp = client.post("/admin/reload")
        self.assertEqual(resp.status_code, 400)

    def test_reload_with_admin_token_rejects_missing_auth(self) -> None:
        import os

        os.environ["REEFLEX_MCP_ADMIN_TOKEN"] = "s3cr3t"
        try:
            app = self.gateway.mcp.streamable_http_app()
            with TestClient(app) as client:
                resp = client.post("/admin/reload")
            self.assertEqual(resp.status_code, 401)
        finally:
            del os.environ["REEFLEX_MCP_ADMIN_TOKEN"]

    def test_reload_with_admin_token_accepts_correct_auth(self) -> None:
        import os

        os.environ["REEFLEX_MCP_ADMIN_TOKEN"] = "s3cr3t"
        try:
            app = self.gateway.mcp.streamable_http_app()
            with TestClient(app) as client:
                resp = client.post("/admin/reload", headers={"Authorization": "Bearer s3cr3t"})
            self.assertEqual(resp.status_code, 200)
        finally:
            del os.environ["REEFLEX_MCP_ADMIN_TOKEN"]


def _record_and_noop(sink: list):
    async def _fn():
        sink.append(1)
    return _fn


if __name__ == "__main__":
    unittest.main()
