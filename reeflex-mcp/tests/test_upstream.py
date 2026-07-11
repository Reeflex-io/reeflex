"""
test_upstream.py -- unit tests for reeflex_mcp.upstream.UpstreamRegistry
lifecycle/fail-closed-at-boot logic, using fake in-process UpstreamConnection
implementations (no real MCP transport -- StdioUpstreamConnection /
HttpUpstreamConnection themselves are exercised by the manual E2E instead,
since they need a real subprocess / HTTP server on the other end).
"""

from __future__ import annotations

import asyncio
import unittest

import mcp.types as types

from reeflex_mcp.upstream import UpstreamBootError, UpstreamConnection, UpstreamRegistry, UpstreamUnavailableError
from reeflex_mcp.registry import UpstreamSpec


class _FakeConnection(UpstreamConnection):
    """A fake upstream: connects instantly (or fails, or hangs) per test setup."""

    def __init__(self, name, target_system, target_environment, *, fail: bool = False, hang: bool = False,
                 tools: list[str] | None = None):
        super().__init__(name, target_system, target_environment)
        self._fail = fail
        self._hang = hang
        self._tools = tools if tools is not None else ["read_thing", "delete_thing"]
        self.connected = False
        self.closed = False
        self.calls: list[tuple[str, dict]] = []

    async def connect(self) -> None:
        if self._hang:
            await asyncio.sleep(999)
        if self._fail:
            raise RuntimeError("simulated connect failure")
        self.connected = True

    async def list_tools(self) -> list[types.Tool]:
        return [types.Tool(name=t, description=f"{t} tool", inputSchema={"type": "object", "properties": {}})
                for t in self._tools]

    async def call_tool(self, tool_name: str, arguments: dict) -> types.CallToolResult:
        self.calls.append((tool_name, arguments))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"ran {tool_name}")],
            isError=False,
        )

    async def close(self) -> None:
        self.closed = True


def _spec(name: str, *, required: bool = True) -> UpstreamSpec:
    return UpstreamSpec(
        name=name,
        kind="stdio",
        target_system=f"system-{name}",
        target_environment="staging",
        required=required,
        command="python",
        args=("server.py",),
    )


class TestConnectAllSuccess(unittest.IsolatedAsyncioTestCase):
    async def test_all_connect_and_tools_aggregated(self) -> None:
        reg = UpstreamRegistry([_spec("fs"), _spec("gh")])
        fake_fs = _FakeConnection("fs", "system-fs", "staging", tools=["read_file", "delete_file"])
        fake_gh = _FakeConnection("gh", "system-gh", "staging", tools=["create_issue"])

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        fakes = {"fs": fake_fs, "gh": fake_gh}
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fakes[spec.name]
        try:
            await reg.connect_all(connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertTrue(fake_fs.connected)
        self.assertTrue(fake_gh.connected)

        names = sorted(t.name for t in reg.aggregated_tools())
        self.assertEqual(names, ["fs__delete_file", "fs__read_file", "gh__create_issue"])


class TestConnectAllFailClosed(unittest.IsolatedAsyncioTestCase):
    async def test_required_upstream_failure_aborts_boot(self) -> None:
        reg = UpstreamRegistry([_spec("fs", required=True)])
        fake = _FakeConnection("fs", "system-fs", "staging", fail=True)

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            with self.assertRaises(UpstreamBootError):
                await reg.connect_all(connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

    async def test_non_required_upstream_failure_marks_down_not_fatal(self) -> None:
        reg = UpstreamRegistry([_spec("fs", required=False), _spec("gh", required=True)])
        fake_fs = _FakeConnection("fs", "system-fs", "staging", fail=True)
        fake_gh = _FakeConnection("gh", "system-gh", "staging")

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        fakes = {"fs": fake_fs, "gh": fake_gh}
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fakes[spec.name]
        try:
            await reg.connect_all(connect_timeout=1.0)  # must NOT raise
        finally:
            upstream_mod.build_connection = original_build

        # fs is down -- excluded from aggregation and dispatch, but the
        # gateway still booted (gh is up).
        names = [t.name for t in reg.aggregated_tools()]
        self.assertTrue(all(not n.startswith("fs__") for n in names))
        self.assertIsNone(reg.resolve("fs__read_thing"))
        with self.assertRaises(UpstreamUnavailableError):
            await reg.dispatch("fs", "read_thing", {}, timeout=1.0)

    async def test_connect_timeout_treated_as_failure(self) -> None:
        reg = UpstreamRegistry([_spec("fs", required=True)])
        fake = _FakeConnection("fs", "system-fs", "staging", hang=True)

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            with self.assertRaises(UpstreamBootError):
                await reg.connect_all(connect_timeout=0.05)
        finally:
            upstream_mod.build_connection = original_build


class TestResolveAndDispatch(unittest.IsolatedAsyncioTestCase):
    async def _connected_registry(self):
        reg = UpstreamRegistry([_spec("fs")])
        fake = _FakeConnection("fs", "system-fs", "staging", tools=["read_file", "delete_file"])

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            await reg.connect_all(connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build
        return reg, fake

    async def test_resolve_strips_namespace(self) -> None:
        reg, _fake = await self._connected_registry()
        self.assertEqual(reg.resolve("fs__read_file"), ("fs", "read_file"))

    async def test_resolve_unknown_upstream_none(self) -> None:
        reg, _fake = await self._connected_registry()
        self.assertIsNone(reg.resolve("nope__read_file"))

    async def test_resolve_malformed_name_none(self) -> None:
        reg, _fake = await self._connected_registry()
        self.assertIsNone(reg.resolve("no_namespace_separator"))

    async def test_dispatch_reaches_correct_upstream(self) -> None:
        reg, fake = await self._connected_registry()
        result = await reg.dispatch("fs", "read_file", {"path": "/x"}, timeout=1.0)
        self.assertFalse(result.isError)
        self.assertEqual(fake.calls, [("read_file", {"path": "/x"})])

    async def test_dispatch_timeout_propagates(self) -> None:
        reg = UpstreamRegistry([_spec("slow")])

        class _SlowConn(_FakeConnection):
            async def call_tool(self, tool_name, arguments):
                await asyncio.sleep(999)

        fake = _SlowConn("slow", "system-slow", "staging")

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            await reg.connect_all(connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        with self.assertRaises(asyncio.TimeoutError):
            await reg.dispatch("slow", "read_thing", {}, timeout=0.05)


class TestListChangedReemit(unittest.IsolatedAsyncioTestCase):
    async def test_tools_changed_refreshes_cache_and_invokes_callback(self) -> None:
        calls = []

        async def on_changed():
            calls.append(1)

        reg = UpstreamRegistry([_spec("fs")], on_tools_changed=on_changed)
        fake = _FakeConnection("fs", "system-fs", "staging", tools=["read_file"])

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            await reg.connect_all(connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertEqual([t.name for t in reg.aggregated_tools()], ["fs__read_file"])

        # simulate upstream growing a new tool + firing list_changed
        fake._tools = ["read_file", "write_file"]
        await reg._handle_upstream_tools_changed("fs")

        self.assertEqual(sorted(t.name for t in reg.aggregated_tools()), ["fs__read_file", "fs__write_file"])
        self.assertEqual(calls, [1])


class TestConnectOne(unittest.IsolatedAsyncioTestCase):
    """Track 5 (design doc section 13) `add`/`import` hot-reload:
    UpstreamRegistry.connect_one() adds ONE new upstream into an ALREADY-
    RUNNING registry without disturbing any other connection."""

    async def test_connect_one_adds_new_upstream_without_boot_error(self) -> None:
        reg = UpstreamRegistry([_spec("fs")])
        fake_fs = _FakeConnection("fs", "system-fs", "staging", tools=["read_file"])

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        fakes = {"fs": fake_fs}
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fakes[spec.name]
        try:
            await reg.connect_all(connect_timeout=1.0)

            new_spec = _spec("gh")
            fake_gh = _FakeConnection("gh", "system-gh", "staging", tools=["create_issue"])
            fakes["gh"] = fake_gh
            ok, err = await reg.connect_one(new_spec, connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertTrue(ok)
        self.assertIsNone(err)
        names = sorted(t.name for t in reg.aggregated_tools())
        self.assertEqual(names, ["fs__read_file", "gh__create_issue"])
        # the pre-existing "fs" connection was NOT disturbed
        self.assertEqual(fake_fs.calls, [])
        self.assertTrue(fake_fs.connected)

    async def test_connect_one_failure_is_reported_not_raised(self) -> None:
        reg = UpstreamRegistry([])
        fake = _FakeConnection("bad", "system-bad", "staging", fail=True)

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fake
        try:
            # required=True, but connect_one must NEVER raise UpstreamBootError
            # -- a failed hot-add must not tear down an already-running gateway.
            ok, err = await reg.connect_one(_spec("bad", required=True), connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertFalse(ok)
        self.assertIsNotNone(err)
        self.assertEqual(reg.resolve("bad__anything"), None)

    async def test_connect_one_replaces_existing_connection_of_same_name(self) -> None:
        reg = UpstreamRegistry([_spec("fs")])
        fake_v1 = _FakeConnection("fs", "system-fs", "staging", tools=["read_file"])

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        fakes = {"fs": fake_v1}
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fakes["fs"]
        try:
            await reg.connect_all(connect_timeout=1.0)

            fake_v2 = _FakeConnection("fs", "system-fs", "staging", tools=["write_file"])
            fakes["fs"] = fake_v2
            ok, _err = await reg.connect_one(_spec("fs"), connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertTrue(ok)
        self.assertTrue(fake_v1.closed)  # old connection torn down
        names = [t.name for t in reg.aggregated_tools()]
        self.assertEqual(names, ["fs__write_file"])  # new connection's tools, not the old one's

    def test_known_upstream_names(self) -> None:
        reg = UpstreamRegistry([_spec("fs"), _spec("gh")])
        self.assertEqual(reg.known_upstream_names(), frozenset({"fs", "gh"}))

    async def test_up_upstream_names_excludes_failed_connect(self) -> None:
        # Regression (found live while demonstrating Track 5's hot-reload):
        # a previously-FAILED hot-add must remain retryable -- diffing
        # against known_upstream_names() (attempted, not necessarily
        # successful) would silently skip it forever.
        reg = UpstreamRegistry([_spec("fs")])
        fake_fs = _FakeConnection("fs", "system-fs", "staging")
        fake_bad = _FakeConnection("bad", "system-bad", "staging", fail=True)

        import reeflex_mcp.upstream as upstream_mod

        original_build = upstream_mod.build_connection
        fakes = {"fs": fake_fs, "bad": fake_bad}
        upstream_mod.build_connection = lambda spec, *, on_list_changed: fakes[spec.name]
        try:
            await reg.connect_all(connect_timeout=1.0)
            # A hot-add (connect_one, NOT connect_all) that fails -- must
            # never raise UpstreamBootError, regardless of `required`.
            ok, err = await reg.connect_one(_spec("bad", required=True), connect_timeout=1.0)
        finally:
            upstream_mod.build_connection = original_build

        self.assertFalse(ok)
        self.assertIsNotNone(err)
        # "bad" is KNOWN (attempted) but not UP (failed) -- known_upstream_names
        # includes it, up_upstream_names must not, so a reload diff based on
        # up_upstream_names() will retry it on the next call.
        self.assertEqual(reg.known_upstream_names(), frozenset({"fs", "bad"}))
        self.assertEqual(reg.up_upstream_names(), frozenset({"fs"}))


if __name__ == "__main__":
    unittest.main()
