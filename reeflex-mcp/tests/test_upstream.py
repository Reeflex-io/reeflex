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

from reeflex_mcp.upstream import (
    UpstreamBootError,
    UpstreamConnection,
    UpstreamRegistry,
    UpstreamUnavailableError,
    _BaseUpstreamConnection,
)
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


# ---------------------------------------------------------------------------
# BUG 1 regression (dogfood RCA, 2026-07): stdio upstream teardown crashes
# the gateway. Root cause: stdio_client() (mcp SDK) has no
# terminate_on_close-style knob to skip its baked-in teardown (stdin close +
# anyio.fail_after-guarded process.wait() + SIGTERM/SIGKILL escalation);
# _BaseUpstreamConnection.close() previously wrapped `await stack.aclose()`
# with NO try/except, so a stdio upstream's teardown error (a cancel-scope
# violation surfacing as the front stdio server unwinds on client disconnect)
# could escape and crash the process / block a sibling's close().
#
# These drive _BaseUpstreamConnection directly (not through the real
# StdioUpstreamConnection/stdio_client() -- see test_upstream.py's own module
# docstring: those need a real subprocess, exercised by the manual E2E
# instead). Level of repro: STUB -- a fake AsyncExitStack whose aclose()
# raises a cancel-scope-style BaseException, which is exactly the failure
# mode _BaseUpstreamConnection.close()/connect() must now swallow/clean up.
# A genuine real-subprocess repro would require racing a real child
# process's stdio teardown against an ALREADY-cancelling ancestor scope,
# which is not practical to drive deterministically in a unit-test process.
# ---------------------------------------------------------------------------


class _RaisingStack:
    """Stub AsyncExitStack whose aclose() raises a cancel-scope-style
    BaseException -- mirrors what stdio_client()'s baked-in process-kill
    teardown can do when it runs from inside close_all()'s loop while the
    front stdio server's OWN task group is already unwinding/cancelling."""

    def __init__(self) -> None:
        self.aclose_called = False

    async def aclose(self) -> None:
        self.aclose_called = True
        raise RuntimeError("Attempted to exit a cancel scope that isn't the current task's current cancel scope")


class _MinimalBaseConnection(_BaseUpstreamConnection):
    """A concrete _BaseUpstreamConnection for driving close()/connect() in
    isolation. _open_transport() is never actually invoked by these tests
    (they set self._stack directly, or supply a transport stub) -- it only
    exists to satisfy the ABC."""

    def __init__(self, *args, transport_cm=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._transport_cm = transport_cm

    def _open_transport(self):
        return self._transport_cm


class TestBaseConnectionCloseSwallowsTeardownErrors(unittest.IsolatedAsyncioTestCase):
    async def test_close_swallows_cancel_scope_style_teardown_error(self) -> None:
        """(RED before the fix / GREEN after): before the fix, this raised
        the RuntimeError out of close() -- this exact assertion (close()
        completes without propagating) is what watched the crash and then
        watched it disappear once the try/except + shield landed."""
        conn = _MinimalBaseConnection("stdio-up", "system-x", "staging", on_list_changed=None)
        raising_stack = _RaisingStack()
        conn._stack = raising_stack  # type: ignore[assignment]
        conn._session = object()  # non-None, as a connected upstream would have

        await conn.close()  # must not raise -- this IS the fix under test.

        self.assertTrue(raising_stack.aclose_called)
        # idempotent / cleared state regardless of the teardown error.
        self.assertIsNone(conn._stack)
        self.assertIsNone(conn._session)

    async def test_close_on_never_connected_upstream_is_a_pure_no_op(self) -> None:
        """Guard: a connection whose connect() never succeeded (self._stack
        is None) must not try to touch anyio.CancelScope/aclose() at all."""
        conn = _MinimalBaseConnection("never-connected", "system-x", "staging", on_list_changed=None)
        await conn.close()  # must not raise
        self.assertIsNone(conn._stack)

    async def test_close_all_survives_one_upstream_teardown_error_and_closes_sibling(self) -> None:
        """(b)/(c) of the brief: a registry with a healthy sibling alongside
        the failing stdio-style upstream -- close_all() must still close the
        sibling and the BaseException must not escape (front-shutdown
        scenario: client disconnects, close_all() runs from a `finally`)."""
        reg = UpstreamRegistry([_spec("bad", required=False), _spec("good", required=False)])

        bad = _MinimalBaseConnection("bad", "system-bad", "staging", on_list_changed=None)
        bad._stack = _RaisingStack()  # type: ignore[assignment]
        bad._session = object()

        good = _FakeConnection("good", "system-good", "staging")
        good.connected = True

        reg._connections["bad"] = bad
        reg._connections["good"] = good
        reg._up["bad"] = True
        reg._up["good"] = True

        await reg.close_all()  # must complete without propagating "bad"'s BaseException.

        self.assertTrue(good.closed)  # sibling still closed
        self.assertIsNone(bad._stack)


class _TrackedTransportCM:
    """A transport-shaped async context manager that records whether its
    __aexit__ (the real StdioUpstreamConnection's process-kill teardown, in
    production) actually ran."""

    def __init__(self, streams: tuple[object, object]) -> None:
        self._streams = streams
        self.exited = False

    async def __aenter__(self):
        return self._streams

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        self.exited = True
        return False


class _CancellingSession:
    """Stands in for mcp.ClientSession: a normal async context manager whose
    initialize() raises asyncio.CancelledError -- simulating a stdio
    connect() TIMEOUT (asyncio.wait_for cancelling connect_all()'s call to
    conn.connect() mid-handshake, section 21.2). CancelledError is a
    BaseException, not an Exception, since Python 3.8."""

    def __init__(self, read_stream, write_stream, message_handler=None) -> None:
        del read_stream, write_stream, message_handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def initialize(self) -> None:
        raise asyncio.CancelledError("simulated stdio connect timeout mid-handshake")


class TestConnectFailureTeardownBroadenedToBaseException(unittest.IsolatedAsyncioTestCase):
    """Adjacent leak (BUG 1, connect()-side): a stdio connect() TIMEOUT
    raises asyncio.CancelledError (a BaseException, not an Exception) into
    connect(). Before the fix, `except Exception` skipped stack.aclose()
    entirely, discarding the partial stack (holding the spawned subprocess)
    WITHOUT tearing it down -- an orphaned child process. After the fix, the
    teardown runs (shielded) and the original exception still propagates
    (the connect-failure return contract is unchanged)."""

    async def test_cancelled_error_during_initialize_still_tears_down_transport(self) -> None:
        transport_cm = _TrackedTransportCM((object(), object()))
        conn = _MinimalBaseConnection(
            "stdio-up", "system-x", "staging", on_list_changed=None, transport_cm=transport_cm
        )

        import reeflex_mcp.upstream as upstream_mod

        original_session_cls = upstream_mod.ClientSession
        upstream_mod.ClientSession = _CancellingSession
        try:
            with self.assertRaises(asyncio.CancelledError):
                await conn.connect()
        finally:
            upstream_mod.ClientSession = original_session_cls

        # the transport's own teardown (which, for a real
        # StdioUpstreamConnection, is what kills the spawned child process)
        # ran despite the BaseException -- this is exactly what "orphaned
        # child process" means when it does NOT run.
        self.assertTrue(transport_cm.exited)
        # connect() never assigns self._stack/self._session on a failure path.
        self.assertIsNone(conn._stack)
        self.assertIsNone(conn._session)


if __name__ == "__main__":
    unittest.main()
