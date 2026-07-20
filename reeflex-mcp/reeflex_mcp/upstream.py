"""
upstream.py -- the MCP "back" side: one UpstreamConnection ABC, two
transport impls (stdio, streamable-HTTP), and a process-level UpstreamRegistry
that connects every configured upstream ONCE at boot and dispatches
`tools/call` to the owning upstream for the life of the process.

This module encodes the lifecycle findings in design/MCP-GATEWAY-DESIGN.md
ADDENDUM v1.2 section 21 (verified against mcp SDK 1.28.1 source while
building this package -- see inline citations below):

  section 21.1 -- Upstream connections are PROCESS-level, not per-session.
      This module's connect() is only ever called once per upstream, by
      UpstreamRegistry.connect_all(), driven by gateway.py's process-level
      startup path for BOTH transports (see gateway.py module docstring for
      exactly where that call sits in each transport's event loop).

  section 21.2 -- Connect fails-slow inside a lifespan -> every connect() is
      wrapped in an explicit timeout by connect_all() (asyncio.wait_for), and
      a REQUIRED upstream that fails to connect within that timeout aborts
      the whole boot (UpstreamBootError) -- fail CLOSED at boot, never a bare
      `await connect()`. A non-required upstream that fails is marked down:
      excluded from the aggregated tool list, and any call against its
      namespace is rejected with a clear error (never silently ignored).

  section 21.3 -- `tools/list_changed` is NOT auto-forwarded to the gateway's
      own front clients. Each connection accepts an `on_list_changed`
      callback (see message_handler wiring below); UpstreamRegistry refreshes
      its own tool cache and then invokes ITS OWN `on_tools_changed` callback,
      which gateway.py wires to the front-session registry's broadcast. This
      module has no knowledge of the front side at all -- it only knows "my
      tool list changed", never who is listening.

  section 21.5 -- one UpstreamConnection ABC (connect/list_tools/call_tool/
      close via AsyncExitStack); StdioUpstreamConnection + HttpUpstreamConnection
      behind it. Connect-once-at-startup (registry), dispatch-with-timeout
      (registry.dispatch), close-at-shutdown (registry.close_all).

  section 21.6 -- uses `streamable_http_client` (SDK 1.28.1 name), NOT the
      deprecated `streamablehttp_client`.

isError propagation (section 21.4) is NOT this module's concern: call_tool()
returns the upstream's `types.CallToolResult` completely unmodified,
`isError` included -- gateway.py is what must NOT flatten it away.
"""

from __future__ import annotations

import abc
import asyncio
import sys
from contextlib import AsyncExitStack
from typing import Awaitable, Callable

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from . import registry as registry_mod

OnListChanged = Callable[[str], Awaitable[None]]
OnToolsChanged = Callable[[], Awaitable[None]]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class UpstreamBootError(Exception):
    """One or more REQUIRED upstreams failed to connect at boot.

    `failures` is a list of (upstream_name, error_text). The gateway MUST NOT
    start serving traffic when this is raised (section 21.2 fail-closed-at-boot).
    """

    def __init__(self, failures: list[tuple[str, str]]):
        self.failures = failures
        detail = "; ".join(f"{name}: {err}" for name, err in failures)
        super().__init__(f"reeflex-mcp: required upstream(s) unreachable at boot -- {detail}")


class UpstreamUnavailableError(Exception):
    """Raised when a call targets an upstream that is unknown, down, or was
    marked non-required-and-failed at boot. NEVER silently ignored -- the
    caller (gateway.py) turns this into an isError tool result."""


class UpstreamNotConnectedError(Exception):
    """Raised by a connection's list_tools()/call_tool() if connect() was
    never called or did not succeed -- a programming-error guard, not
    expected to surface once UpstreamRegistry is used correctly."""


# ---------------------------------------------------------------------------
# The ABC (section 21.5)
# ---------------------------------------------------------------------------


class UpstreamConnection(abc.ABC):
    """One live (or not-yet-live) connection to one configured upstream."""

    def __init__(self, name: str, target_system: str, target_environment: str):
        self.name = name
        self.target_system = target_system
        self.target_environment = target_environment

    @abc.abstractmethod
    async def connect(self) -> None:
        """Establish the transport + MCP session + initialize handshake.
        Raises on any failure; caller (UpstreamRegistry) applies the timeout
        and fail-closed-at-boot policy -- this method itself never times out
        on its own and never swallows an error."""

    @abc.abstractmethod
    async def list_tools(self) -> list[types.Tool]:
        """Return this upstream's RAW (un-namespaced) tool list."""

    @abc.abstractmethod
    async def call_tool(self, tool_name: str, arguments: dict) -> types.CallToolResult:
        """Dispatch one call to the REAL (un-namespaced) tool name. Returns
        the upstream's CallToolResult completely unmodified (isError included
        -- section 21.4)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Tear down the session + transport. Idempotent; never raises on an
        already-closed connection."""


# ---------------------------------------------------------------------------
# Shared ClientSession lifecycle (both transports use the same session API
# once they have a (read_stream, write_stream) pair -- only how that pair is
# produced differs)
# ---------------------------------------------------------------------------


class _BaseUpstreamConnection(UpstreamConnection):
    def __init__(
        self,
        name: str,
        target_system: str,
        target_environment: str,
        *,
        on_list_changed: OnListChanged | None,
    ):
        super().__init__(name, target_system, target_environment)
        self._on_list_changed = on_list_changed
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    @abc.abstractmethod
    def _open_transport(self):
        """Return the async context manager yielding (read_stream, write_stream, ...)."""

    async def _message_handler(self, message: object) -> None:
        """ClientSession message_handler -- section 21.3: this is where
        `notifications/tools/list_changed` from the upstream actually
        arrives; it is NOT auto-forwarded anywhere by the SDK."""
        if isinstance(message, Exception):
            print(f"[reeflex-mcp] WARN: upstream {self.name!r} session error: {message}", file=sys.stderr)
            return
        if isinstance(message, types.ServerNotification) and isinstance(
            message.root, types.ToolListChangedNotification
        ):
            if self._on_list_changed is not None:
                await self._on_list_changed(self.name)
            return
        # Anything else (resource/prompt notifications, server->client
        # requests this gateway does not support e.g. sampling) -- mirror the
        # SDK's own _default_message_handler no-op behavior. We do not proxy
        # resources/prompts in Track 2 (see gateway.py module docstring).
        await asyncio.sleep(0)

    async def connect(self) -> None:
        stack = AsyncExitStack()
        try:
            streams = await stack.enter_async_context(self._open_transport())
            read_stream, write_stream = streams[0], streams[1]
            session = await stack.enter_async_context(
                ClientSession(read_stream, write_stream, message_handler=self._message_handler)
            )
            await session.initialize()
        except BaseException:
            # Broadened from `except Exception` (adjacent leak, BUG 1): a
            # stdio connect() TIMEOUT surfaces as asyncio.CancelledError
            # (thrown into this coroutine by connect_all()'s
            # asyncio.wait_for) -- a BaseException, not an Exception. The
            # narrower handler skipped this aclose() entirely, discarding the
            # partial stack WITHOUT tearing it down and orphaning the
            # spawned child process. Shield the teardown itself for the same
            # reason as close() below (an ancestor's in-flight cancellation
            # racing anyio's cancel-scope bookkeeping mid-teardown), then
            # re-raise the original failure -- the connect-failure return
            # contract (_connect_and_register() still sees the failure) is
            # unchanged.
            with anyio.CancelScope(shield=True):
                await stack.aclose()
            raise
        self._stack = stack
        self._session = session

    async def list_tools(self) -> list[types.Tool]:
        if self._session is None:
            raise UpstreamNotConnectedError(self.name)
        result = await self._session.list_tools()
        return list(result.tools)

    async def call_tool(self, tool_name: str, arguments: dict) -> types.CallToolResult:
        if self._session is None:
            raise UpstreamNotConnectedError(self.name)
        return await self._session.call_tool(tool_name, arguments)

    async def close(self) -> None:
        stack, self._stack = self._stack, None
        self._session = None
        if stack is None:
            return
        try:
            with anyio.CancelScope(shield=True):
                await stack.aclose()
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:  # noqa: BLE001 -- teardown must never crash the process or take a sibling's close() down. stdio_client() has no terminate_on_close knob to skip its process-kill teardown; shielding stops an ancestor's in-flight cancellation from racing anyio's cancel-scope bookkeeping mid-teardown. Time-bounded already (PROCESS_TERMINATION_TIMEOUT).
            print(f"[reeflex-mcp] WARN: closing upstream {self.name!r} failed: {exc}", file=sys.stderr)


class StdioUpstreamConnection(_BaseUpstreamConnection):
    """A stdio-launched upstream MCP server (the gateway spawns + owns the
    child process for the life of the connection)."""

    def __init__(
        self,
        name: str,
        target_system: str,
        target_environment: str,
        *,
        command: str,
        args: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        on_list_changed: OnListChanged | None = None,
    ):
        super().__init__(name, target_system, target_environment, on_list_changed=on_list_changed)
        self._params = StdioServerParameters(command=command, args=list(args), env=env or None)

    def _open_transport(self):
        return stdio_client(self._params)


class HttpUpstreamConnection(_BaseUpstreamConnection):
    """A streamable-HTTP upstream MCP server. Uses `streamable_http_client`
    (section 21.6 -- the non-deprecated SDK 1.28.1 name)."""

    def __init__(
        self,
        name: str,
        target_system: str,
        target_environment: str,
        *,
        url: str,
        auth_token: str | None = None,
        on_list_changed: OnListChanged | None = None,
    ):
        super().__init__(name, target_system, target_environment, on_list_changed=on_list_changed)
        self._url = url
        self._auth_token = auth_token

    def _open_transport(self):
        # streamable_http_client only manages an httpx.AsyncClient's lifecycle
        # if IT created one; since we build our own (to carry the bearer
        # token), we must enter/close it ourselves -- done via the same
        # AsyncExitStack in connect() below, entered just before the
        # transport cm so it unwinds in the correct (reverse) order.
        headers = {"Authorization": f"Bearer {self._auth_token}"} if self._auth_token else None
        return _HttpTransportCM(self._url, headers)


class _HttpTransportCM:
    """Small adapter so HttpUpstreamConnection can enter (httpx client, then
    streamable_http_client) as a single async context manager on the shared
    AsyncExitStack in _BaseUpstreamConnection.connect()."""

    def __init__(self, url: str, headers: dict[str, str] | None):
        self._url = url
        self._headers = headers

    async def __aenter__(self):
        self._stack = AsyncExitStack()
        client = create_mcp_http_client(headers=self._headers)
        await self._stack.enter_async_context(client)
        # terminate_on_close=False: skip the session-termination DELETE call
        # on close. Observed while building this package: when close() runs
        # from inside UpstreamRegistry.close_all()'s `finally` during stdio
        # front shutdown (client disconnects -> stdin EOF -> the SDK's own
        # stdio server task group starts cancelling), issuing a NEW httpx
        # request from within that already-cancelling scope raced anyio's
        # cancel-scope bookkeeping ("Attempted to exit a cancel scope that
        # isn't the current task's current cancel scope") and crashed process
        # shutdown. A slightly-delayed upstream-side session reap (the
        # upstream's own idle timeout) is a fully acceptable trade for a
        # gateway that closes cleanly every time -- see also close_all()'s
        # broad exception guard below for defense in depth.
        streams = await self._stack.enter_async_context(
            streamable_http_client(self._url, http_client=client, terminate_on_close=False)
        )
        return streams

    async def __aexit__(self, exc_type, exc, tb):
        await self._stack.aclose()
        return False


# ---------------------------------------------------------------------------
# Factory -- turns a parsed registry.UpstreamSpec into a live connection
# ---------------------------------------------------------------------------


def build_connection(
    spec: registry_mod.UpstreamSpec, *, on_list_changed: OnListChanged | None
) -> UpstreamConnection:
    if spec.kind == "stdio":
        return StdioUpstreamConnection(
            spec.name,
            spec.target_system,
            spec.target_environment,
            command=spec.command,  # type: ignore[arg-type]
            args=spec.args,
            env=dict(spec.env) or None,
            on_list_changed=on_list_changed,
        )
    if spec.kind == "http":
        auth_token = registry_mod.resolve_env_ref(spec.auth_token_env)
        return HttpUpstreamConnection(
            spec.name,
            spec.target_system,
            spec.target_environment,
            url=spec.url,  # type: ignore[arg-type]
            auth_token=auth_token,
            on_list_changed=on_list_changed,
        )
    raise ValueError(f"unknown upstream kind {spec.kind!r}")  # pragma: no cover -- registry.py validates this


# ---------------------------------------------------------------------------
# Process-level registry (section 21.1 / 21.2 / 21.3 / 21.5)
# ---------------------------------------------------------------------------


class UpstreamRegistry:
    """Owns every configured upstream's live connection for the life of the
    gateway process. Connect-once-at-startup, dispatch-with-timeout,
    close-at-shutdown. Zero hardcoded tool knowledge: the tool set is
    whatever each upstream's own `tools/list` reports, aggregated and
    namespaced `<upstream>__<tool>`."""

    def __init__(self, specs: list[registry_mod.UpstreamSpec], *, on_tools_changed: OnToolsChanged | None = None):
        self._specs: dict[str, registry_mod.UpstreamSpec] = {s.name: s for s in specs}
        self._connections: dict[str, UpstreamConnection] = {}
        self._up: dict[str, bool] = {}
        self._tool_cache: dict[str, list[types.Tool]] = {}
        self._on_tools_changed = on_tools_changed

    async def connect_all(self, *, connect_timeout: float) -> None:
        """Connect every configured upstream ONCE. A REQUIRED upstream that
        fails aborts the whole boot (UpstreamBootError) -- section 21.2."""
        fatal: list[tuple[str, str]] = []
        for name, spec in self._specs.items():
            ok, err = await self._connect_and_register(name, spec, connect_timeout=connect_timeout)
            if not ok and spec.required:
                fatal.append((name, err or "unknown error"))

        if fatal:
            await self.close_all()
            raise UpstreamBootError(fatal)

    async def connect_one(
        self, spec: registry_mod.UpstreamSpec, *, connect_timeout: float
    ) -> tuple[bool, str | None]:
        """Track 5 (design doc section 13) `add`/`import` hot-reload: connect
        ONE new upstream into the ALREADY-RUNNING registry, without touching
        any other upstream and WITHOUT raising UpstreamBootError even if
        `spec.required` -- unlike boot-time connect_all(), a failed hot-add
        must never tear down a gateway that is already serving traffic.
        Returns (success, error_message_or_None). On success, the caller
        (gateway.py's admin reload route) is responsible for broadcasting
        `tools/list_changed` to front sessions -- this method only updates
        the registry's own state.

        If `spec.name` already exists in this registry, it is replaced (same
        upsert-by-name semantics as registry.upsert_upstream_raw) -- the old
        connection is closed first.
        """
        existing = self._connections.pop(spec.name, None)
        if existing is not None:
            try:
                await existing.close()
            except Exception:  # noqa: BLE001 -- best-effort; see close_all()'s own docstring
                pass
        self._specs[spec.name] = spec
        return await self._connect_and_register(spec.name, spec, connect_timeout=connect_timeout)

    async def _connect_and_register(
        self, name: str, spec: registry_mod.UpstreamSpec, *, connect_timeout: float
    ) -> tuple[bool, str | None]:
        """Shared connect-one-upstream logic used by both connect_all()
        (boot) and connect_one() (Track 5 hot-add). Never raises -- always
        returns (success, error_message_or_None); the caller decides whether
        a failure is fatal (boot: only if required) or just reported
        (hot-add: never fatal)."""
        conn = build_connection(spec, on_list_changed=self._handle_upstream_tools_changed)
        self._connections[name] = conn
        try:
            await asyncio.wait_for(conn.connect(), timeout=connect_timeout)
            self._tool_cache[name] = await conn.list_tools()
            self._up[name] = True
            print(
                f"[reeflex-mcp] upstream {name!r} connected "
                f"({len(self._tool_cache[name])} tool(s), target={spec.target_system}/{spec.target_environment})",
                file=sys.stderr,
            )
            return True, None
        except Exception as exc:  # noqa: BLE001 -- reachability probe, boot or hot-add
            self._up[name] = False
            print(f"[reeflex-mcp] WARN: upstream {name!r} unreachable: {exc}", file=sys.stderr)
            return False, str(exc)

    def known_upstream_names(self) -> frozenset[str]:
        """Every upstream name this registry currently knows about
        (connected or not)."""
        return frozenset(self._specs.keys())

    def up_upstream_names(self) -> frozenset[str]:
        """Every upstream name that is CURRENTLY successfully connected --
        used by the Track 5 admin reload route to diff against a freshly-
        reloaded reeflex-mcp.yaml. Deliberately NOT known_upstream_names():
        a previously-FAILED hot-add still occupies a `_specs`/`_connections`
        entry (see _connect_and_register()), so diffing against "known"
        would silently skip retrying it forever, even after the operator
        fixed the config and asked for another reload (found live while
        demonstrating this feature -- see the Track 5 report)."""
        return frozenset(name for name, up in self._up.items() if up)

    async def _handle_upstream_tools_changed(self, name: str) -> None:
        conn = self._connections.get(name)
        if conn is None or not self._up.get(name):
            return
        try:
            self._tool_cache[name] = await conn.list_tools()
        except Exception as exc:  # noqa: BLE001
            print(f"[reeflex-mcp] WARN: refreshing tool list for {name!r} failed: {exc}", file=sys.stderr)
            return
        if self._on_tools_changed is not None:
            await self._on_tools_changed()

    def tool_annotations(self, upstream_name: str, tool_name: str) -> types.ToolAnnotations | None:
        """BUG 2 fix, option B: return the MCP-declared `types.ToolAnnotations`
        (readOnlyHint/destructiveHint/idempotentHint) for one REAL
        (un-namespaced) `tool_name` on `upstream_name`, read from the
        already-cached `_tool_cache` (populated at connect time / on
        `tools/list_changed` -- see `_connect_and_register()` and
        `_handle_upstream_tools_changed()`). Zero new network I/O.

        Returns None if the upstream is unknown/down, the tool is not in its
        cached list, or the tool itself simply declared no annotations (MCP
        annotations are optional -- absence is NOT a safe signal; see
        normalize.py's annotation tier, which treats None exactly like "no
        actionable annotation" and falls through to the name-heuristic)."""
        tools = self._tool_cache.get(upstream_name)
        if tools is None:
            return None
        for tool in tools:
            if tool.name == tool_name:
                return tool.annotations
        return None

    def aggregated_tools(self) -> list[types.Tool]:
        """The union of every UP upstream's tools, namespaced `<upstream>__<tool>`."""
        out: list[types.Tool] = []
        for name, tools in self._tool_cache.items():
            if not self._up.get(name):
                continue
            for tool in tools:
                out.append(tool.model_copy(update={"name": f"{name}__{tool.name}"}))
        return out

    def resolve(self, namespaced_name: str) -> tuple[str, str] | None:
        """Split `<upstream>__<tool>` -> (upstream_name, tool_name); None if
        malformed, or the upstream is unknown/down."""
        if "__" not in namespaced_name:
            return None
        upstream_name, tool_name = namespaced_name.split("__", 1)
        if not tool_name or upstream_name not in self._specs or not self._up.get(upstream_name):
            return None
        return upstream_name, tool_name

    def target_for(self, upstream_name: str) -> tuple[str, str]:
        spec = self._specs[upstream_name]
        return spec.target_system, spec.target_environment

    async def dispatch(
        self, upstream_name: str, tool_name: str, arguments: dict, *, timeout: float
    ) -> types.CallToolResult:
        """Dispatch-with-timeout (section 21.5). Raises UpstreamUnavailableError
        if the upstream is unknown/down; asyncio.TimeoutError if the call
        exceeds `timeout` -- both are caller (gateway.py) errors to turn into
        an isError result, never a silent drop."""
        conn = self._connections.get(upstream_name)
        if conn is None or not self._up.get(upstream_name):
            raise UpstreamUnavailableError(upstream_name)
        return await asyncio.wait_for(conn.call_tool(tool_name, arguments), timeout=timeout)

    async def close_all(self) -> None:
        """Best-effort shutdown: every upstream gets a close() attempt even if
        an earlier one fails. Catches BaseException, not just Exception --
        close() commonly runs from a `finally` while the front transport's
        OWN task group is already unwinding/cancelling (e.g. stdio client
        disconnect -> stdin EOF), and `asyncio.CancelledError` is a
        BaseException (not Exception) since Python 3.8. Never let a
        shutdown-time cancellation propagate and crash the process --
        KeyboardInterrupt/SystemExit are the only things still re-raised."""
        for name, conn in list(self._connections.items()):
            try:
                await conn.close()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:  # noqa: BLE001 -- best-effort shutdown, see docstring
                print(f"[reeflex-mcp] WARN: closing upstream {name!r} failed: {exc}", file=sys.stderr)
