"""
e2e_http_front_check.py -- manual proof for design/MCP-GATEWAY-DESIGN.md
ADDENDUM v1.2 section 21.1: on streamable-HTTP front transport, upstream
connections must be established ONCE per gateway PROCESS, never once per
front-side MCP session.

This is exactly the bug the spike caught (2 client sessions -> 2 upstream
subprocesses) and exactly what run_streamable_http()'s router.lifespan_context
wrap (gateway.py) is supposed to prevent. This script drives the SAME
running gateway process with TWO SEPARATE front client sessions and asserts
the gateway's own upstream-connect log line appears exactly once per
upstream -- i.e. the second front session reuses the already-connected
upstream registry, it does not trigger a second connect.

Prerequisites: the gateway must already be running in streamable-http mode
against a config with at least one upstream, with its stderr redirected to a
file (see the adapter-builder's final report for the exact commands used).

Usage:
  python tests/fixtures/e2e_http_front_check.py <gateway_url> <gateway_stderr_log_path>
"""

from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def _one_session(url: str) -> None:
    async with streamable_http_client(url) as (read, write, _get_sid):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"[http_front_check] session saw {len(tools.tools)} tool(s): "
                  f"{sorted(t.name for t in tools.tools)}")


async def main(url: str) -> None:
    print(f"[http_front_check] opening front session #1 against {url}")
    await _one_session(url)
    print("[http_front_check] front session #1 closed")

    print(f"[http_front_check] opening front session #2 against {url}")
    await _one_session(url)
    print("[http_front_check] front session #2 closed")


def _check_log(log_path: str) -> None:
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    connect_lines = [ln for ln in lines if "upstream" in ln and "connected" in ln]
    print(f"[http_front_check] gateway log 'upstream ... connected' lines ({len(connect_lines)}):")
    for ln in connect_lines:
        print(f"    {ln.rstrip()}")
    # Exactly one connect line PER CONFIGURED UPSTREAM, regardless of how many
    # front sessions connected above -- section 21.1's whole point.
    by_upstream: dict[str, int] = {}
    for ln in connect_lines:
        # format: "[reeflex-mcp] upstream 'name' connected (...)"
        try:
            name = ln.split("upstream '", 1)[1].split("'", 1)[0]
        except IndexError:
            continue
        by_upstream[name] = by_upstream.get(name, 0) + 1
    print(f"[http_front_check] connect count per upstream: {by_upstream}")
    for name, count in by_upstream.items():
        if count != 1:
            print(f"[http_front_check] FAIL: upstream {name!r} connected {count} times, expected exactly 1")
            sys.exit(1)
    if not by_upstream:
        print("[http_front_check] FAIL: no connect lines found at all")
        sys.exit(1)
    print("[http_front_check] PASS: every upstream connected exactly once, across 2 front sessions")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: e2e_http_front_check.py <gateway_url> <gateway_stderr_log_path>", file=sys.stderr)
        sys.exit(2)
    gateway_url, log_path = sys.argv[1], sys.argv[2]
    asyncio.run(main(gateway_url))
    _check_log(log_path)
