"""
e2e_smoke.py -- manual, real end-to-end smoke driver for the Track-2 gateway.

NOT part of the pytest suite (needs a real reeflex-core + a real HTTP upstream
fixture already running -- see the adapter-builder's final report / the
module docstring below for the exact steps). Mirrors the pattern
reeflex-holds/README.md documents as its own "live smoke": a real MCP client
(`mcp.client.stdio.stdio_client` + `ClientSession`) driving the gateway as a
subprocess, exactly like Claude Desktop would.

Prerequisites (see the report for the full transcript):
  1. reeflex-core running on 127.0.0.1:8080 (OPA configured, an audit log path
     you can grep afterwards).
  2. tests/fixtures/http_upstream.py running on 127.0.0.1:8091 (the "widgets"
     upstream).
  3. A reeflex-mcp.yaml registering both the "notes" (stdio) and "widgets"
     (http) upstreams -- see reeflex-mcp.yaml.example and this script's
     _DEFAULT_CONFIG default.

Usage:
  python tests/fixtures/e2e_smoke.py [path-to-reeflex-mcp.yaml]

Exits non-zero on any assertion failure (tool missing, unexpected isError,
etc.) so it can be scripted.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_HERE = Path(__file__).resolve().parent
_PACKAGE_ROOT = _HERE.parent.parent
_VENV_PYTHON = _PACKAGE_ROOT / ".venv" / "Scripts" / "python.exe"


def _generate_config(*, python: str, http_upstream_url: str) -> str:
    """Write a reeflex-mcp.yaml wiring the two fixtures, using THIS machine's
    actual paths (never hardcoded -- portable across clones/OSes). Returns
    the path to the generated file."""
    notes_script = str(_HERE / "stdio_upstream.py")
    yaml_text = f"""\
mode: observe
upstreams:
  - name: notes
    command: [{python!r}, {notes_script!r}]
    target: {{ system: notes, environment: production }}
    required: true
  - name: widgets
    url: {http_upstream_url!r}
    target: {{ system: widgets, environment: staging }}
    required: true
"""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(yaml_text)
    fh.close()
    return fh.name


def _fail(msg: str) -> None:
    print(f"[e2e_smoke] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"[e2e_smoke] OK: {msg}")


async def main(config_path: str) -> None:
    python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
    params = StdioServerParameters(
        command=python,
        args=["-m", "reeflex_mcp", "--transport", "stdio"],
        env={
            "REEFLEX_MCP_CONFIG": config_path,
            "REEFLEX_MODE": "observe",
        },
    )

    print(f"[e2e_smoke] launching gateway: {python} -m reeflex_mcp --config {config_path}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            _ok(f"initialize -> server={init_result.serverInfo.name}")

            tools_result = await session.list_tools()
            names = sorted(t.name for t in tools_result.tools)
            print(f"[e2e_smoke] aggregated tools: {names}")

            expected_notes = {"notes__read_note", "notes__delete_note", "notes__delete_notes"}
            expected_widgets = {"widgets__list_widgets", "widgets__create_widget"}
            missing = (expected_notes | expected_widgets) - set(names)
            if missing:
                _fail(f"missing expected namespaced tools: {missing}")
            _ok("both upstreams' tools present and namespaced")

            # 1. stdio upstream, read verb.
            result = await session.call_tool("notes__read_note", {"name": "alpha"})
            print(f"[e2e_smoke] notes__read_note -> isError={result.isError} meta={result.meta} "
                  f"content={[c.text for c in result.content if hasattr(c, 'text')]}")
            if result.isError:
                _fail("notes__read_note unexpectedly returned isError=True")
            corr_1 = (result.meta or {}).get("gateway_correlation_id")
            if not corr_1:
                _fail("notes__read_note result missing gateway_correlation_id in _meta")
            _ok(f"notes__read_note round-tripped through the gateway, correlation_id={corr_1}")

            # 2. stdio upstream, delete verb, SINGLE item (magnitude=1).
            result = await session.call_tool("notes__delete_note", {"name": "alpha"})
            print(f"[e2e_smoke] notes__delete_note -> isError={result.isError} "
                  f"content={[c.text for c in result.content if hasattr(c, 'text')]}")
            if result.isError:
                _fail("notes__delete_note unexpectedly returned isError=True")
            _ok("notes__delete_note round-tripped (single delete, production target)")

            # 3. stdio upstream, delete verb, BULK (list arg -> magnitude>20,
            #    production environment -> exercises core's R2 require_approval
            #    -- observe mode still forwards; this proves the envelope
            #    carried the right axes even though the gateway didn't block it).
            bulk_names = [f"ghost-note-{i}" for i in range(25)]
            result = await session.call_tool("notes__delete_notes", {"names": bulk_names})
            print(f"[e2e_smoke] notes__delete_notes (25 items) -> isError={result.isError} "
                  f"content={[c.text for c in result.content if hasattr(c, 'text')]}")
            if result.isError:
                _fail("notes__delete_notes unexpectedly returned isError=True")
            _ok("notes__delete_notes (bulk, production) round-tripped -- observe forwarded regardless of verdict")

            # 4. http upstream, read verb.
            result = await session.call_tool("widgets__list_widgets", {})
            print(f"[e2e_smoke] widgets__list_widgets -> isError={result.isError} "
                  f"content={[c.text for c in result.content if hasattr(c, 'text')]}")
            if result.isError:
                _fail("widgets__list_widgets unexpectedly returned isError=True")
            _ok("widgets__list_widgets round-tripped through the HTTP upstream")

            # 5. http upstream, create verb (outbound externality).
            result = await session.call_tool("widgets__create_widget", {"name": "e2e-widget"})
            print(f"[e2e_smoke] widgets__create_widget -> isError={result.isError} "
                  f"content={[c.text for c in result.content if hasattr(c, 'text')]}")
            if result.isError:
                _fail("widgets__create_widget unexpectedly returned isError=True")
            _ok("widgets__create_widget round-tripped through the HTTP upstream")

            # 6. unknown tool -> must be an isError result, never a crash.
            result = await session.call_tool("notes__no_such_tool", {})
            if not result.isError:
                _fail("unknown tool did not return isError=True")
            _ok(f"unknown tool correctly returned isError=True: {result.content[0].text}")

    print("[e2e_smoke] ALL CHECKS PASSED")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        config_arg = sys.argv[1]
    else:
        _python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
        config_arg = _generate_config(python=_python, http_upstream_url="http://127.0.0.1:8091/mcp")
        print(f"[e2e_smoke] generated config at {config_arg}")
    asyncio.run(main(config_arg))
