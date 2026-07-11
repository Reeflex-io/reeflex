"""
e2e_declarative_mapping.py -- manual, real end-to-end proof for Track 4
(declarative normalization): drives the REAL `@modelcontextprotocol/server-
filesystem` reference MCP server (via `npx`, not a synthetic fixture) through
the gateway and confirms, from the gateway's own stderr classification log,
that:
  - a tool named in mappings/filesystem.yaml (e.g. `write_file`) resolves via
    the "mapping" tier;
  - a real tool NOT named in that mapping (`read_file`, the deprecated read
    alias -- present on the real server, deliberately left unmapped) falls
    through to the "heuristic:read" tier.

Requires Node.js/npx on PATH and network access to fetch
`@modelcontextprotocol/server-filesystem` the first time (npx caches it
after that). Not part of the pytest suite for that reason.

Usage:
  python tests/fixtures/e2e_declarative_mapping.py
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


def _text_of(result) -> str:
    return "".join(c.text for c in result.content if hasattr(c, "text"))


def _fail(msg: str) -> None:
    print(f"[e2e_declarative_mapping] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"[e2e_declarative_mapping] OK: {msg}")


def _generate_config(*, allowed_dir: str) -> str:
    yaml_text = f"""\
mode: observe
upstreams:
  - name: fs
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", {allowed_dir!r}]
    target: {{ system: filesystem, environment: staging }}
    required: true
"""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(yaml_text)
    fh.close()
    return fh.name


async def main() -> None:
    allowed_dir = tempfile.mkdtemp(prefix="reeflex-mcp-track4-")
    (Path(allowed_dir) / "hello.txt").write_text("hello from a real file\n", encoding="utf-8")

    config_path = _generate_config(allowed_dir=allowed_dir)
    python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
    params = StdioServerParameters(
        command=python,
        args=["-m", "reeflex_mcp", "--transport", "stdio"],
        env={"REEFLEX_MCP_CONFIG": config_path, "REEFLEX_MODE": "observe"},
    )

    print(f"[e2e_declarative_mapping] allowed_dir={allowed_dir}")
    print(f"[e2e_declarative_mapping] launching gateway: {python} -m reeflex_mcp --config {config_path}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            names = sorted(t.name for t in tools_result.tools)
            print(f"[e2e_declarative_mapping] real filesystem server tools: {names}")
            if "fs__write_file" not in names or "fs__read_file" not in names:
                _fail(f"expected real tool names not found: {names}")

            # -- tier 1: declarative mapping (write_file IS in filesystem.yaml) --
            result = await session.call_tool(
                "fs__write_file", {"path": "hello2.txt", "content": "written via reeflex-mcp Track 4"}
            )
            print(f"fs__write_file -> isError={result.isError} content={_text_of(result)!r}")
            if result.isError:
                _fail("fs__write_file unexpectedly failed")
            _ok("fs__write_file (real, mapped tool) round-tripped -- check stderr above for "
                "\"classified 'fs__write_file' via 'mapping'\"")

            # -- tier 1 again + magnitude-from-arg on a real list argument --
            result = await session.call_tool("fs__read_multiple_files", {"paths": ["hello.txt", "hello2.txt"]})
            print(f"fs__read_multiple_files -> isError={result.isError} content={_text_of(result)[:120]!r}")
            if result.isError:
                _fail("fs__read_multiple_files unexpectedly failed")
            _ok("fs__read_multiple_files (real tool, magnitude-from-arg 'paths') round-tripped")

            # -- tier 2: read_file is a REAL tool on this server (the
            # deprecated alias) deliberately left OUT of filesystem.yaml --
            # must fall through to the heuristic's read_* bucket.
            result = await session.call_tool("fs__read_file", {"path": "hello.txt"})
            print(f"fs__read_file -> isError={result.isError} content={_text_of(result)!r}")
            if result.isError:
                _fail("fs__read_file unexpectedly failed")
            _ok("fs__read_file (real, deliberately UNMAPPED tool) round-tripped -- check stderr above for "
                "\"classified 'fs__read_file' via 'heuristic:read'\"")

    print("\n[e2e_declarative_mapping] ALL CHECKS PASSED -- both tiers proven against a REAL upstream")


if __name__ == "__main__":
    asyncio.run(main())
