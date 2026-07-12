"""
e2e_obligations.py -- manual, real end-to-end proof for Track 5.1
(obligations, design doc ADDENDUM v1.5 section 25 / SPEC section 5+7#5):
a REAL gateway subprocess (enforce mode) + a REAL stdio upstream
(tests/fixtures/stdio_upstream.py) + a REAL stub-core HTTP server
(tests/fixtures/stub_core_obligations.py, standing in for reeflex-core since
its real base policy pack emits no obligations today) + a REAL MCP client.

Proves, against a live process (not just the in-process unit tests in
tests/test_gateway_obligations.py):
  (a) allow + empty obligations -> forwards normally
  (b) allow + a KNOWN obligation ('audit:full') -> applied (visible in the
      gateway's own stderr log) + forwarded
  (c) allow + an UNKNOWN obligation ('redact:pii') -> BLOCKED (isError=True,
      reason names the obligation + the decision_id), upstream NEVER
      dispatched

Usage:
  1. python tests/fixtures/stub_core_obligations.py --port 8080   (separate terminal/background)
  2. python tests/fixtures/e2e_obligations.py
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


def _generate_config(*, python: str) -> str:
    notes_script = str(_HERE / "stdio_upstream.py")
    yaml_text = f"""\
mode: enforce
upstreams:
  - name: notes
    command: [{python!r}, {notes_script!r}]
    target: {{ system: notes, environment: production }}
    required: true
"""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(yaml_text)
    fh.close()
    return fh.name


def _text_of(result) -> str:
    return "".join(c.text for c in result.content if hasattr(c, "text"))


def _fail(msg: str) -> None:
    print(f"[e2e_obligations] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"[e2e_obligations] OK: {msg}")


async def main(config_path: str) -> None:
    python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
    params = StdioServerParameters(
        command=python,
        args=["-m", "reeflex_mcp", "--transport", "stdio"],
        env={"REEFLEX_MCP_CONFIG": config_path, "REEFLEX_MODE": "enforce"},
    )

    print(f"[e2e_obligations] launching gateway (enforce mode) against the stub core: "
          f"{python} -m reeflex_mcp --config {config_path}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # -- (a) empty obligations -> forwards -----------------------
            print("\n=== (a) read_note -- stub core returns obligations: [] ===")
            result = await session.call_tool("notes__read_note", {"name": "alpha"})
            text = _text_of(result)
            print(f"isError={result.isError} meta={result.meta} content={text!r}")
            if result.isError:
                _fail("read_note unexpectedly blocked")
            _ok("empty obligations -> forwarded normally")

            # -- (b) known obligation 'audit:full' -> applied + forwarded --
            print("\n=== (b) delete_note -- stub core returns obligations: ['audit:full'] (KNOWN) ===")
            result = await session.call_tool("notes__delete_note", {"name": "beta"})
            text = _text_of(result)
            print(f"isError={result.isError} meta={result.meta} content={text!r}")
            if result.isError:
                _fail("delete_note (known obligation) unexpectedly blocked -- check gateway stderr above for "
                      "the 'OBLIGATION audit:full honored' log line")
            _ok("known obligation 'audit:full' applied (see gateway stderr: 'OBLIGATION audit:full honored') "
                "and the call still forwarded")

            # -- (c) unknown obligation 'redact:pii' -> BLOCKED ------------
            print("\n=== (c) delete_notes -- stub core returns obligations: ['redact:pii'] (UNKNOWN) ===")
            result = await session.call_tool("notes__delete_notes", {"names": ["ghost-1", "ghost-2"]})
            text = _text_of(result)
            print(f"isError={result.isError} content={text!r}")
            if not result.isError:
                _fail("delete_notes with an UNKNOWN obligation was forwarded -- THIS IS THE CONFORMANCE BUG")
            if "unsupported obligation" not in text or "redact:pii" not in text:
                _fail(f"blocked, but the reason text doesn't name the obligation correctly: {text!r}")
            if "deleted_count" in text:
                _fail("the upstream's own return value leaked through a supposedly-blocked call!")
            _ok("unknown obligation 'redact:pii' correctly BLOCKED before any dispatch -- "
                "isError=True, reason names the obligation, upstream never ran")

    print("\n[e2e_obligations] ALL CHECKS PASSED")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        config_arg = sys.argv[1]
    else:
        _python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
        config_arg = _generate_config(python=_python)
        print(f"[e2e_obligations] generated config at {config_arg}")
    asyncio.run(main(config_arg))
