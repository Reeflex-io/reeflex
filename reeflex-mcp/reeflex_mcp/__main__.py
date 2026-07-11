"""__main__.py -- enables `python -m reeflex_mcp` (same entry point as the
`reeflex-mcp` console script; see cli.py).

Unlike reeflex-holds/reeflex-claude's __main__.py (whose main() functions run
an MCP server loop or always exit 0 themselves), reeflex_mcp.cli.main()
RETURNS a meaningful exit code (0 pass / 1 fail -- see cmd_check() and
UpstreamBootError handling in cmd_run()), so it MUST be passed to sys.exit()
here -- a bare `main()` call would silently discard that code and always
exit 0 regardless of PASS/FAIL, which would itself be a fail-open bug in the
`check` self-test's own reporting when invoked via `python -m reeflex_mcp`
(found and fixed while validating the Track 3 self-probe)."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
