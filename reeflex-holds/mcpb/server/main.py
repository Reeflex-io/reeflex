"""
main.py -- MCPB entry shim for reeflex-holds.

Claude Desktop launches this file directly (see manifest.json's
server.mcp_config: `python ${__dirname}/server/main.py`). It does nothing on
its own: it imports the real package (installed under server/lib/ by
build.ps1 / build.sh, and put on PYTHONPATH by the manifest's env block) and
calls its actual entry point -- the same `main()` that the `reeflex-holds`
console script and `python -m reeflex_holds` call.

Kept intentionally thin (YAGNI): this file exists only because the MCPB
"python" server type wants a single launchable script, not a package/module
target. All real behavior lives in reeflex_holds itself.
"""

from __future__ import annotations

from reeflex_holds.server import main

if __name__ == "__main__":
    main()
