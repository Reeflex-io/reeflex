"""
hook_entry.py -- Top-level shim for Claude Code PreToolUse hook.

Usage in Claude Code settings.json:
  "command": "python <ABSOLUTE_PATH>/reeflex-claude/hook_entry.py"

This shim adds the reeflex-claude root to sys.path and delegates to
reeflex_claude.hook.main().  It is equivalent to `python -m reeflex_claude`.
"""

import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from reeflex_claude.hook import main  # noqa: E402

if __name__ == "__main__":
    main()
