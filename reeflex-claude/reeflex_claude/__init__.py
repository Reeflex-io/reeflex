"""
reeflex_claude -- Claude Code PreToolUse adapter for Reeflex governance.

Implements the four Reeflex adapter responsibilities (SPEC §6):
  INTERCEPT  -- PreToolUse hook (Claude Code calls this before every tool execution)
  NORMALIZE  -- classify.py + envelope.py produce a signed Action Envelope (SPEC §2)
  ENFORCE    -- enforce.py POSTs to reeflex-core /v1/decide and maps the Decision
  AUDIT      -- audit.py appends one JSONL record per decision

Entry points:
  `reeflex-claude hook|setup|check`  (console script, after `pip install reeflex-claude`)
  `python -m reeflex_claude`         (back-compat: runs the hook directly)
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("reeflex-claude")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
