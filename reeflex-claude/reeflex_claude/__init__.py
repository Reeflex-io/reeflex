"""
reeflex_claude -- Claude Code PreToolUse adapter for Reeflex governance.

Implements the four Reeflex adapter responsibilities (SPEC §6):
  INTERCEPT  -- PreToolUse hook (Claude Code calls this before every tool execution)
  NORMALIZE  -- classify.py + envelope.py produce a signed Action Envelope (SPEC §2)
  ENFORCE    -- enforce.py POSTs to reeflex-core /v1/decide and maps the Decision
  AUDIT      -- audit.py appends one JSONL record per decision

Entry points:
  `reeflex-claude hook|setup|connect|check|status`
                                     (console script, after `pip install reeflex-claude`)
  `python -m reeflex_claude`         (back-compat: runs the hook directly)

`check` answers a question about the PACKAGE: can the wired hook be spawned,
and does it fail closed.  `status` answers a question about the INSTALLATION:
of the tools Claude Code has, which ones are routed to the hook at all -- see
posture.py (RFX-325).
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("reeflex-claude")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
