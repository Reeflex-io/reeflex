"""
reeflex_claude -- Claude Code PreToolUse adapter for Reeflex governance.

Implements the four Reeflex adapter responsibilities (SPEC §6):
  INTERCEPT  -- PreToolUse hook (Claude Code calls this before every tool execution)
  NORMALIZE  -- classify.py + envelope.py produce a signed Action Envelope (SPEC §2)
  ENFORCE    -- enforce.py POSTs to reeflex-core /v1/decide and maps the Decision
  AUDIT      -- audit.py appends one JSONL record per decision

Entry point: `python -m reeflex_claude`  (hook.main)
"""

__version__ = "0.1.0"
