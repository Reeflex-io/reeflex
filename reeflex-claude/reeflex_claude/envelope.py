"""
envelope.py -- Build the Reeflex Action Envelope (SPEC §2) from a Claude Code
PreToolUse hook payload + classify.py classification result.

This module is pure: no network, no I/O, no side effects.  It takes the raw
hook JSON (parsed dict) and a classification dict and returns a signed Action
Envelope.

The envelope shape mirrors reeflex-mock/adapter.py exactly, extended for the
Claude Code backend.

Required env:
  REEFLEX_CLAUDE_PRINCIPAL   -- on_behalf_of value (nullable; default None)
  REEFLEX_CLAUDE_ENVIRONMENT -- target environment (production|staging|dev;
                                default "production" -- conservative)
"""

from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REEFLEX_VERSION = "0.1"
_AGENT_ID        = "agent:claude-code"
_NAMESPACE       = "claude-code"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_envelope(hook_payload: dict, cls: dict) -> dict:
    """
    Construct a signed Action Envelope from the PreToolUse hook payload and the
    output of classify.classify().

    hook_payload fields used:
      session_id      (REQUIRED -- fail-closed if missing/empty)
      tool_name       string
      tool_input      object
      cwd             string (optional)

    cls fields (from classify.py):
      verb, reversibility, blast_radius, externality,
      magnitude_count, target_kind, target_ref, danger_signature,
      classification_tier, command_preview, file_path

    Raises:
      ValueError if session_id is missing or empty.
    """
    session_id = hook_payload.get("session_id") or ""
    if not session_id:
        raise ValueError("session_id missing or empty -- fail-closed required")

    tool_name  = hook_payload.get("tool_name") or "unknown"
    tool_input = hook_payload.get("tool_input") or {}

    # Agent block
    on_behalf_of = os.environ.get("REEFLEX_CLAUDE_PRINCIPAL") or None
    agent = {
        "id": _AGENT_ID,
        "on_behalf_of": on_behalf_of,
        "session_id": "claude:" + session_id,
    }

    # Action block
    action = {
        "namespace": _NAMESPACE,
        "verb": cls["verb"],
        "ability": f"claude-code/{tool_name}",
    }

    # Target block
    environment = _get_environment()
    target = {
        "kind": cls["target_kind"],
        "ref": cls.get("target_ref"),
        "environment": environment,
    }

    # Params block -- small, structured; do NOT dump full content
    params = {
        "tool_name": tool_name,
        "verb_source": _verb_source(tool_name, cls["verb"], tool_input),
    }

    # Magnitude
    magnitude = {
        "count": max(int(cls.get("magnitude_count", 1)), 1),
    }

    # Axes
    axes = {
        "reversibility": cls["reversibility"],
        "blast_radius":  cls["blast_radius"],
        "externality":   cls["externality"],
    }

    # Approval -- always false at interception
    approval = {
        "present": False,
        "by": None,
        "role": None,
    }

    # Context (fixed contract -- demo Rego pack keys on classification_tier)
    context = {
        "tool_name":          tool_name,
        "command_preview":    cls.get("command_preview"),
        "file_path":          cls.get("file_path"),
        "danger_signature":   cls["danger_signature"],
        "classification_tier": cls["classification_tier"],
    }

    # Meta: timestamp, nonce, stub signature (mirrors mock/adapter.py)
    ts        = _now_utc()
    nonce     = _make_nonce(session_id, ts, tool_name,
                            cls.get("command_preview") or cls.get("file_path") or "")
    signature = f"ed25519:stub:{nonce[:16]}"

    meta = {
        "timestamp": ts,
        "nonce":     nonce,
        "signature": signature,
    }

    return {
        "reeflex_version":  _REEFLEX_VERSION,
        "agent":            agent,
        "action":           action,
        "target":           target,
        "params":           params,
        "magnitude":        magnitude,
        "axes":             axes,
        "approval":         approval,
        "trajectory_ref":   None,
        "context":          context,
        "meta":             meta,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_environment() -> str:
    """
    Read REEFLEX_CLAUDE_ENVIRONMENT; default to "production" (conservative).
    Only accepts production | staging | dev; anything else falls back to production.
    """
    v = os.environ.get("REEFLEX_CLAUDE_ENVIRONMENT", "production").strip().lower()
    if v in ("production", "staging", "dev"):
        return v
    return "production"


def _verb_source(tool_name: str, verb: str, tool_input: dict) -> str:
    """
    Short description of why this verb was assigned; used in params for
    transparency but never used as policy input.
    """
    if tool_name.lower() == "bash":
        cmd = tool_input.get("command", "")
        preview = str(cmd)[:40] if cmd else ""
        return f"bash_intent_parse:{preview}"
    return f"tool_name_map:{tool_name}"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_nonce(session_id: str, ts: str, tool_name: str, content_preview: str) -> str:
    """
    Generate a determinism-safe nonce.  Mirrors mock/adapter.py: sha256 of
    session + ts + tool + content_preview + monotonic_ns, hex[:32].
    """
    raw = f"{session_id}:{ts}:{tool_name}:{content_preview}:{time.monotonic_ns()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
