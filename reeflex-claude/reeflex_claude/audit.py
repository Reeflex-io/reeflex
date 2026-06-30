"""
audit.py -- Best-effort JSONL audit writer (SPEC §6, §7: one record per decision).

AUDIT INVARIANT: a write failure MUST NOT change the decision or raise to the caller.
This module always catches its own exceptions and logs a WARN to stderr.

Default log path: <tempdir>/reeflex-claude-audit.jsonl
Override with env REEFLEX_CLAUDE_AUDIT_LOG.

Record fields (one per decision):
  ts                 UTC ISO-8601 Z
  session_id         "claude:<hook_session_id>" (from envelope.agent.session_id)
  tool_name          string
  verb               string (SPEC §3)
  ability            string (e.g. "claude-code/Bash")
  environment        string (production|staging|dev)
  axes               {reversibility, blast_radius, externality}
  classification_tier string
  danger_signature   string
  decision           string (allow|deny|require_approval)
  rule               string
  reason             string
  obligations        list[str]   -- obligations from the core Decision (SPEC §5)
  permission_decision string (allow|deny|ask -- the mapped value)
  core_reachable     bool
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import List


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _audit_log_path() -> str:
    configured = os.environ.get("REEFLEX_CLAUDE_AUDIT_LOG", "").strip()
    if configured:
        return configured
    return os.path.join(tempfile.gettempdir(), "reeflex-claude-audit.jsonl")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def emit(
    envelope: dict,
    permission_decision: str,
    rule: str,
    reason: str,
    core_reachable: bool,
    obligations: List[str] = None,
) -> None:
    """
    Append one JSONL audit record derived from the envelope + decision result.
    Never raises; prints a WARN to stderr on write failure.

    obligations: list of obligation strings from the core Decision (SPEC §5).
                 Included in the audit record regardless of permission_decision
                 so the audit trail shows what was required.
    """
    if obligations is None:
        obligations = []
    try:
        record = _build_record(
            envelope=envelope,
            permission_decision=permission_decision,
            rule=rule,
            reason=reason,
            core_reachable=core_reachable,
            obligations=obligations,
        )
        line = json.dumps(record, separators=(",", ":")) + "\n"
        log_path = _audit_log_path()
        # Ensure parent directory exists
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
    except Exception as exc:  # noqa: BLE001
        print(f"[reeflex-claude] WARN: audit write failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_record(
    envelope: dict,
    permission_decision: str,
    rule: str,
    reason: str,
    core_reachable: bool,
    obligations: List[str],
) -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    agent   = envelope.get("agent") or {}
    action  = envelope.get("action") or {}
    target  = envelope.get("target") or {}
    axes    = envelope.get("axes") or {}
    context = envelope.get("context") or {}
    meta    = envelope.get("meta") or {}

    # Core decision is embedded in the reason string that was already built by
    # enforce.py.  We reconstruct the raw decision value from permission_decision.
    # allow->allow, deny->deny, ask->require_approval
    _pd_to_decision = {"allow": "allow", "deny": "deny", "ask": "require_approval"}
    raw_decision = _pd_to_decision.get(permission_decision, "deny")

    return {
        "ts":                 ts,
        "session_id":         agent.get("session_id"),
        "tool_name":          context.get("tool_name") or action.get("ability", "").split("/", 1)[-1],
        "verb":               action.get("verb"),
        "ability":            action.get("ability"),
        "environment":        target.get("environment"),
        "axes":               axes,
        "classification_tier": context.get("classification_tier"),
        "danger_signature":   context.get("danger_signature"),
        "decision":           raw_decision,
        "rule":               rule,
        "reason":             reason,
        "obligations":        obligations,
        "permission_decision": permission_decision,
        "core_reachable":     core_reachable,
        "nonce":              meta.get("nonce"),
    }
