"""
enforce.py -- POST the Action Envelope to reeflex-core /v1/decide and map the
Decision to a Claude Code permissionDecision.

FAIL-CLOSED INVARIANT (mirrors mock/adapter.py):
  On ANY error (connection refused, timeout, non-200 without decision, JSON
  parse failure, missing 'decision' field, unknown decision value, any
  exception) we return ("deny", <reason>, <rule>, False, []) and the hook
  emits deny + exits 0.  We NEVER silently allow on error.

  This module never raises.  The hook's top-level try/except is a belt-and-
  suspenders backup; this layer handles all expected failure modes itself.

Decision mapping (SPEC §5 -> Claude Code permissionDecision):
  core "allow"            -> "allow"
  core "deny"             -> "deny"
  core "require_approval" -> "ask"   (routes to the human confirmation dialog)
  core unreachable / error -> "deny" (fail-closed)

Return tuple: (permission_decision, reason_text, rule, core_reachable, obligations)
  obligations: list[str] -- the obligations from the core Decision (empty on error)

Env:
  REEFLEX_CORE_URL       -- default http://127.0.0.1:8080
  REEFLEX_CLAUDE_TIMEOUT -- float seconds for HTTP request timeout; default 5.0
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_CORE_URL = "http://127.0.0.1:8080"
_DEFAULT_TIMEOUT  = 5.0
_MAX_ERROR_LEN    = 300   # max chars of external error text in reason strings

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Return type: (permissionDecision, reason_text, rule, core_reachable, obligations)
_Result = Tuple[str, str, str, bool, List[str]]


def call_core_and_map(envelope: dict) -> _Result:
    """
    POST envelope to /v1/decide; map core Decision to permissionDecision.

    Returns (permission_decision, reason, rule, core_reachable, obligations).
    Never raises.
    """
    core_url = os.environ.get("REEFLEX_CORE_URL", _DEFAULT_CORE_URL).rstrip("/")
    timeout  = _parse_timeout()

    url  = f"{core_url}/v1/decide"
    body = json.dumps(envelope).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw    = resp.read()
    except urllib.error.HTTPError as exc:
        # HTTP 4xx/5xx -- try to parse a decision from the body
        try:
            raw    = exc.read()
            status = exc.code
            parsed = json.loads(raw.decode("utf-8"))
            if "decision" in parsed:
                return _map_decision(parsed, core_reachable=True)
        except Exception:
            pass
        return _fail_closed(f"core HTTP {exc.code}: {_trunc(str(exc.reason))}")
    except Exception as exc:
        # Connection refused, timeout, DNS failure, etc.
        return _fail_closed(f"core unreachable: {_trunc(str(exc))}")

    # Parse response body
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return _fail_closed(f"core response not JSON: {_trunc(str(exc))}")

    # Non-200 with embedded decision (e.g. core's 500 fail-closed response)
    if status != 200:
        if "decision" in parsed:
            return _map_decision(parsed, core_reachable=True)
        return _fail_closed(f"core returned HTTP {status} without decision")

    # 200 but missing decision field
    if "decision" not in parsed:
        return _fail_closed("core response missing 'decision' field")

    return _map_decision(parsed, core_reachable=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_decision(decision_resp: dict, core_reachable: bool) -> _Result:
    """
    Map core decision -> permissionDecision.

    core "allow"            -> "allow"
    core "deny"             -> "deny"
    core "require_approval" -> "ask"
    anything else           -> "deny" (fail-closed on unknown value)
    """
    decision    = decision_resp.get("decision", "")
    reason      = decision_resp.get("reason", "")
    rule        = decision_resp.get("rule", "unknown")
    obligations = decision_resp.get("obligations", [])
    # Coerce to list (defensive -- policy could return null or a non-list)
    if not isinstance(obligations, list):
        obligations = list(obligations) if obligations else []

    # Compose the reason string that will be shown to the user / model
    reason_text = f"Reeflex: {reason} [rule={rule}]"

    if decision == "allow":
        return ("allow", reason_text, rule, core_reachable, obligations)
    elif decision == "deny":
        return ("deny", reason_text, rule, core_reachable, obligations)
    elif decision == "require_approval":
        return ("ask", reason_text, rule, core_reachable, obligations)
    else:
        return (
            "deny",
            f"Reeflex: unknown decision value '{_trunc(decision)}' -- failing closed "
            f"[rule=adapter/unknown_decision]",
            "adapter/unknown_decision_fail_closed",
            core_reachable,
            [],
        )


def _fail_closed(reason: str) -> _Result:
    """Return a deny decision indicating core was unreachable or errored."""
    rule = "reeflex.core/fail_closed"
    return (
        "deny",
        f"Reeflex: core unreachable or error -- failing closed: {reason} [rule={rule}]",
        rule,
        False,
        [],
    )


def _trunc(text: str) -> str:
    """Truncate external/error text to _MAX_ERROR_LEN chars to avoid leaking huge strings."""
    if len(text) > _MAX_ERROR_LEN:
        return text[:_MAX_ERROR_LEN] + "...[truncated]"
    return text


def _parse_timeout() -> float:
    """Read REEFLEX_CLAUDE_TIMEOUT; default 5.0 seconds."""
    raw = os.environ.get("REEFLEX_CLAUDE_TIMEOUT", "")
    try:
        v = float(raw)
        return v if v > 0 else _DEFAULT_TIMEOUT
    except (ValueError, TypeError):
        return _DEFAULT_TIMEOUT
