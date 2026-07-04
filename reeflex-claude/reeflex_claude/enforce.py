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
  REEFLEX_VERIFY_SSL     -- default TRUE (full TLS verification).
                            Falsy values (0, false, no, off, case-insensitive)
                            DISABLE certificate verification.  Use only for dev
                            or staging endpoints with self-signed / untrusted
                            certs (e.g. api-dev.reeflex.io).  Default is full
                            verification; opt-in insecure at the operator's risk.
                            Same env name as the WordPress adapter for cross-adapter
                            consistency.
  REEFLEX_CORE_TOKEN     -- optional bearer token.  When set and non-empty, adds
                            "Authorization: Bearer <token>" to the request.  Never
                            logged.  Same env name as the WordPress adapter for
                            cross-adapter consistency.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_CORE_URL = "http://127.0.0.1:8080"
_DEFAULT_TIMEOUT  = 5.0
_MAX_ERROR_LEN    = 300   # max chars of external error text in reason strings

# Falsy string values for REEFLEX_VERIFY_SSL (case-insensitive).
# Anything not in this set is treated as truthy (verification ON -- secure default).
_VERIFY_SSL_FALSY = frozenset({"0", "false", "no", "off"})

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

    headers = {"Content-Type": "application/json"}

    # Bearer token (REEFLEX_CORE_TOKEN).  When set and non-empty, add the
    # Authorization header.  The token is used here and is never logged anywhere
    # in this module -- not in reason strings, audit records, or tracebacks.
    # Same env name as the WordPress adapter (class-reeflex-config.php) for
    # cross-adapter consistency.
    token = os.environ.get("REEFLEX_CORE_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    # token is not referenced beyond this point in this function.

    req = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )

    # TLS verification toggle (REEFLEX_VERIFY_SSL).
    # Default: verification ON (full certificate validation -- secure default).
    # Disable: set REEFLEX_VERIFY_SSL to 0 / false / no / off (case-insensitive).
    #
    # OPT-IN INSECURE -- dev/self-signed endpoints only, at the operator's risk.
    # Never disable in production: this setting protects the governance decision
    # call from MITM interception.  Default is full verification.
    # Same env name as the WordPress adapter (REEFLEX_VERIFY_SSL) for
    # cross-adapter consistency.
    ssl_ctx = _build_ssl_context(url)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
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


def _verify_ssl() -> bool:
    """
    Parse REEFLEX_VERIFY_SSL.

    Default: True (verification ON -- secure default).
    Falsy values (0 / false / no / off, case-insensitive) -> False (opt-in insecure).
    Any other value (including unset) -> True.

    This matches the WordPress adapter's REEFLEX_VERIFY_SSL semantics so the two
    adapters can be configured with the same env variable and the same values.
    """
    raw = os.environ.get("REEFLEX_VERIFY_SSL", "").strip().lower()
    if raw in _VERIFY_SSL_FALSY:
        return False
    return True


def _build_ssl_context(url: str):
    """
    Build an ssl.SSLContext for the given URL when TLS verification is disabled,
    or return None (which lets urlopen use its default full-verification context).

    Only applies to https:// targets; for http:// this function always returns None
    (a custom ssl context is harmless but irrelevant for plain http).

    OPT-IN INSECURE -- dev/self-signed endpoints only, at the operator's risk.
    Default is full verification (REEFLEX_VERIFY_SSL unset or truthy).
    """
    if not url.lower().startswith("https://"):
        return None  # http target -- no TLS context needed

    if _verify_ssl():
        return None  # full verification -- let urllib use its secure default

    # OPT-IN INSECURE: operator explicitly set REEFLEX_VERIFY_SSL to a falsy value.
    # Build a context that skips hostname and certificate verification.
    # This is intentional and required for dev/staging endpoints with self-signed
    # or privately-signed certificates (e.g. api-dev.reeflex.io).
    # NEVER use this in production -- it removes MITM protection on the decision call.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
