"""
opa.py — OPA subprocess integration for reeflex-core.

Integration method chosen: `opa eval` subprocess with stdin pipe.
Rationale:
  - No OPA server to manage (no startup ordering, no port, no health check).
  - Each call is stateless: pass the full input on stdin, read result on stdout.
  - Deterministic by construction: same input -> same OPA output -> same Decision.
  - Suitable for skeleton/dev; in production with high QPS a long-running
    `opa run --server` sidecar reduces subprocess overhead.
    TODO: add an opt-in OPA REST server mode via env REEFLEX_OPA_MODE=server.

Query path: data.reeflex.policy.decision
  - Returns a single {decision, reason, rule} object (reeflex.rego).
  - Parsed from result.expressions[0].value.

Binary: env REEFLEX_OPA_BIN (default "opa").
Policy dir: env REEFLEX_POLICY_DIR (default: <this file's repo root>/policy).

FAIL-CLOSED contract: ANY error (binary missing, OPA error, timeout, empty/
undefined result, malformed JSON) -> raise OpaEvalError.  Caller converts
OpaEvalError to a deny decision.  We NEVER return an allow on error.
"""

from __future__ import annotations

import json
import os
import subprocess
import pathlib

# ---------------------------------------------------------------------------
# Configuration (from environment, never hardcoded)
# ---------------------------------------------------------------------------

def _opa_bin() -> str:
    return os.environ.get("REEFLEX_OPA_BIN", "opa")


def _policy_dir() -> str:
    env_dir = os.environ.get("REEFLEX_POLICY_DIR", "")
    if env_dir:
        return env_dir
    # Default: <repo root>/reeflex-core/policy (two levels up from this file)
    here = pathlib.Path(__file__).resolve()
    return str(here.parent.parent / "policy")


_OPA_TIMEOUT_SECONDS = int(os.environ.get("REEFLEX_OPA_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class OpaEvalError(RuntimeError):
    """Raised on ANY OPA evaluation failure.  Caller MUST deny on this."""


# ---------------------------------------------------------------------------
# Core eval function
# ---------------------------------------------------------------------------


def evaluate(policy_input: dict) -> dict:
    """
    Evaluate the policy against policy_input.

    Returns the Decision dict: {decision, reason, rule}.
    Raises OpaEvalError on ANY failure (binary missing, non-zero exit,
    timeout, undefined result, JSON parse error, missing keys).

    FAIL-CLOSED: caller must catch OpaEvalError and return a deny decision.
    """
    opa = _opa_bin()
    policy_dir = _policy_dir()
    query = "data.reeflex.policy.decision"

    try:
        input_json = json.dumps(policy_input)
    except (TypeError, ValueError) as exc:
        raise OpaEvalError(f"failed to serialize policy input: {exc}") from exc

    cmd = [
        opa, "eval",
        "-d", policy_dir,
        "-I",               # read input from stdin
        "--format=json",
        query,
    ]

    try:
        result = subprocess.run(
            cmd,
            input=input_json,
            capture_output=True,
            text=True,
            timeout=_OPA_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise OpaEvalError(f"OPA binary not found at '{opa}': {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise OpaEvalError(f"OPA eval timed out after {_OPA_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise OpaEvalError(f"OPA exec error: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise OpaEvalError(
            f"OPA exited {result.returncode}: {stderr or '(no stderr)'}"
        )

    # Parse the JSON output
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise OpaEvalError(f"OPA output is not valid JSON: {exc}") from exc

    # Extract result.expressions[0].value
    try:
        value = parsed["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpaEvalError(
            f"unexpected OPA result shape (undefined or empty?): {exc!r} — raw: {result.stdout[:500]}"
        ) from exc

    if not value:
        raise OpaEvalError("OPA returned undefined/empty decision — failing closed")

    # Validate minimum required keys
    decision_str = value.get("decision")
    if not decision_str:
        raise OpaEvalError(f"OPA decision object missing 'decision' key: {value!r}")

    # F4: pass through obligations from OPA result (SPEC §5)
    obligations = value.get("obligations", [])
    if not isinstance(obligations, list):
        obligations = []

    return {
        "decision": decision_str,
        "reason": value.get("reason", ""),
        "rule": value.get("rule", ""),
        "obligations": obligations,
    }
