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

Query: one composite expression carrying BOTH halves of a budget decision —
  data.reeflex.policy.decision      the {decision, reason, rule} object
                                    (reeflex.rego).
  data.reeflex.policy.ledger_charge what this action costs the session ledger
                                    (budgets.rego; RFX-293 — the write side and
                                    the read side must price an action the
                                    same).
  - Both parsed from result.expressions[0].value, in ONE subprocess.

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


#: The verdict AND the number the ledger must record, in ONE `opa eval`.
#
# RFX-293. The budget's two terms used to be computed by two different parties:
# the CURRENT action was priced by budgets.rego (charged_count, the RFX-143
# floor), and the HISTORY was priced by ledger.py, which recorded the caller's
# raw `magnitude.count`. A caller that under-declared paid the floor once and
# then 1 per call forever after.
#
# They are one party now: this query returns `ledger_charge` beside `decision`,
# decide.py hands that number to append_entry, and the floors stay readable in
# exactly one place (policy/budgets.rego) instead of being mirrored in Python,
# which is the RFX-216 failure mode.
#
# ONE query, not two, DELIBERATELY: every decision already forks an `opa eval`
# (~50ms, RFX-208) and a second fork per decision would double that. A composite
# query expression is undefined as a WHOLE if any member is undefined, which
# would fail every decision closed on a policy edit — `ledger_charge` therefore
# carries a `default` in budgets.rego so it cannot be the undefined member.
_DECISION_QUERY = (
    '{"decision": data.reeflex.policy.decision, '
    '"ledger_charge": data.reeflex.policy.ledger_charge}'
)

#: The charge alone, for the one path that allows an action WITHOUT consulting
#: OPA for a verdict: decide.py's approved-hold resubmission. That action still
#: spends session budget, so it still has to be recorded at the price the policy
#: would have charged -- not at the caller's declared count.
_CHARGE_QUERY = "data.reeflex.policy.ledger_charge"


def _eval_query(query: str, policy_input: dict):
    """Run one `opa eval` and return result.expressions[0].value.

    Raises OpaEvalError on ANY failure. Shared by evaluate() and
    evaluate_ledger_charge() so the two cannot drift apart in how they treat a
    missing binary, a timeout or a malformed result.
    """
    opa = _opa_bin()
    policy_dir = _policy_dir()

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
        return parsed["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpaEvalError(
            f"unexpected OPA result shape (undefined or empty?): {exc!r} — raw: {result.stdout[:500]}"
        ) from exc


def _coerce_charge(raw) -> int:
    """The policy's charge, validated into the int the ledger will store.

    FAIL-CLOSED, and this is the direction that matters: a charge core cannot
    read is NOT quietly downgraded to the caller's count — that is the very
    substitution RFX-293 is about. It raises, and the caller denies.

    `bool` is rejected explicitly because it subclasses int (envelope.py F2
    rejects it on the same grounds).
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise OpaEvalError(f"OPA ledger_charge is not a number: {raw!r}")
    charge = int(raw)
    if charge < 1:
        raise OpaEvalError(f"OPA ledger_charge is below the domain minimum: {raw!r}")
    return charge


def evaluate(policy_input: dict) -> dict:
    """
    Evaluate the policy against policy_input.

    Returns {decision, reason, rule, obligations, ledger_charge} — the verdict
    plus the number ledger.append_entry must record for this action (RFX-293).
    Raises OpaEvalError on ANY failure (binary missing, non-zero exit,
    timeout, undefined result, JSON parse error, missing keys).

    FAIL-CLOSED: caller must catch OpaEvalError and return a deny decision.
    """
    value = _eval_query(_DECISION_QUERY, policy_input)

    if not value or not isinstance(value, dict):
        raise OpaEvalError("OPA returned undefined/empty decision — failing closed")

    decision_doc = value.get("decision")
    if not decision_doc or not isinstance(decision_doc, dict):
        raise OpaEvalError(f"OPA returned no decision document: {value!r}")

    # Validate minimum required keys
    decision_str = decision_doc.get("decision")
    if not decision_str:
        raise OpaEvalError(f"OPA decision object missing 'decision' key: {decision_doc!r}")

    # F4: pass through obligations from OPA result (SPEC §5)
    obligations = decision_doc.get("obligations", [])
    if not isinstance(obligations, list):
        obligations = []

    return {
        "decision": decision_str,
        "reason": decision_doc.get("reason", ""),
        "rule": decision_doc.get("rule", ""),
        "obligations": obligations,
        "ledger_charge": _coerce_charge(value.get("ledger_charge")),
    }


def evaluate_ledger_charge(policy_input: dict) -> int:
    """The policy's charge for this action, without asking for a verdict.

    Used only by the approved-hold resubmission path, which has a human's
    approval instead of a verdict but still spends budget. Same fail-closed
    contract as evaluate().
    """
    return _coerce_charge(_eval_query(_CHARGE_QUERY, policy_input))
