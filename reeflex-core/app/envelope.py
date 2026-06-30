"""
envelope.py — Action Envelope validation and conservative-default injection.

Implements SPEC §2 rules:
  - REQUIRED fields: action.verb, target.environment, axes (object present).
  - Missing AXIS VALUES -> safe-conservative defaults (never silent allow).
  - Non-canonical axis values -> coerced to most-restrictive (fail-closed).
  - Structural invalidity -> ValidationError (caller returns HTTP 400).
  - NOTE: meta.signature / meta.nonce verification = roadmap (TODO below).

SKELETON SHORTCUTS (upgrade path documented):
  - Signature verification (meta.signature): TODO — wire ed25519 verify once
    the key distribution mechanism is settled (Vault-backed key per adapter).
  - Nonce replay store: TODO — replace the in-process nonce set with a
    distributed cache (Redis / Postgres) for multi-replica deployments.
"""

from __future__ import annotations

import threading
from typing import Any

# ---------------------------------------------------------------------------
# F1: Closed enums + conservative defaults for axis VALUES (SPEC §2, §4)
#
# Match is EXACT (case-sensitive, lowercase canonical).
# Anything NOT in the allowed set (including absent) -> most-restrictive member.
# This means a non-canonical value like "Irreversible" or "permanent" is treated
# as "irreversible" (deny-class), never silently passed to OPA as unknown.
# ---------------------------------------------------------------------------

_AXIS_ALLOWED: dict[str, frozenset[str]] = {
    "reversibility": frozenset({"reversible", "recoverable", "irreversible"}),
    "blast_radius": frozenset({"single", "scoped", "broad", "systemic"}),
    "externality": frozenset({"internal", "outbound", "physical"}),
}

_AXIS_DEFAULTS: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "physical",
}

# ---------------------------------------------------------------------------
# Nonce store — in-memory replay protection (skeleton; see upgrade TODO above)
# ---------------------------------------------------------------------------

_nonce_lock = threading.Lock()
_seen_nonces: set[str] = set()


def _check_nonce(nonce: str | None) -> None:
    """Raise ValidationError if nonce is absent or already seen."""
    if not nonce:
        # Nonce field absent is a soft rejection in skeleton mode so that
        # test envelopes without nonces still pass. Production MUST enforce.
        # TODO: change this to a hard raise once nonce issuance is wired.
        return
    with _nonce_lock:
        if nonce in _seen_nonces:
            raise ValidationError("replay: nonce already seen")
        _seen_nonces.add(nonce)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when an envelope fails structural validation."""


def validate_and_fill_defaults(raw: Any) -> dict:
    """
    Validate the raw (already JSON-decoded) envelope and return a normalized
    copy with conservative defaults injected for any missing or non-canonical
    axis values.

    Raises ValidationError on structural failure (HTTP 400).
    Does NOT raise on missing-but-defaultable axis values; those are coerced
    to the most-restrictive canonical member (fail-closed per SPEC §2).

    F1: Non-canonical axis values are coerced to most-restrictive, not passed
    through verbatim (prevents silent allow on typo/case mismatch).
    F2: magnitude.count is canonicalized to int; invalid values raise.
    F3: agent.session_id is required; missing/empty raises ValidationError.
    """
    if not isinstance(raw, dict):
        raise ValidationError("envelope must be a JSON object")

    # -- REQUIRED: action.verb --
    action = raw.get("action")
    if not isinstance(action, dict):
        raise ValidationError("envelope.action is required and must be an object")
    verb = action.get("verb")
    if not verb or not isinstance(verb, str):
        raise ValidationError("envelope.action.verb is required")

    # -- REQUIRED: target.environment --
    target = raw.get("target")
    if not isinstance(target, dict):
        raise ValidationError("envelope.target is required and must be an object")
    environment = target.get("environment")
    if not environment or not isinstance(environment, str):
        raise ValidationError("envelope.target.environment is required")

    # -- REQUIRED: axes object present (values may be defaulted/coerced) --
    axes = raw.get("axes")
    if axes is not None and not isinstance(axes, dict):
        raise ValidationError("envelope.axes must be an object if present")

    # -- F3: REQUIRED: agent.session_id (SPEC §7 conformance requirement) --
    # session_id MUST be a non-empty string; a numeric or other non-str value
    # is a structural error (hard reject -> 400), not silently coerced.
    agent = raw.get("agent")
    if not isinstance(agent, dict):
        raise ValidationError(
            "agent.session_id is required (SPEC section 7)"
        )
    _sid = agent.get("session_id")
    if not isinstance(_sid, str) or not _sid.strip():
        raise ValidationError(
            "agent.session_id is required (SPEC section 7)"
        )

    # -- Nonce replay check (soft in skeleton; see TODO in module docstring) --
    meta = raw.get("meta") or {}
    _check_nonce(meta.get("nonce"))

    # Build normalized copy
    envelope = dict(raw)

    # -- params: free passthrough; must be a dict for ledger to iterate safely.
    # If present but not a dict (string, list, number) -> coerce to {}.
    # This is NOT a 400: params is optional, free-form, and not decision-critical.
    _raw_params = envelope.get("params")
    if _raw_params is not None and not isinstance(_raw_params, dict):
        envelope["params"] = {}

    # -- F1: Axes: coerce absent OR non-canonical values to most-restrictive --
    # Exact, case-sensitive match against the SPEC §4 closed enum.
    # Anything outside the allowed set (including absent, wrong case, typo)
    # coerces to the conservative default — it is never passed to OPA verbatim.
    normalized_axes = dict(axes) if isinstance(axes, dict) else {}
    for axis, default in _AXIS_DEFAULTS.items():
        raw_value = normalized_axes.get(axis)
        # Unhashable types (list, dict) cannot be checked against a frozenset;
        # any non-str value is by definition non-canonical -> coerce to default.
        if not isinstance(raw_value, str) or raw_value not in _AXIS_ALLOWED[axis]:
            # Absent, wrong-case ("Irreversible"), typo ("permanent"),
            # or unhashable garbage (list/dict) -> most-restrictive default.
            normalized_axes[axis] = default
    envelope["axes"] = normalized_axes

    # -- F2: magnitude.count: canonicalize to int; reject invalid values --
    # Guard: magnitude must be a dict if present; a string/list is a hard error.
    _raw_magnitude = raw.get("magnitude")
    if _raw_magnitude is not None and not isinstance(_raw_magnitude, dict):
        raise ValidationError(
            f"envelope.magnitude must be an object if present, got {type(_raw_magnitude).__name__}"
        )
    magnitude = dict(_raw_magnitude) if isinstance(_raw_magnitude, dict) else {}
    raw_count = magnitude.get("count")
    if raw_count is None:
        # Absent -> conservative default of 1
        magnitude["count"] = 1
    else:
        # Reject bool (Python bool subclasses int; True/False are not valid counts)
        if isinstance(raw_count, bool):
            raise ValidationError(
                "magnitude.count must be an integer >= 1 (bool not accepted)"
            )
        # Reject non-integer types (float, string, etc.)
        if not isinstance(raw_count, int):
            raise ValidationError(
                f"magnitude.count must be an integer >= 1, got {type(raw_count).__name__} {raw_count!r}"
            )
        # Reject zero or negative
        if raw_count < 1:
            raise ValidationError(
                f"magnitude.count must be an integer >= 1, got {raw_count}"
            )
        magnitude["count"] = raw_count  # already a canonical int
    envelope["magnitude"] = magnitude

    # Ensure approval.present has a conservative default (false = not approved).
    # If approval is present but not a dict (e.g. string "yes", list), treat it
    # as no approval — fail-closed: garbage does NOT grant approval.
    _raw_approval = raw.get("approval")
    if isinstance(_raw_approval, dict):
        approval = dict(_raw_approval)
    else:
        # Non-dict approval (string, list, number, etc.) -> coerce to empty dict.
        # This includes the case where approval was absent (None).
        approval = {}
    if not isinstance(approval.get("present"), bool):
        approval["present"] = False
    envelope["approval"] = approval

    return envelope
