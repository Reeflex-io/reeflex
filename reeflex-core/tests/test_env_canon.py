"""
test_env_canon.py — F5: target.environment canonicalization (fail-closed).

Regression guard for the verdict-integrity gap where R2/R3 (which match
`environment == "production"` exactly) FAILED OPEN on near-miss environment
strings ("Production", "PROD", "prod", "production ", ...), because
target.environment was passed to OPA verbatim while the axes were canonicalized.

These tests hit validate_and_fill_defaults() directly (no OPA needed): the
canonical tier the policy sees is what matters.
"""

from __future__ import annotations

import pytest

from app.envelope import validate_and_fill_defaults, ValidationError


def _env(environment):
    return {
        "agent": {"id": "agent:test", "session_id": "s-1"},
        "action": {"namespace": "t", "verb": "delete", "ability": "t/delete"},
        "target": {"environment": environment},
        "magnitude": {"count": 5},
        "axes": {
            "reversibility": "irreversible",
            "blast_radius": "systemic",
            "externality": "internal",
        },
    }


@pytest.mark.parametrize(
    "raw",
    [
        "production",
        "Production",
        "PRODUCTION",
        "prod",
        "PROD",
        "prd",
        "live",
        "production ",
        " production",
        "  Production  ",
    ],
)
def test_production_near_misses_canonicalize_to_production(raw):
    env = validate_and_fill_defaults(_env(raw))
    assert env["target"]["environment"] == "production"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("staging", "staging"),
        ("Staging", "staging"),
        ("stg", "staging"),
        ("dev", "dev"),
        ("development", "dev"),
        ("DEV", "dev"),
    ],
)
def test_non_prod_tiers_preserved(raw, expected):
    env = validate_and_fill_defaults(_env(raw))
    assert env["target"]["environment"] == expected


def test_unrecognized_environment_coerces_to_production_fail_closed():
    # An out-of-enum custom string is treated as the most-guarded tier so the
    # firewall fails CLOSED, never open (documented trade-off in envelope.py).
    env = validate_and_fill_defaults(_env("frobnitz-custom-env"))
    assert env["target"]["environment"] == "production"


def test_absent_environment_still_hard_rejects():
    bad = _env("production")
    bad["target"] = {}
    with pytest.raises(ValidationError):
        validate_and_fill_defaults(bad)


def test_empty_environment_still_hard_rejects():
    with pytest.raises(ValidationError):
        validate_and_fill_defaults(_env(""))
