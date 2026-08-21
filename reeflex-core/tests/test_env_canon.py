"""
test_env_canon.py — F5: target.environment canonicalization (fail-closed).

Regression guard for the verdict-integrity gap where R2/R3 (which match
`environment == "production"` exactly) FAILED OPEN on near-miss environment
strings ("Production", "PROD", "prod", "production ", ...), because
target.environment was passed to OPA verbatim while the axes were canonicalized.

These tests hit validate_and_fill_defaults() directly (no OPA needed): the
canonical tier the policy sees is what matters.

STYLE, AND WHY IT CHANGED (RFX-CORE-2): this file was originally written as
bare pytest functions with @pytest.mark.parametrize. gate.py runs this suite
with `unittest discover`, which imports such a module and collects ZERO tests
from it -- so from the moment it was added, this regression guard reported
green without ever executing a single assertion. It is now unittest.TestCase
based, like every other file in this directory, so it actually runs. See also
tests/test_verb_canon.py, which extends the same canon to action.verb.
"""

from __future__ import annotations

import unittest

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


def _canon(environment):
    return validate_and_fill_defaults(_env(environment))["target"]["environment"]


class TestProductionNearMisses(unittest.TestCase):
    """Every near-miss must land on the most-guarded tier."""

    CASES = [
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
    ]

    def test_production_near_misses_canonicalize_to_production(self):
        for raw in self.CASES:
            with self.subTest(environment=raw):
                self.assertEqual(_canon(raw), "production")


class TestNonProdTiersPreserved(unittest.TestCase):

    CASES = [
        ("staging", "staging"),
        ("Staging", "staging"),
        ("stg", "staging"),
        ("dev", "dev"),
        ("development", "dev"),
        ("DEV", "dev"),
    ]

    def test_non_prod_tiers_preserved(self):
        for raw, expected in self.CASES:
            with self.subTest(environment=raw):
                self.assertEqual(_canon(raw), expected)


class TestUnrecognizedFailsClosed(unittest.TestCase):

    def test_unrecognized_environment_coerces_to_production_fail_closed(self):
        # An out-of-enum custom string is treated as the most-guarded tier so
        # the firewall fails CLOSED, never open (documented trade-off in
        # envelope.py).
        self.assertEqual(_canon("frobnitz-custom-env"), "production")


class TestStructuralRejections(unittest.TestCase):

    def test_absent_environment_still_hard_rejects(self):
        bad = _env("production")
        bad["target"] = {}
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(bad)

    def test_empty_environment_still_hard_rejects(self):
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(_env(""))


if __name__ == "__main__":
    unittest.main()
