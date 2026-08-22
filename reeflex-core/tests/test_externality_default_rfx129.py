"""RFX-129: the conservative default for an axis must be a value the RULES read.

`axes.externality` coerced to `physical` -- the one member of its enum that
`grep physical policy/*.rego` cannot find. Its only decision effect anywhere in
the shipped pack is R5's `external_sends` budget, which counts
`externality == "outbound"` exactly, so the coercion target charged nothing and
the budget became opt-in on the audited party's own spelling:

    axes.externality: "outbound"    -> require_approval at call 51 (limit 50)
    axes.externality  OMITTED       -> 200 allowed, then objects_touched at 201
    axes.externality: "Outbound"    -> 200 allowed, then objects_touched at 201

There are two separable things to pin, and the second is the one that would
have caught this class of defect rather than this instance of it:

  1. the boundary behaviour -- absent/near-miss externality now lands on a
     value the external_sends budget charges (TestExternalitySendsAreCharged);
  2. the INVARIANT behind it -- no axis may have a conservative default that
     the policy pack never reads (TestEveryAxisDefaultIsReadByThePolicyPack).

(2) is deliberately generic over the axes and over the .rego files on disk: it
fails for a NEW axis or a NEW member with the same shape, not just for this one.
"""

from __future__ import annotations

import pathlib
import unittest

from app.envelope import (
    _AXIS_ALLOWED,
    _AXIS_DEFAULTS,
    validate_and_fill_defaults,
)

_POLICY_DIR = pathlib.Path(__file__).resolve().parents[1] / "policy"


def _policy_text() -> str:
    """Every non-test .rego file in the shipped pack, concatenated.

    reeflex_test.rego is EXCLUDED on purpose: a member mentioned only by a test
    is not read by any rule, and counting the tests would make the invariant
    below self-satisfying -- the exact "a check that passes without running"
    shape this test exists to prevent.
    """
    parts = []
    for path in sorted(_POLICY_DIR.glob("*.rego")):
        if path.name.endswith("_test.rego"):
            continue
        parts.append(path.read_text(encoding="utf-8"))
    assert parts, "no policy .rego files found under %s" % (_POLICY_DIR,)
    return "\n".join(parts)


def _envelope(externality, **overrides):
    """A reversible, single-entity production `emit`.

    reversibility/blast_radius are declared, so R2, R3 and R0 cannot fire and
    the ONLY rule that can change this decision is R5's external_sends budget.
    `externality` is passed through exactly as a caller would send it; the
    sentinel `_ABSENT` omits the key entirely.
    """
    axes = {"reversibility": "reversible", "blast_radius": "single"}
    if externality is not _ABSENT:
        axes["externality"] = externality
    payload = {
        "agent": {"id": "agent:rfx129", "session_id": "s-rfx129"},
        "action": {"verb": "emit", "ability": "http/post-webhook"},
        "target": {"environment": "production", "id": "hook-1"},
        "axes": axes,
        "magnitude": {"count": 1},
    }
    payload.update(overrides)
    return validate_and_fill_defaults(payload)


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return "<absent>"


_ABSENT = _Absent()


class TestExternalitySendsAreCharged(unittest.TestCase):
    """The boundary: what a caller who did not say `outbound` gets charged."""

    #: Every spelling that is not the canonical member. Each of these produced
    #: `physical` before RFX-129, i.e. an uncharged external_sends budget.
    NON_CANONICAL = [
        ("absent", _ABSENT),
        ("wrong case", "Outbound"),
        ("trailing space", "outbound "),
        ("upper", "OUTBOUND"),
        ("synonym nobody aliased", "external"),
        ("empty string", ""),
        ("not a string", ["outbound"]),
    ]

    def test_canonical_outbound_is_unchanged(self):
        env = _envelope("outbound")
        self.assertEqual(env["axes"]["externality"], "outbound")

    def test_non_canonical_externality_coerces_to_a_charged_value(self):
        charged = "outbound"
        for label, raw in self.NON_CANONICAL:
            with self.subTest(spelling=label):
                env = _envelope(raw)
                self.assertEqual(
                    env["axes"]["externality"], charged,
                    "%r must coerce to the member R5's external_sends budget "
                    "counts; anything else leaves the budget uncharged and "
                    "opt-in on the caller's spelling (RFX-129)" % (raw,),
                )

    def test_absent_axes_block_still_coerces_all_three(self):
        env = validate_and_fill_defaults({
            "agent": {"id": "agent:rfx129", "session_id": "s-rfx129"},
            "action": {"verb": "emit"},
            "target": {"environment": "production"},
            "magnitude": {"count": 1},
        })
        self.assertEqual(env["axes"], dict(_AXIS_DEFAULTS))

    def test_affirmatively_declared_members_are_never_rewritten(self):
        """The fix must not touch a caller who DID declare. `physical` in
        particular still means physical -- RFX-129's remaining half (that no
        rule reads it) is a canon question, not this coercion."""
        for member in sorted(_AXIS_ALLOWED["externality"]):
            with self.subTest(member=member):
                self.assertEqual(_envelope(member)["axes"]["externality"], member)

    def test_r1_label_still_requires_an_affirmative_internal(self):
        """R1 reads `externality == "internal"`. Nothing may coerce INTO it --
        that would hand an unclassified action the read_only_internal allow."""
        self.assertNotEqual(
            _AXIS_DEFAULTS["externality"], "internal",
            "coercing an unknown externality to `internal` would make R1's "
            "allow reachable by omission",
        )


class TestEveryAxisDefaultIsReadByThePolicyPack(unittest.TestCase):
    """The invariant: a conservative default the rules cannot see is not a
    default, it is an exemption.

    This is the check whose absence let `physical` sit in `_AXIS_DEFAULTS` for
    as long as it did -- with core's own field_treatments.py recording, in one
    record, both "conservative_default = physical" and "'physical' appears in
    no rule" and nothing reconciling them.
    """

    def test_every_axis_default_appears_in_the_shipped_policy(self):
        policy = _policy_text()
        for axis, default in sorted(_AXIS_DEFAULTS.items()):
            with self.subTest(axis=axis):
                self.assertIn(
                    '"%s"' % default, policy,
                    "%s coerces an absent/non-canonical value to %r, and no "
                    "rule in the shipped policy pack mentions it -- so every "
                    "envelope that lands on this default is exempt from every "
                    "rule that reads this axis (RFX-129)" % (axis, default),
                )

    def test_the_invariant_can_fail(self):
        """A test that cannot fail proves nothing. `physical` is a real member
        of the real enum and is genuinely absent from the pack: assert that,
        so this file fails if someone satisfies the check above by adding a
        mention rather than by choosing a read default."""
        self.assertIn("physical", _AXIS_ALLOWED["externality"])
        self.assertNotIn(
            '"physical"', _policy_text(),
            "`physical` is now read by the policy pack. That is RFX-129's "
            "option (a) and it is welcome -- but update this test and the "
            "field_treatments note deliberately rather than by accident.",
        )


if __name__ == "__main__":
    unittest.main()
