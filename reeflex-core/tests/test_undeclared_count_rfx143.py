"""
test_undeclared_count_rfx143.py — an action whose size the caller did not state
is not charged as the smallest possible action.

RFX-143.  `magnitude.count` is an int >= 1 (F2 rejects 0, negatives, floats and
bools), and an ABSENT count was filled with 1 — the MINIMUM of that domain —
under the comment "Absent -> conservative default of 1". Every budget dimension
in budgets.rego charges that number, and `objects_touched` charges it on every
action unconditionally. So:

    ONE call, count=45, irreversible/scoped/production  -> require_approval
    ONE call, count=1,  same axes                       -> allow
    ONE call, magnitude OMITTED, same axes              -> allow  (+20 more)

The adapter that said how many objects it was about to destroy paid for all of
them; the adapter that said nothing paid for one. R5's deletions budget was
measuring the caller's candour rather than its deletions.

WHAT THESE TESTS PIN, each a requirement rather than an implementation detail:

  1. an absent (or unusable) magnitude.count is RECORDED in
     provenance.undeclared, so the guess is visible to the policy at all;
  2. a count the caller DID state is not recorded as a guess;
  3. that block stays core-computed — a caller cannot assert its way into or
     out of it by supplying its own `provenance`;
  4. adding the field does NOT widen R0 (RFX-132): R0 reads an explicit
     three-field allowlist, so an omitted count must not start holding
     everything. This is the regression that would have mattered most;
  5. the floors in budgets.rego are ORDERED and >= 1, read out of the .rego
     file itself rather than mirrored as a literal here (RFX-216: a test that
     compares a constant to its own copy cannot detect drift);
  6. `single` and `scoped` are floor 1 in the shipped pack — pinned so that
     tightening them becomes a deliberate, visible edit rather than a silent
     retune of every everyday session.

unittest.TestCase style on purpose: gate.py runs this suite with
`unittest discover`, which collects nothing from bare pytest functions.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.envelope import (  # noqa: E402
    _PROVENANCE_FIELDS,
    validate_and_fill_defaults,
)

_POLICY_DIR = _repo_root / "policy"


def _envelope(magnitude="OMIT", blast="scoped", verb="delete"):
    """A minimal envelope. magnitude='OMIT' omits the block entirely."""
    env = {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:test", "session_id": "sess-rfx143"},
        "action": {"namespace": "t", "verb": verb, "ability": "t/x"},
        "target": {"kind": "t", "ref": "t:1", "environment": "production"},
        "params": {},
        "axes": {"reversibility": "irreversible", "blast_radius": blast,
                 "externality": "internal"},
    }
    if magnitude != "OMIT":
        env["magnitude"] = magnitude
    return env


def _undeclared(env):
    return validate_and_fill_defaults(env)["provenance"]["undeclared"]


class UndeclaredCountIsRecorded(unittest.TestCase):
    """(1) and (2): the guess is visible, a declaration is not a guess."""

    def test_magnitude_count_is_a_provenance_field(self):
        # The tuple's own docstring says "Anything a rule reads to decide WHAT
        # KIND OF ACTION this is belongs here", and every budget dimension
        # reads magnitude.count.
        self.assertIn("magnitude.count", _PROVENANCE_FIELDS)

    def test_absent_magnitude_block_is_undeclared(self):
        self.assertIn("magnitude.count", _undeclared(_envelope()))

    def test_absent_count_key_is_undeclared(self):
        self.assertIn("magnitude.count", _undeclared(_envelope(magnitude={})))

    def test_stated_count_is_not_undeclared(self):
        for c in (1, 2, 45, 10_000):
            with self.subTest(count=c):
                self.assertNotIn("magnitude.count",
                                 _undeclared(_envelope(magnitude={"count": c})))

    def test_absent_count_still_fills_to_one(self):
        # The fill itself is unchanged -- this ticket makes it VISIBLE, it does
        # not change the value, so no envelope_hash preimage moves.
        env = validate_and_fill_defaults(_envelope())
        self.assertEqual(env["magnitude"]["count"], 1)

    def test_declared_and_absent_produce_the_same_count_value(self):
        # The whole point: without provenance these two are indistinguishable
        # downstream. With it, they differ in exactly one place.
        a = validate_and_fill_defaults(_envelope())
        b = validate_and_fill_defaults(_envelope(magnitude={"count": 1}))
        self.assertEqual(a["magnitude"]["count"], b["magnitude"]["count"])
        self.assertNotEqual(a["provenance"]["undeclared"],
                            b["provenance"]["undeclared"])


class ProvenanceStaysCoreComputed(unittest.TestCase):
    """(3): a caller cannot assert its way into or out of the block."""

    def test_caller_cannot_claim_it_declared_a_count(self):
        env = _envelope()
        env["provenance"] = {"undeclared": []}
        self.assertIn("magnitude.count", _undeclared(env))

    def test_caller_cannot_claim_core_guessed_a_count_it_stated(self):
        env = _envelope(magnitude={"count": 45})
        env["provenance"] = {"undeclared": ["magnitude.count"]}
        self.assertNotIn("magnitude.count", _undeclared(env))


class R0IsNotWidened(unittest.TestCase):
    """(4) the regression that would have mattered most.

    R0 (RFX-132) turns a verdict into `unclassified_action` when a field it
    READS was guessed. It reads an explicit three-field allowlist. If
    magnitude.count leaked into that set, every envelope that omits a count
    would start holding -- a wrong-HOLD factory shipped as a hardening.
    """

    def test_r0_allowlist_does_not_contain_the_count(self):
        src = (_POLICY_DIR / "reeflex.rego").read_text()
        m = re.search(r"r0_classification_inputs\s*:=\s*\{(.*?)\}", src, re.S)
        self.assertIsNotNone(m, "r0_classification_inputs not found in reeflex.rego")
        self.assertNotIn("magnitude.count", m.group(1))

    def test_r0_still_reads_the_three_axes_it_always_read(self):
        src = (_POLICY_DIR / "reeflex.rego").read_text()
        m = re.search(r"r0_classification_inputs\s*:=\s*\{(.*?)\}", src, re.S)
        for f in ("axes.reversibility", "axes.blast_radius", "target.environment"):
            self.assertIn(f, m.group(1))


class CountFloorsAreOrderedPolicyData(unittest.TestCase):
    """(5) and (6): read the floors OUT OF budgets.rego, never mirror them.

    RFX-216: `test_core_axis_defaults_match_core_envelope_py` compared a
    constant to a copy of itself in the same file and called that a drift
    detector. This parses the real table, so editing budgets.rego is what makes
    these assertions move.
    """

    @staticmethod
    def _floors():
        src = (_POLICY_DIR / "budgets.rego").read_text()
        m = re.search(r"^count_floor\s*:=\s*\{(.*?)^\}", src, re.S | re.M)
        assert m, "count_floor table not found in budgets.rego"
        return {k: int(v) for k, v in
                re.findall(r'"(\w+)"\s*:\s*(\d+)', m.group(1))}

    def test_every_blast_radius_member_has_a_floor(self):
        self.assertEqual(set(self._floors()),
                         {"single", "scoped", "broad", "systemic"})

    def test_no_floor_is_below_one(self):
        # A floor below 1 would be cheaper than F2's own minimum, i.e. it would
        # reintroduce the defect from the other side.
        for k, v in self._floors().items():
            with self.subTest(blast_radius=k):
                self.assertGreaterEqual(v, 1)

    def test_floors_are_non_decreasing_in_blast_radius(self):
        f = self._floors()
        order = ["single", "scoped", "broad", "systemic"]
        vals = [f[k] for k in order]
        self.assertEqual(vals, sorted(vals),
                         "a wider blast radius must never carry a smaller floor")

    def test_broad_and_systemic_are_actually_floored(self):
        # If these were 1 the fix would be inert: `count: 1` next to a declared
        # whole-table blast radius is the understatement every shipped adapter
        # emits today.
        f = self._floors()
        self.assertGreater(f["broad"], 1)
        self.assertGreater(f["systemic"], 1)

    def test_single_and_scoped_are_left_at_one_deliberately(self):
        # Pinned so that changing them is a visible decision: `scoped` is what
        # the reference adapters emit for ordinary work, and flooring it would
        # retune every everyday session.
        f = self._floors()
        self.assertEqual(f["single"], 1)
        self.assertEqual(f["scoped"], 1)

    def test_dimensions_charge_the_floored_count_not_the_raw_one(self):
        # The wiring itself: if current_for() went back to reading
        # input.magnitude.count directly, every assertion above would still
        # pass and the fix would be gone.
        src = (_POLICY_DIR / "budgets.rego").read_text()
        m = re.search(r"^current_for\(dimension\).*?^\}", src, re.S | re.M)
        self.assertIsNotNone(m, "current_for not found in budgets.rego")
        body = m.group(0)
        self.assertIn("charged_count", body)
        self.assertNotIn("input.magnitude.count", body)


if __name__ == "__main__":
    unittest.main()
