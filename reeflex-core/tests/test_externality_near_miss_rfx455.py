"""RFX-455 (1): a near-miss `physical` walked a safety-function override out of R8.

Measured by qa round 215 on main e0f06f0 and again on 747d38e, a production
`override` through app.decide.process:

    axes.externality: "physical"                 -> deny  safety_function_override_prod
    axes.externality: "PHYSICAL" | "Physical" | " physical "
                                                 -> allow default_allow

F1 matched the axis value EXACTLY and coerced anything else to `outbound`,
which arms none of R8-R11. The canon now (console decision, RFX-455):

  (a) all three axes are FOLDED (NFKC, control/format strip, trim, casefold)
      before the membership test, the way F5 folds target.environment;
  (b) a PRESENT value still unreadable after folding ("phsyical", "physical!")
      is recorded in provenance.unrecognised, and R0 holds it in production
      and staging where nothing else would stop it;
  (c) an ABSENT externality (missing, null, "") keeps the `outbound` default
      and is not recorded -- RFX-129's measured decision.

The near-miss grid below runs every envelope through the same two steps core
runs (envelope.validate_and_fill_defaults, then the shipped pack), in one bulk
`opa eval`. It does not run the ledger, so no budget can trip on it; budgets
are covered by the totality grid's BUDGET dimension.

Run:
  cd reeflex-core
  python -m unittest tests.test_externality_near_miss_rfx455 -v
"""

from __future__ import annotations

import copy
import itertools
import os
import shutil
import tempfile
import unittest
import uuid

from app.envelope import _AXIS_ALLOWED, _AXIS_DEFAULTS, validate_and_fill_defaults
from tests.test_decision_totality import _eval
from tests.test_physical_impact_rfx427 import _envelope, _opa_available

#: Spellings that FOLD to `physical`: (a) says they are physical.
FOLDED = ["PHYSICAL", "Physical", " physical ", "physical\n", "phys​ical",
          "ｐｈｙｓｉｃａｌ"]  # fullwidth
#: Spellings that do not fold to any member: (b) says they are held.
TYPOS = ["phsyical", "physcal", "physical!", "physicals", "phys ical"]
#: Not a string, not absent: also the adapter saying something core cannot read.
MALFORMED = [["physical"], 1, True, {"physical": True}]
#: Silence: (c) says these keep `outbound` and are not recorded.
_MISSING = object()
ABSENT = [_MISSING, None, "", "   ", "​"]

PHYSICAL_VERBS = ["set", "actuate", "override", "mode", "flash"]
ENVIRONMENTS = ["production", "staging", "dev"]

_RANK = {"allow": 0, "require_approval": 1, "deny": 2}


def _raw(externality, *, verb="override", environment="production",
         reversibility="recoverable", blast_radius="scoped",
         safety_function=None, envelope_fraction=None):
    env = _envelope(verb=verb, environment=environment,
                    reversibility=reversibility, blast_radius=blast_radius,
                    safety_function=safety_function,
                    envelope_fraction=envelope_fraction,
                    session_id=f"rfx455_{uuid.uuid4().hex[:8]}")
    if externality is _MISSING:
        del env["axes"]["externality"]
    else:
        env["axes"]["externality"] = externality
    return env


def _decide_bulk(raws):
    """validate_and_fill_defaults on each, then one `opa eval` over all."""
    ok, out = _eval([validate_and_fill_defaults(copy.deepcopy(r)) for r in raws])
    assert ok, f"pack did not evaluate: {str(out)[:400]}"
    assert len(out) == len(raws), (len(out), len(raws))
    return out


# ===========================================================================
# 1. What envelope.py hands the pack
# ===========================================================================

class TestTheAxisValueIsFolded(unittest.TestCase):

    def test_folded_spellings_are_the_member_they_spell(self):
        for spelling in FOLDED:
            with self.subTest(externality=spelling):
                out = validate_and_fill_defaults(_raw(spelling))
                self.assertEqual(out["axes"]["externality"], "physical")
                self.assertEqual(out["provenance"]["unrecognised"], [])
                self.assertNotIn("axes.externality", out["provenance"]["undeclared"])

    def test_every_axis_folds_not_only_externality(self):
        for axis, members in _AXIS_ALLOWED.items():
            for member in sorted(members):
                for spelling in (member.upper(), f" {member.title()} "):
                    with self.subTest(axis=axis, spelling=spelling):
                        raw = _raw("physical")
                        raw["axes"][axis] = spelling
                        out = validate_and_fill_defaults(raw)
                        self.assertEqual(out["axes"][axis], member)

    def test_the_folded_value_is_what_the_hold_hash_binds(self):
        """canonical_hash reads `axes`, so "Physical" and "physical" are the
        same action to an approval -- the fold happens before the hash."""
        from app.holds import canonical_hash
        a = validate_and_fill_defaults(_raw("physical"))
        b = validate_and_fill_defaults(_raw("Physical"))
        self.assertEqual(canonical_hash(a), canonical_hash(b))


class TestAnUnreadableExternalityIsRecorded(unittest.TestCase):

    def test_typos_and_malformed_values_are_recorded(self):
        for spelling in TYPOS + MALFORMED:
            with self.subTest(externality=spelling):
                out = validate_and_fill_defaults(_raw(spelling))
                self.assertEqual(out["axes"]["externality"], "outbound")
                self.assertEqual(out["provenance"]["unrecognised"],
                                 ["axes.externality"])
                self.assertIn("axes.externality", out["provenance"]["undeclared"])

    def test_silence_keeps_outbound_and_is_not_recorded(self):
        """(c). RFX-129's default for an adapter that never set the axis."""
        for spelling in ABSENT:
            label = "<missing>" if spelling is _MISSING else repr(spelling)
            with self.subTest(externality=label):
                out = validate_and_fill_defaults(_raw(spelling))
                self.assertEqual(out["axes"]["externality"],
                                 _AXIS_DEFAULTS["externality"])
                self.assertEqual(out["provenance"]["unrecognised"], [])

    def test_the_other_two_axes_are_recorded_the_same_way(self):
        raw = _raw("physical", reversibility="irreversable", blast_radius="Scoped")
        out = validate_and_fill_defaults(raw)
        self.assertEqual(out["provenance"]["unrecognised"], ["axes.reversibility"])

    def test_a_caller_supplied_provenance_is_overwritten(self):
        raw = _raw("phsyical")
        raw["provenance"] = {"undeclared": [], "unrecognised": []}
        out = validate_and_fill_defaults(raw)
        self.assertEqual(out["provenance"]["unrecognised"], ["axes.externality"])
        raw = _raw("physical")
        raw["provenance"] = {"unrecognised": ["axes.externality"]}
        self.assertEqual(
            validate_and_fill_defaults(raw)["provenance"]["unrecognised"], [])


# ===========================================================================
# 2. Through the real decision path (qa--215's proposed test, 3/3 subtests)
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestPhysicalNearMissIsNotAllowed(unittest.TestCase):
    """qa--215's proposed_test_physical_near_miss_qa215.py, as written there:
    reds on main 747d38e with 3 of 3 subtests `allow`."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="rfx455_")
        # Saved and RESTORED, not popped: tests/__init__.py points the whole
        # run at a temp ledger, and popping it sends every later test to the
        # in-tree default (it made test_healthz_revision_rfx89 see the path).
        self._saved_env = {k: os.environ.get(k)
                           for k in ("REEFLEX_HOLDS_PATH", "REEFLEX_LEDGER_PATH",
                                     "REEFLEX_POLICY_DIR")}
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._dir, "holds.jsonl")
        os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(self._dir, "ledger.jsonl")
        import app.holds as h
        import app.ledger as l
        h._reset(os.environ["REEFLEX_HOLDS_PATH"])
        l._reset_for_tests()
        self.ledger = l

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.ledger._reset_for_tests()
        shutil.rmtree(self._dir, ignore_errors=True)

    def _decide(self, externality, **kw):
        from app.decide import process
        status, resp = process(copy.deepcopy(_raw(externality, **kw)))
        self.assertEqual(status, 200, resp)
        return resp

    def test_control_exact_physical_override_is_r8(self):
        r = self._decide("physical")
        self.assertEqual(r["rule"], "reeflex.policy/safety_function_override_prod")

    def test_near_miss_physical_override_is_not_allowed(self):
        for spelling in ["PHYSICAL", "Physical", " physical "]:
            with self.subTest(externality=spelling):
                r = self._decide(spelling)
                self.assertNotEqual(r["decision"], "allow", r)

    def test_a_folded_spelling_gets_the_exact_spellings_rule(self):
        r = self._decide("Physical")
        self.assertEqual(r["rule"], "reeflex.policy/safety_function_override_prod")

    def test_a_typo_is_held_as_unclassified_and_says_which_field(self):
        r = self._decide("phsyical")
        self.assertEqual(r["decision"], "require_approval")
        self.assertEqual(r["rule"], "reeflex.policy/unclassified_action")
        self.assertIn("axes.externality", r["reason"])
        self.assertIn("hold_id", r)

    def test_an_absent_externality_is_not_held(self):
        """(c) at the decision level. Without this, flipping (c) -- recording
        silence as unreadable -- reddened only the envelope-level test above:
        across the whole 797-test core suite no existing test decided an
        envelope with no externality in production (dev-1 round 159, arm A3)."""
        for spelling in ABSENT:
            label = "<missing>" if spelling is _MISSING else repr(spelling)
            with self.subTest(externality=label):
                r = self._decide(spelling, verb="update")
                self.assertEqual(r["rule"], "reeflex.policy/default_allow", r)

    def test_a_typo_in_dev_is_not_held(self):
        """The physical rules do not arm in dev, so neither does the route."""
        r = self._decide("phsyical", environment="dev")
        self.assertEqual(r["decision"], "allow")


# ===========================================================================
# 3. The near-miss grid: spellings x the five physical verbs x environments
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestNearMissGrid(unittest.TestCase):
    """No near-miss spelling is `allow` where the exact spelling denies or holds.

    Folded spellings must get the exact spelling's decision object outright;
    typos and malformed values must not be `allow` in production or staging.
    """

    SHAPES = list(itertools.product(
        PHYSICAL_VERBS, ENVIRONMENTS,
        [None, True],               # target.safety_function
        [None, 0.5, 1.5],           # magnitude.physical.envelope_fraction
        ["recoverable", "irreversible"],
    ))

    @classmethod
    def setUpClass(cls):
        spellings = ["physical"] + FOLDED + TYPOS + MALFORMED
        cls.points = [(s, shape) for shape in cls.SHAPES for s in spellings]
        raws = [
            _raw(s, verb=v, environment=e, safety_function=sf,
                 envelope_fraction=fr, reversibility=rev)
            for s, (v, e, sf, fr, rev) in cls.points
        ]
        decisions = _decide_bulk(raws)
        cls.by_point = {}
        for (s, shape), d in zip(cls.points, decisions):
            cls.by_point[(repr(s), shape)] = d

    def test_the_grid_is_not_vacuous(self):
        """The exact spelling must actually deny AND hold somewhere on the
        grid, or "no allow where the exact spelling stops it" is about nothing."""
        exact = [self.by_point[(repr("physical"), shape)]["decision"]
                 for shape in self.SHAPES]
        self.assertEqual(len(self.SHAPES), 5 * 3 * 2 * 3 * 2)
        self.assertIn("deny", exact)
        self.assertIn("require_approval", exact)
        self.assertIn("allow", exact)

    def test_a_folded_spelling_is_decided_exactly_as_the_exact_one(self):
        for shape in self.SHAPES:
            want = self.by_point[(repr("physical"), shape)]
            for s in FOLDED:
                with self.subTest(externality=s, shape=shape):
                    self.assertEqual(self.by_point[(repr(s), shape)], want)

    def test_no_unreadable_spelling_is_allowed_where_the_exact_one_is_stopped(self):
        for shape in self.SHAPES:
            want = self.by_point[(repr("physical"), shape)]["decision"]
            for s in TYPOS + MALFORMED:
                got = self.by_point[(repr(s), shape)]
                with self.subTest(externality=s, shape=shape):
                    if want != "allow":
                        self.assertNotEqual(got["decision"], "allow", got)

    def test_an_unreadable_spelling_is_never_allowed_where_physical_rules_arm(self):
        for shape in self.SHAPES:
            if shape[1] == "dev":
                continue
            for s in TYPOS + MALFORMED:
                got = self.by_point[(repr(s), shape)]
                with self.subTest(externality=s, shape=shape):
                    self.assertNotEqual(got["decision"], "allow", got)


# ===========================================================================
# 4. (b) for the other two axes: measured, not assumed
# ===========================================================================

@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestTheOtherTwoAxesNeedNoRoute(unittest.TestCase):
    """The console asked for the R0 route on externality only, on the claim
    that the other two defaults (`irreversible`, `systemic`) already restrict
    most. This measures it: a typo in reversibility or blast_radius is not
    `allow` where ANY member of that axis would hold or deny, over a grid of
    every other input the pack reads."""

    TYPO = {"reversibility": "irreversable", "blast_radius": "sistemic"}

    @classmethod
    def setUpClass(cls):
        cls.points = []
        raws = []
        others = itertools.product(
            ["internal", "outbound", "physical", _MISSING],     # externality
            ["read", "delete", "update", "override", "actuate", "mode"],
            ["production", "staging", "dev"],
            ["/srv/prod/db.sqlite", "/tmp/scratch.txt"],        # R6
            [None, 1.5],                                        # R10a
        )
        for ext, verb, environment, ref, fraction in others:
            for rev in sorted(_AXIS_ALLOWED["reversibility"]) + [cls.TYPO["reversibility"]]:
                for blast in sorted(_AXIS_ALLOWED["blast_radius"]) + [cls.TYPO["blast_radius"]]:
                    raw = _raw(ext, verb=verb, environment=environment,
                               reversibility=rev, blast_radius=blast,
                               envelope_fraction=fraction)
                    raw["target"]["ref"] = ref
                    raws.append(raw)
                    cls.points.append(((repr(ext), verb, environment, ref, fraction), rev, blast))
        cls.decisions = dict(zip(cls.points, _decide_bulk(raws)))

    def _check(self, axis):
        members = sorted(_AXIS_ALLOWED[axis])
        typo = self.TYPO[axis]
        rows = stopped = 0
        for (other, rev, blast), d in self.decisions.items():
            if (rev if axis == "reversibility" else blast) != typo:
                continue
            if axis == "blast_radius" and rev == self.TYPO["reversibility"]:
                continue
            if axis == "reversibility" and blast == self.TYPO["blast_radius"]:
                continue
            rows += 1
            member_verdicts = {
                m: self.decisions[(other, m, blast) if axis == "reversibility"
                                  else (other, rev, m)]["decision"]
                for m in members
            }
            with self.subTest(axis=axis, other=other, rev=rev, blast=blast):
                if any(v != "allow" for v in member_verdicts.values()):
                    stopped += 1
                    self.assertNotEqual(d["decision"], "allow",
                                        (d, member_verdicts))
        # Not vacuous: the typo was checked on rows where a member is stopped
        # AND on rows where every member is allowed.
        self.assertGreater(stopped, 0)
        self.assertGreater(rows, stopped)

    def test_a_reversibility_typo_is_never_allowed_where_a_member_is_stopped(self):
        self._check("reversibility")

    def test_a_blast_radius_typo_is_never_allowed_where_a_member_is_stopped(self):
        self._check("blast_radius")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
