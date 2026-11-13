"""RFX-455 (2): the envelope-fraction vectors agree with the pack that reads them.

reeflex-spec/conformance/envelope-fraction.json pins how an adapter computes
`magnitude.physical.envelope_fraction` (SPEC §4.5). Core does not compute it,
so the arithmetic is run by the adapter's runner
(reeflex-mcp/tests/test_conformance_envelope_fraction.py). This file runs the
other half of each row: the number the row requires, sent to the shipped pack
on a production `set`, is denied by R10a exactly when the row says `r10a`, and
`r10a` is exactly "the request lies outside the range". If the SPEC's table and
R10a's `> 1.0` ever disagree again, a row here goes red.

Run:
  cd reeflex-core
  python -m unittest tests.test_conformance_envelope_fraction_r10a -v
"""

from __future__ import annotations

import json
import pathlib
import unittest
import uuid

from app.envelope import validate_and_fill_defaults
from tests.test_decision_totality import _eval
from tests.test_physical_impact_rfx427 import _envelope, _opa_available

_VECTORS = (pathlib.Path(__file__).resolve().parents[2]
            / "reeflex-spec" / "conformance" / "envelope-fraction.json")


def _cases():
    return json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]


class TestTheVectorsAreSelfConsistent(unittest.TestCase):

    def test_there_are_rows_on_both_sides_of_the_range(self):
        cases = _cases()
        self.assertGreaterEqual(len(cases), 8)
        self.assertEqual({c["required"]["outside_range"] for c in cases}, {True, False})

    def test_the_spec_example_is_a_row(self):
        given = [c["given"] for c in _cases()]
        self.assertIn({"range": [20, 90], "current": 85, "requested": 92}, given)

    def test_outside_range_is_exactly_above_one(self):
        """SPEC §4.5: > 1.0 = the request lies outside the declared range."""
        for c in _cases():
            lo, hi = c["given"]["range"]
            outside = not (lo <= c["given"]["requested"] <= hi)
            with self.subTest(case=c["name"]):
                self.assertEqual(c["required"]["outside_range"], outside)
                self.assertEqual(c["required"]["envelope_fraction"] > 1.0, outside)
                self.assertEqual(c["required"]["r10a"], outside)


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestR10aReadsEachRowAsTheRowSays(unittest.TestCase):

    def test_r10a_fires_exactly_on_the_rows_that_say_so(self):
        cases = _cases()
        envelopes = [
            validate_and_fill_defaults(_envelope(
                verb="set", environment="production",
                envelope_fraction=c["required"]["envelope_fraction"],
                session_id=f"rfx455_vec_{uuid.uuid4().hex[:8]}"))
            for c in cases
        ]
        ok, decisions = _eval(envelopes)
        self.assertTrue(ok, decisions)
        for c, d in zip(cases, decisions):
            with self.subTest(case=c["name"]):
                is_r10a = d["rule"] == "reeflex.policy/outside_operating_envelope_prod"
                self.assertEqual(is_r10a, c["required"]["r10a"], d)
                if c["required"]["r10a"]:
                    self.assertEqual(d["decision"], "deny")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
