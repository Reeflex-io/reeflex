"""SPEC §4.5 conformance: reeflex-mcp computes envelope_fraction as the SPEC says.

Runs every row of reeflex-spec/conformance/envelope-fraction.json through the
extractor the gateway uses (`mappings.assess_physical`), with a static safe
range and `when_current_absent: worst_case` -- the default, and the rule the
SPEC table states. The file carries the expectations; this runner carries
none of its own (SPEC §7).

The row that matters most is the SPEC's own example: range [20, 90], current
85, requested 92. The v0.2 draft formula gave 0.1 there, below R10a's 1.0.
"""

from __future__ import annotations

import json
import pathlib
import unittest

from reeflex_mcp import mappings

_VECTORS = (pathlib.Path(__file__).resolve().parents[2]
            / "reeflex-spec" / "conformance" / "envelope-fraction.json")


def _rule(lo: float, hi: float) -> "mappings.PhysicalRule":
    return mappings.PhysicalRule(
        each=None,
        select=(mappings.PhysicalExtractor(
            when=None, value_arg="value", range=(float(lo), float(hi)),
            min_arg=None, max_arg=None, current_arg="current", unit=None,
            when_current_absent="worst_case",
        ),),
    )


class TestEnvelopeFractionConformance(unittest.TestCase):

    def test_every_row(self) -> None:
        doc = json.loads(_VECTORS.read_text(encoding="utf-8"))
        tolerance = doc["tolerance"]
        self.assertGreaterEqual(len(doc["cases"]), 8)
        for case in doc["cases"]:
            given, required = case["given"], case["required"]
            arguments = {"value": given["requested"]}
            if given["current"] is not None:
                arguments["current"] = given["current"]
            with self.subTest(case=case["name"]):
                got = mappings.assess_physical(_rule(*given["range"]), arguments)
                self.assertIsNone(got.error)
                fraction = got.physical["envelope_fraction"]
                self.assertAlmostEqual(fraction, required["envelope_fraction"],
                                       delta=tolerance)
                self.assertEqual(got.basis == "outside_range", required["outside_range"])
                self.assertEqual(fraction > 1.0, required["r10a"])

    def test_the_spec_example_is_above_one(self) -> None:
        got = mappings.assess_physical(_rule(20, 90), {"value": 92, "current": 85})
        self.assertGreater(got.physical["envelope_fraction"], 1.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
