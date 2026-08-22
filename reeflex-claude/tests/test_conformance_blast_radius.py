"""
test_conformance_blast_radius.py -- SPEC §4.2 conformance for axes.blast_radius.

This test does NOT hold its own expectations. It reads the shared vector file
`reeflex-spec/conformance/blast-radius.json` -- the same file the WordPress
adapter's runner reads (`reeflex-wordpress/tests/conformance-blast-radius.php`)
-- and asserts that this adapter's real classify() agrees with it.

That is the point. Before RFX-131 each reference adapter derived blast_radius its
own way (this one from the shape of the command's target, the WordPress one from
substrings in the ability name), SPEC §7 said an adapter "MUST pass the
conformance suite" for the axes, and for this axis no suite existed. A test that
carried its own table would let the two adapters keep disagreeing while both
stayed green.

A case with no `claude` binding is NOT APPLICABLE to this adapter -- reported by
name in the summary, never silently dropped, so the number of cases actually
exercised stays legible (RFX-105..110).

Pure: no network, no I/O beyond reading the vector file, no side effects.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import classify

ADAPTER = "claude"
VECTORS = (pathlib.Path(_PARENT).parent
           / "reeflex-spec" / "conformance" / "blast-radius.json")


def load_cases():
    """Read the shared vectors.

    A missing file is a FAILURE, not a skip: in the monorepo (and under
    `pip install -e`, which leaves the tree in place) the path always resolves,
    so an absent file means the suite moved and this test would otherwise go
    quietly green while asserting nothing.
    """
    if not VECTORS.is_file():
        raise AssertionError(
            "SPEC §4.2 conformance vectors not found at %s -- this test asserts "
            "nothing without them; fix the path rather than skipping." % VECTORS
        )
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    return doc, doc["cases"]


class TestBlastRadiusConformance(unittest.TestCase):
    """SPEC §4.2, asserted against the shared vector file."""

    @classmethod
    def setUpClass(cls):
        cls.doc, cls.cases = load_cases()
        cls.not_applicable = [c["name"] for c in cls.cases
                              if ADAPTER not in (c.get("bindings") or {})]

    def test_broad_min_matches_the_spec(self):
        """The cardinality boundary is shared data, not a per-adapter constant."""
        self.assertEqual(self.doc["broad_min"], 20)

    def test_every_bound_case_conforms(self):
        bound = [c for c in self.cases if ADAPTER in (c.get("bindings") or {})]
        self.assertGreater(len(bound), 0,
                           "no case in the vector file binds to this adapter")
        for case in bound:
            b = case["bindings"][ADAPTER]
            with self.subTest(case=case["name"]):
                got = classify(b["tool"], b["tool_input"])
                self.assertEqual(
                    got["blast_radius"], case["expect"]["blast_radius"],
                    "SPEC §4.2 case %r: target_shape=%s -> expected %r, got %r\n"
                    "  binding: %s %s"
                    % (case["name"], case["given"].get("target_shape"),
                       case["expect"]["blast_radius"], got["blast_radius"],
                       b["tool"], json.dumps(b["tool_input"])[:160]),
                )

    def test_not_applicable_cases_are_named(self):
        """Coverage is stated, not assumed.

        This does not fail on non-applicability -- some cases genuinely have no
        expression in a coding-agent adapter (there is no WordPress rewrite
        table in Bash). It fails if the vector file binds NOTHING, which would
        mean this whole test class is decorative.
        """
        bound = len(self.cases) - len(self.not_applicable)
        self.assertGreater(bound, 0)
        if self.not_applicable:
            sys.stderr.write(
                "\n[SPEC §4.2 / %s] %d of %d cases exercised; NOT APPLICABLE: %s\n"
                % (ADAPTER, bound, len(self.cases), ", ".join(self.not_applicable))
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
