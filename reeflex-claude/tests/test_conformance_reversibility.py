"""
test_conformance_reversibility.py -- SPEC §2 conformance for axes.reversibility.

The sibling of test_conformance_blast_radius.py, and it exists for the same
reason that one does: this test does NOT hold its own expectations. It reads the
shared vector file `reeflex-spec/conformance/reversibility.json` -- the same file
the WordPress adapter's runner reads
(`reeflex-wordpress/tests/conformance-reversibility.php`) -- and asserts that
this adapter's real classify() agrees with it.

WHY IT WAS MISSING, which is the whole of RFX-166. RFX-164 wrote the vectors and
wired ONE arm: the WordPress runner went 20/20 while ten of those twenty cases
carried a `claude` binding that nothing ever executed. A shared corpus scored on
one arm cannot detect the two adapters drifting apart on the axis it was written
to converge -- it can only keep one of them honest. The asymmetry was visible in
a grep at the tip: blast-radius.json had a runner on both arms, reversibility.json
on one.

What the unasserted arm was hiding, measured at main 1919215 before this file
existed: 9 of the 10 bound cases already conformed, and `user/single`
(`userdel alice`) did not -- this adapter priced an account deletion
`recoverable`, the corpus and the WordPress adapter price it `irreversible`.
reversibility is one of the two axes R2/R3 read to hold a destructive action, so
the disagreement was in the direction that under-prices. Fixed in classify.py in
the same change as this file.

A case with no `claude` binding is NOT APPLICABLE to this adapter -- reported by
name in the summary, never silently dropped, so the number of cases actually
exercised stays legible (RFX-105..110). Ten of the twenty are WordPress-only
concepts (a post trash, term meta) and are left unbound rather than given an
invented Bash equivalent: authoring a vector to match the implementation it is
meant to score is the vacuity shape RFX-217 is about.

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
           / "reeflex-spec" / "conformance" / "reversibility.json")


def load_cases():
    """Read the shared vectors.

    A missing file is a FAILURE, not a skip: in the monorepo (and under
    `pip install -e`, which leaves the tree in place) the path always resolves,
    so an absent file means the suite moved and this test would otherwise go
    quietly green while asserting nothing.
    """
    if not VECTORS.is_file():
        raise AssertionError(
            "SPEC §2 conformance vectors not found at %s -- this test asserts "
            "nothing without them; fix the path rather than skipping." % VECTORS
        )
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    return doc, doc["cases"]


class TestReversibilityConformance(unittest.TestCase):
    """SPEC §2, asserted against the shared vector file."""

    @classmethod
    def setUpClass(cls):
        cls.doc, cls.cases = load_cases()
        cls.not_applicable = [c["name"] for c in cls.cases
                              if ADAPTER not in (c.get("bindings") or {})]

    def test_bulk_min_matches_the_spec(self):
        """The bulk boundary is shared data, not a per-adapter constant."""
        self.assertEqual(self.doc["bulk_min"], 20)

    def test_every_bound_case_conforms(self):
        bound = [c for c in self.cases if ADAPTER in (c.get("bindings") or {})]
        self.assertGreater(len(bound), 0,
                           "no case in the vector file binds to this adapter")
        for case in bound:
            b = case["bindings"][ADAPTER]
            with self.subTest(case=case["name"]):
                got = classify(b["tool"], b["tool_input"])
                self.assertEqual(
                    got["reversibility"], case["expect"]["reversibility"],
                    "SPEC §2 case %r: object_kind=%s undo_available=%s -> "
                    "expected %r, got %r\n  binding: %s %s"
                    % (case["name"], case["given"].get("object_kind"),
                       case["given"].get("undo_available"),
                       case["expect"]["reversibility"], got["reversibility"],
                       b["tool"], json.dumps(b["tool_input"])[:160]),
                )

    def test_the_claude_arm_is_actually_exercised(self):
        """The floor this file exists to install.

        RFX-166 was not a wrong expectation, it was an arm nobody ran: the
        bindings were present and unexecuted. A count that can only go up is
        what makes deleting a binding, or quietly narrowing this runner back to
        the WordPress arm, visible instead of silent.
        """
        bound = len(self.cases) - len(self.not_applicable)
        self.assertGreaterEqual(
            bound, 10,
            "reversibility.json bound %d cases to %r; it bound 10 when RFX-166 "
            "wired this arm. A binding was removed, not added." % (bound, ADAPTER),
        )

    def test_not_applicable_cases_are_named(self):
        """Coverage is stated, not assumed.

        This does not fail on non-applicability -- some cases genuinely have no
        expression in a coding-agent adapter (there is no WordPress post trash
        in Bash). It fails if the vector file binds NOTHING, which would mean
        this whole test class is decorative.
        """
        bound = len(self.cases) - len(self.not_applicable)
        self.assertGreater(bound, 0)
        if self.not_applicable:
            sys.stderr.write(
                "\n[SPEC §2 / %s] %d of %d cases exercised; NOT APPLICABLE: %s\n"
                % (ADAPTER, bound, len(self.cases), ", ".join(self.not_applicable))
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
