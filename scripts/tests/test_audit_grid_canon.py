"""Unit tests for scripts/audit-grid-canon.py's rule-id inventory (RFX-128).

WHY THIS FILE EXISTS. The script is declared in check_suite_coverage.py as a
"reporting tool: prints the canon grid for a human reading a report. No verdict,
nothing to gate on." It nonetheless printed a verdict-SHAPED line —

    UNREACHABLE ON THE WHOLE GRID: none

— computed against `ALL_RULES`, a SIX-ITEM HARDCODED LIST written when the pack
had six rule ids. The pack now emits nine. So the reassuring line was printed
over a run in which three of the nine could not have fired, because the grid
holds the fields they read (`action.ability`, `target.ref`,
`provenance.undeclared`) constant. That is the "a check that passes without
running" shape, in a human-facing instrument, and it is how 94.4% came to be
quoted five weeks after three rules landed that the number cannot register.

WHAT IS GUARDED HERE, and why it is static rather than behavioural. The failure
was a LIST DRIFTING BEHIND THE PACK, so the guard is: the inventory is derived
from the pack, and the pack's real ids are all in it. No `opa` binary is
required, so this runs anywhere `unittest discover -s scripts/tests -t scripts`
runs.

Written as unittest TestCases because bare pytest-style functions here would
collect zero tests and pass forever (RFX-87).
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPTS, ".."))
POLICY_DIR = pathlib.Path(REPO_ROOT) / "reeflex-core" / "policy"


def _load():
    """Import the hyphenated script as a module."""
    path = os.path.join(SCRIPTS, "audit-grid-canon.py")
    spec = importlib.util.spec_from_file_location("audit_grid_canon", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_grid_canon"] = mod
    spec.loader.exec_module(mod)
    return mod


AGC = _load()


class PackRuleIdInventory(unittest.TestCase):
    """The inventory must come from the pack, not from a literal."""

    def test_reads_the_real_pack_and_finds_more_than_the_old_hardcoded_six(self):
        # The floor that makes every other assertion here non-vacuous: if the
        # scan returns nothing, a `set() - set(coverage)` difference is empty and
        # the script's "never fired" line would go quiet for every rule.
        ids = AGC.pack_rule_ids(POLICY_DIR)
        self.assertTrue(POLICY_DIR.is_dir(), f"no pack at {POLICY_DIR}")
        self.assertGreater(
            len(ids), 6,
            "the scan found six or fewer rule ids, which is the count the "
            "hardcoded list had. Either the pack shrank or the scan is broken.",
        )

    def test_the_three_fine_field_rules_are_really_in_the_pack(self):
        # The attribution table must not name a rule the pack no longer emits:
        # that would print an explanation for a silence with another cause.
        ids = AGC.pack_rule_ids(POLICY_DIR)
        for rule, field in AGC.FINE_FIELD_RULES.items():
            with self.subTest(rule=rule):
                self.assertIn(
                    rule, ids,
                    f"FINE_FIELD_RULES says {rule} reads {field}, but the pack "
                    f"does not emit that id. Fix the table or drop the row.",
                )

    def test_test_rego_files_are_excluded(self):
        # CAUGHT vs BLIND: the same id, once in a rule file and once in a
        # _test.rego. Only the first may count, or a rule deleted from the pack
        # but still named in its own test file would read as present.
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p / "real.rego").write_text('x := {"rule": "reeflex.policy/kept"}\n')
            (p / "real_test.rego").write_text(
                'y := {"rule": "reeflex.policy/only_in_a_test"}\n'
            )
            ids = AGC.pack_rule_ids(p)
        self.assertEqual(ids, {"reeflex.policy/kept"})

    def test_a_new_rule_id_is_picked_up_without_editing_the_script(self):
        # This is the regression proper. A rule added to the pack must appear in
        # the inventory with no edit here; that is the whole difference between
        # a derived list and the one that drifted three rules behind.
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p / "a.rego").write_text('x := {"rule": "reeflex.policy/old_one"}\n')
            before = AGC.pack_rule_ids(p)
            (p / "b.rego").write_text('z := {"rule": "reeflex.policy/brand_new"}\n')
            after = AGC.pack_rule_ids(p)
        self.assertEqual(before, {"reeflex.policy/old_one"})
        self.assertEqual(
            after, {"reeflex.policy/old_one", "reeflex.policy/brand_new"}
        )


class GridHoldsTheFineFieldsConstant(unittest.TestCase):
    """The docstring's claim, pinned to the code that makes it true.

    If someone later adds `action.ability` to the grid, these go red and the
    prose above section 3b has to be rewritten to match — which is the point.
    The claim and the code cannot drift apart silently.
    """

    def test_no_grid_point_carries_a_fine_grained_field(self):
        inputs = AGC.build_inputs()
        self.assertGreater(len(inputs), 0, "empty grid: nothing is being asserted")
        for label, inp in inputs:
            self.assertNotIn("ability", inp["action"], f"{label} carries an ability")
            self.assertNotIn("ref", inp["target"], f"{label} carries a target.ref")
            self.assertNotIn("provenance", inp, f"{label} carries provenance")

    def test_the_fine_field_probe_populates_each_field_it_claims_to(self):
        # The complement of the test above: the probe is the reason section 3's
        # silence is attributable, so it must actually vary the three fields.
        probes = AGC.fine_field_inputs()
        self.assertGreater(len(probes), 0)
        got_ability = any("ability" in e["action"] for _, e in probes)
        got_ref = any("ref" in e["target"] for _, e in probes)
        got_prov = any("provenance" in e for _, e in probes)
        self.assertTrue(got_ability, "no probe sets action.ability")
        self.assertTrue(got_ref, "no probe sets target.ref")
        self.assertTrue(got_prov, "no probe sets provenance")

    def test_every_fine_field_probe_has_a_control_twin(self):
        # A probe with no control cannot tell "the fine field did it" from "the
        # axes did it". Each field appears at least twice by construction.
        probes = AGC.fine_field_inputs()
        n_ability = sum(1 for _, e in probes if "ability" in e["action"])
        n_ref = sum(1 for _, e in probes if "ref" in e["target"])
        n_prov = sum(1 for _, e in probes if "provenance" in e)
        for field, n in (("action.ability", n_ability), ("target.ref", n_ref),
                         ("provenance", n_prov)):
            with self.subTest(field=field):
                self.assertGreaterEqual(
                    n, 2, f"{field} is probed {n} time(s): no control twin"
                )


if __name__ == "__main__":
    unittest.main()
