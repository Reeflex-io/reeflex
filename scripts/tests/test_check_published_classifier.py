"""Unit tests for scripts/check_published_classifier.py (RFX-241).

WHY THIS FILE EXISTS, GIVEN THE SCRIPT ALREADY HAS `--selftest`. `--selftest`
proves the comparison on synthetic fixtures, and gate.py runs it as its own
component. What it cannot prove is that the tool is correctly JOINED to the two
things it sits between:

  * the REAL corpus — the floor, the ledger and the oracle are only meaningful
    against `reeflex_claude.conformance` as it actually ships today, and every
    one of those three is a constant someone will edit;
  * the REAL parser — `gate.py` decides this component's status by matching an
    anchored regex against a line this script writes. Two files, one contract,
    and nothing in either of them fails if the wording drifts apart. Here they
    are imported together and the line is matched with the regex that will read
    it in CI.

This root is run by `unittest discover -s scripts/tests -t scripts`, the same
runner the suites are measured with, so these execute in the gate as well as in
the script's own selftest.

Written as unittest TestCases because bare pytest-style functions here would
collect zero tests and pass forever (RFX-87).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_published_classifier as cpc  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "reeflex-claude"))
sys.path.insert(0, REPO_ROOT)

sys.path.insert(0, os.path.join(REPO_ROOT, "reeflex-claude", "tests"))

from reeflex_claude import conformance  # noqa: E402
from policy_oracle import policy_oracle as tree_oracle  # noqa: E402 -- SHARED (RFX-303)
import gate  # noqa: E402


class TestTheLedgerIsHonest(unittest.TestCase):
    """PUBLISHED_LAG is an exclusion list. Exclusion lists rot."""

    def test_every_declared_lag_names_a_ticket(self):
        for cid, ticket in cpc.PUBLISHED_LAG.items():
            self.assertRegex(
                str(ticket), r"RFX-\d+",
                "PUBLISHED_LAG[%s] excludes a case from the published-wheel "
                "comparison without naming the ticket that closes it" % cid)

    def test_every_declared_lag_names_a_case_that_still_exists(self):
        ids = {c["id"] for c in conformance.CASES}
        for cid in cpc.PUBLISHED_LAG:
            self.assertIn(
                cid, ids,
                "PUBLISHED_LAG declares %r, which the corpus no longer contains "
                "— a declaration for a deleted case silently covers nothing" % cid)


class TestTheFloorIsMeaningfulAgainstTheRealCorpus(unittest.TestCase):
    """RFX-217: a bound the empty set passes is not a bound.

    The floor is a number in a file. These pin it to the corpus it is supposed
    to be a floor UNDER — both ends, because it fails to do its job when it is
    too low (zero cases scored still passes) and it turns the gate permanently
    red when it is above what the corpus can supply.
    """

    def setUp(self):
        self.scored = [c for c in conformance.CASES if not c["residual"]]

    def test_the_floor_is_above_zero(self):
        self.assertGreater(
            cpc.MIN_SCORED_CASES, 0,
            "a floor of zero is satisfied by a run that classified nothing, "
            "which is exactly the failure this constant exists to catch")

    def test_the_floor_is_reachable_by_the_corpus_that_ships(self):
        self.assertLessEqual(
            cpc.MIN_SCORED_CASES, len(self.scored),
            "the floor (%d) is higher than the %d non-residual cases the corpus "
            "actually has, so this component can never pass — raising the floor "
            "without adding cases turns the gate red for a reason that says "
            "nothing about any published wheel"
            % (cpc.MIN_SCORED_CASES, len(self.scored)))

    def test_the_corpus_has_not_quietly_shrunk_to_the_floor(self):
        self.assertGreater(
            len(self.scored), cpc.MIN_SCORED_CASES,
            "the scored corpus (%d) has fallen to the floor (%d). Either cases "
            "were deleted or `residual` was applied broadly; both are changes "
            "someone must make deliberately, not discover in a green run"
            % (len(self.scored), cpc.MIN_SCORED_CASES))


class TestTheOracleIsNotTranscribedTwice(unittest.TestCase):
    """The published wheel must be scored with THIS tree's verdict function --
    and there must be exactly ONE of those (RFX-303), reached by all three
    planes: the offline unit suite, the live attack probe, and this script.
    """

    def test_the_conformance_suite_uses_the_same_oracle_object(self):
        import test_conformance_bash as suite
        self.assertIs(
            suite.policy_oracle, tree_oracle,
            "the unit suite and the published-wheel check must apply the SAME "
            "transcription; two copies drift and the drift shows up as a "
            "disagreement about a published artefact")

    def test_the_adapter_package_carries_no_oracle_of_its_own(self):
        """RFX-327, the regression this pins.

        An earlier revision of this component put an R1-R4 copy of the oracle in
        `reeflex_claude.conformance` so the script could import it from the
        package. That copy was missing R6 and ranked R1 first -- the two
        divergences RFX-303 had just removed -- and it scored the CORRECT
        published wheel 0.2.0 FAIL on `protected-rm-single-file-under-srv`.
        policy_oracle.py's own docstring is the rule: the adapter "does not
        import this module and must not", because the adapter classifies and
        core decides.
        """
        self.assertFalse(
            hasattr(conformance, "policy_oracle"),
            "reeflex_claude.conformance has grown a policy_oracle again — the "
            "oracle belongs in reeflex-claude/tests/policy_oracle.py, which is "
            "deliberately NOT shipped in the package (RFX-303/RFX-327)")

    def test_the_oracle_routes_a_broad_irreversible_production_action_to_a_human(self):
        verdict = tree_oracle(
            {"verb": "delete", "reversibility": "irreversible",
             "blast_radius": "broad", "externality": "internal"})
        self.assertEqual("ask", verdict)

    def test_the_oracle_allows_an_ordinary_read(self):
        verdict = tree_oracle(
            {"verb": "read", "reversibility": "reversible",
             "blast_radius": "single", "externality": "internal"})
        self.assertEqual("allow", verdict)

    def test_the_oracle_holds_a_protected_single_file_delete(self):
        """R6 -- the rule the replaced copy could not see. Reads the ref only."""
        verdict = tree_oracle(
            {"verb": "delete", "reversibility": "irreversible",
             "blast_radius": "single", "externality": "internal",
             "target_ref": "/srv/app/truncate.log"})
        self.assertEqual("ask", verdict)

    def test_the_driver_projects_every_axis_the_oracle_reads(self):
        """The projection in DRIVER is what the oracle actually gets.

        R6 reads `target_ref` and nothing else. A projection that drops it does
        not fail loudly -- it silently scores every wheel as ref-less, which is
        under no protected prefix, so R6 can never fire. Dropping a key here is
        indistinguishable from a clean run.
        """
        for axis in ("verb", "reversibility", "blast_radius", "externality",
                     "target_ref"):
            self.assertIn('"%s"' % axis, cpc.DRIVER,
                          "DRIVER stopped projecting %r, which the oracle reads" % axis)


class TestTheLineAndTheParserAgree(unittest.TestCase):
    """One contract, two files: the script writes it, gate.py reads it."""

    def test_gate_reads_a_pass_line_this_script_would_write(self):
        line = cpc.anchored_line(
            "PASS", "reeflex-claude==0.2.0; 78 cases scored (floor 40); "
                    "0 fail-open; 0 fail-noisy; 0 declared")
        status, detail = gate.parse_published_classifier(0, line + "\n")
        self.assertEqual("PASS", status)
        self.assertIn("78 cases scored", detail)

    def test_gate_reads_a_fail_line_this_script_would_write(self):
        line = cpc.anchored_line(
            "FAIL", "reeflex-claude==0.1.7; 78 cases scored (floor 40); "
                    "42 fail-open; 4 fail-noisy; 0 declared")
        status, detail = gate.parse_published_classifier(1, line + "\n")
        self.assertEqual("FAIL", status)
        self.assertIn("42 fail-open", detail)

    def test_gate_reads_a_skip_line_this_script_would_write(self):
        line = cpc.anchored_line("SKIP", "reeflex-claude is not installable from "
                                         "the index here — no verdict, not a pass")
        self.assertEqual("SKIPPED", gate.parse_published_classifier(3, line + "\n")[0])

    def test_a_skip_cannot_be_reached_without_the_skip_exit_code(self):
        """The one that matters: "I could not measure" must never read as PASS."""
        line = cpc.anchored_line("SKIP", "index unreachable")
        self.assertEqual("FAIL", gate.parse_published_classifier(0, line + "\n")[0])

    def test_the_component_is_registered_as_skippable_with_a_reason(self):
        self.assertIn(
            "pypi-behaviour", gate.SKIP_REGISTRY,
            "this component can skip (no index), and gate.py's skip-ledger "
            "REFUSES a skip nobody wrote a reason for")
        self.assertTrue(gate.SKIP_REGISTRY["pypi-behaviour"].strip())


class TestTheAuditOnTheRealCorpusShape(unittest.TestCase):
    """The fixtures in --selftest are synthetic. These use the shipped cases."""

    def test_a_wheel_that_matches_the_tree_passes_over_the_real_corpus(self):
        from reeflex_claude.classify import classify
        rows = {c["id"]: {"cls": classify(c["tool"], c["input"])}
                for c in conformance.CASES}
        ok, lines, stats = cpc.audit(rows, conformance.CASES,
                                     tree_oracle, lag={})
        self.assertTrue(ok, "\n".join(lines))
        self.assertEqual(0, stats["fail_open"])
        self.assertGreaterEqual(stats["scored"], cpc.MIN_SCORED_CASES)

    def test_one_mispriced_destruction_over_the_real_corpus_fails_it(self):
        """The RFX-241 shape itself: a chained rm priced as an ordinary read."""
        from reeflex_claude.classify import classify
        rows = {c["id"]: {"cls": classify(c["tool"], c["input"])}
                for c in conformance.CASES}
        target = next(c for c in conformance.CASES
                      if not c["residual"] and c["expect"] in ("ask", "deny"))
        rows[target["id"]] = {"cls": {"verb": "read", "reversibility": "reversible",
                                      "blast_radius": "single",
                                      "externality": "internal"}}
        ok, lines, stats = cpc.audit(rows, conformance.CASES,
                                     tree_oracle, lag={})
        self.assertFalse(ok)
        self.assertEqual(1, stats["fail_open"])
        self.assertTrue(any(target["id"] in line and "FAIL-OPEN" in line
                            for line in lines),
                        "the failing line must name the case: %s" % lines)

    def test_an_r6_shaped_regression_over_the_real_corpus_fails_it(self):
        """RFX-327's second consequence, which only the R2 shape was pinning.

        RFX-327 said the component was "blind to the entire R6 family": with an
        oracle that cannot produce `ask` for a protected-asset delete, a wheel
        that genuinely under-prices one scores PASS. 447b954 closed it by
        importing the shared oracle -- and the test above does NOT pin that,
        because it rewrites a case to `read/reversible/single`, which R2 catches.
        Remove R6 from the oracle and it still fails, on arithmetic: the R6 cases
        also go fail-open, so `fail_open` is 3 and not 1. A guard that reddens
        for the wrong reason is not measuring the thing it is named after.

        THE REGRESSION SHAPE IS NOT INVENTED. R6 reads `target_ref` and nothing
        else, so a wheel loses the whole family the moment it stops carrying the
        ref -- with every other axis still correct. That is RFX-342 exactly:
        reeflex-claude priced every NotebookEdit with no path at all because it
        never read `notebook_path`, and core saw `target.ref=null`. Here the
        classification is left otherwise untouched and only the ref is dropped,
        so nothing but R6 can account for the verdict moving.

        Measured pre-fix (dev-2--081): under the R1-R4 copy 447b954 replaced,
        this arm and the correct-wheel arm return the SAME verdicts -- allow on
        both R6 cases either way -- so the component could not tell them apart.
        """
        from reeflex_claude.classify import classify
        rows = {c["id"]: {"cls": classify(c["tool"], c["input"])}
                for c in conformance.CASES}

        # Enumerate the family from the ORACLE, not from a hand-listed set of
        # ids: a case added later that R6 decides joins this test by itself,
        # and a corpus that stops exercising R6 makes it fail loudly rather
        # than pass over an empty set (RFX-217).
        from policy_oracle import policy_oracle_rule
        r6_ids = [c["id"] for c in conformance.CASES
                  if not c["residual"]
                  and policy_oracle_rule(rows[c["id"]]["cls"])[1]
                  == "reeflex.policy/irreversible_protected_asset_prod"]
        self.assertTrue(
            r6_ids,
            "no corpus case is decided by R6, so this test would be vacuous -- "
            "the family RFX-327 is about is no longer exercised at all")

        for cid in r6_ids:
            rows[cid]["cls"]["target_ref"] = None

        ok, lines, stats = cpc.audit(rows, conformance.CASES,
                                     tree_oracle, lag={})
        self.assertFalse(
            ok, "a wheel that lost the ref on every R6 case scored PASS -- the "
                "component is blind to the family again (RFX-327)")
        self.assertEqual(len(r6_ids), stats["fail_open"])
        for cid in r6_ids:
            self.assertTrue(any(cid in line and "FAIL-OPEN" in line
                                for line in lines),
                            "the failing line must name %s: %s" % (cid, lines))


if __name__ == "__main__":
    unittest.main()
