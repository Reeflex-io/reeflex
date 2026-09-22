"""
test_conformance_bash.py -- RFX-144 / RFX-145 / RFX-146.

WHAT THIS ASSERTS THAT test_classify.py DOES NOT
================================================
test_classify.py asserts the classifier's outputs. This asserts the DECISION
those outputs produce, over a corpus of commands whose real-world effect was
fixed before the fix was written (reeflex_claude/conformance.py).

The oracle is a transcription of the shipped policy pack into Python. That is
deliberate duplication: it lets the corpus fail in a unit suite, with no network
and no OPA, at the exact moment a classifier change stops routing a production
destruction to a human. The LIVE equivalent -- the same corpus replayed through
the real hook against a real core -- is
scripts/attack-probe-rfx144-agent-prices-own-action.py.

RFX-303: THE ORACLE NOW LIVES IN tests/policy_oracle.py, AND THE LIVE ARM RUNS.
Until RFX-303 the oracle was a private copy of R1-R4 in this file, the sentence
here claimed the two planes were "kept honest against each other by running both
in the gate", and the live arm was invoked by nothing at all -- `attack-probe`
appeared zero times in gate.py and zero times in .github/workflows/. Two
divergences had accumulated in that gap (the oracle was missing R6; it ranked R1
first where the pack ranks it last). Both planes now import the SAME oracle, and
gate.py's `claude-corpus-live` component replays the corpus through a real core
and fails when the two disagree on any case. See policy_oracle.py for what the
oracle still does not model.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reeflex_claude import conformance
from reeflex_claude.classify import classify

from policy_oracle import (  # noqa: E402  -- the SHARED oracle (RFX-303)
    PROTECTED_PREFIXES,
    DEFAULT_PROTECTED,
    ability_tokens,
    authority_rego_path,
    authority_signals_from_rego,
    policy_oracle,
    policy_oracle_rule,
    protected_assets_from_rego,
    rego_path,
)


class TestBashConformanceCorpus(unittest.TestCase):
    """Every case in the corpus gets the verdict its real-world effect demands."""

    def setUp(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)

    def test_every_case_reaches_its_expected_verdict(self):
        failures = []
        for case in conformance.CASES:
            cls = classify(case["tool"], case["input"])
            actual = policy_oracle(cls)
            expected = case["expect"]
            if case["residual"]:
                # A residual is allowed to miss its expectation -- but ONLY in
                # that direction, and only while its ticket is open. If a
                # residual starts passing, the exclusion is stale and must go.
                continue
            if actual != expected:
                failures.append(
                    f"{case['id']}: expected {expected}, got {actual} "
                    f"({cls['verb']}/{cls['reversibility']}/{cls['blast_radius']}) "
                    f"-- {case['effect']!r} -- {case['input']}"
                )
        self.assertEqual([], failures, "\n" + "\n".join(failures))

    def test_no_ground_truth_destruction_is_allowed(self):
        """The RFX-144 headline, as an assertion."""
        allowed = []
        for case in conformance.gating_destroy_cases():
            cls = classify(case["tool"], case["input"])
            if policy_oracle(cls) == "allow":
                allowed.append(f"{case['id']}: {case['input']} -- {case['effect']}")
        self.assertEqual(
            [], allowed,
            "irreversible production destructions executed with no human:\n"
            + "\n".join(allowed),
        )

    def test_everyday_commands_are_not_blocked(self):
        """The regression floor: a noisy gate is a gate that gets switched off."""
        blocked = []
        for case in conformance.cases(family="everyday"):
            cls = classify(case["tool"], case["input"])
            verdict = policy_oracle(cls)
            if verdict != "allow":
                blocked.append(f"{case['id']}: {verdict} -- {case['input']}")
        self.assertEqual([], blocked, "\n".join(blocked))

    def test_declared_axes_match_the_classifier(self):
        """The corpus records WHY each case decides as it does, not just that it does."""
        mismatches = []
        for case in conformance.CASES:
            cls = classify(case["tool"], case["input"])
            if case["expect_verb"] and cls["verb"] != case["expect_verb"]:
                mismatches.append(
                    f"{case['id']}: verb {cls['verb']} != {case['expect_verb']}")
            if (case["expect_blast_radius"]
                    and cls["blast_radius"] != case["expect_blast_radius"]):
                mismatches.append(
                    f"{case['id']}: blast_radius {cls['blast_radius']} "
                    f"!= {case['expect_blast_radius']}")
        self.assertEqual([], mismatches, "\n".join(mismatches))

    def test_classification_is_by_effect_not_by_vocabulary(self):
        """
        The fail-noisy face of RFX-144. Every `fp-` case demanded human
        approval on main 44c6f85 -- `cat docs/truncate.md` among them -- because
        the SQL patterns matched the WORD, not the effect. If any of them ever
        needs a human again, this fails.
        """
        blocked = []
        for case in conformance.cases(family="everyday"):
            if not case["id"].startswith("fp-"):
                continue
            verdict = policy_oracle(classify(case["tool"], case["input"]))
            if verdict != "allow":
                blocked.append(f"{case['id']}: {verdict} -- {case['input']}")
        self.assertEqual([], blocked, "\n".join(blocked))

    def test_the_coarse_edge_of_sql_reachability_is_where_we_left_it(self):
        """
        `_sql_reachable` is decided for the whole LINE, so a SQL keyword still
        counts when a database client is present anywhere on it. That is the
        safe direction and it is a real cost. Pinned so it cannot widen
        without a test changing: if this stops asking, the edge moved.
        """
        noisy = conformance.cases(family="known-noisy")
        self.assertTrue(noisy, "the known-noisy family must not be empty silently")
        for case in noisy:
            self.assertEqual(
                case["expect"], policy_oracle(classify(case["tool"], case["input"])),
                f"{case['id']}: the _sql_reachable edge moved -- {case['effect']}",
            )

    def test_every_residual_names_an_open_ticket(self):
        """An unexplained exclusion is how a gate quietly stops gating."""
        for case in conformance.residual_cases():
            self.assertTrue(
                case["residual"].startswith("RFX-"),
                f"{case['id']} is excluded from the gate without naming a ticket",
            )

    def test_residuals_are_still_residual(self):
        """
        If a residual starts passing, this test fails so the exclusion gets
        deleted rather than left behind hiding a future regression.
        """
        unexpectedly_passing = []
        for case in conformance.residual_cases():
            cls = classify(case["tool"], case["input"])
            if policy_oracle(cls) == case["expect"]:
                unexpectedly_passing.append(
                    f"{case['id']} now reaches {case['expect']} -- remove its "
                    f"residual={case['residual']} marker")
        self.assertEqual([], unexpectedly_passing, "\n".join(unexpectedly_passing))


# --------------------------------------------------------------------------
# RFX-341/RFX-342: rows whose declared `expect_target_ref` the classifier does
# NOT carry today. Same rules as conformance.py's residuals and
# check_published_classifier.py's PUBLISHED_LAG, for the same reason: an
# exclusion nobody has to justify is how a gate quietly stops gating.
#
#   * an entry must name a ticket, or it fails
#   * an entry that STOPS diverging fails as STALE, so the fix deletes the
#     entry by reddening the suite until someone does
#
# EMPTY, and that is a result rather than an oversight. It held the whole
# NotebookEdit route against RFX-342 -- the tool's key is `notebook_path`,
# `_classify_edit` read only `file_path`, and the tool's schema is
# additionalProperties:false, so that was 100% of real notebook calls. RFX-342
# landed both legs and the table emptied the way it was built to: the entries
# did not get deleted because someone remembered, they got deleted because
# `test_every_ref_blind_entry_still_diverges` went red and would not go green
# again until they were.
#
# Keep the table and its rules. The next ref the classifier cannot carry has a
# declared home, and an empty table is the only honest reading of "there is no
# such row today".
# --------------------------------------------------------------------------
REF_BLIND = {}


class TestRFX341TheRecordNamesTheResource(unittest.TestCase):
    """
    RFX-206 put `target_ref` on the wire and in the audit record because "a
    delete was held in production" is not something a human can answer or an
    auditor can check. That makes WHICH RESOURCE a claim the adapter makes,
    and a claim nothing asserts is a claim nothing keeps: the verdict tests
    above would all stay green with every ref set to None.
    """

    def setUp(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)

    def _declared(self):
        return [c for c in conformance.CASES if c["expect_target_ref"]]

    def test_the_corpus_declares_a_ref_for_the_tools_whose_input_IS_a_path(self):
        """A floor, so this cannot decay to zero declarations and stay green."""
        declared = {c["id"] for c in self._declared()}
        path_tools = {c["id"] for c in conformance.CASES
                      if c["tool"] in ("Write", "Edit", "MultiEdit",
                                       "NotebookEdit", "Read")
                      and len(str(c["input"].get("file_path")
                                  or c["input"].get("notebook_path") or "")) < 4096}
        self.assertTrue(
            path_tools,
            "no file-tool rows in the corpus at all -- RFX-341 regressed")
        self.assertEqual(
            set(), path_tools - declared,
            "file-tool rows with a usable path and no declared ref: "
            + ", ".join(sorted(path_tools - declared)))

    def test_every_declared_ref_is_the_one_the_classification_carries(self):
        mismatches = []
        for case in self._declared():
            if case["id"] in REF_BLIND:
                continue
            cls = classify(case["tool"], case["input"])
            if cls["target_ref"] != case["expect_target_ref"]:
                mismatches.append(
                    f"{case['id']} ({case['tool']}): target_ref "
                    f"{cls['target_ref']!r} != {case['expect_target_ref']!r} "
                    f"-- the record does not name the resource")
        self.assertEqual([], mismatches, "\n".join(mismatches))

    def test_every_ref_blind_entry_names_a_ticket(self):
        for case_id, ticket in REF_BLIND.items():
            self.assertTrue(
                str(ticket).startswith("RFX-"),
                f"{case_id} is excluded from the ref assertion without naming "
                f"a ticket")
            self.assertIn(case_id, {c["id"] for c in conformance.CASES},
                          f"REF_BLIND names {case_id}, which is not a corpus "
                          f"case -- a renamed row would make this exclusion "
                          f"silently cover nothing")

    def test_every_ref_blind_entry_still_diverges(self):
        """A stale exclusion is how a gate quietly stops gating."""
        fixed = []
        for case_id, ticket in REF_BLIND.items():
            case = next(c for c in conformance.CASES if c["id"] == case_id)
            cls = classify(case["tool"], case["input"])
            if cls["target_ref"] == case["expect_target_ref"]:
                fixed.append(
                    f"{case_id} now carries its declared ref -- delete its "
                    f"REF_BLIND entry ({ticket})")
        self.assertEqual([], fixed, "\n".join(fixed))

    def test_the_notebook_route_carries_its_ref_under_the_key_a_caller_sends(self):
        """
        RFX-342, first leg, asserted on the MECHANISM and not on a row id.

        This replaces the blindness test that RFX-342 closed by reddening. It
        is spelled the way the tool is: `notebook_path`, because the tool's
        schema is additionalProperties:false and `file_path` is a shape no real
        caller can send. The test this grew out of fed `file_path` -- the key
        the CODE reads -- and so could not have detected the mismatch in either
        direction. That is the instrument defect, and asserting on the real key
        is the fix for it.
        """
        real = classify("NotebookEdit", {
            "notebook_path": "/srv/prod/etl/nightly.ipynb",
            "cell_id": "c1", "new_source": "x", "edit_mode": "replace"})
        self.assertEqual(
            "/srv/prod/etl/nightly.ipynb", real["target_ref"],
            "a real NotebookEdit call has stopped naming its notebook -- the "
            "audit record RFX-206 added cannot answer WHICH notebook, and R6 "
            "has nothing to match")

        # The other spelling must keep working: the seat maps gateway tools
        # onto this classifier by argument shape, and it emits `file_path`.
        control = classify("NotebookEdit", {
            "file_path": "/srv/prod/etl/nightly.ipynb",
            "cell_id": "c1", "new_source": "x"})
        self.assertEqual("/srv/prod/etl/nightly.ipynb", control["target_ref"])

    def test_deleting_a_notebook_cell_under_production_state_is_held(self):
        """
        RFX-342, second leg -- and the leg that actually makes R6 reachable.

        MEASURED, on the shipped tree, before the fix: a NotebookEdit spelled
        with `file_path` carried a correct, protected ref and STILL scored
        allow/default_allow, because R6 reads `irreversible` first. So the key
        name alone was never going to close this; a fix that stopped there
        would have corrected the record and left the hold unreachable. The
        control below is the one the corpus already pins for `rm`.
        """
        nb = "/srv/prod/etl/nightly.ipynb"
        deleted = classify("NotebookEdit", {
            "notebook_path": nb, "cell_id": "c1", "edit_mode": "delete"})
        self.assertEqual("irreversible", deleted["reversibility"],
                         "the removed cell's source is in the tool input in no "
                         "form, so the Edit family's `recoverable` reason does "
                         "not hold for delete-mode")
        self.assertEqual(
            ("ask", "reeflex.policy/irreversible_protected_asset_prod"),
            policy_oracle_rule(deleted, "production"))

        # Control: `rm` on that same notebook, which this corpus already holds.
        # If this stops being `ask`, the assertion above is measuring the
        # posture and not the fix.
        removed = classify("Bash", {"command": "rm " + nb})
        self.assertEqual(
            ("ask", "reeflex.policy/irreversible_protected_asset_prod"),
            policy_oracle_rule(removed, "production"))

        # Control the OTHER way: `Edit` carries `old_string`, so the inverse of
        # the change IS in the call and it stays recoverable. This is what
        # keeps the delete-mode change scoped to delete-mode instead of
        # quietly repricing the whole Edit family.
        edited = classify("Edit", {"file_path": nb,
                                   "old_string": "a", "new_string": "b"})
        self.assertEqual("recoverable", edited["reversibility"])
        self.assertEqual("allow", policy_oracle_rule(edited, "production")[0])


class TestRFX303TheOracleTracksTheShippedPack(unittest.TestCase):
    """
    The oracle is a hand transcription of policy an operator EDITS, which is
    the exact shape of the defect RFX-303 was filed about. These two tests are
    what stop it drifting again in the direction the live arm cannot see
    cheaply: a prefix added to protected.rego that the oracle never learns
    about would make the oracle score `allow` where a real core holds, and
    every corpus case would have to happen to land on it for the live arm to
    notice.

    Keyed on the MONOREPO (reeflex-spec/SPEC.md), not on protected.rego, for
    the reason TestSpecArtefactIsInSync gives: keying the skip on the file
    under test makes a DELETED file skip silently instead of fail.
    """

    def _require_monorepo(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        if not (repo_root / "reeflex-spec" / "SPEC.md").exists():
            self.skipTest("no monorepo checkout around this file (installed wheel)")

    def test_the_protected_prefixes_are_the_ones_the_pack_ships(self):
        self._require_monorepo()
        parsed = protected_assets_from_rego()
        self.assertIsNotNone(
            parsed,
            f"{rego_path()} is missing -- the oracle's protected list is now "
            "unverifiable against the pack it claims to transcribe")
        self.assertEqual(
            tuple(parsed["protected_assets"]), tuple(PROTECTED_PREFIXES),
            "tests/policy_oracle.py's PROTECTED_PREFIXES no longer matches "
            "reeflex-core/policy/protected.rego. The offline oracle would now "
            "score a protected path `allow` while a real core holds it.")
        self.assertEqual(
            parsed["default_protected"], DEFAULT_PROTECTED,
            "protected.rego's posture switch moved; the oracle still models "
            "the old posture")

    def test_r1_is_ranked_last_not_first(self):
        """
        reeflex.rego's `read_only_internal` decision carries
        `not r2/r3/budget/r6/r7`, and says why: letting R1 win would hand back
        a one-field evasion of R6 -- relabel the delete `read`. The oracle
        ranked R1 first until RFX-303, so it scored exactly that evasion
        `allow`. Measured against a real core v0.2.1: `require_approval`.
        """
        evasion = {"verb": "read", "externality": "internal",
                   "reversibility": "irreversible", "blast_radius": "broad",
                   "target_ref": "/srv/prod/data"}
        verdict, rule = policy_oracle_rule(evasion)
        self.assertEqual("ask", verdict,
                         "an irreversible broad production action relabelled "
                         "verb=read must not reach R1")
        self.assertEqual("reeflex.policy/irreversible_broad_prod", rule)

        # R6 too: at cardinality one, R2 does not fire and only R6 is left.
        single = dict(evasion, blast_radius="single")
        self.assertEqual(
            ("ask", "reeflex.policy/irreversible_protected_asset_prod"),
            policy_oracle_rule(single))

        # The control: a genuine read is still allowed, by R1, and reports it.
        self.assertEqual(
            ("allow", "reeflex.policy/read_only_internal"),
            policy_oracle_rule({"verb": "read", "externality": "internal",
                                "reversibility": "reversible",
                                "blast_radius": "single",
                                "target_ref": "/srv/prod/README.md"}))


class TestTheUnmodelledRulesAreStillUnreachable(unittest.TestCase):
    """RFX-327: the oracle's declared residual was evidence with a date on it.

    policy_oracle.py does not model R7, and justified that with "no corpus case
    reaches it (measured 0 of 84)". The corpus is past 150 now and nothing
    re-took the measurement, so the sentence the offline green rests on had
    quietly become a claim about a corpus that no longer exists. Same family as
    RFX-303 itself: a hand-held fact about the pack, kept in prose, drifting.

    R7 fires on `action.ability`, and envelope.py composes that as
    `claude-code/<tool>` -- so reachability is decided by the TOOL NAME, and it
    changes the moment someone adds a row for a tool whose name carries a
    signal token. `mcp__admin__grant_role` tokenises to {mcp, admin, grant,
    role} and matches two. Nothing stops such a row being added; this is what
    notices.

    IF IT EVER FAILS, THE CORPUS IS NOT WRONG. The failure means the oracle can
    no longer predict what a real core says for that row, so either the row's
    verdict must be verified against the live arm or R7 must be modelled.
    """

    def _require_monorepo(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        if not (repo_root / "reeflex-spec" / "SPEC.md").exists():
            self.skipTest("no monorepo checkout around this file (installed wheel)")

    def test_no_corpus_case_can_reach_r7(self):
        self._require_monorepo()
        parsed = authority_signals_from_rego()
        self.assertIsNotNone(
            parsed,
            f"{authority_rego_path()} is missing -- the oracle's claim that no "
            "corpus case reaches R7 is now unverifiable against the pack")
        self.assertTrue(
            parsed["complete"],
            "authority.rego no longer defines all three signal lists "
            f"(found {parsed['lists_found']}). A renamed list would parse as "
            "an empty set and make this whole test pass vacuously")
        signals = parsed["signals"]
        self.assertTrue(signals, "parsed zero signal tokens from authority.rego")

        offenders = {}
        for case in conformance.cases():
            ability = "claude-code/%s" % case["tool"]
            matched = ability_tokens(ability) & signals
            if matched:
                offenders.setdefault(ability, sorted(matched))
        self.assertEqual(
            {}, offenders,
            "a corpus case's ability matches an R7 signal, so the oracle -- "
            "which does not model R7 -- can no longer predict core for it: "
            "%s. Verify those rows against the live arm, or model R7."
            % offenders)

    def test_the_reachability_check_can_actually_fire(self):
        """The control. Without it the test above is a green that proves nothing:
        an empty signal set, a broken tokenizer or a corpus read as empty all
        produce the same clean pass (RFX-217)."""
        self._require_monorepo()
        signals = authority_signals_from_rego()["signals"]
        for ability, expected in (("claude-code/mcp__admin__grant_role", {"grant", "role"}),
                                  ("claude-code/mcp__ops__install_plugin", {"install", "plugin"})):
            self.assertEqual(expected, ability_tokens(ability) & signals,
                             "the reachability check cannot see a tool name "
                             "that plainly carries R7 signals: %s" % ability)
        # and the shape the corpus actually ships must NOT match, or the test
        # above would be failing for a reason that has nothing to do with R7.
        self.assertEqual(set(), ability_tokens("claude-code/Bash") & signals)


class TestRFX146AuditRecordTruthfulness(unittest.TestCase):
    """
    RFX-146: `echo cleaning up && rm -rf /srv/prod/data` was recorded by the
    governance product as verb=read, reversible/single, tier benign, rule
    read_only_internal. That record is what reaches an Art.12 report. Even
    after the verdict is fixed, a false record is its own defect.
    """

    def setUp(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)

    def test_no_destructive_command_is_recorded_as_a_read(self):
        """
        RFX-341: this used to `continue` on any case with no `command` key,
        which silently excluded every non-Bash row -- one Read row then, the
        whole Write/Edit family now. The subject is the case, not the command
        string, so the row is identified by its id and its input is printed
        whatever shape it has.
        """
        offenders = []
        for case in conformance.CASES:
            if case["family"] == "everyday":
                continue
            # A row whose ground truth IS a read says so in `expect_verb`
            # (`ctrl-read-file` is the harness's own discrimination control).
            # Anything else reporting verb=read is the RFX-146 defect.
            if case["expect_verb"] == "read":
                continue
            cls = classify(case["tool"], case["input"])
            if cls["verb"] == "read":
                offenders.append(
                    f"{case['id']} ({case['tool']}): verb=read for "
                    f"{case['input']!r}")
        self.assertEqual([], offenders, "\n".join(offenders))

    def test_destructions_are_counted_by_the_delete_budget(self):
        """
        RFX-146(1): R5's deletions dimension accumulates on verb == "delete".
        `kubectl delete namespace` reported verb=execute, so thirty of them in
        one session never reached the budget.
        """
        for command in (
            "kubectl delete namespace prod-tenant-7",
            "aws s3 rm s3://acme-prod-7 --recursive",
            "gcloud sql instances delete acme-prod --quiet",
            "docker volume rm acme_prod_pgdata",
            "terraform destroy -auto-approve",
        ):
            cls = classify("Bash", {"command": command})
            self.assertEqual(
                "delete", cls["verb"],
                f"{command!r} reports verb={cls['verb']}, so R5's deletions "
                "budget never counts it",
            )

    def test_command_preview_is_the_whole_line_not_the_winning_segment(self):
        """The operator must see what was submitted, not the fragment that won."""
        command = "echo cleaning up && rm -rf /srv/prod/data"
        cls = classify("Bash", {"command": command})
        self.assertEqual(command, cls["command_preview"])


class TestRFX145StrictModeMovesADecision(unittest.TestCase):
    """
    RFX-145: strict mode lifted reversibility and left blast_radius at
    "scoped", so it could not change a verdict -- the strict and non-strict
    verdict sets over the corpus were identical.
    """

    def tearDown(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)

    def _verdicts(self):
        return {c["id"]: policy_oracle(classify(c["tool"], c["input"]))
                for c in conformance.CASES}

    def test_strict_and_default_verdict_sets_differ(self):
        """
        RFX-145's PASS CRITERION asked, in its own words, for "a test that
        fails if the strict and non-strict verdict sets are equal over the
        conformance corpus".  This is that test, and ASSERTING ONLY THAT THEY
        DIFFER IS NOT ENOUGH -- measured, qa--304, not reasoned.

        Restore RFX-145's exact defect in the shipped tree (the strict branch
        of `_classify_bash_execute` lifts reversibility to `irreversible` and
        leaves blast_radius at `scoped`) and the sets still DIFFER, on three
        rows, so the non-emptiness assertion stays GREEN:

            destroy-noop-prefix-redirect-andand   ask -> allow
            destroy-noop-prefix-redirect-brace    ask -> allow
            destroy-noop-prefix-truncate          ask -> allow

        Tightened: 0.  Loosened: 3.  So the guard named by this ticket's own
        closing criterion certified a SAFETY knob on the evidence that it had
        loosened three decisions.  `test_strict_only_ever_tightens` below is
        what actually caught that defect; this one has to ask for the
        direction, not merely for a difference.
        """
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)
        default = self._verdicts()
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        strict = self._verdicts()
        rank = {"allow": 0, "ask": 1, "deny": 2}
        tightened = {k: (default[k], strict[k]) for k in default
                     if rank[strict[k]] > rank[default[k]]}
        self.assertTrue(
            tightened,
            "REEFLEX_CLAUDE_STRICT tightened no verdict over the whole corpus "
            "-- it is documented as the knob for TIGHTENING the adapter, so a "
            "verdict set that merely differs does not discharge RFX-145",
        )

    def test_strict_only_ever_tightens(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)
        default = self._verdicts()
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        strict = self._verdicts()
        rank = {"allow": 0, "ask": 1, "deny": 2}
        loosened = [k for k in default if rank[strict[k]] < rank[default[k]]]
        self.assertEqual([], loosened, f"strict mode LOOSENED: {loosened}")

    def test_strict_covers_the_gap_family_except_remote_execution(self):
        """
        The README tells an operator that strict mode is the only lever they
        have over the commands the classifier cannot read (RFX-158). That is a
        claim about behaviour, so it is asserted here rather than only written
        down: the `gap-` cases that are unrecognised EXECUTE commands reach a
        human under strict mode.

        TWO KINDS OF UNCOVERED, AND THE DISTINCTION IS THE POINT.
        `gap-remote-execution` is uncovered because strict does not reach it --
        it is classified `emit`, so the lever misses it and the operator should
        know.  The three `gap-command-substitution*` rows are uncovered because
        they are already DENIED without the lever (RFX-158, dev-3--141): strict
        cannot "cover" a row that no longer needs covering.  Lumping the two
        together under one list would have let the second kind hide the first.
        """
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        covered, already_refused, uncovered = [], [], []
        for case in conformance.cases(family="gap"):
            verdict = policy_oracle(classify(case["tool"], case["input"]))
            if verdict == "ask":
                covered.append(case["id"])
            elif verdict == "deny":
                already_refused.append(case["id"])
            else:
                uncovered.append(case["id"])
        self.assertEqual(["gap-remote-execution"], uncovered,
                         "the strict-mode claim in README.md no longer holds: "
                         f"covered={covered} already_refused={already_refused} "
                         f"uncovered={uncovered}")
        self.assertEqual(
            ["gap-command-substitution",
             "gap-command-substitution-ctrl-rm-rf-root",
             "gap-command-substitution-ctrl-drop-database"],
            already_refused,
            "the set of gap rows refused WITHOUT the lever moved; if a row "
            "joined, say so in the corpus, and if one left, RFX-158 regressed")

    def test_strict_sends_an_unknown_production_command_to_a_human(self):
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        cls = classify("Bash", {"command": "some-unrecognised-deploy-tool --go"})
        self.assertEqual("ask", policy_oracle(cls))

    def test_strict_does_not_turn_a_read_into_an_approval(self):
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        self.assertEqual("allow", policy_oracle(classify("Bash", {"command": "ls -la"})))
        self.assertEqual("allow", policy_oracle(classify("Read", {"file_path": "/x"})))

    def test_readme_strict_numbers_are_recomputed_from_the_corpus(self):
        """
        The README quantifies this knob for an operator deciding whether to set
        it.  Those numbers were measured once and then pinned by nothing.

        MEASURED, qa--304, on the wheel a customer installs (reeflex-claude
        0.2.1 from PyPI) and on main: the README said strict "moves 23 of 82
        verdicts" and covered "five of the six" RFX-158 gaps.  The corpus was
        202 rows on the published wheel and 252 on main; strict moved 46 and 66
        of them; and the gap family had grown from 6 rows to 8.  Every number
        in the paragraph was wrong, on the artefact that ships the paragraph,
        and the guards beside it stayed green throughout -- because they pin
        the SETS and nothing read the prose.

        So this reads the prose.  Adding a corpus row now reddens here until
        the sentence is updated, which is the intended cost: a number a README
        presents as measured should not be able to outlive the measurement.
        """
        readme = pathlib.Path(__file__).resolve().parent.parent / "README.md"
        # Normalised, because the claims are prose and wrap across lines; a
        # guard that a reflow can silently unpin is the defect it exists for.
        text = " ".join(readme.read_text(encoding="utf-8").split())

        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)
        default = self._verdicts()
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        strict = self._verdicts()
        moved = [k for k in default if default[k] != strict[k]]

        gap_ids = [c["id"] for c in conformance.cases(family="gap")]
        covered = [i for i in gap_ids if strict[i] == "ask"]
        already_refused = [i for i in gap_ids if strict[i] == "deny"]
        uncovered = [i for i in gap_ids if strict[i] == "allow"]

        measured = {
            "corpus total": len(conformance.CASES),
            "verdicts moved": len(moved),
            "everyday rows moved": len([k for k in moved if k.startswith("everyday-")]),
            "gap rows moved": len([k for k in moved if k.startswith("gap-")]),
            "gap rows total": len(gap_ids),
            "gap rows covered by strict": len(covered),
            "gap rows already refused": len(already_refused),
            "gap rows out of reach": len(uncovered),
        }

        # Each claim is anchored on the README's own wording so that rewording
        # the sentence fails loudly here rather than silently unpinning it.
        claims = {
            "verdicts moved": r"it moves (\d+) of the \d+ conformance cases",
            "corpus total": r"it moves \d+ of the (\d+) conformance cases",
            "everyday rows moved": r"(\d+) of those \d+ are `everyday-` rows",
            "gap rows moved": r"and (\d+) are the RFX-158 gap rows above",
            "gap rows covered by strict": r"covers (\d+) of the \d+ `gap-` rows",
            "gap rows total": r"covers \d+ of the (\d+) `gap-` rows",
            "gap rows already refused": r"(\d+) are already refused without the knob",
            "gap rows out of reach": r"(\d+) is out of its reach",
        }

        wrong = []
        for name, pattern in claims.items():
            hit = re.search(pattern, text)
            if hit is None:
                wrong.append(
                    f"{name}: README no longer carries the sentence this guard "
                    f"reads (pattern {pattern!r}). Measured value is "
                    f"{measured[name]} -- put it back in a form this matches, "
                    f"or the number is unpinned again.")
                continue
            if int(hit.group(1)) != measured[name]:
                wrong.append(f"{name}: README says {hit.group(1)}, "
                             f"corpus measures {measured[name]}")
        self.assertEqual([], wrong, "\n".join(wrong))

        # The README also states the DIRECTION and the CEILING of the knob:
        # every move is allow -> ask and none reaches deny. That is what makes
        # it "the noisy setting" rather than an off switch, so it is asserted
        # rather than only written down.
        self.assertEqual(
            [], [k for k in moved if not (default[k] == "allow" and strict[k] == "ask")],
            "the README says every verdict strict moves goes allow -> ask; "
            "some row now moves differently, so the sentence needs rewriting")


class TestSpecArtefactIsInSync(unittest.TestCase):
    """
    reeflex-spec/conformance/claude-adapter-bash.json is generated from
    reeflex_claude.conformance. It is committed so the spec carries the
    corpus, and compared here so it cannot drift from the code.

    Skipped ONLY when there is no monorepo around this file at all (an
    installed wheel). The skip is keyed on reeflex-spec/SPEC.md, NOT on the
    artefact: keying it on the artefact would make a DELETED artefact skip
    silently instead of fail, which is the RFX-111..115 defect -- a check that
    passes without running.
    """

    def test_json_artefact_matches_the_module(self):
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        if not (repo_root / "reeflex-spec" / "SPEC.md").exists():
            self.skipTest("no monorepo checkout around this file (installed wheel)")
        artefact = repo_root / "reeflex-spec" / "conformance" / "claude-adapter-bash.json"
        regenerate = "regenerate with: python3 scripts/export-claude-conformance.py"
        self.assertTrue(artefact.exists(),
                        f"{artefact} is missing -- {regenerate}")
        on_disk = json.loads(artefact.read_text(encoding="utf-8"))
        self.assertEqual(
            conformance.CASES, on_disk["cases"],
            "reeflex-spec/conformance/claude-adapter-bash.json is out of date -- "
            + regenerate,
        )


if __name__ == "__main__":
    unittest.main()
