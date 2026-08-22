"""
test_conformance_bash.py -- RFX-144 / RFX-145 / RFX-146.

WHAT THIS ASSERTS THAT test_classify.py DOES NOT
================================================
test_classify.py asserts the classifier's outputs. This asserts the DECISION
those outputs produce, over a corpus of commands whose real-world effect was
fixed before the fix was written (reeflex_claude/conformance.py).

The oracle below is R1-R4 of the shipped policy pack transcribed into Python.
That is deliberate duplication: it lets the corpus fail in a unit suite, with
no network and no OPA, at the exact moment a classifier change stops routing a
production destruction to a human. The LIVE equivalent -- the same corpus
replayed through the real hook against a real core -- is
scripts/attack-probe-rfx144-agent-prices-own-action.py, and the two are kept
honest against each other by running both in the gate.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reeflex_claude import conformance
from reeflex_claude.classify import classify


def policy_oracle(cls: dict, environment: str = "production") -> str:
    """
    R1-R4 of reeflex-core/policy/reeflex.rego for a FIRST call in a session.

    R5 (cumulative budgets) needs session history and is out of scope here;
    it can only make a verdict stricter, never looser, so a case that reaches
    `ask`/`deny` under this oracle reaches at least that under the real pack.
    """
    if cls["verb"] == "read" and cls["externality"] == "internal":
        return "allow"                                              # R1
    irreversible = cls["reversibility"] == "irreversible"
    if irreversible and cls["blast_radius"] == "systemic" and environment == "production":
        return "deny"                                               # R3
    if irreversible and cls["blast_radius"] == "broad" and environment == "production":
        return "ask"                                                # R2
    return "allow"                                                  # R4


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
        offenders = []
        for case in conformance.CASES:
            if case["family"] == "everyday":
                continue
            command = case["input"].get("command")
            if not command:
                continue
            cls = classify(case["tool"], case["input"])
            if cls["verb"] == "read":
                offenders.append(f"{case['id']}: verb=read for {command!r}")
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
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)
        default = self._verdicts()
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        strict = self._verdicts()
        changed = {k: (default[k], strict[k]) for k in default if default[k] != strict[k]}
        self.assertTrue(
            changed,
            "REEFLEX_CLAUDE_STRICT changed no verdict over the whole corpus -- "
            "it is documented as the knob for tightening the adapter",
        )

    def test_strict_only_ever_tightens(self):
        os.environ.pop("REEFLEX_CLAUDE_STRICT", None)
        default = self._verdicts()
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        strict = self._verdicts()
        rank = {"allow": 0, "ask": 1, "deny": 2}
        loosened = [k for k in default if rank[strict[k]] < rank[default[k]]]
        self.assertEqual([], loosened, f"strict mode LOOSENED: {loosened}")

    def test_strict_sends_an_unknown_production_command_to_a_human(self):
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        cls = classify("Bash", {"command": "some-unrecognised-deploy-tool --go"})
        self.assertEqual("ask", policy_oracle(cls))

    def test_strict_does_not_turn_a_read_into_an_approval(self):
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        self.assertEqual("allow", policy_oracle(classify("Bash", {"command": "ls -la"})))
        self.assertEqual("allow", policy_oracle(classify("Read", {"file_path": "/x"})))


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
