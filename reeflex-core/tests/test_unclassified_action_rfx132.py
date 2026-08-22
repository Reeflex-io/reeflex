"""
test_unclassified_action_rfx132.py — an action the policy cannot classify
resolves to HOLD, and says so in its own words.

RFX-132.  After #89 and #90 the three conservative defaults COMPOSE:

    reversibility -> irreversible   (F1)
    blast_radius  -> systemic       (F1)
    environment   -> production     (F5)
    = R3 = deny, TERMINALLY, with no human anywhere in it.

So the envelope an adapter emits when it cannot classify an action landed on
the one rule a human is not allowed to clear -- "when unsure, refuse" on a
product whose value proposition is "when unsure, ask".

WHAT THESE TESTS PIN, and each one is a requirement rather than an
implementation detail:

  1. the unclassifiable envelope holds instead of denying;
  2. it carries a DISTINCT rule id, so an auditor can tell "a rule asked for a
     human" from "we could not tell what this was";
  3. an adapter that DECLARED all three still gets R3's terminal deny -- the
     rule loses nothing it was designed for;
  4. a caller cannot ASSERT its way into the softer verdict by supplying its
     own `provenance` block;
  5. a recognisable-but-non-canonical spelling ("Systemic") is a DECLARATION,
     not a guess, so the downgrade is not one capital letter away;
  6. R0 never converts an allow -- the volume objection, pinned as a test.

unittest.TestCase style on purpose: gate.py runs this suite with
`unittest discover`, which collects nothing from bare pytest functions.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.decide import process  # noqa: E402
from app.envelope import validate_and_fill_defaults  # noqa: E402

UNCLASSIFIED_RULE = "reeflex.policy/unclassified_action"


def _opa_available() -> bool:
    return bool(os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa"))


_SESSION_SEQ = [0]


def _envelope(**over):
    """The RFX-132 envelope: an adapter that cannot classify the action."""
    _SESSION_SEQ[0] += 1
    env = {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:rfx132", "session_id": "sess-rfx132-%d" % _SESSION_SEQ[0]},
        "action": {"verb": "frobnicate"},
        "target": {"environment": "qa-eu"},
        "axes": {},
        "magnitude": {"count": 1},
        "approval": {"present": False},
    }
    env.update(over)
    return env


# ---------------------------------------------------------------------------
# The provenance block itself (no OPA needed)
# ---------------------------------------------------------------------------

class TestProvenanceRecordsWhatCoreGuessed(unittest.TestCase):

    def test_the_unclassifiable_envelope_records_every_guess(self):
        got = validate_and_fill_defaults(_envelope())
        self.assertEqual(
            got["provenance"]["undeclared"],
            ["action.verb", "axes.blast_radius", "axes.externality",
             "axes.reversibility", "target.environment"],
        )
        # ...and the coerced VALUES are unchanged by RFX-132.
        self.assertEqual(got["axes"]["reversibility"], "irreversible")
        self.assertEqual(got["axes"]["blast_radius"], "systemic")
        self.assertEqual(got["target"]["environment"], "production")

    def test_a_fully_declared_envelope_guesses_nothing(self):
        got = validate_and_fill_defaults(_envelope(
            action={"verb": "delete"},
            target={"environment": "production"},
            axes={"reversibility": "irreversible", "blast_radius": "systemic",
                  "externality": "internal"},
        ))
        self.assertEqual(got["provenance"]["undeclared"], [])

    def test_a_non_canonical_spelling_is_a_declaration_not_a_guess(self):
        """The downgrade must not be one capital letter away.

        Judged on the RAW exact match, "Systemic" would read as undeclared and
        a caller would turn a terminal R3 into a resolvable hold by
        capitalising -- RFX-86's evasion one tier up. Judged on the folded
        token, it is what it plainly is: a declaration of systemic.
        """
        got = validate_and_fill_defaults(_envelope(
            action={"verb": "Delete"},
            target={"environment": "PROD"},
            axes={"reversibility": "Irreversible", "blast_radius": "Systemic",
                  "externality": "Internal"},
        ))
        self.assertEqual(got["provenance"]["undeclared"], [])

    def test_the_value_coercion_is_deliberately_unchanged(self):
        """A recognised-but-non-canonical spelling still coerces exactly as
        it did before this change.

        Folding the VALUE too would turn `blast_radius: "SINGLE"` on an
        irreversible production action from a DENY into an ALLOW, and a case
        fix that relaxes a refusal is not RFX-132's to make. The residual (a
        wrong DENY on "Broad") is unchanged and stated in the module comment,
        not silently fixed here.
        """
        got = validate_and_fill_defaults(_envelope(
            axes={"reversibility": "irreversible", "blast_radius": "Broad",
                  "externality": "internal"},
        ))
        self.assertEqual(got["axes"]["blast_radius"], "systemic")
        self.assertNotIn("axes.blast_radius", got["provenance"]["undeclared"])

    def test_a_caller_cannot_supply_its_own_provenance(self):
        """THE SECURITY OF R0. A caller that could write this block could
        claim core guessed at an envelope it declared perfectly, and downgrade
        its own terminal R3 to a hold a colleague can approve."""
        forged = _envelope(
            action={"verb": "delete"},
            target={"environment": "production"},
            axes={"reversibility": "irreversible", "blast_radius": "systemic",
                  "externality": "internal"},
            provenance={"undeclared": ["axes.reversibility", "target.environment"]},
        )
        got = validate_and_fill_defaults(forged)
        self.assertEqual(got["provenance"]["undeclared"], [],
                         "a caller-supplied provenance block must be discarded")

    def test_a_garbage_provenance_block_is_also_discarded(self):
        for junk in ("undeclared", ["axes.reversibility"], 7, None):
            with self.subTest(provenance=junk):
                got = validate_and_fill_defaults(_envelope(provenance=junk))
                self.assertIsInstance(got["provenance"], dict)
                self.assertIn("target.environment", got["provenance"]["undeclared"])

    def test_the_list_is_sorted_so_two_identical_envelopes_look_identical(self):
        a = validate_and_fill_defaults(_envelope())["provenance"]["undeclared"]
        b = validate_and_fill_defaults(_envelope())["provenance"]["undeclared"]
        self.assertEqual(a, b)
        self.assertEqual(a, sorted(a))


# ---------------------------------------------------------------------------
# The verdict, end to end through decide.process (needs OPA)
# ---------------------------------------------------------------------------

@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestUnclassifiableActionHolds(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = {k: os.environ.get(k) for k in
                      ("REEFLEX_HOLDS_PATH", "REEFLEX_AUDIT_LOG")}
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._tmp.name, "holds.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self._tmp.name, "audit.jsonl")
        import app.holds as holds_mod
        holds_mod._reset(os.environ["REEFLEX_HOLDS_PATH"])

    def tearDown(self):
        for k, v in self._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def test_1_it_holds_instead_of_denying(self):
        status, resp = process(_envelope())
        print("\n[T_rfx132/unclassified] %s" % json.dumps(resp))
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "require_approval", resp)

    def test_2_the_rule_id_is_distinct_from_a_policy_intended_hold(self):
        _, unclassified = process(_envelope())
        _, intended = process(_envelope(
            action={"verb": "delete"},
            target={"environment": "production"},
            axes={"reversibility": "irreversible", "blast_radius": "broad",
                  "externality": "internal"},
        ))
        self.assertEqual(intended["decision"], "require_approval")
        self.assertEqual(intended["rule"], "reeflex.policy/irreversible_broad_prod")
        self.assertEqual(unclassified["rule"], UNCLASSIFIED_RULE)
        self.assertNotEqual(unclassified["rule"], intended["rule"])

    def test_2b_the_reason_names_which_fields_were_not_classified(self):
        _, resp = process(_envelope())
        for field in ("axes.reversibility", "axes.blast_radius",
                      "target.environment"):
            self.assertIn(field, resp["reason"], resp)

    def test_3_a_declared_r3_still_denies_terminally(self):
        _, resp = process(_envelope(
            action={"verb": "delete"},
            target={"environment": "production"},
            axes={"reversibility": "irreversible", "blast_radius": "systemic",
                  "externality": "internal"},
        ))
        self.assertEqual(resp["decision"], "deny", resp)
        self.assertEqual(resp["rule"], "reeflex.policy/irreversible_systemic_prod")

    def test_4_a_forged_provenance_block_does_not_soften_the_deny(self):
        _, resp = process(_envelope(
            action={"verb": "delete"},
            target={"environment": "production"},
            axes={"reversibility": "irreversible", "blast_radius": "systemic",
                  "externality": "internal"},
            provenance={"undeclared": ["axes.reversibility", "axes.blast_radius",
                                       "target.environment"]},
        ))
        self.assertEqual(resp["decision"], "deny", resp)
        self.assertEqual(resp["rule"], "reeflex.policy/irreversible_systemic_prod")

    def test_5_capitalising_one_letter_does_not_downgrade_the_deny(self):
        _, resp = process(_envelope(
            action={"verb": "Delete"},
            target={"environment": "Production"},
            axes={"reversibility": "Irreversible", "blast_radius": "Systemic",
                  "externality": "Internal"},
        ))
        self.assertEqual(resp["decision"], "deny", resp)
        self.assertEqual(resp["rule"], "reeflex.policy/irreversible_systemic_prod")

    def test_6_it_never_converts_an_allow(self):
        """The volume objection, as a test.

        An unaliased verb on a declared, reversible, non-production action is
        the long tail every coding agent generates. If R0 held those, the gate
        would be switched off within a day -- which is RFX-145's lesson and
        the whole reason this rule is scoped to converting a REFUSAL.
        """
        _, resp = process(_envelope(
            action={"verb": "frobnicate"},
            target={"environment": "dev"},
            axes={"reversibility": "reversible", "blast_radius": "single",
                  "externality": "internal"},
        ))
        self.assertEqual(resp["decision"], "allow", resp)
        self.assertEqual(resp["rule"], "reeflex.policy/default_allow")

    def test_7_the_hold_is_real_and_carries_the_distinct_rule_id(self):
        """Requirement 3's precondition: the Holds screen can only show what
        the hold record says. The rule id has to reach it."""
        _, resp = process(_envelope())
        self.assertIn("hold_id", resp, resp)
        from app.holds import get_hold
        rec = get_hold(resp["hold_id"])
        self.assertIsNotNone(rec)
        self.assertEqual(rec["rule_id"], UNCLASSIFIED_RULE)
        self.assertEqual(rec["status"], "pending")

    def test_8_the_unclassified_hold_is_RESOLVABLE(self):
        """The whole difference from the R3 it replaces.

        `irreversible_systemic_prod` is in server.NON_RESOLVABLE_RULES, so a
        hold carrying it could never be answered. A hold that says "ask a
        human" and then refuses every human would be worse than the deny.
        """
        from app.server import NON_RESOLVABLE_RULES
        self.assertNotIn(UNCLASSIFIED_RULE.rsplit("/", 1)[1], NON_RESOLVABLE_RULES)

    def test_9_the_audit_line_records_the_distinct_rule(self):
        """An auditor reading the evidence stream, not the live store."""
        _, resp = process(_envelope())
        with open(os.environ["REEFLEX_AUDIT_LOG"], encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        mine = [x for x in lines if x.get("decision_id") == resp["decision_id"]]
        self.assertTrue(mine, "no audit record for this decision")
        self.assertEqual(mine[-1]["rule"], UNCLASSIFIED_RULE)

    def test_10_one_guessed_input_is_enough(self):
        """An adapter that priced two of three axes and could not price the
        third has still not classified the action."""
        _, resp = process(_envelope(
            action={"verb": "delete"},
            target={"environment": "qa-eu"},   # the only guess
            axes={"reversibility": "irreversible", "blast_radius": "systemic",
                  "externality": "internal"},
        ))
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], UNCLASSIFIED_RULE)
        self.assertIn("target.environment", resp["reason"])
        self.assertNotIn("axes.reversibility", resp["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
