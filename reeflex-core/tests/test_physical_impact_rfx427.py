"""
test_physical_impact_rfx427.py -- the physical / human-safety rules (R8-R11)
and budgets (R10b) through core's REAL decision path, app.decide.process.

WHY THIS FILE AND NOT ONLY policy/physical_test.rego
====================================================
The Rego tests feed the policy a canonical envelope. core never does: it runs
envelope.validate_and_fill_defaults() first, and on main 2f4fa25 that turned
`set` into `update` and every other physical verb into the reversibility
default. Measured through this same function before RFX-427: verb=override,
production, irreversible, single, physical -> allow / default_allow. A rule
that reads `verb == "override"` was dead code behind /v1/decide while its
opa tests passed. So every rule here is driven through process() at least
once, and the canon change is pinned in both directions.

THE TWO HASH TESTS (SPEC §5.1 / §4.5). A human's approval binds the hashed
projection {action, axes, magnitude, target}; magnitude.physical and
target.safety_function sit inside it. Each test approves a hold, resubmits a
CHANGED envelope citing it, and checks the change is refused -- and resubmits
the UNCHANGED envelope as the control, so a refusal for some other reason
cannot pass for binding.

Run:
  cd reeflex-core
  REEFLEX_OPA_BIN=/root/.local/bin/opa python3.12 -m unittest tests.test_physical_impact_rfx427 -v
"""

from __future__ import annotations

import copy
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app import envelope as envelope_mod  # noqa: E402
from app.envelope import ValidationError, validate_and_fill_defaults  # noqa: E402


def _opa_available() -> bool:
    return bool(os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa"))


def _envelope(
    *,
    verb: str = "set",
    environment: str = "production",
    reversibility: str = "recoverable",
    blast_radius: str = "scoped",
    externality: str = "physical",
    count: int = 1,
    safety_function: bool | None = None,
    envelope_fraction: float | None = None,
    session_id: str,
    approval: dict | None = None,
) -> dict:
    """A physical envelope with no `ability` (an eval/* ability trips R7 in
    production and would refuse every arm for the wrong reason)."""
    out = {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:rfx427",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id,
        },
        "action": {"namespace": "plc", "verb": verb},
        "target": {"kind": "tag", "environment": environment},
        "params": {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": externality,
        },
        "approval": approval if approval is not None else {"present": False},
        "context": {},
        "meta": {
            "timestamp": "2026-10-13T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:synthetic",
        },
    }
    if safety_function is not None:
        out["target"]["safety_function"] = safety_function
    if envelope_fraction is not None:
        out["magnitude"]["physical"] = {
            "envelope_fraction": envelope_fraction,
            "unit": "degC",
        }
    return out


def _session() -> str:
    return f"rfx427_{uuid.uuid4().hex[:12]}"


# ===========================================================================
# 1. The verb canon (no OPA)
# ===========================================================================

class TestPhysicalVerbsSurviveOnlyOnAPhysicalEnvelope(unittest.TestCase):
    """The five verbs are canonical on `physical`, and NOTHING moves elsewhere."""

    def _canon(self, verb, externality, reversibility="irreversible"):
        env = _envelope(verb=verb, externality=externality,
                        reversibility=reversibility, session_id="s")
        out = validate_and_fill_defaults(env)
        return out["action"]["verb"], "action.verb" in out["provenance"]["undeclared"]

    def test_each_physical_verb_is_kept_on_a_physical_envelope(self):
        for verb in ["set", "mode", "override", "actuate", "flash"]:
            for rev in ["irreversible", "reversible"]:
                with self.subTest(verb=verb, reversibility=rev):
                    self.assertEqual(self._canon(verb, "physical", rev), (verb, False))

    def test_folding_applies_as_for_every_other_verb(self):
        self.assertEqual(self._canon(" Override ", "physical")[0], "override")
        self.assertEqual(self._canon("FLASH", "physical")[0], "flash")

    def test_non_physical_envelopes_resolve_exactly_as_on_main(self):
        """The table main 2f4fa25 produces, frozen. `set` is still `update`;
        the other four are still unknown words (the reversibility default, and
        recorded undeclared) -- so an irreversible `override` on an IT envelope
        is still charged by the deletions budget, which is the RFX-308 rule."""
        expected_on_main = {
            ("set", "irreversible"): ("update", False),
            ("set", "reversible"): ("update", False),
            ("mode", "irreversible"): ("delete", True),
            ("mode", "reversible"): ("update", True),
            ("override", "irreversible"): ("delete", True),
            ("override", "reversible"): ("update", True),
            ("actuate", "irreversible"): ("delete", True),
            ("actuate", "reversible"): ("update", True),
            ("flash", "irreversible"): ("delete", True),
            ("flash", "reversible"): ("update", True),
        }
        for ext in ["internal", "outbound"]:
            for (verb, rev), want in expected_on_main.items():
                with self.subTest(externality=ext, verb=verb, reversibility=rev):
                    self.assertEqual(self._canon(verb, ext, rev), want)

    def test_a_compound_is_not_elected_into_a_physical_verb(self):
        """Stated limit: whole-verb recognition only."""
        self.assertEqual(self._canon("set_temperature", "physical")[0], "update")
        self.assertEqual(self._canon("override_interlock", "physical", "reversible")[0], "update")

    def test_the_it_canon_is_unchanged(self):
        self.assertNotIn("override", envelope_mod._VERB_CANON)
        self.assertEqual(envelope_mod._VERB_CANON["set"], "update")
        self.assertEqual(
            envelope_mod._SPEC_VERBS,
            frozenset({"read", "create", "update", "delete", "execute", "transact", "emit"}),
        )


# ===========================================================================
# 2. F10: the two new fields are refused, not guessed at (no OPA)
# ===========================================================================

class TestF10RefusesWhatItCannotRead(unittest.TestCase):

    def _refused(self, **kw):
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(_envelope(session_id="s", **kw))

    def test_safety_function_must_be_a_boolean(self):
        for bad in ["true", 1, 0, "yes", None, [], {}]:
            with self.subTest(value=bad):
                env = _envelope(session_id="s")
                env["target"]["safety_function"] = bad
                with self.assertRaises(ValidationError):
                    validate_and_fill_defaults(env)

    def test_envelope_fraction_must_be_a_finite_non_negative_number(self):
        for bad in [-0.01, "1.4", True, float("nan"), float("inf"), None, [0.4]]:
            with self.subTest(value=bad):
                env = _envelope(session_id="s")
                env["magnitude"]["physical"] = {"envelope_fraction": bad}
                with self.assertRaises(ValidationError):
                    validate_and_fill_defaults(env)

    def test_physical_must_be_an_object(self):
        env = _envelope(session_id="s")
        env["magnitude"]["physical"] = 0.4
        with self.assertRaises(ValidationError):
            validate_and_fill_defaults(env)

    def test_valid_values_pass_through_untouched(self):
        out = validate_and_fill_defaults(_envelope(
            session_id="s", safety_function=True, envelope_fraction=0, count=2))
        self.assertIs(out["target"]["safety_function"], True)
        self.assertEqual(out["magnitude"]["physical"],
                         {"envelope_fraction": 0, "unit": "degC"})

    def test_absent_stays_absent(self):
        """No key is added, so the hash preimage of an IT envelope is unchanged."""
        out = validate_and_fill_defaults(_envelope(session_id="s"))
        self.assertNotIn("safety_function", out["target"])
        self.assertNotIn("physical", out["magnitude"])


# ===========================================================================
# 3. Through the real decision path
# ===========================================================================

class _DecidePathCase(unittest.TestCase):

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="rfx427_")
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._dir, "holds.jsonl")
        os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(self._dir, "ledger.jsonl")
        import app.holds as holds_mod
        import app.ledger as ledger_mod
        holds_mod._reset(os.environ["REEFLEX_HOLDS_PATH"])
        ledger_mod._reset_for_tests()
        self.holds = holds_mod
        self.ledger = ledger_mod

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        os.environ.pop("REEFLEX_LEDGER_PATH", None)
        self.ledger._reset_for_tests()
        shutil.rmtree(self._dir, ignore_errors=True)

    def decide(self, env: dict) -> dict:
        from app.decide import process
        status, resp = process(copy.deepcopy(env))
        self.assertEqual(status, 200, resp)
        return resp


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestEachRuleFiresThroughProcess(_DecidePathCase):

    def test_r8_override_production(self):
        r = self.decide(_envelope(verb="override", reversibility="irreversible",
                                  blast_radius="single", session_id=_session()))
        self.assertEqual((r["decision"], r["rule"]),
                         ("deny", "reeflex.policy/safety_function_override_prod"))

    def test_r8_set_on_a_safety_function_staging(self):
        r = self.decide(_envelope(environment="staging", safety_function=True,
                                  session_id=_session()))
        self.assertEqual(r["rule"], "reeflex.policy/safety_function_override_prod")

    def test_r10a_outside_the_range(self):
        r = self.decide(_envelope(envelope_fraction=1.3, session_id=_session()))
        self.assertEqual((r["decision"], r["rule"]),
                         ("deny", "reeflex.policy/outside_operating_envelope_prod"))

    def test_r9_irreversible_actuate(self):
        r = self.decide(_envelope(verb="actuate", reversibility="irreversible",
                                  session_id=_session()))
        self.assertEqual((r["decision"], r["rule"]),
                         ("require_approval", "reeflex.policy/physical_irreversible"))
        self.assertIn("hold_id", r)

    def test_r11_mode(self):
        r = self.decide(_envelope(verb="mode", session_id=_session()))
        self.assertEqual((r["decision"], r["rule"]),
                         ("require_approval", "reeflex.policy/mode_change_live"))

    def test_dev_arms_nothing(self):
        for kw in [dict(verb="override"), dict(safety_function=True),
                   dict(envelope_fraction=1.5), dict(verb="mode"),
                   dict(verb="flash", reversibility="irreversible")]:
            with self.subTest(**kw):
                r = self.decide(_envelope(environment="dev", session_id=_session(), **kw))
                self.assertEqual(r["rule"], "reeflex.policy/default_allow")

    def test_the_same_override_on_an_it_envelope_is_not_r8(self):
        """Control: the verdict follows the declared externality."""
        r = self.decide(_envelope(verb="override", externality="internal",
                                  session_id=_session()))
        self.assertEqual(r["rule"], "reeflex.policy/default_allow")


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestPhysicalBudgetsThroughTheLedger(_DecidePathCase):

    def _first_hold(self, n, **kw):
        sid = _session()
        for i in range(1, n + 1):
            r = self.decide(_envelope(session_id=sid, **kw))
            if r["decision"] != "allow":
                return i, r
        return None, None

    def test_physical_writes_trips_on_the_eleventh_write(self):
        i, r = self._first_hold(20, verb="set", environment="staging")
        self.assertEqual(i, 11)
        self.assertEqual(r["rule"], "reeflex.policy/cumulative_budget")
        self.assertIn("physical_writes", r["reason"])

    def test_the_40_step_sweep_with_shipped_defaults_trips_physical_writes_first(self):
        """0.03 x 40 is 1.2 of a range, but the writes budget (10) is met long
        before the envelope sum (0.33 at step 11). The envelope dimension
        deciding that sequence is pinned in physical_test.rego, under a
        principal override that takes the writes budget out of play."""
        i, r = self._first_hold(40, verb="set", envelope_fraction=0.03)
        self.assertEqual(i, 11)
        self.assertIn("physical_writes", r["reason"])

    def test_physical_envelope_trips_when_the_sum_exceeds_one_range(self):
        # 5 x 0.18 = 0.90, 6 x 0.18 = 1.08
        i, r = self._first_hold(10, verb="set", envelope_fraction=0.18)
        self.assertEqual(i, 6)
        self.assertIn("physical_envelope", r["reason"])

    def test_ten_steps_of_a_tenth_are_one_range_and_do_not_trip(self):
        """fsum: ten 0.1 steps are exactly 1.0, so the 10th is AT the limit and
        the 11th is the first one over. With a left-to-right `+=` the prior
        sum at step 11 is 0.9999999999999999 and the 11th step reads 1.0999...
        -- same trip here, but the sum the policy sees is the declared one."""
        sid = _session()
        for _ in range(10):
            # `update` so physical_writes (set/mode/...) is not what is measured.
            r = self.decide(_envelope(verb="update", envelope_fraction=0.1, session_id=sid))
            self.assertEqual(r["decision"], "allow")
        cum = self.ledger.compute_cumulative(sid, 3600)
        self.assertEqual(cum["sum_physical_envelope"], 1.0)
        r = self.decide(_envelope(verb="update", envelope_fraction=0.1, session_id=sid))
        self.assertIn("physical_envelope", r["reason"])

    def test_an_unmapped_physical_update_session_keeps_todays_verdicts(self):
        """SPEC §3.1 tells an adapter that cannot classify a plant action to
        send `update` + physical + the most restrictive axes. In staging that
        is not R3, so the only thing that can hold it is a budget: main holds
        it at call 11 (objects_touched, 11 x the systemic charge of 20 > 200).
        Same here -- physical_writes does not charge `update`, so the physical
        dimensions add nothing to this session. (Measured on main with the
        same probe: .ev154 evidence, before/after.)"""
        i, r = self._first_hold(15, verb="update", environment="staging",
                                reversibility="irreversible", blast_radius="systemic")
        self.assertEqual(i, 11)
        self.assertIn("objects_touched", r["reason"])


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestAnApprovalBindsThePhysicalFields(_DecidePathCase):
    """A hold approved for one physical action does not release another."""

    def _approve_then_resubmit(self, held: dict, resubmitted: dict) -> dict:
        r1 = self.decide(held)
        self.assertEqual(r1["decision"], "require_approval", r1)
        hold_id = r1["hold_id"]
        self.holds.resolve_hold(hold_id, "approve", "human", "supervisor:carol-synthetic",
                                "synthetic approval")
        again = copy.deepcopy(resubmitted)
        again["meta"]["nonce"] = uuid.uuid4().hex
        again["approval"] = {"present": True, "hold_id": hold_id}
        return self.decide(again)

    def _actuate(self, sid, **kw):
        # R9 holds it; actuate is not one of R8's verbs, so a safety_function
        # of true does NOT turn it into a deny -- the hash is the only thing
        # that can tell the two envelopes apart.
        return _envelope(verb="actuate", reversibility="irreversible",
                         session_id=sid, **kw)

    def test_a_hold_for_a_0_4_step_does_not_release_a_0_9_step(self):
        sid = _session()
        r = self._approve_then_resubmit(self._actuate(sid, envelope_fraction=0.4),
                                        self._actuate(sid, envelope_fraction=0.9))
        self.assertEqual(r["decision"], "deny", r)
        self.assertEqual(r["reason"], "reeflex_hold_envelope_mismatch")

    def test_control_the_same_0_4_step_is_released(self):
        sid = _session()
        r = self._approve_then_resubmit(self._actuate(sid, envelope_fraction=0.4),
                                        self._actuate(sid, envelope_fraction=0.4))
        self.assertEqual((r["decision"], r["rule"]),
                         ("allow", "reeflex.policy/approved_resubmission"))

    def test_an_approval_for_a_non_safety_target_does_not_release_a_safety_one(self):
        sid = _session()
        r = self._approve_then_resubmit(self._actuate(sid, safety_function=False),
                                        self._actuate(sid, safety_function=True))
        self.assertEqual(r["decision"], "deny", r)
        self.assertEqual(r["reason"], "reeflex_hold_envelope_mismatch")

    def test_control_the_same_non_safety_target_is_released(self):
        sid = _session()
        r = self._approve_then_resubmit(self._actuate(sid, safety_function=False),
                                        self._actuate(sid, safety_function=False))
        self.assertEqual(r["decision"], "allow", r)


class TestNonResolvable(unittest.TestCase):

    def test_the_physical_denies_are_not_resolvable(self):
        from app.server import NON_RESOLVABLE_RULES
        self.assertIn("safety_function_override_prod", NON_RESOLVABLE_RULES)
        self.assertIn("outside_operating_envelope_prod", NON_RESOLVABLE_RULES)
        self.assertNotIn("physical_irreversible", NON_RESOLVABLE_RULES)
        self.assertNotIn("mode_change_live", NON_RESOLVABLE_RULES)


if __name__ == "__main__":
    unittest.main()
