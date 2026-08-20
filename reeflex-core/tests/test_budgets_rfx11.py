"""
test_budgets_rfx11.py — E2E proof for RFX-11: configurable cumulative
budgets over heterogeneous action types.

Drives the REAL decide.process() path end-to-end (envelope -> validate ->
ledger -> OPA eval -> decision), same discipline as test_decide.py. No
mocking of OPA.

What this proves, concretely:

  T_smurfing_objects_touched
    N individually-harmless actions of DIFFERENT verbs (none of them
    "delete", none outbound, none carrying money — the tier a hardcoded,
    payments-specific session amplifier assigns weight 0 and never
    accumulates) still push the `objects_touched` dimension over budget at
    the N+1-th action. The Permit0 gap this ticket closes.

  T_budget_is_policy_not_python
    The SAME scenario, run against a policy directory whose budgets.rego
    has been edited (objects_touched limit lowered from the default 200 to
    5) with ZERO Python changes. The number of harmless actions tolerated
    before a HOLD changes because a human edited a Rego file — proving the
    budget is policy data a user writes, not a constant baked into core.

  T_money_dimension_aggregates_e2e
    Two different verbs ("transact", "refund") both carrying params.amount
    in the same currency accumulate toward the SAME `money` budget end to
    end through the real ledger, not just in the Rego unit tests.

Run:
  cd reeflex-core
  python -m unittest tests.test_budgets_rfx11 -v
"""

from __future__ import annotations

import json
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

import app.ledger as ledger_mod
from app.decide import process


def _fresh_session() -> str:
    return f"rfx11_sess_{uuid.uuid4().hex[:12]}"


def _envelope(
    *,
    session_id: str,
    verb: str,
    externality: str = "internal",
    count: int = 1,
    params: dict | None = None,
) -> dict:
    """A harmless-by-construction envelope: reversible/single/<externality>,
    staging, never trips R1/R2/R3 on its own. Only the cumulative budget
    mechanism (R5) can turn this into a hold."""
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:rfx11-test-runner",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id,
        },
        "action": {
            "namespace": "test",
            "verb": verb,
            "ability": f"test/{verb}",
        },
        "target": {"kind": "row", "ref": None, "environment": "staging"},
        "params": params or {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": "reversible",
            "blast_radius": "single",
            "externality": externality,
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-08-20T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


# ---------------------------------------------------------------------------
# T_smurfing_objects_touched: heterogeneous small actions still accumulate
# ---------------------------------------------------------------------------

class TestSmurfingObjectsTouched(unittest.TestCase):

    def setUp(self) -> None:
        self.session_id = _fresh_session()
        ledger_mod.clear_session(self.session_id)

    def test_heterogeneous_small_actions_accumulate_to_a_hold(self) -> None:
        """
        200 individually-harmless actions of DIFFERENT verbs (default
        objects_touched budget), none of them deletions/outbound/money ->
        none blocked. The 201st (any verb) crosses the budget -> hold.

        This is the exact scenario a hardcoded, payments-only cumulative
        budget misses: no single action is a delete, an outbound send, or a
        transaction, so a rival whose small tier contributes 0 never
        accumulates. objects_touched has no such blind spot.
        """
        verbs = ["read", "update", "comment", "react", "tag", "list", "describe"]

        for i in range(200):
            env = _envelope(session_id=self.session_id, verb=verbs[i % len(verbs)])
            status, resp = process(env)
            self.assertEqual(status, 200, f"call {i + 1}: unexpected status {status}")
            self.assertEqual(
                resp["decision"], "allow",
                f"call {i + 1} (verb={env['action']['verb']}) was blocked prematurely: {resp}",
            )
            self.assertNotEqual(resp["rule"], "reeflex.policy/cumulative_budget")

        # Call 201: any verb; cumulative total_count is now 200, +1 = 201 > 200.
        env = _envelope(session_id=self.session_id, verb="react")
        status, resp = process(env)
        print(f"\n[T_smurfing] crossing call: status={status} response={json.dumps(resp, indent=2)}")

        self.assertEqual(status, 200)
        self.assertEqual(
            resp["decision"], "require_approval",
            f"the 201st harmless action should have been held, got: {resp}",
        )
        self.assertEqual(resp["rule"], "reeflex.policy/cumulative_budget")
        self.assertIn("objects_touched", resp["reason"])


# ---------------------------------------------------------------------------
# T_money_dimension_aggregates_e2e: heterogeneous verbs, same money budget
# ---------------------------------------------------------------------------

class TestMoneyDimensionAggregatesAcrossVerbs(unittest.TestCase):

    def setUp(self) -> None:
        self.session_id = _fresh_session()
        ledger_mod.clear_session(self.session_id)

    def test_transact_and_refund_share_the_same_money_budget(self) -> None:
        """
        "transact" and "refund" are different verbs; the money budget
        (default 5000) must aggregate them as ONE dimension, not reset per
        verb (the exact hardcoded, payments-specific-verb gap RFX-11
        targets).
        """
        env1 = _envelope(
            session_id=self.session_id, verb="transact",
            params={"amount": 3000, "currency": "EUR"},
        )
        status1, resp1 = process(env1)
        self.assertEqual(resp1["decision"], "allow", resp1)

        # A DIFFERENT verb, same currency: 3000 + 2500 = 5500 > 5000.
        env2 = _envelope(
            session_id=self.session_id, verb="refund",
            params={"amount": 2500, "currency": "EUR"},
        )
        status2, resp2 = process(env2)
        print(f"\n[T_money] resp={json.dumps(resp2, indent=2)}")

        self.assertEqual(resp2["decision"], "require_approval", resp2)
        self.assertEqual(resp2["rule"], "reeflex.policy/cumulative_budget")
        self.assertIn("money", resp2["reason"])


# ---------------------------------------------------------------------------
# T_budget_is_policy_not_python: editing budgets.rego changes the outcome,
# with ZERO Python changes.
# ---------------------------------------------------------------------------

class TestBudgetIsPolicyNotPython(unittest.TestCase):

    def setUp(self) -> None:
        self.session_id = _fresh_session()
        ledger_mod.clear_session(self.session_id)

        # Copy the real policy dir, then edit ONLY budgets.rego (a data
        # file) to lower objects_touched from 200 to 5. This is the "user
        # writes the budget in policy" proof: no app code changes, just
        # Rego data, and the mechanism honors it end to end.
        self._tmpdir = tempfile.mkdtemp(prefix="rfx11-policy-")
        real_policy_dir = _repo_root / "policy"
        self._tmp_policy_dir = pathlib.Path(self._tmpdir) / "policy"
        shutil.copytree(real_policy_dir, self._tmp_policy_dir)

        budgets_path = self._tmp_policy_dir / "budgets.rego"
        text = budgets_path.read_text(encoding="utf-8")
        edited = text.replace(
            '"objects_touched": {"limit": 200},',
            '"objects_touched": {"limit": 5},',
        )
        self.assertNotEqual(text, edited, "expected default limit literal to be present and replaced")
        budgets_path.write_text(edited, encoding="utf-8")

        self._orig_policy_dir = os.environ.get("REEFLEX_POLICY_DIR")
        os.environ["REEFLEX_POLICY_DIR"] = str(self._tmp_policy_dir)

    def tearDown(self) -> None:
        if self._orig_policy_dir is None:
            os.environ.pop("REEFLEX_POLICY_DIR", None)
        else:
            os.environ["REEFLEX_POLICY_DIR"] = self._orig_policy_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_lowering_the_rego_budget_holds_sooner(self) -> None:
        """
        With objects_touched lowered to 5 by editing budgets.rego, 5
        harmless heterogeneous actions allow and the 6th holds — a policy
        author changed the tolerance with a one-line data edit, not a code
        change.
        """
        verbs = ["read", "update", "comment", "react", "tag"]
        for i, verb in enumerate(verbs):
            env = _envelope(session_id=self.session_id, verb=verb)
            status, resp = process(env)
            self.assertEqual(status, 200)
            self.assertEqual(
                resp["decision"], "allow",
                f"call {i + 1} (verb={verb}) blocked prematurely under the lowered budget: {resp}",
            )

        env6 = _envelope(session_id=self.session_id, verb="list")
        status6, resp6 = process(env6)
        print(f"\n[T_budget_is_policy] crossing call: status={status6} response={json.dumps(resp6, indent=2)}")

        self.assertEqual(status6, 200)
        self.assertEqual(resp6["decision"], "require_approval", resp6)
        self.assertEqual(resp6["rule"], "reeflex.policy/cumulative_budget")
        self.assertIn("objects_touched", resp6["reason"])


if __name__ == "__main__":
    unittest.main()
