"""
test_strict_preset_rfx433.py -- the strict preset R2s
`reeflex.policy/irreversible_prod_strict` (strict.rego) through core's REAL
decision path, and what switching it on changes over the totality grid.

WHY THIS FILE AND NOT ONLY policy/strict_test.rego
==================================================
The Rego tests flip the switch with `with policy.strict as ...`. An operator
does not: they edit strict.rego in the policy dir core loads. So this file
copies the shipped pack, flips the one literal in strict.rego, points
REEFLEX_POLICY_DIR at the copy and drives app.decide.process -- the leg
`opa test` cannot see (core canonicalises the envelope first, and raises a
hold off the decision).

WHAT SWITCHING IT ON CHANGES, MEASURED OVER THE GRID
====================================================
test_decision_totality.py proves the pack answers one decision per point with
the switch off and on. This file asserts what the switch MOVES between those
two answers: every point that changes goes from an ALLOW to an R2s hold, and
no deny, no hold and no other rule id moves. That is the property the R2s
block in reeflex.rego claims for placing it last among the holds.

Run:
  cd reeflex-core
  REEFLEX_OPA_BIN=/root/.local/bin/opa python3.12 -m unittest tests.test_strict_preset_rfx433 -v
"""

from __future__ import annotations

import collections
import copy
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

from app.opa import _policy_dir  # noqa: E402
from tests.test_decision_totality import (  # noqa: E402
    _QUERY, _STRICT_QUERY, _eval, _strict_grid,
)

R2S = "reeflex.policy/irreversible_prod_strict"
SHIPPED_LINE = '"hold_every_irreversible_in_production": false,'
ON_LINE = '"hold_every_irreversible_in_production": true,'


def _opa_available() -> bool:
    return bool(os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa"))


def _envelope(*, blast_radius="scoped", reversibility="irreversible",
              environment="production", verb="delete", session_id) -> dict:
    """An irreversible production action no base rule holds: no ability
    (R7), no protected ref (R6), count 1 (R5)."""
    return {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:rfx433", "on_behalf_of": "user:synthetic",
                  "session_id": session_id},
        "action": {"namespace": "files", "verb": verb},
        "target": {"kind": "file", "ref": "/tmp/scratch.txt",
                   "environment": environment},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {"reversibility": reversibility, "blast_radius": blast_radius,
                 "externality": "internal"},
        "approval": {"present": False},
        "context": {},
        "meta": {"timestamp": "2026-10-21T00:00:00Z",
                 "nonce": uuid.uuid4().hex, "signature": "ed25519:synthetic"},
    }


def _session() -> str:
    return f"rfx433_{uuid.uuid4().hex[:12]}"


class TestTheShippedSwitch(unittest.TestCase):

    def test_strict_rego_ships_the_switch_off_on_exactly_one_line(self):
        text = (pathlib.Path(_policy_dir()) / "strict.rego").read_text()
        self.assertEqual(text.count(SHIPPED_LINE), 1, "the flip below would be vacuous")
        self.assertNotIn(ON_LINE, text)


class _DecidePathCase(unittest.TestCase):
    """process() against either the shipped pack or a copy with strict ON."""

    strict_on = False

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="rfx433_")
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._dir, "holds.jsonl")
        os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(self._dir, "ledger.jsonl")
        if self.strict_on:
            pack = os.path.join(self._dir, "policy")
            shutil.copytree(_policy_dir(), pack)
            path = pathlib.Path(pack) / "strict.rego"
            path.write_text(path.read_text().replace(SHIPPED_LINE, ON_LINE))
            self.assertEqual(path.read_text().count(ON_LINE), 1)
            os.environ["REEFLEX_POLICY_DIR"] = pack
        import app.holds as holds_mod
        import app.ledger as ledger_mod
        holds_mod._reset(os.environ["REEFLEX_HOLDS_PATH"])
        ledger_mod._reset_for_tests()
        self.ledger = ledger_mod

    def tearDown(self) -> None:
        for k in ("REEFLEX_HOLDS_PATH", "REEFLEX_LEDGER_PATH", "REEFLEX_POLICY_DIR"):
            os.environ.pop(k, None)
        self.ledger._reset_for_tests()
        shutil.rmtree(self._dir, ignore_errors=True)

    def decide(self, env: dict) -> dict:
        from app.decide import process
        status, resp = process(copy.deepcopy(env))
        self.assertEqual(status, 200, resp)
        return resp


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestStrictOffThroughProcess(_DecidePathCase):
    """The shipped default: the coding-agent posture, unchanged."""

    def test_scoped_irreversible_production_allows(self):
        for blast in ("single", "scoped"):
            with self.subTest(blast_radius=blast):
                r = self.decide(_envelope(blast_radius=blast, session_id=_session()))
                self.assertEqual((r["decision"], r["rule"]),
                                 ("allow", "reeflex.policy/default_allow"))


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestStrictOnThroughProcess(_DecidePathCase):

    strict_on = True

    def test_scoped_irreversible_production_holds_under_its_own_rule(self):
        for blast in ("single", "scoped"):
            with self.subTest(blast_radius=blast):
                r = self.decide(_envelope(blast_radius=blast, session_id=_session()))
                self.assertEqual((r["decision"], r["rule"]), ("require_approval", R2S))
                self.assertTrue(r.get("hold_id"), f"a hold was not raised: {r}")

    def test_the_hold_is_resolvable(self):
        from app.server import NON_RESOLVABLE_RULES
        self.assertNotIn("irreversible_prod_strict", NON_RESOLVABLE_RULES)

    def test_r3_still_denies(self):
        r = self.decide(_envelope(blast_radius="systemic", session_id=_session()))
        self.assertEqual((r["decision"], r["rule"]),
                         ("deny", "reeflex.policy/irreversible_systemic_prod"))

    def test_r2_keeps_its_rule_id(self):
        r = self.decide(_envelope(blast_radius="broad", session_id=_session()))
        self.assertEqual(r["rule"], "reeflex.policy/irreversible_broad_prod")

    def test_recoverable_and_non_production_are_untouched(self):
        for kw in ({"reversibility": "reversible"}, {"environment": "staging"},
                   {"environment": "dev"}):
            with self.subTest(**kw):
                r = self.decide(_envelope(session_id=_session(), **kw))
                self.assertEqual(r["rule"], "reeflex.policy/default_allow")

    def test_an_omitted_reversibility_is_reported_as_unclassified(self):
        """core fills an absent reversibility with `irreversible`: the strict
        hold then rests on a guess, and R0 says so."""
        env = _envelope(session_id=_session())
        del env["axes"]["reversibility"]
        r = self.decide(env)
        self.assertEqual((r["decision"], r["rule"]),
                         ("require_approval", "reeflex.policy/unclassified_action"))


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestWhatTheSwitchMoves(unittest.TestCase):
    """Off vs on over every grid point the preset can reach."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.grid = grid = _strict_grid()
        ok_off, cls.off = _eval(grid, _QUERY)
        ok_on, cls.on = _eval(grid, _STRICT_QUERY)
        assert ok_off and ok_on, (cls.off, cls.on)
        assert len(cls.off) == len(cls.on) == len(grid)

    def _changed(self):
        return [(e, a, b) for e, a, b in zip(self.grid, self.off, self.on) if a != b]

    def test_the_switch_changes_something(self):
        """A property over zero changed points holds forever."""
        self.assertGreater(len(self._changed()), 0)

    def test_every_change_is_an_allow_becoming_a_hold(self):
        """No deny, no hold and no other rule id moves when the switch flips.
        Measured on the first draft of the R0 clause: 1,206 R5/R7/R11 holds
        were renamed `unclassified_action` -- this is the assertion that saw it."""
        moves = collections.Counter(
            (a["rule"], b["decision"], b["rule"]) for _, a, b in self._changed()
        )
        allows = {"reeflex.policy/default_allow", "reeflex.policy/read_only_internal"}
        holds = {R2S, "reeflex.policy/unclassified_action"}
        bad = {k: n for k, n in moves.items()
               if k[0] not in allows or k[1] != "require_approval" or k[2] not in holds}
        self.assertEqual(bad, {}, json.dumps({str(k): n for k, n in moves.items()}))

    def test_r2s_on_declared_inputs_and_r0_on_guessed_ones(self):
        """The strict hold is reported as R0 exactly when core guessed one of
        the two fields R2s reads; a guessed blast_radius alone is still R2s."""
        reads = {"axes.reversibility", "target.environment"}
        seen = collections.Counter()
        for e, _, b in self._changed():
            guessed = bool(reads & set(e.get("provenance", {}).get("undeclared", [])))
            seen[(guessed, b["rule"])] += 1
            self.assertEqual(
                b["rule"],
                "reeflex.policy/unclassified_action" if guessed else R2S,
                json.dumps(e, sort_keys=True),
            )
        self.assertEqual({k[0] for k in seen}, {True, False}, "one side is vacuous")

    def test_no_allow_survives_the_switch_on_this_subset(self):
        """Every irreversible production point on the grid is held or denied."""
        allowed = [b for b in self.on if b["decision"] == "allow"]
        self.assertEqual(allowed, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
