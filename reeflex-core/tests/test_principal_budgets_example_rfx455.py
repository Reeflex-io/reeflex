"""RFX-455 (3): the shipped `principal_budgets` example must load.

budgets.rego documents its per-principal override with an example in a
comment. Copying that example into the pack made `opa check` fail with a
rego_type_error (OPA infers the type of `principal_budgets` from its literal,
and `money_limit` dotted into a `money.limits` key the example does not have),
and every decision failed closed with HTTP 500 (dev-2 round 034, OPA 1.18.0).
The policy tests inject overrides with `with`, which the type checker never
sees, so nothing in the suite could catch it.

This file does what an operator does: it takes the example TEXT out of the
shipped budgets.rego, writes it into a copy of the pack, and runs `opa check`
and a real decision through app.decide.process against that copy. If the
example's text changes, the test follows it; if it stops being findable, the
test fails rather than going vacuous.

Run:
  cd reeflex-core
  python -m unittest tests.test_principal_budgets_example_rfx455 -v
"""

from __future__ import annotations

import copy
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
import uuid

from app.opa import _opa_bin
from tests.test_physical_impact_rfx427 import _opa_available

_POLICY = pathlib.Path(__file__).resolve().parents[1] / "policy"
_EMPTY = "principal_budgets := {}\n"
#: The example line in the comment above `principal_budgets := {}`.
_EXAMPLE = re.compile(r'^#\s+("[^"]+":\s*\{.*\})\s*$', re.M)


def _shipped_example() -> tuple[str, str]:
    """(session_id, entry) as written in the shipped budgets.rego comment."""
    text = (_POLICY / "budgets.rego").read_text(encoding="utf-8")
    head = text[: text.index(_EMPTY)]
    block = head[head.rindex("# Empty by default"):]
    found = _EXAMPLE.findall(block)
    assert len(found) == 1, f"expected one example line above principal_budgets, got {found}"
    session_id = re.match(r'"([^"]+)"', found[0]).group(1)
    return session_id, found[0]


def _pack_with(entry: str, into: str) -> str:
    """A copy of the shipped pack (tests excluded) with `entry` enabled."""
    for src in _POLICY.glob("*.rego"):
        if not src.name.endswith("_test.rego"):
            shutil.copy(src, into)
    path = pathlib.Path(into) / "budgets.rego"
    text = path.read_text(encoding="utf-8")
    assert text.count(_EMPTY) == 1
    path.write_text(text.replace(_EMPTY, "principal_budgets := {%s}\n" % entry),
                    encoding="utf-8")
    return into


def _opa_check(policy_dir: str) -> subprocess.CompletedProcess:
    return subprocess.run([_opa_bin(), "check", policy_dir],
                          capture_output=True, text=True, timeout=60)


@unittest.skipUnless(_opa_available(), "OPA binary not available")
class TestTheShippedExampleLoads(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="rfx455_pb_")
        self.policy = os.path.join(self._dir, "policy")
        os.mkdir(self.policy)
        # Saved and RESTORED, not popped: tests/__init__.py points the whole
        # run at a temp ledger, and popping it sends every later test to the
        # in-tree default (it made test_healthz_revision_rfx89 see the path).
        self._saved_env = {k: os.environ.get(k)
                           for k in ("REEFLEX_HOLDS_PATH", "REEFLEX_LEDGER_PATH",
                                     "REEFLEX_POLICY_DIR")}
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._dir, "holds.jsonl")
        os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(self._dir, "ledger.jsonl")
        import app.holds as h
        import app.ledger as l
        h._reset(os.environ["REEFLEX_HOLDS_PATH"])
        l._reset_for_tests()
        self.ledger = l

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.ledger._reset_for_tests()
        shutil.rmtree(self._dir, ignore_errors=True)

    def _decide(self, session_id: str, count: int) -> tuple[int, dict]:
        from app.decide import process
        env = {
            "reeflex_version": "0.1",
            "agent": {"id": "agent:rfx455", "session_id": session_id},
            "action": {"namespace": "grid", "verb": "update"},
            "target": {"kind": "row", "environment": "staging"},
            "magnitude": {"count": count},
            "axes": {"reversibility": "reversible", "blast_radius": "single",
                     "externality": "internal"},
            "meta": {"nonce": uuid.uuid4().hex},
        }
        return process(copy.deepcopy(env))

    def test_the_example_is_the_shape_this_file_expects(self):
        session_id, entry = _shipped_example()
        self.assertEqual(session_id, "agent:some-session-id")
        self.assertIn("objects_touched", entry)
        self.assertNotIn("money", entry)

    def test_opa_check_passes_with_the_example_enabled(self):
        _pack_with(_shipped_example()[1], self.policy)
        proc = _opa_check(self.policy)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_real_decision_reads_the_example(self):
        """objects_touched limit 10 for that principal: 11 objects is held
        for it, and the same call under another session is allowed."""
        session_id, entry = _shipped_example()
        os.environ["REEFLEX_POLICY_DIR"] = _pack_with(entry, self.policy)
        status, resp = self._decide(session_id, 11)
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], "reeflex.policy/cumulative_budget")
        self.assertIn("objects_touched", resp["reason"])
        status, resp = self._decide(f"rfx455_other_{uuid.uuid4().hex[:6]}", 11)
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["decision"], "allow", resp)

    def test_other_partial_entries_also_pass_opa_check(self):
        """The example is one shape; these are the others an operator writes."""
        for entry in ('"s": {"money": {"limit": 100}}',
                      '"s": {"money": {"limits": {"EUR": 100}}}',
                      '"s": {"physical_writes": {"limit": 40}}',
                      '"s": {"money": {"limit": 100, "limits": {"EUR": 100}}}'):
            with self.subTest(entry=entry):
                shutil.rmtree(self.policy)
                os.mkdir(self.policy)
                proc = _opa_check(_pack_with(entry, self.policy))
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
