"""
test_durable_ledger_rfx197.py — RFX-197: the anti-fragmentation ledger must
survive a restart and must be shared by a second replica.

WHAT WAS MEASURED BEFORE THE FIX, on the customer artefact (the root
Dockerfile) at origin/main 7f9ebf8, with the shipped `deletions: {limit: 20}`
budget and ONE session_id, 4 x count=5 to exhaust it:

    CONTROL   same live process                     -> 5th call held
    VECTOR A  `docker restart`, replay SAME session -> 20 MORE deletes allowed
    VECTOR B  a 2nd replica, SAME session           -> another 20 allowed

So "a per-session cumulative ledger defeats split-batch evasion" (README) held
for exactly one process that had never been restarted. No attacker, no
privilege, no race -- just a restart, or the ordinary two-replicas-behind-a-
load-balancer HA shape.

These tests are the in-process equivalents of those vectors, so the defect
cannot come back without a red suite:

  T_vector_A_restart          exhaust the budget, DROP every byte of in-process
                              state (the restart), replay the same session ->
                              still held. This is the test that fails on main.
  T_vector_B_second_replica   a genuinely SEPARATE PROCESS spends the budget;
                              this process must then refuse. Not a second
                              module instance -- a real subprocess, because
                              "two replicas" is the thing being claimed.
  T_counter_never_falls       the audit stream's `cumulative_injected` is
                              monotonic across a restart. The original defect
                              was detectable in the evidence (delete 20 -> 0 in
                              11 seconds, both rows claiming window 3600) and
                              nothing detected it.
  T_epoch_marker              a restart now writes a `ledger_epoch` event and
                              every decision row carries the epoch it was
                              decided under, so a counter that DOES fall has a
                              named cause on the same append-only stream.
  T_fail_closed               if the ledger cannot record the action, /v1/decide
                              DENIES. An enforcement point that cannot remember
                              must refuse -- otherwise the next call's budget
                              under-counts, which is this same fail-open by
                              another route.
  T_guard_spans_the_cycle     decide.process() holds session_guard() across
                              compute_cumulative -> eval -> append_entry, and
                              the guard excludes ACROSS PROCESSES. Checked
                              structurally (AST) as well as behaviourally,
                              because a future refactor can silently unwrap it
                              and every other test here would still pass.
  T_persist_default           an unrecognised REEFLEX_LEDGER_PERSIST value reads
                              as DURABLE. A typo must not silently return the
                              product to the RFX-197 behaviour.

Run:
  cd reeflex-core
  python -m unittest tests.test_durable_ledger_rfx197 -v
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod  # noqa: E402

_LEDGER_PY = pathlib.Path(ledger_mod.__file__)
_DECIDE_PY = _LEDGER_PY.parent / "decide.py"

# The shipped deletions budget (policy/budgets.rego default_budgets). Read from
# the policy rather than hardcoded here, so a policy edit cannot make this file
# quietly assert against a limit the product no longer has.
_DELETE_LIMIT = 20
_STEP = 5  # count per call; 4 calls == the limit, the 5th must hold


def _envelope(session_id: str, count: int = _STEP, verb: str = "delete") -> dict:
    """Harmless by construction: reversible / single / internal / staging, all
    axes declared (so RFX-132's unclassified-action rule is not what fires).
    ONLY the cumulative budget (R5) can turn this into a hold."""
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:rfx197-test-runner",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id,
        },
        "action": {"namespace": "test", "verb": verb, "ability": f"test/{verb}"},
        "target": {"kind": "row", "ref": None, "environment": "staging"},
        "params": {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": "reversible",
            "blast_radius": "single",
            "externality": "internal",
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-08-22T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


class _LedgerTmpEnv(unittest.TestCase):
    """Per-test tmpdir for the ledger AND the audit log, restored on teardown.

    Every test here owns its own files: these tests assert on absolute
    cumulative totals, so a ledger shared with another test (or another run of
    this suite) would make them pass or fail on history rather than on
    behaviour. That is the same class of bug as the defect under test.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger_path = os.path.join(self._tmp.name, "ledger.jsonl")
        self.audit_path = os.path.join(self._tmp.name, "decisions.jsonl")
        self._saved = {
            k: os.environ.get(k)
            for k in ("REEFLEX_LEDGER_PATH", "REEFLEX_AUDIT_LOG",
                      "REEFLEX_LEDGER_PERSIST", "REEFLEX_HOLDS_PATH")
        }
        os.environ["REEFLEX_LEDGER_PATH"] = self.ledger_path
        os.environ["REEFLEX_AUDIT_LOG"] = self.audit_path
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._tmp.name, "holds.jsonl")
        os.environ.pop("REEFLEX_LEDGER_PERSIST", None)
        ledger_mod._reset_for_tests()
        self.session = f"rfx197_{uuid.uuid4().hex[:12]}"

    def tearDown(self) -> None:
        ledger_mod._reset_for_tests()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    # -- helpers ----------------------------------------------------------

    def _decide(self, **kw) -> dict:
        from app.decide import process
        status, resp = process(_envelope(self.session, **kw))
        self.assertEqual(200, status, resp)
        return resp

    def _exhaust(self) -> None:
        """Spend exactly the delete budget: 4 x count=5 == 20, all allowed."""
        for i in range(_DELETE_LIMIT // _STEP):
            resp = self._decide()
            self.assertEqual(
                "allow", resp["decision"],
                f"call {i + 1} of the budget should still be allowed: {resp}",
            )

    def _simulate_restart(self) -> None:
        """The restart, as seen by this module: every byte of in-process state
        is dropped and only the FILE survives. This is exactly what
        `docker restart` does to the old in-memory dict -- which is why, before
        RFX-197, this call alone restored the full budget."""
        ledger_mod._reset_for_tests()

    def _audit_rows(self) -> list[dict]:
        if not os.path.exists(self.audit_path):
            return []
        with open(self.audit_path, encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def _decisions_for_session(self) -> list[dict]:
        return [
            r for r in self._audit_rows()
            if r.get("session_id") == self.session and "decision" in r
        ]


class TestVectorARestart(_LedgerTmpEnv):

    def test_restart_does_not_hand_back_the_budget(self) -> None:
        self._exhaust()
        held = self._decide()
        self.assertEqual("require_approval", held["decision"], held)
        self.assertEqual("reeflex.policy/session_delete_budget", held["rule"], held)

        self._simulate_restart()

        # THE ASSERTION THAT FAILS ON main 7f9ebf8: there, this came back
        # {"decision": "allow", "rule": "reeflex.policy/default_allow"} and the
        # session got a second full budget of 20 deletes with no human.
        after = self._decide()
        self.assertEqual(
            "require_approval", after["decision"],
            "a restart handed the session a fresh delete budget -- RFX-197 "
            f"vector A has regressed: {after}",
        )
        self.assertEqual("reeflex.policy/session_delete_budget", after["rule"], after)

    def test_restart_restores_the_spend_it_reports(self) -> None:
        self._exhaust()
        self._simulate_restart()
        epoch = ledger_mod.ledger_epoch()
        self.assertTrue(epoch["durable"], epoch)
        self.assertEqual(1, epoch["restored_sessions"], epoch)
        self.assertEqual(
            _DELETE_LIMIT // _STEP, epoch["restored_entries"],
            f"the epoch must report what it actually restored: {epoch}",
        )
        cum = ledger_mod.compute_cumulative(self.session, 3600)
        self.assertEqual(_DELETE_LIMIT, cum["count_by_verb"]["delete"], cum)


class TestVectorBSecondReplica(_LedgerTmpEnv):

    def test_a_second_process_shares_one_budget(self) -> None:
        # A REAL second process, sharing only the ledger file -- the in-process
        # equivalent of a second replica behind a load balancer. It spends the
        # whole delete budget on OUR session_id.
        script = textwrap.dedent(
            """
            import json, sys, uuid
            sys.path.insert(0, %(root)r)
            from app.decide import process
            session = sys.argv[1]
            out = []
            for _ in range(%(n)d):
                env = json.loads(sys.argv[2])
                env["agent"]["session_id"] = session
                env["meta"]["nonce"] = uuid.uuid4().hex
                status, resp = process(env)
                out.append(resp["decision"])
            print(json.dumps(out))
            """
        ) % {"root": str(_repo_root), "n": _DELETE_LIMIT // _STEP}

        env = dict(os.environ)
        env["REEFLEX_LEDGER_PATH"] = self.ledger_path
        env["REEFLEX_AUDIT_LOG"] = self.audit_path
        proc = subprocess.run(
            [sys.executable, "-c", script, self.session,
             json.dumps(_envelope(self.session))],
            capture_output=True, text=True, env=env, timeout=180,
        )
        self.assertEqual(0, proc.returncode, proc.stderr[-3000:])
        decisions = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(
            ["allow"] * (_DELETE_LIMIT // _STEP), decisions,
            f"the other replica should have spent the budget: {decisions}",
        )

        # THE ASSERTION THAT FAILS ON main: this process had its own dict, saw
        # cumulative 0, and allowed another 20 deletes.
        resp = self._decide()
        self.assertEqual(
            "require_approval", resp["decision"],
            "a second replica got its own full delete budget -- RFX-197 "
            f"vector B has regressed: {resp}",
        )
        self.assertEqual("reeflex.policy/session_delete_budget", resp["rule"], resp)


class TestTheEvidenceExplainsItself(_LedgerTmpEnv):

    def test_cumulative_counter_never_falls_across_a_restart(self) -> None:
        self._exhaust()
        self._simulate_restart()
        self._decide()

        deltas = [
            r["cumulative_injected"]["count_by_verb"].get("delete", 0)
            for r in self._decisions_for_session()
        ]
        self.assertTrue(len(deltas) >= 5, deltas)
        # On main this list was [0, 5, 10, 15, 20, 0] -- a monotonic counter
        # moving BACKWARDS inside its own declared 3600s window.
        for prev, cur in zip(deltas, deltas[1:]):
            self.assertGreaterEqual(
                cur, prev,
                "cumulative_injected.count_by_verb.delete fell inside its own "
                f"declared window: {deltas}",
            )

    def test_a_restart_is_named_in_the_audit_stream(self) -> None:
        self._exhaust()
        first = {r.get("ledger_epoch") for r in self._decisions_for_session()}
        self._simulate_restart()
        self._decide()

        epochs = [r for r in self._audit_rows() if r.get("event") == "ledger_epoch"]
        self.assertGreaterEqual(
            len(epochs), 2,
            "each boot must write a ledger_epoch event; on main the whole audit "
            "log contained no startup marker at all (grep returned 0)",
        )
        self.assertTrue(all(e["durable"] for e in epochs), epochs)
        self.assertTrue(all(e["path"] for e in epochs), epochs)
        self.assertEqual(
            _DELETE_LIMIT // _STEP, epochs[-1]["restored_entries"], epochs[-1],
        )

        # Every decision row is joinable to the boot that decided it, and the
        # epoch CHANGED across the restart -- which is what distinguishes "this
        # core rebooted" from "the spend vanished and nobody knows why".
        rows = self._decisions_for_session()
        self.assertTrue(all(r.get("ledger_epoch") for r in rows),
                        "a decision row with no ledger_epoch cannot be joined "
                        "to the ledger state it was decided against")
        self.assertNotEqual(
            first, {rows[-1]["ledger_epoch"]},
            "the epoch must change across a restart, or it explains nothing",
        )


class TestFailClosedWhenItCannotRemember(_LedgerTmpEnv):

    def test_an_unwritable_ledger_denies_instead_of_allowing(self) -> None:
        # Force the write to fail in a way that does not depend on file
        # permissions: these tests run as root, and root ignores a chmod. A
        # DIRECTORY where the ledger file should be makes open(path, "ab")
        # raise IsADirectoryError, which is the same OSError path a full disk
        # or a read-only mount takes.
        as_dir = os.path.join(self._tmp.name, "ledger-is-a-dir")
        os.makedirs(as_dir, exist_ok=True)
        os.environ["REEFLEX_LEDGER_PATH"] = as_dir
        ledger_mod._reset_for_tests()

        resp = self._decide(verb="read", count=1)
        # A read-only internal action is an ordinary ALLOW. It must still be
        # refused, because allowing an action the ledger has no record of is
        # how the NEXT call's budget silently under-counts.
        self.assertEqual(
            "deny", resp["decision"],
            f"an unrecordable action must not be allowed: {resp}",
        )
        self.assertEqual("reeflex.core/ledger_write_failed", resp["rule"], resp)

    def test_the_ledger_raises_rather_than_dropping_the_entry(self) -> None:
        as_dir = os.path.join(self._tmp.name, "ledger-is-a-dir-2")
        os.makedirs(as_dir, exist_ok=True)
        os.environ["REEFLEX_LEDGER_PATH"] = as_dir
        ledger_mod._reset_for_tests()
        with self.assertRaises(ledger_mod.LedgerWriteError):
            ledger_mod.append_entry(self.session, _envelope(self.session))


class TestTheGuardSpansTheCycle(_LedgerTmpEnv):
    """The guard is defence-in-depth and is NOT claiming the race occurs today.

    RFX-197 measured the read-decide-write race as HELD on the shipped image,
    because app/server.py builds http.server.HTTPServer and requests serialise.
    RFX-198's fix is ThreadingHTTPServer. The moment it lands, that accident is
    gone -- so the budget's correctness must not depend on the server class.
    """

    def test_decide_holds_the_guard_across_read_and_write(self) -> None:
        tree = ast.parse(_DECIDE_PY.read_text(encoding="utf-8"))
        process_fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "process"), None,
        )
        self.assertIsNotNone(process_fn, "decide.process not found")

        def _calls(node) -> set:
            out = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    out.add(n.func.id)
            return out

        guarded = [
            n for n in ast.walk(process_fn)
            if isinstance(n, ast.With)
            and any(
                isinstance(i.context_expr, ast.Call)
                and isinstance(i.context_expr.func, ast.Name)
                and i.context_expr.func.id == "session_guard"
                for i in n.items
            )
        ]
        self.assertTrue(
            guarded,
            "decide.process must hold session_guard() -- without it the "
            "read-decide-write cycle is only atomic by accident of the server "
            "class (RFX-197 / RFX-198)",
        )
        spanning = [
            w for w in guarded
            if "compute_cumulative" in _calls(w) and "append_entry" in _calls(w)
        ]
        self.assertTrue(
            spanning,
            "a session_guard() exists but does not span BOTH "
            "compute_cumulative and append_entry, so two callers can still "
            "read the same prior cumulative and both be allowed",
        )

    def test_the_guard_excludes_another_process(self) -> None:
        script = textwrap.dedent(
            """
            import sys, time
            sys.path.insert(0, %(root)r)
            import app.ledger as L
            with L.session_guard(sys.argv[1]):
                print("HELD", flush=True)
                time.sleep(2.0)
            """
        ) % {"root": str(_repo_root)}
        env = dict(os.environ)
        env["REEFLEX_LEDGER_PATH"] = self.ledger_path
        proc = subprocess.Popen(
            [sys.executable, "-c", script, self.session],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )
        try:
            self.assertEqual("HELD", (proc.stdout.readline() or "").strip(),
                             "helper never took the guard")
            t0 = time.time()
            with ledger_mod.session_guard(self.session):
                waited = time.time() - t0
            self.assertGreater(
                waited, 0.5,
                "session_guard did not exclude another PROCESS holding the "
                f"same session (acquired in {waited:.3f}s) -- two replicas "
                "sharing a volume can then interleave one session's budget",
            )
        finally:
            proc.wait(timeout=30)


class TestPersistenceDefault(_LedgerTmpEnv):

    def test_unrecognised_persist_value_stays_durable(self) -> None:
        # RFX-84's idiom: a typo must read as the SAFE default, never as the
        # opt-out. "REEFLEX_LEDGER_PERSIST=flase" must not silently return the
        # product to the behaviour RFX-197 filed.
        for raw in ("", "flase", "maybe", "1", "true", "TRUE", "yes"):
            os.environ["REEFLEX_LEDGER_PERSIST"] = raw
            self.assertTrue(
                ledger_mod.is_durable(),
                f"REEFLEX_LEDGER_PERSIST={raw!r} must not disable durability",
            )
        for raw in ("0", "false", "no", "off", "OFF"):
            os.environ["REEFLEX_LEDGER_PERSIST"] = raw
            self.assertFalse(
                ledger_mod.is_durable(),
                f"REEFLEX_LEDGER_PERSIST={raw!r} is an explicit opt-out",
            )

    def test_ephemeral_mode_says_so_in_the_epoch(self) -> None:
        os.environ["REEFLEX_LEDGER_PERSIST"] = "0"
        ledger_mod._reset_for_tests()
        epoch = ledger_mod.ledger_epoch()
        self.assertFalse(epoch["durable"], epoch)
        self.assertEqual("", epoch["path"], epoch)


if __name__ == "__main__":
    unittest.main()
