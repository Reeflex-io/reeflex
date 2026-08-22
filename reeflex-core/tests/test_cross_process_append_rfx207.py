"""RFX-207 (+ the holds twin, dev-1--040) — cross-process append discipline.

WHY EVERY TEST HERE SPAWNS A REAL SUBPROCESS.  The defect is invisible to a
same-interpreter test: `threading.Lock()` correctly serialises two threads, and
importing the module twice in one process gives you the SAME module object and
therefore the same lock and the same in-memory index.  RFX-207 says so
explicitly ("a second module instance is not a second replica"), so these tests
use `subprocess` with a fresh interpreter per replica.

Run under `python -m unittest discover` like the rest of the suite (RFX-87 —
this repo does not use pytest, and a pytest-style file collects zero tests here
while still passing the gate).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

_CORE_ROOT = str(pathlib.Path(__file__).resolve().parent.parent)

sys.path.insert(0, _CORE_ROOT)

from app import appendlog  # noqa: E402
from app.appendlog import AppendVerifyError  # noqa: E402


def _run_replica(code: str, env_extra: dict[str, str], timeout: int = 120):
    """Run `code` in a fresh interpreter — a genuinely separate replica."""
    env = dict(os.environ)
    env.update(env_extra)
    env["PYTHONPATH"] = _CORE_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", code],
        env=env, capture_output=True, text=True, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# 1. The wrong DENY: concurrent appends must not be mistaken for corruption
# ---------------------------------------------------------------------------

_WRITER = """
import json, os, sys
from app import audit, holds
env = {
    "action": {"verb": "delete", "ability": "wp/delete-post"},
    "target": {"environment": "production", "ref": "post/x"},
    "axes": {"reversibility": "irreversible", "blast_radius": "broad",
             "externality": "internal"},
    "magnitude": {"count": 901},
    "agent": {"session_id": os.environ["RFX_TAG"]},
}
n = int(os.environ["RFX_N"])
fails = []
for i in range(n):
    for what, fn in (("holds", lambda: holds.create_hold(env, "r2")),
                     ("audit", lambda: audit.record("s", env, {}, {"decision": "allow"}))):
        try:
            fn()
        except Exception as exc:
            fails.append(f"{what}:{type(exc).__name__}:{exc}"[:200])
print(json.dumps({"fails": fails}))
"""


class TwoReplicasOneVolume(unittest.TestCase):
    """The measured defect: 2-4 replicas on one volume, hundreds of raises."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="rfx207-")
        self.holds = os.path.join(self.tmp, "holds.jsonl")
        self.audit = os.path.join(self.tmp, "decisions.jsonl")

    def _spawn(self, n_replicas: int, n_writes: int):
        procs = []
        for idx in range(n_replicas):
            env = {
                "REEFLEX_HOLDS_PATH": self.holds,
                "REEFLEX_AUDIT_LOG": self.audit,
                "RFX_TAG": f"replica-{idx}",
                "RFX_N": str(n_writes),
                "PYTHONPATH": _CORE_ROOT,
            }
            full = dict(os.environ)
            full.update(env)
            procs.append(subprocess.Popen(
                [sys.executable, "-c", _WRITER],
                env=full, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        fails: list[str] = []
        for p in procs:
            out, err = p.communicate(timeout=180)
            self.assertEqual(p.returncode, 0, f"replica died: {err[-1500:]}")
            fails.extend(json.loads(out.strip().splitlines()[-1])["fails"])
        return fails

    def test_concurrent_replicas_never_refuse_a_write_that_landed(self) -> None:
        """No append may raise merely because a neighbour appended too.

        BEFORE this fix, at 3 replicas x 120 writes: 254 of 360 holds appends
        and 199 of 360 audit appends raised, in two distinct modes -- an
        OSError id mismatch (the mode RFX-207 predicted) and a JSONDecodeError
        from read()ing past the recorded size (a mode it did not).  Every line
        was on disk and every line parsed: the data was never the problem.
        """
        fails = self._spawn(3, 40)
        self.assertEqual(fails, [], f"{len(fails)} appends raised: {fails[:5]}")

    def test_every_record_from_every_replica_is_on_disk_and_parses(self) -> None:
        """The append-only stream must be intact and complete, not just quiet."""
        self._spawn(3, 40)
        for path, expected in ((self.holds, 120), (self.audit, 120)):
            lines = [l for l in pathlib.Path(path).read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), expected, f"{path}: {len(lines)} lines")
            for line in lines:
                json.loads(line)  # raises if a record was torn

    def test_records_are_whole_lines_never_interleaved_mid_record(self) -> None:
        """A record must never be spliced into the middle of another record."""
        self._spawn(4, 30)
        raw = pathlib.Path(self.holds).read_bytes()
        self.assertTrue(raw.endswith(b"\n"), "stream does not end on a record boundary")
        for line in raw.decode().splitlines():
            if line.strip():
                self.assertEqual(line.count('"id"'), 1,
                                 f"two records spliced into one line: {line[:120]}")


# ---------------------------------------------------------------------------
# 2. The proof must be a real proof — it has to BITE
# ---------------------------------------------------------------------------

class TheReadBackProofBites(unittest.TestCase):
    """A read-back that cannot fail is not evidence (gate-drift lesson)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="rfx207-verify-")
        self.path = pathlib.Path(self.tmp) / "log.jsonl"

    def test_a_clean_append_verifies_and_returns_its_offset(self) -> None:
        off1 = appendlog.append_and_verify(self.path, '{"a":1}\n')
        off2 = appendlog.append_and_verify(self.path, '{"a":2}\n')
        self.assertEqual(off1, 0)
        self.assertEqual(off2, len('{"a":1}\n'))

    def test_a_neighbours_append_does_not_invalidate_our_proof(self) -> None:
        """The whole point: someone else's line after ours is not our problem."""
        off = appendlog.append_and_verify(self.path, '{"mine":true}\n')
        with open(self.path, "a") as fh:          # a second writer, no lock
            fh.write('{"theirs":true}\n')
        # Our record is still exactly where we put it.
        with open(self.path, "rb") as fh:
            fh.seek(off)
            self.assertEqual(fh.read(len('{"mine":true}\n')), b'{"mine":true}\n')
        # And a further append of ours still verifies.
        appendlog.append_and_verify(self.path, '{"mine":2}\n')

    def test_a_real_tamper_is_detected_and_named_tampered(self) -> None:
        """A rewrite between our append and our read-back must be refused.

        This is the test that keeps the read-back honest.  The offset proof
        makes a NEIGHBOUR's append harmless (see the test above) -- so the
        thing left to prove is that it still fails when the log really is
        rewritten under us.  A verification that cannot fail is not evidence.

        The rewrite is injected by intercepting exactly the read-back open on
        exactly this path, which is the narrowest way to occupy the window
        between the fsync and the verify without a timing race.
        """
        import builtins
        real_open = builtins.open
        target = str(self.path)
        fired: list[bool] = []

        def clobber_on_readback(file, mode="r", *args, **kwargs):
            # Only the read-back of OUR file, and only once.
            if str(file) == target and "b" in mode and "r" in mode and not fired:
                fired.append(True)
                with real_open(target, "wb") as bad:
                    bad.write(b"a log that is not ours\n")
            return real_open(file, mode, *args, **kwargs)

        builtins.open = clobber_on_readback
        try:
            with self.assertRaises(AppendVerifyError) as ctx:
                appendlog.append_and_verify(self.path, '{"b":2}\n')
        finally:
            builtins.open = real_open

        self.assertTrue(fired, "the tamper was never injected — this asserted nothing")
        self.assertEqual(ctx.exception.cause, "tampered")
        self.assertIsInstance(ctx.exception, OSError,
                              "existing `except OSError` call sites must still catch it")

    def test_unavailable_and_tampered_do_not_share_one_code(self) -> None:
        """RFX-207: a refusal that cannot verify must not read as a tamper."""
        # A path that cannot be opened for append at all -> "unavailable".
        bad = pathlib.Path(self.tmp) / "not-a-dir" / "x.jsonl"
        (pathlib.Path(self.tmp) / "not-a-dir").write_text("i am a file")
        with self.assertRaises(AppendVerifyError) as ctx:
            appendlog.append_and_verify(bad, '{"a":1}\n')
        self.assertEqual(ctx.exception.cause, "unavailable")
        self.assertNotEqual(ctx.exception.cause, "tampered")


class TailFollow(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="rfx207-tail-")
        self.path = pathlib.Path(self.tmp) / "log.jsonl"

    def test_a_partial_trailing_record_is_left_for_the_next_read(self) -> None:
        self.path.write_bytes(b'{"a":1}\n{"a":2}\n{"a":3')  # last one mid-write
        lines, off = appendlog.read_new_records(self.path, 0)
        self.assertEqual(lines, ['{"a":1}', '{"a":2}'])
        self.assertEqual(off, len(b'{"a":1}\n{"a":2}\n'))
        # Once the writer finishes the record, the next call picks it up.
        with open(self.path, "ab") as fh:
            fh.write(b'}\n')
        lines2, _ = appendlog.read_new_records(self.path, off)
        self.assertEqual(lines2, ['{"a":3}'])

    def test_a_missing_file_is_not_an_error(self) -> None:
        lines, off = appendlog.read_new_records(pathlib.Path(self.tmp) / "nope", 0)
        self.assertEqual((lines, off), ([], 0))


# ---------------------------------------------------------------------------
# 3. The fail-open: one human approval, spendable once per warm replica
# ---------------------------------------------------------------------------

# Replica B: warm its index while the hold is still `approved`, signal, wait for
# replica A to consume, then try to consume the SAME hold.
_REPLICA_B = """
import json, os, sys, time, pathlib
from app import holds
hold_id = os.environ["RFX_HOLD"]
warm = pathlib.Path(os.environ["RFX_WARM"])
go = pathlib.Path(os.environ["RFX_GO"])

# 1. Warm this replica's in-memory index while the hold is still approved.
#    _boot_load() is LAZY, so a replica that has served no traffic reads the
#    file fresh and would refuse for the wrong reason -- this is the state a
#    replica in a load-balanced pool is actually in.
before = holds.get_hold(hold_id)
warm.write_text("warm")

# 2. Wait for replica A to consume the hold.
for _ in range(600):
    if go.exists():
        break
    time.sleep(0.05)

# 3. Try to spend the same single-use approval a second time.
after = holds.mark_consumed(hold_id)
print(json.dumps({
    "warmed_status": (before or {}).get("status"),
    "second_consume_returned_a_hold": after is not None,
}))
"""


class OneApprovalIsSpentOnce(unittest.TestCase):
    """The single-use hold guarantee must hold ACROSS replicas, not per replica.

    mark_consumed() documents a CAS that makes an approved-once irreversible
    action impossible to double-consume.  Measured on origin/main 759b83f, that
    was true per process and false per deployment: with replica B's index warmed
    to `approved`, BOTH replicas returned allow/approved_resubmission for the
    same hold and the volume carried TWO `consumed` events for ONE human
    approval.  Walked over real HTTP at the shipped 0.2.0 strict default
    (decided_by_verified=true, principal_source=credential), no timing race
    required.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="rfx207-single-use-")
        self.holds_path = os.path.join(self.tmp, "holds.jsonl")
        os.environ["REEFLEX_HOLDS_PATH"] = self.holds_path
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self.tmp, "decisions.jsonl")
        from app import holds
        self.holds = holds
        holds._reset(self.holds_path)

    def tearDown(self) -> None:
        self.holds._reset(None)

    def test_a_warm_second_replica_cannot_spend_the_same_approval(self) -> None:
        env = {
            "action": {"verb": "delete", "ability": "wp/delete-post"},
            "target": {"environment": "production", "ref": "post/single-use"},
            "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                     "externality": "internal"},
            "magnitude": {"count": 901},
            "agent": {"session_id": "single-use-walk"},
        }
        hold = self.holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        hold_id = hold["id"]
        # ONE human approval.
        self.holds.resolve_hold(hold_id, "approve", "human", "alice@example.com",
                                reason="the only approval in this test",
                                verified=True, principal_source="credential")
        self.assertEqual(self.holds.get_hold(hold_id)["status"], "approved")

        warm = os.path.join(self.tmp, "warm")
        go = os.path.join(self.tmp, "go")
        full = dict(os.environ)
        full.update({
            "REEFLEX_HOLDS_PATH": self.holds_path,
            "REEFLEX_AUDIT_LOG": os.path.join(self.tmp, "decisions.jsonl"),
            "RFX_HOLD": hold_id, "RFX_WARM": warm, "RFX_GO": go,
            "PYTHONPATH": _CORE_ROOT,
        })
        proc = subprocess.Popen([sys.executable, "-c", _REPLICA_B], env=full,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        try:
            for _ in range(600):                    # wait for B to warm
                if os.path.exists(warm):
                    break
                time.sleep(0.05)
            self.assertTrue(os.path.exists(warm), "replica B never warmed its index")

            # Replica A spends the approval.
            self.assertIsNotNone(self.holds.mark_consumed(hold_id),
                                 "replica A could not consume a hold it approved")
            pathlib.Path(go).write_text("go")

            out, err = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, f"replica B died: {err[-1500:]}")
            result = json.loads(out.strip().splitlines()[-1])
        finally:
            if proc.poll() is None:
                proc.kill()

        self.assertEqual(
            result["warmed_status"], "approved",
            "the test did not reproduce its own precondition: replica B's index "
            "must be warmed to `approved` BEFORE replica A consumes, or this "
            "asserts nothing (orderings (i)/(ii) in the round-040 walk read as "
            "SECURE for exactly this reason)")
        self.assertFalse(
            result["second_consume_returned_a_hold"],
            "ONE human approval was spent TWICE -- once per warm replica")

    def test_the_volume_carries_exactly_one_consumed_event(self) -> None:
        """The append-only stream must not claim one approval was spent twice."""
        env = {
            "action": {"verb": "delete", "ability": "wp/delete-post"},
            "target": {"environment": "production", "ref": "post/count"},
            "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                     "externality": "internal"},
            "magnitude": {"count": 901},
            "agent": {"session_id": "count-walk"},
        }
        hold = self.holds.create_hold(env, "reeflex.policy/irreversible_broad_prod")
        self.holds.resolve_hold(hold["id"], "approve", "human", "alice@example.com",
                                verified=True, principal_source="credential")
        self.holds.mark_consumed(hold["id"])
        self.holds.mark_consumed(hold["id"])        # same process, must refuse
        records = [json.loads(l) for l in
                   pathlib.Path(self.holds_path).read_text().splitlines() if l.strip()]
        consumed = [r for r in records if r.get("event_type") == "consumed"]
        self.assertEqual(len(consumed), 1,
                         f"{len(consumed)} consumed events for one approval")


# ---------------------------------------------------------------------------
# 4. A refusal must name its cause (RFX-207's closing requirement)
# ---------------------------------------------------------------------------

class ARefusalNamesItsCause(unittest.TestCase):
    """RFX-207: "if the append genuinely cannot be verified, the refusal must
    name that cause distinctly, not share a code with a tamper detection."

    One id covered three situations.  Two of them need different operator
    responses -- "the volume may be torn, investigate" versus "the disk is
    full" -- and the third (a neighbouring replica appending) was not a defect
    in the store at all and can no longer reach this branch.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="rfx207-cause-")
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self.tmp, "holds.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self.tmp, "decisions.jsonl")
        from app import decide as decide_mod
        from app import holds as holds_mod
        self.decide = decide_mod
        self.holds_mod = holds_mod
        self._original = holds_mod.create_hold

    def tearDown(self) -> None:
        self.holds_mod.create_hold = self._original
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        os.environ.pop("REEFLEX_AUDIT_LOG", None)

    def _env(self) -> dict:
        return {
            "agent": {"session_id": "cause-walk"},
            "action": {"verb": "delete", "ability": "wp/delete-post"},
            "target": {"environment": "production", "ref": "post/cause"},
            "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                     "externality": "internal"},
            "magnitude": {"count": 901},
        }

    def _decide_with_create_hold_raising(self, exc: BaseException):
        def _raise(*_a, **_kw):
            raise exc
        self.holds_mod.create_hold = _raise
        return self.decide.process(self._env())

    def test_an_integrity_failure_gets_its_own_rule_id(self) -> None:
        status, resp = self._decide_with_create_hold_raising(
            AppendVerifyError("torn", cause="tampered"))
        self.assertEqual(status, 500)
        self.assertEqual(resp.get("rule"), "reeflex.core/hold_store_integrity")

    def test_an_availability_failure_gets_a_different_rule_id(self) -> None:
        status, resp = self._decide_with_create_hold_raising(
            AppendVerifyError("disk full", cause="unavailable"))
        self.assertEqual(status, 500)
        self.assertEqual(resp.get("rule"), "reeflex.core/hold_store_unavailable")

    def test_the_two_causes_do_not_share_a_rule_id(self) -> None:
        _, torn = self._decide_with_create_hold_raising(
            AppendVerifyError("torn", cause="tampered"))
        _, full = self._decide_with_create_hold_raising(
            AppendVerifyError("disk full", cause="unavailable"))
        self.assertNotEqual(torn.get("rule"), full.get("rule"))

    def test_an_unrelated_failure_keeps_the_original_rule_id(self) -> None:
        """Backward compatibility: anything without a cause is unchanged."""
        status, resp = self._decide_with_create_hold_raising(
            RuntimeError("something else entirely"))
        self.assertEqual(status, 500)
        self.assertEqual(resp.get("rule"), "reeflex.core/hold_creation_failed")

    def test_every_refusal_still_fails_closed(self) -> None:
        """Whatever the cause, the verdict must never become an allow."""
        for exc in (AppendVerifyError("t", cause="tampered"),
                    AppendVerifyError("u", cause="unavailable"),
                    RuntimeError("x")):
            status, resp = self._decide_with_create_hold_raising(exc)
            self.assertEqual(status, 500, f"{exc!r} did not fail closed")
            self.assertEqual(resp.get("decision"), "deny", f"{exc!r} was not a deny")


if __name__ == "__main__":
    unittest.main()
