"""
test_audit_provenance_rfx215.py — the audit record says which classification
inputs core GUESSED (RFX-215).

THE DEFECT THESE TESTS PIN. envelope.py F8 computes `provenance.undeclared`
from the raw caller input, assigns it unconditionally, and OPA reads it for R0
(RFX-132). audit.py never wrote it. So an auditor reading core's own audit log
could not tell a decision that rested on a value the ADAPTER DECLARED from one
that rested on a value CORE GUESSED — which is the exact distinction RFX-132's
whole argument for R0 rests on.

Measured on origin/main 759b83f before the fix (dev-1--045 evidence,
BEFORE-759b83f.txt): nine envelopes, five of them carrying a classification
input core had to guess, produced nine audit records with NO provenance key at
all — 9 / 9.

WHICH ASSERTIONS BITE, AND WHICH ARE INVARIANTS. 044's lesson was that a test
file where both halves pass on the broken tree measures nothing, so this is
stated rather than left to be discovered:

  BITES on 759b83f (fails without the fix)
    TestGuessedInputsReachTheRecord.*        — the record has no provenance key
    TestEverythingDeclared.test_key_present_and_empty
    TestNotASecondInventory.*                — the field list is not copied here
    TestCallerCannotAssertProvenance.*       — the key does not exist to check
    TestKeySetIsAdditive.test_provenance_is_the_only_new_key

  INVARIANT (passes on both trees, and that is the point)
    TestEverythingDeclared.test_no_existing_key_changed
    TestPredatesF8.*                         — a record from a path with no
                                               provenance block must look
                                               exactly as it did before
    TestKeySetIsAdditive.test_no_pre_existing_key_dropped

Run:
  cd reeflex-core
  python3.12 -m unittest tests.test_audit_provenance_rfx215 -v
  # or, the way the release gate runs it:
  python3.12 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.audit import record  # noqa: E402
from app.decide import process  # noqa: E402
from app.envelope import _PROVENANCE_FIELDS  # noqa: E402

# The audit-line keys a decision record carried on origin/main 759b83f, read
# off a real record (dev-1--045, BEFORE-759b83f.txt). Kept as a literal on
# purpose: this is the "nothing was renamed or dropped" baseline, and a
# baseline computed from the code under test would agree with any change.
_KEYS_BEFORE_RFX215 = {
    "action", "agent_id", "cumulative_injected", "decision", "decision_id",
    "envelope_hash", "magnitude_count", "reason", "rule", "session_id", "ts",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    return f"rfx215_sess_{uuid.uuid4().hex[:12]}"


def _base_envelope(**overrides) -> dict:
    """A fully-declared, canonical envelope. Every override in these tests is
    a deliberate step AWAY from full declaration."""
    env: dict = {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:rfx215-test",
            "on_behalf_of": "user:synthetic",
            "session_id": _fresh_session(),
        },
        "action": {
            "namespace": "wordpress",
            "verb": "update",
            "ability": "core/update-option",
        },
        "target": {
            "kind": "option",
            "ref": "option:blogname",
            "environment": "production",
        },
        "params": {},
        "magnitude": {"count": 1},
        "axes": {
            "reversibility": "recoverable",
            "blast_radius": "single",
            "externality": "internal",
        },
        "approval": {"present": False, "hold_id": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-08-23T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }
    for key, value in overrides.items():
        if value is _ABSENT:
            env.pop(key, None)
        else:
            env[key] = value
    return env


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ABSENT>"


_ABSENT = _Absent()


def _find_opa_bin() -> str | None:
    import subprocess

    candidates: list[str] = []
    env_bin = os.environ.get("REEFLEX_OPA_BIN", "")
    if env_bin:
        candidates.append(env_bin)
    candidates.append("opa")
    for name in ("opa.exe", "opa"):
        local = _repo_root / name
        if local.exists():
            candidates.append(str(local))
    for candidate in candidates:
        try:
            r = subprocess.run([candidate, "version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                os.environ["REEFLEX_OPA_BIN"] = candidate
                return candidate
        except Exception:  # noqa: BLE001
            continue
    return None


def _opa_available() -> bool:
    return _find_opa_bin() is not None


def _read_records() -> list[dict]:
    path = pathlib.Path(os.environ["REEFLEX_AUDIT_LOG"])
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def _decision_record_for(session_id: str) -> dict:
    matching = [
        r for r in _read_records()
        if r.get("session_id") == session_id and "event" not in r
    ]
    assert matching, f"no decision audit record for session_id={session_id}"
    return matching[-1]


class _IsolatedAudit(unittest.TestCase):
    """Every test gets its own audit log AND its own holds file.

    The holds path matters even for tests that expect an allow: one R0 case
    here creates a hold, and core's hold store is a single shared file, so a
    test that let a hold escape into the repo's default store would leak state
    into every other suite on the box.
    """

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="reeflex_rfx215_")
        base = pathlib.Path(self._tmpdir.name)
        self._prev = {
            "REEFLEX_AUDIT_LOG": os.environ.get("REEFLEX_AUDIT_LOG"),
            "REEFLEX_HOLDS_PATH": os.environ.get("REEFLEX_HOLDS_PATH"),
        }
        os.environ["REEFLEX_AUDIT_LOG"] = str(base / "decisions.jsonl")
        os.environ["REEFLEX_HOLDS_PATH"] = str(base / "holds.jsonl")

    def tearDown(self) -> None:
        for key, value in self._prev.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmpdir.cleanup()


# ===========================================================================
# The record can name a guess
# ===========================================================================

class TestGuessedInputsReachTheRecord(_IsolatedAudit):
    """BITES on 759b83f: every one of these produced a record with no
    provenance key, so the fact that the verdict rested on a guess was
    unrecoverable from the log."""

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_unrecognised_externality_is_named(self) -> None:
        """A CORRECTION TO THE TICKET, found by writing this test. RFX-215's
        worked example is `externality: "Outbound"` (capital O) as "a value
        core did not recognise and coerced". On main it IS recognised:
        `_axis_is_declared` compares through `_normalize_token`, which
        casefolds, so "Outbound" is a DECLARED outbound and provenance for it
        is correctly empty. The defect the ticket describes is real — the
        example that shows it has to be a value outside the enum, and
        "external" is the spelling an adapter author actually reaches for."""
        env = _base_envelope()
        env["axes"]["externality"] = "external"  # not in the SPEC §2 enum
        session_id = env["agent"]["session_id"]

        status, resp = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)
        print(f"\n[rfx215/externality] verdict={resp.get('decision')} "
              f"rule={resp.get('rule')}\n  audit={json.dumps(rec)}")

        self.assertIn("provenance", rec,
                      "the audit record does not say core guessed an axis")
        self.assertIn("axes.externality", rec["provenance"]["undeclared"])

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_environment_outside_the_enum_is_named(self) -> None:
        env = _base_envelope()
        env["target"]["environment"] = "qa-eu"
        session_id = env["agent"]["session_id"]

        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertIn("target.environment", rec.get("provenance", {}).get("undeclared", []))

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_unaliased_verb_is_named(self) -> None:
        env = _base_envelope()
        env["action"]["verb"] = "frobnicate"
        session_id = env["agent"]["session_id"]

        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertIn("action.verb", rec.get("provenance", {}).get("undeclared", []))

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_r0_hold_carries_the_guessed_inputs_in_a_PARSEABLE_field(self) -> None:
        """The sharpest row. With no axes at all the verdict IS the guess: R0
        fires and asks a human. On 759b83f the only place the guessed field
        names appeared was inside the English `reason` string — prose, in a
        field whose wording is not a contract. The same fact now has a
        structured home, and the prose is left alone."""
        env = _base_envelope(axes=_ABSENT)
        session_id = env["agent"]["session_id"]

        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "require_approval")
        self.assertTrue(str(resp.get("rule", "")).endswith("unclassified_action"),
                        f"expected R0, got rule={resp.get('rule')!r}")

        rec = _decision_record_for(session_id)
        print(f"\n[rfx215/R0] rule={resp.get('rule')}\n  audit={json.dumps(rec)}")

        undeclared = rec.get("provenance", {}).get("undeclared", [])
        self.assertIn("axes.reversibility", undeclared)
        self.assertIn("axes.blast_radius", undeclared)
        self.assertIn("axes.externality", undeclared)
        # Sorted, so two identical envelopes produce two identical lines.
        self.assertEqual(undeclared, sorted(undeclared))


# ===========================================================================
# The record can also say "nothing was guessed"
# ===========================================================================

class TestEverythingDeclared(_IsolatedAudit):

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_key_present_and_empty(self) -> None:
        """BITES on 759b83f. An EMPTY list is the affirmative statement
        "every classification input was declared". Omitting the key here
        instead would make "no provenance key" mean both that and "an older
        core wrote this line", which an auditor cannot disambiguate."""
        env = _base_envelope()
        session_id = env["agent"]["session_id"]

        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertIn("provenance", rec)
        self.assertEqual(rec["provenance"], {"undeclared": []})

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_no_existing_key_changed(self) -> None:
        """INVARIANT (passes on both trees). Additive means additive: the
        decision/rule/reason a consumer already reads are untouched."""
        env = _base_envelope()
        session_id = env["agent"]["session_id"]

        status, resp = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertEqual(rec["decision"], resp["decision"])
        self.assertEqual(rec["rule"], resp["rule"])
        self.assertEqual(rec["action"]["environment"], "production")
        self.assertEqual(rec["magnitude_count"], 1)


# ===========================================================================
# A caller does not get to describe core's own confidence
# ===========================================================================

class TestCallerCannotAssertProvenance(_IsolatedAudit):

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_caller_supplied_provenance_is_discarded(self) -> None:
        """BITES on 759b83f (the key does not exist to be checked).

        envelope.py F8 overwrites `provenance` unconditionally. This pins that
        the OVERWRITE, not the caller's claim, is what reaches the record —
        otherwise a caller could stamp its own perfectly-declared envelope as
        "you guessed at this" and buy R0's softer verdict, and the audit line
        would corroborate it."""
        env = _base_envelope()
        env["provenance"] = {"undeclared": ["axes.reversibility",
                                            "axes.blast_radius",
                                            "target.environment"]}
        session_id = env["agent"]["session_id"]

        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertEqual(rec.get("provenance"), {"undeclared": []},
                         "the caller's claim about core's confidence reached the record")


# ===========================================================================
# Not a second inventory of a set that grows elsewhere
# ===========================================================================

class TestNotASecondInventory(_IsolatedAudit):
    """BITES on 759b83f, and guards the RFX-216 / RFX-217 defect shape: a
    hardcoded inventory of something another file grows.

    audit.py must carry WHATEVER envelope.py put in the block, never a copy of
    `_PROVENANCE_FIELDS`. The consequence is stated in audit.py and pinned
    here: the moment envelope.py starts recording provenance for another field
    — `magnitude.count` on PR #116 is the pending one — it appears on the audit
    line with no further change to audit.py."""

    def test_a_field_envelope_py_does_not_yet_record_still_lands(self) -> None:
        # A field name that is deliberately NOT in _PROVENANCE_FIELDS today.
        future = "magnitude.count"
        self.assertNotIn(
            future, _PROVENANCE_FIELDS,
            "magnitude.count is now a provenance field — this test's premise "
            "has landed (PR #116); point it at the next un-recorded field, do "
            "not delete the assertion",
        )

        rec = record(
            session_id="rfx215-inventory",
            envelope={
                "agent": {"id": "agent:rfx215"},
                "action": {"namespace": "test", "verb": "update", "ability": "t/u"},
                "target": {"environment": "production"},
                "magnitude": {"count": 1},
                "provenance": {"undeclared": [future]},
            },
            cumulative={},
            decision_result={"decision": "allow", "rule": "r", "reason": ""},
            decision_id="d-inventory",
        )
        self.assertEqual(rec["provenance"], {"undeclared": [future]})
        self.assertEqual(_read_records()[-1]["provenance"], {"undeclared": [future]})

    def test_every_field_envelope_py_records_today_can_reach_the_record(self) -> None:
        """Non-vacuity floor for the pin above: the carry is exercised over the
        WHOLE current field set, so a future change that silently narrows it to
        a subset fails here."""
        rec = record(
            session_id="rfx215-allfields",
            envelope={
                "agent": {"id": "agent:rfx215"},
                "action": {"namespace": "test", "verb": "update", "ability": "t/u"},
                "target": {"environment": "production"},
                "magnitude": {"count": 1},
                "provenance": {"undeclared": sorted(_PROVENANCE_FIELDS)},
            },
            cumulative={},
            decision_result={"decision": "allow", "rule": "r", "reason": ""},
            decision_id="d-allfields",
        )
        self.assertEqual(rec["provenance"]["undeclared"], sorted(_PROVENANCE_FIELDS))
        self.assertGreater(len(_PROVENANCE_FIELDS), 0)


# ===========================================================================
# A record from a path that predates F8 must look exactly as it did
# ===========================================================================

class TestPredatesF8(_IsolatedAudit):
    """INVARIANT (passes on both trees). Not a delta — a guard on the
    defensive read, so that adding this key cannot make an older/other caller
    of record() start writing a key it has no value for."""

    def test_no_provenance_block_means_no_provenance_key(self) -> None:
        rec = record(
            session_id="rfx215-legacy",
            envelope={
                "agent": {"id": "agent:rfx215"},
                "action": {"namespace": "test", "verb": "read", "ability": "t/r"},
                "target": {"environment": "staging"},
                "magnitude": {"count": 1},
            },
            cumulative={},
            decision_result={"decision": "allow", "rule": "r", "reason": ""},
            decision_id="d-legacy",
        )
        self.assertNotIn("provenance", rec)
        self.assertNotIn("provenance", _read_records()[-1])

    def test_malformed_provenance_block_is_not_written(self) -> None:
        for bad in ({"undeclared": "axes.externality"}, {"undeclared": None},
                    "axes.externality", []):
            with self.subTest(bad=bad):
                rec = record(
                    session_id="rfx215-malformed",
                    envelope={
                        "agent": {"id": "agent:rfx215"},
                        "action": {"namespace": "test", "verb": "read",
                                   "ability": "t/r"},
                        "target": {"environment": "staging"},
                        "magnitude": {"count": 1},
                        "provenance": bad,
                    },
                    cumulative={},
                    decision_result={"decision": "allow", "rule": "r",
                                     "reason": ""},
                    decision_id="d-malformed",
                )
                self.assertNotIn("provenance", rec)


# ===========================================================================
# Additive means additive
# ===========================================================================

class TestKeySetIsAdditive(_IsolatedAudit):

    #: Every key added to the decision record SINCE the baseline this file
    #: pinned, each with the PR that added it. The point of the assertion below
    #: is that this list is SHORT and EXPLICIT — a new key must be added here
    #: deliberately, by whoever adds it, and cannot arrive unnoticed.
    #:
    #: RFX-197 (#110) is the first entry after RFX-215's own. It stamps
    #: `ledger_epoch` on the decision record, which is what makes a cumulative
    #: counter that fell inside its own window diagnosable rather than merely
    #: visible. Added here on the cluster-A merge (dev-3 round 039), in #110's
    #: own PR rather than as a follow-up, because #110 is the change that makes
    #: the old assertion false. Neither PR's conflict graph could see this:
    #: #110 edits audit.py and this file asserts over audit.py's OUTPUT, so
    #: `git merge-tree` reports no overlap at all.
    KEYS_ALLOWED_SINCE = {
        "provenance",     # RFX-215 (#119) — this file's own subject
        "ledger_epoch",   # RFX-197 (#110)
    }

    #: Of those, the ones that must be on EVERY decision record. `provenance` is
    #: unconditional by design (an empty `undeclared` list is the affirmative
    #: statement "everything was declared"). `ledger_epoch` is NOT: audit.py
    #: omits the key when the value is empty, exactly like every other additive
    #: field, so a tree with no ledger state yet writes records without it.
    #: MEASURED THE HARD WAY: asserting equality against the full set above
    #: passed locally, where a previous run had left ledger state behind, and
    #: FAILED in CI on a fresh checkout. An assertion whose answer depends on
    #: what an earlier run left on disk is not an assertion.
    KEYS_ALWAYS_PRESENT = {"provenance"}

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_provenance_is_the_only_new_key(self) -> None:
        """BITES on 759b83f in the other direction: there, `provenance` is
        absent from the record and the first assertion below fails.

        ADDITIVE, STILL ASSERTED EXACTLY, IN TWO HALVES. This was NOT loosened
        into "any new key is fine": a key nobody declared in
        KEYS_ALLOWED_SINCE still fails the second assertion, which is the
        property RFX-215 wanted. Splitting it is what lets an OPTIONAL additive
        key be declared without claiming it is always written.
        """
        env = _base_envelope()
        session_id = env["agent"]["session_id"]
        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        new_keys = set(rec.keys()) - _KEYS_BEFORE_RFX215
        self.assertTrue(
            self.KEYS_ALWAYS_PRESENT <= new_keys,
            "a key that must be on every decision record is missing: %s"
            % (self.KEYS_ALWAYS_PRESENT - new_keys),
        )
        self.assertEqual(
            new_keys - self.KEYS_ALLOWED_SINCE, set(),
            "the decision record's key set moved without anyone declaring it "
            "in KEYS_ALLOWED_SINCE — add it there, with the ticket, or take it "
            "back out",
        )

    @unittest.skipUnless(_opa_available(), "OPA binary not available")
    def test_no_pre_existing_key_dropped(self) -> None:
        """INVARIANT. A key an existing consumer reads must not vanish."""
        env = _base_envelope()
        session_id = env["agent"]["session_id"]
        status, _ = process(env)
        self.assertEqual(status, 200)
        rec = _decision_record_for(session_id)

        self.assertEqual(_KEYS_BEFORE_RFX215 - set(rec.keys()), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
