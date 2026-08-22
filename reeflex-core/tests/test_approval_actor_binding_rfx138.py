"""
test_approval_actor_binding_rfx138.py — an approval is granted to a PARTY.

THE DEFECT
==========
Checks 1-7 of the hold-resubmission chain answer "is this the action a human
approved".  Nothing answered "is this the requester they approved it FOR".
`agent` is outside canonical_hash()'s {action, axes, magnitude, target}
projection and outside check 7's params comparison, so:

  * agent ALPHA raised an irreversible production delete, a human approved it,
    and agent BETA resubmitted the identical action with ALPHA's hold_id and
    received `allow` -- then ALPHA, the agent the human actually approved, was
    refused `reeflex_hold_consumed`, because BETA's resubmission had spent the
    single-use hold;
  * quieter and worse: the SAME bot, the same session, the same action, with
    only `agent.on_behalf_of` changed from alice to bob.  Core's audit line for
    that allow is byte-identical to a legitimate resubmission.

Both were confirmed over HTTP against the container built from 44c6f85 -- the
commit AFTER check 7 landed -- by scripts/attack-probe-rfx97-release-gate.py
A6.  This file is the same six requests in process, so the regression is
caught by `python -m unittest` and not only by someone remembering to build an
image and run the probe.

WHAT IS ASSERTED, AND WHY THE OVER-BLOCK HALF IS NOT OPTIONAL
=============================================================
  TestSubstitutionIsRefused     the four substitutions above are denied with
                                reeflex_hold_actor_mismatch.
  TestTheApprovalSurvives       the refusal does NOT consume the hold, so the
                                agent the human approved can still act.  This
                                is half the finding: the substitution did not
                                merely allow the wrong agent, it locked out
                                the right one.
  TestLegitimateResubmission    an agent that restarts (new session_id) and an
                                identity that differs only by case or an
                                invisible character MUST still be allowed.  A
                                wrong DENY here is a wrong deny on the one
                                path where a human explicitly said yes, and it
                                would be a worse product than the bug.
  TestActorKeyShape             unit-level: a session-only key can never
                                compare equal to a named-agent key, so the
                                fallback cannot be used to impersonate.
  TestRefusalIsEvidenced        the denial reaches the audit log naming the
                                hold it was decided against -- the
                                substitution used to leave no trace at all.

Run:
  cd reeflex-core
  python -m unittest tests.test_approval_actor_binding_rfx138 -v
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

import app.holds as holds_mod
from app.decide import process
from app.principal import approval_actor_key

_RULE = "reeflex.policy/irreversible_broad_prod"
#: A third party, so check 6 (actor_is_approver) can never be what refuses a
#: resubmission below -- otherwise a pass here would be a pass for the wrong
#: reason, the trap the RFX-97 harness documents.
_APPROVER = ("human", "rfx138-manager@example.invalid")


def _envelope(*, session_id, agent_id="agent:rfx138-alpha", on_behalf_of=None,
              include_agent_id=True, approval=None) -> dict:
    """The SAME irreversible production delete every time.

    Only the agent block varies across a test, so any verdict difference is
    attributable to identity alone: checks 5 and 7 see identical inputs.
    """
    agent: dict = {"session_id": session_id}
    if include_agent_id:
        agent["id"] = agent_id
    if on_behalf_of is not None:
        agent["on_behalf_of"] = on_behalf_of
    return {
        "reeflex_version": "0.1",
        "agent": agent,
        "action": {"namespace": "test", "verb": "delete",
                   "ability": "test/delete"},
        "target": {"kind": "entity", "ref": "posts/*",
                   "environment": "production"},
        "params": {},
        "magnitude": {"count": 901},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                 "externality": "internal"},
        "approval": approval if approval is not None else {"present": False},
        "trajectory_ref": None,
        "context": {},
        "meta": {"timestamp": "2026-08-22T00:00:00Z", "nonce": uuid.uuid4().hex,
                 "signature": "ed25519:skeleton_placeholder"},
    }


def _sid(tag: str) -> str:
    return "rfx138_%s_%s" % (tag, uuid.uuid4().hex[:8])


class _HoldStoreCase(unittest.TestCase):
    """A fresh hold store + audit log per test."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="rfx138_")
        holds_mod._reset(os.path.join(self._dir.name, "holds.jsonl"))
        self._prev_audit = os.environ.get("REEFLEX_AUDIT_LOG")
        self._audit_path = os.path.join(self._dir.name, "audit.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = self._audit_path

    def tearDown(self) -> None:
        if self._prev_audit is None:
            os.environ.pop("REEFLEX_AUDIT_LOG", None)
        else:
            os.environ["REEFLEX_AUDIT_LOG"] = self._prev_audit
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        self._dir.cleanup()

    # -- helpers -----------------------------------------------------------

    def approved_hold(self, envelope: dict) -> str:
        """Create the hold this envelope would raise and have a human approve.

        create_hold() is the same call decide.process() makes on
        require_approval; going through it directly keeps the test independent
        of OPA (the resubmission branch returns before OPA is consulted).
        """
        rec = holds_mod.create_hold(envelope, _RULE)
        resolved = holds_mod.resolve_hold(rec["id"], "approve", *_APPROVER, None)
        self.assertEqual("approved", resolved["status"])
        return rec["id"]

    def resubmit(self, hold_id: str, **envelope_kw) -> dict:
        env = _envelope(approval={"present": True, "hold_id": hold_id},
                        **envelope_kw)
        status, resp = process(env)
        self.assertEqual(200, status, resp)
        return resp

    def audit_lines(self) -> list:
        p = pathlib.Path(self._audit_path)
        if not p.exists():
            return []
        return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip()]


# ===========================================================================
# The substitutions
# ===========================================================================

class TestSubstitutionIsRefused(_HoldStoreCase):

    def test_control_the_approved_agent_may_spend_its_approval(self) -> None:
        """Read every deny below against this: the chain does work."""
        sid = _sid("ctl")
        hold_id = self.approved_hold(_envelope(session_id=sid))
        resp = self.resubmit(hold_id, session_id=sid)
        print("\n[RFX-138/control] approved agent -> %s (%s)"
              % (resp["decision"], resp["reason"]))
        self.assertEqual("allow", resp["decision"],
                         "the agent the human approved must be able to act")

    def test_a_different_agent_cannot_spend_it(self) -> None:
        """Variant A, measured live: ALPHA approved, BETA executes."""
        sid = _sid("varA")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-alpha"))
        resp = self.resubmit(hold_id, session_id=_sid("varA-beta"),
                             agent_id="agent:rfx138-beta")
        print("[RFX-138/agent-substitution] -> %s (%s)"
              % (resp["decision"], resp["reason"]))
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])

    def test_the_same_bot_cannot_switch_the_person_it_acts_for(self) -> None:
        """Variant B: one bot, one session, on_behalf_of alice -> bob."""
        sid = _sid("varB")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-shared-bot",
                      on_behalf_of="alice@example.invalid"))
        resp = self.resubmit(hold_id, session_id=sid,
                             agent_id="agent:rfx138-shared-bot",
                             on_behalf_of="bob@example.invalid")
        print("[RFX-138/obo-substitution] -> %s (%s)"
              % (resp["decision"], resp["reason"]))
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])

    def test_an_on_behalf_of_cannot_be_added_after_approval(self) -> None:
        """The human approved a bot acting for nobody in particular."""
        sid = _sid("added")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-shared-bot"))
        resp = self.resubmit(hold_id, session_id=sid,
                             agent_id="agent:rfx138-shared-bot",
                             on_behalf_of="bob@example.invalid")
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])

    def test_an_on_behalf_of_cannot_be_dropped_after_approval(self) -> None:
        """...and the reverse: what was approved FOR alice stays for alice."""
        sid = _sid("dropped")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-shared-bot",
                      on_behalf_of="alice@example.invalid"))
        resp = self.resubmit(hold_id, session_id=sid,
                             agent_id="agent:rfx138-shared-bot")
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])

    def test_the_guard_is_not_vacuous_for_a_spec_minimal_envelope(self) -> None:
        """agent.id is OPTIONAL in SPEC §2; session_id is the only required
        agent field.  An envelope that sends only session_id must still bind
        SOMETHING, or the guard is off for exactly the adapters least likely
        to be watched."""
        sid = _sid("minimal")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, include_agent_id=False))
        resp = self.resubmit(hold_id, session_id=_sid("minimal-other"),
                             include_agent_id=False)
        print("[RFX-138/session-only-substitution] -> %s (%s)"
              % (resp["decision"], resp["reason"]))
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])

    def test_a_named_agent_cannot_impersonate_a_session_only_holder(self) -> None:
        """The fallback must not be a second way in: a hold raised with no
        agent.id is not spendable by naming an agent.id equal to the session."""
        sid = _sid("shape")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, include_agent_id=False))
        resp = self.resubmit(hold_id, session_id=sid, agent_id=sid)
        self.assertEqual("deny", resp["decision"])
        self.assertEqual("reeflex_hold_actor_mismatch", resp["reason"])


# ===========================================================================
# The other half: the approval must SURVIVE the refusal
# ===========================================================================

class TestTheApprovalSurvives(_HoldStoreCase):

    def test_a_refused_substitution_does_not_consume_the_hold(self) -> None:
        """On 44c6f85 the substitution consumed the hold and the approved
        agent got `reeflex_hold_consumed` -- the human's decision was not just
        misapplied, it was destroyed.  The refusal must return before
        mark_consumed()."""
        sid = _sid("survive")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-alpha"))

        stolen = self.resubmit(hold_id, session_id=_sid("survive-beta"),
                               agent_id="agent:rfx138-beta")
        self.assertEqual("deny", stolen["decision"])

        after = holds_mod.get_hold(hold_id)
        self.assertEqual("approved", after["status"],
                         "a refused substitution must not consume the hold")
        self.assertIsNone(after.get("consumed_ts"))

        rightful = self.resubmit(hold_id, session_id=sid,
                                 agent_id="agent:rfx138-alpha")
        print("[RFX-138/survives] approved agent afterwards -> %s (%s)"
              % (rightful["decision"], rightful["reason"]))
        self.assertEqual("allow", rightful["decision"],
                         "the agent the human approved must still be able to "
                         "act after someone else tried to spend its approval")

    def test_single_use_still_holds_for_the_rightful_agent(self) -> None:
        """Check 8 must not weaken check 4."""
        sid = _sid("singleuse")
        hold_id = self.approved_hold(_envelope(session_id=sid))
        self.assertEqual("allow", self.resubmit(hold_id, session_id=sid)["decision"])
        second = self.resubmit(hold_id, session_id=sid)
        self.assertEqual("deny", second["decision"])
        self.assertEqual("reeflex_hold_consumed", second["reason"])


# ===========================================================================
# Over-blocking is its own failure
# ===========================================================================

class TestLegitimateResubmission(_HoldStoreCase):

    def test_an_agent_that_restarts_keeps_its_approval(self) -> None:
        """A hold lives 4h by default.  An agent that restarts gets a new
        session_id; binding the session would deny an action a human already
        approved."""
        hold_id = self.approved_hold(
            _envelope(session_id=_sid("restart-1"), agent_id="agent:rfx138-alpha"))
        resp = self.resubmit(hold_id, session_id=_sid("restart-2"),
                             agent_id="agent:rfx138-alpha")
        print("[RFX-138/over-block] same agent, new session -> %s (%s)"
              % (resp["decision"], resp["reason"]))
        self.assertEqual("allow", resp["decision"],
                         "a restart must not cost an agent its approval")

    def test_identity_is_compared_folded_not_byte_for_byte(self) -> None:
        """The four-eyes guard folds identities so a variant spelling cannot
        sneak PAST it; the same fold here stops a variant spelling being
        wrongly refused.  One normalization, used in both directions."""
        for label, raised, resubmitted in (
            ("case", "agent:RFX138-Mixed", "agent:rfx138-mixed"),
            ("padding", "agent:rfx138-pad", "  agent:rfx138-pad  "),
            ("zero-width", "agent:rfx138zw", "agent:rfx138​zw"),
        ):
            with self.subTest(label):
                sid = _sid("fold-%s" % label)
                hold_id = self.approved_hold(
                    _envelope(session_id=sid, agent_id=raised))
                resp = self.resubmit(hold_id, session_id=sid,
                                     agent_id=resubmitted)
                self.assertEqual("allow", resp["decision"],
                                 "%s: %r must still be %r" % (label, resubmitted, raised))


# ===========================================================================
# The key itself
# ===========================================================================

class TestActorKeyShape(unittest.TestCase):

    def test_a_session_key_never_equals_a_named_key(self) -> None:
        named = approval_actor_key({"agent": {"id": "alpha", "session_id": "s1"}})
        session_only = approval_actor_key({"agent": {"session_id": "alpha"}})
        self.assertNotEqual(named, session_only)

    def test_session_is_ignored_when_the_agent_is_named(self) -> None:
        a = approval_actor_key({"agent": {"id": "alpha", "session_id": "s1"}})
        b = approval_actor_key({"agent": {"id": "alpha", "session_id": "s2"}})
        self.assertEqual(a, b)

    def test_on_behalf_of_is_part_of_the_key(self) -> None:
        a = approval_actor_key({"agent": {"id": "bot", "on_behalf_of": "alice"}})
        b = approval_actor_key({"agent": {"id": "bot", "on_behalf_of": "bob"}})
        c = approval_actor_key({"agent": {"id": "bot"}})
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

    def test_an_invisible_only_identity_is_still_compared(self) -> None:
        """normalize_identity() strips format characters, so an id made only
        of them folds to "".  Two DIFFERENT such ids must not compare equal
        just because the fold emptied them both."""
        a = approval_actor_key({"agent": {"id": "​", "session_id": "s"}})
        b = approval_actor_key({"agent": {"id": "‌", "session_id": "s"}})
        self.assertNotEqual(a, b)

    def test_a_missing_or_malformed_agent_block_yields_a_stable_key(self) -> None:
        for envelope in ({}, {"agent": None}, {"agent": "not-a-dict"},
                         {"agent": {}}):
            with self.subTest(repr(envelope)):
                self.assertEqual(("", "", ""), approval_actor_key(envelope))


# ===========================================================================
# The refusal has to be findable afterwards
# ===========================================================================

class TestRefusalIsEvidenced(_HoldStoreCase):

    def test_the_denial_is_audited_against_the_hold(self) -> None:
        sid = _sid("audit")
        hold_id = self.approved_hold(
            _envelope(session_id=sid, agent_id="agent:rfx138-alpha"))
        self.resubmit(hold_id, session_id=_sid("audit-beta"),
                      agent_id="agent:rfx138-beta")

        denials = [ln for ln in self.audit_lines()
                   if ln.get("reason") == "reeflex_hold_actor_mismatch"]
        print("[RFX-138/audit] %d denial line(s): %s"
              % (len(denials), json.dumps(denials[:1])[:400]))
        self.assertEqual(1, len(denials),
                         "the refused substitution must be in the audit log")
        self.assertEqual(hold_id, denials[0].get("hold_id"),
                         "the denial must name the hold it was decided against")
        self.assertEqual("deny", denials[0].get("decision"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
