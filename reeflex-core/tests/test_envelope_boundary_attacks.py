"""
test_envelope_boundary_attacks.py — ALL FIVE envelope-boundary attacks, in one
re-runnable file (RFX-97).

=============================================================================
WHY ONE FILE
=============================================================================
Five ways to beat the deterministic decision path were found separately and
fixed in three PRs.  RFX-97's release decision needs a single answer to a
single question — "do all five fail on THIS artifact?" — so all five live
here, drive the REAL decide.process() path end to end (envelope -> validate ->
ledger -> OPA -> decision, no mocking of OPA), and can be pointed at any build.

    A1  RFX-86   target.environment compared exactly: "Prod" evaded R2/R3
                 and fell through to default_allow.            fixed PR #89
    A2  RFX-85   action.verb compared exactly: "Delete"/"remove"/"destroy"/
                 "purge" fragmented the deletions budget.      fixed PR #90
    A3  RFX-84   the approving human on /v1/holds/{id}/resolve was
                 self-asserted and nothing verified it.        fixed PR #90
    A4  RFX-127  approval:{present:true} with NO hold_id switched off EVERY
                 cumulative budget.                            fixed here
    A5  RFX-133  the money budget was evaded by omitting params.currency,
                 and the sum it compared mixed currencies.     fixed here

They are ONE defect in five places: A CALLER-SUPPLIED VALUE THAT THE POLICY
READS WITHOUT CANONICALISING OR VERIFYING IT.  The structural fix is the
enumeration in app/field_treatments.py and its test; this file is the
behavioural proof that the five known instances are shut, and the artifact
RFX-97 can re-run against any future build.

Live evidence for A4/A5 (raw request and raw verdict, before and after) is in
scripts/attack-probe-envelope-boundary.py.  A4 was reproduced on LIVE api-dev
with the published eval token; A5 was NOT reproducible there because api-dev
runs a pre-RFX-11 build with no money dimension at all, so it was reproduced
against a pinned local build instead — the probe fingerprints the target and
says which it is rather than assuming.

Run:
  cd reeflex-core
  python -m unittest tests.test_envelope_boundary_attacks -v
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod
from app.decide import process


def _sid(tag: str) -> str:
    return "atk_%s_%s" % (tag, uuid.uuid4().hex[:10])


def _env(
    *,
    session_id: str,
    verb: str = "update",
    ability: str = "eval/synthetic",
    environment: str = "dev",
    reversibility: str = "reversible",
    blast_radius: str = "single",
    externality: str = "internal",
    count: int = 1,
    params: dict | None = None,
    approval: dict | None = None,
    agent_id: str | None = "agent:atk",
) -> dict:
    agent: dict = {"session_id": session_id}
    if agent_id is not None:
        agent["id"] = agent_id
    return {
        "reeflex_version": "0.1",
        "agent": agent,
        "action": {"namespace": "eval", "verb": verb, "ability": ability},
        "target": {"kind": "synthetic", "ref": "atk:1",
                   "environment": environment},
        "params": params if params is not None else {},
        "magnitude": {"count": count},
        "axes": {"reversibility": reversibility, "blast_radius": blast_radius,
                 "externality": externality},
        "approval": approval if approval is not None else {"present": False,
                                                           "hold_id": None},
        "context": {"mode": "enforce"},
    }


def _verdict(envelope: dict) -> tuple[str, str]:
    status, resp = process(envelope)
    return resp.get("decision", "?"), resp.get("rule", "?")


class _AttackCase(unittest.TestCase):
    """Shared setup: an isolated ledger + holds store per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev_holds = os.environ.get("REEFLEX_HOLDS_PATH")
        self._prev_audit = os.environ.get("REEFLEX_AUDIT_LOG")
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._tmp.name, "holds.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self._tmp.name, "audit.jsonl")
        self._sessions: list[str] = []

    def tearDown(self):
        for s in self._sessions:
            ledger_mod.clear_session(s)
        for key, prev in (("REEFLEX_HOLDS_PATH", self._prev_holds),
                          ("REEFLEX_AUDIT_LOG", self._prev_audit)):
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev
        self._tmp.cleanup()

    def session(self, tag: str) -> str:
        s = _sid(tag)
        self._sessions.append(s)
        return s


# ---------------------------------------------------------------------------
# A1 — RFX-86: target.environment compared exactly
# ---------------------------------------------------------------------------

class TestA1EnvironmentNearMiss(_AttackCase):
    """"Prod" is production. So are "PROD", "prod ", "live" and "qa-eu"."""

    #: Every spelling that missed `environment == "production"` and fell
    #: through to R4 default_allow, plus an unrecognised tier which SPEC §7
    #: says must coerce to the most-guarded one.
    SPELLINGS = ["production", "Production", "PRODUCTION", "Prod", "prod",
                 "PROD", " production ", "production\n", "production​",
                 "﻿production", "live", "prd", "qa-eu-west-1"]

    def test_a1_no_spelling_of_production_reaches_default_allow(self):
        for spelling in self.SPELLINGS:
            with self.subTest(environment=spelling):
                decision, rule = _verdict(_env(
                    session_id=self.session("a1"), environment=spelling,
                    reversibility="irreversible", blast_radius="systemic",
                ))
                self.assertNotEqual(
                    "reeflex.policy/default_allow", rule,
                    "environment=%r evaded R3 and fell through to "
                    "default_allow — an irreversible systemic change in "
                    "production was ALLOWED" % spelling,
                )
                self.assertEqual("deny", decision, "environment=%r" % spelling)

    def test_a1_broad_variant_still_requires_a_human(self):
        for spelling in self.SPELLINGS:
            with self.subTest(environment=spelling):
                decision, _ = _verdict(_env(
                    session_id=self.session("a1b"), environment=spelling,
                    reversibility="irreversible", blast_radius="broad",
                ))
                self.assertEqual("require_approval", decision,
                                 "environment=%r" % spelling)

    def test_a1_genuine_non_production_is_not_escalated(self):
        """The wrong-DENY side of the trade-off stays bounded."""
        for spelling in ("dev", "DEV", " staging ", "stg", "development",
                         "test", "staging​"):
            with self.subTest(environment=spelling):
                decision, _ = _verdict(_env(
                    session_id=self.session("a1c"), environment=spelling,
                    reversibility="irreversible", blast_radius="systemic",
                ))
                self.assertEqual("allow", decision,
                                 "environment=%r was escalated to production"
                                 % spelling)


# ---------------------------------------------------------------------------
# A2 — RFX-85: action.verb compared exactly
# ---------------------------------------------------------------------------

class TestA2VerbFragmentation(_AttackCase):
    """R5's whole purpose is "fragmentation buys nothing" (SPEC §4.1).

    The deletions budget is 20 and both sides of it key on the exact literal
    "delete", so any other spelling accumulated under its own ledger key and
    never reached the budget.  Fragmented into 5-item calls, the 5th call
    (prior 20 + current 5 = 25 > 20) must be held for EVERY spelling.
    """

    SPELLINGS = ["delete", "Delete", "DELETE", "delete ", "delete\n",
                 "delete​", "ｄｅｌｅｔｅ", "remove", "destroy", "purge",
                 "drop", "truncate", "rm", "hard-delete", "bulk_delete",
                 "DeleteObject", "force_delete", "wipe", "erase",
                 "obliterate"]

    def _fragment(self, verb: str, chunk: int = 5, calls: int = 5) -> list[str]:
        session = self.session("a2")
        out = []
        for _ in range(calls):
            decision, _rule = _verdict(_env(
                session_id=session, verb=verb, count=chunk,
                reversibility="irreversible", environment="dev",
            ))
            out.append(decision)
        return out

    def test_a2_every_spelling_of_delete_hits_the_deletions_budget(self):
        for spelling in self.SPELLINGS:
            with self.subTest(verb=spelling):
                verdicts = self._fragment(spelling)
                self.assertIn(
                    "require_approval", verdicts,
                    "verb=%r fragmented 5x5=25 deletions past a budget of 20 "
                    "without ever being held: %s" % (spelling, verdicts),
                )

    def test_a2_an_unknown_irreversible_verb_lands_on_the_guarded_default(self):
        verdicts = self._fragment("zorblify")
        self.assertIn("require_approval", verdicts,
                      "an unrecognised IRREVERSIBLE verb escaped the "
                      "deletions budget: %s" % verdicts)

    def test_a2_a_mislabelled_delete_is_caught_by_the_ability(self):
        """verb:"read" carrying ability:"wordpress/delete-post"."""
        session = self.session("a2c")
        verdicts = []
        for _ in range(5):
            decision, _ = _verdict(_env(
                session_id=session, verb="read", ability="wordpress/delete-post",
                count=5, reversibility="irreversible",
            ))
            verdicts.append(decision)
        self.assertIn("require_approval", verdicts,
                      "a delete labelled 'read' evaded the budget: %s" % verdicts)

    def test_a2_benign_verbs_are_not_swept_into_the_deletions_budget(self):
        """The wrong-DENY side: a reversible long-tail verb must not be a
        delete just because nobody aliased it."""
        verdicts = self._fragment("zorblify_reversible", chunk=5, calls=5)
        # Reversible + unknown -> "update", policy-inert. 25 objects is well
        # under the objects_touched budget of 200.
        session = self.session("a2d")
        out = []
        for _ in range(5):
            decision, _ = _verdict(_env(
                session_id=session, verb="reticulate", count=5,
                reversibility="reversible",
            ))
            out.append(decision)
        self.assertEqual(["allow"] * 5, out,
                         "a benign reversible verb collected a spurious hold")


# ---------------------------------------------------------------------------
# A3 — RFX-84: the approving principal was self-asserted
# ---------------------------------------------------------------------------

class TestA3SelfAssertedApprover(_AttackCase):
    """Four-eyes must not be satisfiable by naming a different string.

    The four confirmed live variants: a case variant of the actor's own id,
    an invisible-character variant, the human the agent declares it acts FOR,
    and the session identity when agent.id is absent entirely.
    """

    def test_a3_all_four_self_approval_variants_are_caught(self):
        from app.principal import is_self_approval

        cases = [
            ("case variant",
             {"agent": {"id": "svc-bot", "session_id": "s1"}},
             "human", "SVC-BOT"),
            ("invisible character",
             {"agent": {"id": "svc-bot", "session_id": "s1"}},
             "human", "svc​-bot" if False else "svc-bot​"),
            ("approving as the human it acts for",
             {"agent": {"id": "agent:x", "on_behalf_of": "user:alice",
                        "session_id": "s1"}},
             "human", "alice"),
            ("session identity when agent.id is absent",
             {"agent": {"session_id": "sess-7"}},
             "human", "sess-7"),
        ]
        for name, envelope, ptype, pid in cases:
            with self.subTest(variant=name):
                self.assertTrue(
                    is_self_approval(envelope, ptype, pid),
                    "%s: %r approving as %s:%s was NOT caught as self-approval"
                    % (name, envelope["agent"], ptype, pid),
                )

    def test_a3_a_genuinely_different_human_is_still_allowed_to_approve(self):
        from app.principal import is_self_approval
        self.assertFalse(is_self_approval(
            {"agent": {"id": "svc-bot", "session_id": "s1"}},
            "human", "alice@example.com"))

    def test_a3_an_unverifiable_approver_is_refused_at_the_shipped_default(self):
        """RFX-84, 0.2.0: out of the box, core does not accept it at all.

        This assertion is the whole of the RFX-84 default flip, at the unit
        the release gate exercises over HTTP: with NOTHING configured, an
        approver core cannot tie to the calling credential is refused, not
        recorded.
        """
        from app.principal import PrincipalRefused, resolve_approver
        for key in ("REEFLEX_RESOLVER_TOKENS", "REEFLEX_REQUIRE_VERIFIED_APPROVER"):
            os.environ.pop(key, None)
        with self.assertRaises(PrincipalRefused) as ctx:
            resolve_approver("any-token", "human", "leo.david")
        self.assertEqual("principal_not_verified", ctx.exception.error)

    def test_a3_the_opt_out_still_never_mints_verified_looking_evidence(self):
        """The forgery-of-evidence half: core must not mint a record that
        says a named human exercised oversight when nothing checked.

        Now reachable only via the documented escape hatch -- and it has to
        keep holding there, because that is the configuration a 0.1.x
        deployment lands on when it takes the one-liner rather than wiring up
        credentials. Downgrading the default must not also downgrade the
        provenance.
        """
        from app.principal import resolve_approver
        os.environ.pop("REEFLEX_RESOLVER_TOKENS", None)
        os.environ["REEFLEX_REQUIRE_VERIFIED_APPROVER"] = "false"
        got = resolve_approver("any-token", "human", "leo.david")
        self.assertFalse(got["verified"])
        self.assertEqual("asserted", got["source"])

    def test_a3_asserting_someone_elses_identity_is_refused(self):
        from app.principal import PrincipalRefused, resolve_approver
        os.environ["REEFLEX_RESOLVER_TOKENS"] = (
            '{"tok-alice": {"type": "human", "id": "alice@example.com"}}')
        try:
            with self.assertRaises(PrincipalRefused):
                resolve_approver("tok-alice", "human", "leo.david")
        finally:
            os.environ.pop("REEFLEX_RESOLVER_TOKENS", None)


# ---------------------------------------------------------------------------
# A4 — RFX-127: an unverified approval.present switches R5 off
# ---------------------------------------------------------------------------

class TestA4UnverifiedApprovalDisablesBudgets(_AttackCase):
    """The highest-leverage field in the envelope.

    R5 reads `not input.approval.present`, so a caller-asserted boolean did
    not evade one matching condition — it disabled the entire cumulative
    budget rule, across all four dimensions, with no hold ever created.
    """

    #: Every shape of "I claim this was approved" a caller can write without
    #: naming a hold.  All must fail; none may reach OPA as an approval.
    FORGERIES = [
        {"present": True},
        {"present": True, "hold_id": None},
        {"present": True, "hold_id": ""},
        {"present": True, "hold_id": "no-such-hold-id"},
        {"present": True, "hold_id": "  "},
        {"present": True, "parent_decision_id": "deadbeef"},
    ]

    def _tripping_envelope(self, session: str, approval: dict | None) -> dict:
        """25 deletions in one call — over the deletions budget of 20."""
        return _env(session_id=session, verb="delete", count=25,
                    reversibility="irreversible", approval=approval)

    def test_a4_control_the_budget_really_does_fire(self):
        decision, rule = _verdict(
            self._tripping_envelope(self.session("a4ctl"), None))
        self.assertEqual("require_approval", decision)
        self.assertEqual("reeflex.policy/session_delete_budget", rule)

    def test_a4_no_forged_approval_yields_an_allow(self):
        for forgery in self.FORGERIES:
            with self.subTest(approval=forgery):
                decision, rule = _verdict(
                    self._tripping_envelope(self.session("a4"), dict(forgery)))
                self.assertNotEqual(
                    "allow", decision,
                    "approval=%r switched the cumulative budget off and the "
                    "action was ALLOWED (rule=%s)" % (forgery, rule),
                )

    def test_a4_forged_approvals_are_refused_by_the_hold_chain(self):
        """Not silently downgraded to a hold: REFUSED, and on the record.

        A caller claiming an approval that does not exist is a signal, not a
        formatting difference, so it takes the hold-validation refusal path
        rather than being quietly rewritten to present=false.
        """
        for forgery in self.FORGERIES:
            with self.subTest(approval=forgery):
                decision, rule = _verdict(
                    self._tripping_envelope(self.session("a4b"), dict(forgery)))
                self.assertEqual("deny", decision, "approval=%r" % forgery)
                self.assertEqual("reeflex.core/hold_validation", rule)

    def test_a4_a_forged_approval_cannot_rescue_an_otherwise_denied_action(self):
        decision, _ = _verdict(_env(
            session_id=self.session("a4c"), verb="delete",
            environment="production", reversibility="irreversible",
            blast_radius="systemic", approval={"present": True}))
        self.assertEqual("deny", decision)

    def test_a4_every_budget_dimension_not_just_deletions(self):
        """The rule was disabled wholesale, so every dimension is checked."""
        dimensions = [
            ("objects_touched", dict(verb="update", count=250)),
            ("external_sends", dict(verb="emit", count=60,
                                    externality="outbound")),
            ("money", dict(verb="transact", count=1,
                           params={"amount": 6000, "currency": "EUR"})),
            ("deletions", dict(verb="delete", count=25,
                               reversibility="irreversible")),
        ]
        for name, kwargs in dimensions:
            with self.subTest(dimension=name):
                # control: the dimension fires
                decision, _ = _verdict(_env(session_id=self.session("a4d"),
                                            **kwargs))
                self.assertEqual("require_approval", decision,
                                 "%s control did not fire" % name)
                # attack: the same envelope, plus a forged approval
                decision, _ = _verdict(_env(session_id=self.session("a4d"),
                                            approval={"present": True},
                                            **kwargs))
                self.assertNotEqual("allow", decision,
                                    "%s budget was switched off" % name)

    def test_a4_a_legitimate_absent_approval_is_untouched(self):
        """The wrong-DENY side: not asserting an approval is still normal."""
        for approval in (None, {"present": False},
                         {"present": False, "hold_id": None}, {}):
            with self.subTest(approval=approval):
                decision, _ = _verdict(_env(session_id=self.session("a4e"),
                                            approval=approval))
                self.assertEqual("allow", decision)

    def test_a4_a_non_bool_present_does_not_grant_an_approval(self):
        for junk in ("true", 1, "yes", [1], {"x": 1}):
            with self.subTest(present=junk):
                decision, _ = _verdict(self._tripping_envelope(
                    self.session("a4f"), {"present": junk}))
                self.assertEqual("require_approval", decision,
                                 "present=%r was read as an approval" % junk)


# ---------------------------------------------------------------------------
# A5 — RFX-133: the money budget's missing unit
# ---------------------------------------------------------------------------

class TestA5MoneyBudgetUnits(_AttackCase):
    """Two defects: an evasion by omission, and a unit error underneath it.

    The default money budget is 5000 for EUR and for any currency without its
    own entry (including "XXX", the undeclared bucket).
    """

    def _spend(self, session: str, amount, currency=None, n: int = 1) -> list[str]:
        params: dict = {"amount": amount}
        if currency is not None:
            params["currency"] = currency
        out = []
        for _ in range(n):
            decision, _rule = _verdict(_env(session_id=session, verb="transact",
                                            ability="eval/pay", params=params))
            out.append(decision)
        return out

    def test_a5_control_a_declared_currency_accumulates(self):
        s = self.session("a5ctl")
        self.assertEqual(["allow", "allow", "require_approval"],
                         self._spend(s, 2000, "EUR", n=3))

    def test_a5_omitting_the_currency_does_not_evade_the_budget(self):
        """THE EVASION. Four 2000-unit spends = 8000 against a budget of 5000."""
        s = self.session("a5")
        verdicts = self._spend(s, 2000, None, n=4)
        self.assertIn(
            "require_approval", verdicts,
            "8000 was spent against a money budget of 5000 with "
            "params.currency omitted, and nothing was ever held: %s" % verdicts,
        )
        self.assertEqual(["allow", "allow", "require_approval"], verdicts[:3])

    def test_a5_an_unusable_currency_does_not_evade_the_budget(self):
        for junk in ("", "   ", "€", "euros", "Bitcoin", 42, None, [], {}):
            with self.subTest(currency=junk):
                s = self.session("a5b")
                verdicts = self._spend(s, 2000, junk, n=3)
                self.assertIn("require_approval", verdicts,
                              "currency=%r evaded the money budget: %s"
                              % (junk, verdicts))

    def test_a5_currency_spelling_variants_share_one_bucket(self):
        """"EUR", "eur", " Eur " must not be three budgets."""
        s = self.session("a5c")
        verdicts = []
        for spelling in ("EUR", "eur", " Eur "):
            verdicts += self._spend(s, 2000, spelling)
        self.assertEqual(["allow", "allow", "require_approval"], verdicts)

    def test_a5_negative_amounts_cannot_unwind_cumulative_spend(self):
        """A refund is money moving, not money un-spent."""
        s = self.session("a5d")
        verdicts = []
        for amount in (2000, -2000, 2000):
            verdicts += self._spend(s, amount, "EUR")
        self.assertEqual("require_approval", verdicts[-1],
                         "alternating +N/-N unwound the budget: %s" % verdicts)

    def test_a5_splitting_across_currencies_does_not_evade_the_budget(self):
        """THE UNIT FIX MUST NOT OPEN A NEW HOLE.

        Per-currency budgets alone would reintroduce fragmentation one
        currency over: 4900 EUR + 4900 USD is ~EUR 9000 and neither limit is
        breached.  The utilisation sum (0.98 + 0.89 = 1.87) closes it.
        """
        s = self.session("a5e")
        verdicts = self._spend(s, 4900, "EUR") + self._spend(s, 4900, "USD")
        self.assertEqual("require_approval", verdicts[-1],
                         "spend split across two currencies evaded the money "
                         "budget: %s" % verdicts)

    def test_a5_a_small_foreign_amount_is_not_counted_as_a_large_one(self):
        """THE UNIT ERROR, from the wrong-DENY side.

        The old code compared sum(amount_by_currency) against one scalar, so
        2000 JPY (~EUR 12) counted exactly as much as 2000 EUR and a
        EUR 4000 + JPY 2000 session was held at "6000 > 5000".  With
        per-currency limits that is 0.800 + 0.0025 = 0.8025 — not a budget
        overage, and not a hold.
        """
        s = self.session("a5f")
        verdicts = self._spend(s, 4000, "EUR") + self._spend(s, 2000, "JPY")
        self.assertEqual(
            ["allow", "allow"], verdicts,
            "EUR 4000 + JPY 2000 (about EUR 4012) was held as if it were "
            "6000 of something: %s" % verdicts,
        )

    def test_a5_a_non_numeric_amount_contributes_nothing_and_does_not_crash(self):
        s = self.session("a5g")
        for junk in ("2000", None, True, [], {}):
            with self.subTest(amount=junk):
                decision, _ = _verdict(_env(session_id=s, verb="transact",
                                            params={"amount": junk,
                                                    "currency": "EUR"}))
                self.assertIn(decision, ("allow", "require_approval"))


# ---------------------------------------------------------------------------
# A6 — found BY the enumeration during this sweep, not by a report
# ---------------------------------------------------------------------------

class TestA6NonFiniteAmountPoisonsTheLedger(_AttackCase):
    """A single NaN used to permanently disable a session's money budget.

    Python's json.loads accepts the bare tokens NaN / Infinity / -Infinity
    (they are not valid JSON, but the stdlib parser is lenient).  `NaN` was
    recorded in the ledger verbatim, and every subsequent comparison against
    that currency's accumulated total was then false, because every
    comparison with NaN is false.  One call, and the money budget for that
    currency was off for the rest of the session.

    THE FIELD WAS ALREADY IN THE ENUMERATION — params.amount, declared
    VALIDATE.  It was the TREATMENT that was incomplete, which is the honest
    limit of what an enumeration buys: it tells you which fields need a
    treatment, not that the treatment you wrote is sufficient.
    """

    def test_a6_a_non_finite_amount_is_refused(self):
        from app.decide import process
        for junk in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(amount=junk):
                status, resp = process(_env(session_id=self.session("a6"),
                                            verb="transact",
                                            params={"amount": junk,
                                                    "currency": "EUR"}))
                self.assertEqual(400, status,
                                 "amount=%r was accepted" % junk)
                self.assertEqual("invalid_envelope", resp.get("error"))

    def test_a6_a_nan_cannot_poison_a_sessions_money_budget(self):
        """The consequence, tested through the ledger rather than the parser."""
        s = self.session("a6b")
        from app.decide import process
        process(_env(session_id=s, verb="transact",
                     params={"amount": float("nan"), "currency": "EUR"}))
        verdicts = []
        for _ in range(3):
            decision, _rule = _verdict(_env(session_id=s, verb="transact",
                                            params={"amount": 2000,
                                                    "currency": "EUR"}))
            verdicts.append(decision)
        self.assertEqual(
            ["allow", "allow", "require_approval"], verdicts,
            "a NaN amount disabled the money budget for the session: %s"
            % verdicts,
        )


class TestA6bApprovalBindsTheAmount(_AttackCase):
    """A human approved EUR 6,000 and the agent executed EUR 6,000,000.

    envelope_hash projects {action, axes, magnitude, target} only, so `params`
    — which carries the entire money dimension — was bound to nothing.  Check
    5 passed on a byte-identical hash.  Also found by walking the enumeration:
    the fields were declared, but nothing checked them against what the human
    saw.
    """

    def _approved_hold(self, session: str, amount, currency="EUR") -> str:
        from app.holds import resolve_hold
        _status, resp = __import__("app.decide", fromlist=["process"]).process(
            _env(session_id=session, verb="transact", ability="eval/pay",
                 params={"amount": amount, "currency": currency}))
        self.assertEqual("require_approval", resp["decision"], resp)
        hold_id = resp["hold_id"]
        resolve_hold(hold_id, "approve", "human", "alice@example.com",
                     reason="reviewed")
        return hold_id

    def test_a6b_resubmitting_the_approved_amount_is_allowed(self):
        s = self.session("a6c")
        hold_id = self._approved_hold(s, 6000)
        decision, rule = _verdict(_env(
            session_id=s, verb="transact", ability="eval/pay",
            params={"amount": 6000, "currency": "EUR"},
            approval={"present": True, "hold_id": hold_id}))
        self.assertEqual("allow", decision, rule)

    def test_a6b_inflating_the_amount_on_resubmission_is_refused(self):
        for inflated in (6000000, 6001, 6000.01):
            with self.subTest(amount=inflated):
                s = self.session("a6d")
                hold_id = self._approved_hold(s, 6000)
                decision, rule = _verdict(_env(
                    session_id=s, verb="transact", ability="eval/pay",
                    params={"amount": inflated, "currency": "EUR"},
                    approval={"present": True, "hold_id": hold_id}))
                self.assertEqual(
                    "deny", decision,
                    "a human approved EUR 6,000 and EUR %s executed on that "
                    "approval" % inflated)
                self.assertEqual("reeflex.core/hold_validation", rule)

    def test_a6b_swapping_the_currency_on_resubmission_is_refused(self):
        s = self.session("a6e")
        hold_id = self._approved_hold(s, 6000, "EUR")
        decision, _ = _verdict(_env(
            session_id=s, verb="transact", ability="eval/pay",
            params={"amount": 6000, "currency": "BHD"},
            approval={"present": True, "hold_id": hold_id}))
        self.assertEqual("deny", decision)

    def test_a6b_the_bound_paths_are_derived_not_hardcoded(self):
        """If a new params-block decision input is declared, it is bound."""
        from app.field_treatments import approval_bound_paths
        self.assertEqual(("params.amount", "params.currency"),
                         approval_bound_paths())


# ---------------------------------------------------------------------------
# The invariants the five instances are instances OF
# ---------------------------------------------------------------------------

class TestBoundaryInvariants(_AttackCase):
    """Properties that must hold for fields nobody has attacked yet."""

    def test_a_caller_supplied_cumulative_is_ignored(self):
        """`cumulative` is CORE_COMPUTED: core overwrites it before eval.

        Without the overwrite a caller could pre-load a fabricated history —
        or, more usefully to an attacker, a fabricated EMPTY one.
        """
        s = self.session("inv1")
        for _ in range(4):
            _verdict(_env(session_id=s, verb="delete", count=5,
                          reversibility="irreversible"))
        # 20 deletions banked. A forged empty cumulative must not reset it.
        envelope = _env(session_id=s, verb="delete", count=5,
                        reversibility="irreversible")
        envelope["cumulative"] = {"count_by_verb": {}, "total_count": 0,
                                  "amount_by_currency": {}}
        decision, _ = _verdict(envelope)
        self.assertEqual("require_approval", decision,
                         "a caller-supplied `cumulative` reset the ledger")

    def test_the_normalized_envelope_never_carries_a_raw_enum_to_the_policy(self):
        """Everything declared CANONICALISE lands in its closed set.

        The per-field version of this lives in tests/test_field_treatments.py;
        this is the end-to-end restatement: whatever the caller writes, the
        envelope that reaches OPA is drawn from the closed sets.
        """
        from app.envelope import validate_and_fill_defaults
        from app.field_treatments import CANONICALISE, TREATMENTS

        hostile = _env(session_id="s", verb="ZORBLE​",
                       environment="Pr​od", reversibility="Irreversible",
                       blast_radius="BROAD", externality="Outbound",
                       params={"amount": 1, "currency": " eur\n"})
        out = validate_and_fill_defaults(hostile)
        flat = {
            "action.verb": out["action"]["verb"],
            "target.environment": out["target"]["environment"],
            "axes.reversibility": out["axes"]["reversibility"],
            "axes.blast_radius": out["axes"]["blast_radius"],
            "axes.externality": out["axes"]["externality"],
            "params.currency": out["params"]["currency"],
        }
        for path, value in flat.items():
            treatment = TREATMENTS[path]
            self.assertEqual(CANONICALISE, treatment.kind, path)
            if treatment.closed_set:
                self.assertIn(value, treatment.closed_set,
                              "%s = %r escaped its closed set" % (path, value))


if __name__ == "__main__":
    unittest.main()
