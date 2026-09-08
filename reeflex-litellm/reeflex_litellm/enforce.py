"""
enforce.py -- turn one core Verdict into one gateway outcome.

This is the whole decision logic of the seat, and it is deliberately free of
any `litellm` import so it can be tested -- and IS tested -- without a proxy,
without a model and without the litellm package installed.  `guardrail.py` is
the thin adapter that wires it to LiteLLM's hook signature.

THE FOUR OUTCOMES
=================
  allow             the tool call is released untouched.

  deny              the tool call is REMOVED from the response and a structured
                    refusal takes its place:
                      {"error": "reeflex_denied", "rule": ..., "reason": ...,
                       "tool_call_id": ..., "tool": ...,
                       "stage": "refused_at_gateway"}

  require_approval  a hold exists in core.  The response is WITHHELD -- this
                    function blocks up to REEFLEX_LITELLM_HOLD_WAIT seconds
                    polling the hold -- and then:
                      approved  -> the ORIGINAL envelope is resubmitted with the
                                   approval, and released only if core answers
                                   allow.  The gateway does not release on the
                                   strength of the hold status alone: core's
                                   eight resubmission checks are the authority,
                                   and one of them (check 8, RFX-138) exists
                                   because a hold id alone was once enough to
                                   spend someone else's approval.
                      rejected  -> refused, error `reeflex_rejected`
                      expired   -> refused, error `reeflex_hold_expired`
                      pending   -> refused, error `reeflex_hold_timeout`, and
                                   the refusal NAMES the hold id so the caller
                                   can retry once a human decides.  The hold
                                   stays open; nothing is consumed.

  fail closed       core unreachable, unparseable, or answering something this
                    adapter does not understand -> refused, error
                    `reeflex_unavailable`, rule `reeflex.core/fail_closed`.
                    The reason string is the one the model sees.

  unmapped tenant   (RFX-243) the proxy authenticated a virtual key or team
                    that the tenancy map does not bind to a Reeflex org ->
                    refused, error `reeflex_tenant_unmapped`, rule
                    `reeflex.litellm/tenancy_unmapped`, BEFORE core is called.
                    See `refuse_unmapped_tenant()`, and tenancy.py for why
                    there is no default org.

WHAT `stage` IS FOR, AND WHY IT IS NOT OPTIONAL
===============================================
Every refusal this module produces carries `"stage": "refused_at_gateway"`.

A gateway sees a tool call PROPOSED.  It does not see it executed and cannot
prevent its execution: it removes the instruction from the response, and an
application that keeps its own copy, or that reads the refusal and runs the tool
anyway, is not stopped.  SPEC §5.1's adapter obligation is that an adapter
records what it actually did -- so "refused at gateway" must be a DIFFERENT
recorded fact from "prevented at execution", which is what the Claude Code hook
and the WordPress gate produce.  Collapsing the two would let an Attest report
claim prevention this seat cannot deliver.

`stage` is that distinction, on every refusal, in the payload the caller reads.
The same string, plus its ALLOWED counterpart and an explicit
`prevents_execution: false`, is written to the adapter's evidence ledger --
evidence.py owns the vocabulary and this module imports it, so the two cannot
drift.  `prevented_at_execution` is defined there and is unreachable from here:
`evidence.assert_never_claims_prevention()` raises on it.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from . import core as _core
from . import envelope as _envelope
from . import evidence as _evidence
from . import tenancy as _tenancy

# The caller-visible stage on a refusal.  Single-sourced from evidence.py so
# the string in the payload the model reads and the string in the evidence
# ledger can never drift apart -- a report that counts `refused_at_gateway`
# rows and a caller that matches on `stage` are reading the same fact.
STAGE = _evidence.STAGE_REFUSED_AT_GATEWAY

ERROR_DENIED = "reeflex_denied"
ERROR_REJECTED = "reeflex_rejected"
ERROR_HOLD_TIMEOUT = "reeflex_hold_timeout"
ERROR_HOLD_EXPIRED = "reeflex_hold_expired"
ERROR_HOLD_UNREADABLE = "reeflex_hold_unreadable"
ERROR_UNAVAILABLE = "reeflex_unavailable"


class Outcome:
    """What the gateway does with one proposed tool call.

    allowed    True -> release the tool call untouched.
    refusal    the structured payload when allowed is False; None otherwise.
    verdict    the core Verdict that produced this (for logging/telemetry).
    hold_id    set whenever a hold was raised, released or refused.
    released_after_approval
               True when a human approved and core's resubmission said allow.
    ledger     the adapter's own decision record (evidence.ledger_record), or
               None when no envelope existed to build one from -- i.e. when the
               tenant was unresolved or the envelope could not be built.  It
               carries `enforcement_stage` and `gateway_routing`, which
               EVIDENCE-INGEST-SPEC-v1 §4 has no field for; see evidence.py.
    """

    __slots__ = ("allowed", "refusal", "verdict", "hold_id",
                 "released_after_approval", "ledger", "hold_announced",
                 "hold_decision", "parent_decision_id")

    def __init__(self, allowed, refusal=None, verdict=None, hold_id=None,
                 released_after_approval=False, ledger=None,
                 hold_announced=None, hold_decision=None,
                 parent_decision_id=None):
        self.allowed = allowed
        self.refusal = refusal
        self.verdict = verdict
        self.hold_id = hold_id
        self.released_after_approval = released_after_approval
        self.ledger = ledger
        # None when no hold was raised; otherwise one of evidence.ANNOUNCE_*.
        # Recorded because "a human was asked" and "we could not reach the
        # inbox to ask" must not read the same in a report.
        self.hold_announced = hold_announced
        # WHO decided the hold, read off core's own record: the Article 14
        # fact. None when no hold was raised, when nobody decided, or when the
        # record could not be read -- and `None` never reads as "no human
        # decided", because the wire simply omits the fields, which is what §4
        # already means by absent.
        self.hold_decision = hold_decision
        # The decision that RAISED the hold, for the §6 chain.
        self.parent_decision_id = parent_decision_id

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("Outcome(allowed=%r, error=%r, hold_id=%r)"
                % (self.allowed,
                   (self.refusal or {}).get("error"), self.hold_id))


def refusal(call, error: str, rule: str, reason: str,
            hold_id: Optional[str] = None) -> dict:
    """The structured refusal the model reads.  `stage` is always present."""
    out = {
        "error": error,
        "rule": rule,
        "reason": reason,
        "tool_call_id": call.call_id,
        "tool": call.gateway_tool,
        "stage": STAGE,
    }
    if hold_id:
        out["hold_id"] = hold_id
    return out


def refuse_unmapped_tenant(call, reason: str) -> Outcome:
    """The refusal for a caller no tenancy map binds to a Reeflex org.

    Produced BEFORE any envelope exists, and deliberately so: an envelope built
    for an unresolved caller would have to name some org or none, and either
    choice writes a decision record that misattributes the action.  Core is not
    called, so no decision is recorded against the wrong tenant, and no R5
    budget is charged to a session that belongs to nobody.

    `ledger` is None for the same reason -- there is no decision to record.
    That is a stated gap: an operator who wants unmapped callers COUNTED must
    read the proxy's own log line, which `guardrail.py` writes.  A ledger row
    naming no org would be worse than an absent one, because a report could
    total it.
    """
    return Outcome(False, refusal(
        call, _tenancy.ERROR_UNMAPPED, _tenancy.RULE_UNMAPPED, reason))


def rule_one_call(call, *, session_id: str, model: str,
                  principal: Optional[str] = None,
                  environment: Optional[str] = None,
                  hold_wait: Optional[float] = None,
                  tenant=None,
                  gateway_routing: Optional[dict] = None) -> Outcome:
    """Build the envelope for one normalized call, decide it, and enforce.

    Synchronous.  `guardrail.py` runs this off the event loop.
    NEVER raises: an exception escaping here would either take the proxy down or
    -- worse -- be swallowed by a caller and release the call.

    `tenant` defaults to `tenancy.UNSCOPED` -- a Tenant with NO org, which
    cannot select a gate credential and which stamps the envelope
    `tenancy.scope = "unscoped"`.  It exists so this function stays callable in
    a unit test with no tenancy map; `guardrail.py` never passes it, because a
    request that reaches the hook is resolved to an org or refused before this
    is called.

    The returned Outcome carries a `ledger` record (evidence.py) whenever an
    envelope was built -- including on every refusal, because a refusal is the
    evidence.  The ONE case with no ledger is an envelope that could not be
    built at all: there is nothing to record a decision about, and inventing a
    record for it would put a governance line in the ledger that names no
    action.
    """
    tenant = _tenancy.UNSCOPED if tenant is None else tenant
    try:
        env = _envelope.build_gateway_envelope(
            session_id=session_id, model=model, call=call,
            principal=principal, environment=environment,
            tenant=tenant, gateway_routing=gateway_routing)
    except Exception as exc:
        # A session id we could not use, or any other envelope failure.  There
        # is no envelope, so there is no decision, so this is a refusal.
        return Outcome(False, refusal(
            call, ERROR_UNAVAILABLE, _core.FAIL_CLOSED_RULE,
            "Reeflex: could not build an action envelope for this tool call, "
            "so it was not ruled on and is refused: %s" % _short(exc)))

    outcome = _decide_and_enforce(call, env, hold_wait, tenant)
    # The ledger is written from the DECIDED outcome, so the recorded
    # `enforcement_stage` is what the caller actually got -- not what the
    # verdict said before the hold loop, the resubmission and the fail-closed
    # branches had their say.  An approved-then-released call records
    # `allowed_at_gateway`; an approved call core then refused on resubmission
    # records `refused_at_gateway`, which is the true fact about that request.
    try:
        outcome.ledger = _evidence.ledger_record(
            envelope=env,
            verdict=outcome.verdict,
            outcome_allowed=outcome.allowed,
            gateway_routing=gateway_routing or {},
            call=call,
            tenant=tenant,
            hold_id=outcome.hold_id,
            released_after_approval=outcome.released_after_approval,
            refusal=outcome.refusal,
            hold_announced=outcome.hold_announced,
            hold_decision=outcome.hold_decision,
            parent_decision_id=outcome.parent_decision_id,
        )
    except Exception:
        # A ledger we could not build must not change a decision already made.
        # Same rule core applies to its own audit: "audit failure != deny".
        outcome.ledger = None
    return outcome


def _decide_and_enforce(call, env: dict, hold_wait: Optional[float],
                        tenant=None) -> Outcome:
    """Decide one built envelope and apply the verdict.  Never raises.

    Split out of `rule_one_call` so the decision paths stay byte-identical
    while the ledger is attached in one place at the end.  Every `return` below
    is a verdict path the test suite pins individually.
    """
    verdict = _core.decide(env)

    if verdict.kind == "allow":
        return Outcome(True, verdict=verdict)

    if verdict.kind == "deny":
        if not verdict.core_reachable:
            return Outcome(False, refusal(
                call, ERROR_UNAVAILABLE, verdict.rule, verdict.reason),
                verdict=verdict)
        return Outcome(False, refusal(
            call, ERROR_DENIED, verdict.rule, verdict.reason), verdict=verdict)

    # verdict.kind == "ask": core raised a hold.
    hold_id = verdict.hold_id
    if not hold_id:
        # require_approval with no hold id: the hold cannot be resolved, so it
        # cannot be released.  Refuse rather than wait forever on nothing.
        return Outcome(False, refusal(
            call, ERROR_UNAVAILABLE, verdict.rule,
            "Reeflex: this action needs human approval but core returned no "
            "hold id, so no approval can be recorded against it -- refused. "
            + verdict.reason), verdict=verdict)

    # ASK THE HUMAN BEFORE WAITING FOR THE ANSWER.
    #
    # Core raising a hold means "a human decides".  Core is where the hold
    # LIVES; it is not where a human looks.  So unless the hold reaches an
    # approval inbox, the wait below is a wait for somebody who was never told,
    # and the honest outcome of the whole request is a timeout that reads like
    # a human declining to answer.
    #
    # This is the ONLY network call this package makes before enforcement, and
    # it is guarded accordingly: `announce_hold()` never raises, never denies,
    # and returns a state that goes on the ledger line.  With the push
    # disabled -- the default -- it is a dictionary lookup and the behaviour is
    # byte-identical to the version of this file that had no announcement.
    announced, announce_detail = _evidence.announce_hold(
        envelope=env, verdict=verdict,
        tenant=_tenancy.UNSCOPED if tenant is None else tenant)

    status, err = _core.await_hold(hold_id, wait_seconds=hold_wait)

    if err is not None:
        return Outcome(False, refusal(
            call, ERROR_HOLD_UNREADABLE, verdict.rule,
            "Reeflex: this action needs human approval and the hold could not "
            "be read, so it is refused: %s" % err, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id, hold_announced=announced)

    # WHO DECIDED IT, read once, for every status a human could have produced.
    #
    # Not only on approval: a REJECTION is human oversight too, and Article 14
    # is about oversight being exercised, not about it saying yes. A report
    # that recorded only approvals would make "a person looked at a production
    # DROP TABLE and said no" invisible -- the single most valuable row in the
    # whole trail.
    #
    # One extra GET, on a path that has already polled N times. A failure here
    # is recorded as unknown and never blocks or changes the outcome: the
    # approval is core's to honour either way, and an evidence gap must not
    # become a governance outage.
    decision = None
    if status in ("approved", "rejected", "expired", "consumed"):
        decision, _decision_err = _core.hold_decision(hold_id)

    if status == "pending":
        return Outcome(False, refusal(
            call, ERROR_HOLD_TIMEOUT, verdict.rule,
            "Reeflex: this action needs human approval. No decision arrived "
            "within the gateway's wait window, so the call is refused for now. "
            "The hold is still open -- retry after a human resolves it. "
            + _announce_note(announced, announce_detail)
            + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id, hold_announced=announced)

    if status == "rejected":
        return Outcome(False, refusal(
            call, ERROR_REJECTED, verdict.rule,
            "Reeflex: a human reviewed this action and rejected it. "
            + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id, hold_announced=announced,
            hold_decision=decision,
            parent_decision_id=verdict.decision_id)

    if status in ("expired", "consumed"):
        return Outcome(False, refusal(
            call, ERROR_HOLD_EXPIRED, verdict.rule,
            "Reeflex: the approval hold for this action is %s, so the call is "
            "refused. " % status + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id, hold_announced=announced,
            hold_decision=decision,
            parent_decision_id=verdict.decision_id)

    if status != "approved":
        # An unknown hold status is not an approval.
        return Outcome(False, refusal(
            call, ERROR_HOLD_UNREADABLE, verdict.rule,
            "Reeflex: the approval hold for this action reported an "
            "unrecognized status %r, which is not an approval -- refused. "
            % status + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id, hold_announced=announced,
            hold_decision=decision,
            parent_decision_id=verdict.decision_id)

    # Approved by a human.  Core, not the hold status, releases the call.
    # `decision` (who approved it) was already read above, for every terminal
    # status, so this path adds no request of its own.
    approver = os.environ.get("REEFLEX_LITELLM_APPROVER") or None
    resubmission = _envelope.with_approval(env, hold_id, approver=approver)
    second = _core.resubmit_with_approval(resubmission)
    # `parent_decision_id` is the decision that RAISED the hold, not the
    # resubmission -- §4/§6 use it to stitch decision -> hold -> approval ->
    # re-decision into one navigable chain, and a report that pointed it at
    # the resubmission would make every chain a self-loop.
    common = dict(hold_id=hold_id, hold_announced=announced,
                  hold_decision=decision,
                  parent_decision_id=verdict.decision_id)
    if second.kind == "allow":
        return Outcome(True, verdict=second, released_after_approval=True,
                       **common)
    return Outcome(False, refusal(
        call, ERROR_DENIED if second.core_reachable else ERROR_UNAVAILABLE,
        second.rule,
        "Reeflex: a human approved this action but core refused the "
        "resubmission, so it is not released. " + second.reason,
        hold_id=hold_id), verdict=second, **common)


def _announce_note(announced: str, detail: str) -> str:
    """One clause telling the caller whether anyone was actually asked.

    A timeout with the inbox unreachable and a timeout with a human who simply
    has not answered yet call for different next steps from whoever reads the
    refusal -- fix the wiring, or wait.  The refusal says which.  It names the
    failure class, never the URL and never a credential.
    """
    if announced == _evidence.ANNOUNCE_SENT:
        return "The hold was delivered to the approval inbox. "
    if announced == _evidence.ANNOUNCE_FAILED:
        return ("NOTE: the hold could NOT be delivered to the approval inbox "
                "(%s), so nobody may have been asked -- this is a gateway "
                "configuration problem, not a human declining. "
                % _short_reason(detail))
    return ("NOTE: no approval inbox is configured on this gateway, so the "
            "hold exists in reeflex-core and was not delivered anywhere a "
            "human is watching. ")


def _short_reason(detail: str) -> str:
    d = (detail or "").strip() or "no detail"
    return d if len(d) <= 120 else d[:120] + "...[truncated]"


def _short(exc: Exception) -> str:
    s = "%s: %s" % (type(exc).__name__, exc)
    return s if len(s) <= 200 else s[:200] + "...[truncated]"
