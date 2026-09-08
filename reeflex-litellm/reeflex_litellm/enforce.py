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
"""

from __future__ import annotations

import os
from typing import Any, Optional

from . import core as _core
from . import envelope as _envelope

STAGE = "refused_at_gateway"

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
    """

    __slots__ = ("allowed", "refusal", "verdict", "hold_id",
                 "released_after_approval")

    def __init__(self, allowed, refusal=None, verdict=None, hold_id=None,
                 released_after_approval=False):
        self.allowed = allowed
        self.refusal = refusal
        self.verdict = verdict
        self.hold_id = hold_id
        self.released_after_approval = released_after_approval

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


def rule_one_call(call, *, session_id: str, model: str,
                  principal: Optional[str] = None,
                  environment: Optional[str] = None,
                  hold_wait: Optional[float] = None) -> Outcome:
    """Build the envelope for one normalized call, decide it, and enforce.

    Synchronous.  `guardrail.py` runs this off the event loop.
    NEVER raises: an exception escaping here would either take the proxy down or
    -- worse -- be swallowed by a caller and release the call.
    """
    try:
        env = _envelope.build_gateway_envelope(
            session_id=session_id, model=model, call=call,
            principal=principal, environment=environment)
    except Exception as exc:
        # A session id we could not use, or any other envelope failure.  There
        # is no envelope, so there is no decision, so this is a refusal.
        return Outcome(False, refusal(
            call, ERROR_UNAVAILABLE, _core.FAIL_CLOSED_RULE,
            "Reeflex: could not build an action envelope for this tool call, "
            "so it was not ruled on and is refused: %s" % _short(exc)))

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

    status, err = _core.await_hold(hold_id, wait_seconds=hold_wait)

    if err is not None:
        return Outcome(False, refusal(
            call, ERROR_HOLD_UNREADABLE, verdict.rule,
            "Reeflex: this action needs human approval and the hold could not "
            "be read, so it is refused: %s" % err, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id)

    if status == "pending":
        return Outcome(False, refusal(
            call, ERROR_HOLD_TIMEOUT, verdict.rule,
            "Reeflex: this action needs human approval. No decision arrived "
            "within the gateway's wait window, so the call is refused for now. "
            "The hold is still open -- retry after a human resolves it. "
            + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id)

    if status == "rejected":
        return Outcome(False, refusal(
            call, ERROR_REJECTED, verdict.rule,
            "Reeflex: a human reviewed this action and rejected it. "
            + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id)

    if status in ("expired", "consumed"):
        return Outcome(False, refusal(
            call, ERROR_HOLD_EXPIRED, verdict.rule,
            "Reeflex: the approval hold for this action is %s, so the call is "
            "refused. " % status + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id)

    if status != "approved":
        # An unknown hold status is not an approval.
        return Outcome(False, refusal(
            call, ERROR_HOLD_UNREADABLE, verdict.rule,
            "Reeflex: the approval hold for this action reported an "
            "unrecognized status %r, which is not an approval -- refused. "
            % status + verdict.reason, hold_id=hold_id),
            verdict=verdict, hold_id=hold_id)

    # Approved by a human.  Core, not the hold status, releases the call.
    approver = os.environ.get("REEFLEX_LITELLM_APPROVER") or None
    resubmission = _envelope.with_approval(env, hold_id, approver=approver)
    second = _core.resubmit_with_approval(resubmission)
    if second.kind == "allow":
        return Outcome(True, verdict=second, hold_id=hold_id,
                       released_after_approval=True)
    return Outcome(False, refusal(
        call, ERROR_DENIED if second.core_reachable else ERROR_UNAVAILABLE,
        second.rule,
        "Reeflex: a human approved this action but core refused the "
        "resubmission, so it is not released. " + second.reason,
        hold_id=hold_id), verdict=second, hold_id=hold_id)


def _short(exc: Exception) -> str:
    s = "%s: %s" % (type(exc).__name__, exc)
    return s if len(s) <= 200 else s[:200] + "...[truncated]"
