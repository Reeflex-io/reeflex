"""
policy.py -- `ReeflexConfirmationPolicy` and the helpers that act on a
conversation stopped in `WAITING_FOR_CONFIRMATION`.

WHY THE POLICY ALONE CANNOT REJECT A DENY
========================================
openhands-sdk 1.56.0's `ConfirmationPolicyBase.should_confirm(risk)` is handed a
risk level and nothing else -- not the action, not the conversation -- and it
returns a bool.  So the policy's whole job is to STOP the batch:

    HIGH (deny or hold)   -> confirm (stop)
    UNKNOWN (unreachable) -> confirm (stop)   -- fail closed
    MEDIUM / LOW (allow)  -> run

Telling a deny from a hold, rejecting the deny, and waiting on the hold happen
AFTER the stop, in `resolve_pending()` / `resolve_holds()`, which read the
analyzer's per-action record.  `run_governed()` is the loop that calls them.

ALL OR NOTHING, PER BATCH -- the SDK's semantics, not ours
=========================================================
`conversation.run()` executes EVERY pending action and
`conversation.reject_pending_actions(reason)` rejects every one.  There is no
per-action approve in 1.56.0.  So a batch that holds one denied action is
rejected as a whole, and a batch with a held action runs only when every hold
in it is approved.

WHERE A HOLD IS RESOLVED
========================
In the Reeflex portal's holds inbox.  The analyzer pushed the pending hold
there (holds-v1 DIR-1) when the gate held it; `resolve_holds()` polls
`GET /api/v1/holds/resolutions` (DIR-2, gate-scoped) until every hold in the
batch is answered:

    approve -> conversation.run()                    (the SDK's approve)
    deny    -> reject_pending_actions(<resolver's reason>)
    expired -> reject_pending_actions("... expired")
    max_wait elapsed with no answer -> reject         (fail closed)

and then pushes the deferred §4 evidence row for each hold with how it was
resolved and by whom.  The engine is NOT told: this seat never re-submits a
held action to core, the agent runs it on the human's approval, so core's own
hold record stays pending until its TTL.  The approval is recorded in the
portal and in the evidence row, which is where an Attest report reads it.

`console_confirm()` is the alternative for an operator who wants to answer at
the terminal instead of in the portal.  A deny is never offered for override
there either.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from pydantic import Field, PrivateAttr

from openhands.sdk.conversation.state import ConversationExecutionStatus, ConversationState
from openhands.sdk.security.confirmation_policy import ConfirmationPolicyBase
from openhands.sdk.security.risk import SecurityRisk

_RESOLUTION = {"approve": "approved", "deny": "rejected", "expired": "expired"}


class ReeflexConfirmationPolicy(ConfirmationPolicyBase):
    """Stop on HIGH (deny / hold) and UNKNOWN (gate unreachable); run the rest.

    ReeflexConfirmationPolicy(analyzer, poll=2.0, max_wait=900)
    """

    poll: float = Field(default=2.0, gt=0)
    max_wait: float = Field(default=900.0, gt=0)

    _analyzer: Any = PrivateAttr(default=None)

    def __init__(self, analyzer: Any = None, /, **data: Any) -> None:
        super().__init__(**data)
        self._analyzer = analyzer

    @property
    def analyzer(self):
        return self._analyzer

    def should_confirm(self, risk: SecurityRisk = SecurityRisk.UNKNOWN) -> bool:
        return risk in (SecurityRisk.HIGH, SecurityRisk.UNKNOWN)

    def resolve_holds(self, conversation: Any, **kw: Any) -> dict:
        kw.setdefault("poll", self.poll)
        kw.setdefault("max_wait", self.max_wait)
        return resolve_pending(conversation, self._analyzer, **kw)


# ---------------------------------------------------------------------------

def is_waiting(conversation: Any) -> bool:
    return (conversation.state.execution_status
            == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION)


def pending_actions(conversation: Any) -> list:
    state = conversation.state
    events = state.active_branch() if hasattr(state, "active_branch") else state.events
    return ConversationState.get_unmatched_actions(events)


def _records(conversation: Any, analyzer: Any, pending: list) -> list:
    """(action, record) per pending action.  The analyzer's side map first;
    else the `SecurityAnalysisEvent.details` the SDK wrote into the event log,
    which is the only copy a client has when the analyzer ran in a remote agent
    server.  None when neither has it (the caller fails closed)."""
    from openhands.sdk.event import SecurityAnalysisEvent

    from_events: dict = {}
    for e in conversation.state.events:
        if isinstance(e, SecurityAnalysisEvent):
            from_events.update(e.details or {})
    side = getattr(analyzer, "decisions", None) or {}
    return [(a, side.get(a.id) or from_events.get(a.id)) for a in pending]


def _reject(conversation: Any, reason: str, out: dict) -> dict:
    conversation.reject_pending_actions(reason)
    out.update(outcome="rejected", reason=reason)
    return out


def resolve_pending(conversation: Any, analyzer: Any, *, poll: float = 2.0,
                    max_wait: float = 900.0, resume: bool = True,
                    sleep: Callable[[float], None] = time.sleep,
                    clock: Callable[[], float] = time.monotonic,
                    on_wait: Optional[Callable[[dict], None]] = None) -> dict:
    """Act on a stopped batch.  Returns what was done and why.

    resume=True calls `conversation.run()` after an approval (the SDK's
    approve).  `run_governed()` passes False and runs the loop itself.
    """
    out: dict = {"outcome": "nothing_pending", "reason": None, "actions": [], "holds": {}}
    if not is_waiting(conversation):
        return out
    pending = pending_actions(conversation)
    records = _records(conversation, analyzer, pending)
    out["actions"] = [{"action_id": a.id, "tool_name": a.tool_name,
                       "verdict": (r or {}).get("verdict"), "rule": (r or {}).get("rule"),
                       "hold_id": (r or {}).get("hold_id"),
                       "reeflex_decision_id": (r or {}).get("reeflex_decision_id")}
                      for a, r in records]

    missing = [a for a, r in records if r is None]
    if missing:
        return _reject(conversation, "Reeflex has no decision for %d pending action(s); "
                       "failing closed" % len(missing), out)
    denied = [r for _, r in records if r["verdict"] == "deny"]
    if denied:
        return _reject(conversation, "Reeflex denied: %s" % denied[0]["rule"], out)
    unreachable = [r for _, r in records if r["verdict"] == "unreachable"]
    if unreachable:
        return _reject(conversation, "Reeflex gate unreachable; failing closed (%s)"
                       % (unreachable[0].get("gate_error") or "no decision"), out)

    holds = [r["hold_id"] for _, r in records if r["verdict"] == "require_approval"]
    if not holds:
        out.update(outcome="approved", reason="every pending action was allowed")
        if resume:
            conversation.run()
        return out

    unannounced = [r["hold_id"] for _, r in records
                   if r["verdict"] == "require_approval" and r.get("hold_announced") != "announced"]
    if unannounced:
        return _reject(conversation, "Reeflex held this action but the hold could not be put "
                       "in front of a human (%s); failing closed" % ", ".join(unannounced), out)

    answers = _await_resolutions(analyzer, holds, poll=poll, max_wait=max_wait,
                                 sleep=sleep, clock=clock, on_wait=on_wait)
    out["holds"] = answers
    for hold_id in holds:
        ans = answers.get(hold_id)
        by = (ans or {}).get("decided_by") or {}
        analyzer.complete_hold(hold_id, resolution=_RESOLUTION.get((ans or {}).get("decision")),
                               decided_by_type=by.get("type"), decided_by_id=by.get("id"))

    for hold_id in holds:
        ans = answers.get(hold_id)
        if ans is None:
            return _reject(conversation, "Reeflex hold %s was not resolved within %ss; "
                           "failing closed" % (hold_id, int(max_wait)), out)
        if ans.get("decision") == "deny":
            reason = ans.get("reason") or "no reason given"
            return _reject(conversation, "Reeflex hold %s rejected in the portal: %s"
                           % (hold_id, reason), out)
        if ans.get("decision") != "approve":
            return _reject(conversation, "Reeflex hold %s %s" % (hold_id, ans.get("decision")), out)

    out.update(outcome="approved", reason="every hold approved in the portal")
    if resume:
        conversation.run()
    return out


def _await_resolutions(analyzer: Any, hold_ids: list, *, poll: float, max_wait: float,
                       sleep, clock, on_wait) -> dict:
    wanted = set(hold_ids)
    got: dict = {}
    since = None
    deadline = clock() + max_wait
    while True:
        rows, err = analyzer.pull_resolutions(since)
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            ts = row.get("resolved_ts")
            if isinstance(ts, str) and (since is None or ts > since):
                since = ts
            if row.get("hold_id") in wanted:
                got[row["hold_id"]] = row
        if wanted <= set(got):
            return got
        if on_wait is not None:
            on_wait({"waiting_on": sorted(wanted - set(got)), "error": err})
        if clock() >= deadline:
            return got
        sleep(poll)


def resolve_holds(conversation: Any, analyzer: Any = None, **kw: Any) -> dict:
    """Module-level form of `ReeflexConfirmationPolicy.resolve_holds`."""
    if analyzer is None:
        analyzer = conversation.state.security_analyzer
    return resolve_pending(conversation, analyzer, **kw)


def console_confirm(conversation: Any, analyzer: Any = None, *,
                    input_fn: Callable[[str], str] = input,
                    print_fn: Callable[[str], None] = print,
                    approver_id: Optional[str] = None, resume: bool = True) -> dict:
    """Answer a stopped batch at the terminal instead of in the portal.

    Denies are rejected without asking.  Holds (and, if you choose, an
    unreachable gate) are shown with their Reeflex rule and need an explicit
    "yes".  `approver_id` is what the evidence row records as `decided_by.id`;
    with none, the row states the resolution and not who made it.
    """
    if analyzer is None:
        analyzer = conversation.state.security_analyzer
    out: dict = {"outcome": "nothing_pending", "reason": None, "actions": []}
    if not is_waiting(conversation):
        return out
    pending = pending_actions(conversation)
    records = _records(conversation, analyzer, pending)
    for a, r in records:
        r = r or {}
        print_fn("  %-14s %-18s rule=%s hold=%s" % (a.tool_name, r.get("verdict"),
                                                    r.get("rule"), r.get("hold_id")))
    if any((r or {}).get("verdict") == "deny" for _, r in records):
        return _reject(conversation, "Reeflex denied: %s" % next(
            r["rule"] for _, r in records if (r or {}).get("verdict") == "deny"), out)
    answer = (input_fn("Run these actions? [y/N] ") or "").strip().lower()
    holds = [r["hold_id"] for _, r in records if (r or {}).get("hold_id")]
    approved = answer in ("y", "yes")
    for h in holds:
        analyzer.complete_hold(h, resolution="approved" if approved else "rejected",
                               decided_by_type="human" if approver_id else None,
                               decided_by_id=approver_id)
    if not approved:
        return _reject(conversation, "Rejected at the console", out)
    out.update(outcome="approved", reason="approved at the console")
    if resume:
        conversation.run()
    return out


def run_governed(conversation: Any, analyzer: Any = None, *, max_rounds: int = 50,
                 resolver: Optional[Callable[..., dict]] = None, **kw: Any) -> list:
    """`conversation.run()`, then keep acting on every stop until the agent
    finishes or `max_rounds` stops have been handled.  Returns one entry per
    stop.  `resolver` defaults to the portal (`resolve_pending`); pass
    `console_confirm` to answer at the terminal."""
    if analyzer is None:
        analyzer = conversation.state.security_analyzer
    resolver = resolver or resolve_pending
    log: list = []
    conversation.run()
    for _ in range(max_rounds):
        if not is_waiting(conversation):
            break
        log.append(resolver(conversation, analyzer, resume=False, **kw))
        conversation.run()
    return log
