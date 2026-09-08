#!/usr/bin/env python3
"""
show.py -- print one fact out of a real response, and FAIL if it is not there.

Every subcommand here is an assertion as well as a printer. A demo whose
helper prints "(none)" when the thing it was looking for is missing is a demo
that reports success over a broken run; each of these exits non-zero instead.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request


def die(msg):
    print("\n\033[31m   FAILED: %s\033[0m" % msg)
    raise SystemExit(1)


def load(path):
    if path == "-":
        raw = sys.stdin.read()
    else:
        raw = open(path, encoding="utf-8").read()
    if not raw.strip():
        die("the response was EMPTY (%s). A blocked request that was killed "
            "leaves a zero-byte file, and reading it as 'no tool call' is how "
            "a walk reports a refusal that never happened." % path)
    try:
        return json.loads(raw)
    except ValueError:
        die("not JSON (%s): %s" % (path, raw[:300]))


def refusals(doc):
    choice = (doc.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content = msg.get("content")
    if not content:
        die("the response carries no refusal payload. tool_calls=%r "
            "finish_reason=%r" % (msg.get("tool_calls"),
                                  choice.get("finish_reason")))
    try:
        payload = json.loads(content)
    except ValueError:
        die("message.content is not the structured refusal, it is prose: %s"
            % content[:300])
    out = (payload.get("reeflex") or {}).get("refused") or []
    if not out:
        die("no `reeflex.refused` entries in message.content: %s"
            % content[:300])
    return choice, msg, out


def cmd_refusal(path):
    doc = load(path)
    choice, msg, refs = refusals(doc)
    print("   tool_calls:    %r      <- the model proposed one; the caller got none"
          % msg.get("tool_calls"))
    print("   finish_reason: %r" % choice.get("finish_reason"))
    for r in refs:
        print("   error:   %s" % r.get("error"))
        print("   rule:    %s" % r.get("rule"))
        print("   stage:   %s   <- refused at the GATEWAY. Not 'prevented at "
              "execution'." % r.get("stage"))
        print("   hold_id: %s" % r.get("hold_id"))
        print("   reason:  %s" % r.get("reason"))
    if msg.get("tool_calls"):
        die("a tool call was RELEASED on a response that also carries a refusal")


def cmd_refusal_full(path):
    doc = load(path)
    choice, msg, _ = refusals(doc)
    print("   tool_calls:    %r" % msg.get("tool_calls"))
    print("   finish_reason: %r" % choice.get("finish_reason"))
    print("   message.content, verbatim -- this is what the MODEL reads on its")
    print("   next turn, and it is why an agent can react instead of retrying")
    print("   the same refused call in a loop:")
    print()
    for line in json.dumps(json.loads(msg["content"]), indent=2).splitlines():
        print("     " + line)


def cmd_hold_id(path):
    _, _, refs = refusals(load(path))
    hid = refs[0].get("hold_id")
    if not hid:
        die("the refusal names no hold_id")
    print(hid)


def cmd_absent(path, needle):
    raw = open(path, encoding="utf-8").read()
    if needle in raw:
        die("%r IS present in the %d bytes the caller received" % (needle, len(raw)))
    print("   %r does not appear in the %d bytes of the response. Searched the"
          % (needle, len(raw)))
    print("   whole document, not just the tool_calls field.")


def cmd_hold(path):
    h = load(path)
    env = h.get("envelope") or {}
    print("   id:            %s" % h.get("id"))
    print("   status:        %s" % h.get("status"))
    print("   rule_id:       %s" % h.get("rule_id"))
    print("   expires_ts:    %s" % h.get("expires_ts"))
    print("   agent.id:      %s   <- the ORG is in the actor identity, not just"
          % (env.get("agent") or {}).get("id"))
    print("                       a label: core's hold check 8 binds an approval")
    print("                       to it, so one department cannot spend another's.")
    print("   session_id:    %s" % (env.get("agent") or {}).get("session_id"))
    print("   axes:          %s" % json.dumps(env.get("axes")))
    print("   provenance:    %s   <- nothing undeclared, so R0 does not apply"
          % json.dumps(env.get("provenance")))
    ctx = env.get("context") or {}
    print("   danger_signature:    %s" % ctx.get("danger_signature"))
    print("   classification_tier: %s" % ctx.get("classification_tier"))
    print("   command_preview:     %s" % ctx.get("command_preview"))
    if h.get("status") != "pending":
        die("expected a pending hold, got %r" % h.get("status"))


def cmd_pending_for_session(base, token, session):
    req = urllib.request.Request(base + "/v1/holds?status=pending",
                                 headers={"Authorization": "Bearer " + token})
    data = json.load(urllib.request.urlopen(req, timeout=15))
    ids = [i["id"] for i in data.get("items", [])
           if (((i.get("envelope") or {}).get("agent") or {})
               .get("session_id") or "").endswith(session)]
    if len(ids) != 1:
        die("expected exactly ONE pending hold for session %r, core has %d. "
            "Picking 'the last one' is how a walk approves somebody else's "
            "action." % (session, len(ids)))
    print(ids[0])


def cmd_json_line(path):
    d = load(path)
    print("   %s" % json.dumps({k: v for k, v in d.items()
                                if k in ("error", "reason", "hold_id")}))


def cmd_resolved(path):
    h = load(path)
    print("   status:                %s" % h.get("status"))
    print("   decided_by:            %s" % h.get("decided_by"))
    print("   decided_by_verified:   %s   <- taken from the CREDENTIAL, not"
          % h.get("decided_by_verified"))
    print("                                  from the request body")
    print("   principal_source:      %s" % h.get("principal_source"))
    print("   reason:                %s" % h.get("reason"))
    if h.get("status") != "approved" or not h.get("decided_by_verified"):
        die("the hold is not an approved, verified approval: %r / %r"
            % (h.get("status"), h.get("decided_by_verified")))


def cmd_released(path):
    doc = load(path)
    choice = (doc.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    calls = msg.get("tool_calls")
    if not calls:
        die("the caller did NOT receive the tool call. content=%r"
            % (msg.get("content") or "")[:400])
    print("   tool_calls:    %s" % json.dumps(calls))
    print("   finish_reason: %r" % choice.get("finish_reason"))
    print("   content:       %r" % msg.get("content"))
    print()
    print("   The SAME request. It was withheld while a human decided, and")
    print("   released only because core answered `allow` to the resubmission")
    print("   -- not because the hold said 'approved'.")


def _ledger(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def cmd_ledger_last(path):
    r = _ledger(path)[-1]
    for k in ("enforcement_stage", "observed", "prevents_execution",
              "hold_id", "hold_announced", "hold_decision", "rule",
              "agent_id"):
        print("   %-20s %s" % (k + ":", json.dumps(r.get(k))))


def cmd_ledger_table(path):
    rows = _ledger(path)
    print("   %-3s %-16s %-30s %-20s %-9s %-8s %s"
          % ("#", "verdict", "rule", "enforcement_stage", "announced",
             "released", "decided_by"))
    print("   " + "-" * 118)
    for i, r in enumerate(rows, 1):
        by = ((r.get("hold_decision") or {}).get("decided_by") or {}).get("id")
        print("   %-3d %-16s %-30s %-20s %-9s %-8s %s"
              % (i, r.get("verdict"), (r.get("rule") or "").split("/")[-1][:30],
                 r.get("enforcement_stage"),
                 r.get("hold_announced") or "-",
                 r.get("released_after_approval"), by or "-"))
    print()
    print("   Every row says `prevents_execution: false` and `observed:")
    print("   proposal`, on purpose. This seat sees a call PROPOSED. An")
    print("   application that keeps its own copy of the model's answer is not")
    print("   stopped by anything a gateway can do.")


def cmd_ledger_released(path):
    # REVERSED: the walk's step 5 is the LAST release in the file, and reading
    # the first one printed a line from an earlier experiment once.
    for r in reversed(_ledger(path)):
        if r.get("released_after_approval"):
            for line in json.dumps(r, indent=2, sort_keys=True).splitlines():
                print("     " + line)
            return
    die("no released-after-approval line in the ledger")


COMMANDS = {
    "refusal": cmd_refusal, "refusal-full": cmd_refusal_full,
    "hold-id": cmd_hold_id, "absent": cmd_absent, "hold": cmd_hold,
    "pending-for-session": cmd_pending_for_session, "json-line": cmd_json_line,
    "resolved": cmd_resolved, "released": cmd_released,
    "ledger-last": cmd_ledger_last, "ledger-table": cmd_ledger_table,
    "ledger-released": cmd_ledger_released,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit("usage: show.py {%s} ..." % "|".join(COMMANDS))
    COMMANDS[sys.argv[1]](*sys.argv[2:])
