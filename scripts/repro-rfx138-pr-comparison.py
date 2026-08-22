#!/usr/bin/env python3
"""Independent RFX-138 reproduction — written for the dev-1--023 PR comparison.

Deliberately NOT either PR's own test file: #95 and #96 each ship a probe row
and each row was written by the author of the fix it scores.  This is a third
one, so the comparison rests on a harness neither PR tuned itself against.

Six probes against one target:

  P1 CONTROL   the approved agent spends its own approval        -> must ALLOW
  P2 EVASION   a different agent.id spends ALPHA's approval      -> must DENY
  P3 CONTROL   after P2, can ALPHA still spend its approval      -> must ALLOW
  P4 EVASION   same bot, same session, on_behalf_of alice->bob   -> must DENY
  P5 EVASION   SPEC-minimal envelope (session_id only), swapped  -> must DENY
  P6 CONTROL   same agent + same person, agent RESTARTED (new
               session_id) spends its approval                   -> must ALLOW

P3 and P6 are controls, not evasions.  P3 catches half a fix: refusing the
substitute but still burning the hold leaves the approved agent locked out of
the action a human said yes to.  P6 catches over-blocking: a hold lives 4h by
default, so binding agent.session_id turns an ordinary restart into a wrong
DENY on an already-approved irreversible action.  A build is only correct if
all six hold.

Usage:
    BASE=http://127.0.0.1:18795 TOKEN=t95 python3 scripts/repro-rfx138-pr-comparison.py
Exit code = number of probes that did not behave as required.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["BASE"].rstrip("/")
TOKEN = os.environ.get("TOKEN", "")
RUN = os.environ.get("RUN", str(int(time.time())))
LABEL = "synthetic:dev-1:RFX-138:pr-comparison"

if "api.reeflex.io" in BASE or BASE.startswith("https://api.reeflex"):
    sys.exit("refusing to run against production core")


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Reeflex-Eval", LABEL)
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")}


def env(session, agent_id="agent:alpha", on_behalf_of=None, with_id=True,
        approval=None):
    agent = {"session_id": session}
    if with_id:
        agent["id"] = agent_id
    if on_behalf_of is not None:
        agent["on_behalf_of"] = on_behalf_of
    return {
        "reeflex_version": "0.1",
        "agent": agent,
        "action": {"namespace": "eval", "verb": "delete",
                   "ability": "eval/synthetic"},
        "target": {"kind": "synthetic", "ref": "eval:rfx138",
                   "environment": "production"},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                 "externality": "internal"},
        "approval": approval or {"present": False, "hold_id": None},
        "context": {"mode": "enforce", "note": LABEL},
    }


def sid(tag):
    return "sess-rfx138-%s-%s" % (RUN, tag)


def raise_and_approve(tag, **kw):
    """Raise a hold, then have a THIRD-PARTY human approve it.

    The approver is neither the raiser nor the substitute, so the four-eyes
    guard (check 6) cannot be what refuses anything below.
    """
    s = sid(tag)
    st, r = call("POST", "/v1/decide", env(s, **kw))
    hid = r.get("hold_id")
    if r.get("decision") != "require_approval" or not hid:
        return s, None, "no hold: HTTP %s decision=%s" % (st, r.get("decision"))
    st2, r2 = call("POST", "/v1/holds/%s/resolve" % hid,
                   {"decision": "approve",
                    "principal": {"type": "human",
                                  "id": "manager@rfx138.invalid"},
                    "reason": LABEL})
    if st2 != 200:
        return s, None, "resolve refused HTTP %s %s" % (st2, r2.get("error", ""))
    return s, hid, None


def spend(session, hold_id, **kw):
    _, r = call("POST", "/v1/decide",
                env(session, approval={"present": True, "hold_id": hold_id},
                    **kw))
    return r.get("decision", "?"), r.get("reason", ""), r.get("rule", "")


ROWS = []


def row(name, want, got, reason, rule, note=""):
    ok = got == want
    ROWS.append({"probe": name, "want": want, "got": got, "reason": reason,
                 "rule": rule, "pass": ok, "note": note})
    print("  %-52s want=%-16s got=%-16s %-34s %s"
          % (name, want, got, reason or "-", "OK" if ok else "<< FAIL"))


print("=" * 140)
print("RFX-138 independent reproduction   target=%s   run=%s" % (BASE, RUN))
print("=" * 140)

# ---- P1 CONTROL -----------------------------------------------------------
s, h, err = raise_and_approve("p1", agent_id="agent:alpha")
if err:
    row("P1 CONTROL approved agent spends its own approval", "allow",
        "SETUP-FAIL", err, "")
else:
    d, rs, ru = spend(s, h, agent_id="agent:alpha")
    row("P1 CONTROL approved agent spends its own approval", "allow", d, rs, ru)

# ---- P2 EVASION + P3 the denial-of-service half ---------------------------
s, h, err = raise_and_approve("p2", agent_id="agent:alpha")
if err:
    row("P2 EVASION  different agent.id spends it", "deny", "SETUP-FAIL", err, "")
else:
    d, rs, ru = spend(sid("p2-beta"), h, agent_id="agent:beta")
    row("P2 EVASION  different agent.id spends it", "deny", d, rs, ru)
    d3, rs3, ru3 = spend(s, h, agent_id="agent:alpha")
    row("P3 CONTROL  ALPHA (the approved one) afterwards", "allow", d3, rs3, ru3,
        note="if P2 allowed this is the DoS half; if P2 denied it asks whether "
             "the refusal burned the hold")

# ---- P4 EVASION: on_behalf_of swap, same bot, same session ----------------
s, h, err = raise_and_approve("p4", agent_id="agent:bot",
                              on_behalf_of="alice@rfx138.invalid")
if err:
    row("P4 EVASION  on_behalf_of alice -> bob (same session)", "deny",
        "SETUP-FAIL", err, "")
else:
    d, rs, ru = spend(s, h, agent_id="agent:bot",
                      on_behalf_of="bob@rfx138.invalid")
    row("P4 EVASION  on_behalf_of alice -> bob (same session)", "deny", d, rs, ru)

# ---- P5 EVASION: SPEC-minimal envelope, no agent.id at all ---------------
s, h, err = raise_and_approve("p5", with_id=False)
if err:
    row("P5 EVASION  SPEC-minimal (session only), swapped session", "deny",
        "SETUP-FAIL", err, "")
else:
    d, rs, ru = spend(sid("p5-other"), h, with_id=False)
    row("P5 EVASION  SPEC-minimal (session only), swapped session", "deny",
        d, rs, ru)

# ---- P6 CONTROL: the restart ---------------------------------------------
s, h, err = raise_and_approve("p6", agent_id="agent:restarter",
                              on_behalf_of="alice@rfx138.invalid")
if err:
    row("P6 CONTROL restarted agent (new session) keeps approval", "allow",
        "SETUP-FAIL", err, "")
else:
    d, rs, ru = spend(sid("p6-after-restart"), h, agent_id="agent:restarter",
                      on_behalf_of="alice@rfx138.invalid")
    row("P6 CONTROL restarted agent (new session) keeps approval", "allow",
        d, rs, ru)

print("-" * 140)
bad = [r for r in ROWS if not r["pass"]]
print("VERDICT %s: %d/%d probes as required%s"
      % (BASE, len(ROWS) - len(bad), len(ROWS),
         "" if not bad else "  FAILING: " + ", ".join(
             r["probe"].split()[0] for r in bad)))
out = os.environ.get("OUT")
if out:
    with open(out, "w") as fh:
        json.dump({"base": BASE, "run": RUN, "rows": ROWS}, fh, indent=2)
sys.exit(len(bad))
