#!/usr/bin/env python3
"""
attack-probe-rfx143-undeclared-count.py -- RFX-143, the CORE half.

THE CLAIM UNDER TEST
--------------------
`magnitude.count` has no representation for "I cannot enumerate the affected
set". Its domain is int >= 1 (envelope.py F2 rejects 0, negatives, floats and
bools), and an ABSENT count is filled with 1 -- the MINIMUM of that domain --
under the comment "Absent -> conservative default of 1".

Every one of R5's four budget dimensions charges that number
(budgets.rego::current_for), and `objects_touched` charges it UNCONDITIONALLY on
every action. So the caller that declares how many objects it is about to
destroy is charged for all of them, and the caller that says nothing is charged
one -- for the same action.

`provenance.undeclared` exists precisely to make "core guessed this" visible to
the policy, and it records axes.reversibility, axes.blast_radius,
axes.externality, target.environment and action.verb. It does NOT record
magnitude.count, although _PROVENANCE_FIELDS' own docstring says "Anything a
rule reads to decide WHAT KIND OF ACTION this is belongs here" and
field_treatments.py annotates magnitude.count `unverifiable_assertion=True,
note="...Feeds every count dimension."`

WHY THE AXES ARE HELD AT irreversible/scoped/production
-------------------------------------------------------
R2 needs blast_radius == broad, R3 needs systemic. `scoped` fires neither, so
R5's budget is the ONLY thing that can hold these envelopes -- if a cell holds,
the budget held it, and the rule id says so. Choosing `broad` here would have
R2 hold at call 1 in every cell and the budget would be invisible: that is
RFX-167's trap (a conjunction masking the dimension you are measuring).

RUN
    REEFLEX_PROBE_BASE=http://127.0.0.1:8391 \
        python3.12 scripts/attack-probe-rfx143-undeclared-count.py

Each cell uses a FRESH session id derived from a per-run nonce. R5's ledger is
per-session and lives in the core PROCESS; reusing a session id across runs
reads the previous run's cumulative and reports a hold that arithmetic says is
impossible (dev-1--041 lost a finding to exactly that).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("REEFLEX_PROBE_BASE", "http://127.0.0.1:8391").rstrip("/")
TOKEN = os.environ.get("REEFLEX_PROBE_TOKEN", "")
RUN = os.environ.get("REEFLEX_PROBE_RUN", "r1")
SYNTH = "SYNTHETIC probe, RFX-143, no real target"

# budgets.rego default_budgets: deletions limit 20, objects_touched limit 200.
# exceeded_dimensions uses `>`, not `>=`, so the trip is at prior+current == 21.
DELETIONS_LIMIT = 20


def call(envelope, label):
    body = json.dumps(envelope).encode()
    req = urllib.request.Request(
        BASE + "/v1/decide", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def envelope(session_id, verb="delete", env="production",
             reversibility="irreversible", blast="scoped",
             externality="internal", count="OMIT"):
    """Build a synthetic envelope. count='OMIT' omits the magnitude BLOCK."""
    env_ = {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:dev-1-synthetic", "session_id": session_id},
        "action": {"namespace": "eval", "verb": verb, "ability": "eval/synthetic"},
        "target": {"kind": "synthetic", "ref": "eval:dev-1", "environment": env},
        "params": {},
        "axes": {"reversibility": reversibility, "blast_radius": blast,
                 "externality": externality},
        "approval": {"present": False, "hold_id": None},
        "context": {"mode": "enforce", "note": SYNTH},
    }
    if count != "OMIT":
        env_["magnitude"] = {"count": count}
    return env_


def sid(tag):
    return "sess-rfx143-%s-%s" % (RUN, tag)


def banner(t):
    print("\n" + "=" * 78 + "\n== " + t + "\n" + "=" * 78)


def one(tag, label, **kw):
    st, r = call(envelope(sid(tag), **kw), label)
    d = r.get("decision", "?")
    ru = r.get("rule", "?")
    print("  %-58s -> %-16s %s" % (label, d, ru))
    return st, r, d, ru


def walk(tag, label, limit=40, **kw):
    """Fire the same envelope repeatedly under ONE fresh session until it holds.

    NOTE the explicit **kw pass-through: an earlier revision of this probe
    called walk() without forwarding `count`, so three cells that were supposed
    to differ all ran the same omitted-magnitude envelope and reported an
    identical "call 21". A count=45 cell tripping at call 21 is arithmetically
    impossible under a limit of 20 -- that impossibility is what exposed the
    harness bug, which is why the per-cell arithmetic is asserted below.
    """
    s = sid(tag)
    for i in range(1, limit + 1):
        st, r = call(envelope(s, **kw), label)
        d = r.get("decision", "?")
        ru = r.get("rule", "?")
        if d != "allow":
            print("  %-46s -> first non-allow at call %-3d %s / %s"
                  % (label, i, d, ru))
            return i, d, ru
    print("  %-46s -> NEVER in %d calls (allow x%d)" % (label, limit, limit))
    return None, "allow", "never"


def main():
    banner("PRECHECK  which build is this? (core exposes no version string)")
    # #89's environment canon: a near-miss spelling must coerce to production.
    _, _, d_exact, _ = one("pre-a", "irreversible+systemic, env='production'",
                           blast="systemic", count=1)
    _, _, d_near, _ = one("pre-b", "irreversible+systemic, env='Prod'",
                          blast="systemic", count=1, env="Prod")
    print("\n  exact -> %s ; near-miss -> %s" % (d_exact, d_near))
    print("  => #89 env canon %s on this build."
          % ("IS live" if d_exact == d_near == "deny" else "is NOT live"))

    banner("CONTROL  can anything downstream tell a guessed count from a stated one?")
    # Two envelopes identical except that one omits the magnitude block. If the
    # guess were recorded anywhere an auditor can reach, these two would differ.
    _, r_omit, _, _ = one("aud-omit", "magnitude OMITTED", verb="read",
                          reversibility="reversible")
    _, r_one, _, _ = one("aud-one", "count=1 stated", verb="read",
                         reversibility="reversible", count=1)
    log = os.environ.get("REEFLEX_AUDIT_LOG", "/tmp/rfx143-before/decisions.jsonl")
    try:
        lines = [json.loads(l) for l in open(log)]
        by_sid = {ln["session_id"]: ln for ln in lines}
        a = by_sid.get(sid("aud-omit"), {})
        b = by_sid.get(sid("aud-one"), {})
        print("\n  audit line, magnitude OMITTED : magnitude_count=%r  provenance=%r"
              % (a.get("magnitude_count"), a.get("provenance")))
        print("  audit line, count=1 stated    : magnitude_count=%r  provenance=%r"
              % (b.get("magnitude_count"), b.get("provenance")))
        same = a.get("magnitude_count") == b.get("magnitude_count")
        print("  => the two audit records are %s on the count."
              % ("INDISTINGUISHABLE" if same else "distinguishable"))
    except OSError as e:
        print("  (audit log unreadable: %s)" % e)
    print("  provenance echoed by /v1/decide: %s"
          % json.dumps(r_omit.get("provenance")))
    print("  core-side list is envelope.py::_PROVENANCE_FIELDS; the unit tests")
    print("  in test_undeclared_count_rfx143.py assert its membership directly.")

    banner("THE MEASUREMENT  'delete 45 accounts', three ways to say it")
    print("  axes held at irreversible / scoped / production in every cell, so")
    print("  R2 and R3 cannot fire and only R5's budget can hold.\n")

    one("honest", "ONE call, count=45 (adapter enumerated)", count=45)
    one("silent", "ONE call, magnitude OMITTED (adapter cannot count)")
    one("one", "ONE call, count=1 (adapter enumerated ONE object)", count=1)

    banner("HOW FAR EACH ONE GETS IN A SINGLE SESSION")
    n_omit, _, _ = walk("w-omit", "magnitude OMITTED, repeated", limit=40)
    n_one, _, _ = walk("w-one", "count=1, repeated", limit=40, count=1)
    n_45, _, _ = walk("w-45", "count=45, repeated", limit=40, count=45)
    # Arithmetic tripwire: exceeded_dimensions uses `>`, so a per-call charge of
    # c trips at the first call where c*i > 20. c=1 -> 21; c=45 -> 1.
    print("\n  ARITHMETIC CHECK (limit %d, strict >):" % DELETIONS_LIMIT)
    print("    count=1  expected trip at 21, measured %s  %s"
          % (n_one, "OK" if n_one == 21 else "*** HARNESS SUSPECT ***"))
    print("    count=45 expected trip at  1, measured %s  %s"
          % (n_45, "OK" if n_45 == 1 else "*** HARNESS SUSPECT ***"))
    print("    OMITTED  measured %s -- equal to count=1 means an absent count"
          % n_omit)
    print("             is charged as the MINIMUM of the domain, not as unknown.")

    banner("THE CASE OUR OWN ADAPTERS ACTUALLY EMIT: blast_radius=broad, count=1")
    print("  Every adapter in this repo defaults its own magnitude.count to 1")
    print("  (reeflex-claude envelope.py:97, reeflex-mcp normalize.py, the WP")
    print("  normalizer, the n8n node), so the live understatement is NOT an")
    print("  omitted field -- it is `count: 1` next to a declared whole-table")
    print("  blast radius. reversibility=recoverable so R2/R3 cannot fire and")
    print("  the budget is again the only thing that can hold.\n")
    walk("w-broad-1", "delete, broad, count=1", limit=40,
         blast="broad", reversibility="recoverable", count=1)
    walk("w-broad-omit", "delete, broad, magnitude OMITTED", limit=40,
         blast="broad", reversibility="recoverable")
    walk("w-sys-1", "delete, systemic, count=1", limit=40,
         blast="systemic", reversibility="recoverable", count=1)

    banner("NO-REGRESSION CONTROLS  single and scoped must not move")
    print("  count_floor leaves single and scoped at 1 deliberately: `scoped`")
    print("  is the everyday value our adapters emit, and a floor there would")
    print("  retune every ordinary session (the RFX-158 trade in reverse).\n")
    walk("w-single-1", "delete, single, count=1", limit=40,
         blast="single", reversibility="recoverable", count=1)
    walk("w-scoped-1", "delete, scoped, count=1", limit=40,
         blast="scoped", reversibility="recoverable", count=1)
    walk("w-scoped-omit", "delete, scoped, magnitude OMITTED", limit=40,
         blast="scoped", reversibility="recoverable")

    banner("THE SAME ASYMMETRY ON objects_touched (charges EVERY action)")
    print("  verb=read, so the deletions dimension charges 0 and only")
    print("  objects_touched (limit 200) can accumulate.\n")
    walk("w-read-omit", "verb=read, magnitude OMITTED", limit=25,
         verb="read", reversibility="reversible")
    one("read-big", "verb=read, count=250 (enumerated)", count=250,
        verb="read", reversibility="reversible")


if __name__ == "__main__":
    sys.exit(main())
