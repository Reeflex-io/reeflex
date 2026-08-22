#!/usr/bin/env python3
"""
attack-probe-rfx97-release-gate.py — the RFX-97 release gate.

WHAT THIS IS FOR
================
RFX-97 asks one question that no test suite answers: *if we cut a release from
this commit, which of the five known evasions does it actually close?*  A unit
suite answers "does the fix's own test pass"; this answers "does the ARTEFACT
still fall over when you push on it".  Point it at a built image (or api-dev)
and it replays all five attacks and prints a verdict per evasion.

    THE FIVE
    RFX-86   environment string compared exactly ("Prod" fell to default_allow)   fix #89
    RFX-85   delete-verb spelling slipped past R5                                 fix #90
    RFX-84   the approving human on /resolve was self-asserted                    fix #90
    RFX-127  R5 switched off entirely by approval:{present:true}, no hold_id       fix #92
    RFX-133  R5 money budget evaded by omitting params.currency                   fix #92

    AND THE SIXTH, added when it was found the same way (A6)
    RFX-138  a human's approval is spendable by a DIFFERENT agent, or by the
             same agent claiming a different on_behalf_of                          fix: check 8

A6 SCORES THREE OUTCOMES, NOT TWO, and that is the lesson of the row rather
than a detail of it.  A fix here can fail in two opposite directions and both
are release blockers:

  * TOO LOOSE — the substitute spends the approval.  The evasion itself.
  * TOO TIGHT — a legitimate resubmission is refused.  An agent that merely
    RESTARTED inside the hold's 4h TTL, or whose id is spelled in a different
    case, is a wrong DENY on the one path in this product where a human has
    explicitly said yes.  Not an evasion; still not releasable.
  * HALF DONE — the substitute is refused and the hold is consumed anyway.
    The hijack is closed and the denial of service is kept: any caller holding
    the hold_id can destroy a human's approval on demand, and the approved
    agent has to go find a second human.  This is scored because the first
    version of this row probed it only on the ALLOW branch and therefore
    scored that build CLOSED.

USAGE
=====
    # against a container built from the commit under test
    docker build -t reeflex-core:under-test .
    docker run -d --name ut -p 18391:8080 -e REEFLEX_AUTH_TOKEN=t reeflex-core:under-test
    REEFLEX_PROBE_BASE=http://127.0.0.1:18391 REEFLEX_PROBE_TOKEN=t REEFLEX_PROBE_PACE=0 \
        python3 scripts/attack-probe-rfx97-release-gate.py

    # against api-dev (published eval token, paced for the 429 limiter)
    python3 scripts/attack-probe-rfx97-release-gate.py

    --json PATH   also write the machine-readable verdict table
    --only A1,A4  run a subset

EXIT CODE = the number of evasions still exploitable.  0 means every evasion in
the table above is closed, so a release cut here closes RFX-97.  CI can gate on
it directly.  The list is deliberately APPEND-ONLY: an evasion that has been
found once stays in the gate forever, because "we fixed that" is a claim about
a commit and this file is the only thing that checks it against an artefact.

THE DISCIPLINE THIS FILE ENCODES (and why a naive probe reports the opposite)
============================================================================
Every attack runs a CONTROL and an EVASION, and an evasion only counts when
the control BLOCKED and the evasion did not.  Without the control an "allow"
is unreadable: it could mean the guard was evaded, or that the guard was never
in scope for that request.  Three specific traps this encodes against:

1.  R5 MUST BE PROBED FRAGMENTED, NEVER SINGLE-CALL.  The R5 shape deployed on
    api-dev v0.1.13 (original SPEC §4.1) adds `magnitude.count` to the delete
    budget UNCONDITIONALLY — it never checks the verb, so ONE count=25 call
    trips it whatever the verb is (it fires on a `read`).  A single-call probe
    of RFX-85 therefore returns "0/N evaded, SECURE" on a build where the
    evasion is entirely real.  Only the CUMULATIVE term is keyed on the literal
    "delete", so N × count=5 in one session is the form that is decisive on
    BOTH R5 shapes.  This cost a full round once; see qa--012.

2.  RFX-84 HAS A CONFIG DIMENSION, so "fixed" is not a single bit.  #90 made
    the approver verifiable but deliberately did NOT default it on (defaulting
    it on makes every hold unresolvable on upgrade).  With no
    REEFLEX_RESOLVER_TOKENS the fabricated principal is still ACCEPTED — it is
    merely recorded as `decided_by_verified: false`.  So this probe reports
    RFX-84 as two rows: the self-approval variants (closed unconditionally by
    #90) and the unrelated-fabricated-human variant (closed only when the
    deployment sets a token map or REQUIRE_VERIFIED_APPROVER).  A probe that
    collapses them either over- or under-claims.

3.  CORE EXPOSES NO VERSION OVER HTTP, so a build can only be fingerprinted by
    behaviour.  `fingerprint()` below runs three cheap probes that pin which R5
    is live before any verdict is trusted.

RULES OF ENGAGEMENT
===================
Traffic is labelled synthetic on every request (X-Reeflex-Eval header +
context.note).  PROD CORE IS REFUSED OUTRIGHT by the host guard below — this
harness talks to localhost or api-dev only, and never deploys or restarts
anything.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("REEFLEX_PROBE_BASE", "https://api-dev.reeflex.io").rstrip("/")
TOKEN = os.environ.get("REEFLEX_PROBE_TOKEN", "reeflex-eval-public-2026")
RUN = os.environ.get("REEFLEX_PROBE_RUN", str(int(time.time())))
PACE = float(os.environ.get("REEFLEX_PROBE_PACE", "1.2"))
SYNTH = "synthetic:qa:RFX-97:release-gate"

# HARD GUARD: production core is out of scope for this harness, entirely.
_host = BASE.split("://", 1)[-1].split("/", 1)[0].lower()
if _host in ("api.reeflex.io", "reeflex.io", "www.reeflex.io"):
    sys.exit("refusing to probe production core (%s) — api-dev / localhost only" % _host)

# Budgets this harness assumes (budgets.rego default_budgets).
MONEY_LIMIT = 5000
DELETIONS_LIMIT = 20

_TRANSCRIPT: list[dict] = []


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

def call(method: str, path: str, body=None, label: str = ""):
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
            # api-dev rate-limits concurrent bursts; back off rather than
            # recording a 429 as if it were a policy verdict.
            if status == 429 and attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            break
        except Exception as exc:  # noqa: BLE001
            status, raw = -1, str(exc)
            break

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"_raw": raw}

    _TRANSCRIPT.append({"label": label, "method": method, "path": path,
                        "request": body, "status": status, "response": parsed})
    if PACE:
        time.sleep(PACE)
    return status, parsed


def envelope(session_id, verb, count=1, env="dev", reversibility="irreversible",
             blast="single", externality="internal", params=None, approval=None,
             agent_id="agent:qa-rfx97-synthetic", include_agent_id=True,
             on_behalf_of=None):
    """A labelled synthetic Action Envelope (SPEC §2)."""
    agent = {"session_id": session_id}
    if include_agent_id:
        agent["id"] = agent_id
    if on_behalf_of is not None:
        agent["on_behalf_of"] = on_behalf_of
    return {
        "reeflex_version": "0.1",
        "agent": agent,
        "action": {"namespace": "eval", "verb": verb, "ability": "eval/synthetic"},
        "target": {"kind": "synthetic", "ref": "eval:qa-rfx97", "environment": env},
        "params": {} if params is None else params,
        "magnitude": {"count": count},
        "axes": {"reversibility": reversibility, "blast_radius": blast,
                 "externality": externality},
        "approval": approval or {"present": False, "hold_id": None},
        "context": {"mode": "enforce", "note": SYNTH},
    }


def sid(tag):
    return "sess-qa97-%s-%s" % (RUN, tag)


def verdict(resp):
    return resp.get("decision", "?") if isinstance(resp, dict) else "?"


def rule(resp):
    return resp.get("rule", "?") if isinstance(resp, dict) else "?"


def banner(text):
    print("\n" + "=" * 78)
    print("== " + text)
    print("=" * 78)


def blocked(resp):
    """True if this verdict withheld the action (deny or require_approval)."""
    return verdict(resp) in ("deny", "require_approval")


# ---------------------------------------------------------------------------
# fingerprint — core exposes no version, so pin the build by behaviour first
# ---------------------------------------------------------------------------

def fingerprint():
    banner("FINGERPRINT  which build is this? (core exposes no version over HTTP)")
    facts = {}

    _, r = call("POST", "/v1/decide",
                envelope(sid("fp-read"), "read", count=25, env="dev",
                         reversibility="reversible", blast="single"),
                "fingerprint: verb='read' count=25")
    if "session_delete_budget" in rule(r):
        facts["r5_shape"] = "original SPEC §4.1 (pre-#82) — count added unconditionally"
    elif verdict(r) == "allow":
        facts["r5_shape"] = "budgets.rego (RFX-11 / #82) — deletions gated on verb"
    else:
        facts["r5_shape"] = "inconclusive (%s / %s)" % (verdict(r), rule(r))
    print("  verb='read' count=25            -> %-16s %s" % (verdict(r), rule(r)))

    _, r2 = call("POST", "/v1/decide",
                 envelope(sid("fp-ot"), "create", count=201, env="dev",
                          reversibility="reversible"),
                 "fingerprint: verb='create' count=201 (objects_touched)")
    facts["objects_touched_dimension"] = "cumulative_budget" in rule(r2) or \
                                         "budget" in rule(r2)
    print("  verb='create' count=201         -> %-16s %s" % (verdict(r2), rule(r2)))

    _, r3 = call("POST", "/v1/decide",
                 envelope(sid("fp-env"), "delete", 1, env="Prod",
                          reversibility="irreversible", blast="systemic"),
                 "fingerprint: environment='Prod' near-miss")
    facts["env_canon_89"] = blocked(r3)
    print("  environment='Prod' irrev+system -> %-16s %s" % (verdict(r3), rule(r3)))
    return facts


# ---------------------------------------------------------------------------
# A1 — RFX-86: environment compared exactly, near-misses fell to default_allow
# ---------------------------------------------------------------------------

NEAR_MISS_ENVS = [
    "Prod", "prod", "PROD", "Production", "PRODUCTION",
    "production ", " production", "production\t", "prod​",
    "production",  # NFKC-identical, different bytes
]


def attack_a1():
    banner("A1  RFX-86 — environment string compared exactly (fix #89)")
    # CONTROL: the exact spelling must be caught, or nothing below is readable.
    _, ctl = call("POST", "/v1/decide",
                  envelope(sid("a1-ctl"), "delete", 1, env="production",
                           reversibility="irreversible", blast="systemic"),
                  "A1 control: environment='production' irreversible+systemic")
    control_ok = blocked(ctl)
    print("  CONTROL 'production'            -> %-16s %s" % (verdict(ctl), rule(ctl)))
    if not control_ok:
        print("  !! control did not block — R3 is not in scope; A1 is inconclusive")

    evaded = []
    for i, e in enumerate(NEAR_MISS_ENVS):
        _, r = call("POST", "/v1/decide",
                    envelope(sid("a1-%d" % i), "delete", 1, env=e,
                             reversibility="irreversible", blast="systemic"),
                    "A1 evasion: environment=%r" % e)
        ok = blocked(r)
        print("  %-22r -> %-16s %s" % (e, verdict(r), rule(r)))
        if not ok:
            evaded.append(e)

    return finding(
        "A1", "RFX-86", "environment string compared exactly", "#89",
        control_ok, evaded, len(NEAR_MISS_ENVS),
        "an irreversible+systemic PRODUCTION action returns allow with no human",
    )


# ---------------------------------------------------------------------------
# A2 — RFX-85: delete-verb spelling slipped past R5.  FRAGMENTED (see trap 1).
# ---------------------------------------------------------------------------

DELETE_SPELLINGS = [
    "Delete", "DELETE", "remove", "destroy", "purge", "drop", "truncate",
    "rm", "hard_delete", "delete​", "delete ",
]


def _fragment(session, verb, chunk=5, calls=6, params=None, approval=None,
              label=""):
    """N × chunk in ONE session. Returns (verdicts, first_blocked_at_total)."""
    trail, tripped = [], None
    for i in range(1, calls + 1):
        _, r = call("POST", "/v1/decide",
                    envelope(session, verb, count=chunk, env="dev",
                             params=params, approval=approval),
                    "%s call %d/%d (chunk=%d, running=%d)"
                    % (label, i, calls, chunk, i * chunk))
        trail.append(verdict(r))
        if blocked(r) and tripped is None:
            tripped = i * chunk
    return trail, tripped


def attack_a2():
    banner("A2  RFX-85 — delete-verb spelling past R5, FRAGMENTED (fix #90)")
    print("  shape: 6 calls x count=5 = 30 deletes against a budget of %d"
          % DELETIONS_LIMIT)
    # CONTROL: the canonical spelling must trip the deletions budget.
    trail, tripped = _fragment(sid("a2-ctl"), "delete", label="A2 control verb='delete'")
    control_ok = tripped is not None
    print("  CONTROL 'delete'      -> %s  (blocked at %s)" % (trail, tripped))
    if not control_ok:
        print("  !! control never tripped — R5 not in scope; A2 is inconclusive")

    evaded = []
    for i, verb in enumerate(DELETE_SPELLINGS):
        t, trip = _fragment(sid("a2-%d" % i), verb,
                            label="A2 evasion verb=%r" % verb)
        print("  %-18r -> %s  (blocked at %s)" % (verb, t, trip))
        if trip is None:
            evaded.append(verb)

    return finding(
        "A2", "RFX-85", "delete-verb spelling slipped past R5", "#90",
        control_ok, evaded, len(DELETE_SPELLINGS),
        "30 deletes land under a 20-delete budget; fragmentation buys what "
        "SPEC §4.1 says it must not",
    )


# ---------------------------------------------------------------------------
# A3 — RFX-84: the approving human on /resolve was self-asserted (fix #90)
#
# Two DIFFERENT questions, reported separately (see trap 2):
#   A3-self  can the RAISER approve its own action?   (closed by #90 always)
#   A3-fab   can an unrelated human be FABRICATED?    (closed only when the
#            deployment binds credentials to principals)
# ---------------------------------------------------------------------------

def _raise_hold(session, agent_id="agent:qa-rfx97-synthetic",
                include_agent_id=True, on_behalf_of=None, label=""):
    """Raise a require_approval hold. Returns (hold_id, envelope_used)."""
    env_used = envelope(session, "delete", 1, env="production",
                        reversibility="irreversible", blast="broad",
                        agent_id=agent_id, include_agent_id=include_agent_id,
                        on_behalf_of=on_behalf_of)
    _, r = call("POST", "/v1/decide", env_used, "%s: raise hold" % label)
    return r.get("hold_id"), env_used


def _resolve(hold_id, ptype, pid, label=""):
    return call("POST", "/v1/holds/%s/resolve" % hold_id,
                {"decision": "approve", "principal": {"type": ptype, "id": pid},
                 "reason": SYNTH}, label)


def attack_a3():
    banner("A3  RFX-84 — the approving human on /resolve was self-asserted (fix #90)")

    # ---- A3-self: five self-approval shapes that all used to pass ----------
    # Each names the raiser a DIFFERENT way; #90 disqualifies agent.id,
    # agent.on_behalf_of and agent.session_id, bare or "type:"-prefixed,
    # under normalized compare.
    #
    # EVERY variant asserts principal.type == "human" ON PURPOSE.  The default
    # resolution policy is {"default": ["human"]}, so asserting "agent" or
    # "user" is refused at validation check 3 (`principal_type_not_allowed`)
    # and NEVER REACHES the four-eyes guard at check 5.  A probe that asserts
    # type "agent" therefore gets a 403 for the wrong reason and scores the
    # self-approval bypass as CLOSED without ever having tested it.  That is
    # exactly the fabricated finding this harness exists to avoid — so the
    # refusal REASON is asserted below, not merely the status code.
    variants = [
        ("bare-vs-prefixed", dict(agent_id="agent:cursor"), "cursor"),
        ("prefixed-both", dict(agent_id="agent:cursor"), "agent:cursor"),
        ("case-fold", dict(agent_id="svc-bot"), "SVC-BOT"),
        ("zero-width", dict(agent_id="svcbot"), "svc​bot"),
        ("no-agent-id", dict(include_agent_id=False), None),  # session_id fallback
        ("on-behalf-of", dict(agent_id="agent:runner",
                              on_behalf_of="user:alice"), "alice"),
    ]
    self_evaded, wrong_reason = [], []
    for i, (name, kw, pid) in enumerate(variants):
        session = sid("a3s-%d" % i)
        hold_id, _ = _raise_hold(session, label="A3-self/%s" % name, **kw)
        if not hold_id:
            print("  %-18s -> no hold raised; variant inconclusive" % name)
            continue
        approve_as = pid if pid is not None else session
        st, r = _resolve(hold_id, "human", approve_as,
                         "A3-self/%s: approve as human:%s" % (name, approve_as))
        err = r.get("error", "")
        # Refused for the RIGHT reason == the four-eyes guard actually fired.
        refused = st == 403 and err == "actor_is_approver"
        if st == 403 and err != "actor_is_approver":
            wrong_reason.append("%s(%s)" % (name, err))
        print("  %-18s approve as %-24s -> HTTP %s %s"
              % (name, "human:%s" % approve_as, st, err))
        if not refused:
            # It resolved. Does the approval actually unblock the action?
            _, rr = call("POST", "/v1/decide",
                         envelope(session, "delete", 1, env="production",
                                  reversibility="irreversible", blast="broad",
                                  approval={"present": True, "hold_id": hold_id}),
                         "A3-self/%s: resubmit with the self-approval" % name)
            print("      resubmit -> %s (%s)" % (verdict(rr), rule(rr)))
            if verdict(rr) == "allow":
                self_evaded.append(name)

    f_self = finding(
        "A3-self", "RFX-84", "raiser approves its own action (four-eyes bypass)",
        "#90", True, self_evaded, len(variants),
        "the party that raised an irreversible production action supplies its "
        "own human approval and receives allow",
    )
    # A variant refused for some OTHER reason never exercised the guard; say so
    # rather than banking it as a pass.
    if wrong_reason:
        f_self["state"] = "INCONCLUSIVE"
        f_self["wrong_reason_refusals"] = wrong_reason
        print("  !! refused for a reason OTHER than actor_is_approver: %s"
              % ", ".join(wrong_reason))
        print("     those variants never reached the four-eyes guard — not a pass")

    # ---- A3-fab: an unrelated human, fabricated out of nothing -------------
    # This is the config-dependent half. Report what the ARTEFACT does AND
    # whether verification is even configured here.
    session = sid("a3fab")
    hold_id, _ = _raise_hold(session, label="A3-fab")
    fab_evaded, detail = [], {}
    if hold_id:
        st, r = _resolve(hold_id, "human", "fabricated.approver@example.invalid",
                         "A3-fab: approve as a human that does not exist")
        print("  fabricated human            -> HTTP %s %s"
              % (st, r.get("error", "")))
        if st == 403:
            detail["mode"] = "refused (%s) — credential binding is configured" \
                             % r.get("error")
        else:
            detail["decided_by"] = r.get("decided_by")
            detail["decided_by_verified"] = r.get("decided_by_verified")
            detail["principal_source"] = r.get("principal_source")
            print("      decided_by=%r verified=%r source=%r"
                  % (r.get("decided_by"), r.get("decided_by_verified"),
                     r.get("principal_source")))
            _, rr = call("POST", "/v1/decide",
                         envelope(session, "delete", 1, env="production",
                                  reversibility="irreversible", blast="broad",
                                  approval={"present": True, "hold_id": hold_id}),
                         "A3-fab: resubmit with the fabricated approval")
            print("      resubmit -> %s (%s)" % (verdict(rr), rule(rr)))
            if verdict(rr) == "allow":
                fab_evaded.append("fabricated-human")

    f_fab = finding(
        "A3-fab", "RFX-84", "unrelated approving human fabricated in the body",
        "#90 (opt-in)", True, fab_evaded, 1,
        "core mints and persists decided_by:'human:<name>' for a human that "
        "never acted — the Art.14 record says oversight happened",
    )
    f_fab["detail"] = detail
    f_fab["config_dependent"] = True
    return [f_self, f_fab]


# ---------------------------------------------------------------------------
# A4 — RFX-127: approval:{present:true} with NO hold_id switches off all of R5
# ---------------------------------------------------------------------------

def attack_a4():
    banner("A4  RFX-127 — unverified approval:{present:true} disables R5 (fix #92)")
    # CONTROL: same traffic with no approval flag must trip the budget.
    trail, tripped = _fragment(sid("a4-ctl"), "delete",
                               label="A4 control (no approval flag)")
    control_ok = tripped is not None
    print("  CONTROL no approval        -> %s (blocked at %s)" % (trail, tripped))

    evaded = []
    # The evasion: present:true, NO hold_id. decide.py validates a hold only
    # when present AND hold_id are both set, so this skips validation entirely
    # and still reaches OPA with the flag set.
    shapes = [
        ("present-only", {"present": True}),
        ("present+null-hold", {"present": True, "hold_id": None}),
        ("present+bogus-hold", {"present": True, "hold_id": ""}),
    ]
    for i, (name, appr) in enumerate(shapes):
        t, trip = _fragment(sid("a4-%d" % i), "delete", approval=appr,
                            label="A4 evasion %s" % name)
        print("  %-20s -> %s (blocked at %s)" % (name, t, trip))
        if trip is None:
            evaded.append(name)

    # Does it disable OTHER dimensions too, not just deletions? (money)
    t_m, trip_m = _fragment(sid("a4-money"), "transact", chunk=1, calls=4,
                            params={"amount": 4000, "currency": "EUR"},
                            approval={"present": True},
                            label="A4 evasion money dimension")
    print("  money dimension too   -> %s (blocked at %s)" % (t_m, trip_m))
    if trip_m is None:
        evaded.append("money-dimension-also-off")

    f = finding(
        "A4", "RFX-127", "unverified approval:{present:true} disables all of R5",
        "#92", control_ok, evaded, len(shapes) + 1,
        "one unverified boolean in the envelope switches off every budget "
        "dimension, and the audit record carries no approval field, so the "
        "bypass leaves no trace",
    )
    # R2/R3 do not read approval — confirm the flag does NOT disable them,
    # so the report states the blast radius accurately.
    _, r23 = call("POST", "/v1/decide",
                  envelope(sid("a4-r3"), "delete", 1, env="production",
                           reversibility="irreversible", blast="systemic",
                           approval={"present": True}),
                  "A4 scope: does the flag also disable R3?")
    f["detail"] = {"r3_still_fires": blocked(r23),
                   "r3_verdict": verdict(r23), "r3_rule": rule(r23)}
    print("  scope: R3 with the flag set -> %s (%s)" % (verdict(r23), rule(r23)))
    return f


# ---------------------------------------------------------------------------
# A5 — RFX-133: money budget evaded by OMITTING params.currency
# ---------------------------------------------------------------------------

def attack_a5():
    banner("A5  RFX-133 — money budget evaded by omitting params.currency (fix #92)")
    print("  shape: 6 x amount=4000 = 24,000 against a money budget of %d"
          % MONEY_LIMIT)
    # CONTROL: with a currency the ledger accumulates and the budget trips.
    t_c, trip_c = _fragment(sid("a5-ctl"), "transact", chunk=1, calls=6,
                            params={"amount": 4000, "currency": "EUR"},
                            label="A5 control (amount+currency)")
    control_ok = trip_c is not None
    print("  CONTROL amount+currency  -> %s (blocked at call %s)" % (t_c, trip_c))
    if not control_ok:
        print("  !! control never tripped — money dimension not in scope")

    evaded = []
    # The evasion is an ABSENT field, which is why it survives _normalize_token:
    # there is no token to normalize. ledger.py accumulates into
    # amount_by_currency only when currency AND amount are both present.
    t_e, trip_e = _fragment(sid("a5-nocur"), "transact", chunk=1, calls=6,
                            params={"amount": 4000},
                            label="A5 evasion (amount, NO currency)")
    print("  EVASION no currency      -> %s (blocked at call %s)" % (t_e, trip_e))
    if trip_e is None:
        evaded.append("currency-omitted")

    # Blank/whitespace currency: falsy, so the same ledger gate skips it.
    for name, cur in (("empty-string", ""), ("whitespace", " "), ("null", None)):
        t, trip = _fragment(sid("a5-%s" % name), "transact", chunk=1, calls=6,
                            params={"amount": 4000, "currency": cur},
                            label="A5 evasion currency=%r" % cur)
        print("  currency=%-14r -> %s (blocked at call %s)" % (cur, t, trip))
        if trip is None:
            evaded.append("currency-%s" % name)

    f = finding(
        "A5", "RFX-133", "money budget evaded by omitting params.currency", "#92",
        control_ok, evaded, 4,
        "24,000 of spend clears a 5,000 budget because an absent field means "
        "the ledger never accumulates it",
    )

    # SECOND HALF of the same ticket: cumulative_for('money') sums
    # amount_by_currency ACROSS currencies as one scalar — it adds EUR to JPY.
    # Report it separately: it is an unsoundness, not an evasion, and it can
    # only be seen by mixing.
    t_mix, trip_mix = _fragment(sid("a5-mix"), "transact", chunk=1, calls=3,
                                params={"amount": 2000, "currency": "JPY"},
                                label="A5 unit-error: JPY leg")
    _, rmix = call("POST", "/v1/decide",
                   envelope(sid("a5-mix"), "transact", 1, env="dev",
                            params={"amount": 2000, "currency": "EUR"}),
                   "A5 unit-error: EUR on top of the JPY ledger")
    f["detail"] = {
        "mixed_currency_summed_as_one_scalar": blocked(rmix) or trip_mix is not None,
        "jpy_leg": t_mix, "eur_on_top": "%s (%s)" % (verdict(rmix), rule(rmix)),
        "note": "cumulative_for('money') = sum(amount_by_currency.values()); "
                "JPY 6000 + EUR 2000 is compared to one 5000 limit — a unit "
                "error, not a canonicalisation one",
    }
    print("  unit error: JPY %s then EUR -> %s (%s)"
          % (t_mix, verdict(rmix), rule(rmix)))
    return f


# ---------------------------------------------------------------------------
# A6 — RFX-138: the approval binds the ACTION, not the party it was granted to
#
# A3 asks "can the raiser approve itself".  A6 asks the other half, which no
# check covered: once a human HAS approved, WHO may spend that approval?
# canonical_hash() projects {action, axes, magnitude, target} and check 7 binds
# `params` — the whole `agent` block is outside both, so an approval was
# spendable by any caller that knew the hold_id.
#
# Two evasions and two OVER-BLOCK controls.  The over-block controls matter as
# much as the evasions here: a fix that binds the agent block too tightly turns
# an agent restart (new session_id) into a wrong DENY on an action a human
# already approved, and a wrong DENY on an approved irreversible action is a
# product failure of its own.  A6 fails either way round.
# ---------------------------------------------------------------------------

def _resubmit(session, hold_id, label, **agent_kw):
    """Resubmit the A6 action against `hold_id`, varying ONLY the agent block.

    Every other block is byte-identical to the raise, so check 5
    (canonical_hash) and check 7 (params) both pass and the verdict is
    attributable to the agent identity alone.
    """
    env_used = envelope(session, "delete", 1, env="production",
                        reversibility="irreversible", blast="broad",
                        approval={"present": True, "hold_id": hold_id},
                        **agent_kw)
    _, r = call("POST", "/v1/decide", env_used, label)
    return r


def _approved_hold(session, label, **agent_kw):
    """Raise a hold as `agent_kw` and have a human approve it.

    Returns (hold_id, ok).  The approver is a third party, so check 6
    (actor_is_approver) cannot be what refuses any resubmission below.
    """
    hold_id, _ = _raise_hold(session, label=label, **agent_kw)
    if not hold_id:
        return None, False
    st, r = _resolve(hold_id, "human", "a6-manager@rfx138.invalid",
                     "%s: human approves" % label)
    if st != 200:
        print("  %-26s !! resolve refused HTTP %s %s — variant inconclusive"
              % (label, st, r.get("error", "")))
        return hold_id, False
    return hold_id, True


def attack_a6():
    banner("A6  RFX-138 — a human's approval is spendable by a DIFFERENT agent")

    ALPHA = "agent:a6-alpha"
    BETA = "agent:a6-beta"

    # CONTROL: the agent the human actually approved must be able to spend it.
    # Without this an "allow" below is unreadable and a "deny" could just mean
    # the hold chain is broken on this build.
    s_ctl = sid("a6-ctl")
    h_ctl, ok_ctl = _approved_hold(s_ctl, "A6 control", agent_id=ALPHA)
    ctl_resp = _resubmit(s_ctl, h_ctl, "A6 control: the APPROVED agent resubmits",
                         agent_id=ALPHA) if ok_ctl else {}
    control_ok = ok_ctl and verdict(ctl_resp) == "allow"
    print("  CONTROL approved agent spends -> %-16s %s"
          % (verdict(ctl_resp), rule(ctl_resp)))
    if not control_ok:
        print("  !! the approved agent could not spend its own approval — the "
              "hold chain is not in scope; A6 is inconclusive")

    # ---- the evasions ------------------------------------------------------
    # Each gets its OWN hold: a spent approval is consumed, so sharing one
    # would make every variant after the first read as "consumed".
    variants = [
        # name, raise kwargs, resubmit kwargs, what it proves
        ("agent-substitution",
         dict(agent_id=ALPHA), dict(agent_id=BETA),
         "a different agent, different session, spends it"),
        ("obo-substitution",
         dict(agent_id="agent:a6-shared-bot", on_behalf_of="alice@rfx138.invalid"),
         dict(agent_id="agent:a6-shared-bot", on_behalf_of="bob@rfx138.invalid"),
         "same bot, same session, acting for a DIFFERENT person"),
        ("obo-added",
         dict(agent_id="agent:a6-shared-bot"),
         dict(agent_id="agent:a6-shared-bot", on_behalf_of="bob@rfx138.invalid"),
         "an on_behalf_of the human never saw is added at resubmission"),
        ("session-only-substitution",
         dict(include_agent_id=False), dict(include_agent_id=False),
         "SPEC-minimal envelope (session_id only): the guard must not be "
         "vacuous when agent.id is absent"),
    ]

    # `burned` is scored separately from `evaded`: a build that refuses the
    # substitute but consumes the hold anyway is not evadable, it is a build
    # where any caller can destroy a human's approval on demand.
    evaded, burned, detail = [], [], {}
    for i, (name, raise_kw, sub_kw, _why) in enumerate(variants):
        s_raise = sid("a6-%d-raise" % i)
        # A different SESSION for the substitute is part of the attack for
        # every variant except obo-substitution, where the point is that
        # nothing at all changes except the person named.
        s_sub = s_raise if name == "obo-substitution" else sid("a6-%d-sub" % i)
        h, ok = _approved_hold(s_raise, "A6/%s" % name, **raise_kw)
        if not ok:
            print("  %-26s -> inconclusive (no approved hold)" % name)
            continue
        r = _resubmit(s_sub, h, "A6/%s: substitute spends the approval" % name,
                      **sub_kw)
        print("  %-26s -> %-16s %s" % (name, verdict(r), rule(r)))
        if verdict(r) == "allow":
            evaded.append(name)

        # THE SECOND HALF OF THE DEFECT, AND IT IS PROBED WHETHER OR NOT THE
        # FIRST HALF LANDED.  A hold is single-use, so the question "can the
        # agent the human ACTUALLY approved still act?" has a different answer
        # for each outcome above, and both answers matter:
        #
        #   substitution ALLOWED  -> the hijack also consumed the hold, so the
        #                            approved agent is refused
        #                            `reeflex_hold_consumed`.  The evasion is
        #                            a denial of service against the
        #                            legitimate actor as well as a hijack.
        #   substitution DENIED   -> the refusal must return BEFORE
        #                            mark_consumed().  A fix that refuses BETA
        #                            and still burns the hold has closed the
        #                            hijack and KEPT the denial of service: the
        #                            human's decision is destroyed by an
        #                            attacker's failed attempt, and the
        #                            approved agent has to get a second human
        #                            to approve the same action.
        #
        # An earlier version of this row only ran the follow-up on the ALLOW
        # branch, which scored that half-fix CLOSED — a gate reporting "safe to
        # cut a release" over an approval any caller can destroy at will.  It
        # is a wrong DENY on an already-approved action, not an evasion, so it
        # scores OVER-BLOCKING (which also fails the exit code) rather than
        # being folded into the hijack count.
        back = _resubmit(s_raise, h,
                         "A6/%s: the APPROVED agent tries afterwards" % name,
                         **raise_kw)
        detail["%s_approved_agent_afterwards" % name] = "%s (%s)" % (
            verdict(back), back.get("reason", ""))
        print("      then the APPROVED agent          -> %-16s %s"
              % (verdict(back), back.get("reason", "") or rule(back)))
        if verdict(r) != "allow" and verdict(back) != "allow":
            burned.append("%s(%s)" % (name, back.get("reason", "")))

    # `fixed_in` names the GUARD, not a PR number: two competing PRs
    # implemented this row's fix (#95 and #96, compared in dev-1--022) and a
    # gate that hardcodes the losing number goes stale the moment one merges.
    f = finding(
        "A6", "RFX-138", "a human's approval is spendable by a different agent",
        "check 8 (actor key)", control_ok, evaded, len(variants),
        "a human approves agent A's irreversible production delete and agent B "
        "executes it; core's audit line for that allow is byte-identical to a "
        "legitimate resubmission, and A is locked out of what it was approved for",
    )

    # ---- OVER-BLOCK controls: legitimate resubmissions must still pass -----
    # A fix that binds the agent block by raw equality fails these, and that
    # failure is a wrong DENY on an approved irreversible action.
    overblocked = []
    for name, raise_kw, sub_kw, same_session in [
        ("same-agent-new-session", dict(agent_id=ALPHA), dict(agent_id=ALPHA), False),
        ("same-agent-case-folded", dict(agent_id="agent:A6-Mixed-Case"),
         dict(agent_id="agent:a6-mixed-case"), True),
    ]:
        s_raise = sid("a6-ob-%s" % name)
        s_sub = s_raise if same_session else sid("a6-ob-%s-2" % name)
        h, ok = _approved_hold(s_raise, "A6-overblock/%s" % name, **raise_kw)
        if not ok:
            continue
        r = _resubmit(s_sub, h, "A6-overblock/%s: legitimate resubmission" % name,
                      **sub_kw)
        print("  OVER-BLOCK %-16s -> %-16s %s" % (name, verdict(r), rule(r)))
        if verdict(r) != "allow":
            overblocked.append("%s(%s)" % (name, r.get("reason", "")))
    detail["over_blocked_legitimate_resubmissions"] = overblocked
    detail["hold_burned_by_a_refused_substitution"] = burned
    if burned:
        print("  !! a REFUSED substitution still consumed the hold: %s"
              % ", ".join(burned))
        print("     half a fix — the hijack is closed and the denial of "
              "service against the approved agent is not: any caller holding "
              "the hold_id can destroy a human's approval on demand")
    if overblocked:
        print("  !! a legitimate resubmission was REFUSED: %s"
              % ", ".join(overblocked))
        print("     that is a wrong DENY on an action a human already approved")
    if overblocked or burned:
        f["state"] = "STILL EXPLOITABLE" if evaded else "OVER-BLOCKING"
    f["detail"] = detail
    return f


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def finding(code, ticket, name, fixed_in, control_ok, evaded, total, impact):
    if not control_ok:
        state = "INCONCLUSIVE"
    elif evaded:
        state = "STILL EXPLOITABLE"
    else:
        state = "CLOSED"
    return {"code": code, "ticket": ticket, "name": name, "fixed_in": fixed_in,
            "control_blocked": control_ok, "variants_tried": total,
            "variants_evaded": evaded, "state": state, "impact": impact}


ATTACKS = {"A1": attack_a1, "A2": attack_a2, "A3": attack_a3,
           "A4": attack_a4, "A5": attack_a5, "A6": attack_a6}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    which = [c.strip().upper() for c in args.only.split(",") if c.strip()] \
        or list(ATTACKS)

    print("reeflex-core RFX-97 release gate — every known evasion, one artefact")
    print("target : %s" % BASE)
    print("run    : %s" % RUN)
    print("attacks: %s" % ", ".join(which))

    facts = fingerprint()

    findings = []
    for code in which:
        out = ATTACKS[code]()
        findings.extend(out if isinstance(out, list) else [out])

    banner("VERDICT TABLE")
    print("%-9s %-9s %-14s %-18s %s"
          % ("attack", "ticket", "fixed in", "verdict", "evaded variants"))
    print("-" * 78)
    for f in findings:
        print("%-9s %-9s %-14s %-18s %s"
              % (f["code"], f["ticket"], f["fixed_in"], f["state"],
                 "%d/%d %s" % (len(f["variants_evaded"]), f["variants_tried"],
                               ",".join(f["variants_evaded"][:3]) or "—")))

    # RFX-84 is reported as two rows but is ONE ticket; count tickets, not rows.
    tickets = {}
    for f in findings:
        prev = tickets.get(f["ticket"])
        # worst state wins for a ticket split across rows
        rank = {"CLOSED": 0, "INCONCLUSIVE": 1, "OVER-BLOCKING": 2,
                "STILL EXPLOITABLE": 3}
        if prev is None or rank[f["state"]] > rank.get(prev, 0):
            tickets[f["ticket"]] = f["state"]
    closed = [t for t, s in tickets.items() if s == "CLOSED"]
    open_ = [t for t, s in tickets.items() if s == "STILL EXPLOITABLE"]
    incon = [t for t, s in tickets.items() if s == "INCONCLUSIVE"]
    # A fix that refuses a LEGITIMATE resubmission is its own release blocker:
    # it is a wrong DENY on an action a human already approved.  It is not an
    # evasion, so it gets its own row rather than being folded into either.
    overblock = [t for t, s in tickets.items() if s == "OVER-BLOCKING"]

    print("\nA release cut from this artefact would close %d of %d:"
          % (len(closed), len(tickets)))
    print("  closed            : %s" % (", ".join(sorted(closed)) or "none"))
    print("  still exploitable : %s" % (", ".join(sorted(open_)) or "none"))
    if incon:
        print("  INCONCLUSIVE      : %s" % ", ".join(sorted(incon)))
    if overblock:
        print("  OVER-BLOCKING     : %s  (wrong DENY on an approved action)"
              % ", ".join(sorted(overblock)))
    print("\nfingerprint: %s" % json.dumps(facts))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"base": BASE, "run": RUN, "fingerprint": facts,
                       "findings": findings, "tickets": tickets,
                       "transcript": _TRANSCRIPT}, fh, indent=2)
        print("wrote %s (%d calls)" % (args.json_out, len(_TRANSCRIPT)))

    # Exit code = evasions still exploitable + over-blocking fixes, so CI can
    # gate on it: both are reasons not to cut a release from this artefact.
    return len(open_) + len(overblock)


if __name__ == "__main__":
    sys.exit(main())
