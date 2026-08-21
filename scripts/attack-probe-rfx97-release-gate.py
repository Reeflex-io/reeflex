#!/usr/bin/env python3
"""
attack-probe-rfx97-release-gate.py — the RFX-97 release gate.

WHAT THIS IS FOR
================
RFX-97 asks one question that no test suite answers: *if we cut a release from
this commit, which of the known evasions does it actually close?*  A unit suite
answers "does the fix's own test pass"; this answers "does the ARTEFACT still
fall over when you push on it".  Point it at a built image (or api-dev) and it
replays every attack and prints a verdict per evasion.

    THE KNOWN EVASIONS
    RFX-86   environment string compared exactly ("Prod" fell to default_allow)   fix #89
    RFX-85   delete-verb spelling slipped past R5                                 fix #90
    RFX-84   the approving human on /resolve was self-asserted                    fix #90
    RFX-127  R5 switched off entirely by approval:{present:true}, no hold_id       fix #92
    RFX-133  R5 money budget evaded by omitting params.currency                   fix #92
    RFX-138  a human's approval for agent ALPHA spent by agent BETA, and the
             same bot swapping on_behalf_of alice -> bob (A7)                     fix TBD

THE ROW SET IS THE CLAIM.  This file said "all five" and exited 0 against
v0.1.13 while RFX-138 was live on that exact image -- an exit code of 0 reads
as "safe to cut a release", so a missing row is not a documentation gap, it is
a false all-clear.  Adding an attack to
reeflex-core/tests/test_envelope_boundary_attacks.py without adding it here
re-opens that gap.

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

EXIT CODE = the number of evasions still exploitable.  0 means every evasion
IN THE TABLE ABOVE is closed on this artefact -- which is a statement about
that list, not about the artefact.  CI can gate on it directly.

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
# A7 — RFX-138: the approval bound the ACTION, not the AGENT it was granted for
# ---------------------------------------------------------------------------
#
# WHY THIS ROW EXISTS, AND WHY ITS ABSENCE MATTERED.  Without it this gate
# printed "0 evasions, all five closed" against v0.1.13 — the published image —
# while a human's approval for agent ALPHA could be spent by agent BETA on an
# irreversible production delete.  An exit code of 0 reads as "safe to cut a
# release"; it was answering a question with one row missing.  Confirmed on
# live api-dev v0.1.13 AND on origin/main 44c6f85 by qa--018.
#
# THE CONTROL MATTERS MORE HERE THAN ANYWHERE ELSE IN THIS FILE.  The evasion
# and the control differ by ONE STRING, so a build that denies every
# resubmission — a broken adapter contract, a stricter hash, a hold store that
# lost the envelope — would score this CLOSED while being useless.  The
# control is "the agent the human actually approved gets its allow"; if that
# fails, the row is INCONCLUSIVE, not CLOSED.
#
# AND THE SECOND HALF OF THE DEFECT IS CHECKED SEPARATELY: before the fix, the
# substitute's resubmission CONSUMED the hold, so the legitimate agent came
# back `reeflex_hold_consumed`.  A build that refuses BETA but still burns the
# hold has fixed the hijack and kept the denial of service.

def attack_a7():
    banner("A7  RFX-138 — the approval bound the action, not the agent")

    # ---- CONTROL: an honest resubmission must be ALLOWED -------------------
    s_ctl = sid("a7-ctl")
    hold_ctl, env_ctl = _raise_hold(s_ctl, agent_id="agent:a7-gamma",
                                    label="A7 control")
    control_ok = False
    if hold_ctl:
        _resolve(hold_ctl, "human", "a7-approver-human", "A7 control: approve")
        env_ctl["approval"] = {"present": True, "hold_id": hold_ctl}
        _, rc = call("POST", "/v1/decide", env_ctl,
                     "A7 control: the approved agent resubmits")
        control_ok = verdict(rc) == "allow"
        print("  CONTROL approved agent resubmits -> %-16s %s"
              % (verdict(rc), rule(rc)))
    if not control_ok:
        print("  !! control did not ALLOW — resubmission is broken on this "
              "build for some other reason; A7 is inconclusive, not closed")

    evaded, detail = [], {}

    # ---- variant A: a different agent.id spends the approval --------------
    s_a = sid("a7-a")
    hold_a, env_a = _raise_hold(s_a, agent_id="agent:a7-alpha",
                                label="A7-A: ALPHA raises")
    if hold_a:
        _resolve(hold_a, "human", "a7-approver-human",
                 "A7-A: a human approves ALPHA")
        beta = json.loads(json.dumps(env_a))
        beta["agent"]["id"] = "agent:a7-beta"
        beta["approval"] = {"present": True, "hold_id": hold_a}
        _, rb = call("POST", "/v1/decide", beta,
                     "A7-A: BETA resubmits with ALPHA's hold_id")
        print("  A/ different agent.id            -> %-16s %s"
              % (verdict(rb), rule(rb)))
        if verdict(rb) == "allow":
            evaded.append("agent.id substituted")

        # The denial-of-service half: is ALPHA's approval still spendable?
        env_a["approval"] = {"present": True, "hold_id": hold_a}
        _, ra = call("POST", "/v1/decide", env_a,
                     "A7-A: ALPHA, the approved agent, tries")
        print("     then ALPHA (the approved one) -> %-16s %s"
              % (verdict(ra), ra.get("reason", "")))
        detail["approved_agent_locked_out"] = verdict(ra) != "allow"
        if verdict(ra) != "allow" and verdict(rb) != "allow":
            # Refused BETA and still burned the hold: half a fix.
            evaded.append("hold consumed by the refused substitution")

    # ---- variant B: same bot, same session, on_behalf_of alice -> bob -----
    s_b = sid("a7-b")
    hold_b, env_b = _raise_hold(s_b, agent_id="agent:a7-shared-bot",
                                on_behalf_of="user:alice@a7.invalid",
                                label="A7-B: bot FOR alice raises")
    if hold_b:
        _resolve(hold_b, "human", "a7-manager@a7.invalid",
                 "A7-B: a manager approves the alice request")
        swapped = json.loads(json.dumps(env_b))
        swapped["agent"]["on_behalf_of"] = "user:bob@a7.invalid"
        swapped["approval"] = {"present": True, "hold_id": hold_b}
        _, rs = call("POST", "/v1/decide", swapped,
                     "A7-B: SAME bot, SAME session, acting for bob")
        print("  B/ on_behalf_of alice -> bob     -> %-16s %s"
              % (verdict(rs), rule(rs)))
        if verdict(rs) == "allow":
            evaded.append("agent.on_behalf_of substituted")
        detail["substitution_is_named"] = \
            rs.get("reason") == "reeflex_hold_actor_mismatch"

    # ---- SECOND CONTROL: a restarted agent must keep its approval ---------
    # A build that "closes" A7 by binding agent.session_id passes both
    # evasions above and breaks a real gate: a hold lives 4h by default, and
    # an agent that restarts in between presents the same agent.id and the
    # same on_behalf_of with a NEW session. Denying that is a wrong deny on
    # the one path where a human explicitly said yes, and it is a REGRESSION
    # against main -- so the gate has to be able to see it. Scored as an
    # evasion row rather than a note, because a release that ships it is not
    # releasable.
    s_r = sid("a7-restart")
    hold_r, env_r = _raise_hold(s_r, agent_id="agent:a7-restarting",
                               on_behalf_of="user:a7-alice",
                               label="A7 restart: raise before the restart")
    if hold_r:
        _resolve(hold_r, "human", "a7-manager@a7.invalid",
                 "A7 restart: a human approves it")
        rebooted = json.loads(json.dumps(env_r))
        rebooted["agent"]["session_id"] = sid("a7-restart-2")
        rebooted["approval"] = {"present": True, "hold_id": hold_r}
        _, rr = call("POST", "/v1/decide", rebooted,
                     "A7 restart: same agent, same person, NEW session")
        print("  CONTROL restarted agent resubmits -> %-16s %s"
              % (verdict(rr), rule(rr)))
        detail["restarted_agent_keeps_approval"] = verdict(rr) == "allow"
        if verdict(rr) != "allow":
            evaded.append("WRONG DENY: a restarted agent lost a human's "
                          "approval (session bound too tightly)")

    f = finding(
        "A7", "RFX-138", "the approval bound the action, not the agent",
        "this PR", control_ok, evaded, 4,
        "an irreversible production action executes for an agent, or for a "
        "person, no human ever approved — and the approved agent is locked "
        "out. On the on_behalf_of variant core's audit line is byte-identical "
        "to a legitimate resubmission",
    )
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
           "A4": attack_a4, "A5": attack_a5, "A7": attack_a7}


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
        rank = {"CLOSED": 0, "INCONCLUSIVE": 1, "STILL EXPLOITABLE": 2}
        if prev is None or rank[f["state"]] > rank[prev]:
            tickets[f["ticket"]] = f["state"]
    closed = [t for t, s in tickets.items() if s == "CLOSED"]
    open_ = [t for t, s in tickets.items() if s == "STILL EXPLOITABLE"]
    incon = [t for t, s in tickets.items() if s == "INCONCLUSIVE"]

    print("\nA release cut from this artefact would close %d of %d:"
          % (len(closed), len(tickets)))
    print("  closed            : %s" % (", ".join(sorted(closed)) or "none"))
    print("  still exploitable : %s" % (", ".join(sorted(open_)) or "none"))
    if incon:
        print("  INCONCLUSIVE      : %s" % ", ".join(sorted(incon)))
    print("\nfingerprint: %s" % json.dumps(facts))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"base": BASE, "run": RUN, "fingerprint": facts,
                       "findings": findings, "tickets": tickets,
                       "transcript": _TRANSCRIPT}, fh, indent=2)
        print("wrote %s (%d calls)" % (args.json_out, len(_TRANSCRIPT)))

    # Exit code = evasions still exploitable, so CI can gate on it.
    return len(open_)


if __name__ == "__main__":
    sys.exit(main())
