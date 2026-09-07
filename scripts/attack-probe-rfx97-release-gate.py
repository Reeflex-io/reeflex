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

A6 SCORES FOUR OUTCOMES, NOT TWO, and that is the lesson of the row rather
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
  * REFUSED BY SOMETHING ELSE — the substitution is denied, but not with
    `reeflex_hold_actor_mismatch`.  The hijack did not land; the guard this row
    names in its `fixed_in` column was not shown to be what stopped it, and may
    not have been reached at all.  Scored INCONCLUSIVE, because "was it blocked"
    and "was the guard exercised" are different questions and qa--016 already
    answered the first one for the second on A3: five self-approval variants
    scored CLOSED on a 403 that was `principal_type_not_allowed`.

APPROVER CREDENTIALS — READ THIS BEFORE RUNNING IT (RFX-179)
===========================================================
Since core 0.2.0 `REEFLEX_REQUIRE_VERIFIED_APPROVER` defaults to true and the
shipped image sets it, so the approving principal comes from the CREDENTIAL the
resolve call was made with and an approver core cannot verify is refused
`403 principal_not_verified`.  Two of the six rows (A3-self, A6) need an
APPROVED hold as their precondition, so against the configuration we actually
ship this harness could not build one, both rows reported INCONCLUSIVE — and
INCONCLUSIVE was in neither term of the exit code.  The gate printed
"still exploitable: none" and returned 0 over two attacks that never ran.

Both halves of that are fixed here:

  * `REEFLEX_PROBE_RESOLVER_MAP` is the HOST path of the JSON file the core
    under test reads as `REEFLEX_RESOLVER_TOKENS`.  Given it, the probe does
    what an operator does — it ISSUES a bearer token per approver and resolves
    holds with it.  The map is re-read per request, so no restart is needed;
    existing bindings are preserved and the file is restored on the way out.
  * INCONCLUSIVE now FAILS the exit code.  An attack that did not run is a
    reason not to cut a release.

Nothing is switched off to achieve this, and the A3-fab row is what proves it:
`no-credential` is deliberately never provisioned and must still be refused,
and `mismatch` holds a REAL approver's credential while asserting somebody
else's name, which must be refused `principal_mismatch`.  Without the ability
to mint, that second attack cannot be run at all.

USAGE
=====
    # against a container built from the commit under test
    docker build -t reeflex-core:under-test .
    mkdir -p /tmp/rfx97 && echo '{}' > /tmp/rfx97/resolver-tokens.json
    docker run -d --name ut -p 18391:8080 -e REEFLEX_AUTH_TOKEN=t \
        -e REEFLEX_RESOLVER_TOKENS=/etc/reeflex/resolver-tokens.json \
        -v /tmp/rfx97:/etc/reeflex:ro reeflex-core:under-test
    REEFLEX_PROBE_BASE=http://127.0.0.1:18391 REEFLEX_PROBE_TOKEN=t REEFLEX_PROBE_PACE=0 \
        REEFLEX_PROBE_RESOLVER_MAP=/tmp/rfx97/resolver-tokens.json \
        python3 scripts/attack-probe-rfx97-release-gate.py

    Mount the DIRECTORY, not the file: the probe replaces the map atomically
    (os.replace), which changes the inode, and a file bind-mount would pin the
    container to the old one.  `:ro` is correct — core only ever reads it.

    # against api-dev (published eval token, paced for the 429 limiter)
    python3 scripts/attack-probe-rfx97-release-gate.py

    Without REEFLEX_PROBE_RESOLVER_MAP the probe does NOT fall back to
    asserting identities.  Against a core that requires verified approvers the
    affected rows stay INCONCLUSIVE and the run exits non-zero, which is the
    honest answer: this harness could not attack that build.

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

#: Host path of the JSON map the core under test reads as
#: REEFLEX_RESOLVER_TOKENS.  See the "approver credentials" section below for
#: why the probe writes it rather than being handed a fixed set of tokens.
RESOLVER_MAP = os.environ.get("REEFLEX_PROBE_RESOLVER_MAP", "")

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

def call(method: str, path: str, body=None, label: str = "", bearer=None):
    """One paced HTTP call. Returns (status, parsed_body).

    `bearer` overrides the gate token for THIS call only.  Since 0.2.0 the
    approving principal is taken from the credential and not from the request
    body, so "approve as Alice" is not a field any more — it is a different
    Authorization header.  A probe with one token can only ever approve as one
    principal, which is the whole of RFX-179.
    """
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    sent = TOKEN if bearer is None else bearer
    if sent:
        req.add_header("Authorization", "Bearer " + sent)
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

    # The transcript names the principal the credential is bound to, never the
    # credential: this file's output is attached to round reports.
    _TRANSCRIPT.append({"label": label, "method": method, "path": path,
                        "as": _PRINCIPAL_OF.get(sent, "gate-token"),
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


# ---------------------------------------------------------------------------
# approver credentials — RFX-179
#
# THE PROBLEM THIS SOLVES.  Since 0.2.0 REEFLEX_REQUIRE_VERIFIED_APPROVER
# defaults to true, and that is now baked into the shipped image (Dockerfile).
# At that default core takes the approving principal from the CREDENTIAL the
# resolve call was made with and refuses an assertion it cannot verify
# (403 principal_not_verified).  The probe held exactly one bearer token, so it
# could not construct an approved hold at all — and A3-self and A6 both NEED
# one as a precondition.  Both rows went INCONCLUSIVE, and INCONCLUSIVE did not
# move the exit code, so the gate printed "still exploitable: none" and returned
# 0 while two of the six attacks never executed.  That is RFX-179.
#
# THE ROUTE, AND WHY IT DOES NOT WEAKEN WHAT THE FLAG ASSERTS.  The flag
# asserts one thing: the approver's identity comes from a credential the
# OPERATOR issued, not from the request body.  So the probe stops trying to
# assert identities and starts doing what an operator does — it ISSUES a
# credential per approver.  `REEFLEX_RESOLVER_TOKENS` accepts a path to a JSON
# file and `principal.principal_for_token()` re-reads it on every request
# (deliberately, so a map can be rotated without a restart), so a bind-mounted
# map can be provisioned DURING the run.  Every approval the probe obtains
# below is therefore a genuinely verified one: it travels as its own bearer
# token, core resolves the principal from that token, and
# `decided_by_verified` comes back true.  Nothing is asserted and nothing is
# switched off.
#
# WHAT KEEPS THIS HONEST — the negative controls, which are the reason this is
# a gate and not a fixture:
#   * A3-fab NEVER gets a credential.  The fabricated human is asserted with
#     the plain gate token and must still be refused.  If provisioning had
#     quietly weakened verification, this row would flip to CLOSED-by-accident
#     and the gate would say so.
#   * A3-fab gains a SECOND, sharper variant that only exists because
#     provisioning does: hold a REAL approver's credential and assert somebody
#     else's identity.  That must be refused `principal_mismatch`.  A probe
#     that cannot mint a real credential cannot run that attack at all.
#   * If no map path is configured the probe does NOT fall back to asserting
#     identities.  It says so, and the affected rows stay INCONCLUSIVE — which
#     now fails the exit code.
# ---------------------------------------------------------------------------

#: token -> principal, exactly the shape core reads.  One source of truth: the
#: probe writes this dict out verbatim, so there is no inverted-map bug to have.
_TOKEN_MAP: dict[str, dict] = {}
#: token -> "type:id", for the transcript and for error messages.
_PRINCIPAL_OF: dict[str, str] = {}
#: "type:id" -> token, so asking for the same approver twice reuses its
#: credential rather than issuing a second one for the same person.
_CREDENTIAL_OF: dict[str, str] = {}
#: Set when provisioning was asked for and could not be done, so the reason is
#: reported once at the top instead of per row.
PROVISION_ERROR = ""
#: The map's contents before this run touched it, restored on the way out.
_MAP_ORIGINAL: str | None = None
#: What core said about every approval this run obtained with a bound
#: credential.  Checked at the end: see `_approve_verified`.
_VERIFICATION_READBACK: list[dict] = []


def can_provision() -> bool:
    """True if this run can issue approver credentials."""
    return bool(RESOLVER_MAP) and not PROVISION_ERROR


def provision_init() -> None:
    """Adopt the map that is already there, rather than replacing it.

    THIS IS NOT TIDINESS.  The file core reads as REEFLEX_RESOLVER_TOKENS is
    shared: CI points this harness and the four WordPress live-core harnesses
    at the SAME `harness-resolver-tokens.json`, deliberately, so the two sides
    cannot drift (CHANGELOG 0.2.0).  A probe that wrote only its own tokens
    would silently revoke every approver those harnesses depend on, and they
    would fail `principal_not_verified` in a way that reads as a core
    regression.  So the existing bindings are loaded and written back
    untouched, and `restore()` puts the file back byte-for-byte at the end.

    The adopted tokens are NOT offered to `credential_for()`: the probe issues
    its own credentials for the principals it approves as, so a row can never
    quietly pass by spending an approver somebody else provisioned.
    """
    global PROVISION_ERROR, _MAP_ORIGINAL
    if not RESOLVER_MAP:
        return
    try:
        with open(RESOLVER_MAP, encoding="utf-8") as fh:
            _MAP_ORIGINAL = fh.read()
        existing = json.loads(_MAP_ORIGINAL)
        if isinstance(existing, dict):
            for tok, principal in existing.items():
                if isinstance(tok, str) and isinstance(principal, dict):
                    _TOKEN_MAP[tok] = principal
    except FileNotFoundError:
        # A map that does not exist yet is fine — this run creates it, and
        # restore() removes it again.
        _MAP_ORIGINAL = None
    except (OSError, json.JSONDecodeError) as exc:
        PROVISION_ERROR = "cannot read %s: %s" % (RESOLVER_MAP, exc)
        return
    # Fail loudly HERE if the path is not writable, not at the first row that
    # needs a credential: "A6 is inconclusive" three minutes in is a much
    # worse error message than "I cannot write this file" at second zero.
    if not _write_token_map():
        return


def restore() -> None:
    """Put the token map back the way this run found it."""
    if not RESOLVER_MAP or PROVISION_ERROR:
        return
    try:
        if _MAP_ORIGINAL is None:
            if os.path.exists(RESOLVER_MAP):
                os.remove(RESOLVER_MAP)
        else:
            with open(RESOLVER_MAP, "w", encoding="utf-8") as fh:
                fh.write(_MAP_ORIGINAL)
            os.chmod(RESOLVER_MAP, 0o644)
    except OSError as exc:
        print("  !! could not restore %s: %s — it still contains this run's "
              "synthetic approver tokens" % (RESOLVER_MAP, exc))


def _write_token_map() -> bool:
    """Rewrite the map atomically. 0644 because core runs as a non-root user."""
    global PROVISION_ERROR
    try:
        tmp = RESOLVER_MAP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_TOKEN_MAP, fh, indent=2)
        os.chmod(tmp, 0o644)
        os.replace(tmp, RESOLVER_MAP)
        return True
    except OSError as exc:
        PROVISION_ERROR = "cannot write %s: %s" % (RESOLVER_MAP, exc)
        return False


def credential_for(ptype: str, pid: str):
    """Issue (or reuse) the bearer token bound to `ptype:pid`. None if unable.

    The returned token is what makes the approval verified.  Callers must pass
    it as `bearer` on the resolve call — approving as somebody whose credential
    you do not hold is the attack, not the fixture.
    """
    display = "%s:%s" % (ptype, pid)
    if display in _CREDENTIAL_OF:
        return _CREDENTIAL_OF[display]
    if not can_provision():
        return None
    token = "tok_rfx97_%s_%d" % (RUN, len(_TOKEN_MAP) + 1)
    _TOKEN_MAP[token] = {"type": ptype, "id": pid}
    if not _write_token_map():
        del _TOKEN_MAP[token]
        return None
    _PRINCIPAL_OF[token] = display
    _CREDENTIAL_OF[display] = token
    return token


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

    # RFX-179: WHICH APPROVER CONFIGURATION IS THIS, and can the probe attack
    # it?  Reported here rather than left to be inferred from A3, because it
    # decides whether two of the six rows mean anything at all — and because
    # the 0.2.0 default is precisely the config that made them stop meaning
    # anything.  One hold, resolved with an unbound principal: refused
    # `principal_not_verified` == this artefact requires verified approvers.
    h_fp, _ = _raise_hold(sid("fp-strict"), label="fingerprint: raise a hold")
    if h_fp:
        st, r4 = _resolve(h_fp, "human", "fp-probe@rfx179.invalid",
                          "fingerprint: resolve with an ASSERTED principal")
        strict = st == 403 and r4.get("error") == "principal_not_verified"
        facts["requires_verified_approver"] = strict
        print("  asserted approver on /resolve   -> HTTP %-11s %s"
              % (st, r4.get("error", "") or "accepted"))
    else:
        facts["requires_verified_approver"] = "inconclusive (no hold)"
    facts["probe_can_issue_credentials"] = can_provision()
    print("  probe can issue credentials     -> %-16s %s"
          % (can_provision(),
             PROVISION_ERROR or ("" if RESOLVER_MAP
                                 else "REEFLEX_PROBE_RESOLVER_MAP unset")))
    if facts["requires_verified_approver"] is True and not can_provision():
        print("  !! this artefact requires verified approvers and this run "
              "cannot issue one:")
        print("     every row needing an approved hold will be INCONCLUSIVE, "
              "which now fails the exit code (RFX-179)")
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


def _resolve(hold_id, ptype, pid, label="", bearer=None):
    """Resolve `hold_id` as `ptype:pid`, optionally with that principal's own
    credential.  `bearer=None` means the plain gate token — i.e. an ASSERTED
    principal, which is what the strict default is there to refuse."""
    return call("POST", "/v1/holds/%s/resolve" % hold_id,
                {"decision": "approve", "principal": {"type": ptype, "id": pid},
                 "reason": SYNTH}, label, bearer=bearer)


#: The refusals core returns from the VERIFICATION check, before any guard a
#: row scores.  A variant refused with one of these did not run — whatever the
#: row was trying to prove, this answer is about the caller's credentials.
VERIFICATION_ERRORS = frozenset({"principal_not_verified", "principal_mismatch"})


def _approve_verified(hold_id, pid, label="", ptype="human"):
    """Approve as `ptype:pid` HOLDING THAT PRINCIPAL'S CREDENTIAL (RFX-179).

    Returns (status, body, how) where `how` is one of:
      "verified"    — a credential bound to this principal was used
      "asserted"    — no credential could be issued; the gate token was used,
                      which the shipped default refuses
      "unavailable" — provisioning was asked for and failed

    The caller must not treat "asserted" as a resolve that merely failed: it is
    a MEASUREMENT THAT DID NOT RUN, and it is reported as such.
    """
    token = credential_for(ptype, pid)
    if token is None:
        st, r = _resolve(hold_id, ptype, pid, label)
        return st, r, ("unavailable" if PROVISION_ERROR else "asserted")
    st, r = _resolve(hold_id, ptype, pid, label, bearer=token)
    if st == 200:
        # MEASURED, NOT ASSUMED.  The whole route this fix takes rests on the
        # claim that an approval made with a bound credential is a genuinely
        # VERIFIED approval — the same thing a real approver produces, not a
        # probe-shaped imitation.  Core says so in the resolve body, so the
        # claim is read back rather than trusted.  If it ever came back
        # `false`, every row built on this precondition would be resting on an
        # approval core itself does not consider verified, and that is a
        # finding about the harness that must not be silent.
        _VERIFICATION_READBACK.append(
            {"principal": _PRINCIPAL_OF.get(token), "label": label,
             "decided_by": r.get("decided_by"),
             "decided_by_verified": r.get("decided_by_verified"),
             "principal_source": r.get("principal_source")})
    return st, r, "verified"


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
    # RFX-179: the approval is made WITH THE RAISER'S OWN CREDENTIAL, not by
    # asserting the raiser's name in the body.  At the shipped default an
    # asserted principal is refused `principal_not_verified` at check 2 and
    # never reaches the four-eyes guard at check 5 — which is precisely how
    # this row went INCONCLUSIVE while the gate exited 0.  Issuing the raiser a
    # credential is a STRICTER precondition than the original run had: the
    # attacker is no longer merely claiming to be the raiser, it demonstrably
    # IS the raiser, and the guard still has to refuse it.
    self_evaded, wrong_reason, not_run = [], [], []
    for i, (name, kw, pid) in enumerate(variants):
        session = sid("a3s-%d" % i)
        hold_id, _ = _raise_hold(session, label="A3-self/%s" % name, **kw)
        if not hold_id:
            print("  %-18s -> no hold raised; variant inconclusive" % name)
            not_run.append("%s(no-hold)" % name)
            continue
        approve_as = pid if pid is not None else session
        st, r, how = _approve_verified(
            hold_id, approve_as,
            "A3-self/%s: approve as human:%s (%s credential)"
            % (name, approve_as, "own" if can_provision() else "no"))
        err = r.get("error", "")
        # Refused for the RIGHT reason == the four-eyes guard actually fired.
        refused = st == 403 and err == "actor_is_approver"
        # WHAT MAKES A VARIANT "NOT RUN" IS THE REFUSAL CORE RETURNED, NOT HOW
        # THE PROBE OBTAINED ITS CREDENTIAL.  An earlier draft of this fix
        # tested `how != "verified"` and got the opposite of RFX-179 wrong: a
        # core with REQUIRE_VERIFIED_APPROVER=false accepts an asserted
        # approver, so all six variants reached check 5 and were correctly
        # refused `actor_is_approver` — and the probe reported "the four-eyes
        # guard was NOT REACHED" over six refusals proving it had been.  A
        # gate that cries INCONCLUSIVE at a guard that fired is the same
        # defect as one that cries CLOSED at a guard that did not; both are
        # the instrument talking about itself.  So: the guard was not reached
        # iff core refused at verification, which it names.
        if st == 403 and err in VERIFICATION_ERRORS:
            not_run.append("%s(%s)" % (name, err))
        elif st == 403 and err != "actor_is_approver":
            wrong_reason.append("%s(%s)" % (name, err))
        print("  %-18s approve as %-24s -> HTTP %s %s [%s]"
              % (name, "human:%s" % approve_as, st, err, how))
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
    # RFX-179: a variant whose approval was merely ASSERTED was refused before
    # check 5, so the four-eyes guard was never reached at all.  That is not a
    # weaker pass, it is no measurement.
    if not_run:
        f_self["state"] = "INCONCLUSIVE"
        f_self["variants_not_executed"] = not_run
        print("  !! the four-eyes guard was NOT REACHED for: %s"
              % ", ".join(not_run))
        print("     the approving principal could not be verified, so core "
              "refused at check 2; nothing here says anything about check 5")
        if not can_provision():
            print("     -> set REEFLEX_PROBE_RESOLVER_MAP to the host path of "
                  "the file this core reads as REEFLEX_RESOLVER_TOKENS (RFX-179)")

    # ---- A3-fab: an unrelated human, fabricated out of nothing -------------
    # THE NEGATIVE CONTROLS, AND WHY THERE ARE NOW TWO OF THEM (RFX-179).
    #
    # This row is what keeps the credential provisioning above honest: if
    # issuing tokens had quietly weakened verification, a fabricated human
    # would resolve here and the gate would say so.  So `no-credential` is
    # deliberately NOT provisioned — it is asserted with the plain gate token
    # and must still be refused.
    #
    # But `no-credential` ALONE cannot score this row, and the run that
    # produced RFX-179 is the proof: at the shipped default a probe holding no
    # bound credential is refused `principal_not_verified` on EVERY resolve it
    # makes, fabricated approver or not.  This row read CLOSED off that 403 and
    # counted toward "closes 4 of 6" — a pass that would have looked identical
    # if the fabrication guard did not exist at all.  The refusal was about the
    # probe's credentials, not about the approver it named.
    #
    # `mismatch` is what disambiguates, and it is only runnable because the
    # probe can now mint: hold a REAL, verified approver's credential and
    # assert somebody ELSE's identity in the body.  There is nothing wrong with
    # the caller's credentials, so `principal_not_verified` is off the table;
    # the only thing that can refuse it is core comparing the asserted
    # principal against the credential's, which is exactly the guard RFX-84
    # asks for.  Refused `principal_mismatch` = the guard fired, and the whole
    # row now means something.
    session_prefix = "a3fab"
    fab_evaded, wrong_reason, not_run, detail = [], [], [], {}

    # name, credential to hold (None = plain gate token), asserted principal,
    # the reason code that means THIS variant's guard fired
    fab_variants = [
        ("no-credential", None, "fabricated.approver@example.invalid",
         "principal_not_verified"),
        ("mismatch", ("human", "a3fab-real-approver@rfx84.invalid"),
         "fabricated.approver@example.invalid", "principal_mismatch"),
    ]
    for i, (name, cred, asserted, want_err) in enumerate(fab_variants):
        bearer = None
        if cred is not None:
            bearer = credential_for(*cred)
            if bearer is None:
                # Not "refused" — never attempted.  Saying anything else here
                # is the fabricated finding this file exists to prevent.
                print("  %-26s -> NOT RUN (no credential could be issued)" % name)
                not_run.append("%s(%s)" % (name, PROVISION_ERROR or "unavailable"))
                continue
        session = sid("%s-%d" % (session_prefix, i))
        hold_id, _ = _raise_hold(session, label="A3-fab/%s" % name)
        if not hold_id:
            not_run.append("%s(no-hold)" % name)
            continue
        st, r = _resolve(hold_id, "human", asserted,
                         "A3-fab/%s: approve as a human that does not exist"
                         % name, bearer=bearer)
        err = r.get("error", "")
        print("  %-26s -> HTTP %s %s%s"
              % (name, st, err,
                 "" if cred is None else
                 "  (holding %s's credential)" % _PRINCIPAL_OF.get(bearer, "?")))
        if st == 403 and err == want_err:
            detail[name] = "refused %s — the guard fired" % err
        elif st == 403:
            # A 403 from somewhere else is not this guard.  Scored, not
            # counted as a pass: this is the qa--016 trap that scored five
            # self-approval variants CLOSED on an unrelated refusal.
            detail[name] = "refused %s — NOT %s" % (err, want_err)
            wrong_reason.append("%s(%s, wanted %s)" % (name, err, want_err))
        else:
            detail["%s_decided_by" % name] = r.get("decided_by")
            detail["%s_decided_by_verified" % name] = r.get("decided_by_verified")
            detail["%s_principal_source" % name] = r.get("principal_source")
            print("      decided_by=%r verified=%r source=%r"
                  % (r.get("decided_by"), r.get("decided_by_verified"),
                     r.get("principal_source")))
            _, rr = call("POST", "/v1/decide",
                         envelope(session, "delete", 1, env="production",
                                  reversibility="irreversible", blast="broad",
                                  approval={"present": True, "hold_id": hold_id}),
                         "A3-fab/%s: resubmit with the fabricated approval" % name)
            print("      resubmit -> %s (%s)" % (verdict(rr), rule(rr)))
            if verdict(rr) == "allow":
                fab_evaded.append(name)

    f_fab = finding(
        "A3-fab", "RFX-84", "unrelated approving human fabricated in the body",
        "#90 (opt-in)", True, fab_evaded, len(fab_variants),
        "core mints and persists decided_by:'human:<name>' for a human that "
        "never acted — the Art.14 record says oversight happened",
    )
    if wrong_reason:
        print("  !! refused, but not by the guard this row scores: %s"
              % ", ".join(wrong_reason))
        f_fab["state"] = "INCONCLUSIVE" if f_fab["state"] == "CLOSED" \
            else f_fab["state"]
    if not_run:
        print("  !! variants that never ran: %s" % ", ".join(not_run))
        print("     a fabrication guard that was not exercised is not a pass "
              "(RFX-179)")
        f_fab["variants_not_executed"] = not_run
        f_fab["state"] = "INCONCLUSIVE" if f_fab["state"] == "CLOSED" \
            else f_fab["state"]
    detail["refused_but_not_by_this_guard"] = wrong_reason
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


A6_APPROVER = "a6-manager@rfx138.invalid"


def _approved_hold(session, label, **agent_kw):
    """Raise a hold as `agent_kw` and have a human approve it.

    Returns (hold_id, ok, why).  `why` is "" when ok, else the reason the
    precondition could not be established — and A6 needs that string, because
    "the approval could not be built" and "the substitution was refused" are
    opposite findings that a bare False cannot tell apart.

    The approver is a third party, so check 6 (actor_is_approver) cannot be
    what refuses any resubmission below.

    RFX-179: the approval is obtained WITH THE APPROVER'S OWN CREDENTIAL.  At
    the shipped default an asserted approver is refused
    `principal_not_verified`, so every variant of this row lost its
    precondition and A6 reported INCONCLUSIVE — which did not move the exit
    code.  One manager approves throughout, so this issues exactly one
    credential and reuses it.
    """
    hold_id, _ = _raise_hold(session, label=label, **agent_kw)
    if not hold_id:
        return None, False, "no-hold"
    st, r, how = _approve_verified(hold_id, A6_APPROVER,
                                   "%s: human approves" % label)
    if st != 200:
        print("  %-26s !! resolve refused HTTP %s %s [%s] — precondition failed"
              % (label, st, r.get("error", ""), how))
        return hold_id, False, "%s:%s" % (how, r.get("error", "") or st)
    return hold_id, True, ""


ACTOR_MISMATCH = "reeflex_hold_actor_mismatch"


def attack_a6():
    banner("A6  RFX-138 — a human's approval is spendable by a DIFFERENT agent")

    ALPHA = "agent:a6-alpha"
    BETA = "agent:a6-beta"

    # CONTROL: the agent the human actually approved must be able to spend it.
    # Without this an "allow" below is unreadable and a "deny" could just mean
    # the hold chain is broken on this build.
    s_ctl = sid("a6-ctl")
    h_ctl, ok_ctl, why_ctl = _approved_hold(s_ctl, "A6 control", agent_id=ALPHA)
    ctl_resp = _resubmit(s_ctl, h_ctl, "A6 control: the APPROVED agent resubmits",
                         agent_id=ALPHA) if ok_ctl else {}
    control_ok = ok_ctl and verdict(ctl_resp) == "allow"
    print("  CONTROL approved agent spends -> %-16s %s"
          % (verdict(ctl_resp), rule(ctl_resp)))
    if not control_ok:
        print("  !! the approved agent could not spend its own approval — the "
              "hold chain is not in scope; A6 is inconclusive")
        if why_ctl:
            print("     precondition: %s" % why_ctl)
        if not can_provision():
            print("     -> no approver credential could be issued. Set "
                  "REEFLEX_PROBE_RESOLVER_MAP to the host path of the file "
                  "this core reads as REEFLEX_RESOLVER_TOKENS (RFX-179)")

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
    # `wrong_reason` exists because THE VERDICT ALONE DOES NOT SCORE THIS ROW.
    # The `fixed_in` column claims a specific guard — "check 8 (actor key)" —
    # and a `deny` for any other reason satisfies `verdict(r) != "allow"` while
    # proving nothing about that guard: `reeflex_hold_consumed` from a
    # mis-sequenced chain, `reeflex_hold_expired` from a clock, a validation
    # refusal that never reached the actor compare at all.  That is the same
    # trap qa--016 hit on A3, where five self-approval variants scored CLOSED on
    # a 403 that was `principal_type_not_allowed` — the guard was never
    # exercised and the pass was invented.  So the reason is asserted, and a
    # refusal from somewhere else makes the row INCONCLUSIVE rather than green.
    evaded, burned, wrong_reason, not_run, detail = [], [], [], [], {}
    for i, (name, raise_kw, sub_kw, _why) in enumerate(variants):
        s_raise = sid("a6-%d-raise" % i)
        # A different SESSION for the substitute is part of the attack for
        # every variant except obo-substitution, where the point is that
        # nothing at all changes except the person named.
        s_sub = s_raise if name == "obo-substitution" else sid("a6-%d-sub" % i)
        h, ok, why = _approved_hold(s_raise, "A6/%s" % name, **raise_kw)
        if not ok:
            # RFX-179: no approved hold means the substitution was never
            # ATTEMPTED. It is a variant that did not run, and it is now
            # counted as one rather than vanishing into a 0/4 evaded column.
            print("  %-26s -> NOT RUN (no approved hold: %s)" % (name, why))
            not_run.append("%s(%s)" % (name, why))
            continue
        r = _resubmit(s_sub, h, "A6/%s: substitute spends the approval" % name,
                      **sub_kw)
        print("  %-26s -> %-16s %-34s %s"
              % (name, verdict(r), r.get("reason", "") or rule(r), rule(r)))
        if verdict(r) == "allow":
            evaded.append(name)
        elif r.get("reason") != ACTOR_MISMATCH:
            wrong_reason.append("%s(%s)" % (name, r.get("reason", "") or "no reason"))

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
        h, ok, why = _approved_hold(s_raise, "A6-overblock/%s" % name, **raise_kw)
        if not ok:
            # An over-block control that did not run cannot clear the fix of
            # over-blocking, so it is reported rather than skipped in silence.
            print("  OVER-BLOCK %-16s -> NOT RUN (%s)" % (name, why))
            not_run.append("overblock/%s(%s)" % (name, why))
            continue
        r = _resubmit(s_sub, h, "A6-overblock/%s: legitimate resubmission" % name,
                      **sub_kw)
        print("  OVER-BLOCK %-16s -> %-16s %s" % (name, verdict(r), rule(r)))
        if verdict(r) != "allow":
            overblocked.append("%s(%s)" % (name, r.get("reason", "")))
    detail["over_blocked_legitimate_resubmissions"] = overblocked
    detail["hold_burned_by_a_refused_substitution"] = burned
    detail["refused_but_not_by_check_8"] = wrong_reason
    if wrong_reason:
        print("  !! a substitution was refused for a DIFFERENT reason: %s"
              % ", ".join(wrong_reason))
        print("     the hijack did not land, but this row's `fixed_in` column "
              "claims check 8 closed it and that is now unproven — the actor "
              "compare may not have been reached at all")
        f["state"] = "INCONCLUSIVE" if f["state"] == "CLOSED" else f["state"]
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
    # RFX-179 — LAST, so it cannot be overwritten by the branches above. A row
    # where variants did not run is not entitled to CLOSED; but a row that DID
    # catch an evasion or an over-block keeps that worse verdict, because a
    # measured failure outranks an unmeasured one.
    if not_run:
        # On the finding, not just in `detail`: every row that can skip a
        # variant reports it under the same key, so one JSON consumer finds
        # them all.
        f["variants_not_executed"] = not_run
        print("  !! variants that never ran: %s" % ", ".join(not_run))
        print("     the approval could not be built, so the substitution was "
              "never attempted — this says nothing about check 8 (RFX-179)")
        if f["state"] == "CLOSED":
            f["state"] = "INCONCLUSIVE"
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

    provision_init()
    print("approver credentials: %s"
          % (("issued into %s" % RESOLVER_MAP) if can_provision()
             else (PROVISION_ERROR or
                   "NOT AVAILABLE — REEFLEX_PROBE_RESOLVER_MAP unset (RFX-179)")))

    try:
        facts = fingerprint()

        findings = []
        for code in which:
            out = ATTACKS[code]()
            findings.extend(out if isinstance(out, list) else [out])
    finally:
        # The synthetic approver tokens must not outlive the run: the file is
        # shared with other harnesses, and a leftover binding is a credential
        # nobody issued deliberately.
        restore()

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
        print("  INCONCLUSIVE      : %s  (NOT ATTACKED — see above)"
              % ", ".join(sorted(incon)))
    if overblock:
        print("  OVER-BLOCKING     : %s  (wrong DENY on an approved action)"
              % ", ".join(sorted(overblock)))
    # RFX-179: were the approvals this run BUILT ON actually verified ones?
    # Reported next to the verdicts, because if they were not, several of the
    # verdicts above are about something other than what their row claims.
    unverified = [x for x in _VERIFICATION_READBACK
                  if x.get("decided_by_verified") is not True]
    if _VERIFICATION_READBACK:
        print("\napprovals obtained with a bound credential: %d, of which core "
              "recorded %d as verified"
              % (len(_VERIFICATION_READBACK),
                 len(_VERIFICATION_READBACK) - len(unverified)))
    if unverified:
        print("  !! %d approval(s) came back NOT verified: %s"
              % (len(unverified),
                 ", ".join(sorted({str(x["principal"]) for x in unverified}))))
        print("     the preconditions of the rows above are approvals core "
              "does not consider verified — read those verdicts with that in "
              "mind (RFX-179)")

    print("\nfingerprint: %s" % json.dumps(facts))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"base": BASE, "run": RUN, "fingerprint": facts,
                       "findings": findings, "tickets": tickets,
                       "verification_readback": _VERIFICATION_READBACK,
                       "transcript": _TRANSCRIPT}, fh, indent=2)
        print("wrote %s (%d calls)" % (args.json_out, len(_TRANSCRIPT)))

    # Exit code = every ticket this run could not certify, so CI can gate on
    # it.  All three states below are reasons not to cut a release from this
    # artefact, and INCONCLUSIVE is in the sum because of RFX-179:
    #
    #   still exploitable — the attack landed.
    #   over-blocking    — the fix landed and refuses a legitimate approved
    #                      action, which is a product failure of its own.
    #   INCONCLUSIVE     — THE ATTACK NEVER RAN.  It was in the sum from
    #                      neither side before, so when the 0.2.0 default made
    #                      two of six attacks unrunnable this harness printed
    #                      "still exploitable: none" and returned 0 — a green
    #                      release gate over two attacks nobody had performed.
    #                      A gate that cannot attack the build we ship must say
    #                      so in the only channel CI reads.
    #
    # A run that cannot certify a ticket and a run that found it broken are
    # different findings and the table says which; they are the same DECISION,
    # which is: do not cut this release.
    #
    # THE COST OF THIS, STATED RATHER THAN DISCOVERED.  dev-3--026 looked at
    # the same line and deliberately did NOT change it, for a reason that is
    # still true: against **api-dev** a build that legitimately predates a
    # dimension scores INCONCLUSIVE, so a blanket non-zero turns those runs
    # red, and that round judged the clean fix to be target-aware rather than
    # a one-line `return`.
    #
    # Changed anyway, and here is the argument rather than an oversight:
    #   * The sentence this exit code should mean is "this run certified these
    #     tickets against this artefact".  Against a lagging api-dev that
    #     sentence is FALSE, so non-zero is the accurate answer, not a false
    #     alarm — api-dev is not the release artefact and a gate reading of it
    #     was never a release decision (see the api-dev pinning trap).
    #   * The blast radius today is zero: no file in .github/workflows/ runs
    #     this script, so nothing in CI goes red on this change.  It is invoked
    #     by hand, where a non-zero exit is read by a person who can see the
    #     table two lines above it.
    #   * Leaving it meant the DEFAULT SHIPPED CONFIG could not be certified
    #     and said so only in prose, which is the defect (RFX-179), not a
    #     tuning preference.
    # If a target-aware exit code is wanted later, the fingerprint already
    # carries what it needs and the per-row `variants_not_executed` says which
    # rows were skipped and why.  Flagged for the console.
    return len(open_) + len(overblock) + len(incon)


if __name__ == "__main__":
    sys.exit(main())
