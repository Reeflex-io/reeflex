"""
principal.py — who is allowed to say "a human approved this" (RFX-CORE-2).

=============================================================================
THE DEFECT THIS MODULE EXISTS TO CLOSE
=============================================================================
`POST /v1/holds/{id}/resolve` took the approving principal from the REQUEST
BODY and wrote it into the hold record as fact:

    principal_type = str(principal.get("type", "")).strip()
    principal_id   = str(principal.get("id", "")).strip()
    ...
    decided_by = f"{principal_type}:{principal_id}"      # recorded as truth

Nothing tied that principal to the credential that made the call.  Core's auth
is a single shared bearer token (REEFLEX_AUTH_TOKEN), which authenticates the
CALLER but says nothing about WHICH HUMAN is approving.  So one token could:

  1. raise a hold as `agent:whatever` via POST /v1/decide, then
  2. approve it as `human:<any name it likes>` via the resolve endpoint, then
  3. resubmit and receive `allow`.

Confirmed live on api-dev v0.1.13 with the published eval token — see
scripts/attack-probe-rfx-core-2.py, attack A1.  The two guards in front of it
do not help:

  * `principal_type_not_allowed` only checks the ASSERTED type against the
    resolution policy, so the caller writes `"type": "human"` and passes.
  * `actor_is_approver` is a string INEQUALITY (`agent.id != principal.id`),
    which any caller satisfies by naming a different string.

So four-eyes was not enforced at the core boundary.  Worse, the fabricated
identity is not merely accepted — it is PERSISTED as `decided_by:
"human:leo.david"` in holds.jsonl and re-emitted on the hold.resolved webhook
and the Art.14 hold_resolution audit record, i.e. core mints evidence that a
named human exercised oversight when no human did.

RELATIONSHIP TO RFX-74 (fabricated `decided_by: human:...` in the Attest
report): the SAME DEFECT, seen at two layers.  RFX-74 is the downstream
symptom — a report faithfully rendering an attestation it had no way to
distinguish from a real one.  This is the upstream cause: the boundary that
mints the attestation never verified it.  Fixing the report alone would only
hide the forgery; the record has to stop being forgeable, which is what this
module does.

=============================================================================
WHAT THIS MODULE DOES
=============================================================================
1. VERIFY WHEN POSSIBLE.  `REEFLEX_RESOLVER_TOKENS` maps a bearer token to the
   principal that token IS.  When configured, the approver is taken from the
   credential, and a body-asserted principal that disagrees is REFUSED (403)
   rather than silently rewritten — a caller asserting someone else's identity
   is a signal, not a formatting difference.

2. NEVER LAUNDER AN UNVERIFIED ASSERTION INTO VERIFIED-LOOKING EVIDENCE.  When
   no mapping is configured the principal is still an assertion, and it is now
   RECORDED AS ONE: `decided_by_verified: false` / `principal_source:
   "asserted"` ride along on the hold record, the webhook and the audit line.
   The frozen `decided_by` "{type}:{id}" shape is left exactly as it was, so
   nothing downstream breaks; the provenance is additive.

3. REFUSE OUTRIGHT BY DEFAULT.  `REEFLEX_REQUIRE_VERIFIED_APPROVER` makes an
   unverifiable approver a hard 403, and SINCE 0.2.0 IT IS ON UNLESS THE
   OPERATOR TURNS IT OFF.  A deployment that wants to keep resolving holds on
   a self-asserted approver must now say so in as many words.

=============================================================================
WHY (3) IS THE DEFAULT — AND WHAT THE OLD ARGUMENT FOR THE OTHER DEFAULT WAS
=============================================================================
Until 0.2.0 the default was OFF, and the reason written here was: SPEC §7's
fail-closed bias is about ambiguous INPUT, not a licence to disable a subsystem
when CONFIG is absent; defaulting it on would make every hold unresolvable on
upgrade — the holds API, the holds CLI (RFX-42) and the dashboard would all
stop working until an operator wrote a token map — and a feature outage is not
core's trade to make silently.

That argument was about UPGRADE COST, and it was answered rather than refuted:

  * The cost is real and it is now PAID EXPLICITLY.  This is a MINOR version
    bump, the CHANGELOG names the break and who it breaks, and the refusal
    below tells the operator, at the moment it happens, the one line that
    restores the old behaviour.  A break an operator is told about at the
    point of failure is a different thing from a silent one.

  * The thing being defended was never a working feature.  What
    `REQUIRE_VERIFIED_APPROVER=false` buys is the ability to resolve a hold
    with an approver core cannot verify — and RFX-84 is the measurement of
    what that is worth: one bearer token raised an irreversible production
    hold and approved it as `human:totally-invented-auditor`, and core minted
    and PERSISTED the Art.14 record saying a human had overseen it.  Keeping
    a subsystem "working" in the sense that it still accepts an invented human
    is keeping the defect, not the feature.

  * The RFX-97 release gate measures the difference on a built artefact.  At
    the old default, five of six known evasions close and the survivor is
    exactly this one.  At the new default it closes.  Shipping an image whose
    DEFAULT accepts an invented approver, in a product whose entire claim is
    evidence of human oversight, is the fail-open class the last six tickets
    were spent killing.

WHAT DOES NOT CHANGE.  (1) and (2) are untouched: a deployment that configures
`REEFLEX_RESOLVER_TOKENS` verifies its approvers and nothing about this default
is visible to it, and a deployment that opts out with
`REEFLEX_REQUIRE_VERIFIED_APPROVER=false` gets exactly the pre-0.2.0
behaviour, warning on stderr and `decided_by_verified: false` included.
"""

from __future__ import annotations

import hmac
import json
import os
import sys
import unicodedata

# ---------------------------------------------------------------------------
# Identity normalization
#
# `actor_is_approver` compared identities with `==` on raw strings, so the SAME
# identity in a different case or carrying an invisible character read as two
# different people: agent.id "svc-bot" approving itself as "SVC-BOT" passed the
# check (confirmed live, attack A3).  This is the exact-match class of defect
# from PR #89, sitting in the four-eyes guard itself.
#
# Same treatment as envelope.py's token canon: NFKC-fold, drop control/format
# characters (zero-width space, BOM, RLO), strip, casefold.
# ---------------------------------------------------------------------------


def normalize_identity(raw: object) -> str:
    """Fold an identity string to a stable comparison key ("" if unusable)."""
    if not isinstance(raw, str):
        return ""
    folded = unicodedata.normalize("NFKC", raw)
    cleaned = "".join(
        ch for ch in folded if unicodedata.category(ch) not in ("Cc", "Cf")
    )
    return cleaned.strip().casefold()


def actor_identities(envelope: dict) -> set[str]:
    """Every identity that counts as "the party that raised this action".

    Four-eyes means the approver is not the raiser.  The raiser can be named in
    the envelope three ways, and ALL THREE must be disqualified as approvers:

      agent.id           the acting agent ("agent:cursor-claude")
      agent.on_behalf_of the human the agent declares it acts FOR
                         ("user:alice").  Without this, an agent acting for
                         Alice raises an action and "Alice" approves it — self
                         approval at one remove, which is the thing four-eyes
                         exists to prevent.  Confirmed live, attack A4.
      agent.session_id   the session identity.  This is the only one SPEC §2
                         REQUIRES (agent.id is optional), so it is the fallback
                         that keeps the guard non-vacuous for a conformant
                         adapter that sends no agent.id at all — the case where
                         the old check compared against "" and was skipped
                         entirely (confirmed live, attack A2).

    Both the bare value and the part after a "type:" prefix are included, so
    "user:alice" is disqualified whether the approver writes "user:alice" or
    "alice" with type "human".
    """
    agent = envelope.get("agent") or {}
    if not isinstance(agent, dict):
        return set()
    out: set[str] = set()
    for field in ("id", "on_behalf_of", "session_id"):
        norm = normalize_identity(agent.get(field))
        if not norm:
            continue
        out.add(norm)
        if ":" in norm:
            out.add(norm.split(":", 1)[1])
    return {v for v in out if v}


def approver_identities(principal_type: str, principal_id: str) -> set[str]:
    """The identity forms an asserted approver could be matched by."""
    out: set[str] = set()
    pid = normalize_identity(principal_id)
    if pid:
        out.add(pid)
        if ":" in pid:
            out.add(pid.split(":", 1)[1])
        ptype = normalize_identity(principal_type)
        if ptype:
            out.add("%s:%s" % (ptype, pid))
    return {v for v in out if v}


def is_self_approval(envelope: dict, principal_type: str, principal_id: str) -> bool:
    """True if the approver is (any identity of) the party that raised it."""
    return bool(actor_identities(envelope) & approver_identities(principal_type, principal_id))


def approval_actor_key(envelope: dict) -> tuple[str, ...]:
    """WHO an approval is granted TO -- comparable across two envelopes.

    RFX-138.  `actor_identities()` above answers "is the approver one of the
    raisers", which is a SET question and deliberately loose.  This answers a
    different one: two envelopes, is this the same party acting for the same
    person?  That has to be an ORDERED, EXACT comparison, because a set
    intersection would let an agent that merely OVERLAPS the approved
    identities spend the approval.

    WHAT IS IN THE KEY, AND WHY NOT MORE
      agent.id + agent.on_behalf_of   the party and the person it acts for.
                                      Changing either means the human approved
                                      one requester and a different one turned
                                      up, which is the whole finding.
      agent.session_id                ONLY as the fallback, when the envelope
                                      names no agent at all.  SPEC §2 makes
                                      agent.id optional and session_id
                                      required, so without this fallback a
                                      conformant minimal envelope would carry
                                      an EMPTY key and the guard would be
                                      vacuous for exactly the adapters least
                                      likely to be watched.  Same reasoning as
                                      actor_identities()'s session fallback.

    WHY session_id IS NOT IN THE KEY WHEN THE AGENT IS NAMED.  A hold lives
    for hours (REEFLEX_HOLD_TTL_SECONDS defaults to 4h) and an agent that
    restarts between raising and resubmitting gets a new session.  Binding the
    session would turn that restart into a DENY on an action a human already
    approved -- a wrong deny on the one path where a human has explicitly said
    yes.  The ledger is recomputed per session by design; identity is the
    thing an approval is about.

    Normalized (NFKC, control/format stripped, casefolded) so a case or
    zero-width difference is not read as a different agent -- the same
    treatment the four-eyes guard uses, for the same reason in reverse: there
    it must not let a variant spelling through, here it must not refuse one.
    Falls back to the raw string when normalization empties it, so an identity
    made entirely of invisible characters is still COMPARED rather than
    silently collapsing to "" on both sides.
    """
    agent = envelope.get("agent") or {}
    if not isinstance(agent, dict):
        agent = {}

    def key_for(field: str) -> str:
        raw = agent.get(field)
        norm = normalize_identity(raw)
        if norm:
            return norm
        return raw.strip() if isinstance(raw, str) else ""

    named = (key_for("id"), key_for("on_behalf_of"))
    if any(named):
        return named
    # No agent named at all: fall back to the session, and keep the tuple a
    # different SHAPE so a session key can never compare equal to a named one.
    return ("", "", key_for("session_id"))


# ---------------------------------------------------------------------------
# Credential -> principal binding
# ---------------------------------------------------------------------------

_TOKENS_ENV = "REEFLEX_RESOLVER_TOKENS"
_STRICT_ENV = "REEFLEX_REQUIRE_VERIFIED_APPROVER"

#: Where the operator can read the whole story rather than one 403's worth of
#: it.  Named once, so a moved page is one edit and not four.
_DOCS_URL = "https://github.com/Reeflex-io/reeflex/blob/main/docs/reference/configuration.md#verified-approvers"


def _display(ptype: object, pid: object) -> str:
    """The "type:id" form used in messages -- never the bare id.

    A refusal that says only `alice` leaves the operator guessing whether core
    read a human or an agent, and the type is half of what makes an approver
    acceptable (the resolution policy is keyed on it).
    """
    t = str(ptype or "").strip() or "?"
    i = str(pid or "").strip() or "?"
    return "%s:%s" % (t, i)


def _load_resolver_tokens() -> dict:
    """Load the bearer-token -> principal map.

    Shape (JSON string, or a path to a JSON file):

        {
          "tok_live_alice": {"type": "human", "id": "alice@example.com"},
          "tok_live_bob":   {"type": "human", "id": "bob@example.com"}
        }

    Malformed/absent -> {} (no token can be verified).  Read per request so an
    operator can rotate the map without a restart, matching how
    REEFLEX_RESOLUTION_POLICY and REEFLEX_FREEZE already behave.
    """
    raw = os.environ.get(_TOKENS_ENV, "").strip()
    if not raw:
        return {}
    parsed = None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import pathlib
            p = pathlib.Path(raw)
            if p.is_file():
                with open(p, encoding="utf-8") as fh:
                    parsed = json.load(fh)
        except Exception:  # noqa: BLE001
            parsed = None
    if not isinstance(parsed, dict):
        return {}
    out = {}
    for token, principal in parsed.items():
        if not isinstance(token, str) or not token or not isinstance(principal, dict):
            continue
        ptype = str(principal.get("type", "")).strip()
        pid = str(principal.get("id", "")).strip()
        if ptype and pid:
            out[token] = {"type": ptype, "id": pid}
    return out


#: What `REEFLEX_REQUIRE_VERIFIED_APPROVER` does when the operator says nothing.
#: Flipped to True in 0.2.0 — see the module docstring for the argument, and
#: the CHANGELOG for who this breaks and the one line that restores 0.1.x.
STRICT_DEFAULT: bool = True

_TRUTHY = frozenset({"true", "1", "yes", "on"})
_FALSEY = frozenset({"false", "0", "no", "off"})


def strict_mode() -> bool:
    """True if an unverifiable approver must be refused outright.

    TRI-STATE, and it has to be: unset now means something DIFFERENT from
    "false", so the two cannot share a parse.

        unset / empty / unrecognised  -> STRICT_DEFAULT (True since 0.2.0)
        true | 1 | yes | on           -> True
        false | 0 | no | off          -> False   (the 0.1.x behaviour)

    AN UNRECOGNISED VALUE READS AS THE DEFAULT, NOT AS "off".  `="maybe"` or
    `="False "` with a stray character is a config the operator got wrong, and
    the SPEC §7 reading of a value we cannot parse is the most-guarded one --
    the same rule envelope.py applies to every caller-supplied enum.  Turning
    the guard OFF on a typo would be the fail-open shape this default exists to
    close, one config file over.  Only an explicit, recognised falsey word
    opts out; the word is compared folded (`_normalize_token`-equivalent:
    trim + casefold) so `FALSE` and `False` work, but nothing else does.
    """
    raw = os.environ.get(_STRICT_ENV)
    if raw is None:
        return STRICT_DEFAULT
    token = raw.strip().casefold()
    if token in _TRUTHY:
        return True
    if token in _FALSEY:
        return False
    if token:
        print(
            "[reeflex-core] WARN: %s=%r is not a recognised boolean; reading it "
            "as the default (%s). Use 'true' or 'false'."
            % (_STRICT_ENV, raw, "true" if STRICT_DEFAULT else "false"),
            file=sys.stderr,
        )
    return STRICT_DEFAULT


def verification_configured() -> bool:
    """True if any credential->principal binding exists at all."""
    return bool(_load_resolver_tokens())


def principal_for_token(bearer: str | None) -> dict | None:
    """Return the principal this bearer token IS, or None if unverifiable.

    Constant-time compare against every configured token, same discipline as
    server._authorized(), so this does not become a timing oracle for the
    token map.
    """
    if not bearer:
        return None
    for token, principal in _load_resolver_tokens().items():
        if hmac.compare_digest(bearer, token):
            return dict(principal)
    return None


# ---------------------------------------------------------------------------
# The decision this module exists to make
# ---------------------------------------------------------------------------

class PrincipalRefused(Exception):
    """Raised when the asserted principal must not be accepted.

    `error` is the machine reason code the HTTP layer returns; `reason` is the
    human sentence; `remedy` is the machine-readable "what would make this
    work", echoed on the 403 alongside the other two.

    WHY THERE IS A `remedy` AT ALL.  `principal_not_verified` on its own is a
    refusal that sends the operator to the source: it names no principal, no
    setting and no next step, and the person reading it is usually a human who
    just clicked Approve in a holds inbox on an action that is now stuck.  A
    refusal a product means to ship as a DEFAULT has to carry its own
    instructions.  `reason` says what happened in a sentence; `remedy` is the
    same thing in fields a dashboard can render as a button:

        {"error": "principal_not_verified",
         "reason": "...one sentence, naming the principal...",
         "remedy": {"principal": "human:alice@example.com",
                    "why": "unbound_credential" | "verification_not_configured",
                    "actions": ["...", "..."],
                    "docs": "https://..."} }

    `remedy` is ADDITIVE and optional -- every existing consumer reads `error`
    and ignores unknown keys, so no wire contract moves.
    """

    def __init__(self, error: str, reason: str, remedy: dict | None = None) -> None:
        super().__init__(reason)
        self.error = error
        self.reason = reason
        self.remedy = remedy or {}


def resolve_approver(bearer: str | None, asserted_type: str, asserted_id: str) -> dict:
    """Decide who is recorded as the approver, and how much that is worth.

    Returns {"type", "id", "verified": bool, "source": "credential"|"asserted"}.
    Raises PrincipalRefused when the assertion must not be accepted at all.
    """
    bound = principal_for_token(bearer)

    if bound is not None:
        # The credential names a principal. If the body asserts a DIFFERENT
        # one, refuse rather than quietly substituting: a caller claiming
        # someone else's identity is a signal worth surfacing, and silently
        # rewriting it would make the audit trail disagree with the request.
        a_ids = approver_identities(asserted_type, asserted_id)
        b_ids = approver_identities(bound["type"], bound["id"])
        if asserted_id and not (a_ids & b_ids):
            raise PrincipalRefused(
                "principal_mismatch",
                "the asserted principal %s does not match %s, the principal "
                "bound to the credential this request was made with; a caller "
                "may only approve as itself"
                % (_display(asserted_type, asserted_id),
                   _display(bound["type"], bound["id"])),
                {
                    "principal": _display(asserted_type, asserted_id),
                    "bound_principal": _display(bound["type"], bound["id"]),
                    "why": "credential_bound_to_another_principal",
                    "actions": [
                        "approve as %s (the principal this credential IS), or"
                        % _display(bound["type"], bound["id"]),
                        "make this request with the bearer token %s is bound to "
                        "in %s" % (_display(asserted_type, asserted_id), _TOKENS_ENV),
                    ],
                    "docs": _DOCS_URL,
                },
            )
        return {"type": bound["type"], "id": bound["id"],
                "verified": True, "source": "credential"}

    # No binding for this credential.
    if verification_configured() or strict_mode():
        # Either this deployment DOES bind credentials (and this one is not in
        # the map), or it demands verified approvers. Both mean: refuse.
        #
        # SAME CODE, DIFFERENT SITUATIONS -- and the operator's next move is
        # not the same one, so the sentence must not be.  "Your token is
        # missing from a map that exists" is a five-second fix by whoever owns
        # the map; "this core has verification switched on and no map at all"
        # is a deployment that has never been wired up, and the honest thing
        # to offer there is BOTH the real fix and the documented escape hatch.
        # The `error` code stays `principal_not_verified` for both, because it
        # is the same refusal and the code is a wire contract the RFX-97
        # release gate and every adapter assert on.
        configured = verification_configured()
        principal = _display(asserted_type, asserted_id)
        if configured:
            raise PrincipalRefused(
                "principal_not_verified",
                "the approver %s cannot be verified: this core binds bearer "
                "tokens to approving principals via %s, and the credential "
                "this request was made with is not in that map, so nothing "
                "establishes that %s is who resolved this hold"
                % (principal, _TOKENS_ENV, principal),
                {
                    "principal": principal,
                    "why": "unbound_credential",
                    "actions": [
                        "add this bearer token to %s as "
                        '{"<token>": {"type": %r, "id": %r}} -- the map is '
                        "re-read per request, so no restart is needed"
                        % (_TOKENS_ENV, asserted_type or "human",
                           asserted_id or "alice@example.com"),
                        "or resolve this hold with a token that IS bound in %s"
                        % _TOKENS_ENV,
                    ],
                    "docs": _DOCS_URL,
                },
            )
        raise PrincipalRefused(
            "principal_not_verified",
            "the approver %s is asserted by the caller and this core cannot "
            "check it: %s is on (the default since 0.2.0) and no %s map is "
            "configured, so no credential is bound to any approving principal "
            "and four-eyes cannot be established for this resolution"
            % (principal, _STRICT_ENV, _TOKENS_ENV),
            {
                "principal": principal,
                "why": "verification_not_configured",
                "actions": [
                    "set %s to a JSON object (or a path to one) binding each "
                    'approver\'s bearer token to the principal it IS: '
                    '{"<token>": {"type": %r, "id": %r}}'
                    % (_TOKENS_ENV, asserted_type or "human",
                       asserted_id or "alice@example.com"),
                    "or, to keep the pre-0.2.0 behaviour while you wire that "
                    "up, set %s=false -- the hold resolves, and the record "
                    "says decided_by_verified=false because nothing verified it"
                    % _STRICT_ENV,
                ],
                "docs": _DOCS_URL,
            },
        )

    # Unverifiable, and this deployment has EXPLICITLY OPTED OUT of strictness
    # (`REEFLEX_REQUIRE_VERIFIED_APPROVER=false`; since 0.2.0 that is the only
    # way to reach this line).  Accept the assertion but record it AS an
    # assertion.  Loud on stderr because a deployment running like this cannot
    # claim four-eyes -- and louder than before, because it is now a state the
    # operator chose rather than one they inherited.
    print(
        "[reeflex-core] WARN: resolving a hold with an UNVERIFIED approver "
        "(%s) -- %s=false is set and no %s binding exists for this credential, "
        "so core is recording an approver it did not authenticate. The hold "
        "record, the hold.resolved webhook and the Art.14 audit line all carry "
        "decided_by_verified=false; this deployment cannot claim four-eyes. "
        "Set %s to bind credentials to principals and remove the opt-out."
        % (_display(asserted_type, asserted_id), _STRICT_ENV, _TOKENS_ENV,
           _TOKENS_ENV),
        file=sys.stderr,
    )
    return {"type": asserted_type, "id": asserted_id,
            "verified": False, "source": "asserted"}
