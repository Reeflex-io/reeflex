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

3. OPTIONALLY REFUSE OUTRIGHT.  `REEFLEX_REQUIRE_VERIFIED_APPROVER=true` makes
   an unverifiable approver a hard 403.  A deployment that wants to CLAIM
   four-eyes must set this.

WHY (3) IS NOT THE DEFAULT — AND WHY THAT IS NOT A SOFTENED FIX.  SPEC §7's
fail-closed bias is about ambiguous INPUT: an unparseable value resolves to the
most-guarded reading.  It is not a licence to disable a subsystem when CONFIG
is absent.  Defaulting (3) on would make every hold unresolvable on upgrade for
every existing deployment — the holds API, the holds CLI (RFX-42) and the
dashboard would all stop working until an operator wrote a token map.  That is
not a wrong-DENY on one action, it is a feature outage, and the trade is not
core's to make silently.  So the default is: still resolvable, but the evidence
now tells the truth about what was verified, and core says so loudly on stderr.
Whether to flip the default is flagged as an OWNER GATE in the PR.
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


def strict_mode() -> bool:
    """True if an unverifiable approver must be refused outright."""
    return os.environ.get(_STRICT_ENV, "").strip().lower() in ("true", "1", "yes")


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
    human sentence.
    """

    def __init__(self, error: str, reason: str) -> None:
        super().__init__(reason)
        self.error = error
        self.reason = reason


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
                "the asserted principal does not match the principal bound to "
                "this credential; a caller may only approve as itself",
            )
        return {"type": bound["type"], "id": bound["id"],
                "verified": True, "source": "credential"}

    # No binding for this credential.
    if verification_configured() or strict_mode():
        # Either this deployment DOES bind credentials (and this one is not in
        # the map), or it demands verified approvers. Both mean: refuse.
        raise PrincipalRefused(
            "principal_not_verified",
            "this credential is not bound to an approving principal, so the "
            "asserted principal cannot be verified; four-eyes cannot be "
            "established for this resolution",
        )

    # Unverifiable, and this deployment has not opted into strictness.  Accept
    # the assertion but record it AS an assertion -- see the module docstring
    # for why this is not a softened fix.  Loud on stderr because a deployment
    # running like this cannot claim four-eyes.
    print(
        "[reeflex-core] WARN: resolving a hold with an UNVERIFIED approver "
        "(%s:%s) -- no %s binding for this credential. The hold record is "
        "marked decided_by_verified=false. Set %s to bind credentials to "
        "principals, or %s=true to refuse instead."
        % (asserted_type, asserted_id, _TOKENS_ENV, _TOKENS_ENV, _STRICT_ENV),
        file=sys.stderr,
    )
    return {"type": asserted_type, "id": asserted_id,
            "verified": False, "source": "asserted"}
