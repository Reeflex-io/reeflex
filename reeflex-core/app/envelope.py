"""
envelope.py — Action Envelope validation and conservative-default injection.

Implements SPEC §2 rules:
  - REQUIRED fields: action.verb, target.environment, axes (object present).
  - Missing AXIS VALUES -> safe-conservative defaults (never silent allow).
  - Non-canonical axis values -> coerced to most-restrictive (fail-closed).
  - Structural invalidity -> ValidationError (caller returns HTTP 400).

EVERY CLOSED ENUM IS CANONICALIZED HERE, IN ONE PLACE.  The rules in
policy/*.rego compare caller-supplied strings by EXACT match, so a closed-enum
field that reaches OPA verbatim fails OPEN on any near-miss.  Three fields are
closed enums per the SPEC and all three are folded to their canonical member
before eval, with anything unrecognized coerced to the most-guarded member:
    axes.*             (SPEC §4)  -> F1
    target.environment (SPEC §2)  -> F5, added by RFX-CORE-1 / PR #89
    action.verb        (SPEC §3)  -> F6, added by RFX-CORE-3
If a future rule exact-matches a NEW caller-supplied field, canonicalize it
here first — that is the whole lesson of #89 and RFX-CORE-3.
  - NOTE: meta.signature / meta.nonce verification = roadmap (TODO below).

SKELETON SHORTCUTS (upgrade path documented):
  - Signature verification (meta.signature): TODO — wire ed25519 verify once
    the key distribution mechanism is settled (Vault-backed key per adapter).
  - Nonce replay store: TODO — replace the in-process nonce set with a
    distributed cache (Redis / Postgres) for multi-replica deployments.
"""

from __future__ import annotations

import threading
import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# Shared token normalizer (used by the environment AND verb canons below)
#
# A closed-enum field is only as closed as its comparison.  Every canon in this
# module funnels through here first so that a value which merely LOOKS
# different from a canonical member cannot be treated as a different value:
#
#   NFKC        folds compatibility/fullwidth forms, so "ｄｅｌｅｔｅ" and
#               "delete" are the same token.
#   Cc/Cf strip drops control and format characters -- a trailing "\n", a
#               zero-width space ("delete​"), a BOM, an RLO override.
#               These are invisible in a log line, which is exactly what makes
#               them useful for slipping past an exact-string rule.
#   strip       leading/trailing whitespace.
#   casefold    case, more aggressively than lower() (handles e.g. "ß").
#
# NOTE: this deliberately runs BEFORE the alias lookup, never after -- the
# point is that the lookup key is already canonical.
# ---------------------------------------------------------------------------


def _normalize_token(raw: str) -> str:
    """Fold a caller-supplied enum-ish string to a stable comparison key."""
    folded = unicodedata.normalize("NFKC", raw)
    cleaned = "".join(
        ch for ch in folded if unicodedata.category(ch) not in ("Cc", "Cf")
    )
    return cleaned.strip().casefold()

# ---------------------------------------------------------------------------
# F1: Closed enums + conservative defaults for axis VALUES (SPEC §2, §4)
#
# Match is EXACT (case-sensitive, lowercase canonical).
# Anything NOT in the allowed set (including absent) -> most-restrictive member.
# This means a non-canonical value like "Irreversible" or "permanent" is treated
# as "irreversible" (deny-class), never silently passed to OPA as unknown.
# ---------------------------------------------------------------------------

_AXIS_ALLOWED: dict[str, frozenset[str]] = {
    "reversibility": frozenset({"reversible", "recoverable", "irreversible"}),
    "blast_radius": frozenset({"single", "scoped", "broad", "systemic"}),
    "externality": frozenset({"internal", "outbound", "physical"}),
}

_AXIS_DEFAULTS: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "physical",
}

# ---------------------------------------------------------------------------
# F5: target.environment is a CLOSED ENUM (SPEC §2: production | staging | dev),
# and SPEC §7 requires unknown/undeterminable values to default safe-conservative
# — exactly the treatment the axes above already get.  Historically environment
# was passed to OPA VERBATIM, so R2/R3 (which match `environment == "production"`
# exactly) FAILED OPEN on any near-miss: "Production", "PROD", "prod",
# "production " (trailing space), a zero-width char, etc. all missed the exact
# match and fell through to R4 default_allow — i.e. an irreversible systemic
# production action was ALLOWED with no human.  We now canonicalize environment
# the same way we canonicalize axes: strip + casefold, map known aliases to the
# canonical tier, and coerce anything unrecognized to the most-guarded tier
# ("production") so the firewall fails CLOSED, never open.
#
# TRADE-OFF (documented deliberately): coercing an UNRECOGNIZED environment
# string (e.g. a custom "qa-eu") to "production" can turn an allow into a
# hold/deny (a wrong-DENY).  For a safety firewall that is the correct bias —
# a wrong DENY is a nuisance, a wrong ALLOW is the product failing.  Adapters
# SHOULD emit one of the SPEC enum values; out-of-enum strings are treated as
# production by design.
# ---------------------------------------------------------------------------

_ENV_CANON: dict[str, str] = {
    "production": "production",
    "prod": "production",
    "prods": "production",
    "prd": "production",
    "live": "production",
    "staging": "staging",
    "stage": "staging",
    "stg": "staging",
    "dev": "dev",
    "development": "dev",
    "develop": "dev",
    "test": "dev",
    "testing": "dev",
}

# The conservative default for any environment string we do not recognize:
# the most-guarded tier, so R2/R3 fire rather than being evaded.
_ENV_DEFAULT: str = "production"


def _canonicalize_environment(raw_env: str) -> str:
    """Map a raw environment string to its canonical SPEC tier.

    Normalize first (see _normalize_token: NFKC + control/format strip + strip
    + casefold, so "Production", " production ", "PRODUCTION", "staging​"
    all fold), then look up the alias table.  Anything unrecognized coerces to
    the most-restrictive tier ("production") — fail-closed, never fail-open.

    RFX-CORE-2 note: this used to be a bare `.strip().casefold()`.  Routing it
    through _normalize_token cannot weaken the gate — an unrecognized value
    still coerces to "production" — and it removes a latent WRONG-DENY, where
    a non-prod tier carrying an invisible character ("dev​", "staging\n")
    missed its own alias and was escalated to production.
    """
    return _ENV_CANON.get(_normalize_token(raw_env), _ENV_DEFAULT)


# ---------------------------------------------------------------------------
# F6: action.verb is ALSO a CLOSED ENUM (SPEC §3: "Adapters map backend
# operations onto a small, fixed verb set" — read | create | update | delete |
# execute | transact | emit), and it was NOT canonicalized.  This is the same
# class of defect PR #89 fixed for target.environment, one field over.
#
# R5 (the cumulative delete budget, SPEC §4.1) is keyed on the EXACT literal
# "delete" on both sides of its comparison:
#
#     current    budgets.rego current_for("deletions")  input.action.verb == "delete"
#     cumulative budgets.rego cumulative_for("deletions") cumulative.count_by_verb.delete
#
# and ledger.py keys count_by_verb on the verb string VERBATIM.  So any other
# spelling of a delete — "Delete", "DELETE", "delete " (trailing space), a
# trailing newline, a zero-width char, or a plain synonym ("remove",
# "destroy", "purge", "drop", "truncate", "rm") — accumulates under its OWN
# ledger key and never reaches the budget.  Fragmentation resistance is the
# entire stated purpose of R5 ("fragmentation buys nothing", SPEC §4.1), so
# this was the rule failing at precisely the thing it exists to do, and it
# failed OPEN: the verdict was R4 default_allow, unbounded, forever.
#
# Fix mirrors the environment canon: normalize, alias-map to the closed SPEC
# §3 verb set, and coerce anything UNRECOGNIZED to the most-guarded member.
#
# WHY "delete" IS THE MOST-GUARDED VERB: of the seven SPEC verbs, `delete` is
# the only one that carries a verb-driven budget consequence.  `external_sends`
# is driven by axes.externality and `money` by params.amount — neither reads
# the verb — and `objects_touched` counts every action regardless.  R1 reads
# the verb but only to ALLOW (`verb == "read"`), so `read` is the one member an
# unknown verb must never coerce to.  That leaves `delete` as the only coercion
# target that can tighten the gate, which is what SPEC §7 asks for.
#
# WHICH DEFAULT AN UNRECOGNIZED VERB GETS — AND WHY IT IS CONDITIONAL.
# Coercing EVERY unrecognized verb to `delete` was the first cut, and it is too
# blunt: it silently converts the deletions budget (20) into a global action cap
# for any adapter whose vocabulary we do not alias, well below the
# `objects_touched` budget (200) that RFX-11 added precisely to be the
# cross-cutting backstop.  A benign, reversible, long-tail action (a "react", a
# "vote", some domain verb nobody has aliased yet) would collect a spurious
# require_approval after 20 calls, and RFX-11's heterogeneous-smurfing
# behaviour would be masked by a delete budget that fired first.
#
# So the destructiveness signal is taken from the axis that already carries it,
# and that is ITSELF canonicalized fail-closed just above: reversibility.
#
#     unrecognized verb + irreversible          -> "delete"   (guarded)
#     unrecognized verb + reversible/recoverable -> "update"   (policy-inert)
#
# This composes well with F1: a missing, malformed or unknown `axes` block
# already coerces reversibility to `irreversible`, so an envelope that omits
# its axes entirely still lands an unknown verb on `delete`.  You have to
# affirmatively declare the action reversible to get the lenient default.
#
# `update` is the lenient target because it is policy-inert (no rule reads it)
# while still being honest — "this changed some state and we do not recognize
# the operation".  It is deliberately NOT `read`, which would hand out R1.
#
# TRADE-OFF (documented deliberately, same as #89): an irreversible action
# whose verb we do not alias is counted against the deletions budget, so an
# adapter inventing an irreversible verb can collect a spurious
# require_approval once its session passes 20 such actions.  That is a
# wrong-DENY (a nuisance) traded for closing a wrong-ALLOW (the product
# failing).  The generous alias table below keeps the trade-off cheap: every
# ordinary operation an adapter is likely to emit is mapped explicitly, so
# only genuinely novel verbs reach a default at all.
#
# RESIDUAL, STATED PLAINLY: a caller that declares a hard delete `reversible`
# evades the deletions budget under a novel verb.  That caller has strictly
# easier evasions available already (write `verb: "read"`), so this is not a
# new hole — it is the same unverifiable-self-assertion limit called out below.
#
# WHAT THIS DOES NOT CLOSE, STATED PLAINLY: action.verb is ASSERTED by the
# adapter and is not verifiable by core.  A caller that deliberately labels a
# delete as `verb: "read"` still evades the deletions budget — it could always
# do that, since "read" is a canonical value requiring no evasion at all.
# This fix closes the NEAR-MISS and SYNONYM surface (the spellings an honest
# adapter actually emits, and the ones an attacker reaches for first because
# they still read as a delete); it does not and cannot make an asserted verb
# trustworthy.  _delete_signal_from_ability() below adds one cross-check
# against that deliberate case.  Only signed envelopes (SPEC §6, roadmap)
# close it properly.
# ---------------------------------------------------------------------------

# The closed SPEC §3 verb set.
_SPEC_VERBS: frozenset[str] = frozenset(
    {"read", "create", "update", "delete", "execute", "transact", "emit"}
)

_VERB_CANON: dict[str, str] = {
    # -- read: observe, no state change -----------------------------------
    "read": "read", "list": "read", "get": "read", "query": "read",
    "search": "read", "describe": "read", "inspect": "read", "select": "read",
    "fetch": "read", "view": "read", "show": "read", "head": "read",
    "index": "read", "count": "read", "exists": "read", "stat": "read",
    "ls": "read", "cat": "read", "find": "read", "scan": "read",
    "lookup": "read", "retrieve": "read", "download": "read", "export": "read",
    "check": "read", "status": "read", "diff": "read", "log": "read",
    # -- create: add new state --------------------------------------------
    "create": "create", "insert": "create", "add": "create", "new": "create",
    "make": "create", "register": "create", "provision": "create",
    "upload": "create", "import": "create", "mkdir": "create",
    "clone": "create", "copy": "create", "duplicate": "create",
    "generate": "create", "issue": "create", "mint": "create",
    "post": "create", "attach": "create",
    # -- update: modify existing state ------------------------------------
    "update": "update", "modify": "update", "edit": "update",
    "patch": "update", "change": "update", "set": "update",
    "rename": "update", "move": "update", "alter": "update",
    "upsert": "update", "replace": "update", "put": "update",
    "write": "update", "configure": "update", "enable": "update",
    "disable": "update", "toggle": "update", "assign": "update",
    "grant": "update", "tag": "update", "label": "update",
    "publish_draft": "update", "approve": "update", "merge": "update",
    # -- delete: remove state ---------------------------------------------
    # Every near-miss and synonym that previously walked past R5.
    "delete": "delete", "remove": "delete", "destroy": "delete",
    "drop": "delete", "truncate": "delete", "purge": "delete",
    "erase": "delete", "wipe": "delete", "del": "delete", "rm": "delete",
    "rmdir": "delete", "unlink": "delete", "expunge": "delete",
    "clear": "delete", "flush": "delete", "evict": "delete",
    "prune": "delete", "obliterate": "delete", "nuke": "delete",
    "shred": "delete", "discard": "delete", "trash": "delete",
    "revoke": "delete", "deprovision": "delete", "terminate": "delete",
    "kill": "delete", "teardown": "delete", "destroy_all": "delete",
    "hard_delete": "delete", "soft_delete": "delete",
    "bulk_delete": "delete", "delete_all": "delete", "delete_many": "delete",
    "batch_delete": "delete", "mass_delete": "delete", "force_delete": "delete",
    "uninstall": "delete", "deregister": "delete", "detach": "delete",
    "unpublish": "delete", "unset": "delete", "format": "delete",
    # -- execute: run / trigger / deploy ----------------------------------
    "execute": "execute", "exec": "execute", "run": "execute",
    "invoke": "execute", "call": "execute", "trigger": "execute",
    "deploy": "execute", "apply": "execute", "start": "execute",
    "restart": "execute", "stop": "execute", "launch": "execute",
    "schedule": "execute", "spawn": "execute", "rollout": "execute",
    "rollback": "execute", "migrate": "execute", "build": "execute",
    "compile": "execute", "sync": "execute", "reindex": "execute",
    # -- transact: move money or commit an obligation ---------------------
    "transact": "transact", "pay": "transact", "payment": "transact",
    "refund": "transact", "charge": "transact", "transfer": "transact",
    "withdraw": "transact", "deposit": "transact", "purchase": "transact",
    "buy": "transact", "sell": "transact", "invoice": "transact",
    "settle": "transact", "sign": "transact", "subscribe": "transact",
    "chargeback": "transact", "payout": "transact", "capture": "transact",
    # -- emit: send to the outside world ----------------------------------
    "emit": "emit", "send": "emit", "publish": "emit", "notify": "emit",
    "email": "emit", "mail": "emit", "message": "emit", "broadcast": "emit",
    "dispatch": "emit", "share": "emit", "tweet": "emit", "webhook": "emit",
    "sms": "emit", "push": "emit", "announce": "emit", "forward": "emit",
    "reply": "emit", "post_message": "emit", "comment": "emit",
    # -- benign long-tail interactions, aliased explicitly so they never reach
    # a default at all. These are the "individually harmless small actions of
    # different types" objects_touched exists to accumulate (RFX-11).
    "react": "create", "like": "create", "upvote": "create",
    "downvote": "create", "vote": "create", "star": "create",
    "bookmark": "create", "favorite": "create", "follow": "create",
    "annotate": "create", "note": "create", "rate": "create",
    "ping": "read", "heartbeat": "read", "healthcheck": "read",
    "acknowledge": "update", "mark_read": "update", "pin": "update",
    "watch": "update", "subscribe_topic": "update",
}

# Defaults for a verb we do not recognize. Conditional on the reversibility
# axis — see "WHICH DEFAULT AN UNRECOGNIZED VERB GETS" above.
_VERB_DEFAULT_IRREVERSIBLE: str = "delete"
_VERB_DEFAULT: str = "update"

# Separators an adapter may use inside a compound verb ("hard-delete",
# "hard delete", "hard.delete", "delete/all") — all folded to "_" so one
# alias entry covers every spelling of the same compound.
_VERB_SEPARATORS = {ord(c): "_" for c in " -./:\\\t"}


def _split_words(raw: str) -> list[str]:
    """Split a raw identifier into lowercase words.

    Handles BOTH conventions real adapters use for compound operation names:
      separators   "hard-delete", "hard_delete", "delete/all", "hard delete"
      camel case   "DeleteObject", "PutObject", "listDeletedObjects"
    Camel boundaries are found on the RAW string, before casefolding, because
    casefolding destroys them.  AWS/S3-style ability ids ("DeleteObject") are
    camel case with no separator at all, so a separator-only split would miss
    the operative verb entirely.
    """
    spaced = []
    for i, ch in enumerate(raw):
        if i and ch.isupper() and (raw[i - 1].islower() or raw[i - 1].isdigit()):
            spaced.append("_")
        spaced.append(ch)
    token = _normalize_token("".join(spaced))
    return [p for p in token.translate(_VERB_SEPARATORS).split("_") if p]


def _verb_key_variants(raw_verb: str):
    """Yield the lookup keys to try for a raw verb, most specific first."""
    token = _normalize_token(raw_verb)
    yield token                        # "delete"      (already canonical)
    words = _split_words(raw_verb)
    if not words:
        return
    yield "_".join(words)              # "hard delete" -> "hard_delete"
    yield "".join(words)               # "hard delete" -> "harddelete"
    # LAST RESORT: the leading word of a compound. Operation names are
    # conventionally verb-first ("DeleteObject", "delete_backup_policy",
    # "GetObject"), so this recovers the operative verb from a compound we do
    # not alias wholesale. It cannot create an evasion a caller did not
    # already have -- anything it resolves to a non-delete verb was reachable
    # by simply writing that verb -- but it does prevent a pile of wrong-DENYs
    # for adapters that speak CamelCase API operation names.
    if len(words) > 1:
        yield words[0]


def _canonicalize_verb(raw_verb: str, canonical_reversibility: str) -> str:
    """Map a raw action verb to its canonical SPEC §3 member.

    Try the normalized verb as-is, then with separators/camel boundaries
    folded, then its leading word.  Anything still unrecognized falls back on
    the reversibility axis: irreversible -> "delete" (guarded), otherwise
    "update" (policy-inert).  Never "read", which would hand out R1.

    `canonical_reversibility` MUST be the already-canonicalized axis value
    (F1 runs first), so a missing or garbage axes block has already become
    "irreversible" and lands here on the guarded default.
    """
    for key in _verb_key_variants(raw_verb):
        if key in _VERB_CANON:
            return _VERB_CANON[key]
    if canonical_reversibility == "irreversible":
        return _VERB_DEFAULT_IRREVERSIBLE
    return _VERB_DEFAULT


def _delete_signal_from_ability(ability: Any) -> bool:
    """True if action.ability names a delete while action.verb claims otherwise.

    Defence in depth against the one case the verb canon cannot reach: a
    DELIBERATE mislabel, where the envelope says `verb: "read"` but the
    ability it also carries says `wordpress/delete-post`.  `ability` is the
    backend-specific operation id and is what the audit trail describes the
    real operation as (SPEC §2), so a contradiction between the two is a
    strong signal — and SPEC §7 says an ambiguous input resolves to the
    most-guarded reading.

    DELIBERATELY NARROW, to keep this from inventing wrong-DENYs:
      - only the LAST "/"-separated segment is considered (the operation, not
        the namespace), and
      - only its FIRST token, because backend ability ids are conventionally
        `verb-object` ("delete-post", "list-objects").
    So "wordpress/delete-post" signals a delete, while
    "s3/list-deleted-objects" does NOT (its first token is "list") — the
    past-tense/adjectival forms that would cause false positives are also
    absent from _VERB_CANON on purpose.
    """
    if not isinstance(ability, str) or not ability:
        return False
    words = _split_words(ability.rsplit("/", 1)[-1])
    if not words:
        return False
    return _VERB_CANON.get(words[0]) == "delete"

# ---------------------------------------------------------------------------
# Nonce store — in-memory replay protection (skeleton; see upgrade TODO above)
# ---------------------------------------------------------------------------

_nonce_lock = threading.Lock()
_seen_nonces: set[str] = set()


def _check_nonce(nonce: str | None) -> None:
    """Raise ValidationError if nonce is absent or already seen."""
    if not nonce:
        # Nonce field absent is a soft rejection in skeleton mode so that
        # test envelopes without nonces still pass. Production MUST enforce.
        # TODO: change this to a hard raise once nonce issuance is wired.
        return
    with _nonce_lock:
        if nonce in _seen_nonces:
            raise ValidationError("replay: nonce already seen")
        _seen_nonces.add(nonce)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when an envelope fails structural validation."""


def validate_and_fill_defaults(raw: Any) -> dict:
    """
    Validate the raw (already JSON-decoded) envelope and return a normalized
    copy with conservative defaults injected for any missing or non-canonical
    axis values.

    Raises ValidationError on structural failure (HTTP 400).
    Does NOT raise on missing-but-defaultable axis values; those are coerced
    to the most-restrictive canonical member (fail-closed per SPEC §2).

    F1: Non-canonical axis values are coerced to most-restrictive, not passed
    through verbatim (prevents silent allow on typo/case mismatch).
    F2: magnitude.count is canonicalized to int; invalid values raise.
    F3: agent.session_id is required; missing/empty raises ValidationError.
    F5: target.environment is canonicalized to the closed SPEC §2 tier enum;
        unrecognized -> "production" (most-guarded).
    F6: action.verb is canonicalized to the closed SPEC §3 verb set;
        unrecognized -> "delete" (most-guarded), so R5's delete budget cannot
        be evaded by spelling the delete differently.
    """
    if not isinstance(raw, dict):
        raise ValidationError("envelope must be a JSON object")

    # -- REQUIRED: action.verb --
    action = raw.get("action")
    if not isinstance(action, dict):
        raise ValidationError("envelope.action is required and must be an object")
    verb = action.get("verb")
    if not verb or not isinstance(verb, str):
        raise ValidationError("envelope.action.verb is required")

    # -- REQUIRED: target.environment --
    target = raw.get("target")
    if not isinstance(target, dict):
        raise ValidationError("envelope.target is required and must be an object")
    environment = target.get("environment")
    if not environment or not isinstance(environment, str):
        raise ValidationError("envelope.target.environment is required")

    # -- REQUIRED: axes object present (values may be defaulted/coerced) --
    axes = raw.get("axes")
    if axes is not None and not isinstance(axes, dict):
        raise ValidationError("envelope.axes must be an object if present")

    # -- F3: REQUIRED: agent.session_id (SPEC §7 conformance requirement) --
    # session_id MUST be a non-empty string; a numeric or other non-str value
    # is a structural error (hard reject -> 400), not silently coerced.
    agent = raw.get("agent")
    if not isinstance(agent, dict):
        raise ValidationError(
            "agent.session_id is required (SPEC section 7)"
        )
    _sid = agent.get("session_id")
    if not isinstance(_sid, str) or not _sid.strip():
        raise ValidationError(
            "agent.session_id is required (SPEC section 7)"
        )

    # -- Nonce replay check (soft in skeleton; see TODO in module docstring) --
    meta = raw.get("meta") or {}
    _check_nonce(meta.get("nonce"))

    # Build normalized copy
    envelope = dict(raw)

    # -- F5: canonicalize target.environment to the closed SPEC enum. --
    # `environment` is already guaranteed a non-empty string above.  We map it
    # to its canonical tier (production|staging|dev), coercing case/whitespace
    # near-misses AND any unrecognized value to the most-restrictive tier so
    # R2/R3 cannot be evaded by writing "Production" / "prod" instead of
    # "production".  target is copied first so the caller's dict is untouched.
    _norm_target = dict(target)
    _norm_target["environment"] = _canonicalize_environment(environment)
    envelope["target"] = _norm_target

    # -- params: free passthrough; must be a dict for ledger to iterate safely.
    # If present but not a dict (string, list, number) -> coerce to {}.
    # This is NOT a 400: params is optional, free-form, and not decision-critical.
    _raw_params = envelope.get("params")
    if _raw_params is not None and not isinstance(_raw_params, dict):
        envelope["params"] = {}

    # -- F1: Axes: coerce absent OR non-canonical values to most-restrictive --
    # Exact, case-sensitive match against the SPEC §4 closed enum.
    # Anything outside the allowed set (including absent, wrong case, typo)
    # coerces to the conservative default — it is never passed to OPA verbatim.
    normalized_axes = dict(axes) if isinstance(axes, dict) else {}
    for axis, default in _AXIS_DEFAULTS.items():
        raw_value = normalized_axes.get(axis)
        # Unhashable types (list, dict) cannot be checked against a frozenset;
        # any non-str value is by definition non-canonical -> coerce to default.
        if not isinstance(raw_value, str) or raw_value not in _AXIS_ALLOWED[axis]:
            # Absent, wrong-case ("Irreversible"), typo ("permanent"),
            # or unhashable garbage (list/dict) -> most-restrictive default.
            normalized_axes[axis] = default
    envelope["axes"] = normalized_axes

    # -- F6: canonicalize action.verb to the closed SPEC §3 verb set. --
    # MUST run AFTER F1 above: an unrecognized verb's fallback depends on the
    # CANONICAL reversibility, so the axis has to be settled first.
    #
    # `verb` is already guaranteed a non-empty string.  R5's deletions
    # dimension and ledger.py's count_by_verb key are BOTH the exact literal
    # "delete", so a near-miss or synonym spelling previously accumulated under
    # its own key and never reached the budget (fail-OPEN).  Coerce here, once,
    # so the ledger, the policy, the hold record and the audit line all agree
    # on one canonical verb.  `action` is copied first so the caller's dict is
    # untouched.
    #
    # The ability cross-check runs only when the verb did NOT already
    # canonicalize to "delete", and only escalates (never relaxes) — a
    # `verb: "read"` carrying `ability: "wordpress/delete-post"` is counted as
    # the delete it describes.  See _delete_signal_from_ability().
    _norm_action = dict(action)
    _canon_verb = _canonicalize_verb(verb, normalized_axes["reversibility"])
    if _canon_verb != "delete" and _delete_signal_from_ability(action.get("ability")):
        _canon_verb = "delete"
    _norm_action["verb"] = _canon_verb
    envelope["action"] = _norm_action

    # -- F2: magnitude.count: canonicalize to int; reject invalid values --
    # Guard: magnitude must be a dict if present; a string/list is a hard error.
    _raw_magnitude = raw.get("magnitude")
    if _raw_magnitude is not None and not isinstance(_raw_magnitude, dict):
        raise ValidationError(
            f"envelope.magnitude must be an object if present, got {type(_raw_magnitude).__name__}"
        )
    magnitude = dict(_raw_magnitude) if isinstance(_raw_magnitude, dict) else {}
    raw_count = magnitude.get("count")
    if raw_count is None:
        # Absent -> conservative default of 1
        magnitude["count"] = 1
    else:
        # Reject bool (Python bool subclasses int; True/False are not valid counts)
        if isinstance(raw_count, bool):
            raise ValidationError(
                "magnitude.count must be an integer >= 1 (bool not accepted)"
            )
        # Reject non-integer types (float, string, etc.)
        if not isinstance(raw_count, int):
            raise ValidationError(
                f"magnitude.count must be an integer >= 1, got {type(raw_count).__name__} {raw_count!r}"
            )
        # Reject zero or negative
        if raw_count < 1:
            raise ValidationError(
                f"magnitude.count must be an integer >= 1, got {raw_count}"
            )
        magnitude["count"] = raw_count  # already a canonical int
    envelope["magnitude"] = magnitude

    # Ensure approval.present has a conservative default (false = not approved).
    # If approval is present but not a dict (e.g. string "yes", list), treat it
    # as no approval — fail-closed: garbage does NOT grant approval.
    _raw_approval = raw.get("approval")
    if isinstance(_raw_approval, dict):
        approval = dict(_raw_approval)
    else:
        # Non-dict approval (string, list, number, etc.) -> coerce to empty dict.
        # This includes the case where approval was absent (None).
        approval = {}
    if not isinstance(approval.get("present"), bool):
        approval["present"] = False
    envelope["approval"] = approval

    return envelope
