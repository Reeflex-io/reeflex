"""
envelope.py — Action Envelope validation and conservative-default injection.

Implements SPEC §2 rules:
  - REQUIRED fields: action.verb, target.environment, axes (object present).
  - Missing AXIS VALUES -> safe-conservative defaults (never silent allow).
  - Non-canonical axis values -> coerced to most-restrictive (fail-closed).
  - Structural invalidity -> ValidationError (caller returns HTTP 400).

EVERY CLOSED ENUM IS CANONICALIZED HERE, IN ONE PLACE.  The rules in
policy/*.rego compare caller-supplied strings by EXACT match, so a closed-enum
field that reaches OPA verbatim fails OPEN on any near-miss.  Four fields are
closed enums per the SPEC and all four are folded to their canonical member
before eval, with anything unrecognized coerced to the most-guarded member:
    axes.*             (SPEC §4)  -> F1
    target.environment (SPEC §2)  -> F5, added by RFX-CORE-1 / PR #89
    action.verb        (SPEC §3)  -> F6, added by RFX-CORE-3
    params.currency    (SPEC §4.1) -> F7, added by RFX-133
If a future rule exact-matches a NEW caller-supplied field, canonicalize it
here first — that is the whole lesson of #89 and RFX-CORE-3.
  - NOTE: meta.signature / meta.nonce verification = roadmap (TODO below).

THE ENUMERATION IS THE POINT, NOT THE FOUR INSTANCES.  `app/field_treatments.py`
declares EVERY caller-supplied field the decision path reads, together with the
treatment it gets here (canonicalize / validate / verify).  `tests/
test_field_treatments.py` derives the set of fields the policy ACTUALLY reads
from policy/*.rego and from ledger.py, and fails if any of them lacks a
declared treatment — so a new field cannot reach a rule untreated.

SKELETON SHORTCUTS (upgrade path documented):
  - Signature verification (meta.signature): TODO — wire ed25519 verify once
    the key distribution mechanism is settled (Vault-backed key per adapter).
  - Nonce replay store: TODO — replace the in-process nonce set with a
    distributed cache (Redis / Postgres) for multi-replica deployments.
"""

from __future__ import annotations

import math
import posixpath
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
#
# "Most-restrictive" is decided by what the RULES do with each member, not by
# where SPEC §4's prose lists it -- see the block above _AXIS_DEFAULTS for the
# axis where those two answers disagreed and the measurement that settled it.
# ---------------------------------------------------------------------------

_AXIS_ALLOWED: dict[str, frozenset[str]] = {
    "reversibility": frozenset({"reversible", "recoverable", "irreversible"}),
    "blast_radius": frozenset({"single", "scoped", "broad", "systemic"}),
    "externality": frozenset({"internal", "outbound", "physical"}),
}

# WHICH MEMBER IS "MOST-RESTRICTIVE" IS A MEASURABLE QUESTION, NOT A LADDER
# (RFX-129). F1's promise above is that a non-canonical value coerces to the
# member that RESTRICTS MOST. For two of the three axes the enum's written
# order and its decision effect agree, so the promise held by accident. For
# `externality` they do not, and it shipped inverted:
#
#   externality member   what any rule in the shipped pack does with it
#   -------------------  ----------------------------------------------------
#   internal             gates R1 (read_only_internal) -- an ALLOW, and R1 is
#                        itself decision-inert (RFX-130). Charges no budget.
#   outbound             charged against R5's `external_sends` budget
#                        (budgets.rego current_for/cumulative_for). THE ONLY
#                        MEMBER WITH A RESTRICTIVE EFFECT ANYWHERE.
#   physical            *nothing*. `grep physical policy/*.rego` is empty
#                        (RFX-129). No rule reads it.
#
# So coercing to `physical` -- because SPEC §4's prose lists it last and it
# sounds like the worst thing that can happen -- pointed F1 at the one member
# the policy pack cannot see, and the effect was a FAIL-OPEN on the budget
# externality exists to feed. Measured on origin/main 759b83f, one session of
# `emit`/production actions at magnitude.count=1, external_sends limit 50:
#
#   axes.externality: "outbound"   -> require_approval at call 51  (control works)
#   axes.externality  OMITTED      -> 200 allowed, held at 201 by objects_touched
#   axes.externality: "Outbound"   -> 200 allowed, held at 201 by objects_touched
#   axes.externality: "outbound "  -> 200 allowed, held at 201 by objects_touched
#
# i.e. the external_sends budget could only ever be charged by a caller that
# affirmatively spelled `outbound` byte-for-byte -- an opt-in control on the
# audited party's own word, which is the RFX-133 defect one field over ("omit
# one optional field and the spend leaves the budget entirely"). The residual
# 200 is `objects_touched`, not this dimension doing its job: an operator who
# TIGHTENS external_sends to 5 still gets 200 for the same traffic, so editing
# the limit in budgets.rego bought a 40x tightening worth exactly nothing.
#
# Hence `outbound`: the member that is measurably most-restrictive, which is
# also what the shipped n8n node already calls "the safe-conservative value"
# for this axis (ReeflexGate.node.ts) -- core was the outlier among its own
# adapters.
#
# THE COST, STATED. An adapter that omits or misspells `externality` on more
# than `external_sends` actions in one session now collects a require_approval
# it did not before. That is a wrong-HOLD, and it is the documented bias (see
# F5's trade-off note). It is also unreachable for every adapter in this repo:
# reeflex-claude sets all three axes always, reeflex-wordpress's
# resolve_externality() returns internal|outbound and never nothing, and the
# n8n node's parameter defaults to outbound. Only reeflex-mcp filled this axis
# from a mirror of THIS dict, and that mirror moves with it.
#
# NOT FIXED HERE, AND DELIBERATELY: `physical` remains read by no rule, so an
# adapter that AFFIRMATIVELY declares it still charges nothing. Whether the
# base pack should gain a rule that reads it (RFX-129's option (a):
# irreversible + physical + production -> require_approval) is a canon
# question, it is not this fail-open, and closing it would not have closed
# this one -- a reversible outbound send with an undeclared axis escaped the
# budget no matter what `physical` means. Flagged on RFX-129, not smuggled in.
_AXIS_DEFAULTS: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "outbound",
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
    # RFX-308: seven words an operator uses for a destruction and this map
    # had no entry for at all.  See the "WIDENING THIS VOCABULARY" note
    # below for why each of these is `delete` and why two of the nine words
    # the ticket named are deliberately still absent.
    "expire": "delete", "reset": "delete", "rotate": "delete",
    "overwrite": "delete", "compact": "delete", "vacuum": "delete",
    "restore": "delete",
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

# ---------------------------------------------------------------------------
# RFX-308: WIDENING THIS VOCABULARY — AND THE ONE DIRECTION IT MUST NOT MOVE.
#
# THE GAP.  reeflex-mcp's `_MUTATING_STEMS` (51 stems, RFX-175) is the other
# layer's reading of "this word names a mutation".  42 of the 51 had an entry
# here.  NINE did not: expire, reset, restore, rotate, overwrite, commit,
# compact, vacuum, install.  Measured on the deployed v0.2.1 (image id
# sha256:2f18d19f…, whose `envelope.py` is byte-identical to origin/main), one
# /v1/decide per word with only `action.verb` varying, canonical verb read back
# out of the container's own audit line:
#
#     verb: "vacuum"   irreversible/single/internal/production -> recorded
#                      `delete`  (the F6 default, not the word)
#     verb: "vacuum"   REVERSIBLE/single/internal/production   -> recorded
#                      `update`  (the policy-inert default)
#     ability: "db/vacuum-rows" with verb "read"               -> recorded
#                      `read`, decided reeflex.policy/read_only_internal
#
# i.e. each of the nine was indistinguishable from `frobnicate`, and 25
# reversible `expire` / `overwrite` / `vacuum` calls in one session charged
# R5's deletions budget nothing at all (the canonical-`delete` control in the
# same run held on call 21).  The ability cross-check below shared the gap: it
# resolves the operation id through THIS map, so an adapter naming the
# operation honestly — `db/expire-rows` — signalled nothing.
#
# THE TRAP, AND WHY THE TICKET'S OWN PROPOSED MAPPING WOULD HAVE WEAKENED CORE.
# RFX-308 suggested `rotate/overwrite/compact/vacuum -> update` and
# `restore -> create`.  Measuring what happens TODAY shows why that is the
# wrong direction: an unrecognized IRREVERSIBLE verb already resolves to
# `delete` (the guarded default, twenty lines above).  So mapping any of these
# words to a non-`delete` member would REMOVE an irreversible production
# `overwrite` from the one budget that prices destruction — a de-escalation
# bought with a compound fix, on the exact surface R5 exists to close.
#
# THE RULE THIS MAP NOW FOLLOWS, STATED SO THE NEXT ADDITION KEEPS IT: a word
# joins the destructive section only if `delete` is at least as guarded as
# what it resolves to today on BOTH reversibility values.  In practice that
# means the widening is `delete` or nothing, and the seven above are the ones
# that earn it — each names the removal of state that was there before:
#   expire    a session, token or object stops existing (neighbours: `evict`,
#             `flush`, `revoke`)
#   reset     current state is discarded for the initial one (`truncate`)
#   rotate    the superseded credential stops working (`revoke`)
#   overwrite the prior content is gone.  `replace` is still `update`, which
#             is deliberate and is the asymmetry a reader will ask about:
#             `search_and_replace` names a write, `overwrite_backup` names the
#             loss of the backup.
#   compact   superseded versions and tombstones are dropped
#   vacuum    same, under the word a DBA uses for it
#   restore   from the operator's side this creates; from the data's side the
#             live state it lands on is gone, and that is the side a budget
#             called "deletions" is counting.
#
# `commit` AND `install` ARE DELIBERATELY ABSENT, and this is the residual.
# Neither names a destruction (`commit` is a transaction or a revision;
# `install` adds software), so neither earns `delete`, and mapping them to
# `transact`/`execute` would lower today's guard on their irreversible use.
# What that leaves open: WITH the RFX-304 election in the tree, a compound
# like `count_and_install` still elects `count` -> `read` -> R1.  That is
# unchanged by this commit rather than introduced by it, and the fix for it is
# a rule about UNKNOWN words in the election, not more vocabulary.  Filed
# separately.
#
# CLOSED BY RFX-324, AND THIS NOTE UNDERSTATED IT BY TEN WORDS.  The residual
# is not `commit` and `install`: the election skips EVERY word the canon does
# not know, so it was the whole complement of the canon — `get_and_redact`,
# `list_and_anonymize`, `describe_and_decommission` and nine more, ALLOWED
# under R1 as decisions on an irreversible production envelope.  The rule that
# closed it is the NARROW half of the one proposed above: see the RFX-324
# block in `_verb_last_resort_key`, which also records why the wide reading
# ("an unknown word outranking `read`") must not ship.
#
# THE COST, MEASURED (dev-1--080 evidence).  A word here escalates any name
# that CONTAINS it, so a genuine read can be priced a delete.  Over the 39
# real MCP tool names in reeflex-mcp's own test corpus the wrong-escalation
# count is 0 and `count_and_compact` — the name RFX-308 is written around —
# stops reading as `read`; over nine read-only names built adversarially to
# carry one of these words, four escalate (`get_reset_token_status`,
# `get_overwrite_policy`, `show_vacuum_progress`, `describe_restore_point`).
# The past-tense and noun forms an operator actually writes for a read do NOT
# match, because this map has no entry for them: `list_expired_sessions`,
# `list_installed_packages`, `get_compaction_stats` and `check_rotation_
# schedule` stay reads.  A wrong escalation costs a HOLD once the operator's
# deletions budget is spent, names its reason, and is removed by declaring a
# canonical verb — one field.  The other direction costs a customer their data
# with no human in it.
# ---------------------------------------------------------------------------

# Separators an adapter may use inside a compound verb ("hard-delete",
# "hard delete", "hard.delete", "delete/all") — all folded to "_" so one
# alias entry covers every spelling of the same compound.
_VERB_SEPARATORS = {ord(c): "_" for c in " -./:\\\t"}

# ---------------------------------------------------------------------------
# RFX-304: HOW A COMPOUND VERB ELECTS ITS WORD.
#
# THE DEFECT.  The last resort below used to take the LEADING word of a
# compound, on the convention that operation names are verb-first.  Measured
# on the deployed v0.2.1 (= this code): `findOneAndDelete` — MongoDB's own
# operation name — splits to [find, one, and, delete], `find` hits the canon
# first, and an irreversible PRODUCTION deletion is decided by
# `reeflex.policy/read_only_internal`, written into the permanent audit line
# as `verb: "read"`, and charged NOTHING by R5's deletions budget.  Twenty
# lines above, the design note states the invariant the default already keeps:
# "It is deliberately NOT `read`, which would hand out R1."  The alias lookup
# did not keep it.
#
# WHY THE OLD DOCSTRING'S DEFENCE WAS WRONG.  It argued the last resort "cannot
# create an evasion a caller did not already have — anything it resolves to a
# non-delete verb was reachable by simply writing that verb".  That is true of
# a deliberate attacker and false of the HONEST integration this canon exists
# to serve: a customer's backend passes its own operation name through, means
# every letter of it, and gets R1.
#
# THE RULE NOW: among the words of a compound that the canon knows, elect the
# MOST-GUARDED one; ties go to the earliest, which preserves the verb-first
# convention the last resort was added for (`DeleteObject`, `GetObject`,
# `delete_backup_policy` all resolve exactly as before).
#
# THE RANK IS A READING OF THE SHIPPED PACK, NOT AN INVENTED RISK ORDER.
# `grep -n 'action.verb' policy/*.rego` finds exactly three rules:
#   2  delete   budgets.rego's `deletions` dimension charges `verb == "delete"`
#               and nothing else — the only verb any budget prices.
#   1  create / update / execute / transact / emit — read by NO rule in the
#               pack.  Their order relative to each other is therefore a
#               convention with no verdict consequence today; it decides only
#               which word the audit line records, and earliest-wins keeps
#               that the caller's own leading word wherever it can.
#   0  read     R1 (`verb == "read"` + internal) is the only ALLOW any verb
#               unlocks, and R7 exempts `verb != "read"`.  Strictly the least
#               guarded value in the vocabulary.
# If a future rule reads another verb, this table is where that changes.
#
# THE COST, MEASURED AND NOT ARGUED (dev-1--074 evidence, census arm).  The
# election can ESCALATE a genuine read whose name embeds a destructive word:
# `list_trash`, `check_delete_permission`, `describe_clear_policy` go read ->
# delete.  Over the 39 real MCP tool names in reeflex-mcp's own test corpus
# the escalation count is ZERO; over eight names built adversarially to carry
# that shape it is five.  The bias is deliberate and is the same one RFX-175
# took one layer up in reeflex-mcp's `_MUTATING_STEMS`: a wrong escalation
# costs a HOLD once an operator's deletions budget is exceeded, is visible in
# the reason string, and is fixed by the adapter declaring a canonical verb —
# which costs one field.  A missed de-escalation costs a customer their data
# with no human anywhere in it.
# ---------------------------------------------------------------------------
_VERB_GUARD_RANK: dict[str, int] = {
    "read": 0,
    "create": 1, "update": 1, "execute": 1, "transact": 1, "emit": 1,
    "delete": 2,
}

# RFX-324: the words that join two OPERATIONS in an operation name.  Read by
# `_verb_last_resort_key` only, and only to decide whether a leading `read`
# word is still the whole operation — see the block there for why the rule is
# a conjunction and not "any unknown word".  These three are the spellings the
# census names actually use (`findOneAndDelete`, `get_or_create_index`,
# `fetch_then_purge`); they are not a general English conjunction list, and a
# word added here TIGHTENS (it can only ever turn an elected `read` into the
# reversibility default), never the other way.
_VERB_CONJUNCTIONS: frozenset[str] = frozenset({"and", "or", "then"})


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
    """Yield the lookup keys for a verb the caller spelled WHOLE, most
    specific first.

    These three are recognitions, not guesses: each matches the caller's own
    string end to end, modulo folding and separators.  The per-word election
    that handles a compound the canon does not alias wholesale is deliberately
    NOT here — it lives in `_verb_last_resort_key()` so that
    `_verb_is_declared()` cannot silently inherit it again (RFX-304 §4.2).
    """
    yield _normalize_token(raw_verb)   # "delete"      (already canonical)
    words = _split_words(raw_verb)
    if not words:
        return
    yield "_".join(words)              # "hard delete" -> "hard_delete"
    yield "".join(words)               # "hard delete" -> "harddelete"


def _verb_last_resort_key(raw_verb: str) -> str | None:
    """LAST RESORT for a compound the canon does not alias wholesale: the
    MOST-GUARDED word it contains, or None if it contains no known word.

    Ties go to the earliest word, so the verb-first convention this was
    originally added for is preserved exactly ("DeleteObject",
    "delete_backup_policy", "GetObject", "PutObject" all resolve as before).
    See the _VERB_GUARD_RANK block above for why the rank is what it is, and
    for the escalation cost this trades a fail-open against (RFX-304).

    This is a GUESS about a string the caller did not spell canonically, and
    `_verb_is_declared()` reports it as one.
    """
    words = _split_words(raw_verb)
    if len(words) < 2:
        return None
    best_rank, best_word = -1, None
    for word in words:
        canon = _VERB_CANON.get(word)
        if canon is None:
            continue
        rank = _VERB_GUARD_RANK[canon]
        if rank > best_rank:          # strict: first word of a rank wins
            best_rank, best_word = rank, word
    # A `read` MAY ONLY BE ELECTED FROM THE LEADING WORD (dev-1--080).
    #
    # Measured on a core running this file against one running origin/main's,
    # same image, same policy, one file apart:
    #
    #   verb "compact_event_log"    irreversible -> origin/main: `delete`
    #                                               this rule w/o the guard
    #                                               below: `read` = R1
    #   verb "rebuild_search_index"              -> same
    #   verb "refresh_materialized_status"       -> same
    #   verb "zorp_query"                        -> same
    #
    # The election is only as good as the word it elects.  When the operative
    # verb is one the canon does NOT know, an incidental read NOUN later in
    # the name ("log", "index", "status", "query") was the highest-ranked
    # known word, so the compound resolved to `read` — strictly WEAKER than
    # the fallback it replaced, which lands an unknown compound on the
    # reversibility default (`delete` / `update`) and never on `read`.
    #
    # The convention this file already relies on settles it: operation names
    # are VERB-FIRST.  A read word in the leading position IS the operation
    # ("GetObject", "list_deleted_objects", "query_status" — all preserved);
    # a read word after a leading word we do not recognize is an object, not
    # the verb.  So when every known word is a read and none of them leads,
    # this returns None and the caller falls through to the default that
    # `_VERB_DEFAULT_IRREVERSIBLE`'s note above calls "deliberately NOT read,
    # which would hand out R1".
    if best_rank == 0 and best_word != words[0]:
        return None
    # AND A LEADING `read` DOES NOT SURVIVE AN EXPLICIT CONJUNCTION FOLLOWED BY
    # A WORD THE CANON DOES NOT KNOW (RFX-324).
    #
    # The guard above assumes the leading read word IS the operation.  For a
    # NAMED SECOND OPERATION that assumption is false, and the RFX-308 note
    # twenty lines up says so in passing — "a compound like `count_and_install`
    # still elects `count` -> `read` -> R1" — while characterising the residual
    # as the two words that note declined to add to the vocabulary.  It is not
    # two words.  The election skips EVERY word the canon does not know, so the
    # residual is the whole complement of the canon.  Measured as DECISIONS on
    # `caf2cd6` (qa--229's probe, the real pack, deletions budget 20):
    #
    #   verb "get_and_redact"            irreversible/scoped/internal/production
    #                                    -> allow, reeflex.policy/read_only_
    #                                       internal, canonical verb `read`,
    #                                       26 calls in one session without
    #                                       stopping
    #   verb "describe_and_decommission" -> same
    #   verb "list_and_unmount"          -> same
    #   verb "delete" (control)          -> require_approval at call 21
    #
    # i.e. GDPR erasure, account lifecycle and infra teardown, spelled the way
    # an HONEST adapter names them, decided by the one rule that hands out an
    # allow and charged nothing by the budget that prices destruction.
    #
    # WHY A CONJUNCTION AND NOT "ANY UNKNOWN WORD".  envelope.py's own RFX-308
    # note proposes the wider rule ("an unknown word outranking `read`").
    # Both rules were scored through THIS function — not through a model of it
    # — over 130 names: dev-1--080's 82-name census (every name carrying the
    # `human_reading` its own author declared, from reeflex-mcp's corpus, the
    # qa-213 attack set, the last-resort design names and two adversarial
    # sets) plus the 12 arms above in four spellings each, because an adapter
    # picks the spelling and `_split_words` folds all four.
    #
    #                        arm spellings priced `read`   declared reads
    #                        (48 = the fail-open)          priced non-read
    #                                                      (36 = the cost)
    #   shipped caf2cd6              48                        11
    #   FIX A  unknown-word veto      0                        34
    #   FIX B  this clause            0                        11
    #
    # FIX A turns `GetObject`, `search_files`, `query_database`,
    # `read_text_file` and `getUserProfile` into the irreversible default —
    # a human approval on almost every read — because a read's extra words are
    # an object noun phrase and nouns are not in a VERB canon.  A conjunction
    # is what distinguishes the two populations: every arm names a SECOND
    # operation after an explicit `and`/`or`/`then`, while
    # `list_directory_with_sizes` and `get_pull_request_comments` contain no
    # conjunction at all.  The 11 wrong escalations are the shipped tree's own
    # (RFX-304/RFX-308 priced them) and this clause moves none of them.
    #
    # WHAT THIS DOES NOT CLOSE, STATED.  A second operation named WITHOUT a
    # conjunction after a leading read word — `get_subject_erasure` — still
    # elects `get`.  That shape is not reachable by this rule without the cost
    # of the wider one, and it is the residual a future round owns.
    if best_rank == 0:
        for i, word in enumerate(words):
            if word in _VERB_CONJUNCTIONS and any(
                later not in _VERB_CANON for later in words[i + 1:]
            ):
                return None
    return best_word


def _canonicalize_verb(raw_verb: str, canonical_reversibility: str) -> str:
    """Map a raw action verb to its canonical SPEC §3 member.

    Try the normalized verb as-is, then with separators/camel boundaries
    folded, then — for a compound only — the most-guarded word it contains
    (RFX-304; it used to be the leading word, which resolved
    `findOneAndDelete` to `read`).  Anything still unrecognized falls back on
    the reversibility axis: irreversible -> "delete" (guarded), otherwise
    "update" (policy-inert).  Never "read", which would hand out R1.

    `canonical_reversibility` MUST be the already-canonicalized axis value
    (F1 runs first), so a missing or garbage axes block has already become
    "irreversible" and lands here on the guarded default.
    """
    for key in _verb_key_variants(raw_verb):
        if key in _VERB_CANON:
            return _VERB_CANON[key]
    elected = _verb_last_resort_key(raw_verb)
    if elected is not None:
        return _VERB_CANON[elected]
    if canonical_reversibility == "irreversible":
        return _VERB_DEFAULT_IRREVERSIBLE
    return _VERB_DEFAULT


# ---------------------------------------------------------------------------
# F8: CLASSIFICATION PROVENANCE — did the adapter TELL us, or did we GUESS?
# (RFX-132)
#
# Every conservative default above is correct and every one of them is a
# GUESS.  Composed, three of them price an envelope an adapter emits when it
# cannot classify an action:
#
#     {"action": {"verb": "frobnicate"},
#      "target": {"environment": "qa-eu"},
#      "axes": {}}
#
#     reversibility -> irreversible   (F1 default)
#     blast_radius  -> systemic       (F1 default)
#     environment   -> production     (F5 default)
#     = irreversible + systemic + production = R3 = DENY, TERMINALLY.
#
# R3 is the one rule a human cannot clear.  So "we could not tell what this
# was" was resolving to the most brittle answer the product has, with no human
# anywhere in it -- on a product whose value proposition IS the human in the
# loop.  See policy/reeflex.rego's R0 block for the argument about what it
# should resolve to instead; this block's only job is to make the difference
# VISIBLE to the policy, because a coerced value is indistinguishable from a
# declared one once the coercion has happened.
#
# WHAT COUNTS AS "DECLARED", AND WHY THE FOLD IS USED FOR THE JUDGEMENT BUT
# NOT FOR THE VALUE.  A field is DECLARED when the caller supplied something
# core RECOGNISES -- checked against the folded token (NFKC, control/format
# stripped, trimmed, casefolded), so "Systemic" is a declaration of systemic
# and not a guess.  That much is required for soundness: judged on the raw
# exact match, a caller would downgrade a terminal R3 DENY to a resolvable
# hold by capitalising one letter, which is RFX-86's evasion one tier up.
#
# The fold is NOT used to pick the VALUE, and that restraint is deliberate.
# `_AXIS_ALLOWED` is still matched exactly, so "Broad" still coerces to
# `systemic` exactly as it did before this change -- because folding the value
# too would turn `blast_radius: "SINGLE"` on an irreversible production action
# from a DENY into an ALLOW, and a case fix that relaxes a refusal is not
# something this ticket is chartered to do. The residual (a recognisable but
# non-canonical spelling is read as the most-guarded member, a wrong DENY) is
# UNCHANGED by this change and is its own ticket. Stated rather than quietly
# fixed or quietly ignored.
#
# CORE-COMPUTED, UNCONDITIONALLY.  A caller supplying its own `provenance`
# block would otherwise be able to assert "you guessed at this" about an
# envelope it declared perfectly, and downgrade its own R3 to a hold. Same
# treatment `cumulative` gets in decide.py, for the same reason: the block is
# overwritten from what core actually did, never merged with what the caller
# claims. See field_treatments.TREATMENTS.
# ---------------------------------------------------------------------------

#: The classification fields whose provenance is recorded. Anything a rule
#: reads to decide WHAT KIND OF ACTION this is belongs here.
#:
#: `magnitude.count` is here as of RFX-143, and it was the one field this
#: tuple's own docstring already required and did not contain. Every budget
#: dimension in budgets.rego reads it (`objects_touched` reads it
#: UNCONDITIONALLY, on every action), and F2 below fills an absent count with
#: 1 -- the MINIMUM of its domain, since F2 rejects 0 and negatives. So before
#: this change "the caller enumerated one object" and "the caller said nothing"
#: arrived at the policy as the same number, which is precisely the condition
#: this block exists to prevent: "a coerced value is indistinguishable from a
#: declared one once the coercion has happened."
_PROVENANCE_FIELDS: tuple[str, ...] = (
    "axes.reversibility",
    "axes.blast_radius",
    "axes.externality",
    "target.environment",
    "action.verb",
    "magnitude.count",
)


def _count_is_declared(raw_magnitude: Any) -> bool:
    """True if the caller supplied a `magnitude.count` core ACCEPTS.

    Mirrors F2's own acceptance test exactly, for the same reason
    `_verb_is_declared` mirrors `_canonicalize_verb`: "declared" here must mean
    "did not fall back on the default of 1" and nothing else. F2 REJECTS every
    other shape with HTTP 400 (bool, float, str, < 1), so the only value that
    reaches a rule without having been declared is the absent one.
    """
    if not isinstance(raw_magnitude, dict):
        return False
    raw_count = raw_magnitude.get("count")
    if isinstance(raw_count, bool):  # bool subclasses int; not a count
        return False
    return isinstance(raw_count, int) and raw_count >= 1


def _axis_is_declared(raw_value: Any, axis: str) -> bool:
    """True if the caller supplied a value for `axis` that core RECOGNISES."""
    if not isinstance(raw_value, str):
        return False
    return _normalize_token(raw_value) in _AXIS_ALLOWED[axis]


def _environment_is_declared(raw_env: Any) -> bool:
    """True if `target.environment` folds to a tier core knows."""
    if not isinstance(raw_env, str):
        return False
    return _normalize_token(raw_env) in _ENV_CANON


def _verb_is_declared(raw_verb: Any) -> bool:
    """True if `action.verb`, AS THE CALLER SPELLED IT, matched the SPEC §3
    verb set or an alias of it.

    RFX-304 §4.2.  This used to mirror `_canonicalize_verb` exactly, last
    resort included — so `action.verb` was recorded DECLARED *precisely* when
    core had guessed it from one word of a compound, and `provenance` asserted
    a declaration that never happened.  `action.verb` is a REQUIRED field (an
    absent one is a 400 that reaches no rule), so undeclared here means "a
    value core does not recognise" — and a compound the canon has no entry for
    is exactly that, whatever core then elects out of it.

    WHAT THIS DOES AND DOES NOT MOVE, because the obvious reading is wrong.
    No verdict changes: `r0_classification_inputs` in reeflex.rego is
    {axes.reversibility, axes.blast_radius, target.environment}, and the block
    above it says why `action.verb` is excluded — R2/R3 do not read the verb,
    so guessing it cannot be what produced the verdict R0 softens.  What moves
    is the RECORD: the audit line now says core guessed the verb on a compound
    instead of claiming the adapter declared it.
    """
    if not isinstance(raw_verb, str):
        return False
    return any(key in _VERB_CANON for key in _verb_key_variants(raw_verb))


def _delete_signal_from_ability(ability: Any) -> bool:
    """True if action.ability names a delete while action.verb claims otherwise.

    Defence in depth against the one case the verb canon cannot reach: a
    DELIBERATE mislabel, where the envelope says `verb: "read"` but the
    ability it also carries says `wordpress/delete-post`.  `ability` is the
    backend-specific operation id and is what the audit trail describes the
    real operation as (SPEC §2), so a contradiction between the two is a
    strong signal — and SPEC §7 says an ambiguous input resolves to the
    most-guarded reading.

    Only the LAST "/"-separated segment is considered — the operation, not the
    namespace, so a tenant called `purge-inc` cannot signal anything.

    RFX-304 §4.1: THIS USED TO READ ONLY THE SEGMENT'S FIRST TOKEN, WHICH IS
    THE SAME BLIND SPOT AS THE DEFECT IT DEFENDS AGAINST.  The one cross-check
    written for "the verb says read but the ability says delete" was silent on
    `mongodb/findOneAndDelete` — the most honest ability id an adapter could
    send for that call — because the ability's first token is `find` too.  A
    defence in depth that shares the failure mode of the thing it backs up is
    not depth.  Any word of the segment now signals, the same election rule
    `_verb_last_resort_key()` applies one layer down.

    Still narrow where it matters: "s3/list-deleted-objects" does NOT signal,
    because the past-tense/adjectival forms are absent from _VERB_CANON on
    purpose, and this reads the canon rather than matching stem prefixes.
    """
    if not isinstance(ability, str) or not ability:
        return False
    words = _split_words(ability.rsplit("/", 1)[-1])
    return any(_VERB_CANON.get(word) == "delete" for word in words)

# ---------------------------------------------------------------------------
# F7: params.currency — the UNIT on the money budget (RFX-133).
#
# THE DEFECT.  R5's `money` dimension aggregates `params.amount` across the
# session.  ledger.py only recorded an amount when `params.currency` was ALSO
# truthy, so OMITTING the currency meant the amount never entered
# `cumulative.amount_by_currency` at all: every call re-compared a single
# amount against the limit and N calls of (limit - 1) accumulated to nothing.
# The budget whose entire purpose is fragmentation resistance was evaded by
# leaving one optional field out.  Confirmed live on a pinned build of this
# commit — see scripts/attack-probe-envelope-boundary.py, attack A5.
#
# THE UNIT ERROR UNDERNEATH IT.  Even when the budget DID fire, the number
# compared against the limit was `sum(amount_by_currency.values())` — EUR
# added to JPY added to IDR.  That is not a quantity of money, it is a sum of
# unlike units, and no amount of canonicalization fixes it.  See the "money
# has UNITS" section of budgets.rego for the resolution: per-currency limits,
# aggregated as DIMENSIONLESS UTILISATION (used_c / limit_c), which is
# legitimate arithmetic across currencies where summing amounts is not.
#
# THE TREATMENT HERE is the canonicalization half.  A currency is an ISO 4217
# alpha-3 code or it is UNDECLARED:
#   - normalize (NFKC, drop control/format chars, trim), then upper-case, so
#     "eur", " EUR ", "Eur​" are one currency, not four ledger buckets;
#   - accept exactly three ASCII letters;
#   - anything else — absent, empty, "€", "euros", "Bitcoin", 42 — becomes
#     "XXX", which is ISO 4217's own code for "no currency involved".
#
# "XXX" IS A REAL BUCKET, NOT A DISCARD.  That is the whole fix for the
# evasion: an amount with no usable currency still accumulates, against the
# base limit, so omitting the field buys nothing.
#
# WHY NOT VALIDATE AGAINST THE FULL ISO 4217 LIST, and why arbitrary alpha-3
# codes are safe: a caller could mint 1,000 fake currency codes to get 1,000
# separate buckets.  Under a naive sum that would be an evasion; under the
# utilisation rule it is not, because 1,000 buckets each at 99% of their limit
# sum to a utilisation of ~990, which trips immediately.  So the closed-list
# check would add maintenance (180+ codes, revised by ISO) for no gate.
#
# WHY SYMBOLS AND WORDS ARE NOT ALIASED.  "€" and "yen" are unambiguous, but
# "$" is not (USD/CAD/AUD/...), and a firewall that GUESSES which currency a
# caller meant has invented a fact.  Bucketing them as XXX is both honest and
# strictly tighter, since XXX shares the base limit.
#
# NARROW BY DESIGN: this canonicalization is applied ONLY when the sibling
# `params.amount` is a number.  `params` is adapter-specific free-form data
# (SPEC §2) and core has no business rewriting a `currency` key that is not
# denominating a money amount.  When there is no amount, the field is
# policy-inert and is left exactly as the adapter sent it.
#
# TRADE-OFF (documented deliberately, same as #89 and RFX-CORE-3): the
# canonical currency is what appears in the ledger, the cumulative object and
# the audit line — the caller's original spelling of a money-denominating
# currency is not preserved.  This is the treatment SPEC §3 already mandates
# for `action.verb` ("the NORMALIZED verb is what appears in the cumulative
# ledger ... and the audit line"), applied one field over.  params is NOT part
# of the envelope_hash projection (holds._HASH_ALLOWLIST = action, axes,
# magnitude, target), so hold binding is unaffected.
# ---------------------------------------------------------------------------

# ISO 4217's code for "no currency involved" — the bucket an amount lands in
# when the caller declared no usable currency for it.
CURRENCY_UNDECLARED: str = "XXX"


def canonicalize_currency(raw: Any) -> str:
    """Fold a caller-supplied currency to an ISO 4217 alpha-3 code or "XXX"."""
    if not isinstance(raw, str):
        return CURRENCY_UNDECLARED
    token = _normalize_token(raw).upper()
    if len(token) == 3 and token.isascii() and token.isalpha():
        return token
    return CURRENCY_UNDECLARED


def is_money_amount(raw: Any) -> bool:
    """True if this value is a number the money budget must account for.

    `bool` is excluded even though it subclasses `int`: `{"amount": true}` is
    not a quantity, and admitting it would let `True` accumulate as 1.0.

    NaN AND INFINITY ARE EXCLUDED, AND THAT IS NOT A DETAIL.  Python's
    json.loads accepts the bare tokens `NaN`, `Infinity` and `-Infinity`
    (they are not valid JSON — RFC 8259 has no such literals — but the
    stdlib parser is lenient by default).  A single `{"amount": NaN}` used to
    be recorded in the ledger verbatim, and from then on EVERY comparison
    against that currency's accumulated total was false, because every
    comparison with NaN is false.  One call permanently disabled the money
    budget for that currency for the rest of the session.  Found by walking
    the enumeration in field_treatments.py during the RFX-127/133 sweep: the
    field was declared, the treatment was incomplete.
    """
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return False
    return math.isfinite(raw)


# ---------------------------------------------------------------------------
# F9: target.ref is now READ BY A RULE (SPEC §2) — RFX-153
#
# R6 (policy/protected.rego) compares target.ref against the operator's
# declared production assets by PREFIX.  That makes ref the sixth
# caller-supplied value a rule reads, and the module docstring above already
# said what has to happen next: "If a future rule exact-matches a NEW
# caller-supplied field, canonicalize it here first — that is the whole lesson
# of #89 and RFX-CORE-3."  Shipping the prefix comparison without this
# function would have re-opened the RFX-86 hole one field over —
# `/srv/prod/../prod/db.sqlite`, `//srv/prod/db.sqlite`, a trailing newline
# and a zero-width character are all the same file and none of them starts
# with "/srv/".
#
# THE TREATMENT IS DIFFERENT IN KIND FROM F1/F5/F6/F7, AND THE DIFFERENCE
# MATTERS.  Those four fold a value into a CLOSED ENUM, so an unrecognised
# input can be coerced to the most-guarded member.  A ref is an open-valued
# identifier — there is no "most-guarded path" to coerce to — so this
# canonicalisation is IDENTITY-PRESERVING ONLY: every step below rewrites a
# path into a different spelling of THE SAME path, and nothing here can turn
# one file into another.  What guards the unknown case is the posture switch
# in protected.rego (`default_protected`), not a coercion here.
#
# WHAT IS DELIBERATELY *NOT* DONE: case is NOT folded.  On Linux
# /srv/Prod/db and /srv/prod/db are two different files, and this value is
# written into the audit record and into the envelope_hash preimage — folding
# it would make the evidence name a file that was never touched.  The
# case-insensitive comparison R6 needs is done in protected.rego, on a
# lowercased copy, and is documented there as deliberate over-protection.
# ---------------------------------------------------------------------------


def canonicalize_target_ref(raw: Any) -> Any:
    """Fold a caller-supplied target.ref to a stable comparison spelling.

    Returns None for an absent/null ref (SPEC §2: ref is nullable for bulk
    actions).  Raises ValidationError for a list or dict, which is neither an
    identifier nor coercible to one: admitting it would let
    `{"ref": ["/srv/prod/db.sqlite"]}` match no prefix and so evade R6, and
    silently dropping it to None would do the same.  A bool/int/float is
    stringified — an adapter that numbers its entities (`ref: 1481`) is using
    the field as SPEC §2 intends.

    Two shapes, because one normalisation would corrupt the other:

    PATH-SHAPED refs (no "://") get lexical path normalisation, which
    collapses duplicate separators and resolves "." and ".." segments.  A ".."
    that walks OUT of a protected prefix is honestly no longer protected —
    `/srv/prod/../../etc/hosts` is `/etc/hosts` and is not a declared asset.

    URI-SHAPED refs (containing "://" — the `s3://bucket/key` and
    `k8s://ns/pod` forms other adapters emit) get token normalisation ONLY.
    posixpath.normpath would rewrite `s3://b/k` to `s3:/b/k`, mangling the
    identifier in the audit record to save a comparison nobody asked for.
    STATED LIMIT: a URI ref is therefore compared as written apart from
    Unicode/whitespace folding, so `s3://b//k` and `s3://b/k` are two keys.
    """
    if raw is None:
        return None
    if isinstance(raw, (list, dict)):
        raise ValidationError(
            "envelope.target.ref must be a string or null, got %s"
            % type(raw).__name__
        )
    if not isinstance(raw, str):
        raw = str(raw)

    # NFKC + drop control/format chars + trim.  Shared with every other canon
    # in this module, minus the casefold — see the section comment above.
    folded = unicodedata.normalize("NFKC", raw)
    cleaned = "".join(
        ch for ch in folded if unicodedata.category(ch) not in ("Cc", "Cf")
    ).strip()

    if not cleaned:
        return ""
    if "://" in cleaned:
        return cleaned
    # normpath("") is ".", which is why the empty case returned above.
    normalized = posixpath.normpath(cleaned)
    # normpath collapses a leading "//" to "//" (POSIX permits an
    # implementation-defined meaning for exactly two leading slashes); no
    # deployment relies on that and leaving it in would make "//srv/..." miss
    # the "/srv/" prefix, which is the E2 evasion.
    while normalized.startswith("//"):
        normalized = normalized[1:]
    return normalized


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
    # -- F9: canonicalize target.ref — read by R6 via protected.rego (RFX-153).
    # Identity-preserving only; see canonicalize_target_ref() for why this one
    # is not a closed-enum coercion like the four above it.  `ref` is absent
    # from most envelopes, and absent stays absent: adding a null key would
    # change the canonical_hash preimage for every envelope that never had one.
    if "ref" in _norm_target:
        _norm_target["ref"] = canonicalize_target_ref(_norm_target["ref"])
    envelope["target"] = _norm_target

    # -- params: free passthrough; must be a dict for ledger to iterate safely.
    # If present but not a dict (string, list, number) -> coerce to {}.
    # This is NOT a 400: params is optional, free-form, and not decision-critical.
    _raw_params = envelope.get("params")
    if _raw_params is not None and not isinstance(_raw_params, dict):
        envelope["params"] = {}

    # -- F7: canonicalize params.currency when it denominates a money amount.
    # params.amount + params.currency are the ONE part of the free-form params
    # block that the decision path reads (R5's `money` dimension, SPEC §4.1),
    # so that pair — and only that pair — gets the closed-enum treatment.
    # Applied only when `amount` is a number, so a `currency` key that is not
    # denominating money is left untouched.  See the F7 block above.
    _params = envelope.get("params")
    if isinstance(_params, dict):
        _amount = _params.get("amount")
        # An amount that is PRESENT and is not a number is REFUSED, not
        # silently read as "no amount".  Same treatment F2 gives an invalid
        # magnitude.count, for the same reason: a decision-critical number
        # that is not a number is a structural error, and reinterpreting it
        # would hide a caller's real intent behind a zero.  See
        # is_money_amount() for what a NaN did to the ledger before this
        # existed.
        #
        # RFX-305 — THIS GUARD USED TO COVER ONE OF THE CASES ITS OWN COMMENT
        # NAMED.  It tested `isinstance(_amount, float) and not isfinite`, so
        # NaN/Infinity were refused and every other non-number was not: a
        # quoted `"6000"`, `true`, `{"value": 6000}` and `[6000]` all fell
        # through to `is_money_amount()` returning False, which meant "there
        # is no amount here" — the zero the comment above says must never be
        # invented.  Measured 2026-09-16 on the deployed v0.2.1: 10 encodings,
        # 10 uncharged, and 40 calls of `"4000"` moved EUR 160,000 through a
        # EUR 5,000 session limit without ever being withheld, while the
        # numeric control was withheld at call 2.  The condition is now the
        # negation of the predicate that decides whether the money budget sees
        # the value at all, so the two cannot drift apart again.
        #
        # ABSENT AND NULL ARE STILL NOT AN ERROR, and that is deliberate:
        # `params` is optional free-form adapter data (SPEC §2) and most
        # actions carry no money.  "No amount" is a legitimate statement;
        # "an amount that is not a number" is not.
        #
        # DIRECTION AND ITS COST, STATED: this is fail-closed and it is a
        # widening — a caller that sends `{"amount": "6000"}` now gets HTTP
        # 400 where it previously got `allow`.  No adapter in this repo does
        # that (reeflex-claude coerces with float(), the n8n node declares the
        # field as a number, and mcp/litellm/wordpress never populate it), but
        # reeflex-spec declares no TYPE for params.amount, so a third-party
        # adapter serialising money as a decimal string was not violating
        # anything written down.  Coercing the string instead would be the
        # permissive alternative and is rejected for the reason this comment
        # already gives: parsing a caller's text into a number is a guess
        # about intent, and a firewall that guesses has invented a fact.
        if _amount is not None and not is_money_amount(_amount):
            raise ValidationError(
                "params.amount must be a finite number if present, got %s %r "
                "(a quoted or structured amount is not a quantity; "
                "NaN/Infinity are not valid JSON)"
                % (type(_amount).__name__, _amount)
            )
        if is_money_amount(_amount):
            _norm_params = dict(_params)
            _norm_params["currency"] = canonicalize_currency(
                _norm_params.get("currency")
            )
            envelope["params"] = _norm_params

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

    # -- F8: record WHICH classification fields core had to guess (RFX-132) --
    # Built from the RAW caller input, after every coercion above has run, and
    # assigned unconditionally so a caller-supplied `provenance` block is
    # discarded rather than merged. Sorted so the list is stable across
    # requests -- it rides on the audit line and the hold record, where an
    # unstable ordering would make two identical envelopes look different.
    _undeclared: list[str] = []
    if not _axis_is_declared(
            (axes or {}).get("reversibility") if isinstance(axes, dict) else None,
            "reversibility"):
        _undeclared.append("axes.reversibility")
    if not _axis_is_declared(
            (axes or {}).get("blast_radius") if isinstance(axes, dict) else None,
            "blast_radius"):
        _undeclared.append("axes.blast_radius")
    if not _axis_is_declared(
            (axes or {}).get("externality") if isinstance(axes, dict) else None,
            "externality"):
        _undeclared.append("axes.externality")
    if not _environment_is_declared(environment):
        _undeclared.append("target.environment")
    if not _verb_is_declared(verb):
        _undeclared.append("action.verb")
    # RFX-143. Judged on the RAW magnitude block, before F2 below fills the
    # default -- after the fill there is nothing left to tell apart.
    if not _count_is_declared(raw.get("magnitude")):
        _undeclared.append("magnitude.count")
    envelope["provenance"] = {"undeclared": sorted(_undeclared)}

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
