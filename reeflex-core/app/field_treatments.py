"""
field_treatments.py — the declared treatment of every caller-supplied field
the decision path reads.

=============================================================================
WHY THIS FILE EXISTS
=============================================================================
Five separate ways to beat the deterministic decision path have now been
found, and they are not five bugs.  They are ONE missing discipline wearing
five hats: A CALLER-SUPPLIED VALUE THAT THE POLICY READS WITHOUT
CANONICALISING OR VERIFYING IT.

    RFX-86  target.environment compared exactly -> "Prod" missed R2/R3 and
            fell through to default_allow.                        (PR #89)
    RFX-85  action.verb compared exactly -> "Delete"/"remove"/"purge"
            accumulated under their own ledger key, never reaching R5.
                                                                  (PR #90)
    RFX-84  the approving human on /v1/holds/{id}/resolve was self-asserted
            and nothing verified it.                              (PR #90)
    RFX-127 approval.present is self-asserted; a bare {"present": true} with
            no hold_id switched off EVERY cumulative budget.       (this PR)
    RFX-133 params.currency is optional, and omitting it kept an amount out
            of the ledger entirely, so the money budget never accumulated;
            and the money it did compare was a sum of unlike currencies.
                                                                  (this PR)

Patching the fifth instance and stopping would guarantee a sixth.  What stops
the recurrence is an ENUMERATION: every caller-supplied field a rule can read,
each with a declared treatment, and a test that DERIVES the set of fields the
decision path actually reads and fails when one of them is not declared here.

That test is tests/test_field_treatments.py.  It reads:

  * policy/*.rego   — every `input.<path>` and every
                      `object.get(input, [...])`, extracted mechanically.
  * app/ledger.py   — the SECOND reader (LEDGER_ENVELOPE_PATHS).  Scanning
                      only the Rego is not enough and RFX-133 is the proof:
                      the ledger decides what lands in
                      `cumulative.amount_by_currency`, so a field it reads
                      can disable a budget without appearing in any rule.
  * app/decide.py   — the THIRD reader (DECIDE_ENVELOPE_PATHS).  The freeze
                      gate and the entire hold-approval chain reach verdicts
                      OPA never sees.  RFX-127 lived exactly here:
                      `approval.hold_id` appears in no .rego file and in no
                      ledger read, yet its ABSENCE was what let an unverified
                      `approval.present` reach the budget rule.

THREE READERS, NOT ONE — and each of the last two was discovered only after a
defect had already shipped through it.  Adding a field to any of them without
declaring it here turns the gate red.

=============================================================================
THE FOUR TREATMENTS
=============================================================================
CANONICALISE  The field is a CLOSED ENUM.  Fold it (NFKC, drop control/format
              characters, trim, casefold) and alias-map it to a canonical
              member; coerce anything unrecognised to the MOST-GUARDED member
              (SPEC §7).  Used where a rule compares the value by exact
              string, because an exact comparison against an untreated string
              fails OPEN on every near-miss.

VALIDATE      The field is a type or a range, not an enum.  Check it; reject
              or clamp.  A value that cannot be a quantity is not silently
              read as one.

VERIFY        The field asserts a FACT ABOUT THE WORLD that the caller does
              not get to decide — above all, that a human approved something.
              It must be checked against state the caller does not control
              (the hold store, the credential), and the caller's assertion
              must never reach a rule as if it were established.

CORE_COMPUTED Not caller-supplied at all: core overwrites it before eval.
              Declared here so the enumeration is TOTAL — the invariant is
              "no field reaches a rule undeclared", and a field that is
              deliberately not caller-controlled still has to say so, and to
              be checked that it really is overwritten.

=============================================================================
WHAT AN ENUMERATION CANNOT DO
=============================================================================
It closes the NEAR-MISS and OMISSION surface — the shapes an honest adapter
emits by accident and the ones an attacker reaches for first.  It cannot make
an ASSERTED value true.  `axes.blast_radius: "single"` on a table wipe,
`action.verb: "read"` on a delete, and a `session_id` rotated to reset the
ledger are all conformant envelopes that lie, and no canonicalisation detects
a lie.  Those need signed envelopes (SPEC §6, roadmap) or an authenticated
session identity (RFX-9).  Each such field is marked
`unverifiable_assertion=True` below, and that set IS the residual risk — see
the RESIDUAL section at the bottom of this module.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Treatment kinds
# ---------------------------------------------------------------------------

CANONICALISE = "canonicalise"
VALIDATE = "validate"
VERIFY = "verify"
CORE_COMPUTED = "core_computed"

_KINDS = frozenset({CANONICALISE, VALIDATE, VERIFY, CORE_COMPUTED})


class Treatment(NamedTuple):
    """How one caller-supplied field is made safe to compare against."""

    kind: str
    #: Where the treatment is implemented ("module.function").
    applied_by: str
    #: For CANONICALISE: the closed set the field is guaranteed to be in
    #: after treatment.  Empty for open-valued fields (e.g. a currency code,
    #: which is alpha-3-shaped but not drawn from a list core maintains).
    closed_set: frozenset[str] = frozenset()
    #: For CANONICALISE: the member an unrecognised value coerces to.
    #: "" when the coercion target is conditional (see action.verb).
    conservative_default: str = ""
    #: True when core cannot check the value against anything outside the
    #: envelope, so a deliberate lie is undetectable.  This set is the
    #: residual risk, stated rather than papered over.
    unverifiable_assertion: bool = False
    note: str = ""


# ---------------------------------------------------------------------------
# The closed sets, imported from the ONE place that enforces them so this
# table cannot drift away from the code.
# ---------------------------------------------------------------------------

from .envelope import (  # noqa: E402
    CURRENCY_UNDECLARED,
    _AXIS_ALLOWED,
    _AXIS_DEFAULTS,
    _ENV_CANON,
    _ENV_DEFAULT,
    _SPEC_VERBS,
)

_ENV_TIERS = frozenset(_ENV_CANON.values())


# ---------------------------------------------------------------------------
# THE ENUMERATION
# ---------------------------------------------------------------------------

TREATMENTS: dict[str, Treatment] = {
    # -- axes: the three universal risk axes (SPEC §4) ----------------------
    # R1/R2/R3 and the external_sends budget all compare these by exact
    # string.  F1 in envelope.py.  The original fail-closed treatment, and
    # the model the other four were retrofitted to.
    "axes.reversibility": Treatment(
        CANONICALISE, "envelope.validate_and_fill_defaults (F1)",
        closed_set=_AXIS_ALLOWED["reversibility"],
        conservative_default=_AXIS_DEFAULTS["reversibility"],
        unverifiable_assertion=True,
        note="Read by R2/R3 and by the unrecognised-verb fallback. The "
             "adapter's estimate; core cannot check it.",
    ),
    "axes.blast_radius": Treatment(
        CANONICALISE, "envelope.validate_and_fill_defaults (F1)",
        closed_set=_AXIS_ALLOWED["blast_radius"],
        conservative_default=_AXIS_DEFAULTS["blast_radius"],
        unverifiable_assertion=True,
        note="Decides HOLD (broad) vs DENY (systemic). Both reference "
             "adapters resolve it by substring match, so it is the most "
             "guessed value in the envelope.",
    ),
    "axes.externality": Treatment(
        CANONICALISE, "envelope.validate_and_fill_defaults (F1)",
        closed_set=_AXIS_ALLOWED["externality"],
        conservative_default=_AXIS_DEFAULTS["externality"],
        unverifiable_assertion=True,
        note="Read by R1 (internal) and the external_sends budget "
             "(outbound). 'physical' appears in no rule.",
    ),

    # -- target.environment (SPEC §2) -- RFX-86 / PR #89 --------------------
    "target.environment": Treatment(
        CANONICALISE, "envelope._canonicalize_environment (F5)",
        closed_set=_ENV_TIERS,
        conservative_default=_ENV_DEFAULT,
        unverifiable_assertion=True,
        note="R2/R3 match 'production' exactly. Declared by the adapter, not "
             "guessed (WP reads a PHP constant), so the weakest of the three "
             "unverifiable axes-like fields.",
    ),

    # -- action.verb (SPEC §3) -- RFX-85 / PR #90 ---------------------------
    "action.verb": Treatment(
        CANONICALISE, "envelope._canonicalize_verb (F6)",
        closed_set=_SPEC_VERBS,
        conservative_default="",  # conditional: irreversible -> delete, else update
        unverifiable_assertion=True,
        note="R1 and the deletions budget match exact literals. Unrecognised "
             "coerces to 'delete' when irreversible, else 'update'; never to "
             "'read'. A caller that labels a delete 'read' still evades — "
             "_delete_signal_from_ability() is the one cross-check.",
    ),

    # -- approval (SPEC §2) -- RFX-127, this PR -----------------------------
    "approval.present": Treatment(
        VERIFY, "decide.process Step 4 + decide._validate_approval",
        note="Switches R5 off entirely, so it is the highest-leverage field "
             "in the envelope. NEVER read from the caller: every present=true "
             "envelope goes through the six-check hold chain, and the OPA "
             "input's approval.present is set from what core verified, not "
             "from what the caller wrote.",
    ),
    "approval.hold_id": Treatment(
        VERIFY, "decide._validate_approval (six checks)",
        note="A store-key lookup, so a near-miss fails CLOSED "
             "(reeflex_hold_not_found) and needs no canonicalisation. Bound "
             "to the envelope by canonical_hash, to a resolution by status, "
             "and to a different principal by is_self_approval (RFX-84).",
    ),

    # -- magnitude (SPEC §2) ------------------------------------------------
    "magnitude.count": Treatment(
        VALIDATE, "envelope.validate_and_fill_defaults (F2)",
        unverifiable_assertion=True,
        note="int >= 1 or HTTP 400; absent -> 1. bool rejected (it subclasses "
             "int). Feeds every count dimension.",
    ),

    # -- params: the money pair -- RFX-133, this PR -------------------------
    # params is free-form adapter data (SPEC §2), but these TWO keys are read
    # by the decision path, so these two get the closed-field treatment and
    # the rest of params stays untouched passthrough.
    "params.amount": Treatment(
        VALIDATE, "envelope.is_money_amount + ledger.append_entry + "
                  "budgets.rego current_money_amount",
        unverifiable_assertion=True,
        note="FINITE number or HTTP 400; non-numeric contributes 0. abs() in "
             "both the ledger and the policy: the budget measures exposure, "
             "so a negative amount cannot subtract from cumulative spend. "
             "The finiteness check is not pedantry — one NaN used to poison "
             "amount_by_currency and disable the money budget for the whole "
             "session. Also bound to an approval by _validate_approval check "
             "7, since params is outside the envelope_hash projection.",
    ),
    "params.currency": Treatment(
        CANONICALISE, "envelope.canonicalize_currency (F7)",
        closed_set=frozenset(),  # alpha-3 shaped; not a list core maintains
        conservative_default=CURRENCY_UNDECLARED,
        unverifiable_assertion=True,
        note="READ BY THE LEDGER, NOT BY ANY .rego FILE — which is exactly "
             "why RFX-133 was invisible to a policy-only enumeration. "
             "Undeclared/unusable -> 'XXX', a real accumulating bucket, so "
             "omitting the field no longer keeps the amount out of the "
             "budget.",
    ),

    # -- agent identity: WHO the approval was granted to -- RFX-138 / RFX-139
    # These two were read by the decision path and declared NOWHERE, and that
    # omission is the mechanism by which RFX-138 escaped a sweep designed to
    # be exhaustive: check 7 binds a resubmission to the approval by iterating
    # approval_bound_paths(), which is DERIVED from this table, so a field
    # that is never declared can never be bound.  decide.py's check 6 reads
    # both — one frame deeper, inside principal.actor_identities() — which is
    # exactly the FOURTH READER the RESIDUAL section below predicted.
    "agent.id": Treatment(
        CANONICALISE, "principal.normalize_identity "
                      "(decide._validate_approval checks 6 and 7)",
        closed_set=frozenset(),  # an identifier, not a list core maintains
        conservative_default="",  # unusable -> "" -> contributes no identity
        unverifiable_assertion=True,
        note="NOT a decision input to any rule — it is the SUBJECT OF THE "
             "HUMAN'S APPROVAL, which is why excluding the agent block from "
             "the bound set was wrong (RFX-138: a human approved ALPHA and "
             "BETA spent the approval; ALPHA was then refused "
             "reeflex_hold_consumed). Folded NFKC/casefold/strip before any "
             "comparison so a re-cased or zero-width-padded identity is "
             "neither a spurious mismatch nor a way around check 6. The fold "
             "makes the COMPARISON honest; it does nothing to make the "
             "claimed identity TRUE — see the RESIDUAL note and RFX-9.",
    ),
    "agent.on_behalf_of": Treatment(
        CANONICALISE, "principal.normalize_identity "
                      "(decide._validate_approval checks 6 and 7)",
        closed_set=frozenset(),
        conservative_default="",
        unverifiable_assertion=True,
        note="The human the agent declares it acts FOR. Read by four-eyes "
             "(principal.actor_identities) so that an agent acting for Alice "
             "cannot have 'Alice' approve it, and bound to the approval by "
             "check 7 so that the SAME agent in the SAME session cannot swap "
             "alice -> bob after a human said yes for alice. That variant is "
             "worse than agent substitution because it left no trace at all: "
             "agent_id, session_id and envelope_hash are byte-identical to a "
             "legitimate resubmission. reeflex-claude reads it from an env "
             "var in the agent's own process (envelope.py:67), so the agent "
             "picks whom it claims to act for — the definition of an "
             "unverifiable assertion.",
    ),

    # -- agent.session_id (SPEC §2, REQUIRED) -------------------------------
    "agent.session_id": Treatment(
        VALIDATE, "envelope.validate_and_fill_defaults (F3) + "
                  "decide.resolve_session_identity",
        unverifiable_assertion=True,
        note="Non-empty string or HTTP 400. Keys the ledger AND the "
             "principal_budgets override lookup. NOT canonicalised on "
             "purpose: folding case would merge two adapters' distinct "
             "sessions into one ledger, which changes whose budget is whose. "
             "SEE THE RESIDUAL NOTE — this is the one field where the right "
             "treatment is VERIFY and core cannot yet apply it (RFX-9).",
    ),

    # -- action.ability (SPEC §2) -------------------------------------------
    "action.ability": Treatment(
        CANONICALISE, "envelope._delete_signal_from_ability + "
                      "ledger.append_entry",
        unverifiable_assertion=True,
        note="No rule reads it directly today; it reaches the decision "
             "through the delete cross-check and through "
             "cumulative.count_by_ability. Split/normalised by _split_words "
             "before either use.",
    ),

    # -- core-computed: overwritten in decide.process, never caller-supplied
    "cumulative": Treatment(
        CORE_COMPUTED, "decide.process Step 6 (opa_input['cumulative'] = ...)",
        note="Unconditionally overwritten with ledger.compute_cumulative(), "
             "so a caller cannot pre-load a fabricated history. Every "
             "cumulative.* path below is a projection of this one object.",
    ),
    "cumulative.total_count": Treatment(
        CORE_COMPUTED, "ledger.compute_cumulative", note="objects_touched",
    ),
    "cumulative.count_by_verb": Treatment(
        CORE_COMPUTED, "ledger.compute_cumulative",
        note="deletions; keyed on the CANONICAL verb",
    ),
    "cumulative.count_by_externality": Treatment(
        CORE_COMPUTED, "ledger.compute_cumulative", note="external_sends",
    ),
    "cumulative.amount_by_currency": Treatment(
        CORE_COMPUTED, "ledger.compute_cumulative",
        note="money; keyed on the CANONICAL currency, 'XXX' when undeclared",
    ),
}


# ---------------------------------------------------------------------------
# Mechanical derivation of what the decision path ACTUALLY reads
# ---------------------------------------------------------------------------

# `input.a.b.c` — a dotted reference in Rego.
_RE_DOTTED = re.compile(r"\binput((?:\.[A-Za-z_][A-Za-z0-9_]*)+)")
# `object.get(input, ["a", "b"], default)` — the defensive form.
_RE_OBJECT_GET = re.compile(r"object\.get\(\s*input\s*,\s*\[([^\]]*)\]")
_RE_STRING = re.compile(r'"([^"]*)"')

# Rego syntax that can follow `input.` but is not an envelope field.
_REGO_NOISE = frozenset({"get", "keys"})


def policy_input_paths(rego_sources: dict[str, str]) -> set[str]:
    """Extract every envelope path the given Rego sources read from `input`.

    Comments are stripped first, so a path named only in prose (there are
    several, in exactly the comments that explain these defects) does not
    count as a read.

    Returns dotted paths, e.g. {"action.verb", "cumulative.count_by_verb"}.
    Dictionary-key lookups on a cumulative sub-object
    (`cumulative.count_by_verb.delete`) are truncated to the object itself,
    because the treatment applies to the object, not to each key.
    """
    found: set[str] = set()
    for text in rego_sources.values():
        stripped = "\n".join(
            line.split("#", 1)[0] for line in text.splitlines()
        )
        for match in _RE_DOTTED.finditer(stripped):
            parts = [p for p in match.group(1).split(".") if p]
            if not parts or parts[0] in _REGO_NOISE:
                continue
            found.add(_truncate(parts))
        for match in _RE_OBJECT_GET.finditer(stripped):
            parts = _RE_STRING.findall(match.group(1))
            if parts:
                found.add(_truncate(parts))
    return found


def _truncate(parts: list[str]) -> str:
    """Collapse a path to the level a treatment is declared at.

    `cumulative.count_by_verb.delete` -> `cumulative.count_by_verb`: the
    treatment is a property of the object core builds, not of one key in it.
    Everything else keeps at most two segments (`action.verb`,
    `params.amount`), which is the depth the Action Envelope declares fields
    at (SPEC §2).
    """
    if parts[0] == "cumulative":
        return ".".join(parts[:2])
    return ".".join(parts[:2])


#: Top-level envelope blocks covered by holds.canonical_hash() — the
#: action-defining projection an approval is bound to (holds._HASH_ALLOWLIST).
#: Duplicated as a literal rather than imported so that a change to the hash
#: preimage shows up as a test failure here rather than silently widening or
#: narrowing what an approval binds.
HASH_COVERED_BLOCKS: frozenset[str] = frozenset({"action", "axes", "magnitude", "target"})

#: Blocks an approval must bind that the envelope hash DOES NOT COVER.
#:
#: WHAT A HUMAN APPROVES is "this agent, acting for this person, doing this
#: thing".  canonical_hash() covers only the last third of that sentence, so
#: the other two thirds have to be bound field by field — and there are TWO
#: distinct reasons a block belongs in this set, which is the thing the first
#: version of it got wrong:
#:
#: `params` — IT CARRIES A DECISION INPUT.  The money budget is driven
#: entirely by params.amount, so a hold raised for a EUR 6,000 payment could
#: be resubmitted as EUR 6,000,000 with a byte-identical hash: the human
#: approved one number and the agent executed another.  Confirmed end to end
#: during the RFX-127/133 sweep.
#:
#: `agent` — IT CARRIES THE SUBJECT OF THE APPROVAL.  This block was
#: previously excluded with the reasoning "not a decision input to a rule".
#: That sentence is TRUE and it was the wrong test: agent.id and
#: agent.on_behalf_of are not inputs to a RULE, they are WHO THE HUMAN SAID
#: YES TO.  Excluding them meant a human could approve agent ALPHA and agent
#: BETA would spend the approval — measured on origin/main 44c6f85 and on
#: live api-dev v0.1.13, with ALPHA (the agent actually approved) then
#: refused `reeflex_hold_consumed`.  Same bot, same session, on_behalf_of
#: alice -> bob was the same hole with no trace at all: agent_id, session_id
#: and envelope_hash all byte-identical to a legitimate resubmission
#: (RFX-138).
#:
#: THE ADAPTER CONTRACT ALREADY REQUIRED THIS AND NOTHING CHECKED IT.  The
#: WordPress reference adapter carries `{id, on_behalf_of, session_id}`
#: verbatim from hold creation into the resubmission and calls it a "LOCKED
#: DECISION ... the actor stays the actor"
#: (class-reeflex-normalizer.php, $agent_override); reeflex-mcp's holds
#: tracker is KEYED on (session_id, action_hash) so a cross-session
#: resubmission cannot even find the hold; the n8n recipe respreads the whole
#: envelope and regenerates only `meta.nonce`.  Binding the agent block
#: enforces at the core boundary an invariant every reference adapter already
#: promises.
#:
#: `approval` is still excluded because it is the thing being validated, and
#: `context`/`meta` because they are audit-only: they cannot change a verdict
#: and they are not who the approval names.  See RESIDUAL note 4.
_APPROVAL_BOUND_BLOCKS: frozenset[str] = frozenset({"params", "agent"})


def approval_bound_paths() -> tuple[str, ...]:
    """Caller-supplied fields an approval must bind BEYOND the hash.

    Derived from TREATMENTS, so a future declared field in one of these
    blocks is bound automatically instead of being remembered.  This is the
    enumeration doing the work: the fix is not "also check the amount", it is
    "check everything the approval covers that the hash does not".

    The derivation is only as good as the table: RFX-138 escaped this
    function while it was already shipping, because agent.id and
    agent.on_behalf_of were read by check 6 and declared nowhere, so no
    filter over TREATMENTS could ever have returned them.  A field that is
    never declared can never be bound.
    """
    return tuple(sorted(
        path for path, t in TREATMENTS.items()
        if t.kind != CORE_COMPUTED
        and path.split(".")[0] in _APPROVAL_BOUND_BLOCKS
    ))


def bound_value(path: str, raw: object) -> object:
    """The comparison key for `path` when binding a resubmission to a hold.

    Most fields compare as-is: both sides have already been through
    validate_and_fill_defaults(), so both are canonical and a remaining
    difference is a real difference.

    The `agent` block is the exception, and deliberately so.  "Is this the
    same actor?" is decided by principal.normalize_identity() everywhere else
    in this codebase — check 6 here, and the resolve-time four-eyes guard in
    server.py — so binding must use the same answer, or the two guards
    disagree about who somebody is.  Concretely, the fold is what stops
    `svc-bot` vs `SVC-BOT` being read as an actor substitution (a false deny
    on a legitimate resubmission), and it is what stops a zero-width
    character from making one identity look like two.

    NOTE it is the COMPARISON that folds, not the field: agent.session_id is
    declared VALIDATE and its RAW value keys the cumulative ledger, because
    folding case there would merge two adapters' distinct sessions into one
    budget.  Same field, two uses, and only one of them is an identity
    question.
    """
    if path.split(".")[0] != "agent":
        return raw
    from .principal import normalize_identity  # local: avoids an import cycle

    return normalize_identity(raw)


def undeclared(paths: set[str]) -> set[str]:
    """Paths with no declared treatment — the thing the gate must never see."""
    return {p for p in paths if p not in TREATMENTS}


def unverifiable_assertions() -> set[str]:
    """The fields core cannot check against anything outside the envelope.

    This set IS the residual risk after the sweep.  It is not a bug list: it
    is the honest boundary of what canonicalisation can buy, and it shrinks
    only with signed envelopes (SPEC §6) or an authenticated session identity
    (RFX-9), not with more alias tables.
    """
    return {p for p, t in TREATMENTS.items() if t.unverifiable_assertion}


# ---------------------------------------------------------------------------
# RESIDUAL — read this before concluding the class is closed
# ---------------------------------------------------------------------------
#
# 0. A SIXTH AND A SEVENTH EXISTED, AND THE ENUMERATION FOUND THEM.  Both were
#    found by walking this table field by field during the RFX-127/133 sweep,
#    not by a report, and both are fixed in the same PR:
#
#      params.amount accepted NaN/Infinity (json.loads takes the bare
#      tokens). One NaN in the ledger made every later comparison against
#      that currency false, permanently disabling the session's money budget.
#      -> now a structural refusal; see is_money_amount().
#
#      params is outside the envelope_hash projection, so an approval bound
#      NOTHING about the amount: a hold raised for EUR 6,000 was resubmitted
#      as EUR 6,000,000 with a byte-identical hash and allowed.
#      -> now bound by _validate_approval check 7, derived from this table.
#
#    THE LESSON, WHICH IS THE POINT OF THIS FILE: the enumeration told us
#    WHICH fields need a treatment. It did not tell us the treatment we wrote
#    was sufficient — params.amount was already declared VALIDATE when it
#    accepted a NaN. Enumerating is necessary and it is not sufficient.
#
# 1. EVERY axis, the verb, the environment, the count and the amount remain
#    ASSERTIONS.  Canonicalisation makes an honest adapter's near-miss safe
#    and takes away an attacker's cheap spellings.  It does nothing about a
#    caller that simply declares a table wipe `reversible`/`single`/`dev`.
#    That is not a new hole and it is not closable here; SPEC §6 signing is
#    the only thing that changes it.
#
# 2. agent.session_id IS THE ONE WITH THE WRONG TREATMENT TODAY.  It is
#    VALIDATE (non-empty string) where it should be VERIFY, and it does two
#    jobs: it keys the cumulative ledger, and it selects a
#    `principal_budgets` override.  A caller that rotates it resets every
#    cumulative budget — that is the cross-session-burn limit
#    reeflex-spec/IMPACT-MODEL.md already documents, so it is a known gap and
#    not a new finding.  The SECOND job is less obvious and worth a look
#    before any deployment writes a `principal_budgets` entry: the override
#    table is keyed on an unverified caller-supplied string, so a caller who
#    learns a LOOSENED key can claim it.  The default table is empty, which
#    is the only reason this is latent rather than live.  RFX-9 is the ticket.
#
# 3. THE ENUMERATION IS ONLY AS GOOD AS ITS DERIVATION.  It covers three
#    readers — policy/*.rego, ledger.py and decide.py — and TWO OF THE THREE
#    were found only because a defect had already shipped through them.  A
#    FOURTH reader (a new module that consumes an envelope field and feeds a
#    verdict) would be invisible to it in exactly the same way.  If you add
#    one, add it to the derivation; that is the maintenance cost of this file
#    and it is the whole cost.
#
# 4. AUDIT-ONLY CALLER-SUPPLIED FIELDS ARE OUT OF SCOPE HERE, DELIBERATELY.
#    `approval.parent_decision_id`, `context.traceparent` and `meta.*` are
#    caller-supplied and are written into the audit record and the SIEM event
#    without being verifiable.  They cannot change a verdict, so they are not
#    in this table — but they ARE an evidence-integrity surface, and it is the
#    same shape of defect one layer over (RFX-74 was precisely that: a report
#    faithfully rendering an attestation nothing had verified). Worth its own
#    sweep; this one does not cover it.
