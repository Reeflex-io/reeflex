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
                                                                  (PR #92)
    RFX-138 `agent` sits outside the envelope hash AND outside the binding
            derived from this table, so a human's approval of agent A's
            irreversible production delete was spendable by agent B -- or by
            the same bot claiming a different on_behalf_of.        (this PR)
    RFX-139 ...and the reason it was: DECIDE_ENVELOPE_PATHS omitted agent.id
            and agent.on_behalf_of, which decide.py reads through
            principal.is_self_approval().  The "nothing undeclared" test
            passed by under-reporting, and a field that is never DECLARED can
            never be BOUND by a derivation built from this table.  (this PR)

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

AND A DERIVATION THAT DOES NOT DEPEND ON A HUMAN KEEPING A LIST.  RFX-139 is
the proof that it had to: DECIDE_ENVELOPE_PATHS is hand-maintained, it was
short by two fields, and the test that guards it compared the LIST against
this table — never the list against the CODE.  No regex over decide.py would
have found the gap either, because the two fields are dereferenced in ANOTHER
MODULE (principal.py iterates them by name).  So the decide.py side is now
swept DYNAMICALLY: the approval chain runs against an envelope that records
every field anything dereferences, and the recorded set must be declared here.
It follows indirection because it watches the data, not the source.  See
tests/test_field_treatments.py::TestDecideDeclarationMatchesCode.

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


# ---------------------------------------------------------------------------
# How an APPROVAL binds each field (RFX-138)
#
# A treatment says how a field is made safe to compare.  It does not say what
# a human's approval of that field's value is worth on the NEXT request that
# cites it -- and RFX-138 is exactly that gap: `agent` sits outside the
# envelope hash and outside check 7's params comparison, so a human's approval
# of agent A's irreversible production delete was spendable by agent B.
#
# So every declared field now states its binding, and the gate refuses an
# undeclared one.  The point is not the four constants; it is that adding a
# field forces the question "and what does an approval of it bind?" to be
# ANSWERED IN THE TABLE instead of being answered by omission.
# ---------------------------------------------------------------------------

#: Covered by holds.canonical_hash() -- check 5 already binds it.
BIND_HASH = "hash"
#: Outside the hash; bound by comparing the VALUE against the held envelope
#: (decide._validate_approval check 7).
BIND_VALUE = "value"
#: Outside the hash; part of WHO the approval was granted to, bound as an
#: identity by check 8 (principal.approval_actor_key).
BIND_ACTOR = "actor"
#: Deliberately not bound, with the reason stated in the treatment's note.
BIND_NONE = "none"

_BINDINGS = frozenset({BIND_HASH, BIND_VALUE, BIND_ACTOR, BIND_NONE})


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
    #: What a human's approval of this action binds about this field on the
    #: resubmission that cites it -- one of _BINDINGS.  Empty means UNDECLARED
    #: and is a gate failure for any caller-supplied field: RFX-138 was an
    #: undeclared binding, not a wrong one.
    approval_binding: str = ""
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
        approval_binding=BIND_HASH,
        note="Read by R2/R3 and by the unrecognised-verb fallback. The "
             "adapter's estimate; core cannot check it.",
    ),
    "axes.blast_radius": Treatment(
        CANONICALISE, "envelope.validate_and_fill_defaults (F1)",
        closed_set=_AXIS_ALLOWED["blast_radius"],
        conservative_default=_AXIS_DEFAULTS["blast_radius"],
        unverifiable_assertion=True,
        approval_binding=BIND_HASH,
        note="Decides HOLD (broad) vs DENY (systemic). Both reference "
             "adapters resolve it by substring match, so it is the most "
             "guessed value in the envelope.",
    ),
    "axes.externality": Treatment(
        CANONICALISE, "envelope.validate_and_fill_defaults (F1)",
        closed_set=_AXIS_ALLOWED["externality"],
        conservative_default=_AXIS_DEFAULTS["externality"],
        unverifiable_assertion=True,
        approval_binding=BIND_HASH,
        note="Read by R1 (internal) and the external_sends budget "
             "(outbound). 'physical' appears in no rule.",
    ),

    # -- target.environment (SPEC §2) -- RFX-86 / PR #89 --------------------
    "target.environment": Treatment(
        CANONICALISE, "envelope._canonicalize_environment (F5)",
        closed_set=_ENV_TIERS,
        conservative_default=_ENV_DEFAULT,
        unverifiable_assertion=True,
        approval_binding=BIND_HASH,
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
        approval_binding=BIND_HASH,
        note="R1 and the deletions budget match exact literals. Unrecognised "
             "coerces to 'delete' when irreversible, else 'update'; never to "
             "'read'. A caller that labels a delete 'read' still evades — "
             "_delete_signal_from_ability() is the one cross-check.",
    ),

    # -- approval (SPEC §2) -- RFX-127, this PR -----------------------------
    "approval.present": Treatment(
        VERIFY, "decide.process Step 4 + decide._validate_approval",
        approval_binding=BIND_NONE,
        note="NOT BOUND, and it must not be: this field is the thing being "
             "validated, so binding it to the held envelope would be circular "
             "(the held envelope had present=false by construction). "
             "Switches R5 off entirely, so it is the highest-leverage field "
             "in the envelope. NEVER read from the caller: every present=true "
             "envelope goes through the six-check hold chain, and the OPA "
             "input's approval.present is set from what core verified, not "
             "from what the caller wrote.",
    ),
    "approval.hold_id": Treatment(
        VERIFY, "decide._validate_approval (eight checks)",
        approval_binding=BIND_NONE,
        note="NOT BOUND, same reason as approval.present: it NAMES the hold "
             "the binding is done against. A store-key lookup, so a near-miss "
             "fails CLOSED (reeflex_hold_not_found) and needs no "
             "canonicalisation. Bound to the envelope by canonical_hash, to a "
             "resolution by status, to a different principal by "
             "is_self_approval (RFX-84), and to the party the approval was "
             "granted to by approval_actor_key (RFX-138).",
    ),

    # -- magnitude (SPEC §2) ------------------------------------------------
    "magnitude.count": Treatment(
        VALIDATE, "envelope.validate_and_fill_defaults (F2)",
        unverifiable_assertion=True,
        approval_binding=BIND_HASH,
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
        approval_binding=BIND_VALUE,
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
        approval_binding=BIND_VALUE,
        note="READ BY THE LEDGER, NOT BY ANY .rego FILE — which is exactly "
             "why RFX-133 was invisible to a policy-only enumeration. "
             "Undeclared/unusable -> 'XXX', a real accumulating bucket, so "
             "omitting the field no longer keeps the amount out of the "
             "budget.",
    ),

    # -- agent: WHO is acting -- RFX-138 / RFX-139, this PR -----------------
    # These two were read by the decision path and declared NOWHERE: decide.py
    # check 6 calls principal.is_self_approval(), which iterates
    # ("id", "on_behalf_of", "session_id") -- so the four-eyes guard has always
    # read them.  DECIDE_ENVELOPE_PATHS listed only session_id, so the
    # "nothing undeclared" test passed by under-reporting, and the field that
    # was never declared could never be bound by check 7's derived list.  That
    # is the mechanism by which RFX-138 escaped a sweep designed to be
    # exhaustive: not a wrong entry, a missing one.
    "agent.id": Treatment(
        CANONICALISE, "principal.normalize_identity (four-eyes compare + "
                      "approval_actor_key)",
        closed_set=frozenset(),  # open-valued: an adapter names its own agents
        unverifiable_assertion=True,
        approval_binding=BIND_ACTOR,
        note="OPTIONAL in SPEC §2, which is why nothing may depend on it "
             "alone. Read by the four-eyes guard at resolve AND resubmission, "
             "and by check 8: an approval is granted to THIS agent, so a "
             "different agent citing the hold_id is denied "
             "(reeflex_hold_actor_mismatch) without consuming the hold. "
             "Normalized, not validated: a case or zero-width difference must "
             "not read as a different agent in either direction.",
    ),
    "agent.on_behalf_of": Treatment(
        CANONICALISE, "principal.normalize_identity (four-eyes compare + "
                      "approval_actor_key)",
        closed_set=frozenset(),
        unverifiable_assertion=True,
        approval_binding=BIND_ACTOR,
        note="The human the agent declares it acts FOR. Bound by check 8 "
             "because the substitution it enables is the quietest one in the "
             "envelope: same bot, same session, same action, one field "
             "changed, and core's audit line for the resulting allow is "
             "byte-identical to a legitimate resubmission. Core cannot check "
             "the claim against anything (RESIDUAL 5); it can and now does "
             "check that it is the SAME claim the human approved.",
    ),

    # -- agent.session_id (SPEC §2, REQUIRED) -------------------------------
    "agent.session_id": Treatment(
        VALIDATE, "envelope.validate_and_fill_defaults (F3) + "
                  "decide.resolve_session_identity",
        unverifiable_assertion=True,
        approval_binding=BIND_ACTOR,
        note="BOUND ONLY AS A FALLBACK -- approval_actor_key() uses it when "
             "the envelope names no agent.id and no on_behalf_of, so a "
             "SPEC-minimal envelope (session_id is the only required agent "
             "field) does not produce an empty, vacuous actor key. It is "
             "deliberately NOT bound when the agent IS named: a hold lives "
             "hours, and an agent that restarts before resubmitting gets a "
             "new session -- binding it would deny an action a human already "
             "approved. Non-empty string or HTTP 400. Keys the ledger AND the "
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
        approval_binding=BIND_HASH,
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

def approval_bound_paths() -> tuple[str, ...]:
    """Caller-supplied VALUES an approval must bind beyond the hash (check 7).

    Derived from TREATMENTS, so a future declared field is bound by declaring
    it rather than by anyone remembering.  This is the enumeration doing the
    work: the fix is not "also check the amount", it is "check everything the
    decision reads that the hash does not cover".

    WHAT CHANGED IN RFX-138, AND WHY IT WAS THE TABLE'S FAULT.  This used to
    select on a BLOCK list (`{"params"}`), with a comment excluding `agent`
    on the grounds that it carried no decision input.  That was wrong twice
    over: decide.py's check 6 does read agent.id and agent.on_behalf_of, and
    a block list cannot express "bind this field, not that one in the same
    block" — which is exactly what agent needs (id and on_behalf_of yes,
    session_id only as a fallback).  A per-field declaration can, and an
    exclusion now has to be WRITTEN DOWN as BIND_NONE with a reason instead
    of being implied by a set nobody re-reads.
    """
    return tuple(sorted(
        path for path, t in TREATMENTS.items()
        if t.approval_binding == BIND_VALUE
    ))


def approval_actor_paths() -> tuple[str, ...]:
    """Envelope paths that make up WHO an approval was granted to (check 8).

    Declarative counterpart to principal.approval_actor_key(), which does the
    comparing.  Kept as a derivation so the table stays the single place the
    question is answered, and so a test can assert the two agree.
    """
    return tuple(sorted(
        path for path, t in TREATMENTS.items()
        if t.approval_binding == BIND_ACTOR
    ))


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
#
# 5. WHAT CHECK 8 DOES NOT BUY (RFX-138).  It binds an approval to the actor
#    IDENTITY THE ENVELOPE ASSERTS.  Both agent.id and agent.on_behalf_of are
#    still `unverifiable_assertion=True`: core has no way to know that
#    "agent:alpha" is the process it claims to be, or that alice really asked
#    for this.  What the check removes is the ability to change the claim
#    BETWEEN the approval and the execution -- the human and the executor now
#    see the same requester, and a substitution is a deny with its own reason
#    code instead of an allow indistinguishable from a legitimate one.  Making
#    the identity itself trustworthy is the same signed-envelope /
#    authenticated-session work as RESIDUAL 1 and 2 (SPEC §6, RFX-9).
#
# 6. THE APPROVAL BINDING IS NOW PER-FIELD, AND THAT IS THE POINT.  It used to
#    be a BLOCK list (`{"params"}`) with `agent` excluded by a comment that
#    said agent carried no decision input.  It did, and a block list could not
#    have expressed the fix anyway: agent.id and agent.on_behalf_of must be
#    bound, agent.session_id must NOT be (an agent that restarts between the
#    approval and the resubmission would otherwise be denied an action a human
#    already approved). Every field now declares its binding and an exclusion
#    has to be WRITTEN as BIND_NONE with a reason.
