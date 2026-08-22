# Reeflex base policy pack (v0.1) - deterministic decision rules R1-R5.
# Evaluated by reeflex-core /v1/decide; see reeflex-spec/SPEC.md and docs/adr/0002-no-llm-in-decision-path.md.
# R5's configurable budgets (money/deletions/external_sends/objects_touched)
# live in the sibling file budgets.rego (same package).
#
# Input is the Action Envelope (reeflex-spec/SPEC.md §2). Output is a `decision`
# object per SPEC §5: { "decision", "reason", "rule" }, decision in
# allow | deny | require_approval. Pure Rego, no LLM, no external data — same
# envelope in, same decision out (SPEC §5).
package reeflex.policy

# Precedence is explicit and total: deny > require_approval > allow, so exactly
# one decision is produced for any input.
#   require_approval  when R0 fires (R2/R3 matched on inputs core GUESSED)
#   deny              when R3 fires and R0 does not
#   require_approval  when R2 fires and neither R3 nor R0 does
#   require_approval  when R5 fires and none of R3/R2/R0 do
#   allow             otherwise (R1 read-only internal, or R4 default)

# ---- predicates (the rule bodies, factored out for reuse + precedence) -----

# ===========================================================================
# R0: THE ACTION WE COULD NOT CLASSIFY (RFX-132)
# ===========================================================================
# An adapter that cannot price an action emits an envelope with the axes
# omitted, an environment outside the SPEC enum, a verb nobody aliased.
# envelope.py fills each gap with its conservative default -- and the three
# defaults COMPOSE into irreversible + systemic + production, which is R3:
# the one rule a human is not allowed to clear.
#
#     {"action": {"verb": "frobnicate"},
#      "target": {"environment": "qa-eu"},
#      "axes": {}}                          -> deny, irreversible_systemic_prod
#
# Each of those defaults was individually right and individually argued ("a
# wrong DENY is a nuisance, a wrong ALLOW is the product failing"). The
# COMPOSITION was never designed, and what it produces is "when unsure,
# refuse" on a product whose entire value proposition is "when unsure, ask".
#
# WHY HOLD AND NOT DENY. A gate that denies the unfamiliar gets switched off,
# and a switched-off gate is a fail-open with extra steps. HOLD is the third
# state this product exists to have, and "I do not know what this is, ask a
# human" is the most honest thing it can say. Measured volume is the test of
# that claim and it is in the PR, not asserted here.
#
# WHY HOLD AND NOT ALLOW. ALLOW is the defect class -- RFX-86, RFX-85,
# RFX-127, RFX-133 are all one caller-supplied value reaching a verdict
# unchecked. An unclassified action is not evidence that it is safe.
#
# WHY IT IS SAFE TO DOWNGRADE R3 HERE, AND ONLY HERE. R3's terminal refusal
# is the right answer for an action an adapter AFFIRMATIVELY DECLARED to be
# irreversible + systemic + production. R0 fires only when at least one of
# those three inputs is something core GUESSED -- so R3 keeps every case it
# was designed for and loses only the cases where it was firing on core's own
# defaults. `provenance.undeclared` is computed in envelope.py from the raw
# caller input and OVERWRITTEN there unconditionally, so a caller cannot
# assert its way into this softer verdict.
#
# WHY IT ALSO OUTRANKS R2, WHICH IS ALREADY A HOLD. R0 changes no verdict
# there -- it changes the RULE ID, which is the point. An auditor has to be
# able to tell "a rule asked for a human" from "we could not tell what this
# was": the first is a control working as designed, the second is a coverage
# gap that happens to be safe, and they are different facts about the
# deployment. Same verdict, same obligations, distinct reason code.
#
# R0 IS A HOLD, NOT A DENY, SO IT IS RESOLVABLE. That is deliberate: it is the
# whole difference from the R3 it replaces. `irreversible_systemic_prod` stays
# in core's NON_RESOLVABLE_RULES; `unclassified_action` is not in it, and the
# default resolution policy makes it human-only.

#: The classification inputs R2 and R3 read. `axes.externality` and
#: `action.verb` are recorded in provenance too, but neither is read by R2/R3,
#: so guessing them cannot by itself have produced the verdict R0 is softening.
r0_classification_inputs := {"axes.reversibility", "axes.blast_radius",
	"target.environment"}

#: Which of those this envelope's verdict was reached by GUESSING.
#: Read defensively: an envelope from a path that predates the provenance
#: block has no `provenance` key, and must behave exactly as it did before.
r0_guessed_inputs contains f if {
	some f in object.get(input, ["provenance", "undeclared"], [])
	f in r0_classification_inputs
}

r0_unclassified if {
	count(r0_guessed_inputs) > 0
	r3_deny
}

r0_unclassified if {
	count(r0_guessed_inputs) > 0
	r2_require_approval
}

# R1: read-only internal action.
r1_allow if {
	input.action.verb == "read"
	input.axes.externality == "internal"
}

# R2: the SPEC headline rule — irreversible + broad + production.
r2_require_approval if {
	input.axes.reversibility == "irreversible"
	input.axes.blast_radius == "broad"
	input.target.environment == "production"
}

# R3: irreversible + systemic + production — denied even with approval.
r3_deny if {
	input.axes.reversibility == "irreversible"
	input.axes.blast_radius == "systemic"
	input.target.environment == "production"
}

# R5: CONFIGURABLE cumulative budgets over heterogeneous action types
# (SPEC §4.1; RFX-11). budgets.rego (same package, loaded from the same
# policy dir) defines the dimensions, their limits as policy DATA a user
# writes/edits (not a bare Rego constant baked into this rule, and not a
# Python constant), and optional per-principal overrides. This predicate
# only asks "did ANY configured dimension trip" — exceeded_dimensions and
# first_exceeded_dimension (budgets.rego) already read cumulative
# defensively (missing `cumulative` -> 0), so a first call in a session
# never errors.
budget_require_approval if {
	count(exceeded_dimensions) > 0
	not input.approval.present
}

# ---- decision object (single value via explicit precedence) ----------------

# require_approval (R0) — highest precedence. See the R0 block above for why
# this outranks a DENY: R3's terminal refusal is the right answer for an action
# an adapter declared, and the wrong one for an action core guessed at.
#
# The reason NAMES THE FIELDS, sorted, so the hold an operator sees says which
# part of the action was unclassifiable rather than only that some part was.
# "the classifier is not keeping up" is only actionable if it says at what.
decision := {
	"decision": "require_approval",
	"reason": sprintf(
		"this action could not be classified: %v %s not declared by the adapter and core used its conservative default, so the verdict rests on a guess -- a human decides",
		[concat(", ", sort(r0_guessed_inputs)), r0_was_were],
	),
	"rule": "reeflex.policy/unclassified_action",
} if {
	r0_unclassified
}

r0_was_were := "was" if count(r0_guessed_inputs) == 1

r0_was_were := "were" if count(r0_guessed_inputs) != 1

# deny (R3) — the terminal refusal, on inputs the adapter actually declared.
decision := {
	"decision": "deny",
	"reason": "irreversible systemic change in production is not allowed even with approval",
	"rule": "reeflex.policy/irreversible_systemic_prod",
} if {
	r3_deny
	not r0_unclassified
}

# require_approval (R2) — fires only when R3 and R0 do not.
decision := {
	"decision": "require_approval",
	"reason": "irreversible broad change in production requires human approval",
	"rule": "reeflex.policy/irreversible_broad_prod",
} if {
	r2_require_approval
	not r3_deny
	not r0_unclassified
}

# require_approval (R5) — the "deletions" dimension specifically tripped its
# budget. Kept under its original rule id + reason text (this is the same
# fragmentation guard SPEC §4.1 has documented since v0.1) for backward
# compatibility; the limit itself now comes from budgets.rego's configurable
# default (still 20) instead of a bare constant. Fires when R3 and R2 do not,
# so precedence is preserved and exactly one decision is produced.
decision := {
	"decision": "require_approval",
	"reason": "session delete budget exceeded (fragmentation guard)",
	"rule": "reeflex.policy/session_delete_budget",
} if {
	budget_require_approval
	first_exceeded_dimension == "deletions"
	not r3_deny
	not r2_require_approval
}

# require_approval (R5, other dimensions) — any dimension OTHER than
# "deletions" (money, external_sends, objects_touched, or one a policy
# author adds to budgets.rego) tripped its budget. Same rule number as
# above — R5 is now "the configurable cumulative budget guard", generalized
# past the one hardcoded verb it started as (RFX-11): aggregable across
# heterogeneous action types, including the small-tier actions a
# hardcoded, payments-only amplifier would assign zero weight to.
decision := {
	"decision": "require_approval",
	"reason": sprintf("cumulative %s budget exceeded (fragmentation guard)", [first_exceeded_dimension]),
	"rule": "reeflex.policy/cumulative_budget",
} if {
	budget_require_approval
	first_exceeded_dimension != "deletions"
	not r3_deny
	not r2_require_approval
}

# allow (R1) — read-only internal, when no higher-risk rule applies.
decision := {
	"decision": "allow",
	"reason": "read-only internal action",
	"rule": "reeflex.policy/read_only_internal",
} if {
	r1_allow
	not r2_require_approval
	not r3_deny
	not budget_require_approval
}

# allow (R4) — default: nothing high-risk matched and R1 did not apply.
decision := {
	"decision": "allow",
	"reason": "no high-risk axis matched",
	"rule": "reeflex.policy/default_allow",
} if {
	not r1_allow
	not r2_require_approval
	not r3_deny
	not budget_require_approval
}
