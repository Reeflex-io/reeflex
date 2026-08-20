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
#   deny              when R3 fires
#   require_approval  when R2 fires and R3 does not
#   require_approval  when R5 fires and neither R3 nor R2 fires
#   allow             otherwise (R1 read-only internal, or R4 default)

# ---- predicates (the rule bodies, factored out for reuse + precedence) -----

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

# deny (R3) — highest precedence.
decision := {
	"decision": "deny",
	"reason": "irreversible systemic change in production is not allowed even with approval",
	"rule": "reeflex.policy/irreversible_systemic_prod",
} if {
	r3_deny
}

# require_approval (R2) — fires only when R3 does not.
decision := {
	"decision": "require_approval",
	"reason": "irreversible broad change in production requires human approval",
	"rule": "reeflex.policy/irreversible_broad_prod",
} if {
	r2_require_approval
	not r3_deny
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
