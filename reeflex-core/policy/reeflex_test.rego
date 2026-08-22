# Table-driven tests for the Reeflex policy pack (reeflex.rego).
# Covers all rules: R1 allow, R2 require_approval, R3 deny, R4 default-allow,
# R5 session_delete_budget (fragmentation resistance, SPEC §4.1).
# Each case asserts the exact `decision` string. Pure data in, decision out.
package reeflex.policy_test

import data.reeflex.policy

# Each row: an Action Envelope (trimmed to the fields the policy reads) ->
# expected decision string.
cases := {
	"r1_read_internal_allow": {
		"envelope": {
			"action": {"verb": "read"},
			"target": {"environment": "production"},
			"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
			"magnitude": {"count": 1},
		},
		"expected": "allow",
	},
	"r2_irreversible_broad_prod_require_approval": {
		"envelope": {
			"action": {"verb": "delete"},
			"target": {"environment": "production"},
			"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
			"magnitude": {"count": 42},
		},
		"expected": "require_approval",
	},
	"r3_irreversible_systemic_prod_deny": {
		"envelope": {
			"action": {"verb": "execute"},
			"target": {"environment": "production"},
			"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
			"magnitude": {"count": 1},
		},
		"expected": "deny",
	},
	"r4_default_allow": {
		"envelope": {
			"action": {"verb": "update"},
			"target": {"environment": "staging"},
			"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
			"magnitude": {"count": 3},
		},
		"expected": "allow",
	},
}

# Note the R1 case is a clean read-only internal action (reversible, single,
# internal). Precedence is deny > require_approval > allow, so R1 only wins when
# neither R3 nor R2 fires — a read that ALSO matched the deny axes would (and
# should) deny. test_precedence_deny_over_require_approval guards that ordering.

test_r1_read_internal_allow if {
	policy.decision.decision == "allow" with input as cases.r1_read_internal_allow.envelope
}

test_r2_irreversible_broad_prod_require_approval if {
	policy.decision.decision == "require_approval" with input as cases.r2_irreversible_broad_prod_require_approval.envelope
}

test_r3_irreversible_systemic_prod_deny if {
	policy.decision.decision == "deny" with input as cases.r3_irreversible_systemic_prod_deny.envelope
}

test_r4_default_allow if {
	policy.decision.decision == "allow" with input as cases.r4_default_allow.envelope
}

# Sanity: R3 (deny) must outrank R2 (require_approval) when both could match.
# An irreversible action that is both broad-ish and systemic in production
# resolves to deny, proving precedence is total and deny wins.
test_precedence_deny_over_require_approval if {
	policy.decision.rule == "reeflex.policy/irreversible_systemic_prod" with input as cases.r3_irreversible_systemic_prod_deny.envelope
}

# ---- R5 session_delete_budget tests (SPEC §4.1 fragmentation resistance) ----

# R5 TRIGGERS: prior deletes = 18, this batch = 5; total = 23 > 20 budget.
# No approval present -> require_approval with rule id session_delete_budget.
test_r5_budget_exceeded_triggers_require_approval if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 5},
		"cumulative": {"count_by_verb": {"delete": 18}},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/session_delete_budget"
}

# R5 UNDER BUDGET: prior deletes = 3, this batch = 5; total = 8 <= 20.
# Falls through to R4 (default allow) — the fragmentation guard is satisfied.
test_r5_under_budget_allows if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 5},
		"cumulative": {"count_by_verb": {"delete": 3}},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# R5 APPROVED: same counts as trigger case (18+5=23 > 20) but approval.present
# = true -> r5_require_approval_budget does NOT fire (approval clears the gate).
# Envelope is also not irreversible+broad+prod, so falls through to R4 allow.
test_r5_budget_exceeded_but_approved_allows if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 5},
		"cumulative": {"count_by_verb": {"delete": 18}},
		"approval": {"present": true},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# ABSENT CUMULATIVE: no `cumulative` key at all (first call in a session).
# Defensive read defaults prior_deletes to 0; magnitude.count = 1; total = 1.
# Budget not exceeded, not irreversible+broad+prod -> allow (R1 or R4).
test_r5_absent_cumulative_does_not_crash if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# ---- R5, other dimensions: generalized cumulative budgets (budgets.rego, RFX-11) ----
# Same mechanism as R5, but over the OTHER configurable dimensions, and
# aggregating across HETEROGENEOUS action types (different verbs/abilities
# all counted toward the same dimension) rather than one hardcoded verb.

# MONEY dimension: two different verbs ("transact", "refund") both carry
# params.amount in the same currency; neither alone crosses the default
# 5000 budget, but their sum (4800 prior + 400 current = 5200) does.
test_r6_money_dimension_aggregates_across_verbs if {
	envelope := {
		"action": {"verb": "refund"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 1},
		"params": {"amount": 400, "currency": "EUR"},
		"cumulative": {"amount_by_currency": {"EUR": 4800}},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/cumulative_budget"
	got.reason == "cumulative money budget exceeded (fragmentation guard)"
}

# EXTERNAL_SENDS dimension: outbound axis, not tied to any one verb — an
# "email" verb and a "webhook" verb both count. Prior outbound = 48, current
# batch of 5 -> 53 > default budget 50.
test_r6_external_sends_dimension_holds if {
	envelope := {
		"action": {"verb": "notify_webhook"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "outbound"},
		"magnitude": {"count": 5},
		"cumulative": {"count_by_externality": {"outbound": 48}},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/cumulative_budget"
	got.reason == "cumulative external_sends budget exceeded (fragmentation guard)"
}

# OBJECTS_TOUCHED (the smurfing-gap fix): a batch of individually-harmless
# actions of DIFFERENT verbs (read/update/comment — none delete, none
# outbound, none carrying money) still accumulates, because objects_touched
# counts every action unconditionally. Permit0's session amplifier assigns
# weight 0 to this small tier, so it never trips; this dimension trips at
# 201 (prior 199 + current 2).
test_r6_objects_touched_smurfing_gap_holds if {
	envelope := {
		"action": {"verb": "comment"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
		"magnitude": {"count": 2},
		"cumulative": {"total_count": 199},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/cumulative_budget"
	got.reason == "cumulative objects_touched budget exceeded (fragmentation guard)"
}

# UNDER BUDGET on every dimension -> allow, proving the budget guard does not fire on
# unremarkable traffic.
test_r6_all_dimensions_under_budget_allows if {
	envelope := {
		"action": {"verb": "update"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "outbound"},
		"magnitude": {"count": 1},
		"params": {"amount": 10, "currency": "EUR"},
		"cumulative": {
			"total_count": 5,
			"count_by_externality": {"outbound": 3},
			"amount_by_currency": {"EUR": 20},
		},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# PER-PRINCIPAL OVERRIDE: budgets are DATA a policy author writes, not a
# hardcoded Rego constant — proven by overriding budget_limit() itself via
# `with`, the same technique the rest of this suite uses to swap `input`.
# A principal-specific 10-object budget holds where the 200-default would
# still allow the exact same cumulative state.
test_r6_per_principal_override_is_policy_not_code if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
		"agent": {"session_id": "agent:tight-principal"},
		"magnitude": {"count": 2},
		"cumulative": {"total_count": 9},
		"approval": {"present": false},
	}

	# Default budget (200) does not fire.
	default_got := policy.decision with input as envelope
	default_got.decision == "allow"

	# The SAME cumulative state, with a per-principal override tightening
	# objects_touched to 10, DOES fire — proving the limit is read from
	# policy data, keyed by principal, not a fixed number in the engine.
	tight_got := policy.decision with input as envelope
		with data.reeflex.policy.principal_budgets as {"agent:tight-principal": {"objects_touched": {"limit": 10}}}
	tight_got.decision == "require_approval"
	tight_got.rule == "reeflex.policy/cumulative_budget"
}

# ---- money has UNITS (RFX-133) ----------------------------------------
# The money dimension is the one budget over a QUANTITY WITH A UNIT. It used
# to aggregate as sum(amount_by_currency), i.e. EUR + JPY + IDR compared
# against one scalar, which is not a quantity of money. It now aggregates as
# dimensionless UTILISATION (used_c / limit_c), per currency.

_money_envelope(params, cumulative) := {
	"agent": {"session_id": "sess-money-test"},
	"action": {"verb": "transact"},
	"target": {"environment": "staging"},
	"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
	"magnitude": {"count": 1},
	"params": params,
	"cumulative": cumulative,
	"approval": {"present": false},
}

# An amount with NO declared currency lands in the "XXX" bucket, which
# accumulates against the base limit. Omitting the field buys nothing.
test_money_undeclared_currency_still_accumulates if {
	envelope := _money_envelope(
		{"amount": 2000},
		{"amount_by_currency": {"XXX": 4000}},
	)
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/cumulative_budget"
}

# A small amount in a low-unit-value currency is NOT counted as a large one.
# 4000 EUR (0.800 of 5000) + 2000 JPY (0.0025 of 800000) = 0.8025. The old
# naive sum read this as 6000 > 5000 and held it.
test_money_small_foreign_amount_is_not_a_large_one if {
	envelope := _money_envelope(
		{"amount": 2000, "currency": "JPY"},
		{"amount_by_currency": {"EUR": 4000}},
	)
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# Per-currency limits alone would reopen fragmentation one currency over.
# 4900 EUR (0.980) + 4900 USD (0.891) = 1.871 -> exceeded.
test_money_split_across_currencies_still_trips if {
	envelope := _money_envelope(
		{"amount": 4900, "currency": "USD"},
		{"amount_by_currency": {"EUR": 4900}},
	)
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/cumulative_budget"
}

# A negative amount is EXPOSURE, not a credit: it cannot unwind the budget.
test_money_negative_amount_does_not_unwind if {
	envelope := _money_envelope(
		{"amount": -2000, "currency": "EUR"},
		{"amount_by_currency": {"EUR": 4000}},
	)
	got := policy.decision with input as envelope
	got.decision == "require_approval"
}

# A currency the author priced generously is respected: 100000 JPY is 0.125
# of the declared 800000 limit, not "100000 > 5000".
test_money_declared_per_currency_limit_is_used if {
	envelope := _money_envelope(
		{"amount": 100000, "currency": "JPY"},
		{"amount_by_currency": {}},
	)
	got := policy.decision with input as envelope
	got.decision == "allow"
}

# ---- RFX-127: the approval that switches R5 off ------------------------
# The rule still honours a TRUE approval (core only ever sets present=true in
# the OPA input for an approval it verified), and still fires without one.
test_r5_still_fires_without_an_approval if {
	envelope := _money_envelope(
		{"amount": 2000, "currency": "EUR"},
		{"amount_by_currency": {"EUR": 4000}},
	)
	got := policy.decision with input as envelope
	got.decision == "require_approval"
}

# ===========================================================================
# R0 — the action the classifier could not price (RFX-132)
# ===========================================================================
# These run against the POLICY, on the envelope shape envelope.py produces:
# already-coerced axis values PLUS the `provenance.undeclared` list saying
# which of them core had to guess. The end-to-end path (raw envelope in,
# verdict out) is covered in tests/test_unclassified_action_rfx132.py.

# The exact envelope RFX-132 measured, after envelope.py's coercions:
# axes omitted -> irreversible+systemic, environment "qa-eu" -> production,
# verb "frobnicate" -> delete. That is R3 on three guesses.
_unclassified_envelope := {
	"action": {"verb": "delete"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "physical"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"provenance": {"undeclared": [
		"action.verb", "axes.blast_radius", "axes.externality",
		"axes.reversibility", "target.environment",
	]},
}

test_r0_an_unclassifiable_action_holds_instead_of_denying if {
	got := policy.decision with input as _unclassified_envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/unclassified_action"
}

# THE REQUIREMENT THAT MAKES THIS AUDITABLE: a distinct reason code, so
# "a rule asked for a human" and "we could not tell what this was" are not the
# same row in a report.
test_r0_rule_id_is_distinct_from_a_policy_intended_hold if {
	unclassified := policy.decision with input as _unclassified_envelope
	intended := policy.decision with input as cases.r2_irreversible_broad_prod_require_approval.envelope
	unclassified.decision == intended.decision
	unclassified.rule != intended.rule
	intended.rule == "reeflex.policy/irreversible_broad_prod"
}

# ...and the reason NAMES the fields, so an operator can see WHAT was not
# classified rather than only that something was not.
test_r0_reason_names_the_guessed_fields if {
	got := policy.decision with input as _unclassified_envelope
	contains(got.reason, "axes.reversibility")
	contains(got.reason, "axes.blast_radius")
	contains(got.reason, "target.environment")
}

# R3 KEEPS EVERY CASE IT WAS DESIGNED FOR. Same coerced values, but the
# adapter declared all three: still a terminal deny.
test_r0_does_not_fire_when_the_adapter_declared_the_axes if {
	envelope := object.union(_unclassified_envelope, {"provenance": {"undeclared": []}})
	got := policy.decision with input as envelope
	got.decision == "deny"
	got.rule == "reeflex.policy/irreversible_systemic_prod"
}

# Guessing a field NO RULE READS cannot soften a declared R3. externality and
# verb are recorded in provenance for honesty; neither is an R2/R3 input.
test_r0_ignores_undeclared_fields_that_r2_r3_do_not_read if {
	envelope := object.union(_unclassified_envelope, {"provenance": {"undeclared": ["axes.externality", "action.verb"]}})
	got := policy.decision with input as envelope
	got.decision == "deny"
	got.rule == "reeflex.policy/irreversible_systemic_prod"
}

# One guessed input is enough: core cannot be sure this is an R3 action.
test_r0_fires_on_a_single_guessed_classification_input if {
	envelope := object.union(_unclassified_envelope, {"provenance": {"undeclared": ["target.environment"]}})
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/unclassified_action"
	contains(got.reason, "target.environment was not declared")
}

# R0 ALSO RELABELS AN R2 HOLD RAISED ON A GUESS. Same verdict, distinct code:
# the auditor's question is not "was a human asked" but "why".
test_r0_relabels_an_r2_hold_reached_by_guessing if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false},
		"provenance": {"undeclared": ["target.environment"]},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/unclassified_action"
}

# R0 CANNOT CONVERT AN ALLOW. A guessed verb on a declared, reversible,
# non-production action is still R4 — otherwise every unaliased verb in the
# long tail becomes a hold, which is the volume objection this rule has to
# survive.
test_r0_never_converts_an_allow if {
	envelope := {
		"action": {"verb": "update"},
		"target": {"environment": "dev"},
		"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false},
		"provenance": {"undeclared": ["action.verb", "axes.blast_radius"]},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
	got.rule == "reeflex.policy/default_allow"
}

# An envelope with NO provenance block at all (a pre-RFX-132 caller, or a
# direct OPA eval) behaves exactly as it did before. object.get's default is
# what makes that true; without it the rule would error and core would
# fail-closed on every such envelope.
test_r0_absent_provenance_block_changes_nothing if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "deny"
	got.rule == "reeflex.policy/irreversible_systemic_prod"
}
