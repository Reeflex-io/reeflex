# Tests for the physical / human-safety rules R8-R11 and the two physical
# budgets (RFX-427, SPEC §4.5). One test per rule per environment, the budget
# arithmetic at its boundary, and the precedence pairs the spec fixes.
#
# These test the POLICY. They do not prove a physical verb reaches the policy
# through /v1/decide -- core canonicalises the verb first (envelope.py), and
# that leg is tests/test_physical_impact_rfx427.py, through app.decide.process.
# Totality across the whole input space is tests/test_decision_totality.py.
package reeflex.physical_test

import data.reeflex.policy

# A physical envelope, everything the IT rules read set to a value none of
# them fires on: recoverable (not R2/R3/R6/R9), scoped, no ability (not R7),
# count 1.
base := {
	"action": {"verb": "set"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "physical"},
	"magnitude": {"count": 1},
	"agent": {"session_id": "physical-test"},
}

env(e, verb) := object.union(base, {"action": {"verb": verb}, "target": {"environment": e}})

with_safety(e, verb) := object.union(env(e, verb), {"target": {"safety_function": true}})

with_fraction(e, verb, f) := object.union(env(e, verb), {"magnitude": {"count": 1, "physical": {"envelope_fraction": f}}})

irreversible(x) := object.union(x, {"axes": {"reversibility": "irreversible"}})

# ---- R8 safety_function_override_prod --------------------------------------

test_r8_override_production_denies if {
	d := policy.decision with input as env("production", "override")
	d.decision == "deny"
	d.rule == "reeflex.policy/safety_function_override_prod"
}

test_r8_override_staging_denies if {
	d := policy.decision with input as env("staging", "override")
	d.rule == "reeflex.policy/safety_function_override_prod"
}

test_r8_override_dev_does_not_arm if {
	d := policy.decision with input as env("dev", "override")
	d.rule == "reeflex.policy/default_allow"
}

test_r8_set_on_safety_function_production_denies if {
	policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as with_safety("production", "set")
}

test_r8_every_write_verb_on_a_safety_function_denies if {
	every verb in ["set", "update", "delete", "flash", "mode"] {
		policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as with_safety("staging", verb)
	}
}

test_r8_set_on_a_non_safety_target_is_not_r8 if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as env("production", "set")
}

test_r8_safety_function_false_is_not_r8 if {
	x := object.union(env("production", "set"), {"target": {"safety_function": false}})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

test_r8_read_of_a_safety_function_is_not_r8 if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as with_safety("production", "read")
}

test_r8_needs_externality_physical if {
	x := object.union(env("production", "override"), {"axes": {"externality": "internal"}})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

# ---- R10a outside_operating_envelope_prod ----------------------------------

test_r10a_production_denies if {
	d := policy.decision with input as with_fraction("production", "set", 1.4)
	d.decision == "deny"
	d.rule == "reeflex.policy/outside_operating_envelope_prod"
	contains(d.reason, "1.4")
}

test_r10a_staging_denies if {
	policy.decision.rule == "reeflex.policy/outside_operating_envelope_prod" with input as with_fraction("staging", "set", 1.4)
}

test_r10a_dev_does_not_arm if {
	# 1.4 also exceeds the physical_envelope budget (1.0) -- which does not
	# arm in dev either, so this is R4.
	policy.decision.rule == "reeflex.policy/default_allow" with input as with_fraction("dev", "set", 1.4)
}

test_r10a_exactly_one_full_range_is_not_r10a if {
	# 1.0 is a full-range step, inside the range; the budget is AT its limit,
	# not over it, so this is allowed.
	policy.decision.rule == "reeflex.policy/default_allow" with input as with_fraction("production", "set", 1.0)
}

# ---- R9 physical_irreversible ----------------------------------------------

test_r9_actuate_production_holds if {
	d := policy.decision with input as irreversible(env("production", "actuate"))
	d.decision == "require_approval"
	d.rule == "reeflex.policy/physical_irreversible"
}

test_r9_flash_production_holds if {
	policy.decision.rule == "reeflex.policy/physical_irreversible" with input as irreversible(env("production", "flash"))
}

test_r9_staging_does_not_arm if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as irreversible(env("staging", "actuate"))
}

test_r9_dev_does_not_arm if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as irreversible(env("dev", "flash"))
}

test_r9_needs_irreversible if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as env("production", "actuate")
}

# ---- R11 mode_change_live --------------------------------------------------

test_r11_production_holds if {
	d := policy.decision with input as env("production", "mode")
	d.decision == "require_approval"
	d.rule == "reeflex.policy/mode_change_live"
}

test_r11_staging_does_not_arm if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as env("staging", "mode")
}

test_r11_dev_does_not_arm if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as env("dev", "mode")
}

# ---- precedence: R3 >= R8 >= R10a > R2 > R9 > R11 > R5 > R1 > R4 ----------

systemic(x) := object.union(x, {"axes": {"reversibility": "irreversible", "blast_radius": "systemic"}})

broad(x) := object.union(x, {"axes": {"reversibility": "irreversible", "blast_radius": "broad"}})

test_precedence_r3_over_r8 if {
	policy.decision.rule == "reeflex.policy/irreversible_systemic_prod" with input as systemic(env("production", "override"))
}

test_precedence_r8_over_r10a if {
	x := object.union(with_safety("production", "set"), {"magnitude": {"count": 1, "physical": {"envelope_fraction": 1.5}}})
	policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as x
}

test_precedence_r10a_over_r2 if {
	policy.decision.rule == "reeflex.policy/outside_operating_envelope_prod" with input as broad(with_fraction("production", "set", 1.5))
}

test_precedence_r8_over_r9 if {
	# flash on a safety function, irreversible, production: R8 and R9 both match.
	policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as irreversible(with_safety("production", "flash"))
}

test_precedence_r10a_over_r9 if {
	policy.decision.rule == "reeflex.policy/outside_operating_envelope_prod" with input as irreversible(with_fraction("production", "actuate", 1.5))
}

test_precedence_r2_over_r9 if {
	policy.decision.rule == "reeflex.policy/irreversible_broad_prod" with input as broad(env("production", "actuate"))
}

test_precedence_r8_over_r11 if {
	policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as with_safety("production", "mode")
}

test_precedence_r11_over_r5 if {
	x := object.union(env("production", "mode"), {"cumulative": {"count_by_verb": {"mode": 10}}})
	policy.decision.rule == "reeflex.policy/mode_change_live" with input as x
}

# ---- R0 and the physical rules ---------------------------------------------

guessed(x, fields) := object.union(x, {"provenance": {"undeclared": fields}})

test_r0_does_not_soften_r8_when_r8s_own_inputs_were_declared if {
	# The evasion this ordering closes: omit reversibility on a systemic
	# production override, let core guess it, and R0 would fire through R3.
	# R8 does not read reversibility, so R8 stands.
	x := guessed(systemic(env("production", "override")), ["axes.reversibility"])
	policy.decision.rule == "reeflex.policy/safety_function_override_prod" with input as x
}

test_r0_takes_r8_when_the_environment_was_guessed if {
	x := guessed(env("production", "override"), ["target.environment"])
	policy.decision.rule == "reeflex.policy/unclassified_action" with input as x
}

test_r0_takes_r10a_when_the_environment_was_guessed if {
	x := guessed(with_fraction("production", "set", 1.5), ["target.environment"])
	policy.decision.rule == "reeflex.policy/unclassified_action" with input as x
}

test_r0_takes_r9_when_reversibility_was_guessed if {
	x := guessed(irreversible(env("production", "actuate")), ["axes.reversibility"])
	policy.decision.rule == "reeflex.policy/unclassified_action" with input as x
}

test_r0_takes_r11_when_the_environment_was_guessed if {
	x := guessed(env("production", "mode"), ["target.environment"])
	policy.decision.rule == "reeflex.policy/unclassified_action" with input as x
}

# ---- R10b: the two physical budgets ----------------------------------------

writes_prior(n) := {"count_by_verb": {"set": n}}

test_physical_writes_eleventh_write_holds if {
	x := object.union(env("production", "set"), {"cumulative": writes_prior(10)})
	d := policy.decision with input as x
	d.decision == "require_approval"
	d.rule == "reeflex.policy/cumulative_budget"
	contains(d.reason, "physical_writes")
}

test_physical_writes_tenth_write_allows if {
	x := object.union(env("production", "set"), {"cumulative": writes_prior(9)})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

test_physical_writes_sum_every_write_verb if {
	x := object.union(env("staging", "actuate"), {"cumulative": {"count_by_verb": {"set": 3, "mode": 2, "override": 1, "actuate": 2, "flash": 2}}})
	contains(policy.decision.reason, "physical_writes") with input as x
}

test_physical_writes_a_read_is_not_charged if {
	# prior 10 writes, current a physical read: 0 + 10 is not > 10.
	x := object.union(env("production", "read"), {"cumulative": writes_prior(10)})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

test_physical_writes_ignore_prior_non_write_physical_entries if {
	# 50 prior physical updates and reads are not writes.
	x := object.union(env("staging", "set"), {"cumulative": {"count_by_verb": {"update": 40, "read": 10}, "count_by_externality": {"physical": 50}}})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

test_physical_writes_dev_does_not_arm if {
	x := object.union(env("dev", "set"), {"cumulative": writes_prior(30)})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}

envelope_prior(x, prior) := object.union(x, {"cumulative": {"sum_physical_envelope": prior}})

test_physical_envelope_097_plus_003_is_at_the_limit_not_over_it if {
	# 0.97 + 0.03 is exactly 1 in OPA's arithmetic; "exceeded" is strict.
	policy.decision.rule == "reeflex.policy/default_allow" with input as envelope_prior(with_fraction("production", "set", 0.03), 0.97)
}

test_physical_envelope_097_plus_004_holds if {
	d := policy.decision with input as envelope_prior(with_fraction("production", "set", 0.04), 0.97)
	d.rule == "reeflex.policy/cumulative_budget"
	contains(d.reason, "physical_envelope")
}

test_physical_envelope_05_plus_05_does_not_hold if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as envelope_prior(with_fraction("staging", "set", 0.5), 0.5)
}

test_physical_envelope_dev_does_not_arm if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as envelope_prior(with_fraction("dev", "set", 0.5), 3.0)
}

test_physical_envelope_absent_fraction_charges_nothing if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as envelope_prior(env("production", "update"), 1.0)
}

# The 40-step sweep: 0.03 per step, every step inside its range. With the
# shipped defaults physical_writes (10) trips first, at step 11 -- so to watch
# the ENVELOPE dimension decide, this session's principal gets a writes limit
# no 40-step run reaches. Step 34 is the first where the sum exceeds 1.0
# (33 x 0.03 = 0.99; 34 x 0.03 = 1.02).
sweep_step(i) := object.union(
	with_fraction("production", "set", 0.03),
	{"cumulative": {"count_by_verb": {"set": i - 1}, "sum_physical_envelope": (i - 1) * 0.03}},
)

sweep_first_hold := min({i |
	some i in numbers.range(1, 40)
	d := policy.decision with input as sweep_step(i) with policy.principal_budgets as {"physical-test": {"physical_writes": {"limit": 1000}}}
	d.decision == "require_approval"
})

test_physical_envelope_40_step_sweep_holds_at_step_34 if {
	sweep_first_hold == 34
	d := policy.decision with input as sweep_step(34) with policy.principal_budgets as {"physical-test": {"physical_writes": {"limit": 1000}}}
	contains(d.reason, "physical_envelope")
}

test_physical_writes_with_shipped_defaults_trips_the_sweep_at_step_11 if {
	first := min({i |
		some i in numbers.range(1, 40)
		policy.decision.decision == "require_approval" with input as sweep_step(i)
	})
	first == 11
	contains(policy.decision.reason, "physical_writes") with input as sweep_step(11)
}

# ---- what does NOT change --------------------------------------------------

test_unmapped_update_physical_production_gets_todays_verdict if {
	# An adapter that cannot classify a plant action maps it to `update` with
	# the most restrictive axes (SPEC §3.1). irreversible + systemic +
	# production is R3 today and stays R3.
	x := object.union(base, {"action": {"verb": "update"}, "axes": {"reversibility": "irreversible", "blast_radius": "systemic"}})
	policy.decision.rule == "reeflex.policy/irreversible_systemic_prod" with input as x
}

test_unmapped_update_physical_staging_is_still_default_allow if {
	x := object.union(base, {"action": {"verb": "update"}, "target": {"environment": "staging"}, "axes": {"reversibility": "irreversible", "blast_radius": "systemic"}})
	policy.decision.rule == "reeflex.policy/default_allow" with input as x
}
