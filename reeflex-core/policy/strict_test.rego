# Tests for the strict preset R2s `irreversible_prod_strict` (RFX-433,
# strict.rego). Both settings of the switch, every blast radius, the denies
# that must still win, the holds that must keep their own rule id, and R0.
#
# These test the POLICY. The leg through /v1/decide, and totality over the
# whole input space with the switch ON, is tests/test_strict_preset_rfx433.py.
package reeflex.strict_test

import data.reeflex.policy

on := {"hold_every_irreversible_in_production": true}

off := {"hold_every_irreversible_in_production": false}

# An irreversible production action no base rule holds: single, internal,
# a verb and ability R7 does not read, no protected ref (R6), count 1.
base := {
	"action": {"verb": "delete", "ability": "files/remove"},
	"target": {"environment": "production", "ref": "/tmp/scratch.txt"},
	"axes": {"reversibility": "irreversible", "blast_radius": "single", "externality": "internal"},
	"magnitude": {"count": 1},
	"agent": {"session_id": "strict-test"},
}

blast(b) := object.union(base, {"axes": {"blast_radius": b}})

# ---- the shipped default --------------------------------------------------

test_shipped_default_is_off if {
	policy.strict.hold_every_irreversible_in_production == false
}

test_off_scoped_irreversible_production_allows if {
	d := policy.decision with input as blast("scoped")
	d.decision == "allow"
	d.rule == "reeflex.policy/default_allow"
}

test_explicit_off_is_the_shipped_default if {
	every b in ["single", "scoped"] {
		d := policy.decision with input as blast(b) with policy.strict as off
		d.rule == "reeflex.policy/default_allow"
	}
}

# ---- switch on ------------------------------------------------------------

test_on_scoped_irreversible_production_holds if {
	d := policy.decision with input as blast("scoped") with policy.strict as on
	d.decision == "require_approval"
	d.rule == "reeflex.policy/irreversible_prod_strict"
}

test_on_single_irreversible_production_holds if {
	d := policy.decision with input as blast("single") with policy.strict as on
	d.rule == "reeflex.policy/irreversible_prod_strict"
}

test_on_any_externality_and_verb_holds if {
	every ext in ["internal", "outbound", "physical"] {
		every verb in ["read", "update", "delete", "execute", "send"] {
			x := object.union(base, {"action": {"verb": verb}, "axes": {"externality": ext}})
			d := policy.decision with input as x with policy.strict as on
			d.decision == "require_approval"
		}
	}
}

# R1 must not be a one-field evasion: an irreversible `read` declared internal.
test_on_read_internal_irreversible_production_is_not_r1 if {
	x := object.union(base, {"action": {"verb": "read"}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/irreversible_prod_strict"
}

test_on_does_not_reach_recoverable if {
	x := object.union(base, {"axes": {"reversibility": "recoverable"}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/default_allow"
}

test_on_does_not_reach_staging_or_dev if {
	every e in ["staging", "dev"] {
		x := object.union(base, {"target": {"environment": e}})
		d := policy.decision with input as x with policy.strict as on
		d.rule == "reeflex.policy/default_allow"
	}
}

test_a_non_boolean_true_leaves_the_preset_off if {
	d := policy.decision with input as blast("scoped") with policy.strict as {"hold_every_irreversible_in_production": "true"}
	d.rule == "reeflex.policy/default_allow"
}

test_a_missing_key_leaves_the_preset_off if {
	d := policy.decision with input as blast("scoped") with policy.strict as {}
	d.rule == "reeflex.policy/default_allow"
}

# ---- the denies still win -------------------------------------------------

test_on_r3_still_denies if {
	d := policy.decision with input as blast("systemic") with policy.strict as on
	d.decision == "deny"
	d.rule == "reeflex.policy/irreversible_systemic_prod"
}

test_on_r8_still_denies if {
	x := object.union(base, {"action": {"verb": "override"}, "axes": {"externality": "physical"}})
	d := policy.decision with input as x with policy.strict as on
	d.decision == "deny"
	d.rule == "reeflex.policy/safety_function_override_prod"
}

test_on_r10a_still_denies if {
	x := object.union(base, {
		"action": {"verb": "set"},
		"axes": {"externality": "physical"},
		"magnitude": {"count": 1, "physical": {"envelope_fraction": 1.5}},
	})
	d := policy.decision with input as x with policy.strict as on
	d.decision == "deny"
	d.rule == "reeflex.policy/outside_operating_envelope_prod"
}

# ---- holds above it keep their own rule id ---------------------------------

test_on_r2_keeps_its_id if {
	d := policy.decision with input as blast("broad") with policy.strict as on
	d.rule == "reeflex.policy/irreversible_broad_prod"
}

test_on_r6_keeps_its_id if {
	x := object.union(base, {"target": {"ref": "/srv/prod/db.sqlite"}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/irreversible_protected_asset_prod"
}

test_on_r9_keeps_its_id if {
	x := object.union(base, {"action": {"verb": "actuate"}, "axes": {"externality": "physical"}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/physical_irreversible"
}

test_on_r5_keeps_its_id if {
	x := object.union(base, {"cumulative": {"count_by_verb": {"delete": 21}, "total_count": 21}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/session_delete_budget"
}

test_on_r7_keeps_its_id if {
	x := object.union(base, {"action": {"ability": "iam/delete-role"}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/authority_change_prod"
}

# ---- R0: a strict hold resting on a guess is a coverage gap ---------------

test_on_guessed_reversibility_is_r0 if {
	x := object.union(base, {"provenance": {"undeclared": ["axes.reversibility"]}})
	d := policy.decision with input as x with policy.strict as on
	d.decision == "require_approval"
	d.rule == "reeflex.policy/unclassified_action"
}

test_on_guessed_environment_is_r0 if {
	x := object.union(base, {"provenance": {"undeclared": ["target.environment"]}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/unclassified_action"
}

# R2s does not read blast_radius, so a guessed one is not what produced it.
test_on_guessed_blast_radius_alone_is_still_r2s if {
	x := object.union(base, {"provenance": {"undeclared": ["axes.blast_radius"]}})
	d := policy.decision with input as x with policy.strict as on
	d.rule == "reeflex.policy/irreversible_prod_strict"
}

test_off_guessed_reversibility_on_a_single_target_still_allows if {
	x := object.union(base, {"provenance": {"undeclared": ["axes.reversibility"]}})
	d := policy.decision with input as x
	d.rule == "reeflex.policy/default_allow"
}

# R0's R2s clause fires only when R2s is the hold that would be reported. On
# an envelope R7 already holds, a guessed reversibility must not rename R7's
# hold to R0 when the preset is switched on (R0 does not read R7).
test_on_r0_does_not_rename_a_hold_r2s_would_not_report if {
	x := object.union(base, {
		"action": {"ability": "iam/delete-role"},
		"provenance": {"undeclared": ["axes.reversibility"]},
	})
	off_rule := policy.decision.rule with input as x
	on_rule := policy.decision.rule with input as x with policy.strict as on
	off_rule == "reeflex.policy/authority_change_prod"
	on_rule == off_rule
}
