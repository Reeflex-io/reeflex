# Tests for protected.rego — R6, the declared-production-asset rule (RFX-153).
#
# These are the RULE-LEVEL tests: pure data in, decision out, no core, no
# ledger.  They exist alongside tests/test_protected_asset_rfx153.py rather
# than instead of it, and the split is deliberate:
#
#   here                    the rule's own logic, including the STRICT posture,
#                           which is reachable in Rego with `with data` /
#                           `with input` but needs a copied policy dir to reach
#                           from Python.
#   tests/test_protected_*  the same rule reached through validate ->
#                           canonicalise (F8) -> ledger -> OPA, because the
#                           evasion cases are only closed by the COMBINATION
#                           of F8 and this file.  A path spelled
#                           "/srv/prod/../prod/db.sqlite" is NOT protected by
#                           the rules below on their own, and must not appear
#                           to be: canonicalisation happens at the boundary,
#                           once, and the Rego is entitled to assume it ran.
package reeflex.policy_test

import data.reeflex.policy

_asset_envelope(ref, overrides) := object.union(
	{
		"action": {"verb": "delete", "ability": "bash/rm"},
		"target": {"kind": "command", "ref": ref, "environment": "production"},
		"axes": {
			"reversibility": "irreversible",
			"blast_radius": "single",
			"externality": "internal",
		},
		"magnitude": {"count": 1},
		"agent": {"session_id": "rfx153-rego"},
	},
	overrides,
)

# ---- the hold: cardinality is no longer what decides ----------------------

test_r6_holds_a_single_named_production_asset if {
	got := policy.decision with input as _asset_envelope("/srv/prod/db.sqlite", {})
	got.decision == "require_approval"
	got.rule == "reeflex.policy/irreversible_protected_asset_prod"
}

test_r6_holds_scoped_as_well_as_single if {
	env := _asset_envelope("/var/lib/postgresql/16/main/base", {
		"axes": {
			"reversibility": "irreversible",
			"blast_radius": "scoped",
			"externality": "internal",
		},
	})
	got := policy.decision with input as env
	got.decision == "require_approval"
}

# R6 reads neither the verb nor the cardinality. A truncate-by-redirect is
# `execute` and destroys the file just as completely (RFX-144).
test_r6_ignores_the_verb if {
	env := _asset_envelope("/srv/prod/db.sqlite", {"action": {"verb": "execute", "ability": "bash/dd"}})
	got := policy.decision with input as env
	got.decision == "require_approval"
}

# Declaring "/srv/" protects "/srv" itself, not only paths beneath it.
test_r6_protects_the_declared_prefix_itself if {
	got := policy.decision with input as _asset_envelope("/srv", {})
	got.decision == "require_approval"
}

# ---- the cost: what stays allowed ----------------------------------------

test_r6_does_not_hold_a_scratch_file if {
	got := policy.decision with input as _asset_envelope("/tmp/scratch.txt", {})
	got.decision == "allow"
	got.rule == "reeflex.policy/default_allow"
}

test_r6_does_not_hold_a_relative_working_tree_path if {
	got := policy.decision with input as _asset_envelope("src/old_module.py", {})
	got.decision == "allow"
}

# /var/lib is production state, /var/tmp is designated temporary, and both sit
# under /var — so the protect-list cannot be a top-level-directory list.
test_r6_does_not_hold_var_tmp if {
	got := policy.decision with input as _asset_envelope("/var/tmp/build.log", {})
	got.decision == "allow"
}

test_r6_needs_production if {
	env := _asset_envelope("/srv/prod/db.sqlite", {
		"target": {
			"kind": "command", "ref": "/srv/prod/db.sqlite", "environment": "dev",
		},
	})
	got := policy.decision with input as env
	got.decision == "allow"
}

test_r6_needs_irreversible if {
	env := _asset_envelope("/srv/prod/db.sqlite", {
		"axes": {
			"reversibility": "recoverable",
			"blast_radius": "single",
			"externality": "internal",
		},
	})
	got := policy.decision with input as env
	got.decision == "allow"
}

# An absent ref matches no declared prefix under the default posture.
test_r6_default_posture_ignores_an_absent_ref if {
	env := _asset_envelope(null, {})
	got := policy.decision with input as env
	got.decision == "allow"
}

# ---- precedence: R6 can only ever convert an ALLOW ------------------------

test_r3_deny_still_outranks_r6 if {
	env := _asset_envelope("/srv/prod", {
		"axes": {
			"reversibility": "irreversible",
			"blast_radius": "systemic",
			"externality": "internal",
		},
	})
	got := policy.decision with input as env
	got.decision == "deny"
	got.rule == "reeflex.policy/irreversible_systemic_prod"
}

# The rule id is what an auditor reads, so R2 must not be renamed by R6.
test_r2_keeps_its_rule_id_on_a_protected_asset if {
	env := _asset_envelope("/srv/prod/data", {
		"axes": {
			"reversibility": "irreversible",
			"blast_radius": "broad",
			"externality": "internal",
		},
		"magnitude": {"count": 40},
	})
	got := policy.decision with input as env
	got.rule == "reeflex.policy/irreversible_broad_prod"
}

test_r5_keeps_its_rule_id_on_a_protected_asset if {
	env := object.union(
		_asset_envelope("/srv/prod/db.sqlite", {"magnitude": {"count": 21}}),
		{"cumulative": {"count_by_verb": {"delete": 5}, "total_count": 5}},
	)
	got := policy.decision with input as env
	got.rule == "reeflex.policy/session_delete_budget"
}

# R1's conditions are the verb and the externality, both caller-asserted, so
# R1 winning would hand back a one-field evasion of R6.
test_r6_outranks_r1_for_an_irreversible_read if {
	env := _asset_envelope("/srv/prod/db.sqlite", {"action": {"verb": "read", "ability": "bash/cat"}})
	got := policy.decision with input as env
	got.decision == "require_approval"
	got.rule == "reeflex.policy/irreversible_protected_asset_prod"
}

# ---- the posture switch, which is only reachable from here ----------------

test_strict_posture_holds_an_undeclared_path if {
	got := policy.decision with input as _asset_envelope("/home/app/data/customers.db", {})
		with data.reeflex.policy.default_protected as true
	got.decision == "require_approval"
	got.rule == "reeflex.policy/irreversible_protected_asset_prod"
}

# An adapter that cannot name what it is destroying is the case a human should
# see, not the case that slips through.
test_strict_posture_holds_an_absent_ref if {
	got := policy.decision with input as _asset_envelope(null, {})
		with data.reeflex.policy.default_protected as true
	got.decision == "require_approval"
}

test_strict_posture_still_allows_declared_ephemeral if {
	got := policy.decision with input as _asset_envelope("/tmp/scratch.txt", {})
		with data.reeflex.policy.default_protected as true
	got.decision == "allow"
}

# Even strict, R6 is scoped to irreversible production actions.
test_strict_posture_still_needs_production if {
	env := _asset_envelope("/anything", {
		"target": {
			"kind": "command", "ref": "/anything", "environment": "staging",
		},
	})
	got := policy.decision with input as env
		with data.reeflex.policy.default_protected as true
	got.decision == "allow"
}

# The default posture is the one that ships: an operator who reads only this
# file should see, as an assertion, that it is OFF.
test_default_posture_is_permissive_by_default if {
	policy.default_protected == false
}
