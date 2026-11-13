# Tests for R0's route for an externality core could not read (RFX-455).
#
# envelope.py folds axis values, so "Physical" reaches the pack as `physical`.
# A value still unreadable after the fold ("phsyical", "physical!") reaches it
# as `outbound` -- the conservative default -- with the field named in BOTH
# provenance lists. An ABSENT externality reaches it as `outbound` with the
# field in `undeclared` only. These tests feed the pack those two shapes
# directly; the leg through envelope.py is
# tests/test_externality_near_miss_rfx455.py, through app.decide.process.
package reeflex.externality_unreadable_test

import data.reeflex.policy

# A non-physical envelope nothing fires on: recoverable, scoped, `update`, no
# ability, no ref.
base := {
	"action": {"verb": "update"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "outbound"},
	"magnitude": {"count": 1},
	"agent": {"session_id": "externality-unreadable-test"},
}

# What core hands the pack for `axes.externality: "phsyical"`.
typo(x) := object.union(x, {"provenance": {
	"undeclared": ["axes.externality"],
	"unrecognised": ["axes.externality"],
}})

# What core hands the pack for an absent externality.
silent(x) := object.union(x, {"provenance": {"undeclared": ["axes.externality"], "unrecognised": []}})

in_env(x, e) := object.union(x, {"target": {"environment": e}})

axes(x, rev, blast) := object.union(x, {"axes": {"reversibility": rev, "blast_radius": blast}})

# ---- the route --------------------------------------------------------------

test_a_typo_in_production_is_held_as_unclassified if {
	d := policy.decision with input as typo(base)
	d.decision == "require_approval"
	d.rule == "reeflex.policy/unclassified_action"
	contains(d.reason, "axes.externality")
}

test_a_typo_in_staging_is_held_as_unclassified if {
	policy.decision.rule == "reeflex.policy/unclassified_action" with input as typo(in_env(base, "staging"))
}

test_a_typo_in_dev_is_not_held if {
	# R8-R11 do not arm in dev, so there is nothing a typo can walk out of.
	policy.decision.rule == "reeflex.policy/default_allow" with input as typo(in_env(base, "dev"))
}

test_silence_is_not_held if {
	# (c): RFX-129's `outbound` default for an adapter that never set the axis.
	policy.decision.rule == "reeflex.policy/default_allow" with input as silent(base)
}

test_no_provenance_block_changes_nothing if {
	policy.decision.rule == "reeflex.policy/default_allow" with input as base
}

# ---- it converts an allow, not a deny and not another rule's hold ---------

test_it_does_not_soften_a_declared_r3 if {
	# R3 does not read externality. A typo in it must not turn a terminal
	# deny into a resolvable hold.
	d := policy.decision with input as typo(axes(base, "irreversible", "systemic"))
	d.decision == "deny"
	d.rule == "reeflex.policy/irreversible_systemic_prod"
}

test_it_does_not_rename_r2 if {
	policy.decision.rule == "reeflex.policy/irreversible_broad_prod" with input as typo(axes(base, "irreversible", "broad"))
}

test_it_does_not_rename_a_budget_hold if {
	x := object.union(typo(base), {"cumulative": {"count_by_externality": {"outbound": 50}, "total_count": 50}})
	d := policy.decision with input as x
	d.rule == "reeflex.policy/cumulative_budget"
	contains(d.reason, "external_sends")
}

test_it_does_not_rename_r6 if {
	x := object.union(typo(axes(base, "irreversible", "single")), {"target": {"ref": "/srv/prod/db.sqlite"}})
	policy.decision.rule == "reeflex.policy/irreversible_protected_asset_prod" with input as x
}

test_it_does_not_rename_r7 if {
	x := object.union(typo(base), {"action": {"ability": "iam/delete-role"}})
	policy.decision.rule == "reeflex.policy/authority_change_prod" with input as x
}

test_the_older_r0_keeps_its_own_reason if {
	# A guessed environment on an R2 match is the older R0 body; the typo must
	# not swap in this route's reason.
	x := object.union(axes(base, "irreversible", "broad"), {"provenance": {
		"undeclared": ["axes.externality", "target.environment"],
		"unrecognised": ["axes.externality"],
	}})
	d := policy.decision with input as x
	d.rule == "reeflex.policy/unclassified_action"
	contains(d.reason, "target.environment")
	not contains(d.reason, "is not one of internal, outbound, physical")
}
