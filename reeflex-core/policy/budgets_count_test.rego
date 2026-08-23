# budgets_count_test.rego — RFX-143. A count may raise the charge above the
# floor its own blast_radius implies, never lower it.
#
# A separate file from reeflex_test.rego on purpose: these assert the ARITHMETIC
# of budgets.rego's charged_count, not a verdict, and keeping them apart makes
# the count semantics greppable as one unit.
package reeflex.policy_test

import data.reeflex.policy

# ---- charged_count: the invariant, stated four ways --------------------

_env(blast, magnitude) := e if {
	e := object.union(
		{
			"action": {"verb": "delete"},
			"target": {"environment": "production"},
			"axes": {"reversibility": "recoverable", "blast_radius": blast, "externality": "internal"},
			"cumulative": {"count_by_verb": {}, "total_count": 0},
		},
		magnitude,
	)
}

# A stated count BELOW the floor is raised to the floor.
test_broad_count_one_is_raised_to_the_broad_floor if {
	c := policy.charged_count with input as _env("broad", {"magnitude": {"count": 1}})
	c == policy.count_floor.broad
	c > 1
}

# A stated count ABOVE the floor is left alone -- the floor is a floor, not a
# replacement. An adapter that enumerates honestly must not be re-priced down.
test_broad_count_above_the_floor_is_untouched if {
	c := policy.charged_count with input as _env("broad", {"magnitude": {"count": 5000}})
	c == 5000
}

# An ABSENT magnitude block is charged the floor, not F2's fill of 1.
test_absent_magnitude_is_charged_the_floor if {
	c := policy.charged_count with input as _env("broad", {})
	c == policy.count_floor.broad
}

# THE TICKET'S CONSTRAINT, DIRECTLY: an absent count is never CHEAPER than a
# stated one at the same blast radius. (RFX-133's shape: a field omitted to buy
# a smaller number.)
test_absent_is_never_cheaper_than_stated if {
	every b in ["single", "scoped", "broad", "systemic"] {
		absent := policy.charged_count with input as _env(b, {})
		stated := policy.charged_count with input as _env(b, {"magnitude": {"count": 1}})
		absent >= stated
	}
}

# single/scoped are deliberately floor 1, so an ordinary action is unchanged.
test_single_and_scoped_charge_the_stated_count if {
	every b in ["single", "scoped"] {
		policy.charged_count == 1 with input as _env(b, {"magnitude": {"count": 1}})
	}
}

# Fail-closed: a blast_radius the table does not name gets the STRICTEST floor,
# never the cheapest. envelope.py coerces unknown axis values before they get
# here, so this pins that budgets.rego does not silently depend on that.
test_unknown_blast_radius_gets_the_strictest_floor if {
	c := policy.charged_count with input as _env("not-an-axis-value", {"magnitude": {"count": 1}})
	c == policy.count_floor.systemic
}

# ---- the dimensions actually charge it --------------------------------

test_deletions_dimension_charges_the_floor if {
	policy.current_for("deletions") == policy.count_floor.broad with input as _env("broad", {"magnitude": {"count": 1}})
}

test_objects_touched_charges_the_floor_on_every_verb if {
	e := object.union(_env("broad", {"magnitude": {"count": 1}}), {"action": {"verb": "read"}})

	# deletions charges 0 for a non-delete verb, objects_touched charges anyway.
	policy.current_for("deletions") == 0 with input as e
	policy.current_for("objects_touched") == policy.count_floor.broad with input as e
}

test_external_sends_charges_the_floor_when_outbound if {
	e := _env("broad", {"magnitude": {"count": 1}})
	out := object.union(e, {"axes": {"reversibility": "recoverable", "blast_radius": "broad", "externality": "outbound"}})
	policy.current_for("external_sends") == policy.count_floor.broad with input as out
}

# ---- the floors are ordered ------------------------------------------
#
# Asserted against the table itself rather than against literals, so editing
# budgets.rego is what moves these (RFX-216: a mirror that compares a constant
# to its own copy detects nothing).
test_floors_are_non_decreasing if {
	f := policy.count_floor
	f.single <= f.scoped
	f.scoped <= f.broad
	f.broad <= f.systemic
}

test_no_floor_is_below_f2_minimum if {
	every b in ["single", "scoped", "broad", "systemic"] {
		policy.count_floor[b] >= 1
	}
}

# ---- the decision, not just the arithmetic ---------------------------
#
# RFX-167's lesson: assert the DECISION on a canonical envelope, because a
# per-field assertion can pass while the verdict stays wrong. recoverable so
# R2/R3 cannot fire and only the budget can hold.
test_broad_delete_holds_once_the_floor_exceeds_the_limit if {
	e := object.union(
		_env("broad", {"magnitude": {"count": 1}}),
		{"cumulative": {"count_by_verb": {"delete": 11}, "total_count": 11}},
	)
	policy.decision.decision == "require_approval" with input as e
	policy.decision.rule == "reeflex.policy/session_delete_budget" with input as e
}

# The same envelope one call earlier still allows -- so the test above is
# pinning a boundary and not just a permanently-held envelope.
test_one_call_earlier_still_allows if {
	e := object.union(
		_env("broad", {"magnitude": {"count": 1}}),
		{"cumulative": {"count_by_verb": {"delete": 10}, "total_count": 10}},
	)
	policy.decision.decision == "allow" with input as e
}
