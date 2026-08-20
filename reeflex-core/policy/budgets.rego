# budgets.rego — CONFIGURABLE cumulative budgets over heterogeneous action
# types (RFX-11: "the answer to Permit0's gap"). Same package as
# reeflex.rego (OPA merges every .rego file in a policy dir into one
# evaluation) — this is the file a POLICY AUTHOR edits to write a budget, not
# a Python constant and not a hardcoded Rego literal buried in the rule
# engine below.
#
# Permit0 (the closest thesis rival) ships per-session cumulative budgets
# with HARDCODED, payments-specific thresholds, and its session amplifier
# assigns weight 0 to small-tier actions — so the long tail of "harmless"
# small actions never accumulates and smurfing walks straight through.
# This module fixes both: (1) limits live in data a user writes/edits here
# (or overrides per principal), not in code; (2) `objects_touched` gives
# EVERY action, however small, non-zero weight, so heterogeneous small
# actions still accumulate toward a hold.
#
# A DIMENSION aggregates prior actions from the session ledger
# (ledger.py, via input.cumulative — SPEC §4.1) PLUS the action being
# decided right now, regardless of which verb/ability produced them:
#
#   money             input.params.amount, whatever verb carries one
#   deletions         input.action.verb == "delete"
#   external_sends    input.axes.externality == "outbound"
#   objects_touched   EVERY action, unconditionally — the dimension that
#                      makes a long tail of small, individually-harmless
#                      actions accumulate toward a hold.
#
# A budget definition is {"limit": <number>}. `default_budgets` applies to
# every principal; `principal_budgets` overrides specific dimensions for a
# specific principal (keyed by input.agent.session_id — the identity
# resolved by core's resolve_session_identity() seam; see decide.py. RFX-9
# may later change WHERE that identity comes from, not how this policy
# reads it: it is still whatever lands in input.agent.session_id).
package reeflex.policy

# ---- the policy a user writes -----------------------------------------

default_budgets := {
	"money": {"limit": 5000},
	"deletions": {"limit": 20},
	"external_sends": {"limit": 50},
	"objects_touched": {"limit": 200},
}

# Empty by default; a deployment adds entries like:
#   "agent:some-session-id": {"objects_touched": {"limit": 10}}
# to tighten (or loosen) one dimension for one principal without touching
# the rule engine or any other principal's budget.
principal_budgets := {}

budget_dimensions := ["money", "deletions", "external_sends", "objects_touched"]

# ---- the mechanism (reused by reeflex.rego; not what a user edits) ----

# budget_limit: per-principal override wins; falls back to the default.
budget_limit(dimension) := limit if {
	limit := principal_budgets[input.agent.session_id][dimension].limit
} else := limit if {
	limit := default_budgets[dimension].limit
}

# cumulative_for: PRIOR contribution to a dimension, from the ledger's
# cumulative object. Absent -> 0 (defensive default; SPEC §4.1 R5 pattern).
cumulative_for(dimension) := n if {
	dimension == "objects_touched"
	n := object.get(input, ["cumulative", "total_count"], 0)
} else := n if {
	dimension == "deletions"
	n := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
} else := n if {
	dimension == "external_sends"
	n := object.get(input, ["cumulative", "count_by_externality", "outbound"], 0)
} else := n if {
	dimension == "money"
	by_currency := object.get(input, ["cumulative", "amount_by_currency"], {})
	n := sum([v | some v in by_currency])
}

# current_for: THIS action's contribution to a dimension, added to the
# prior cumulative before comparing to the limit (same "prior + current"
# shape as the original R5).
current_for(dimension) := c if {
	dimension == "objects_touched"
	c := input.magnitude.count
} else := c if {
	dimension == "deletions"
	input.action.verb == "delete"
	c := input.magnitude.count
} else := c if {
	dimension == "deletions"
	input.action.verb != "delete"
	c := 0
} else := c if {
	dimension == "external_sends"
	input.axes.externality == "outbound"
	c := input.magnitude.count
} else := c if {
	dimension == "external_sends"
	input.axes.externality != "outbound"
	c := 0
} else := c if {
	dimension == "money"
	amt := object.get(input, ["params", "amount"], 0)
	is_number(amt)
	c := amt
} else := c if {
	dimension == "money"
	amt := object.get(input, ["params", "amount"], 0)
	not is_number(amt)
	c := 0
}

# exceeded_dimensions: every dimension where prior + current > its budget.
exceeded_dimensions contains dimension if {
	some dimension in budget_dimensions
	current_for(dimension) + cumulative_for(dimension) > budget_limit(dimension)
}

# Deterministic single pick for the reason/rule text when more than one
# dimension trips on the same action — alphabetical, so the SAME input
# always yields the SAME decision (SPEC §5 determinism invariant).
first_exceeded_dimension := sort([d | some d in exceeded_dimensions])[0]
