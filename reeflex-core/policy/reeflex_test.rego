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
