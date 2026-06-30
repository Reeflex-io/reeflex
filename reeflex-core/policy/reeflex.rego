# Reeflex base policy pack (v0.1) - deterministic decision rules R1-R5.
# Evaluated by reeflex-core /v1/decide; see reeflex-spec/SPEC.md and docs/adr/0002-no-llm-in-decision-path.md.
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

# ---- constants -----------------------------------------------------------

# Maximum cumulative delete operations allowed in a session before requiring
# human approval. Defined once here; referenced in R5 and its tests.
delete_session_budget := 20

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

# R5: session delete budget — fragmentation resistance (SPEC §4.1).
# Reads cumulative.count_by_verb.delete defensively: if the `cumulative` object
# is absent (first call in a session) the value defaults to 0, so the rule does
# not error and the missing field conservatively treats prior deletes as zero.
r5_require_approval_budget if {
	prior_deletes := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
	prior_deletes + input.magnitude.count > delete_session_budget
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

# require_approval (R5) — session delete budget exceeded; fires when R3 and R2
# do not, so precedence is preserved and exactly one decision is produced.
decision := {
	"decision": "require_approval",
	"reason": "session delete budget exceeded (fragmentation guard)",
	"rule": "reeflex.policy/session_delete_budget",
} if {
	r5_require_approval_budget
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
	not r5_require_approval_budget
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
	not r5_require_approval_budget
}
