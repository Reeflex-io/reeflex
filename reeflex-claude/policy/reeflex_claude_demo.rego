# reeflex-claude demo policy pack (v0.1)
# Governing Claude Code tool calls via the Reeflex Action Envelope.
# This pack is ADDITIVE and ISOLATED — it lives in its own package
# (reeflex.claude_demo) and is tested independently with `opa test`.
# It does NOT touch, conflict with, or replace the base reeflex.policy pack.
#
# Input: Action Envelope produced by the reeflex-claude adapter, with the
# additional adapter-supplied context fields:
#   input.context.classification_tier  in {benign, moderate, destructive_broad,
#                                           destructive_systemic}
#   input.context.danger_signature     short slug (informational only)
#
# Precedence (mirrors base policy): deny > require_approval > allow.
# Exactly ONE decision is produced for any input (explicit `not` guards).
#
# Rule slugs (for audit `rule` field):
#   D1  reeflex.claude_demo/systemic_destruction_prod
#   D2  reeflex.claude_demo/broad_destruction_prod
#   D3  reeflex.claude_demo/irreversible_outbound_prod
#   A1  reeflex.claude_demo/read_only_internal
#   A2  reeflex.claude_demo/default_allow
package reeflex.claude_demo

# ---- predicates (factored bodies) ------------------------------------------

# D1 predicate: destructive_systemic tier in production.
# Matches: `rm -rf /`, DROP DATABASE, fork bomb — no approval overrides this.
d1_deny if {
	input.context.classification_tier == "destructive_systemic"
	input.target.environment == "production"
}

# D2 predicate: destructive_broad tier in production, not yet approved.
# Matches: broad delete, force-push, prod-config overwrite.
d2_require_approval if {
	input.context.classification_tier == "destructive_broad"
	input.target.environment == "production"
	not input.approval.present
}

# D3 predicate: irreversible outbound emit in production, not yet approved,
# and NOT already captured by D2 (distinct because externality == "outbound"
# is the distinguishing condition — e.g. publish / force-push that carries
# classification_tier other than destructive_broad, such as "moderate").
# When classification_tier == "destructive_broad" the D2 predicate already
# fires and D3 is redundant; the `not d2_require_approval` guard prevents
# double-firing and keeps mutual exclusion intact.
d3_require_approval if {
	input.action.verb == "emit"
	input.axes.reversibility == "irreversible"
	input.axes.blast_radius == "broad"
	input.axes.externality == "outbound"
	input.target.environment == "production"
	not input.approval.present
	not d1_deny
	not d2_require_approval
}

# A1 predicate: read-only internal action.
a1_allow if {
	input.action.verb == "read"
	input.axes.externality == "internal"
}

# ---- decision object (single value, explicit precedence) -------------------

# deny (D1) — highest precedence. No approval can override.
decision := {
	"decision": "deny",
	"reason": "destructive_systemic coding action in production is unconditionally denied",
	"rule": "reeflex.claude_demo/systemic_destruction_prod",
	"obligations": ["audit:full"],
} if {
	d1_deny
}

# require_approval (D2) — broad destructive in production, unapproved.
# Fires only when D1 does not.
decision := {
	"decision": "require_approval",
	"reason": "destructive_broad coding action in production requires human approval",
	"rule": "reeflex.claude_demo/broad_destruction_prod",
	"obligations": ["audit:full"],
} if {
	d2_require_approval
	not d1_deny
}

# require_approval (D3) — irreversible outbound emit in production, unapproved.
# Fires only when D1 and D2 do not.
decision := {
	"decision": "require_approval",
	"reason": "irreversible outbound emit in production requires human approval",
	"rule": "reeflex.claude_demo/irreversible_outbound_prod",
	"obligations": ["audit:full"],
} if {
	d3_require_approval
	not d1_deny
	not d2_require_approval
}

# allow (A1) — read-only internal, when no higher-risk rule applies.
decision := {
	"decision": "allow",
	"reason": "read-only internal action",
	"rule": "reeflex.claude_demo/read_only_internal",
} if {
	a1_allow
	not d1_deny
	not d2_require_approval
	not d3_require_approval
}

# allow (A2) — default: nothing high-risk matched, A1 did not apply either.
decision := {
	"decision": "allow",
	"reason": "no high-risk condition matched",
	"rule": "reeflex.claude_demo/default_allow",
} if {
	not a1_allow
	not d1_deny
	not d2_require_approval
	not d3_require_approval
}
