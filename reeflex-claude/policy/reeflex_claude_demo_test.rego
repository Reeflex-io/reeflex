# Table-driven unit tests for the reeflex-claude demo policy pack.
# Mirrors the style of reeflex-core/policy/reeflex_test.rego.
# Package: reeflex.claude_demo_test  (isolated from base policy tests)
# Run: opa test reeflex-claude/policy/ -v
package reeflex.claude_demo_test

import data.reeflex.claude_demo

# ---------------------------------------------------------------------------
# Shared envelope builder helpers (base shape reused across cases)
# ---------------------------------------------------------------------------

# Minimal read-internal envelope (A1).
read_internal_envelope := {
	"action": {"verb": "read", "namespace": "claude-code", "ability": "claude-code/Read"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"context": {"classification_tier": "benign", "danger_signature": "read_file"},
}

# Destructive-systemic in production (D1).
systemic_prod_envelope := {
	"action": {"verb": "execute", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"context": {"classification_tier": "destructive_systemic", "danger_signature": "rm_rf_root"},
}

# Destructive-broad in production, unapproved (D2).
broad_prod_unapproved_envelope := {
	"action": {"verb": "delete", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
	"magnitude": {"count": 100},
	"approval": {"present": false},
	"context": {"classification_tier": "destructive_broad", "danger_signature": "bulk_delete_prod"},
}

# Destructive-broad in production, approved (D2 bypassed -> allow).
broad_prod_approved_envelope := {
	"action": {"verb": "delete", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
	"magnitude": {"count": 100},
	"approval": {"present": true},
	"context": {"classification_tier": "destructive_broad", "danger_signature": "bulk_delete_prod"},
}

# Destructive-broad in STAGING (environment gate: not production -> allow).
broad_staging_envelope := {
	"action": {"verb": "delete", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "staging"},
	"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
	"magnitude": {"count": 100},
	"approval": {"present": false},
	"context": {"classification_tier": "destructive_broad", "danger_signature": "bulk_delete_staging"},
}

# Irreversible outbound emit (D3) — moderate tier so D2 does NOT apply.
outbound_emit_prod_envelope := {
	"action": {"verb": "emit", "namespace": "claude-code", "ability": "claude-code/WebFetch"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "outbound"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"context": {"classification_tier": "moderate", "danger_signature": "publish_force_push"},
}

# Benign execute (A2 default allow).
benign_execute_envelope := {
	"action": {"verb": "execute", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "dev"},
	"axes": {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"context": {"classification_tier": "benign", "danger_signature": "ls_command"},
}

# Moderate update in staging (A2 default allow).
moderate_update_staging_envelope := {
	"action": {"verb": "update", "namespace": "claude-code", "ability": "claude-code/Write"},
	"target": {"environment": "staging"},
	"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
	"magnitude": {"count": 3},
	"approval": {"present": false},
	"context": {"classification_tier": "moderate", "danger_signature": "edit_config_staging"},
}

# Systemic AND broad in production — D1 must beat D2 (precedence proof).
systemic_broad_prod_envelope := {
	"action": {"verb": "execute", "namespace": "claude-code", "ability": "claude-code/Bash"},
	"target": {"environment": "production"},
	"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
	"magnitude": {"count": 1},
	"approval": {"present": false},
	"context": {"classification_tier": "destructive_systemic", "danger_signature": "drop_database"},
}

# ---------------------------------------------------------------------------
# D1 — destructive_systemic + production -> deny
# ---------------------------------------------------------------------------

test_d1_systemic_prod_deny if {
	got := claude_demo.decision with input as systemic_prod_envelope
	got.decision == "deny"
	got.rule == "reeflex.claude_demo/systemic_destruction_prod"
}

# D1 carries audit:full obligation.
test_d1_systemic_prod_audit_obligation if {
	got := claude_demo.decision with input as systemic_prod_envelope
	got.obligations[_] == "audit:full"
}

# ---------------------------------------------------------------------------
# D2 — destructive_broad + production + not approved -> require_approval
# ---------------------------------------------------------------------------

test_d2_broad_prod_unapproved_require_approval if {
	got := claude_demo.decision with input as broad_prod_unapproved_envelope
	got.decision == "require_approval"
	got.rule == "reeflex.claude_demo/broad_destruction_prod"
}

# D2 approval bypass: same envelope but approval.present = true -> allow (falls to A2).
test_d2_broad_prod_approved_allows if {
	got := claude_demo.decision with input as broad_prod_approved_envelope
	got.decision == "allow"
}

# D2 environment gate: destructive_broad in staging (not production) -> allow.
test_d2_broad_staging_allows if {
	got := claude_demo.decision with input as broad_staging_envelope
	got.decision == "allow"
}

# ---------------------------------------------------------------------------
# D3 — outbound irreversible broad emit in prod, unapproved -> require_approval
# ---------------------------------------------------------------------------

test_d3_irreversible_outbound_prod_require_approval if {
	got := claude_demo.decision with input as outbound_emit_prod_envelope
	got.decision == "require_approval"
	got.rule == "reeflex.claude_demo/irreversible_outbound_prod"
}

# ---------------------------------------------------------------------------
# A1 — read-only internal -> allow
# ---------------------------------------------------------------------------

test_a1_read_internal_allow if {
	got := claude_demo.decision with input as read_internal_envelope
	got.decision == "allow"
	got.rule == "reeflex.claude_demo/read_only_internal"
}

# ---------------------------------------------------------------------------
# A2 — benign/moderate, no high-risk match -> default allow
# ---------------------------------------------------------------------------

test_a2_benign_execute_default_allow if {
	got := claude_demo.decision with input as benign_execute_envelope
	got.decision == "allow"
	got.rule == "reeflex.claude_demo/default_allow"
}

test_a2_moderate_update_staging_default_allow if {
	got := claude_demo.decision with input as moderate_update_staging_envelope
	got.decision == "allow"
	got.rule == "reeflex.claude_demo/default_allow"
}

# ---------------------------------------------------------------------------
# Precedence: D1 (deny) outranks D2 (require_approval) when both axes match.
# An envelope that is both destructive_systemic tier AND broad blast_radius
# in production must yield deny, not require_approval.
# ---------------------------------------------------------------------------

test_precedence_d1_beats_d2 if {
	got := claude_demo.decision with input as systemic_broad_prod_envelope
	got.decision == "deny"
	got.rule == "reeflex.claude_demo/systemic_destruction_prod"
}

# ---------------------------------------------------------------------------
# Exactly one decision is produced (no undefined, no multiple values).
# We verify count == 1 for several representative cases.
# ---------------------------------------------------------------------------

test_exactly_one_decision_systemic if {
	count({d | d := claude_demo.decision with input as systemic_prod_envelope}) == 1
}

test_exactly_one_decision_broad_unapproved if {
	count({d | d := claude_demo.decision with input as broad_prod_unapproved_envelope}) == 1
}

test_exactly_one_decision_read_internal if {
	count({d | d := claude_demo.decision with input as read_internal_envelope}) == 1
}

test_exactly_one_decision_benign if {
	count({d | d := claude_demo.decision with input as benign_execute_envelope}) == 1
}
