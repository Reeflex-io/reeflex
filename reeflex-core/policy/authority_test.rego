# Tests for authority.rego (RFX-128, rule R7).
#
# TWO THINGS THIS FILE DOES ON PURPOSE.
#
# 1. IT ASSERTS THE DECISION, NOT THE PREDICATE.  RFX-167's whole lesson is that
#    a rule can be correct and change no verdict, so every attack row below
#    asserts `policy.decision.rule`, on an envelope core would really receive.
#    An assertion on `r7_authority_change` alone would still pass if someone
#    removed R7 from reeflex.rego's precedence chain and left the predicate.
#
# 2. IT READS THE SIGNAL LISTS OUT OF authority.rego RATHER THAN MIRRORING
#    THEM.  RFX-216 is about a drift detector that compared its own literal to
#    itself.  `policy.authority_signals` below IS the shipped list — editing the
#    list cannot leave these tests green against a rule that no longer contains
#    the token they name.
#
# BITE TEST (how this file was verified, per the round brief): on origin/main
# 759b83f, where authority.rego does not exist, every `attack_` row fails with
# `default_allow` and every `control_` row passes.  A test file where BOTH
# halves pass on the broken tree is measuring nothing.
package reeflex.policy_authority_test

import data.reeflex.policy

_axes := {"reversibility": "reversible", "blast_radius": "single", "externality": "internal"}

_env(verb, ability, environment) := {
	"action": {"namespace": "t", "verb": verb, "ability": ability},
	"target": {"kind": "t", "ref": "t:1", "environment": environment},
	"axes": _axes,
	"magnitude": {"count": 1},
	"approval": {"present": false, "hold_id": null},
}

# ---------------------------------------------------------------------------
# The family RFX-128 measured as allow/default_allow on main. All in
# production, all honestly reversible/single/internal -- the adapter is not
# lying, the canon had nowhere to put the risk.
# ---------------------------------------------------------------------------
attack_cases := {
	"grant_administrator_role": _env("update", "users/assign-role", "production"),
	"grant_db_superuser": _env("update", "postgres/grant_admin", "production"),
	"attach_iam_policy_camelcase": _env("update", "iam/AttachUserPolicy", "production"),
	"revoke_capability": _env("update", "users/revoke-capability", "production"),
	"add_group_member": _env("create", "directory/add-group-member", "production"),
	"reset_password": _env("update", "users/reset-password", "production"),
	"rotate_credential": _env("update", "n8n/update-credential", "production"),
	"disable_mfa": _env("update", "security/disable-mfa", "production"),
	"install_plugin": _env("create", "plugins/install", "production"),
	"activate_plugin": _env("update", "plugins/activate", "production"),
	"install_theme": _env("create", "themes/install", "production"),
	"schedule_cron": _env("create", "cron/schedule-event", "production"),
}

test_attacks_now_require_a_human if {
	every name, envelope in attack_cases {
		d := policy.decision with input as envelope
		_assert_hold(name, d)
	}
}

_assert_hold(name, d) if {
	d.decision == "require_approval"
	d.rule == "reeflex.policy/authority_change_prod"
} else := false if {
	print("FAILED:", name, "got", d)
}

# ---------------------------------------------------------------------------
# The false-positive floor. Every row here MUST stay allow: a gate that asks on
# ordinary work is switched off within a day (RFX-145, RFX-158), and a
# switched-off gate is a fail-open with extra steps.
# ---------------------------------------------------------------------------
control_cases := {
	# ordinary content work
	"edit_a_post": _env("update", "posts/update", "production"),
	"upload_media": _env("create", "media/upload", "production"),
	"update_site_title": _env("update", "core/update-option", "production"),
	"claude_code_edit": _env("update", "claude-code/Edit", "production"),
	# R7 is production-only, exactly like R2 and R3
	"grant_role_in_staging": _env("update", "users/assign-role", "staging"),
	"install_plugin_in_dev": _env("create", "plugins/install", "dev"),
	# WHOLE-TOKEN matching, not substring. These two are the reason
	# ability_tokens() splits instead of calling contains().
	"migrant_is_not_grant": _env("update", "records/update-migrant", "production"),
	"installment_is_not_install": _env("create", "billing/create-installment", "production"),
	# a read cannot change who may act -- this is what keeps R7 and R1 from
	# ever both being true
	"list_roles_is_a_read": _env("read", "users/list-roles", "production"),
	# an envelope with no ability at all must behave exactly as before
	"no_ability_field": {
		"action": {"namespace": "t", "verb": "update"},
		"target": {"kind": "t", "ref": "t:1", "environment": "production"},
		"axes": _axes,
		"magnitude": {"count": 1},
		"approval": {"present": false, "hold_id": null},
	},
}

test_controls_are_not_held if {
	every name, envelope in control_cases {
		d := policy.decision with input as envelope
		_assert_allow(name, d)
	}
}

_assert_allow(name, d) if {
	d.decision == "allow"
} else := false if {
	print("FAILED (false positive):", name, "got", d)
}

# ---------------------------------------------------------------------------
# R7 IS RAISE-ONLY. It may turn an allow into a hold. It must never lower a
# verdict -- so an ability carrying an authority signal on an envelope that R3
# already denies must still DENY, not soften to require_approval.
# ---------------------------------------------------------------------------
test_r7_does_not_lower_an_r3_deny if {
	d := policy.decision with input as {
		"action": {"namespace": "t", "verb": "delete", "ability": "users/revoke-role"},
		"target": {"kind": "t", "ref": "t:1", "environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false, "hold_id": null},
	}
	d.decision == "deny"
	d.rule == "reeflex.policy/irreversible_systemic_prod"
}

test_r7_does_not_relabel_an_r2_hold if {
	d := policy.decision with input as {
		"action": {"namespace": "t", "verb": "delete", "ability": "users/revoke-role"},
		"target": {"kind": "t", "ref": "t:1", "environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 1},
		"approval": {"present": false, "hold_id": null},
	}
	d.rule == "reeflex.policy/irreversible_broad_prod"
}

# ---------------------------------------------------------------------------
# The reason string is what a human reads in the hold. It must name WHICH
# signal fired, or "the canon asked for a human" is not actionable.
# ---------------------------------------------------------------------------
test_reason_names_the_matched_signal if {
	d := policy.decision with input as _env("update", "users/assign-role", "production")
	contains(d.reason, "role")
}

test_matched_signals_are_sorted_and_deduped if {
	got := policy.r7_matched_signals with input as _env(
		"update", "iam/grant-role-permission", "production",
	)
	got == ["grant", "iam", "permission", "role"]
}

# ---------------------------------------------------------------------------
# The tokenizer, directly. camelCase humps and every separator resolve to the
# same whole-token set.
# ---------------------------------------------------------------------------
test_tokenizer_splits_camelcase_and_separators if {
	policy.ability_tokens("iam/AttachUserPolicy") == {"iam", "attach", "user", "policy"}
	policy.ability_tokens("postgres/grant_admin") == {"postgres", "grant", "admin"}
	policy.ability_tokens("users/assign-role") == {"users", "assign", "role"}
	policy.ability_tokens("records/update-migrant") == {"records", "update", "migrant"}
}

test_tokenizer_is_total_on_junk if {
	policy.ability_tokens(null) == set()
	policy.ability_tokens(42) == set()
	policy.ability_tokens("") == set()
	policy.ability_tokens("///") == set()
}

# ---------------------------------------------------------------------------
# The lists are read from the shipped file, never mirrored (RFX-216). If a
# token is removed from authority.rego, the row above that depends on it fails
# -- these assertions say WHICH removal did it.
# ---------------------------------------------------------------------------
test_signal_lists_are_disjoint_and_lowercase if {
	all_signals := (policy.authority_signals | policy.credential_signals) | policy.executable_signals
	every s in all_signals {
		s == lower(s)
	}
	# a token in two lists would make the reason string ambiguous about which
	# family fired
	count(policy.authority_signals & policy.credential_signals) == 0
	count(policy.authority_signals & policy.executable_signals) == 0
	count(policy.credential_signals & policy.executable_signals) == 0
}

# The measurement gap recorded in authority.rego's comment, pinned so that
# adding these tokens is a deliberate edit with this test in the diff rather
# than a quiet widening. See the comment above executable_signals.
test_unmeasured_tokens_are_deliberately_absent if {
	every t in {"webhook", "deploy", "container", "image"} {
		not t in policy.executable_signals
	}
}
