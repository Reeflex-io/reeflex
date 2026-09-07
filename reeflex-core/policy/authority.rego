# authority.rego — WHICH ACTIONS CHANGE WHO MAY ACT, OR CAUSE NEW CODE TO RUN
# (RFX-128, rule R7).
#
# Same package as reeflex.rego (OPA merges every .rego file in a policy dir into
# one evaluation).  Like budgets.rego and protected.rego, this is a file a
# POLICY AUTHOR EDITS: the three lists at the top are the operator's statement
# about their own estate; the mechanism at the bottom is the engine.
#
# =============================================================================
# THE GAP THIS FILE CLOSES
# =============================================================================
# R1-R5 read six things: action.verb, axes.reversibility, axes.blast_radius,
# axes.externality, target.environment, and the cumulative counters.  They read
# `action.ability` NOWHERE — grep the pack and it appears in no rule body.
#
# `action.ability` is not an incidental field.  SPEC §3 says it exists FOR THIS:
#
#     "The backend-specific operation is preserved in `action.ability` for
#      fine-grained rules; `verb` exists so a policy can say 'no delete in
#      production over N items' regardless of backend."
#
# So the pack shipped the coarse half of that sentence and never wrote the fine
# half.  What falls through is a whole family of harm that is honestly
# reversible, single-entity and internal — the adapter is NOT lying, the axes
# have nowhere to put it:
#
#     grant a user the administrator role   update / reversible / single -> ALLOW
#     grant a database superuser            update / reversible / single -> ALLOW
#     attach an IAM policy                  update / reversible / single -> ALLOW
#     reset another user's password         update / reversible / single -> ALLOW
#     rotate a credential to a new endpoint update / reversible / single -> ALLOW
#     disable MFA enrolment                 update / reversible / single -> ALLOW
#     install a plugin (arbitrary PHP)      create / reversible / single -> ALLOW
#
# Measured, not reasoned: all seven, plus five more, answered
# `allow / reeflex.policy/default_allow` on a real core at main 759b83f over
# HTTP, with `target.environment: production`.  12 of 12.  A privilege grant and
# a typo fix were indistinguishable to the canon.
#
# =============================================================================
# WHAT THIS FILE DOES NOT DO — READ THIS BEFORE TRUSTING IT
# =============================================================================
# 1. IT MATCHES `action.ability` AND NOTHING ELSE.  Not `target.ref`, and that
#    exclusion is deliberate and measured.  For reeflex-claude the ref is a
#    filesystem path, so matching refs would hold a coding agent on every edit
#    of `src/auth/roles.py` or `config/credentials.json`.  A gate that asks on
#    an ordinary edit is switched off within a day (RFX-145, RFX-158), and a
#    switched-off gate is a fail-open with extra steps.
#
# 2. SO IT SEES ONLY THE ADAPTERS WHOSE ABILITY NAMES THE OPERATION.  All four
#    shipped adapters populate `action.ability`, but two of them fill it with
#    the TOOL name, not the operation:
#      reeflex-wordpress  ->  users/assign-role, plugins/install   SEEN
#      n8n-nodes-reeflex  ->  operator-supplied ability string     SEEN
#      reeflex-mcp        ->  <system>/<tool_name>                 seen iff the
#                             upstream tool is honestly named
#      reeflex-claude     ->  claude-code/Bash                     NOT SEEN
#    `usermod -aG sudo attacker` reaches core as ability
#    `claude-code/Bash`, and this rule does not fire on it.  That half lives in
#    reeflex-claude's classify.py and is RFX-144 / RFX-158 territory.
#
# 3. AN ABILITY STRING IS CALLER-SUPPLIED.  An adapter that names its ability
#    `tweak-role` instead of `assign-role` evades this rule.  It is a FLOOR, not
#    a boundary, and it can never be complete.  What makes the floor worth
#    having anyway is that it is RAISE-ONLY (see below): being wrong costs an
#    approval prompt, never a missed deny.
#
# 4. IT CANNOT, BY ITSELF, SEE A SENSITIVE SETTING BEHIND A GENERIC ABILITY —
#    AND THAT HALF IS NOW CLOSED IN THE ADAPTER, NOT HERE (RFX-219).  RFX-128's
#    third example, disabling 2FA through `core/update-option`, still cannot be
#    closed in core: `params` is an open backend-specific bag by SPEC §2 and no
#    rule may pattern-match inside it, so `option_name: two_factor_enabled` and
#    `option_name: blogname` reach this file identical.  Matching the ability
#    `core/update-option` itself would hold EVERY option write, which is the
#    "asks on a build" mistake in a different costume.
#
#    What changed is on the WordPress side: the normalizer now splices the
#    security FAMILY and the option NAME into the ability for the options it
#    recognises —
#
#        core/update-option  ->  core/update-option/mfa/two_factor_enabled
#
#    — so `mfa` reaches `credential_signals` below and this rule fires on it
#    with no change to core at all.  Two consequences worth stating here, where
#    the next person edits the lists:
#
#      * THE THREE LISTS BELOW ARE NOW ALSO AN ADAPTER-FACING VOCABULARY.  The
#        WordPress map deliberately labels its options with words FROM these
#        lists (`mfa`, `role`, `membership`, `plugin`, `theme`, `cron`).  A
#        first draft used `security`, which is an honest label that no rule can
#        read — it tokenises to {core, update, security, option} and matches
#        nothing.  Renaming a signal here silently un-wires that adapter, so
#        rename by adding the new word rather than replacing the old one.
#      * IT IS STILL A FLOOR.  An option a plugin invents tomorrow is in no
#        list.  Being wrong costs an approval prompt, never a missed refusal.
#
#    Verified end to end in `reeflex-wordpress/tests/conformance-security-
#    options.php` against a live core: 21 assertions red before the adapter
#    change, 0 after, with `blogname` allowed in both directions.
#
# =============================================================================
# WHY REQUIRE_APPROVAL AND NEVER DENY, AND WHY RAISE-ONLY
# =============================================================================
# A hold is resolvable and a deny is not.  `authority_change_prod` is
# deliberately NOT added to core's NON_RESOLVABLE_RULES (server.py), so a human
# can clear it — "when unsure, ask" is the product's thesis and R0 (RFX-132)
# already established that a new terminal refusal is the wrong answer to a
# coverage gap.
#
# RAISE-ONLY: this rule can turn an `allow` into a `require_approval`.  It can
# never turn a `deny` into anything, never lower a verdict, and never relax
# R0/R2/R3.  That property is what makes an admittedly incomplete name-based
# list safe to ship: an over-long list costs attention, an under-long one leaves
# you exactly where main is today.
#
# WHY A LIST HERE IS NOT THE LIST RFX-131 CONDEMNED.  RFX-131 removed a
# substring allowlist that was used, inside adapter code the operator could
# neither see nor change, to MEASURE the size of an affected set while claiming
# to be an axis value.  These lists measure nothing and claim nothing about any
# axis.  They are a declaration of which operations the operator considers
# authority-bearing, in a file whose whole purpose is to be edited.
#
# A NOTE ON THE NUMBER "R7", BECAUSE THE NUMBER SPACE IS ALREADY CONTESTED.
# `reeflex_test.rego` on main names R5's budget DIMENSIONS `test_r6_*`, and PR
# #100 numbers named production assets R6.  So R6 already means two things and
# the number is the weakest part of any of these names.  Nothing in the code
# depends on it: what an auditor joins on, what NON_RESOLVABLE_RULES matches,
# and what the tests assert is the RULE ID STRING, `authority_change_prod`.
# The number is a comment.
#
# MATCHING IS BY WHOLE TOKEN, NOT SUBSTRING, and that is load-bearing:
# `records/update-migrant` must not match `grant` and
# `billing/create-installment` must not match `install`.  Both are pinned as
# tests.

package reeflex.policy

# ---- the policy an operator writes ----------------------------------------

#: Tokens naming an operation that changes WHO MAY ACT.
authority_signals := {
	"grant", "revoke", "role", "roles",
	"permission", "permissions", "privilege", "privileges",
	"capability", "capabilities",
	"acl", "iam", "rbac",
	"sudo", "superuser", "administrator", "impersonate",
	"owner", "owners", "member", "members", "membership",
}

#: Tokens naming an operation that changes HOW AN IDENTITY IS PROVED.
credential_signals := {
	"password", "passwd",
	"credential", "credentials",
	"secret", "secrets",
	"apikey", "keypair", "ssh",
	"mfa", "2fa", "totp", "otp", "passkey", "webauthn",
}

#: Tokens naming an operation that causes NEW CODE TO RUN.
#
# DELIBERATELY ABSENT, and this is a measurement gap rather than a judgement:
# `webhook`, `deploy`, `container` and `image` are not here because n8n's whole
# execution model is webhooks and this fleet has NO volume data on real n8n or
# CI traffic.  Shipping them blind is the "asks on a build" mistake.  Add them
# once someone has counted; the list is here to be edited.
executable_signals := {
	"install", "uninstall",
	"plugin", "plugins", "theme", "themes",
	"extension", "addon", "module", "package",
	"cron", "crontab",
	"script", "exec", "eval",
	"activate", "deactivate",
}

# ---- the engine -----------------------------------------------------------

#: Split an identifier into lowercase whole tokens, across BOTH separators and
#: camelCase humps, so `iam/AttachUserPolicy`, `grant_admin`, `assign-role` and
#: `plugins/install` all tokenise the same way.
#:
#: The camelCase pass runs FIRST and inserts a separator between a lowercase or
#: digit and a following uppercase; the split then treats every run of
#: non-alphanumerics as one separator.  Empty tokens are dropped.
ability_tokens(raw) := toks if {
	is_string(raw)
	humped := regex.replace(raw, `([a-z0-9])([A-Z])`, "${1}-${2}")
	toks := {t |
		some t in regex.split(`[^a-zA-Z0-9]+`, lower(humped))
		t != ""
	}
}

ability_tokens(raw) := set() if {
	not is_string(raw)
}

#: This envelope's ability, tokenised.  Read defensively: an envelope with no
#: `action.ability` must behave exactly as it did before this file existed.
r7_tokens := ability_tokens(object.get(input, ["action", "ability"], null))

#: Every signal this ability matched, across all three lists, sorted so the
#: reason string an operator reads is deterministic.
r7_matched_signals := sort([s |
	some s in r7_tokens
	s in (authority_signals | credential_signals) | executable_signals
])

# R7: an authority, credential or executability change in production.
#
# `verb != "read"` is STRUCTURAL, not a tuning knob: a read cannot change who
# may act, and without it `users/list-roles` would be held.  It is also what
# keeps R7 and R1 (read-only internal -> allow) from ever both being true, which
# would be a complete-rule conflict rather than a precedence question.
r7_authority_change if {
	input.target.environment == "production"
	input.action.verb != "read"
	count(r7_matched_signals) > 0
}
