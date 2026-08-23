# Reeflex base policy pack (v0.1) - deterministic decision rules R1-R5.
# Evaluated by reeflex-core /v1/decide; see reeflex-spec/SPEC.md and docs/adr/0002-no-llm-in-decision-path.md.
# R5's configurable budgets (money/deletions/external_sends/objects_touched)
# live in the sibling file budgets.rego (same package).
#
# Input is the Action Envelope (reeflex-spec/SPEC.md §2). Output is a `decision`
# object per SPEC §5: { "decision", "reason", "rule" }, decision in
# allow | deny | require_approval. Pure Rego, no LLM, no external data — same
# envelope in, same decision out (SPEC §5).
package reeflex.policy

# Precedence is explicit and total: deny > require_approval > allow, so exactly
# one decision is produced for any input.
#   require_approval  when R0 fires (R2/R3/R6 matched on inputs core GUESSED)
#   deny              when R3 fires and R0 does not
#   require_approval  when R2 fires and neither R3 nor R0 does
#   require_approval  when R5 fires and none of R3/R2/R0 do
#   require_approval  when R6 fires and none of R3/R2/R5/R0 do
#   require_approval  when R7 fires and none of R3/R2/R5/R6/R0 do
#   allow             otherwise (R1 read-only internal, or R4 default)
#
# R6 IS DELIBERATELY LAST AMONG THE HOLDS.  It could equally have been placed
# above R5 — both produce require_approval, so the DECISION is the same either
# way and only the reported `rule` differs.  Putting it last buys a property
# worth more than a better reason string: R6 CAN ONLY EVER CONVERT AN ALLOW
# INTO A HOLD.  No existing deny, no existing hold, and no existing rule id
# changes when protected.rego is added, so an auditor comparing a pre-RFX-153
# and a post-RFX-153 build sees additions and nothing else.  R2's and R5's
# verdicts are still reported under R2's and R5's rule ids, which is what a
# report reads. Pinned by tests/test_protected_asset_rfx153.py.
#
# R0 OUTRANKS R6 TOO, AND THAT IS A REBASE DECISION, NOT AN INHERITED ONE.
# R6 was written against a tree where R0 did not exist (#106 landed after).
# R0's claim is "the verdict rests on a value core GUESSED, so report a
# coverage gap rather than a control"; R6's rule id claims the operator
# DECLARED this path production state.  Both cannot be the honest label for
# one decision, and R0's is the weaker, truer one — so R6 yields.  The
# reachable case is a protected ref with a DECLARED low cardinality and an
# UNRECOGNISED target.environment: F5 coerces `qa-eu` to the most-guarded tier
# `production`, R2/R3 never fire (the cardinality is `single`), and before this
# ladder R6 would have raised a hold whose reason said "declared production
# asset" about a value core supplied.
#
# Note what "guessed" does NOT mean here, because the obvious reading is wrong:
# `target.environment` and `action.verb` are REQUIRED fields — omitting either
# is a 400 and never reaches a rule — so for those two, undeclared means an
# unrecognised VALUE.  Only the axes can genuinely be absent.  Measured, not
# assumed: test_an_absent_environment_or_verb_is_refused_not_guessed.
#
# Pinned in both directions by tests/test_protected_asset_rfx153.py
# (test_r0_outranks_r6_when_environment_was_guessed and
# test_r6_keeps_its_own_rule_id_when_the_adapter_declared_everything).

# ---- predicates (the rule bodies, factored out for reuse + precedence) -----

# ===========================================================================
# R0: THE ACTION WE COULD NOT CLASSIFY (RFX-132)
# ===========================================================================
# An adapter that cannot price an action emits an envelope with the axes
# omitted, an environment outside the SPEC enum, a verb nobody aliased.
# envelope.py fills each gap with its conservative default -- and the three
# defaults COMPOSE into irreversible + systemic + production, which is R3:
# the one rule a human is not allowed to clear.
#
#     {"action": {"verb": "frobnicate"},
#      "target": {"environment": "qa-eu"},
#      "axes": {}}                          -> deny, irreversible_systemic_prod
#
# Each of those defaults was individually right and individually argued ("a
# wrong DENY is a nuisance, a wrong ALLOW is the product failing"). The
# COMPOSITION was never designed, and what it produces is "when unsure,
# refuse" on a product whose entire value proposition is "when unsure, ask".
#
# WHY HOLD AND NOT DENY. A gate that denies the unfamiliar gets switched off,
# and a switched-off gate is a fail-open with extra steps. HOLD is the third
# state this product exists to have, and "I do not know what this is, ask a
# human" is the most honest thing it can say. Measured volume is the test of
# that claim and it is in the PR, not asserted here.
#
# WHY HOLD AND NOT ALLOW. ALLOW is the defect class -- RFX-86, RFX-85,
# RFX-127, RFX-133 are all one caller-supplied value reaching a verdict
# unchecked. An unclassified action is not evidence that it is safe.
#
# WHY IT IS SAFE TO DOWNGRADE R3 HERE, AND ONLY HERE. R3's terminal refusal
# is the right answer for an action an adapter AFFIRMATIVELY DECLARED to be
# irreversible + systemic + production. R0 fires only when at least one of
# those three inputs is something core GUESSED -- so R3 keeps every case it
# was designed for and loses only the cases where it was firing on core's own
# defaults. `provenance.undeclared` is computed in envelope.py from the raw
# caller input and OVERWRITTEN there unconditionally, so a caller cannot
# assert its way into this softer verdict.
#
# WHY IT ALSO OUTRANKS R2, WHICH IS ALREADY A HOLD. R0 changes no verdict
# there -- it changes the RULE ID, which is the point. An auditor has to be
# able to tell "a rule asked for a human" from "we could not tell what this
# was": the first is a control working as designed, the second is a coverage
# gap that happens to be safe, and they are different facts about the
# deployment. Same verdict, same obligations, distinct reason code.
#
# R0 IS A HOLD, NOT A DENY, SO IT IS RESOLVABLE. That is deliberate: it is the
# whole difference from the R3 it replaces. `irreversible_systemic_prod` stays
# in core's NON_RESOLVABLE_RULES; `unclassified_action` is not in it, and the
# default resolution policy makes it human-only.

#: The classification inputs R2 and R3 read. `axes.externality` and
#: `action.verb` are recorded in provenance too, but neither is read by R2/R3,
#: so guessing them cannot by itself have produced the verdict R0 is softening.
r0_classification_inputs := {"axes.reversibility", "axes.blast_radius",
	"target.environment"}

#: Which of those this envelope's verdict was reached by GUESSING.
#: Read defensively: an envelope from a path that predates the provenance
#: block has no `provenance` key, and must behave exactly as it did before.
r0_guessed_inputs contains f if {
	some f in object.get(input, ["provenance", "undeclared"], [])
	f in r0_classification_inputs
}

r0_unclassified if {
	count(r0_guessed_inputs) > 0
	r3_deny
}

r0_unclassified if {
	count(r0_guessed_inputs) > 0
	r2_require_approval
}

#: The classification inputs R6 reads — and it is a DIFFERENT set from R2/R3's.
#: R6 deliberately does not read `axes.blast_radius` (cardinality is the axis
#: that was wrong about a named production asset in the first place, RFX-153),
#: so a guessed blast_radius cannot be what produced an R6 verdict and must not
#: be what downgrades it.  Same discipline as the note on
#: r0_classification_inputs above, applied per rule rather than globally.
r6_classification_inputs := {"axes.reversibility", "target.environment"}

r6_guessed_inputs contains f if {
	some f in object.get(input, ["provenance", "undeclared"], [])
	f in r6_classification_inputs
}

# R0 vs R6.  A hold reported as `irreversible_protected_asset_prod` tells an
# operator the adapter DECLARED this an irreversible production action on a
# path they themselves declared production state.  If core supplied either of
# those two inputs, that sentence is false and #106's `unclassified_action` is
# the true one — same verdict, honest reason code.  r6_guessed_inputs is a
# subset of r0_classification_inputs, so the reason string below always names
# at least one field.
r0_unclassified if {
	count(r6_guessed_inputs) > 0
	r6_require_approval
}

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

# R5: CONFIGURABLE cumulative budgets over heterogeneous action types
# (SPEC §4.1; RFX-11). budgets.rego (same package, loaded from the same
# policy dir) defines the dimensions, their limits as policy DATA a user
# writes/edits (not a bare Rego constant baked into this rule, and not a
# Python constant), and optional per-principal overrides. This predicate
# only asks "did ANY configured dimension trip" — exceeded_dimensions and
# first_exceeded_dimension (budgets.rego) already read cumulative
# defensively (missing `cumulative` -> 0), so a first call in a session
# never errors.
budget_require_approval if {
	count(exceeded_dimensions) > 0
	not input.approval.present
}

# R6: irreversible destruction of a DECLARED PRODUCTION ASSET, at ANY
# cardinality (RFX-153).  R2 and R3 both require a large blast_radius, and
# blast_radius is a CARDINALITY axis — so an irreversible production action on
# ONE named entity reached no rule at all and R4 allowed it.  `rm
# /srv/prod/db.sqlite` was the measured case.
#
# The predicate deliberately reads NEITHER blast_radius NOR the verb.
# Cardinality is the axis that was wrong about this action, and the verb is the
# field an adapter guesses worst (RFX-144): a truncate-by-redirect and a `dd`
# over the same file are `execute`, not `delete`, and destroy it just as
# completely.  What it reads instead is `protected_target` — the operator's own
# declaration of what production state IS (protected.rego), the one input the
# cardinality axis could never carry.
r6_require_approval if {
	input.axes.reversibility == "irreversible"
	input.target.environment == "production"
	protected_target
}

# ---- decision object (single value via explicit precedence) ----------------

# require_approval (R0) — highest precedence. See the R0 block above for why
# this outranks a DENY: R3's terminal refusal is the right answer for an action
# an adapter declared, and the wrong one for an action core guessed at.
#
# The reason NAMES THE FIELDS, sorted, so the hold an operator sees says which
# part of the action was unclassifiable rather than only that some part was.
# "the classifier is not keeping up" is only actionable if it says at what.
decision := {
	"decision": "require_approval",
	"reason": sprintf(
		"this action could not be classified: %v %s not declared by the adapter and core used its conservative default, so the verdict rests on a guess -- a human decides",
		[concat(", ", sort(r0_guessed_inputs)), r0_was_were],
	),
	"rule": "reeflex.policy/unclassified_action",
} if {
	r0_unclassified
}

r0_was_were := "was" if count(r0_guessed_inputs) == 1

r0_was_were := "were" if count(r0_guessed_inputs) != 1

# deny (R3) — the terminal refusal, on inputs the adapter actually declared.
decision := {
	"decision": "deny",
	"reason": "irreversible systemic change in production is not allowed even with approval",
	"rule": "reeflex.policy/irreversible_systemic_prod",
} if {
	r3_deny
	not r0_unclassified
}

# require_approval (R2) — fires only when R3 and R0 do not.
decision := {
	"decision": "require_approval",
	"reason": "irreversible broad change in production requires human approval",
	"rule": "reeflex.policy/irreversible_broad_prod",
} if {
	r2_require_approval
	not r3_deny
	not r0_unclassified
}

# require_approval (R5) — the "deletions" dimension specifically tripped its
# budget. Kept under its original rule id + reason text (this is the same
# fragmentation guard SPEC §4.1 has documented since v0.1) for backward
# compatibility; the limit itself now comes from budgets.rego's configurable
# default (still 20) instead of a bare constant. Fires when R3 and R2 do not,
# so precedence is preserved and exactly one decision is produced.
decision := {
	"decision": "require_approval",
	"reason": "session delete budget exceeded (fragmentation guard)",
	"rule": "reeflex.policy/session_delete_budget",
} if {
	budget_require_approval
	first_exceeded_dimension == "deletions"
	not r3_deny
	not r2_require_approval
	# R0 needed no guard here while it fired only on top of R2/R3, both of
	# which R5 already excludes. R6's clause broke that: R0 can now fire with
	# neither, on a protected ref whose environment core guessed, and a
	# fragmentation budget can be tripped by the same call. Without this line
	# both bodies are true and OPA raises eval_conflict_error — core answering
	# 500 on a decision it used to get right. Pinned by
	# test_precedence_is_total_across_the_grid.
	not r0_unclassified
}

# require_approval (R5, other dimensions) — any dimension OTHER than
# "deletions" (money, external_sends, objects_touched, or one a policy
# author adds to budgets.rego) tripped its budget. Same rule number as
# above — R5 is now "the configurable cumulative budget guard", generalized
# past the one hardcoded verb it started as (RFX-11): aggregable across
# heterogeneous action types, including the small-tier actions a
# hardcoded, payments-only amplifier would assign zero weight to.
decision := {
	"decision": "require_approval",
	"reason": sprintf("cumulative %s budget exceeded (fragmentation guard)", [first_exceeded_dimension]),
	"rule": "reeflex.policy/cumulative_budget",
} if {
	budget_require_approval
	first_exceeded_dimension != "deletions"
	not r3_deny
	not r2_require_approval
	not r0_unclassified
}

# require_approval (R6) — an irreversible production action on an asset the
# operator declared production state, at a cardinality R2 does not reach.
# Fires only when R3, R2, R5 and R0 do not, so precedence stays total and no
# pre-existing verdict is renamed. R0 is in that list because this rule id
# asserts the adapter DECLARED both axes it reads; see the R0-vs-R6 note in the
# precedence block at the top of this file.
decision := {
	"decision": "require_approval",
	"reason": "irreversible change to a declared production asset requires human approval",
	"rule": "reeflex.policy/irreversible_protected_asset_prod",
} if {
	r6_require_approval
	not r3_deny
	not r2_require_approval
	not budget_require_approval
	not r0_unclassified
}

# require_approval (R7) — the action changes WHO MAY ACT, how an identity is
# proved, or what code runs, in production. authority.rego (same package,
# loaded from the same policy dir) holds the three operator-editable signal
# lists and the tokenizer; this predicate only asks "did any of them match".
#
# Fires only when R3, R2, R5, R6 and R0 do not, so precedence stays total and
# exactly one decision is produced. R5 winning a tie is arbitrary and harmless:
# both are require_approval, and R5's reason names a budget the operator
# configured while R7's names a signal, so keeping the configured one visible is
# the better of two holds.
#
# THE R6 AND R0 GUARDS ARE A REBASE DECISION, NOT AN INHERITED ONE (dev-3 round
# 039, rebased onto #100 `be8fe8e` and #106). R7 was written against a tree
# where neither R6 (protected assets, #100) nor R0 (#106) existed. Without these
# two lines OPA raises `eval_conflict_error` — "complete rules must not produce
# multiple outputs" — and core answers HTTP 500 on a decision each rule alone
# gets right. Both pairs are reachable, not theoretical:
#   * R6 x R7: verb=delete ability=iam/revoke-role environment=production
#     ref=/srv/prod/iam/roles.db reversibility=irreversible — `/srv/` is in
#     #100's shipped protected_assets and `iam`/`revoke`/`role` are all
#     authority_signals.
#   * R0 x R7: the same envelope with provenance.undeclared=["target.environment"].
# R6 wins the first because its reason names the operator's own declared asset;
# R0 wins the second for the reason in the R0-vs-R6 note above — a verdict that
# rests on a field core GUESSED is reported as a coverage gap, not as a control.
# The VERDICT is `require_approval` either way; only the rule id moves. Pinned by
# tests/test_authority_family_rfx128.py's co-fire cases.
#
# R7 IS RESOLVABLE. `authority_change_prod` is deliberately not in core's
# NON_RESOLVABLE_RULES — see the "why require_approval and never deny" block in
# authority.rego. R1 needs no `not r7_authority_change` guard because
# r7_authority_change requires `verb != "read"` and r1_allow requires
# `verb == "read"`; the guard is written there anyway so that relaxing one of
# them later cannot silently produce a complete-rule conflict.
decision := {
	"decision": "require_approval",
	"reason": sprintf(
		"this action changes authority, credentials or what code runs in production (%s) -- a human decides",
		[concat(", ", r7_matched_signals)],
	),
	"rule": "reeflex.policy/authority_change_prod",
} if {
	r7_authority_change
	not r3_deny
	not r2_require_approval
	not budget_require_approval
	not r6_require_approval
	not r0_unclassified
}

# allow (R1) — read-only internal, when no higher-risk rule applies.
#
# R6 OUTRANKS R1 ON PURPOSE.  A `read` declared `irreversible` on a protected
# production asset is a contradiction no honest adapter emits, and R1's only
# other conditions are the verb and the externality — both caller-asserted.
# Letting R1 win would therefore hand back a one-field evasion of R6 (relabel
# the delete `read`), which is the exact shape SPEC §3 already cross-checks for
# with _delete_signal_from_ability. So an irreversible action is never
# read-only, whatever the verb says.
decision := {
	"decision": "allow",
	"reason": "read-only internal action",
	"rule": "reeflex.policy/read_only_internal",
} if {
	r1_allow
	not r2_require_approval
	not r3_deny
	not budget_require_approval
	not r6_require_approval
	not r7_authority_change
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
	not budget_require_approval
	not r6_require_approval
	not r7_authority_change
}
