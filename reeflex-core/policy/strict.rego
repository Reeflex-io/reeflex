# strict.rego — the STRICT PRESET (RFX-433). Same package as reeflex.rego and
# budgets.rego; this is a file a POLICY AUTHOR edits, exactly like the limits
# in budgets.rego, not a Python constant and not an environment variable.
#
# WHAT THE BASE PACK DOES WITHOUT IT. An irreversible action in production is
# held when it is broad (R2), denied when it is systemic (R3), held on a path
# the operator declared production state (R6), and handled by R8-R11 when it
# is physical. An irreversible production action on ONE entity, or a bounded
# set of them, that matches none of those is allowed by R4. That is the right
# default for a coding agent, which deletes a single file in a production
# checkout many times a day, and the wrong one for a hospital or a plant.
#
# WHAT THE SWITCH DOES. With `hold_every_irreversible_in_production: true`,
# every envelope whose `axes.reversibility` is `irreversible` and whose
# `target.environment` is `production` is held, at any blast radius, any
# externality and any verb, under its own rule id:
#
#     reeflex.policy/irreversible_prod_strict    (R2s)
#
# so an audit row says the preset asked, not R2. It reads NEITHER the blast
# radius NOR the verb, for the reason R6 gives in reeflex.rego: cardinality and
# verb are the two fields an adapter prices worst.
#
# WHAT IT DOES NOT CHANGE. It only ever turns an ALLOW into a HOLD. Every deny
# (R3, R8, R10a) still wins and stays unresolvable. Every hold another rule
# already raises keeps that rule's id (see the R2s block in reeflex.rego for
# where it sits and why). With the switch off, which is the shipped default,
# no decision and no rule id changes; pinned by strict_test.rego and
# tests/test_strict_preset_rfx433.py.
#
# WHAT IT CANNOT SEE. It reads the reversibility and environment the adapter
# DECLARED. An adapter that prices an irreversible action `recoverable`, or a
# production target `staging`, is not held by this switch. When core GUESSED
# either field (it was absent or unrecognised), the hold is reported as R0
# `unclassified_action` instead, same as R2/R6.
package reeflex.policy

strict := {
	# false: coding agents (the shipped default).
	# true:  regulated / OT -- every irreversible action in production waits
	#        for a human.
	"hold_every_irreversible_in_production": false,
}
