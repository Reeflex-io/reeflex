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
#   money             input.params.amount + input.params.currency, whatever
#                      verb carries them. THE ONE DIMENSION WITH A UNIT:
#                      budgets are PER CURRENCY and aggregate as dimensionless
#                      utilisation, never as a sum of unlike amounts
#                      (RFX-133 -- see "money has UNITS" below).
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
	# money is the one dimension with UNITS -- see "money has UNITS" below.
	# `limits` is the per-currency table a policy author edits: one
	# independent statement of "no more than X of currency C per session".
	# `limit` is the fallback for any currency not named there, and is also
	# what an UNDECLARED currency ("XXX") is charged against.
	#
	# THE VALUES BELOW ARE ILLUSTRATIVE DEFAULTS AN OPERATOR MUST REVIEW.
	# They are not exchange rates and core never computes one; each entry is
	# a separate policy decision about how much of that currency a session
	# may move. A currency with no entry falls back to `limit`, which is
	# STRICTER than a converted equivalent for every low-unit-value currency
	# (JPY, IDR, ...) -- fail-closed, and the reason declaring the currencies
	# you actually transact in is worth doing.
	"money": {
		"limit": 5000,
		"limits": {
			"EUR": 5000,
			"USD": 5500,
			"GBP": 4300,
			"CHF": 4700,
			"JPY": 800000,
		},
	},
	"deletions": {"limit": 20},
	"external_sends": {"limit": 50},
	"objects_touched": {"limit": 200},
}

# ---- what an UNCOUNTABLE action costs (RFX-143) ------------------------
#
# THE DEFECT. `magnitude.count` has no way to say "I cannot enumerate the
# affected set". Its domain is int >= 1 (envelope.py F2 rejects 0, negatives,
# floats and bools) and an ABSENT count is filled with 1 -- the MINIMUM of that
# domain. Every dimension below charges that number, so before this table:
#
#   ONE call, count=45, irreversible/scoped/production  -> require_approval
#                                                          (session_delete_budget)
#   ONE call, count=1,  same axes                       -> allow
#   ONE call, magnitude OMITTED, same axes               -> allow, and 20 more
#
# The adapter that says how many objects it is about to destroy was charged for
# all of them; the adapter that said nothing, or said `1` while declaring the
# blast radius a whole table, was charged one. R5's deletions budget was
# measuring the caller's CANDOUR, not its deletions -- and the incentive ran
# the wrong way, which is the RFX-165/RFX-174 shape (supplying less information
# buys a lower price).
#
# THE SEMANTICS, one sentence: A COUNT MAY ONLY EVER RAISE THE CHARGE ABOVE THE
# FLOOR ITS OWN BLAST RADIUS IMPLIES, NEVER LOWER IT -- charged_count is
# max(count, floor[blast_radius]). This is deliberately keyed on the axis the
# adapter DID declare rather than on whether the count was declared, because
# every adapter shipped in this repo already defaults its own count to 1
# (reeflex-claude envelope.py:97, reeflex-mcp normalize.py, the WordPress
# normalizer, the n8n node) -- so a floor that fired only on an ABSENT count
# would fire on none of our own traffic. See SPEC §4.1.
#
# THE FLOORS BELOW ARE ILLUSTRATIVE DEFAULTS AN OPERATOR MUST REVIEW, exactly
# like the limits above. What is NOT a matter of taste is the ordering and the
# max(): those carry the invariant.
#
#   single   1  SPEC §4: "one entity". The axis already implies the count; 1 is
#               not a guess here, so there is nothing to floor.
#   scoped   1  SPEC §4: "a bounded set". DELIBERATELY LEFT AT 1. `scoped` is
#               the everyday value our adapters emit for ordinary work (a
#               `bash deploy.sh` is priced recoverable/scoped), so a floor here
#               would retune every session and buy a gate that asks on a build
#               -- switched off within a day, which is the RFX-158 trade in the
#               other direction. Stated as a deliberate non-change, not an
#               oversight.
#   broad   10  SPEC §4: "a large set / whole table / bucket". `count: 1` and
#               "whole table" contradict each other; the higher reading is the
#               fail-closed one.
#   systemic 20 SPEC §4: "could affect the system itself". Largely moot for
#               irreversible production work, which R3 already denies outright
#               -- it matters for the RECOVERABLE systemic action no other rule
#               reads.
#
# WHAT THIS ACTUALLY BUYS, MEASURED, AND THE HALF IT DOES NOT CLOSE.
# Repeated `delete` under one session, recoverable so R2/R3 cannot fire, on
# 759b83f vs this file (fresh core per cell, fresh session ids):
#
#   blast_radius    before   after
#   single           21       21     unchanged, by design
#   scoped           21       21     unchanged, by design
#   broad            21       12
#   systemic         21        2
#
# Before this change the trip point was 21 for ALL FOUR values -- the declared
# blast radius was worth nothing to the budget.
#
# `broad` lands on 12 and not on 3 because THE FLOOR APPLIES TO THE ACTION
# BEING DECIDED AND NOT TO THE LEDGER'S HISTORY. ledger.py::append_entry
# records the RAW `magnitude.count`, so the cumulative term keeps summing 1s
# while the current term is charged 10: the trip is the first i where
# 10 + (i-1) > 20, i.e. 12. Charging the floor on the cumulative side too would
# put it at 3, and that is a ledger.py change -- deliberately NOT made here,
# because the single source of truth for these floors is this file and a Python
# copy of the table would be exactly the unchecked mirror RFX-216 is about. The
# sound version routes the policy's own charged_count back into append_entry
# (decide.py already appends AFTER evaluating, so the seam exists). Filed
# rather than bodged; see the RFX-143 report.
#
# An unrecognised blast_radius cannot reach this table: envelope.py matches
# `_AXIS_ALLOWED` exactly and coerces anything else to the most-guarded member.
# The lookup is still written fail-closed (unknown -> the systemic floor) so
# that this file does not silently depend on that.
count_floor := {
	"single": 1,
	"scoped": 1,
	"broad": 10,
	"systemic": 20,
}

#: The floor implied by THIS action's declared blast radius. Fail-closed: a
#: blast_radius this table does not name is charged the strictest floor.
current_count_floor := f if {
	f := count_floor[input.axes.blast_radius]
} else := f if {
	f := count_floor.systemic
}

#: What the budget dimensions actually charge for this action. `magnitude.count`
#: is read defensively (absent -> 1) so this file behaves identically for an
#: envelope built by a path that predates F2's default.
charged_count := max([object.get(input, ["magnitude", "count"], 1), current_count_floor])

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
#
# money IS DELIBERATELY ABSENT from this function (RFX-133). It used to end
#     n := sum([v | some v in by_currency])
# which added EUR to JPY to IDR and compared the result to a scalar limit.
# A count dimension is a pure number and this "prior + current > limit" shape
# is correct for it; money is a QUANTITY WITH A UNIT and is not expressible in
# that shape at all. It has its own rules below.
cumulative_for(dimension) := n if {
	dimension == "objects_touched"
	n := object.get(input, ["cumulative", "total_count"], 0)
} else := n if {
	dimension == "deletions"
	n := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
} else := n if {
	dimension == "external_sends"
	n := object.get(input, ["cumulative", "count_by_externality", "outbound"], 0)
}

# current_for: THIS action's contribution to a dimension, added to the
# prior cumulative before comparing to the limit (same "prior + current"
# shape as the original R5).
#
# Every count dimension charges `charged_count`, not `input.magnitude.count`
# directly (RFX-143): a count may raise the charge above the floor its declared
# blast radius implies, never lower it.
current_for(dimension) := c if {
	dimension == "objects_touched"
	c := charged_count
} else := c if {
	dimension == "deletions"
	input.action.verb == "delete"
	c := charged_count
} else := c if {
	dimension == "deletions"
	input.action.verb != "delete"
	c := 0
} else := c if {
	dimension == "external_sends"
	input.axes.externality == "outbound"
	c := charged_count
} else := c if {
	dimension == "external_sends"
	input.axes.externality != "outbound"
	c := 0
}

# ---- money has UNITS (RFX-133) ----------------------------------------
#
# THE TWO DEFECTS THIS SECTION REPLACES.
#
# 1. EVASION. ledger.py recorded an amount only when params.currency was also
#    present, so omitting one optional field kept the spend out of
#    `cumulative.amount_by_currency` entirely and N calls of (limit - 1)
#    accumulated to nothing. Fixed at the boundary: envelope.py canonicalizes
#    the currency and ledger.py now ALWAYS accumulates, bucketing an
#    undeclared currency as "XXX" (ISO 4217: "no currency involved").
#
# 2. UNIT ERROR. `sum([v | some v in by_currency])` added EUR to JPY to IDR
#    and compared the total to one scalar limit. 2000 EUR + 2000 JPY +
#    2000 IDR read as "6000 > 5000" when it is about EUR 2012. That is not a
#    canonicalization bug and no amount of folding fixes it: the quantity
#    being compared was not a quantity of money.
#
# THE RESOLUTION: BUDGETS ARE PER-CURRENCY, AGGREGATED AS UTILISATION.
#
# Per-currency alone is not enough -- it reopens fragmentation one currency
# over: 4999 EUR + 4999 USD + 4999 GBP is ~EUR 14k and trips nothing. And
# "any mixed set is a refusal" is too blunt: an agent paying a EUR 10 invoice
# and a USD 12 invoice in one session would be held for nothing.
#
# So each currency is compared against ITS OWN limit, and the dimension
# aggregates the resulting UTILISATIONS -- used_c / limit_c -- which are
# DIMENSIONLESS. You cannot add EUR to JPY; you can add "fraction of the EUR
# budget consumed" to "fraction of the JPY budget consumed". That is
# legitimate arithmetic, it is deterministic, and it requires no exchange
# rate -- core never invents one and never reaches the network.
#
#   4999 EUR + 4999 USD -> 0.9998 + 0.9089 = 1.908  -> EXCEEDED (fragmentation
#                                                      across currencies is
#                                                      closed)
#   2000 EUR + 2000 JPY -> 0.4000 + 0.0025 = 0.4025 -> fine (the wrong-DENY
#                                                      the old sum produced)
#
# TRADE-OFF, STATED: the utilisation sum is stricter than a converted total
# whenever several currencies are in play, because it treats each currency's
# limit as independently spendable. Two currencies each at 60% of their own
# limit trip the budget even though neither limit was breached. For a safety
# firewall that is the correct bias -- a session moving money in several
# currencies at once is exactly the shape worth a human look -- and it is a
# wrong-HOLD, not a wrong-ALLOW.

# The amount THIS action moves. abs() because the budget measures EXPOSURE,
# not a signed balance: a negative amount would otherwise subtract from
# cumulative spend and let a session alternate +N/-N forever. Matches
# ledger.append_entry(), which accumulates abs() for the same reason.
current_money_amount := a if {
	raw := object.get(input, ["params", "amount"], 0)
	is_number(raw)
	a := abs(raw)
} else := 0

# The currency it is denominated in. Already canonicalized to an ISO 4217
# alpha-3 code or "XXX" by envelope.canonicalize_currency() -- this rule does
# NOT fold anything itself, by design: canonicalization happens once, at the
# boundary, so the ledger's bucket keys and the policy's lookup keys cannot
# drift apart.
current_money_currency := c if {
	raw := object.get(input, ["params", "currency"], "XXX")
	is_string(raw)
	c := raw
} else := "XXX"

# Per-currency limit: per-principal override wins, then the per-currency
# table, then the principal's scalar fallback, then the default scalar.
money_limit(currency) := lim if {
	lim := principal_budgets[input.agent.session_id].money.limits[currency]
} else := lim if {
	lim := default_budgets.money.limits[currency]
} else := lim if {
	lim := principal_budgets[input.agent.session_id].money.limit
} else := lim if {
	lim := default_budgets.money.limit
}

# Every currency in play: those already in the ledger, plus this action's.
money_current_currencies := {current_money_currency} if {
	current_money_amount > 0
} else := set()

money_currencies := object.keys(object.get(input, ["cumulative", "amount_by_currency"], {})) | money_current_currencies

# prior + current, PER CURRENCY (never across).
money_total(currency) := t if {
	currency == current_money_currency
	t := object.get(input, ["cumulative", "amount_by_currency", currency], 0) + current_money_amount
} else := t if {
	t := object.get(input, ["cumulative", "amount_by_currency", currency], 0)
}

# The dimensionless aggregate. Currencies whose limit is <= 0 are excluded
# here (division would be meaningless) and handled by the second
# money_exceeded rule below.
money_utilisation := sum([u |
	some c in money_currencies
	lim := money_limit(c)
	lim > 0
	u := money_total(c) / lim
])

money_exceeded if {
	money_utilisation > 1
}

# A limit of 0 (or negative) means "no spend permitted in this currency".
# Division cannot express that, so it gets its own rule -- otherwise a
# deliberate zero limit would be silently skipped, i.e. fail OPEN.
money_exceeded if {
	some c in money_currencies
	money_limit(c) <= 0
	money_total(c) > 0
}

# exceeded_dimensions: every dimension where prior + current > its budget.
# money is excluded from this generic shape and contributed separately below,
# because "prior + current" is only meaningful for a unitless count.
exceeded_dimensions contains dimension if {
	some dimension in budget_dimensions
	dimension != "money"
	current_for(dimension) + cumulative_for(dimension) > budget_limit(dimension)
}

exceeded_dimensions contains "money" if {
	money_exceeded
}

# Deterministic single pick for the reason/rule text when more than one
# dimension trips on the same action — alphabetical, so the SAME input
# always yields the SAME decision (SPEC §5 determinism invariant).
first_exceeded_dimension := sort([d | some d in exceeded_dimensions])[0]
