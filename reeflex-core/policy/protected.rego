# protected.rego — WHICH THINGS ARE PRODUCTION ASSETS (RFX-153).
#
# Same package as reeflex.rego (OPA merges every .rego file in a policy dir
# into one evaluation).  Like budgets.rego, this is a file a POLICY AUTHOR
# EDITS: the mechanism at the bottom is the engine, the two lists at the top
# are the operator's statement about their own estate.
#
# =============================================================================
# THE GAP THIS FILE CLOSES
# =============================================================================
# `blast_radius` is a CARDINALITY axis — `single` means "one entity" (SPEC §4).
# R2 requires `broad`, R3 requires `systemic`.  So before this file existed:
#
#     irreversible + production + single   -> no rule but R4 default_allow
#     irreversible + production + scoped   -> the same
#
# and `rm /srv/prod/db.sqlite` — one production database, unrecoverable — was
# ALLOWED with no human.  So were `> db.sqlite`, `truncate -s 0 db.sqlite` and
# `dd of=db.sqlite`.  Measured on a core built from main 44c6f85 (RFX-153).
#
# THIS COULD NOT BE FIXED IN THE ADAPTER.  SPEC §4.2 makes the axis a
# measurement of the affected set and says a name "may claim KIND; it may not
# claim CARDINALITY".  An adapter looking at `rm /srv/prod/db.sqlite` cannot
# honestly emit `broad` about a command that names one file, and pricing it
# `broad` anyway would ALSO price `rm /tmp/scratch.txt` broad — the adapter
# defaults `target.environment` to production, so every `rm` a coding agent
# issues would become an approval prompt, and a gate that asks on that is
# switched off within a day (RFX-145's lesson from the other side).
#
# One production database file is not a small blast radius in any sense a
# customer would recognise.  It is a small CARDINALITY.  What was missing is a
# second, ORTHOGONAL input the cardinality axis was never able to carry: IS THE
# THING BEING DESTROYED A PRODUCTION ASSET.  That is site knowledge — the
# adapter cannot know it and core cannot derive it — so it belongs exactly
# where budgets.rego already put the money limits: in policy data the operator
# owns, edits, and can read.
#
# =============================================================================
# WHY A LIST HERE IS NOT THE LIST RFX-131 CONDEMNED
# =============================================================================
# RFX-131 removed a ten-string substring allowlist from the WordPress and
# Claude Code adapters, and PR #94 replaced it with a measurement.  The
# objection there was not "a list is bad": it was that a list of NAMES was
# being used to MEASURE the size of an affected set, in adapter code the
# operator could neither see nor change, while claiming to be an axis value.
#
# This list makes no measurement and no claim about size.  It is a DECLARATION
# of what the operator considers production state, in a file whose whole
# purpose is to be edited, and it is wrong only in the direction of asking a
# human too often.  A protect-list that is too long costs attention; an axis
# that is too optimistic costs the database.
#
# =============================================================================
# THE DEFAULT IS A FLOOR, NOT A CLAIM OF COMPLETENESS — READ THIS
# =============================================================================
# `protected_assets` below ships NON-EMPTY, because a default of `[]` would
# make the stock pack answer `allow` for `rm /srv/prod/db.sqlite` and RFX-153
# would be open in every installation that had not yet been configured.
#
# The entries are not a guess about naming conventions.  They are the locations
# the Filesystem Hierarchy Standard DESIGNATES for durable service state —
# /srv is "data for services provided by this system", /var/lib is "variable
# state information", /var/opt the same for add-on packages — plus the two
# de-facto container mount points.  The same standard designates /tmp and
# /var/tmp as TEMPORARY, which is why they are not here and why the
# `ephemeral_assets` list below can be short.
#
# IT IS STILL A FLOOR.  It knows nothing about /home/app/data, about a Postgres
# initialised somewhere else, about your bucket names, or about the S3 and
# cluster refs other adapters emit.  AN OPERATOR WHO DOES NOT EDIT THIS FILE IS
# PROTECTED ONLY WHERE THEIR ESTATE HAPPENS TO FOLLOW THE FHS.  That limit is
# restated in docs/ and in the adapter README rather than left implicit, and it
# is the reason `default_protected` exists.
package reeflex.policy

# ---- the policy an operator writes ----------------------------------------

# Prefixes of `target.ref` that name PRODUCTION STATE.  An irreversible action
# on one of these, in production, requires a human at ANY cardinality (R6).
#
# Matching is by path prefix (and exact match on the prefix itself, so
# `rm -rf /srv` is covered as well as `rm /srv/prod/db.sqlite`).  A ref is
# compared after core has canonicalised it — see envelope.py F8 — so `..`
# segments, doubled separators, a trailing newline and a zero-width character
# cannot spell a protected path into an unprotected one.
#
# Matching is CASE-INSENSITIVE, deliberately, and this is the one place the
# list is knowingly imprecise.  Linux paths are case-SENSITIVE, so
# /SRV/prod/db.sqlite is genuinely a different file from /srv/prod/db.sqlite.
# Reading it as a different file is the fail-OPEN direction, and the cost of
# the other choice is one unnecessary approval prompt on a path nobody has.
protected_assets := [
	"/srv/",
	"/var/lib/",
	"/var/opt/",
	"/var/spool/",
	"/var/backups/",
	"/data/",
	"/mnt/data/",
	"/opt/data/",
]

# Prefixes that name state whose loss is not a production event.  ONLY
# consulted when `default_protected` is true (see below); with the default
# posture, anything not in `protected_assets` is already unprotected, so this
# list changes nothing.
ephemeral_assets := [
	"/tmp/",
	"/var/tmp/",
	"/var/cache/",
	"/dev/shm/",
	"/run/",
]

# THE POSTURE SWITCH.  false (default): only the declared assets are
# protected — an unknown path is NOT held, so the stock pack costs the
# operator nothing on scratch files and RFX-153 is closed wherever the estate
# follows the FHS.  true: EVERY irreversible production action is held unless
# its ref is declared ephemeral, so an unknown path IS held.
#
# `true` is the posture that makes the floor's coverage limit disappear, at
# the price the ticket measured: an agent deleting a file the operator has not
# classified waits for a human.  It is off by default because a control the
# operator turns off on day two protects less than a smaller one they keep.
#
# UNLIKE REEFLEX_CLAUDE_STRICT (RFX-145), THIS KNOB IS PROVED TO MOVE A
# DECISION: tests/test_protected_asset_rfx153.py pins one unchanged envelope
# answering `allow` under false and `require_approval` under true.
default_protected := false

# ---- the mechanism (read by reeflex.rego; not what an operator edits) ------

# The ref as a comparison key: canonicalised by core (envelope.py F8), then
# lowercased HERE for the case-insensitive match argued above.  Absent, null
# or non-string -> "", which matches no prefix.  A missing ref therefore
# cannot make a protected asset look unprotected under the strict posture --
# see `protected_target`'s second rule, which treats it as unknown, not safe.
target_ref_key := lower(ref) if {
	ref := object.get(input, ["target", "ref"], "")
	is_string(ref)
} else := ""

# Does `key` fall under `prefix`?  Prefix match, plus exact match on the
# prefix with its trailing separator removed, so declaring "/srv/" protects
# "/srv" itself.
_under(key, prefix) if {
	startswith(key, lower(prefix))
}

_under(key, prefix) if {
	key == trim_suffix(lower(prefix), "/")
}

declared_protected if {
	some prefix in protected_assets
	_under(target_ref_key, prefix)
}

declared_ephemeral if {
	some prefix in ephemeral_assets
	_under(target_ref_key, prefix)
}

# DEFAULT POSTURE: protected only when declared.
protected_target if {
	not default_protected
	declared_protected
}

# STRICT POSTURE: protected unless declared ephemeral.  An empty/absent ref is
# NOT ephemeral, so it is protected -- an adapter that cannot name what it is
# destroying is the case a human should see, not the case that slips through.
protected_target if {
	default_protected
	not declared_ephemeral
}
