# _version.py — single source of truth for the reeflex-core version string.
#
# Read by telemetry.py for the CEF header <version> field and the JSON
# reeflex_version field. Also importable by /healthz if it is ever extended
# to return the version.
#
# WHICH JSON, precisely — measured on the live api-dev core 2026-09-20
# (dev-1--148), because getting this wrong cost a round its instrument:
# `reeflex_version` is written by the telemetry emitter, i.e. it reaches the
# SIEM/syslog stream. It is NOT a key of the local `/app/audit/decisions.jsonl`
# line — over 3032 real decisions in the live file the field appears ZERO times,
# and `/healthz` does not carry the version either. So a running core has no
# unauthenticated surface that states its own version: to read it off a live
# instance you either read the syslog/CEF stream, or resolve
# `app.telemetry._core_version` inside the running container.
#
# Convention: bump this together with the CHANGELOG [x.y.z] entry.

# 0.2.0 and not 0.1.16: REEFLEX_REQUIRE_VERIFIED_APPROVER now defaults to true,
# which CHANGES WHAT GETS ALLOWED for anyone running the OSS core with
# self-asserted approvals. A default that moves the allow/refuse line is not a
# patch, whatever the size of the diff. See CHANGELOG [0.2.0].
#
# 0.2.1 and not 0.3.0: core changed since v0.2.0 (the gate-credential path,
# RFX-224, and the field-treatment work) but no default moved the allow/refuse
# line again — the same envelope gets the same verdict, rule id and reason.
# It is bumped because `release.yml` pushes the GHCR image as BOTH `:v0.2.1`
# and `:latest` whenever reeflex-core/ changed since the previous tag, and an
# image tagged v0.2.1 that answers "0.2.0" in its CEF header and its
# reeflex_version field is two artefacts claiming one version. See
# CHANGELOG [0.2.1].
#
# 0.2.2: THE TEST THE 0.2.1 NOTE ABOVE STATES DOES NOT HOLD HERE, and that is
# recorded rather than glossed. "The same envelope gets the same verdict, rule
# id and reason" is false across v0.2.1 → this build. Measured 2026-09-20
# (dev-1--148) on the artefact api-dev was running, code and pack copied out of
# the running container with `docker cp`, evaluated through app/opa.py on the
# real rego, with FOUR controls in the same run — two destructive, two read:
#
#   verb               v0.2.1                          this build
#   findOneAndDelete   allow/read_only_internal        require_approval/session_delete_budget
#   getAndDelete       allow/read_only_internal        require_approval/session_delete_budget
#   query_and_purge    allow/read_only_internal        require_approval/session_delete_budget
#   count_and_compact  allow/read_only_internal        require_approval/session_delete_budget
#   delete       CTRL  require_approval/…_budget       require_approval/…_budget    (unchanged)
#   frobnicate   CTRL  require_approval/…_budget       require_approval/…_budget    (unchanged)
#   read         CTRL  allow/read_only_internal        allow/read_only_internal     (unchanged)
#   search_files CTRL  allow/read_only_internal        allow/read_only_internal     (unchanged)
#
# The controls are what make those four movements attributable. At a spent
# budget the instrument prints require_approval for both destructive controls on
# BOTH sides and allow for both read controls on BOTH sides — so it is observably
# able to print either verdict, and prints a difference only where one exists.
# `count_and_compact` is the residual RFX-304 declared and left open in its own
# CHANGELOG note; RFX-308 closed it, and it is listed here because a claim in
# that note is only worth as much as the arm that re-measures it.
#
# (at the budget edge — 20 deletions already spent in the session. At call 1 in
# a fresh session both sides allow, so an empty-ledger probe reads "no
# difference" and is wrong: the escape is that a production core computed verb
# `read` for an irreversible delete, so it was never CHARGED against R5's
# deletions budget at all.)
#
# Every movement TIGHTENS — RFX-304, RFX-308 and RFX-324 elect the destructive
# word a compound name describes — and no arm moved in the loosening direction.
# But "it only ever tightens" is still a moved allow/refuse line: an operator on
# v0.2.1 whose agents spell deletions this way will start seeing holds they did
# not see yesterday, and by the rule written for 0.2.0 above that is not a
# patch.
#
# It is numbered 0.2.2 because the console decided the release number on
# 2026-09-19 (PLAN-20260907-backlog.md, "DECISION 1"); the measurement above is
# the argument for 0.3.0 and is left here so the next release reads it rather
# than re-deriving it. Nothing resolves reeflex-core by semver — its artefact is
# a GHCR image tag, it has no pyproject.toml and no dependent pins it — so the
# cost of the number being low is documentary, not functional. See
# CHANGELOG [0.2.2].
CORE_VERSION: str = "0.2.2"
