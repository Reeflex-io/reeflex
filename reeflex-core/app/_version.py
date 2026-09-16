# _version.py — single source of truth for the reeflex-core version string.
#
# Read by telemetry.py for the CEF header <version> field and the JSON
# reeflex_version field. Also importable by /healthz if it is ever extended
# to return the version.
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
CORE_VERSION: str = "0.2.1"
