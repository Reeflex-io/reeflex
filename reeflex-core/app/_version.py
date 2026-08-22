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
CORE_VERSION: str = "0.2.0"
