# _version.py — single source of truth for the reeflex-core version string.
#
# Read by telemetry.py for the CEF header <version> field and the JSON
# reeflex_version field. Also importable by /healthz if it is ever extended
# to return the version.
#
# Convention: bump this together with the CHANGELOG [x.y.z] entry.

CORE_VERSION: str = "0.1.13"
