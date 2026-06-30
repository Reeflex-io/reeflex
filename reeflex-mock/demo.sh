#!/usr/bin/env bash
# reeflex-mock/demo.sh -- thin wrapper to run the end-to-end demo.
# Requires: REEFLEX_OPA_BIN and REEFLEX_POLICY_DIR set in env, OR defaults used.
#
# Usage (from repo root):
#   export REEFLEX_OPA_BIN=/path/to/opa
#   export REEFLEX_POLICY_DIR=/path/to/reeflex-core/policy
#   bash reeflex-mock/demo.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python "${SCRIPT_DIR}/demo.py" "$@"
