"""
main.py — Entry point for reeflex-core.

Usage:
  python main.py

Environment variables:
  REEFLEX_HOST        bind host (default 127.0.0.1)
  REEFLEX_PORT        bind port (default 8080)
  REEFLEX_OPA_BIN     path to opa binary (default: opa, must be on PATH)
  REEFLEX_POLICY_DIR  directory containing reeflex.rego (default: ./policy)
  REEFLEX_AUDIT_LOG   path to JSONL audit log (default: ./audit/decisions.jsonl)
  REEFLEX_WINDOW_SECONDS  rolling window for cumulative ledger (default: 3600)
  REEFLEX_OPA_TIMEOUT seconds before OPA subprocess is killed (default: 10)
"""

import sys
import pathlib

# Ensure the reeflex-core root is on sys.path so `app` package is importable
# whether the user runs `python main.py` from the repo root or from anywhere.
_here = pathlib.Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from app.server import run  # noqa: E402

if __name__ == "__main__":
    run()
