#!/usr/bin/env python3
"""
export-claude-conformance.py -- write the Claude Code adapter's Bash
conformance corpus to reeflex-spec/conformance/claude-adapter-bash.json.

WHY A SCRIPT AND NOT A CLI SUBCOMMAND
=====================================
Regenerating a repo artefact is maintainer work, not something a customer who
ran `pip install reeflex-claude` needs on their PATH -- and `cli.py` is being
rewritten for RFX-147 in parallel, so adding a subparser to it would be a
merge conflict bought for nothing.

The corpus itself lives in the installed package
(reeflex_claude/conformance.py) because it is the adapter's own statement of
what it claims to stop.  This file only serialises it.

    python3 scripts/export-claude-conformance.py

tests/test_conformance_bash.py compares the committed artefact back against
the module, so the two cannot drift silently.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_REPO = _HERE.parent
sys.path.insert(0, str(_REPO / "reeflex-claude"))

from reeflex_claude import conformance  # noqa: E402

OUT = _REPO / "reeflex-spec" / "conformance" / "claude-adapter-bash.json"


def document() -> dict:
    return {
        "spec": "reeflex-spec/SPEC.md §3-§4 (NORMALIZE), Claude Code adapter",
        "adapter": "reeflex-claude",
        "tickets": ["RFX-144", "RFX-145", "RFX-146"],
        "residual_ticket": conformance.RESIDUAL_TICKET,
        "environment": "production",
        "generated_by": "python3 scripts/export-claude-conformance.py",
        "source_of_truth": "reeflex-claude/reeflex_claude/conformance.py",
        "cases": conformance.CASES,
    }


def main(argv: list) -> int:
    out = pathlib.Path(argv[1]) if len(argv) > 1 else OUT
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document(), indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(f"wrote {len(conformance.CASES)} cases to "
          f"{os.path.relpath(out, _REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
