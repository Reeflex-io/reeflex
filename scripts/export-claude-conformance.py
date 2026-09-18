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
        # The measured scope of RFX-158's command-substitution shape.  A
        # residual id in a row tells a reader THAT something is open; this
        # tells them how much.  Exported because the JSON, not the Python
        # module, is what the spec ships and what an auditor reads.
        #
        # `case_ids` is DERIVED and a guard re-measures it on every run
        # (test_residual_scope_rfx158).  `measured_utc` is NOT: it is a
        # hand-maintained literal that nothing checks, so it goes stale the
        # first time the scope changes and nobody edits this line.  dev-2--093
        # found it already stale while rebasing -- the set moved from 41 ids to
        # 53 and the date did not follow it -- and updated it by hand, which is
        # the same failure mode one round later.  Whoever next widens the scope
        # either moves this date or, better, derives it.
        "residual_scope": {
            conformance.GAP_TICKET: {
                "shape": "gap-command-substitution",
                "effect": "a destructive command re-spelled as `$(echo '<command>')` "
                          "is priced execute/recoverable/scoped with target_ref=null",
                "measured_utc": "2026-09-19",
                "case_ids": list(conformance.GAP_COMMAND_SUBSTITUTION_SCOPE),
            },
        },
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
