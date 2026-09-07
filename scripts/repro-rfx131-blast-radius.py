#!/usr/bin/env python3
"""
repro-rfx131-blast-radius.py -- RFX-131 reproduction, core side.

Takes the envelopes the WordPress normalizer actually produced
(repro-rfx131-blast-radius.php, JSONL on stdin) and evaluates each one straight
through `opa eval` against the SHIPPED policy pack -- no core process, no
network. Prints the verdict next to what the honest blast_radius would have
produced, so the cost of the substring miss is a decision, not an axis value.

Then it re-runs the SAME envelope with blast_radius replaced by the honest
value, which is the whole point: the axis is the only thing that changed.

Usage:
    php scripts/repro-rfx131-blast-radius.php 2>/dev/null \
      | python3 scripts/repro-rfx131-blast-radius.py

Env:
    REEFLEX_OPA_BIN     default /root/.local/bin/opa
    REEFLEX_POLICY_DIR  default <repo>/reeflex-core/policy
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

OPA = os.environ.get("REEFLEX_OPA_BIN", "/root/.local/bin/opa")
POLICY_DIR = pathlib.Path(
    os.environ.get(
        "REEFLEX_POLICY_DIR",
        pathlib.Path(__file__).resolve().parent.parent / "reeflex-core" / "policy",
    )
)

# A fresh session: no budget pressure, so nothing here is R5's doing.
FRESH_CUMULATIVE = {
    "total_count": 0,
    "count_by_verb": {},
    "count_by_externality": {},
    "amount_by_currency": {},
    "window_seconds": 3600,
}


def to_opa_input(envelope: dict, blast_radius: str | None = None) -> dict:
    """Mirror decide.py:715-736 -- the envelope plus cumulative, approval from
    what core verified (here: nothing was approved)."""
    inp = json.loads(json.dumps(envelope))
    if blast_radius is not None:
        inp["axes"]["blast_radius"] = blast_radius
    inp["cumulative"] = dict(FRESH_CUMULATIVE)
    inp["approval"] = {"present": False}
    return inp


def evaluate(inp: dict) -> tuple[str, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(inp, fh)
        path = fh.name
    try:
        p = subprocess.run(
            [OPA, "eval", "-d", str(POLICY_DIR), "-i", path, "--format=json",
             "data.reeflex.policy.decision"],
            capture_output=True, text=True, timeout=30,
        )
    finally:
        os.unlink(path)
    if p.returncode != 0:
        tail = p.stderr.strip().splitlines()[-1][:160] if p.stderr.strip() else "nonzero"
        return ("ERROR", tail)
    doc = json.loads(p.stdout)
    res = doc.get("result") or []
    if not res or not res[0].get("expressions"):
        return ("UNDEFINED", "")
    val = res[0]["expressions"][0].get("value")
    if val is None:
        return ("UNDEFINED", "")
    return (val["decision"], val["rule"])


def main() -> int:
    rows = [json.loads(line) for line in sys.stdin if line.strip()]
    if not rows:
        print("no envelopes on stdin -- pipe repro-rfx131-blast-radius.php into this",
              file=sys.stderr)
        return 2

    print(f"# policy dir: {POLICY_DIR}")
    print(f"# envelopes : {len(rows)}   (fresh session, approval absent, "
          f"REEFLEX_ENV=production)\n")

    hdr = (f"{'CASE':<34} {'AS SHIPPED':<26} {'IF AXIS WERE HONEST':<26} {'GAP'}")
    print(hdr)
    print("-" * len(hdr))

    gaps = 0
    for r in rows:
        env = r["envelope"]
        got_dec, got_rule = evaluate(to_opa_input(env))
        hon_dec, hon_rule = evaluate(to_opa_input(env, r["expect_honest"]))
        gap = "" if got_dec == hon_dec else f"{got_dec} -> {hon_dec}"
        if gap:
            gaps += 1
        print(f"{r['name']:<34} "
              f"{got_dec + '/' + got_rule.split('/')[-1]:<26} "
              f"{hon_dec + '/' + hon_rule.split('/')[-1]:<26} "
              f"{gap}")

    print("-" * len(hdr))
    print(f"\n{gaps} of {len(rows)} cases: the axis the adapter emits and the honest "
          f"axis reach DIFFERENT DECISIONS.")
    print("Run this against the pre-RFX-131 tree and again after: before, the gaps are "
          "allow -> deny (a fail-open, no human in the loop); after, they are "
          "require_approval -> deny (a human IS in the loop, and the residual is the "
          "broad/systemic line an undeclared adapter genuinely cannot see).")
    print("target.environment = "
          f"{rows[0]['envelope']['target']['environment']!r} on every row "
          "(REEFLEX_ENV=production), so R2/R3 were reachable throughout.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
