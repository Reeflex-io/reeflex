#!/usr/bin/env python3
"""
audit-grid-canon.py -- dev-1--016: exhaustive coherence check of the base pack.

Evaluates data.reeflex.policy.decision over the FULL cross product of the
closed enums plus budget-relevant states, straight through `opa eval` (no
core, no envelope.py), and reports:

  1. CONFLICTS  -- any input where two `decision :=` bodies are both true with
                   different values (Rego raises; would fail-closed to deny).
  2. UNDEFINED  -- any input where no rule produces a decision.
  3. COVERAGE   -- which rule fires for how many of the grid points; a rule
                   with 0 is unreachable on any envelope shape.
  4. R1-INERT   -- re-evaluates every grid point with R1 deleted and diffs the
                   DECISION (not the rule label). Zero diffs => R1 changes no
                   outcome and is a label, not a rule.
"""
from __future__ import annotations

import itertools
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

REV = ["reversible", "recoverable", "irreversible"]
BLAST = ["single", "scoped", "broad", "systemic"]
EXT = ["internal", "outbound", "physical"]
ENVS = ["production", "staging", "dev"]
VERBS = ["read", "create", "update", "delete", "execute", "transact", "emit"]
# (magnitude.count, cumulative, params, approval.present)
STATES = [
    ("under", 1, {"total_count": 0, "count_by_verb": {}, "count_by_externality": {},
                  "amount_by_currency": {}}, {}, False),
    ("del_over", 5, {"total_count": 18, "count_by_verb": {"delete": 18},
                     "count_by_externality": {}, "amount_by_currency": {}}, {}, False),
    ("obj_over", 5, {"total_count": 199, "count_by_verb": {},
                     "count_by_externality": {}, "amount_by_currency": {}}, {}, False),
    ("send_over", 5, {"total_count": 60, "count_by_verb": {},
                      "count_by_externality": {"outbound": 48},
                      "amount_by_currency": {}}, {}, False),
    ("money_over", 1, {"total_count": 2, "count_by_verb": {},
                       "count_by_externality": {},
                       "amount_by_currency": {"EUR": 4900}},
     {"amount": 200, "currency": "EUR"}, False),
    ("multi_over", 5, {"total_count": 199, "count_by_verb": {"delete": 18},
                       "count_by_externality": {"outbound": 48},
                       "amount_by_currency": {"EUR": 4900}},
     {"amount": 200, "currency": "EUR"}, False),
    ("del_over_approved", 5, {"total_count": 18, "count_by_verb": {"delete": 18},
                              "count_by_externality": {}, "amount_by_currency": {}},
     {}, True),
]


def build_inputs():
    out = []
    for rev, blast, ext, envn, verb, st in itertools.product(
        REV, BLAST, EXT, ENVS, VERBS, STATES
    ):
        label, count, cumulative, params, approved = st
        out.append((
            f"{rev}|{blast}|{ext}|{envn}|{verb}|{label}",
            {
                "agent": {"id": "agent:grid", "session_id": "grid"},
                "action": {"namespace": "grid", "verb": verb},
                "target": {"environment": envn},
                "axes": {"reversibility": rev, "blast_radius": blast,
                         "externality": ext},
                "magnitude": {"count": count},
                "params": params,
                "approval": {"present": approved},
                "cumulative": dict(cumulative, window_seconds=3600),
            },
        ))
    return out


def eval_all(policy_dir: pathlib.Path, inputs):
    """One opa eval per input (batched via a single doc would lose per-input
    conflict attribution)."""
    results = {}
    for label, inp in inputs:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(inp, fh)
            path = fh.name
        try:
            p = subprocess.run(
                [OPA, "eval", "-d", str(policy_dir), "-i", path, "--format=json",
                 "data.reeflex.policy.decision"],
                capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        if p.returncode != 0:
            results[label] = ("ERROR", p.stderr.strip().splitlines()[-1][:160]
                              if p.stderr.strip() else "nonzero")
            continue
        doc = json.loads(p.stdout)
        res = doc.get("result") or []
        if not res or not res[0].get("expressions"):
            results[label] = ("UNDEFINED", "")
            continue
        val = res[0]["expressions"][0].get("value")
        if val is None:
            results[label] = ("UNDEFINED", "")
        else:
            results[label] = (val["decision"], val["rule"])
    return results


def main():
    inputs = build_inputs()
    print(f"# grid points: {len(inputs)}")
    print(f"# policy dir : {POLICY_DIR}\n")

    base = eval_all(POLICY_DIR, inputs)

    conflicts = {k: v for k, v in base.items() if v[0] == "ERROR"}
    undefined = [k for k, v in base.items() if v[0] == "UNDEFINED"]
    coverage: dict[str, int] = {}
    for dec, rule in base.values():
        if dec not in ("ERROR", "UNDEFINED"):
            coverage[rule] = coverage.get(rule, 0) + 1

    print(f"1. CONFLICTS (two decisions on one input): {len(conflicts)}")
    for k, v in list(conflicts.items())[:5]:
        print(f"     {k}\n       {v[1]}")
    print(f"\n2. UNDEFINED (no rule fired): {len(undefined)}")
    for k in undefined[:5]:
        print(f"     {k}")

    print("\n3. COVERAGE (grid points per rule):")
    for rule, n in sorted(coverage.items(), key=lambda kv: -kv[1]):
        print(f"     {n:6d}  {rule}")
    ALL_RULES = [
        "reeflex.policy/irreversible_systemic_prod",
        "reeflex.policy/irreversible_broad_prod",
        "reeflex.policy/session_delete_budget",
        "reeflex.policy/cumulative_budget",
        "reeflex.policy/read_only_internal",
        "reeflex.policy/default_allow",
    ]
    dead = [r for r in ALL_RULES if r not in coverage]
    print(f"     UNREACHABLE ON THE WHOLE GRID: {dead or 'none'}")

    # 4. R1-inert: same grid with r1_allow stubbed to never hold.
    print("\n4. R1 DECISION EFFECT (grid re-evaluated with R1 removed):")
    src = (POLICY_DIR / "reeflex.rego").read_text()
    stripped = src.replace(
        'input.action.verb == "read"\n\tinput.axes.externality == "internal"',
        "false",
    )
    if stripped == src:
        print("     !! could not patch R1 out; skipping")
        return
    with tempfile.TemporaryDirectory() as td:
        tdp = pathlib.Path(td)
        (tdp / "reeflex.rego").write_text(stripped)
        (tdp / "budgets.rego").write_text((POLICY_DIR / "budgets.rego").read_text())
        no_r1 = eval_all(tdp, inputs)
    dec_diffs = [k for k in base
                 if base[k][0] != no_r1.get(k, ("?",))[0]]
    rule_diffs = [k for k in base
                  if base[k][1] != no_r1.get(k, ("?", "?"))[1]]
    print(f"     DECISION differs on : {len(dec_diffs)} / {len(inputs)} grid points")
    print(f"     rule LABEL differs on: {len(rule_diffs)} / {len(inputs)} grid points")
    if not dec_diffs and rule_diffs:
        print("     ==> R1 changes ZERO decisions; it only relabels "
              f"{len(rule_diffs)} allows. R1 is a label, not a rule.")


if __name__ == "__main__":
    sys.exit(main())
