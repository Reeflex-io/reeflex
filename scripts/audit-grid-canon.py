#!/usr/bin/env python3
"""
audit-grid-canon.py -- dev-1--016: exhaustive coherence check of the base pack.

Evaluates data.reeflex.policy.decision over the FULL cross product of the
closed enums plus budget-relevant states, straight through `opa eval` (no
core, no envelope.py), and reports:

  1. CONFLICTS  -- any input where two `decision :=` bodies are both true with
                   different values (Rego raises; would fail-closed to deny).
  2. UNDEFINED  -- any input where no rule produces a decision.
  3. COVERAGE   -- which rule fires for how many of the grid points, against the
                   rule-id inventory READ OUT OF THE PACK.  A rule with 0 here
                   is unreachable ON THIS GRID; see the next section before
                   reading that as "dead".
  3b. FINE-FIELD -- the grid varies the closed enums and holds every
                   FINE-GRAINED field constant, so rules that read those fields
                   cannot fire on it however many points it has.  This section
                   probes them directly, so section 3's silence is attributed
                   rather than left to the reader.
  4. R1-INERT   -- re-evaluates every grid point with R1 deleted and diffs the
                   DECISION (not the rule label). Zero diffs => R1 changes no
                   outcome and is a label, not a rule.

WHAT THE GRID HOLDS CONSTANT, AND WHY IT IS WRITTEN HERE (RFX-128, dev-1--206).
The grid's envelope carries `action` as {namespace, verb} and no `ability`, no
`target.ref` and no `provenance`.  Three of the pack's nine rule ids read
exactly those fields:

    authority_change_prod             action.ability      (authority.rego, R7)
    irreversible_protected_asset_prod target.ref          (protected.rego, R6)
    unclassified_action               provenance.undeclared        (reeflex.rego, R0)

So they cannot fire on any grid point, and until this section existed the
script's own `ALL_RULES` was a SIX-ITEM HARDCODED LIST written before those
three rules existed -- so it printed `UNREACHABLE ON THE WHOLE GRID: none`, a
reassuring line, over a run in which a third of the pack was never exercised.
Measured: the 756 fresh-session points answer `allow` 714/756 (94.4%) on the
pack at 3904c65 AND byte-identically on the pack at 3d097c3, five weeks and
three new rules later, with 0 of 756 decisions differing.  Set
`action.ability = users/assign-role` on the same 756 points and `allow` drops to
534 (70.6%) with R7 on 180 of them.  The number was a property of the
instrument, not of the pack -- which is why the inventory is now DERIVED and the
blind fields are named in output.
"""
from __future__ import annotations

import itertools
import json
import os
import pathlib
import re
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


#: Rule ids the grid CANNOT reach, and the field each one reads.  Used only to
#: attribute section 3's silence; the inventory itself is read out of the pack.
FINE_FIELD_RULES = {
    "reeflex.policy/authority_change_prod": "action.ability",
    "reeflex.policy/irreversible_protected_asset_prod": "target.ref",
    "reeflex.policy/unclassified_action": "provenance.undeclared",
}

RULE_ID_RE = re.compile(r'"rule":\s*"(reeflex\.policy/[a-z_]+)"')


def pack_rule_ids(policy_dir: pathlib.Path) -> set[str]:
    """Every rule id the pack can emit, READ OUT OF THE PACK.

    This used to be a hardcoded list and drifted three rules behind the tree
    (RFX-128).  Deriving it means a rule added tomorrow shows up in section 3
    as never-fired instead of being silently absent from the check.
    """
    ids: set[str] = set()
    for f in sorted(policy_dir.glob("*.rego")):
        if f.name.endswith("_test.rego"):
            continue
        ids |= set(RULE_ID_RE.findall(f.read_text()))
    return ids


def fine_field_inputs():
    """Envelopes that populate the fields the grid holds constant.

    Deliberately small: enough to establish that each fine-field rule is
    reachable and to show what it answers, not a second cross product.  Each
    carries a NEUTRAL twin so a hold here is attributable to the fine field
    rather than to the axes.
    """
    def env(label, **over):
        e = {
            "agent": {"id": "agent:fine", "session_id": "fine"},
            "action": {"namespace": "fine", "verb": "update"},
            "target": {"environment": "production"},
            "axes": {"reversibility": "irreversible", "blast_radius": "single",
                     "externality": "internal"},
            "magnitude": {"count": 1},
            "params": {},
            "approval": {"present": False},
            "cumulative": {"total_count": 0, "count_by_verb": {},
                           "count_by_externality": {}, "amount_by_currency": {},
                           "window_seconds": 3600},
        }
        for k, v in over.items():
            if isinstance(v, dict) and isinstance(e.get(k), dict):
                e[k] = {**e[k], **v}
            else:
                e[k] = v
        return (label, e)

    return [
        env("action.ability  authority-bearing",
            action={"namespace": "fine", "verb": "update",
                    "ability": "users/assign-role"}),
        env("action.ability  neutral (control)",
            action={"namespace": "fine", "verb": "update",
                    "ability": "posts/update-title"}),
        env("target.ref      declared protected prefix",
            target={"environment": "production", "ref": "/srv/prod/data"}),
        env("target.ref      undeclared path (control)",
            target={"environment": "production", "ref": "/tmp/scratch"}),
        env("provenance      reversibility guessed",
            provenance={"undeclared": ["axes.reversibility"]}),
        env("provenance      nothing guessed (control)",
            provenance={"undeclared": []}),
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
    inventory = pack_rule_ids(POLICY_DIR)
    print(f"     rule-id inventory READ FROM THE PACK: {len(inventory)} ids")
    if not inventory:
        print("     !! read 0 rule ids out of the pack -- the inventory scan "
              "found nothing, so the line below would be vacuous. Not printing it.")
        return
    unseen = sorted(inventory - set(coverage))
    surprise = sorted(set(coverage) - inventory)
    if surprise:
        print(f"     !! fired but NOT in the inventory (scan is behind the "
              f"pack): {surprise}")
    print(f"     NEVER FIRED ON THIS GRID: {unseen or 'none'}")
    for r in unseen:
        why = FINE_FIELD_RULES.get(r)
        print(f"       {r}"
              + (f" -- reads {why}, which this grid holds constant; see 3b"
                 if why else
                 " -- reads no field this grid holds constant; look at it"))

    # 3b. The fields the grid cannot vary, probed directly, so that the line
    # above is attributed rather than left to the reader.
    print("\n3b. FINE-FIELD PROBE (the fields the grid holds constant):")
    fine = eval_all(POLICY_DIR, fine_field_inputs())
    for label, (dec, rule) in fine.items():
        print(f"     {label:44} {dec:17} {rule}")
    reached = {rule for dec, rule in fine.values()
               if dec not in ("ERROR", "UNDEFINED")}
    still_unseen = sorted(set(unseen) - reached)
    print(f"     NEVER FIRED IN THIS RUN AT ALL: {still_unseen or 'none'}")
    if still_unseen:
        print("       ^ these are the ones worth looking at: neither the grid "
              "nor the fine-field probe reached them.")

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
        # EVERY non-test rule file, by glob (RFX-128). This used to name
        # reeflex.rego and budgets.rego as literals, so the first new rule
        # file in the pack left `r7_authority_change` (and, on PR #100,
        # `protected_assets`) undefined in the temp dir. opa then exited
        # nonzero on all 5292 points, eval_all recorded ("ERROR", ...) for
        # each, and this section printed "DECISION differs on 5292 / 5292" --
        # a confident number over a run in which nothing evaluated at all.
        # The comparison is only meaningful if both sides ran the same pack
        # minus R1.
        for src_file in sorted(POLICY_DIR.glob("*.rego")):
            if src_file.name.endswith("_test.rego"):
                continue
            text = stripped if src_file.name == "reeflex.rego" else src_file.read_text()
            (tdp / src_file.name).write_text(text)
        copied = sorted(p.name for p in tdp.glob("*.rego"))
        no_r1 = eval_all(tdp, inputs)
    # The floor: an errored re-run must not be reported as a difference.
    errored = [k for k, v in no_r1.items() if v[0] in ("ERROR", "UNDEFINED")]
    if errored:
        print(f"     !! the no-R1 re-run produced {len(errored)} "
              f"ERROR/UNDEFINED point(s) over {copied}")
        print(f"     !! first: {no_r1[errored[0]]}")
        print("     !! NOT reporting a difference count -- it would be a "
              "measurement of the harness, not of R1")
        return
    dec_diffs = [k for k in base
                 if base[k][0] != no_r1.get(k, ("?",))[0]]
    rule_diffs = [k for k in base
                  if base[k][1] != no_r1.get(k, ("?", "?"))[1]]
    print(f"     policy files compared: {copied}")
    print(f"     DECISION differs on : {len(dec_diffs)} / {len(inputs)} grid points")
    print(f"     rule LABEL differs on: {len(rule_diffs)} / {len(inputs)} grid points")
    if not dec_diffs and rule_diffs:
        print("     ==> R1 changes ZERO decisions; it only relabels "
              f"{len(rule_diffs)} allows. R1 is a label, not a rule.")


if __name__ == "__main__":
    sys.exit(main())
