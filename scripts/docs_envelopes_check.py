#!/usr/bin/env python3.12
"""Every verdict printed in docs/use-cases/ must be the verdict core gives.

The use-case pages print Action Envelopes with the verdict and rule id the base
pack returns for them. A page that says `deny` over an envelope core allows is
not documentation, it is marketing -- and nothing else in the repository reads
those pages, so nothing else would notice. This script reads them.

WHAT IT EXTRACTS. A marker line, then the first ```json block after it:

    **Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

    ```json
    { ...envelope... }
    ```

Optional parts of the marker line:

    · **call** 11            the verdict is the one call 11 of the session gets.
                             Calls 1..10 are the SAME envelope, decided first in
                             the same session, and each of them must be `allow`
                             (the page has to say so; the script checks it).
    · **reason contains** `physical_writes`
                             a substring the decision's reason must carry.

WHAT IT RUNS. Not a transcription of the rules: `app.decide.process` from the
core tree named by --core-tree -- the function behind POST /v1/decide minus the
HTTP layer. That is envelope.py's normalisation (verb canon, environment enum,
axis coercion, provenance), the session ledger, and the pack evaluated by
forking `opa eval` over <core-tree>/reeflex-core/policy. Each block runs in its
own interpreter with its own empty holds / audit / ledger files, so blocks
cannot leak budget into each other.

WHAT IT CANNOT SEE, said out loud:
  * the HTTP layer (auth, the gate credential, body limits) -- those refuse,
    they cannot turn one verdict into another;
  * any deployed instance -- this is the pack in the tree you point it at;
  * any adapter -- the envelope is the page's, not one an adapter built. Each
    page says which adapter emits the shape; whether it emits THAT envelope
    for THAT raw action is the adapter's own conformance suite's question;
  * the approval path (approval.present is forced false by core, as in prod).

PENDING-CORE. The physical-impact rules (R8-R11, the physical budgets;
PHYSICAL-IMPACT-SPEC draft 2026-10-13) are being added to core in parallel. A
block whose envelope uses any of that spec's additions -- externality
`physical`, a verb in {set, mode, override, actuate, flash},
`target.safety_function`, `magnitude.physical` -- is reported `PENDING-CORE`
when the core tree does not carry them yet, with what that tree answers today
printed beside it. It is not counted as a pass.

EXIT: 0 every block checked and matched · 1 at least one mismatch or error ·
3 every checked block matched but some are PENDING-CORE (not green) ·
2 usage / nothing found.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

MARKER = re.compile(
    r"^\*\*Verdict:\*\*\s*`(?P<decision>allow|deny|require_approval)`"
    r"\s*·\s*\*\*rule\*\*\s*`(?P<rule>[^`]+)`(?P<rest>.*)$",
    re.IGNORECASE,
)
LOOSE_MARKER = re.compile(r"verdict:", re.IGNORECASE)
CALL = re.compile(r"\*\*call\*\*\s*(\d+)")
REASON = re.compile(r"\*\*reason contains\*\*\s*`([^`]+)`")
FENCE_OPEN = re.compile(r"^\s*```json\s*$")
FENCE_CLOSE = re.compile(r"^\s*```\s*$")

PHYSICAL_VERBS = {"set", "mode", "override", "actuate", "flash"}


def needs_physical_core(env: dict) -> bool:
    action = env.get("action") or {}
    target = env.get("target") or {}
    axes = env.get("axes") or {}
    magnitude = env.get("magnitude") or {}
    return (
        axes.get("externality") == "physical"
        or str(action.get("verb", "")).lower() in PHYSICAL_VERBS
        or "safety_function" in target
        or "physical" in magnitude
    )


def core_has_physical(core_tree: pathlib.Path) -> bool:
    """Does this core tree carry the physical-impact spec? Read from the pack
    AND the normaliser: rules that read `override` are unreachable if
    envelope.py still canonicalises `override` to another verb."""
    pol = core_tree / "reeflex-core" / "policy"
    rego = "".join(p.read_text() for p in pol.glob("*.rego") if not p.name.endswith("_test.rego"))
    env_py = (core_tree / "reeflex-core" / "app" / "envelope.py").read_text()
    return "safety_function" in rego and '"override"' in env_py


def _shown(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:  # a page outside the repo, e.g. a copy under /tmp
        return str(path)


def extract(path: pathlib.Path) -> tuple[list[dict], list[str]]:
    """Return (blocks, problems). A line that says "verdict:" but does not
    parse is a problem, not a skip -- otherwise a typo in the marker silently
    removes a block from the check."""
    lines = path.read_text().splitlines()
    blocks, problems = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = MARKER.match(line.strip())
        if not m:
            if LOOSE_MARKER.search(line) and line.strip().startswith("**Verdict"):
                problems.append(f"{path}:{i + 1}: unparseable verdict marker: {line.strip()}")
            i += 1
            continue
        rest = m.group("rest")
        call = int(CALL.search(rest).group(1)) if CALL.search(rest) else 1
        reason = REASON.search(rest).group(1) if REASON.search(rest) else None
        j = i + 1
        while j < len(lines) and not FENCE_OPEN.match(lines[j]):
            if MARKER.match(lines[j].strip()) or lines[j].startswith("#"):
                break
            j += 1
        if j >= len(lines) or not FENCE_OPEN.match(lines[j]):
            problems.append(f"{path}:{i + 1}: verdict marker with no ```json block after it")
            i += 1
            continue
        k = j + 1
        while k < len(lines) and not FENCE_CLOSE.match(lines[k]):
            k += 1
        body = "\n".join(lines[j + 1:k])
        try:
            env = json.loads(body)
        except json.JSONDecodeError as exc:
            problems.append(f"{path}:{j + 2}: envelope is not valid JSON: {exc}")
            i = k + 1
            continue
        blocks.append({
            "where": f"{_shown(path)}:{j + 2}",
            "decision": m.group("decision"),
            "rule": m.group("rule"),
            "call": call,
            "reason": reason,
            "envelope": env,
        })
        i = k + 1
    return blocks, problems


# Runs inside a fresh python3.12 per block, with the core tree on sys.path and
# empty state files in the environment. Prints one JSON line per call.
_CHILD = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from app.decide import process
env = json.loads(sys.stdin.read())
calls = int(sys.argv[2])
for n in range(1, calls + 1):
    status, resp = process(json.loads(json.dumps(env)))
    print(json.dumps({"call": n, "status": status, "decision": resp.get("decision"),
                      "rule": resp.get("rule"), "reason": resp.get("reason")}))
"""


def decide(core_tree: pathlib.Path, env: dict, calls: int, python: str, opa: str) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="docs-envelopes-") as tmp:
        child_env = dict(os.environ)
        child_env.update({
            "REEFLEX_OPA_BIN": opa,
            "REEFLEX_POLICY_DIR": str(core_tree / "reeflex-core" / "policy"),
            "REEFLEX_HOLDS_PATH": os.path.join(tmp, "holds.jsonl"),
            "REEFLEX_AUDIT_LOG": os.path.join(tmp, "audit.jsonl"),
            "REEFLEX_LEDGER_PATH": os.path.join(tmp, "ledger.jsonl"),
        })
        for k in ("REEFLEX_WEBHOOK_URL", "REEFLEX_SIEM_URL", "REEFLEX_FREEZE_PATH"):
            child_env.pop(k, None)
        out = subprocess.run(
            [python, "-c", _CHILD, str(core_tree / "reeflex-core"), str(calls)],
            input=json.dumps(env), capture_output=True, text=True, env=child_env, timeout=600,
        )
        rows = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
        if out.returncode != 0 or len(rows) != calls:
            raise RuntimeError(f"core child failed (rc={out.returncode}): {out.stderr.strip()[-800:]}")
        return rows


def check(block: dict, rows: list[dict]) -> list[str]:
    errs = []
    for r in rows[:-1]:
        if r["decision"] != "allow":
            errs.append(f"call {r['call']} of {block['call']} was {r['decision']} "
                        f"({r['rule']}); the page says the earlier calls are allowed")
            break
    last = rows[-1]
    if last["status"] != 200:
        errs.append(f"HTTP-equivalent status {last['status']}: {last['reason']}")
    if last["decision"] != block["decision"]:
        errs.append(f"decision: page says {block['decision']}, core says {last['decision']}")
    if last["rule"] != block["rule"]:
        errs.append(f"rule: page says {block['rule']}, core says {last['rule']}")
    if block["reason"] and block["reason"] not in (last["reason"] or ""):
        errs.append(f"reason: page says it contains {block['reason']!r}, core says {last['reason']!r}")
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--core-tree", default=str(REPO),
                    help="a checkout whose reeflex-core/ decides (default: this repo)")
    ap.add_argument("--pages", default=str(REPO / "docs" / "use-cases" / "*.md"))
    ap.add_argument("--python", default=shutil.which("python3.12") or sys.executable)
    ap.add_argument("--opa", default=os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa") or "opa")
    args = ap.parse_args(argv)

    core_tree = pathlib.Path(args.core_tree).resolve()
    if not (core_tree / "reeflex-core" / "app" / "decide.py").is_file():
        print(f"not a core tree: {core_tree}", file=sys.stderr)
        return 2
    physical = core_has_physical(core_tree)
    rev = subprocess.run(["git", "-C", str(core_tree), "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True).stdout.strip() or "?"
    print(f"core tree: {core_tree} @ {rev} · physical-impact rules present: {'yes' if physical else 'NO'}")
    print(f"opa: {args.opa} · python: {args.python}")

    pages = sorted(pathlib.Path(p) for p in glob.glob(args.pages))
    blocks, problems = [], []
    for p in pages:
        b, pr = extract(p.resolve())
        blocks += b
        problems += pr
    if not blocks and not problems:
        print(f"no verdict-marked envelopes under {args.pages}", file=sys.stderr)
        return 2

    ok = bad = pending = 0
    for msg in problems:
        print(f"FAIL     {msg}")
        bad += 1
    for b in blocks:
        label = f"{b['where']:<46} {b['decision']:<16} {b['rule']}" + (
            f" (call {b['call']})" if b["call"] > 1 else "")
        try:
            rows = decide(core_tree, b["envelope"], b["call"], args.python, args.opa)
        except Exception as exc:  # the instrument failing is a failure, never a pass
            print(f"FAIL     {label}\n         instrument error: {exc}")
            bad += 1
            continue
        if needs_physical_core(b["envelope"]) and not physical:
            last = rows[-1]
            print(f"PENDING  {label}\n         core {rev} today: {last['decision']} {last['rule']}")
            pending += 1
            continue
        errs = check(b, rows)
        if errs:
            print(f"FAIL     {label}")
            for e in errs:
                print(f"         {e}")
            bad += 1
        else:
            print(f"ok       {label}")
            ok += 1

    print(f"\n{len(blocks)} envelopes in {len(pages)} pages: {ok} matched, "
          f"{bad} failed, {pending} PENDING-CORE")
    if bad:
        return 1
    if pending:
        print("NOT GREEN: PENDING-CORE blocks were not checked against the rules they cite. "
              "Re-run with --core-tree at a tree that carries the physical-impact spec.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
