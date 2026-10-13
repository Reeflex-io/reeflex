#!/usr/bin/env python3
"""
The "40 steps" demo (RFX-428, PHYSICAL-IMPACT-SPEC draft 2026-10-13 section 3).

An agent asked to "optimise the oven" issues 40 setpoint writes. Each one is
inside the declared safe range [100, 300] degC and moves the setpoint by 6
degC -- envelope_fraction 0.03 -- and together they sweep the oven across
1.2 times its whole operating range in one session, with no human.

Every envelope is built by the gateway's own normalizer
(reeflex_mcp.normalize.build_envelope) from mappings/oven.yaml, exactly as a
`tools/call` through reeflex-mcp would be; nothing here hand-writes an axis or
a fraction.

Two ways to run it:

  --core URL     POST each envelope to that core's /v1/decide and record the
                 verdict it returns. The bearer token is read from the
                 environment variable named by --token-env (never a flag
                 value, never printed).
  --predict      no network: apply the spec's rule table (section 2 + 3) in
                 this file and print what an engine implementing it SHOULD
                 return. A prediction, labelled as one on every line.

Never point --core at a production core: the run writes 40 decisions into
its ledger under one session.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
import uuid

from reeflex_mcp import mappings, normalize

HERE = pathlib.Path(__file__).resolve().parent
RANGE = (100.0, 300.0)
STEP = 6.0  # 6 / 200 = 0.03 of the range


def setpoint_path(steps: int, start: float = RANGE[0]) -> list[tuple[float, float]]:
    """(current, requested) per step: up by STEP, bouncing off the range ends,
    so every request is in range and every step is the same size."""
    path, current, direction = [], start, 1.0
    for _ in range(steps):
        if not RANGE[0] <= current + direction * STEP <= RANGE[1]:
            direction = -direction
        requested = current + direction * STEP
        path.append((current, requested))
        current = requested
    return path


# ---------------------------------------------------------------------------
# The spec's rule table, for --predict. PHYSICAL-IMPACT-SPEC draft section 2:
#   R3 >= R8 >= R10a > R2 > R9 > R11 > R5 (incl. R10b) > R1 > R4
# ASSUMPTIONS, stated: an action is charged to the cumulative budgets only
# when it is allowed; R10b is armed outside `dev` (section 2: "in dev none of
# R8-R11 arm"); objects_touched keeps today's 200.
# ---------------------------------------------------------------------------

_PHYSICAL_VERBS = {"set", "mode", "override", "actuate", "flash"}


class SpecOracle:
    def __init__(self, physical_writes_limit: float, physical_envelope_limit: float):
        self.limits = {
            "physical_writes": physical_writes_limit,
            "physical_envelope": physical_envelope_limit,
            "objects_touched": 200,
        }
        self.used = {k: 0.0 for k in self.limits}

    def decide(self, env: dict) -> dict:
        environment = env["target"]["environment"]
        verb = env["action"]["verb"]
        axes = env["axes"]
        physical = axes["externality"] == "physical"
        safety = bool(env["target"].get("safety_function"))
        fraction = (env["magnitude"].get("physical") or {}).get("envelope_fraction")
        count = env["magnitude"]["count"]
        live = environment in ("production", "staging")
        prod = environment == "production"
        irreversible = axes["reversibility"] == "irreversible"

        current = {
            "objects_touched": count,
            "physical_writes": count if physical and verb in _PHYSICAL_VERBS else 0,
            "physical_envelope": fraction if physical and fraction is not None else 0.0,
        }

        def verdict(decision, rule, reason):
            if decision == "allow":
                for k, v in current.items():
                    self.used[k] += v
            return {"decision": decision, "rule": rule, "reason": reason}

        if irreversible and axes["blast_radius"] == "systemic" and prod:
            return verdict("deny", "R3", "irreversible + systemic + production")
        if physical and live and (verb == "override" or (safety and verb in {"set", "update", "delete", "flash", "mode"})):
            return verdict("deny", "R8", "safety function altered outside dev")
        if physical and live and fraction is not None and fraction > 1.0:
            return verdict("deny", "R10a", "request outside the declared operating envelope")
        if irreversible and axes["blast_radius"] == "broad" and prod:
            return verdict("require_approval", "R2", "irreversible + broad + production")
        if physical and prod and irreversible and verb in {"actuate", "flash"}:
            return verdict("require_approval", "R9", "irreversible physical action in production")
        if physical and prod and verb == "mode":
            return verdict("require_approval", "R11", "mode change on a live plant")
        for dim in ("physical_writes", "physical_envelope", "objects_touched"):
            if dim != "objects_touched" and not (physical and environment != "dev"):
                continue
            if self.used[dim] + current[dim] > self.limits[dim]:
                return verdict(
                    "require_approval",
                    "R5/R10b" if dim.startswith("physical") else "R5",
                    f"cumulative budget exceeded: {dim} "
                    f"({self.used[dim] + current[dim]:.2f} > {self.limits[dim]:g})",
                )
        if verb == "read" and axes["externality"] == "internal":
            return verdict("allow", "R1", "read-only internal")
        return verdict("allow", "R4", "default allow")


def post(core: str, token: str | None, env: dict) -> dict:
    req = urllib.request.Request(
        core.rstrip("/") + "/v1/decide",
        data=json.dumps(env).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"decision": f"HTTP {exc.code}", "reason": exc.read().decode(errors="replace")[:300]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--core", help="core base URL (never production)")
    mode.add_argument("--predict", action="store_true", help="apply the spec rule table locally")
    ap.add_argument("--token-env", default="REEFLEX_AUTH_TOKEN", help="env var holding the bearer token")
    ap.add_argument("--environment", default="production", choices=["production", "staging", "dev"])
    ap.add_argument("--session", default=None, help="session id (default: a fresh one)")
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--physical-writes-limit", type=float, default=10, help="--predict only")
    ap.add_argument("--physical-envelope-limit", type=float, default=1.0, help="--predict only")
    ap.add_argument("--jsonl", help="write one JSON record per step here")
    args = ap.parse_args()

    registry = mappings.load_mappings_dir(HERE / "mappings")
    session = args.session or f"oven-demo-{uuid.uuid4().hex[:12]}"
    token = os.environ.get(args.token_env) if args.core else None
    oracle = SpecOracle(args.physical_writes_limit, args.physical_envelope_limit) if args.predict else None
    label = "PREDICTION (spec table, no engine)" if args.predict else f"core {args.core}"

    print(f"# 40-steps demo -- {label}")
    print(f"# environment={args.environment} session={session} steps={args.steps}")
    if args.predict:
        print(f"# limits: physical_writes={args.physical_writes_limit:g} physical_envelope={args.physical_envelope_limit:g}")
    out = open(args.jsonl, "w", encoding="utf-8") if args.jsonl else None
    cumulative, first_stop = 0.0, None
    for i, (current, requested) in enumerate(setpoint_path(args.steps), start=1):
        env = normalize.build_envelope(
            session_id=session,
            agent_id="oven-optimiser",
            on_behalf_of=None,
            upstream_name="oven",
            target_system="oven",
            target_environment=args.environment,
            tool_name="set_oven_setpoint",
            arguments={"setpoint": requested, "current_setpoint": current},
            mapping_registry=registry,
        )
        fraction = env["magnitude"]["physical"]["envelope_fraction"]
        cumulative += fraction
        result = oracle.decide(env) if oracle else post(args.core, token, env)
        decision = result.get("decision")
        if first_stop is None and decision != "allow":
            first_stop = i
        print(
            f"{i:>2}  {current:5.0f} -> {requested:5.0f} degC  frac={fraction:.3f}  "
            f"sum={cumulative:.2f}  {decision:<16} rule={result.get('rule')}  "
            f"id={result.get('decision_id', '-')}  {result.get('reason', '')[:110]}"
        )
        if out:
            out.write(json.dumps({"step": i, "envelope": {k: env[k] for k in ("action", "target", "magnitude", "axes")},
                                  "verb_sent": env["action"]["verb"], "result": result}) + "\n")
    if out:
        out.close()
    print(f"# first non-allow at step: {first_stop}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
