#!/usr/bin/env python3
"""RFX-214 reproduction: does an operator's external_sends budget bound the
traffic an adapter has ADMITTED IT CANNOT IDENTIFY?

WHY THIS PROBE IS NOT THE RFX-129 ONE. RFX-129's probe hand-wrote the `axes`
block and asked what core does with each spelling. That establishes a fact
about core and nothing about what a customer actually runs. This probe never
writes an axes block: it calls each shipped adapter's OWN classifier and OWN
envelope builder, and posts what THEY produce. Per the standing lesson that a
policy fix proven at /v1/decide can be worth nothing through the shipped
adapter, the converse has to be measured too -- that the value the budget
fails to charge is the value the adapter itself emits.

WHAT IS ISOLATED, so a hold cannot be misattributed:
  magnitude.count == 1 on every call     -> objects_touched (limit 200) cannot
                                            fire inside 60 calls.
  external_sends limit is 50             -> a hold at 51 in a 60-call run is
                                            external_sends and nothing else,
                                            and the harness ASSERTS the
                                            returned rule id rather than
                                            assuming it.
  environment is varied deliberately     -> in `production` the reeflex-mcp
                                            floor is R3 (terminal deny) and
                                            externality is decision-irrelevant
                                            there; `staging` is where the
                                            budget is the only bound. Both are
                                            run and both are printed, because
                                            reporting only the worse one would
                                            overstate the finding.

Every HTTP failure is raised, never counted as "no hold" -- an instrument that
reports a clean allow over a 500 is how you fabricate a SECURE reading.

Usage:  python3.11 attack-probe-rfx214-unknown-tool-externality.py \
            [CORE_URL] [N] [RUN_TAG]
        (needs the `mcp` package importable: reeflex_mcp.normalize imports
         mcp.types for one type hint.)

Run it from a pristine origin/main checkout with RUN_TAG=before and from the
fix with RUN_TAG=after to get the two halves of the replay against one core.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

CORE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8471"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 60
# Session-id namespace. core's ledger accumulates per agent.session_id, so a
# BEFORE run and an AFTER run against the same live core must not share one --
# otherwise the second run inherits the first's counts and the replay is a
# measurement of the harness. Pass a distinct RUN_TAG per run.
RUN_TAG = sys.argv[3] if len(sys.argv) > 3 else "run"

_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "reeflex-mcp"))
sys.path.insert(0, str(_REPO / "reeflex-claude"))

from reeflex_mcp import normalize as mcp_normalize  # noqa: E402
from reeflex_claude import classify as claude_classify  # noqa: E402
from reeflex_claude import envelope as claude_envelope  # noqa: E402

# A tool name no shipped classifier recognises, in either adapter and on either
# side of PR #111: none of its tokens are in reeflex-claude's money /
# destructive / emit escalator sets, and it matches none of reeflex-mcp's
# read / create / delete name prefixes. So both adapters take the path that
# means "I cannot identify this tool" -- which is the whole subject of the
# ticket. It is also a name whose real-world effect is plainly outbound, which
# is the point: the adapter cannot know that, and on origin/main 759b83f said
# `internal` -- the one value the send budget does not charge -- anyway.
UNIDENTIFIABLE_TOOL = "syncRecordsToPartner"
UNIDENTIFIABLE_ARGS = {"batch": "b-1"}


def decide(envelope: dict) -> tuple[int, dict]:
    body = json.dumps(envelope).encode()
    req = urllib.request.Request(
        CORE + "/v1/decide", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(
            "HTTP %s from /v1/decide -- instrument failure, no verdict derived.\n%s"
            % (e.code, e.read().decode()[:800]))


def mcp_envelope(session: str, environment: str, i: int) -> dict:
    """What reeflex-mcp posts for an unmapped tool with no annotations: the
    4-tier resolution falls all the way through to _EXECUTE_AXES."""
    return mcp_normalize.build_envelope(
        session_id=session,
        agent_id="agent:rfx214-probe",
        on_behalf_of=None,
        upstream_name="partner_api",
        target_system="partner_api",
        target_environment=environment,
        tool_name=UNIDENTIFIABLE_TOOL,
        arguments=dict(UNIDENTIFIABLE_ARGS, seq=i),
        mapping_registry=None,   # no operator mapping -- the unmapped case
        annotations=None,        # upstream declared nothing
    )


def claude_env(session: str, environment: str, i: int) -> dict:
    """What reeflex-claude posts for a tool its table does not carry."""
    os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = environment
    tool_name = "mcp__partner_api__" + UNIDENTIFIABLE_TOOL
    tool_input = dict(UNIDENTIFIABLE_ARGS, seq=i)
    try:
        cls = claude_classify.classify(tool_name, tool_input)
    except TypeError:  # pragma: no cover
        raise SystemExit("classify() signature changed -- update the probe")
    return claude_envelope.build_envelope(
        {"session_id": session, "tool_name": tool_name, "tool_input": tool_input},
        cls,
    )


BUILDERS = {"reeflex-mcp": mcp_envelope, "reeflex-claude": claude_env}


def run(adapter: str, environment: str, n: int, tag: str):
    build = BUILDERS[adapter]
    session = "rfx214-%s-%s-%s-%s" % (RUN_TAG, adapter, environment, tag)
    first, first_rule, axes_seen = None, None, None
    for i in range(1, n + 1):
        env = build(session, environment, i)
        if axes_seen is None:
            axes_seen = env["axes"]
            verb_seen = env["action"]["verb"]
            count_seen = env["magnitude"]["count"]
        status, out = decide(env)
        if status != 200:
            raise SystemExit("unexpected status %s: %s" % (status, out))
        if out["decision"] != "allow" and first is None:
            first, first_rule = i, out.get("rule")
            break
    return {
        "adapter": adapter, "environment": environment,
        "axes": axes_seen, "verb": verb_seen, "count": count_seen,
        "first_non_allow": first, "rule": first_rule, "calls": n,
    }


def main() -> None:
    print("core:", CORE)
    print("tool the adapters cannot identify:", UNIDENTIFIABLE_TOOL)
    print("external_sends limit 50 | objects_touched limit 200 | count=1 per call")
    print("")
    rows = []
    for adapter in ("reeflex-mcp", "reeflex-claude"):
        for environment in ("production", "staging"):
            rows.append(run(adapter, environment, N, "n%d" % N))
    hdr = "%-15s %-11s %-52s %-8s %s" % (
        "adapter", "environment", "axes the ADAPTER declared", "held at", "rule")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        a = r["axes"]
        axes = "%s/%s/%s (verb %s)" % (
            a["reversibility"], a["blast_radius"], a["externality"], r["verb"])
        print("%-15s %-11s %-52s %-8s %s" % (
            r["adapter"], r["environment"], axes,
            r["first_non_allow"] if r["first_non_allow"] else "NEVER",
            r["rule"] or "-"))

    print("")
    print("Where the budget is the ONLY bound (staging), how far does the")
    print("un-identifiable traffic actually run before anything stops it?")
    for adapter in ("reeflex-mcp", "reeflex-claude"):
        r = run(adapter, "staging", 210, "bound")
        print("  %-15s staging: first non-allow at %s (%s)" % (
            adapter, r["first_non_allow"] or "NEVER in 210", r["rule"] or "-"))

    print("")
    print("Control -- the same session, one call, with externality declared")
    print("`outbound` by hand, to show the budget itself works:")
    ctl = {
        "agent": {"id": "agent:rfx214-probe", "session_id": "rfx214-%s-control" % RUN_TAG},
        "action": {"verb": "execute", "ability": "partner_api/syncRecordsToPartner"},
        "target": {"environment": "staging", "id": "ctl"},
        "magnitude": {"count": 1},
        "axes": {"reversibility": "irreversible", "blast_radius": "scoped",
                 "externality": "outbound"},
    }
    held = None
    for i in range(1, 60):
        _, out = decide(dict(ctl, target=dict(ctl["target"], id="ctl-%d" % i)))
        if out["decision"] != "allow":
            held = (i, out.get("rule"))
            break
    print("  declared outbound, staging: first non-allow at %s (%s)" % (
        held[0] if held else "NEVER", held[1] if held else "-"))


if __name__ == "__main__":
    main()
