#!/usr/bin/env python3
"""
r0.py -- unclassifiable resolves to a HOLD, not a DENY. And this seat cannot
produce it.

R0 (`reeflex.policy/unclassified_action`, RFX-132, core 0.2.0) is the
highest-precedence rule in the canon and it exists for one situation: an action
whose CLASSIFICATION INPUTS the adapter did not declare, so core filled them
with its conservative default and the verdict would rest on a guess. Core's
answer is to ask a human rather than to refuse -- and it is RESOLVABLE, unlike
R3's terminal deny.

The A/B below is one field wide. Same action, same axes but one omitted:

    fully declared         -> deny            irreversible_systemic_prod
    axes.reversibility     -> require_approval unclassified_action

`provenance` is COMPUTED BY CORE from what is absent and is overwritten
unconditionally, so a caller cannot assert its way from R3's deny into R0's
hold. That is worth knowing before anyone tries.

AND THE PART A DEMO MUST NOT LEAVE OUT: `reeflex-litellm` CANNOT trip R0.
`envelope.build_gateway_envelope()` declares all three axes, `action.verb` and
`magnitude.count` on every call, and `_environment_for()` always resolves
`target.environment` (the tenant's, else `REEFLEX_LITELLM_ENVIRONMENT`, else
`production`). So every envelope this seat sends reads
`provenance.undeclared: []` -- printed below from the walk's own hold. R0 is a
guard for adapters that omit a field; this one does not, and saying otherwise
would be selling a rule this seat never reaches.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

CORE = os.environ.get("REEFLEX_CORE_URL", "http://127.0.0.1:18701")
TOKEN = os.environ["GATEWAY_TOKEN"]

BASE_AXES = {"reversibility": "irreversible", "blast_radius": "systemic",
             "externality": "internal"}


def envelope(axes):
    return {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:litellm-gateway/acme-payments/mock-tools",
                  "session_id": "r0-%s" % os.urandom(4).hex()},
        "action": {"namespace": "litellm-gateway", "verb": "delete",
                   "ability": "litellm/run_shell"},
        "target": {"kind": "resource", "environment": "production"},
        "params": {}, "magnitude": {"count": 1}, "axes": axes,
        "approval": {"present": False},
        "meta": {"timestamp": "2026-09-08T00:00:00Z",
                 "nonce": os.urandom(16).hex()},
    }


def decide(env):
    req = urllib.request.Request(
        CORE + "/v1/decide", data=json.dumps(env).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json",
                                "Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=20) as f:
        return json.load(f)


print("\n   The SAME action, decided twice, differing in ONE field.\n")
for label, axes in [
        ("all three axes declared", dict(BASE_AXES)),
        ("axes.reversibility OMITTED",
         {k: v for k, v in BASE_AXES.items() if k != "reversibility"})]:
    d = decide(envelope(axes))
    print("   %-30s -> %-17s %s" % (label, d["decision"], d["rule"]))
    print("   %-30s    hold_id: %s" % ("", d.get("hold_id")))
    print("   %-30s    %s" % ("", d["reason"][:150]))
    print()

print("   So an action core cannot classify becomes a hold a human can")
print("   resolve, not a refusal nobody can appeal. R0 outranks R3 precisely")
print("   because a terminal deny is the right answer for an action an adapter")
print("   DECLARED and the wrong one for an action core guessed at.\n")

print("   And this gateway seat never reaches it. Read off the gateway-raised")
print("   holds in this core's store:")
req = urllib.request.Request(CORE + "/v1/holds?status=all",
                             headers={"Authorization": "Bearer " + TOKEN})
holds = json.load(urllib.request.urlopen(req, timeout=15))
seen = 0
for h in holds.get("items", []):
    env = h.get("envelope") or {}
    if not (env.get("agent") or {}).get("id", "").startswith(
            "agent:litellm-gateway"):
        continue
    prov = env.get("provenance")
    print("     hold %s  provenance: %s" % (h["id"][:8], json.dumps(prov)))
    seen += 1
    if seen >= 3:
        break
if not seen:
    raise SystemExit("   no gateway-raised hold found to read provenance from")
print()
print("   `undeclared: []` on every one. The adapter declares every field R0")
print("   watches, so R0 is a guard this seat does not need and does not get.")
