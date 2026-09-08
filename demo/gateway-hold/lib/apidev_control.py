#!/usr/bin/env python3
"""
apidev_control.py -- the control that stops the walk being about my container.

Every verdict in this demo comes from a reeflex-core the walk started itself.
That is the right way to run it -- it needs a `REEFLEX_RESOLVER_TOKENS` binding
to complete an approval, and a shared evaluation endpoint cannot hand a demo
runner one -- but it means the verdicts could in principle be a property of
that container rather than of the policy.

So: the three decisive envelopes are re-decided against
`api-dev.reeflex.io`, the shared Reeflex evaluation core, with the published
public eval token. It runs the SAME published image
(`ghcr.io/reeflex-io/reeflex-core@sha256:58a0a531…845b` -- compared by
`RepoDigests` on both hosts) and it is not configured by this walk in any way.

WHY THE APPROVAL LEG IS NOT RUN THERE, measured 2026-09-08 by inspecting the
deployed container: `REEFLEX_REQUIRE_VERIFIED_APPROVER=true`, no
`REEFLEX_RESOLVER_TOKENS`, no config mount. On core 0.2.0 that means EVERY
`POST /v1/holds/{id}/resolve` on api-dev is `403 principal_not_verified` -- for
anyone. Not a defect: a shared evaluation endpoint has no business holding a
credential bound to a named human. It does mean steps 4 and 5 cannot be walked
there, and this file says so rather than quietly using a different core for
those steps and calling the whole thing "verified on api-dev".

Each envelope gets a FRESH nonce and a FRESH session: core's replay guard is a
hard 400 on a repeated nonce, and R5's cumulative budget is charged per
session, so reusing either turns the second reading into a different
measurement. Calls are paced -- this endpoint rate-limits.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

LOCAL = os.environ.get("REEFLEX_CORE_URL", "http://127.0.0.1:18701")
LOCAL_TOKEN = os.environ["GATEWAY_TOKEN"]
DEV = os.environ.get("RFX_DEMO_APIDEV", "https://api-dev.reeflex.io")
DEV_TOKEN = os.environ.get("RFX_DEMO_APIDEV_TOKEN", "reeflex-eval-public-2026")

AXES = {"reversibility": "irreversible", "blast_radius": "broad",
        "externality": "internal"}


def envelope(axes):
    return {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:litellm-gateway/acme-payments/mock-tools",
                  "on_behalf_of": "payments-oncall@acme.example",
                  "session_id": "ctrl-%s" % os.urandom(6).hex()},
        "action": {"namespace": "litellm-gateway", "verb": "delete",
                   "ability": "litellm/run_shell"},
        "target": {"kind": "resource", "environment": "production"},
        "params": {"tool_name": "Bash", "gateway": "litellm",
                   "gateway_tool": "run_shell"},
        "magnitude": {"count": 1}, "axes": axes,
        "approval": {"present": False},
        "meta": {"timestamp": "2026-09-08T00:00:00Z",
                 "nonce": os.urandom(16).hex()},
    }


def decide(base, token, env):
    req = urllib.request.Request(
        base + "/v1/decide", data=json.dumps(env).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json",
                                "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=25) as f:
            body = json.load(f)
        return body["decision"], body["rule"].split("/")[-1]
    except urllib.error.HTTPError as exc:
        return "HTTP %d" % exc.code, (exc.read()[:60].decode("utf-8", "replace"))
    except Exception as exc:
        return "unreachable", type(exc).__name__


ROWS = [
    ("irreversible / broad / production", dict(AXES)),
    ("irreversible / systemic / production",
     dict(AXES, blast_radius="systemic")),
    ("axes.reversibility OMITTED (R0)",
     {k: v for k, v in AXES.items() if k != "reversibility"}),
]

print("\n   %-38s %-34s %s" % ("envelope", "this walk's core", "api-dev (shared)"))
print("   " + "-" * 108)
agree = True
for label, axes in ROWS:
    a = decide(LOCAL, LOCAL_TOKEN, envelope(axes))
    time.sleep(0.8)
    b = decide(DEV, DEV_TOKEN, envelope(axes))
    time.sleep(0.8)
    print("   %-38s %-34s %s" % (label, "%s %s" % a, "%s %s" % b))
    if a != b:
        agree = False

print()
if agree:
    print("   Identical on every row. No verdict in this demo is an artefact")
    print("   of the container the walk started.")
else:
    print("   THE TWO CORES DISAGREE. Read the rows above before believing")
    print("   anything else in this transcript: either api-dev is not running")
    print("   the digest this walk pins, or the local core is misconfigured.")

print()
print("   Not run on api-dev, and why: it has REEFLEX_REQUIRE_VERIFIED_APPROVER")
print("   =true with no REEFLEX_RESOLVER_TOKENS, so no hold there can be")
print("   resolved by anybody. Steps 4 and 5 need a core whose operator has")
print("   bound a credential to a named human.")
