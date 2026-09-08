#!/usr/bin/env python3
"""
late_approval.py -- the limit this demo would rather not have, measured.

The gateway releases a held call INSIDE ONE REQUEST: it polls the hold for up
to `reeflex_hold_wait` seconds and, on an approval, resubmits the original
envelope. There is no way for a caller to hand an already-approved hold id back
to the gateway on a later request, and core raises a NEW hold on every
`require_approval` decision (`decide.py` validates an approval only when
`approval.present` is on the envelope).

Consequence, measured below rather than argued: an approval granted after the
window has closed CANNOT be spent by a retry. The retry raises a second hold
and the first one sits `approved`, unconsumed, forever.

Why it matters operationally: with the shipped default of 30 seconds, "a human
in an approval inbox" and "the gateway's wait window" are not compatible unless
the operator raises the wait to something a person can answer inside -- which
means holding an HTTP request open for minutes. That is a real trade and the
README states it. This is filed, not hidden.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request

PROXY = "http://127.0.0.1:%s" % os.environ.get(
    "REEFLEX_DEMO_PORT_IMPATIENT", "18703")
CORE = os.environ.get("REEFLEX_CORE_URL", "http://127.0.0.1:18701")
KEY = os.environ["LITELLM_MASTER_KEY"]
GATEWAY_TOKEN = os.environ["GATEWAY_TOKEN"]
APPROVER_TOKEN = os.environ["APPROVER_TOKEN"]
APPROVER = os.environ.get("REEFLEX_DEMO_APPROVER", "alice.approver@acme.example")

SESSION = "late-approval-%d" % time.time()
PROMPT = ('TOOL run_shell {"command": "psql -h prod-db -c '
          '\\"DROP TABLE customers\\""}')


def attempt():
    body = json.dumps({"model": "mock-tools",
                       "messages": [{"role": "user", "content": PROMPT}]})
    req = urllib.request.Request(
        PROXY + "/v1/chat/completions", data=body.encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json",
                                "Authorization": "Bearer " + KEY,
                                "x-reeflex-session": SESSION})
    with urllib.request.urlopen(req, timeout=60) as f:
        doc = json.load(f)
    msg = doc["choices"][0]["message"]
    if msg.get("tool_calls"):
        return None, msg["tool_calls"]
    r = json.loads(msg["content"])["reeflex"]["refused"][0]
    return r["hold_id"], None


def resolve(hold_id):
    body = json.dumps({"decision": "approve",
                       "principal": {"type": "human", "id": APPROVER},
                       "reason": "approved, but after the window had closed"})
    req = urllib.request.Request(
        "%s/v1/holds/%s/resolve" % (CORE, hold_id), data=body.encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json",
                                "Authorization": "Bearer " + APPROVER_TOKEN})
    with urllib.request.urlopen(req, timeout=15) as f:
        return json.load(f)


def read(hold_id):
    req = urllib.request.Request(
        "%s/v1/holds/%s" % (CORE, hold_id),
        headers={"Authorization": "Bearer " + GATEWAY_TOKEN})
    with urllib.request.urlopen(req, timeout=15) as f:
        return json.load(f)


h1, _ = attempt()
print("   1. the agent asks              -> refused, hold %s" % h1)
resolve(h1)
print("   2. a human approves hold %s (too late: the window is closed)"
      % h1[:8])
h2, released = attempt()
if released:
    raise SystemExit(
        "   the retry was RELEASED -- this limit no longer exists and this "
        "script is out of date, which is a good problem. Update it.")
print("   3. the agent retries           -> refused, hold %s" % h2)
print()
if h1 == h2:
    raise SystemExit("   the retry reused the SAME hold; rewrite this script")
print("   The retry raised a DIFFERENT hold. And the approved one:")
h = read(h1)
print("     hold %s  status=%s  decided_by=%s  verified=%s  consumed_ts=%s"
      % (h["id"][:8], h["status"], h.get("decided_by"),
         h.get("decided_by_verified"), h.get("consumed_ts")))
print()
print("   `approved`, `consumed_ts: null`: a real human decision that nothing")
print("   will ever spend. Nothing is released by accident, which is the")
print("   fail-closed half -- but the human's answer is lost, and the agent is")
print("   back at the start of the queue.")
