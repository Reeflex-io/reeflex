#!/usr/bin/env python3
"""
relay.py -- carry a human's decision from the approval inbox to reeflex-core.

    python3 lib/relay.py --hold-id HEX --timeout 120

WHY THIS FILE EXISTS AT ALL, AND WHY IT IS IN demo/ RATHER THAN IN A PACKAGE
============================================================================
The hold lives in TWO places and they are two products:

  * reeflex-core holds it. Core is the authority: nothing is released until
    core says `allow`, and core's eight resubmission checks are what make an
    approval unspendable by the wrong actor.
  * reeflex-app SHOWS it. That is where a person can see it and decide.

Something has to carry the decision from the second to the first. In the
product that something is `reeflex_connector` (the holds gate), which polls
`GET /api/v1/holds/resolutions` -- DIR-2 of CONTRACT holds-v1 -- and calls
core's resolve route.

**On reeflex-core 0.2.0 the shipped connector cannot do it.** Measured
independently (dev-1 round 058, ticket RFX-229) and re-measured here: the
connector authenticates with core's single shared `REEFLEX_AUTH_TOKEN`, which
cannot be bound to N approvers in `REEFLEX_RESOLVER_TOKENS`, and it relays the
app's `decided_by.id`, which is an internal per-user UUID rather than the
identity a resolver credential is bound to. Both produce `403` on the resolve
call, the hold stays pending, and the agent's resubmission is
`deny reeflex_hold_not_approved`. The app then tells the truth about it -- the
hold reads `resolution_failed` and an Attest report raises
`ART14_RESOLUTION_REFUSED_BY_CORE`.

So this relay is roughly sixty lines of the connector, with the two RFX-229
causes configured around rather than papered over, and it is in `demo/`
precisely so that nobody reads it as a shipped component:

  1. it presents THE APPROVER'S OWN credential, not the gateway's, so core can
     verify the principal from the credential (`REEFLEX_REQUIRE_VERIFIED_
     APPROVER` is left at its shipped default, `true`);
  2. it is configured with an explicit `decided_by.id -> core principal` map,
     because the app's DIR-2 feed emits the UUID and core requires a
     body-asserted principal that MATCHES the credential's binding. Measured
     on the same core, 2026-09-08: a resolve with no `principal` at all, with
     only `type`, or with only `id`, is `400 invalid_request` -- so a relay
     cannot simply decline to assert an identity and let the credential
     speak.

A relay that cannot map a `decided_by.id` REFUSES TO RELAY IT. It does not
guess, and it does not fall back to a default approver: inventing an approver
is the exact defect `REEFLEX_RESOLVER_TOKENS` exists to close.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

APP = os.environ.get("RFX_DEMO_APP_BASE", "https://app.reeflex.io")
CORE = os.environ.get("REEFLEX_CORE_URL", "http://127.0.0.1:18701")
GATE_TOKEN = os.environ.get("RFX_DEMO_GATE_TOKEN", "")
APPROVER_TOKEN = os.environ.get("APPROVER_TOKEN", "")

# decided_by.id (what the app sends) -> the core principal that credential IS.
# In a real deployment this is one line per approver in the relay's config, or
# it disappears entirely once RFX-229 makes the app send the email it already
# has (`identity.user.email`).
APPROVER_MAP = json.loads(os.environ.get("RFX_DEMO_APPROVER_MAP", "{}"))


def log(msg):
    print("[relay] %s" % msg, flush=True)


def _get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer %s" % token})
    with urllib.request.urlopen(req, timeout=15) as f:
        return json.load(f)


def _post(url, body, token):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer %s" % token})
    try:
        with urllib.request.urlopen(req, timeout=15) as f:
            return f.status, json.load(f)
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b"{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw[:200].decode("utf-8", "replace")}


def resolutions():
    """DIR-2. A BARE JSON ARRAY -- not an object envelope. That shape is
    LOCKED by CONTRACT holds-v1, and it was once shipped wrapped, which the
    gate rejected outright, so no human decision could ever be applied."""
    out = _get(APP + "/api/v1/holds/resolutions", GATE_TOKEN)
    if not isinstance(out, list):
        raise SystemExit("DIR-2 returned %s, not an array -- contract holds-v1 "
                         "says array" % type(out).__name__)
    return out


def relay_one(res):
    hold_id = res["hold_id"]
    decision = res["decision"]           # approve | deny | expired
    decided_by = (res.get("decided_by") or {})
    who = decided_by.get("id") or ""
    if decision == "expired":
        log("hold %s expired in the app; core applies its own TTL, nothing to "
            "relay" % hold_id[:8])
        return None
    principal_id = APPROVER_MAP.get(who)
    if not principal_id:
        log("REFUSING to relay hold %s: the app says it was decided by %r and "
            "this relay has no core principal mapped to that id. It will NOT "
            "guess an approver. (This is RFX-229: the app has the approver's "
            "email and sends an internal UUID.)" % (hold_id[:8], who))
        return None
    body = {"decision": "approve" if decision == "approve" else "reject",
            "principal": {"type": decided_by.get("type") or "human",
                          "id": principal_id},
            "reason": res.get("reason") or "relayed from the approval inbox"}
    status, out = _post("%s/v1/holds/%s/resolve" % (CORE, hold_id), body,
                        APPROVER_TOKEN)
    if status == 200:
        log("core accepted the %s of hold %s as %s "
            "(decided_by_verified=%s)"
            % (decision, hold_id[:8], principal_id,
               out.get("decided_by_verified")))
    else:
        log("core REFUSED the resolve of %s: HTTP %s %s -- the hold stays "
            "pending and the agent stays blocked, which is the correct "
            "outcome of a relay that cannot prove who approved"
            % (hold_id[:8], status, out.get("error") or out))
    return status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold-id", help="stop as soon as THIS hold is relayed")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--poll", type=float, default=2.0)
    args = ap.parse_args()
    if not GATE_TOKEN:
        raise SystemExit("RFX_DEMO_GATE_TOKEN is not set -- the relay reads the "
                         "app's resolution feed with the gate credential")
    if not APPROVER_TOKEN:
        raise SystemExit("APPROVER_TOKEN is not set -- the relay must present "
                         "the APPROVER's credential to core, never the "
                         "gateway's")
    seen = set()
    # PRIME THE CURSOR. A real connector persists one; this relay takes the
    # cheap equivalent -- the first poll records what is already there and
    # relays none of it. Without this, a relay started after an earlier
    # approval immediately re-resolves a hold core has already consumed and
    # reports `409 not_resolvable`, which reads exactly like a failure of the
    # decision it was actually started to carry. That happened on the first
    # live run of this walk.
    try:
        for res in resolutions():
            seen.add((res["hold_id"], res.get("resolved_ts")))
        if seen:
            log("cursor primed past %d resolution(s) that predate this run"
                % len(seen))
    except Exception as exc:
        log("could not prime the cursor (%s: %s); every resolution will look "
            "new" % (type(exc).__name__, exc))

    deadline = time.monotonic() + args.timeout
    log("watching %s/api/v1/holds/resolutions for a human decision" % APP)
    while time.monotonic() < deadline:
        try:
            for res in resolutions():
                key = (res["hold_id"], res.get("resolved_ts"))
                if key in seen:
                    continue
                seen.add(key)
                log("the app reports: hold %s -> %s"
                    % (res["hold_id"][:8], res["decision"]))
                relay_one(res)
                if args.hold_id and res["hold_id"] == args.hold_id:
                    return
        except Exception as exc:   # a poll failure is not a decision
            log("poll failed (%s: %s); retrying" % (type(exc).__name__, exc))
        time.sleep(args.poll)
    log("no decision arrived within %.0fs" % args.timeout)


if __name__ == "__main__":
    main()
