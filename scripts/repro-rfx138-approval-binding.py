#!/usr/bin/env python3
"""
repro-rfx138-approval-binding.py — is a human's approval bound to the AGENT it
was granted for, or only to the action?

WHAT THIS ANSWERS
=================
RFX-138. Run it against any tree and it prints, per variant, whether an
approval a human granted to one agent can be spent by another. It runs
reeflex-core FROM SOURCE on a loopback port with its own policy dir, hold
store, ledger and audit log, drives the REAL HTTP wire (/v1/decide and
/v1/holds/{id}/resolve), and tears the server down. Nothing is sent anywhere;
there is no network, no api-dev, no production.

    python3 scripts/repro-rfx138-approval-binding.py reeflex-core
    python3 scripts/repro-rfx138-approval-binding.py /tmp/main/reeflex-core "main 44c6f85"

MEASURED, on origin/main 44c6f85 (the "before"):

    A3 BETA spends it      -> allow  reeflex.policy/approved_resubmission
    A4 ALPHA (the approved
       agent) then tries   -> deny   reeflex_hold_consumed
    B3 SAME bot FOR bob    -> allow  reeflex.policy/approved_resubmission
    RFX-138 REPRODUCES: YES

and after the fix, on the same harness, byte-for-byte the same inputs:

    A3 BETA spends it      -> deny   reeflex_hold_actor_substituted
    A4 ALPHA               -> allow  (the approval it was granted, restored)
    B3 SAME bot FOR bob    -> deny   reeflex_hold_actor_substituted
    RFX-138 REPRODUCES: NO

WHY VARIANT C (the control) IS NOT OPTIONAL
===========================================
Variant A's evasion and variant C's legitimate resubmission differ by ONE
STRING. A build that denied every resubmission — a stricter hash, a hold store
that lost the envelope, a broken adapter contract — would make A and B "pass"
while the product no longer works. C asserts the agent the human DID approve
still gets its allow, so a deny-everything change cannot read as a fix.

The audit dump at the end is the other half of the finding: on the
on_behalf_of variant, core's own audit lines for the ORIGINAL and the
SUBSTITUTED call are byte-identical (same agent_id, same session_id, same
envelope_hash), and on_behalf_of is absent from the record entirely — it is in
the SIEM/CEF event (telemetry.py) but not in the append-only stream the
evidence connector tails. So "a different principal executed this" was
undetectable after the fact, in both directions.
"""

import json, os, pathlib, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request

TREE = pathlib.Path(sys.argv[1]).resolve()
LABEL = sys.argv[2] if len(sys.argv) > 2 else TREE.name


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def envelope(agent_id, session, on_behalf_of=None, count=901, hold_id=None):
    env = {
        "agent": {"id": agent_id, "session_id": session},
        "action": {"verb": "delete", "ability": "posts/bulk-delete"},
        "target": {"environment": "production", "id": "wp-posts"},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                 "externality": "internal"},
        "magnitude": {"count": count},
    }
    if on_behalf_of is not None:
        env["agent"]["on_behalf_of"] = on_behalf_of
    if hold_id is not None:
        env["approval"] = {"present": True, "hold_id": hold_id}
    return env


work = pathlib.Path(tempfile.mkdtemp(prefix="rfx138-"))
port = free_port()
env = dict(os.environ)
env.update({
    "REEFLEX_HOST": "127.0.0.1",
    "REEFLEX_PORT": str(port),
    "REEFLEX_POLICY_DIR": str(TREE / "policy"),
    "REEFLEX_AUDIT_LOG": str(work / "decisions.jsonl"),
    "REEFLEX_HOLDS_PATH": str(work / "holds.jsonl"),
    "REEFLEX_LEDGER_PATH": str(work / "ledger.jsonl"),
})
env.pop("REEFLEX_AUTH_TOKEN", None)
proc = subprocess.Popen([sys.executable, "main.py"], cwd=str(TREE), env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
base = f"http://127.0.0.1:{port}"
for _ in range(120):
    try:
        get(base + "/healthz")
        break
    except Exception:
        time.sleep(0.25)
else:
    print("SERVER DID NOT START", proc.stderr.read().decode()[-2000:])
    proc.kill()
    sys.exit(1)

results = {}
try:
    print(f"===== RFX-138 repro against {LABEL}  ({TREE})")
    print(f"      core listening on {base}, work dir {work}\n")

    # ---------------- Variant A: agent substitution ----------------
    print("--- Variant A: agent substitution")
    st, alpha = post(base + "/v1/decide",
                     envelope("qa018-agent-ALPHA", "rfx138-alpha-1"))
    print(f"A1 ALPHA raises          -> {st} {alpha.get('decision')} "
          f"{alpha.get('rule')} hold={alpha.get('hold_id')}")
    hold_id = alpha.get("hold_id")
    assert alpha.get("decision") == "require_approval", alpha

    st, res = post(f"{base}/v1/holds/{hold_id}/resolve",
                   {"decision": "approve",
                    "principal": {"type": "human", "id": "qa018-approver-human"}})
    print(f"A2 human approves ALPHA  -> {st} status={res.get('status')} "
          f"decided_by={res.get('decided_by')}")

    st, beta = post(base + "/v1/decide",
                    envelope("qa018-agent-BETA", "rfx138-beta-1", hold_id=hold_id))
    print(f"A3 BETA spends it        -> {st} {beta.get('decision')} "
          f"{beta.get('rule')} reason={beta.get('reason')}")
    st, again = post(base + "/v1/decide",
                     envelope("qa018-agent-ALPHA", "rfx138-alpha-1", hold_id=hold_id))
    print(f"A4 ALPHA (the approved   -> {st} {again.get('decision')} "
          f"reason={again.get('reason')}")
    print("   one) tries")
    results["A_beta_decision"] = beta.get("decision")
    results["A_beta_reason"] = beta.get("reason")
    results["A_alpha_decision"] = again.get("decision")
    results["A_alpha_reason"] = again.get("reason")

    # ---------------- Variant B: principal substitution ----------------
    print("\n--- Variant B: principal substitution (one bot, one session)")
    st, b1 = post(base + "/v1/decide",
                  envelope("qa018-shared-bot", "rfx138-obo-1",
                           on_behalf_of="alice@customer.test", count=902))
    hold_b = b1.get("hold_id")
    print(f"B1 bot FOR alice raises  -> {st} {b1.get('decision')} hold={hold_b}")
    assert b1.get("decision") == "require_approval", b1
    st, res = post(f"{base}/v1/holds/{hold_b}/resolve",
                   {"decision": "approve",
                    "principal": {"type": "human", "id": "manager@customer.test"}})
    print(f"B2 manager approves      -> {st} status={res.get('status')}")
    st, b3 = post(base + "/v1/decide",
                  envelope("qa018-shared-bot", "rfx138-obo-1",
                           on_behalf_of="bob@customer.test", count=902,
                           hold_id=hold_b))
    print(f"B3 SAME bot FOR bob      -> {st} {b3.get('decision')} "
          f"{b3.get('rule')} reason={b3.get('reason')}")
    results["B_decision"] = b3.get("decision")
    results["B_reason"] = b3.get("reason")

    # ---------------- Control: the legitimate resubmission still works ----
    print("\n--- Control: the agent the human DID approve must still be allowed")
    st, c1 = post(base + "/v1/decide",
                  envelope("qa018-agent-GAMMA", "rfx138-gamma-1", count=903))
    hold_c = c1.get("hold_id")
    st, _ = post(f"{base}/v1/holds/{hold_c}/resolve",
                 {"decision": "approve",
                  "principal": {"type": "human", "id": "qa018-approver-human"}})
    st, c3 = post(base + "/v1/decide",
                  envelope("qa018-agent-GAMMA", "rfx138-gamma-1", count=903,
                           hold_id=hold_c))
    print(f"C  GAMMA raises, human   -> {st} {c3.get('decision')} "
          f"{c3.get('rule')} reason={c3.get('reason')}")
    print("   approves, GAMMA spends")
    results["C_decision"] = c3.get("decision")
    results["C_rule"] = c3.get("rule")

    # ---------------- what the audit record shows for variant B ----------
    lines = [json.loads(x) for x in
             (work / "decisions.jsonl").read_text().splitlines() if x.strip()]
    obo = [l for l in lines if l.get("session_id") == "rfx138-obo-1"]
    print("\n--- Variant B in core's own audit log "
          "(is the substitution recorded anywhere?)")
    for l in obo:
        print("   ", json.dumps({k: l.get(k) for k in
              ("decision", "rule", "agent_id", "session_id", "on_behalf_of",
               "envelope_hash")}, sort_keys=True))
    results["B_audit_has_on_behalf_of"] = any("on_behalf_of" in l for l in obo)
    results["B_audit_hashes"] = sorted({l.get("envelope_hash") for l in obo})

    print("\n===== VERDICT")
    print(json.dumps(results, indent=2, sort_keys=True))
    hijacked = (results["A_beta_decision"] == "allow"
                or results["B_decision"] == "allow")
    print("\nRFX-138 REPRODUCES: %s" % ("YES" if hijacked else "NO"))
    print("legitimate resubmission still allowed: %s"
          % (results["C_decision"] == "allow"))
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(f"\n(server stopped; artefacts under {work})")
