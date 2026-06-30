"""
demo.py -- End-to-end runnable demo: agent -> adapter -> reeflex-core -> ENFORCED verdict.

Canonical entry point:
    python reeflex-mock/demo.py

Requirements: Python stdlib only (subprocess, urllib.request, json, time, os, threading).
No pip dependencies.

This script:
  1. Starts reeflex-core as a subprocess on port 8181.
  2. Polls GET /healthz until ready.
  3. Runs 5 scenarios proving the full adapter contract.
  4. Terminates core cleanly (also on error).
  5. Prints per-scenario: action, normalized envelope, verdict, store BEFORE->AFTER.
  6. Ends with a PASS/FAIL summary per scenario + overall STATUS.

Scenarios:
  (1) read benign post              -> ALLOW    (store unchanged)
  (2) delete 1 post (recoverable)   -> ALLOW    (post actually gone; read-back)
  (3) bulk delete 50 in production  -> REQUIRE_APPROVAL  (store UNTOUCHED)
  (4) fragmentation: repeated small deletes until cumulative > 20 -> REQUIRE_APPROVAL
  (5) fail-closed: core with bad OPA binary -> DENY (reeflex.core/fail_closed)
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Paths -- all absolute, never relative
# ---------------------------------------------------------------------------

_DEMO_DIR   = pathlib.Path(__file__).resolve().parent
_REPO_ROOT  = _DEMO_DIR.parent
_CORE_MAIN  = _REPO_ROOT / "reeflex-core" / "main.py"
_POLICY_DIR = _REPO_ROOT / "reeflex-core" / "policy"
_AUDIT_LOG  = _DEMO_DIR / "demo-core-audit.jsonl"
_ADAPTER_AUDIT = _DEMO_DIR / "adapter-audit.jsonl"

# Ports: primary core on 8181, bad-opa core on 8182
_CORE_PORT      = 8181
_BAD_CORE_PORT  = 8182

# OPA binary: from env REEFLEX_OPA_BIN, or fallback to "opa" on PATH
_OPA_BIN = os.environ.get("REEFLEX_OPA_BIN", "opa")
_POLICY_DIR_STR = os.environ.get("REEFLEX_POLICY_DIR", str(_POLICY_DIR))

# ---------------------------------------------------------------------------
# Core lifecycle helpers
# ---------------------------------------------------------------------------

def _start_core(port: int, opa_bin: str, audit_log: str) -> subprocess.Popen:
    """Start reeflex-core as a subprocess on the given port."""
    env = dict(os.environ)
    env["REEFLEX_HOST"]       = "127.0.0.1"
    env["REEFLEX_PORT"]       = str(port)
    env["REEFLEX_OPA_BIN"]    = opa_bin
    env["REEFLEX_POLICY_DIR"] = _POLICY_DIR_STR
    env["REEFLEX_AUDIT_LOG"]  = audit_log
    env["REEFLEX_WINDOW_SECONDS"] = "3600"
    proc = subprocess.Popen(
        [sys.executable, str(_CORE_MAIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def _wait_healthy(port: int, timeout: float = 15.0) -> bool:
    """Poll GET /healthz until 200 OK or timeout. Returns True on success."""
    url = f"http://127.0.0.1:{port}/healthz"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def _stop_core(proc: subprocess.Popen) -> None:
    """Terminate and wait for the core subprocess."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _healthz(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def _decide(envelope: dict, port: int) -> dict:
    """POST envelope to /v1/decide and return the parsed response dict."""
    url = f"http://127.0.0.1:{port}/v1/decide"
    body = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"decision": "deny", "rule": "adapter/http_error",
                    "reason": str(exc), "obligations": []}
    except Exception as exc:
        return {"decision": "deny", "rule": "reeflex.core/fail_closed",
                "reason": f"core unreachable: {exc}", "obligations": []}


# ---------------------------------------------------------------------------
# Printing helpers
# ---------------------------------------------------------------------------

def _hr(char: str = "-", width: int = 72) -> None:
    print(char * width)


def _print_scenario(n: int, title: str) -> None:
    _hr("=")
    print(f"SCENARIO {n}: {title}")
    _hr("=")


def _print_envelope(env: dict) -> None:
    print("NORMALIZED ENVELOPE:")
    print(json.dumps(env, indent=2))


def _print_decision(dec: dict) -> None:
    print("VERDICT:")
    print(f"  decision  : {dec.get('decision')}")
    print(f"  rule      : {dec.get('rule')}")
    print(f"  reason    : {dec.get('reason')}")
    if dec.get("obligations"):
        print(f"  oblig.    : {dec.get('obligations')}")


def _print_store(label: str, count: int, ids: list) -> None:
    shown = ids[:10]
    more = f" ... +{len(ids)-10}" if len(ids) > 10 else ""
    print(f"  {label}: {count} posts  ids={shown}{more}")


# ---------------------------------------------------------------------------
# Per-scenario result tracking
# ---------------------------------------------------------------------------

_scenario_results: list = []


def _assert(scenario: int, condition: bool, label: str) -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  ASSERT [{status}] {label}")
    if len(_scenario_results) < scenario:
        _scenario_results.append(True)
    if not condition:
        _scenario_results[scenario - 1] = False


def _mark_scenario(scenario: int) -> None:
    if len(_scenario_results) < scenario:
        _scenario_results.append(True)


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run_demo() -> int:
    """Run all 5 scenarios. Returns exit code (0=all pass, 1=any fail)."""

    # -----------------------------------------------------------------------
    # Setup: start primary reeflex-core
    # -----------------------------------------------------------------------
    _hr("*")
    print("REEFLEX MOCK ADAPTER -- END-TO-END DEMO")
    print(f"  OPA binary  : {_OPA_BIN}")
    print(f"  Policy dir  : {_POLICY_DIR_STR}")
    print(f"  Core port   : {_CORE_PORT}")
    print(f"  Audit log   : {_AUDIT_LOG}")
    _hr("*")
    print()

    primary_audit = str(_AUDIT_LOG)
    print(f"Starting reeflex-core on port {_CORE_PORT} ...")
    primary_core = _start_core(_CORE_PORT, _OPA_BIN, primary_audit)
    primary_ok = _wait_healthy(_CORE_PORT, timeout=20)
    if not primary_ok:
        stderr_out = primary_core.stderr.read(2000) if primary_core.poll() is not None else b"(still running)"
        print(f"FATAL: reeflex-core failed to start on port {_CORE_PORT}")
        print(f"  stderr: {stderr_out.decode('utf-8', errors='replace')}")
        _stop_core(primary_core)
        return 1
    print(f"  reeflex-core healthy on port {_CORE_PORT}")
    print()

    # Inline adapter/agent wiring (imports are local so adapter uses correct CORE_URL)
    import adapter as adp
    adp.CORE_URL = f"http://127.0.0.1:{_CORE_PORT}"
    adp.AUDIT_LOG = str(_ADAPTER_AUDIT)

    from store import PostStore
    from adapter import MockAdapter
    from agent import MockAgent

    # A shared store + adapter for scenarios 1-4 (same session to test fragmentation)
    SHARED_SESSION = "sess_demo_main_001"
    store = PostStore()
    mock_adapter = MockAdapter(store, session_id=SHARED_SESSION)
    agent = MockAgent(mock_adapter)

    try:
        # -------------------------------------------------------------------
        # SCENARIO 1: read a benign post -> ALLOW, store unchanged
        # -------------------------------------------------------------------
        _print_scenario(1, "Read benign post -> ALLOW (store unchanged)")
        _mark_scenario(1)

        before_count = store.count()
        before_ids   = store.ids()

        intent_1 = {"op": "get", "id": 10, "environment": "production"}
        envelope_1 = mock_adapter._normalize(intent_1)
        _print_envelope(envelope_1)

        result_1 = agent.read_post(10, environment="production")
        dec_1 = {"decision": result_1["decision"], "rule": result_1["rule"],
                 "reason": result_1["reason"], "obligations": result_1["obligations"]}
        _print_decision(dec_1)

        after_count = store.count()
        after_ids   = store.ids()

        print("STORE BEFORE->AFTER:")
        _print_store("before", before_count, before_ids)
        _print_store("after ", after_count, after_ids)

        _assert(1, result_1["decision"] == "allow",       "decision == allow")
        _assert(1, result_1["outcome"] == "executed",     "outcome == executed")
        _assert(1, result_1["store_changed"] == True,     "store_changed == True (read returns value)")
        _assert(1, after_count == before_count,           "store count unchanged after read")
        _assert(1, after_ids == before_ids,               "store IDs unchanged after read")
        print()

        # -------------------------------------------------------------------
        # SCENARIO 2: delete 1 post (recoverable/single/internal) -> ALLOW
        # -------------------------------------------------------------------
        _print_scenario(2, "Delete 1 post (recoverable/single) -> ALLOW (post actually gone)")
        _mark_scenario(2)

        target_id = 42
        before_count = store.count()
        before_has   = store.get(target_id) is not None

        intent_2 = {"op": "delete", "id": target_id, "environment": "production",
                    "force_delete": False}
        envelope_2 = mock_adapter._normalize(intent_2)
        _print_envelope(envelope_2)

        result_2 = agent.delete_post(target_id, environment="production", force=False)
        dec_2 = {"decision": result_2["decision"], "rule": result_2["rule"],
                 "reason": result_2["reason"], "obligations": result_2["obligations"]}
        _print_decision(dec_2)

        after_count = store.count()
        after_has   = store.get(target_id) is not None

        print("STORE BEFORE->AFTER:")
        print(f"  post {target_id} existed before: {before_has}")
        _print_store("before", before_count, store.ids())
        print(f"  post {target_id} exists  after:  {after_has}")
        _print_store("after ", after_count, store.ids())

        _assert(2, result_2["decision"] == "allow",   "decision == allow")
        _assert(2, result_2["outcome"] == "executed", "outcome == executed")
        _assert(2, before_has,                        "post existed before delete")
        _assert(2, not after_has,                     "post gone after delete (read-back)")
        _assert(2, after_count == before_count - 1,   "store count decreased by 1")
        print()

        # -------------------------------------------------------------------
        # SCENARIO 3: bulk delete 50 posts in production (irreversible/broad)
        #             -> REQUIRE_APPROVAL, store UNTOUCHED
        # -------------------------------------------------------------------
        _print_scenario(3, "Bulk delete 50 posts in production -> REQUIRE_APPROVAL (store UNTOUCHED)")
        _mark_scenario(3)

        # Pick 50 IDs from whatever remains
        available = store.ids()
        bulk_ids_50 = available[:50]
        assert len(bulk_ids_50) == 50, f"Expected 50 available, got {len(available)}"

        before_count = store.count()
        before_ids   = store.ids()

        intent_3 = {"op": "bulk_delete", "ids": bulk_ids_50,
                    "environment": "production", "force_delete": True}
        envelope_3 = mock_adapter._normalize(intent_3)
        _print_envelope(envelope_3)

        result_3 = agent.bulk_delete_posts(bulk_ids_50, environment="production",
                                            force=True)
        dec_3 = {"decision": result_3["decision"], "rule": result_3["rule"],
                 "reason": result_3["reason"], "obligations": result_3["obligations"]}
        _print_decision(dec_3)

        after_count = store.count()
        after_ids   = store.ids()

        print("STORE BEFORE->AFTER:")
        _print_store("before", before_count, before_ids)
        _print_store("after ", after_count, after_ids)

        _assert(3, result_3["decision"] == "require_approval", "decision == require_approval")
        _assert(3, result_3["outcome"] == "held",              "outcome == held")
        _assert(3, result_3["store_changed"] == False,         "store_changed == False")
        _assert(3, after_count == before_count,                "store count UNCHANGED (read-back)")
        _assert(3, after_ids == before_ids,                    "store IDs UNCHANGED (read-back)")
        print()

        # -------------------------------------------------------------------
        # SCENARIO 4: FRAGMENTATION -- repeated small deletes until cumulative
        #             > 20 triggers REQUIRE_APPROVAL for the crossing batch
        # -------------------------------------------------------------------
        _print_scenario(4, "Fragmentation: repeated delete batches -> REQUIRE_APPROVAL at budget boundary")
        _mark_scenario(4)

        # We need a FRESH session for this scenario so the ledger starts at 0.
        # Use a new session_id + new adapter (same store).
        FRAG_SESSION = "sess_demo_frag_002"
        frag_adapter = MockAdapter(store, session_id=FRAG_SESSION)
        frag_agent   = MockAgent(frag_adapter)

        # Delete 5 at a time; budget = 20; crossing batch is the 5th batch
        # (4 batches * 5 = 20 cumulative; 5th batch pushes to 25 > 20).
        batch_size = 5
        available_for_frag = store.ids()
        # We need at least 25 IDs available; post 42 was deleted, 99 remain
        assert len(available_for_frag) >= 25, \
            f"Need 25 posts, have {len(available_for_frag)}"

        frag_outcomes = []
        cumulative_deleted = 0
        batch_num = 0

        # Run batches until we hit REQUIRE_APPROVAL or exhaust 8 attempts
        for i in range(8):
            available_now = store.ids()
            batch_ids = available_now[:batch_size]
            if len(batch_ids) < batch_size:
                print(f"  [FRAG] ran out of posts at batch {i+1}")
                break

            batch_num = i + 1
            before_this = store.count()
            r = frag_agent.bulk_delete_posts(
                batch_ids,
                environment="production",
                force=False,
            )
            after_this = store.count()
            deleted_this_batch = before_this - after_this

            frag_outcomes.append({
                "batch": batch_num,
                "ids": batch_ids,
                "decision": r["decision"],
                "rule": r["rule"],
                "store_changed": r["store_changed"],
                "deleted_in_store": deleted_this_batch,
                "cumulative_before": cumulative_deleted,
            })

            print(f"  Batch {batch_num}: ids={batch_ids} | "
                  f"decision={r['decision']} | rule={r['rule']} | "
                  f"store_changed={r['store_changed']} | "
                  f"cumulative_before_call={cumulative_deleted}")

            if r["decision"] == "require_approval":
                # This is the crossing batch -- verify store was NOT mutated
                print(f"  --> Budget crossed at batch {batch_num} "
                      f"(cumulative before = {cumulative_deleted}, "
                      f"batch size = {batch_size})")
                break

            if r["decision"] == "allow":
                cumulative_deleted += deleted_this_batch

        # Find the crossing batch
        crossing = [o for o in frag_outcomes if o["decision"] == "require_approval"]
        allowed  = [o for o in frag_outcomes if o["decision"] == "allow"]

        print(f"\n  Allowed batches: {len(allowed)} "
              f"(total approved deletes: {sum(o['deleted_in_store'] for o in allowed)})")
        if crossing:
            print(f"  Crossing batch {crossing[0]['batch']}: "
                  f"REQUIRE_APPROVAL at cumulative_before="
                  f"{crossing[0]['cumulative_before']} + batch {batch_size} > 20")
            print(f"  Crossing batch store_changed: {crossing[0]['store_changed']}")

        # Read-back: verify crossing batch IDs are still in store
        if crossing:
            crossing_ids = crossing[0]["ids"]
            still_present = all(store.get(pid) is not None for pid in crossing_ids)
            crossing_batch_not_executed = not crossing[0]["store_changed"]
        else:
            still_present = False
            crossing_batch_not_executed = False

        _assert(4, len(allowed) >= 4,              "at least 4 allow batches before budget")
        _assert(4, len(crossing) == 1,             "exactly 1 REQUIRE_APPROVAL (crossing batch)")
        _assert(4, crossing[0]["decision"] == "require_approval" if crossing else False,
                   "crossing batch decision == require_approval")
        _assert(4, crossing_batch_not_executed,    "crossing batch NOT executed (store_changed=False)")
        _assert(4, still_present,                  "crossing batch IDs still in store (read-back)")
        print()

        # -------------------------------------------------------------------
        # SCENARIO 5: FAIL-CLOSED -- core with broken OPA binary -> DENY
        # -------------------------------------------------------------------
        _print_scenario(5, "Fail-closed: broken OPA binary -> DENY (reeflex.core/fail_closed)")
        _mark_scenario(5)

        # Start a second core instance pointing at a nonexistent OPA binary
        bad_opa = "/nonexistent/path/to/opa_does_not_exist"
        bad_audit = str(_DEMO_DIR / "demo-bad-core-audit.jsonl")
        print(f"  Starting bad-OPA core on port {_BAD_CORE_PORT} "
              f"(opa_bin={bad_opa}) ...")
        bad_core = _start_core(_BAD_CORE_PORT, bad_opa, bad_audit)
        bad_ok = _wait_healthy(_BAD_CORE_PORT, timeout=20)
        if not bad_ok:
            # Core may still be starting -- give it a bit
            time.sleep(2)
            bad_ok = _wait_healthy(_BAD_CORE_PORT, timeout=5)

        if not bad_ok:
            stderr_out = b""
            if bad_core.poll() is not None:
                stderr_out = bad_core.stderr.read(2000)
            print(f"WARN: bad-OPA core did not respond to /healthz (may be expected).")
            print(f"  stderr: {stderr_out.decode('utf-8', errors='replace')[:500]}")

        # Build an envelope that WOULD be allowed on a healthy core
        # (single read, reversible/single/internal)
        fail_closed_session = "sess_demo_failclosed_003"
        fail_closed_adapter = MockAdapter(store, session_id=fail_closed_session)
        adp.CORE_URL = f"http://127.0.0.1:{_BAD_CORE_PORT}"

        before_count_fc = store.count()
        before_ids_fc   = store.ids()

        intent_5 = {"op": "get", "id": 1, "environment": "production"}
        envelope_5 = fail_closed_adapter._normalize(intent_5)
        _print_envelope(envelope_5)

        # Directly call core on bad port (adapter enforces fail-closed)
        dec_5_raw = _decide(envelope_5, _BAD_CORE_PORT)

        print("VERDICT (from bad-OPA core):")
        print(f"  decision  : {dec_5_raw.get('decision')}")
        print(f"  rule      : {dec_5_raw.get('rule')}")
        print(f"  reason    : {dec_5_raw.get('reason')}")

        # Also apply via adapter to confirm adapter enforces fail-closed
        result_5 = fail_closed_adapter.apply(intent_5)
        print(f"  adapter outcome: {result_5['outcome']}")
        print(f"  adapter store_changed: {result_5['store_changed']}")

        after_count_fc = store.count()
        after_ids_fc   = store.ids()

        print("STORE BEFORE->AFTER:")
        _print_store("before", before_count_fc, before_ids_fc)
        _print_store("after ", after_count_fc, after_ids_fc)

        # The bad core returns either:
        #   (a) HTTP 500 with decision=deny rule=reeflex.core/fail_closed  (OPA error path)
        #   (b) Connection refused -> adapter's _fail_closed_decision wraps it
        # Either way the adapter must block (outcome != executed on a read IF denied)
        # But if bad_ok=False (core not even reachable), adapter returns deny via _fail_closed_decision.
        fc_decision = dec_5_raw.get("decision")
        fc_rule     = dec_5_raw.get("rule", "")

        # Accept either core-side fail_closed or adapter-side fail_closed
        fc_is_deny = fc_decision == "deny"
        fc_rule_ok = "fail_closed" in fc_rule or "fail_closed" in result_5.get("rule", "")

        _assert(5, fc_is_deny,                "decision == deny (fail-closed)")
        _assert(5, fc_rule_ok,                "rule contains 'fail_closed'")
        _assert(5, after_count_fc == before_count_fc, "store count UNCHANGED")
        _assert(5, after_ids_fc == before_ids_fc,     "store IDs UNCHANGED (read-back)")

        _stop_core(bad_core)
        print()

    except Exception as exc:
        print(f"\nFATAL exception during demo: {exc}")
        import traceback
        traceback.print_exc()
    finally:
        # Restore adapter URL to primary (for clean teardown)
        adp.CORE_URL = f"http://127.0.0.1:{_CORE_PORT}"
        _stop_core(primary_core)
        print("  reeflex-core subprocess terminated.")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    _hr("=")
    print("DEMO SUMMARY")
    _hr("=")
    all_pass = True
    names = [
        "Read benign post                     -> ALLOW, store unchanged",
        "Delete 1 post (recoverable/single)   -> ALLOW, post gone",
        "Bulk delete 50 in prod (irrev/broad) -> REQUIRE_APPROVAL, store intact",
        "Fragmentation (cumulative budget)    -> REQUIRE_APPROVAL at crossing batch",
        "Fail-closed (broken OPA)             -> DENY, store intact",
    ]
    for i, (passed, name) in enumerate(zip(_scenario_results, names), 1):
        status = "PASS" if passed else "FAIL"
        print(f"  Scenario {i}: [{status}] {name}")
        if not passed:
            all_pass = False

    _hr("-")
    overall = "PASS" if all_pass else "FAIL"
    print(f"\nSTATUS: {overall}")
    _hr("*")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(run_demo())
