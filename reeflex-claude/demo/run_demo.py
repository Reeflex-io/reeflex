"""
run_demo.py -- End-to-end demo for the reeflex-claude adapter.

Mirrors reeflex-mock/demo.py structure exactly.  stdlib only.

Entry point:
    python reeflex-claude/demo/run_demo.py

Requirements:
  - REEFLEX_OPA_BIN env var set to the OPA binary path
  - Python 3.12+, stdlib only

Scenarios:
  S1: Bash `ls -la`                (env=production)     -> ALLOW
  S2: Read a file                  (env=production)     -> ALLOW
  S3: Bash `rm -rf /`              (env=production)     -> DENY
  S4: Bash `git push --force`      (env=production)     -> ASK
  S5: Write existing prod config   (env=production)     -> ASK
  S6: FRAGMENTATION -- same session, repeated rm 5 files,
      batch crossing cumulative delete budget (>20)     -> ASK
  S7: FAIL-CLOSED -- dead core URL                      -> DENY, exit 0
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DEMO_DIR   = pathlib.Path(__file__).resolve().parent
_REPO_ROOT  = _DEMO_DIR.parent.parent
_CORE_MAIN  = _REPO_ROOT / "reeflex-core" / "main.py"
_POLICY_DIR = _REPO_ROOT / "reeflex-core" / "policy"
_ADAPTER_ROOT = _REPO_ROOT / "reeflex-claude"

_OPA_BIN    = os.environ.get("REEFLEX_OPA_BIN", "opa")
_CORE_PORT  = 8190
_DEAD_PORT  = 19191   # guaranteed nothing listening

# Audit log for the demo
_AUDIT_LOG  = str(_DEMO_DIR / "demo-core-audit.jsonl")
_ADAPTER_AUDIT = str(_DEMO_DIR / "demo-adapter-audit.jsonl")

# ---------------------------------------------------------------------------
# Core lifecycle helpers (mirrored from mock/demo.py)
# ---------------------------------------------------------------------------

def _start_core(port: int, opa_bin: str, audit_log: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["REEFLEX_HOST"]       = "127.0.0.1"
    env["REEFLEX_PORT"]       = str(port)
    env["REEFLEX_OPA_BIN"]    = opa_bin
    env["REEFLEX_POLICY_DIR"] = str(_POLICY_DIR)
    env["REEFLEX_AUDIT_LOG"]  = audit_log
    env["REEFLEX_WINDOW_SECONDS"] = "3600"
    proc = subprocess.Popen(
        [sys.executable, str(_CORE_MAIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def _wait_healthy(port: int, timeout: float = 20.0) -> bool:
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
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Hook invocation helper
# ---------------------------------------------------------------------------

def _run_hook(payload: dict, core_url: str, environment: str,
              extra_env: dict = None) -> tuple:
    """
    Run the hook as a subprocess with the given payload on stdin.
    Returns (parsed_output_dict, raw_stdout, exit_code).
    """
    env = dict(os.environ)
    env["REEFLEX_CORE_URL"]           = core_url
    env["REEFLEX_CLAUDE_ENVIRONMENT"] = environment
    env["REEFLEX_CLAUDE_AUDIT_LOG"]   = _ADAPTER_AUDIT
    env["REEFLEX_CLAUDE_TIMEOUT"]     = "5"
    if extra_env:
        env.update(extra_env)

    stdin_bytes = json.dumps(payload).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "reeflex_claude"],
        input=stdin_bytes,
        capture_output=True,
        cwd=str(_ADAPTER_ROOT),
        env=env,
        timeout=30,
    )
    raw_stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    code = proc.returncode
    try:
        parsed = json.loads(raw_stdout)
    except Exception:
        parsed = {}
    return parsed, raw_stdout, code


def _permission_decision(parsed: dict) -> str:
    try:
        return parsed["hookSpecificOutput"]["permissionDecision"]
    except (KeyError, TypeError):
        return "PARSE_ERROR"


def _decision_reason(parsed: dict) -> str:
    try:
        return parsed["hookSpecificOutput"].get("permissionDecisionReason", "")
    except (KeyError, TypeError):
        return ""


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
    print("NORMALIZED ENVELOPE (sampled):")
    summary = {
        "action": env.get("action"),
        "target": env.get("target"),
        "axes":   env.get("axes"),
        "magnitude": env.get("magnitude"),
        "context": env.get("context"),
        "approval": env.get("approval"),
        "meta": {
            "timestamp": env.get("meta", {}).get("timestamp"),
            "nonce":     env.get("meta", {}).get("nonce", "")[:12] + "...",
            "signature": env.get("meta", {}).get("signature", "")[:20] + "...",
        },
    }
    print(json.dumps(summary, indent=2))


def _print_hook_result(parsed: dict, raw: str, code: int) -> None:
    print("HOOK STDOUT (raw):")
    print(f"  {raw[:400]}")
    print(f"HOOK EXIT CODE: {code}")
    perm = _permission_decision(parsed)
    reason = _decision_reason(parsed)
    print(f"  permissionDecision       : {perm}")
    print(f"  permissionDecisionReason : {reason[:120]}")


# ---------------------------------------------------------------------------
# Scenario result tracking
# ---------------------------------------------------------------------------

_scenario_results: list = []


def _assert(scenario: int, condition: bool, label: str) -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  ASSERT [{status}] {label}")
    while len(_scenario_results) < scenario:
        _scenario_results.append(True)
    if not condition:
        _scenario_results[scenario - 1] = False


def _mark_scenario(scenario: int) -> None:
    while len(_scenario_results) < scenario:
        _scenario_results.append(True)


# ---------------------------------------------------------------------------
# Envelope builder for display (imports from adapter without running hook)
# ---------------------------------------------------------------------------

def _build_envelope_for_display(payload: dict, env_val: str) -> dict:
    """Build the envelope using the adapter's modules directly for display purposes."""
    orig = os.environ.get("REEFLEX_CLAUDE_ENVIRONMENT")
    os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = env_val
    try:
        # Add _ADAPTER_ROOT to path temporarily
        if str(_ADAPTER_ROOT) not in sys.path:
            sys.path.insert(0, str(_ADAPTER_ROOT))
        from reeflex_claude.classify import classify
        from reeflex_claude.envelope import build_envelope
        tool_name = payload.get("tool_name", "unknown")
        tool_input = payload.get("tool_input", {})
        cls = classify(tool_name, tool_input)
        return build_envelope(payload, cls)
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if orig is None:
            os.environ.pop("REEFLEX_CLAUDE_ENVIRONMENT", None)
        else:
            os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = orig


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run_demo() -> int:
    _hr("*")
    print("REEFLEX-CLAUDE ADAPTER -- END-TO-END DEMO")
    print(f"  OPA binary  : {_OPA_BIN}")
    print(f"  Policy dir  : {_POLICY_DIR}")
    print(f"  Core port   : {_CORE_PORT}")
    print(f"  Adapter root: {_ADAPTER_ROOT}")
    _hr("*")
    print()

    # Ensure adapter root is on path
    if str(_ADAPTER_ROOT) not in sys.path:
        sys.path.insert(0, str(_ADAPTER_ROOT))

    print(f"Starting reeflex-core on port {_CORE_PORT} ...")
    core_proc = _start_core(_CORE_PORT, _OPA_BIN, _AUDIT_LOG)
    ok = _wait_healthy(_CORE_PORT, timeout=25)
    if not ok:
        stderr_out = b""
        if core_proc.poll() is not None:
            stderr_out = core_proc.stderr.read(2000)
        print(f"FATAL: reeflex-core failed to start on port {_CORE_PORT}")
        print(f"  stderr: {stderr_out.decode('utf-8', errors='replace')[:500]}")
        _stop_core(core_proc)
        return 1
    print(f"  reeflex-core healthy on port {_CORE_PORT}\n")

    _CORE_URL = f"http://127.0.0.1:{_CORE_PORT}"

    try:
        # ------------------------------------------------------------------
        # S1: Bash `ls -la` -> ALLOW
        # ------------------------------------------------------------------
        _print_scenario(1, "Bash 'ls -la' (env=production) -> ALLOW")
        _mark_scenario(1)

        payload_s1 = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_demo_s1",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        env_s1 = _build_envelope_for_display(payload_s1, "production")
        _print_envelope(env_s1)

        parsed_s1, raw_s1, code_s1 = _run_hook(payload_s1, _CORE_URL, "production")
        _print_hook_result(parsed_s1, raw_s1, code_s1)

        perm_s1 = _permission_decision(parsed_s1)
        _assert(1, code_s1 == 0, "exit code 0")
        _assert(1, perm_s1 == "allow", f"permissionDecision == allow (got {perm_s1})")
        print()

        # ------------------------------------------------------------------
        # S2: Read file -> ALLOW
        # ------------------------------------------------------------------
        _print_scenario(2, "Read file (env=production) -> ALLOW")
        _mark_scenario(2)

        payload_s2 = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_demo_s2",
            "cwd": "/tmp",
            "tool_name": "Read",
            "tool_input": {"file_path": "/src/main.py"},
        }
        env_s2 = _build_envelope_for_display(payload_s2, "production")
        _print_envelope(env_s2)

        parsed_s2, raw_s2, code_s2 = _run_hook(payload_s2, _CORE_URL, "production")
        _print_hook_result(parsed_s2, raw_s2, code_s2)

        perm_s2 = _permission_decision(parsed_s2)
        _assert(2, code_s2 == 0, "exit code 0")
        _assert(2, perm_s2 == "allow", f"permissionDecision == allow (got {perm_s2})")
        print()

        # ------------------------------------------------------------------
        # S3: Bash `rm -rf /` -> DENY (irreversible_systemic_prod)
        # ------------------------------------------------------------------
        _print_scenario(3, "Bash 'rm -rf /' (env=production) -> DENY [HEADLINE]")
        _mark_scenario(3)

        payload_s3 = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_demo_s3",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        env_s3 = _build_envelope_for_display(payload_s3, "production")
        _print_envelope(env_s3)

        parsed_s3, raw_s3, code_s3 = _run_hook(payload_s3, _CORE_URL, "production")
        _print_hook_result(parsed_s3, raw_s3, code_s3)

        perm_s3 = _permission_decision(parsed_s3)
        reason_s3 = _decision_reason(parsed_s3)
        _assert(3, code_s3 == 0, "exit code 0")
        _assert(3, perm_s3 == "deny", f"permissionDecision == deny (got {perm_s3})")
        _assert(3, "irreversible_systemic_prod" in reason_s3 or "systemic" in reason_s3,
                f"reason mentions systemic rule (got: {reason_s3[:80]})")
        print()

        # ------------------------------------------------------------------
        # S4: Bash `git push --force origin main` -> ASK (irreversible_broad_prod)
        # ------------------------------------------------------------------
        _print_scenario(4, "Bash 'git push --force origin main' (env=production) -> ASK")
        _mark_scenario(4)

        payload_s4 = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_demo_s4",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"},
        }
        env_s4 = _build_envelope_for_display(payload_s4, "production")
        _print_envelope(env_s4)

        parsed_s4, raw_s4, code_s4 = _run_hook(payload_s4, _CORE_URL, "production")
        _print_hook_result(parsed_s4, raw_s4, code_s4)

        perm_s4 = _permission_decision(parsed_s4)
        _assert(4, code_s4 == 0, "exit code 0")
        _assert(4, perm_s4 == "ask", f"permissionDecision == ask (got {perm_s4})")
        print()

        # ------------------------------------------------------------------
        # S5: Write to existing prod config -> ASK (irreversible_broad_prod)
        # The file must exist so os.path.exists() returns True -> irreversible
        # ------------------------------------------------------------------
        _print_scenario(5, "Write existing prod config (env=production) -> ASK")
        _mark_scenario(5)

        # Create a temp file so exists() -> True -> irreversible
        with tempfile.NamedTemporaryFile(
            suffix=".env", delete=False, mode="w", encoding="utf-8"
        ) as tf:
            tf.write("DATABASE_URL=synthetic\n")
            tmp_env_path = tf.name

        try:
            payload_s5 = {
                "hook_event_name": "PreToolUse",
                "session_id": "sess_demo_s5",
                "cwd": "/tmp",
                "tool_name": "Write",
                "tool_input": {
                    "file_path": tmp_env_path,
                    "content": "DATABASE_URL=synthetic-overwrite\n",
                },
            }
            env_s5 = _build_envelope_for_display(payload_s5, "production")
            _print_envelope(env_s5)
            print(f"  [setup] Temp file created: {tmp_env_path} (exists={os.path.exists(tmp_env_path)})")

            parsed_s5, raw_s5, code_s5 = _run_hook(payload_s5, _CORE_URL, "production")
            _print_hook_result(parsed_s5, raw_s5, code_s5)

            perm_s5 = _permission_decision(parsed_s5)
            env_s5_axes = env_s5.get("axes", {})
            _assert(5, code_s5 == 0, "exit code 0")
            _assert(5, env_s5_axes.get("reversibility") == "irreversible",
                    f"axes.reversibility == irreversible (file exists -> overwrite; got {env_s5_axes})")
            _assert(5, perm_s5 == "ask", f"permissionDecision == ask (got {perm_s5})")
        finally:
            try:
                os.unlink(tmp_env_path)
            except Exception:
                pass
        print()

        # ------------------------------------------------------------------
        # S6: FRAGMENTATION -- repeated rm 5 files, same session, budget > 20 -> ASK
        # ------------------------------------------------------------------
        _print_scenario(6, "FRAGMENTATION: repeated rm batches -> ASK at delete budget")
        _mark_scenario(6)

        # Fresh session_id (fragmentation guard is per-session)
        FRAG_SESSION = "sess_demo_frag_s6"
        batch_size = 5
        frag_outcomes = []

        for batch_num in range(1, 9):
            # Build a unique set of synthetic file names per batch
            files = " ".join([f"/tmp/synthetic_f{batch_num}_{i}.txt"
                               for i in range(batch_size)])
            payload_frag = {
                "hook_event_name": "PreToolUse",
                "session_id": FRAG_SESSION,
                "cwd": "/tmp",
                "tool_name": "Bash",
                "tool_input": {"command": f"rm {files}"},
            }
            # Use staging env so only the fragmentation rule (R5) triggers,
            # not the prod rules -- but per policy, R5 also requires prod.
            # Use production env to let core's ledger track deletes.
            parsed_frag, raw_frag, code_frag = _run_hook(
                payload_frag, _CORE_URL, "production"
            )
            perm_frag = _permission_decision(parsed_frag)
            reason_frag = _decision_reason(parsed_frag)

            prior_count = sum(
                o["batch_size"] for o in frag_outcomes
                if o["perm"] in ("allow",)
            )
            print(f"  Batch {batch_num}: files={files[:60]}...")
            print(f"           perm={perm_frag}  prior_deletes={prior_count}")

            frag_outcomes.append({
                "batch": batch_num,
                "perm": perm_frag,
                "reason": reason_frag,
                "batch_size": batch_size,
            })

            if perm_frag in ("ask", "deny"):
                print(f"  --> Budget crossed / blocked at batch {batch_num}: {reason_frag[:80]}")
                break

        allowed_batches  = [o for o in frag_outcomes if o["perm"] == "allow"]
        crossing_batches = [o for o in frag_outcomes if o["perm"] in ("ask", "deny")]

        total_allowed = sum(o["batch_size"] for o in allowed_batches)
        print(f"\n  Allowed batches: {len(allowed_batches)} "
              f"(total units: {total_allowed})")
        if crossing_batches:
            cross = crossing_batches[0]
            print(f"  Crossing at batch {cross['batch']}: "
                  f"perm={cross['perm']} reason={cross['reason'][:60]}")

        _assert(6, len(allowed_batches) >= 4,
                f"at least 4 allow batches (got {len(allowed_batches)})")
        _assert(6, len(crossing_batches) >= 1,
                "at least 1 ASK/DENY crossing batch")
        if crossing_batches:
            _assert(6, crossing_batches[0]["perm"] == "ask",
                    f"crossing batch perm == ask (got {crossing_batches[0]['perm']})")
            _assert(6, "session_delete_budget" in crossing_batches[0]["reason"]
                    or "fragmentation" in crossing_batches[0]["reason"].lower(),
                    f"crossing reason mentions fragmentation guard: {crossing_batches[0]['reason'][:80]}")
        print()

        # ------------------------------------------------------------------
        # S7: FAIL-CLOSED -- dead core URL -> DENY, exit 0  [CRITICAL]
        # ------------------------------------------------------------------
        _print_scenario(7, "FAIL-CLOSED: dead core URL -> DENY, exit 0 [CRITICAL]")
        _mark_scenario(7)

        dead_url = f"http://127.0.0.1:{_DEAD_PORT}"
        payload_s7 = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_demo_s7_failclosed",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        env_s7 = _build_envelope_for_display(payload_s7, "production")
        _print_envelope(env_s7)

        print(f"  [setup] Pointing hook at dead core: {dead_url}")
        parsed_s7, raw_s7, code_s7 = _run_hook(payload_s7, dead_url, "production")
        _print_hook_result(parsed_s7, raw_s7, code_s7)

        perm_s7 = _permission_decision(parsed_s7)
        reason_s7 = _decision_reason(parsed_s7)
        _assert(7, code_s7 == 0,
                "exit code 0  [CRITICAL: non-zero = Claude Code CONTINUES tool = silent allow!]")
        _assert(7, perm_s7 == "deny",
                f"permissionDecision == deny (fail-closed) (got {perm_s7})")
        _assert(7, "fail" in reason_s7.lower() or "unreachable" in reason_s7.lower(),
                f"reason mentions fail-closed: {reason_s7[:80]}")
        print()

    except Exception as exc:
        import traceback
        print(f"\nFATAL exception during demo: {exc}")
        traceback.print_exc()
    finally:
        _stop_core(core_proc)
        print("  reeflex-core subprocess terminated.")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    _hr("=")
    print("DEMO SUMMARY")
    _hr("=")
    scenario_names = [
        "S1: Bash 'ls -la' (prod)                    -> ALLOW",
        "S2: Read file (prod)                         -> ALLOW",
        "S3: Bash 'rm -rf /' (prod)                  -> DENY  [HEADLINE]",
        "S4: Bash 'git push --force' (prod)           -> ASK",
        "S5: Write existing .env (prod)               -> ASK",
        "S6: Fragmentation: repeat rm -> budget       -> ASK",
        "S7: Dead core URL                            -> DENY, exit 0 [CRITICAL]",
    ]
    all_pass = True
    for i, (passed, name) in enumerate(zip(_scenario_results, scenario_names), 1):
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
