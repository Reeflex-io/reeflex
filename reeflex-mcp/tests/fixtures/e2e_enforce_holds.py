"""
e2e_enforce_holds.py -- manual, real end-to-end driver for Track 3
(enforcement + holds): a real gateway (enforce mode) + a real reeflex-core +
a real stdio upstream (tests/fixtures/stdio_upstream.py), proving the full
hold -> resolve -> resubmit -> execute round trip, a terminal deny, and a
clean allow, all with core's real `decision_id`/`parent_decision_id`.

Prerequisites (see the adapter-builder's Track 3 report for the exact
commands): reeflex-core running on 127.0.0.1:8080 with a resolution policy
that allows a "human" principal to resolve
"irreversible_broad_prod"/"session_delete_budget" (the default
human-only-everywhere policy already does).

This script does NOT resolve the hold itself -- it prints the hold_id and
waits for the operator (or an orchestrating shell script) to POST
/v1/holds/{id}/resolve, then press Enter. See e2e_enforce_holds_driver.sh (or
the report) for the fully-scripted version used to produce the reported
transcript.

Usage:
  python tests/fixtures/e2e_enforce_holds.py [path-to-reeflex-mcp.yaml] [--auto-resolve]

  --auto-resolve: resolve the hold itself via urllib against
  REEFLEX_CORE_URL (default http://127.0.0.1:8080) as principal
  human:approver1, instead of pausing for manual/external resolution.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_HERE = Path(__file__).resolve().parent
_PACKAGE_ROOT = _HERE.parent.parent
_VENV_PYTHON = _PACKAGE_ROOT / ".venv" / "Scripts" / "python.exe"


def _generate_config(*, python: str) -> str:
    notes_script = str(_HERE / "stdio_upstream.py")
    yaml_text = f"""\
mode: enforce
upstreams:
  - name: notes
    command: [{python!r}, {notes_script!r}]
    target: {{ system: notes, environment: production }}
    required: true
"""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(yaml_text)
    fh.close()
    return fh.name


def _text_of(result) -> str:
    return "".join(c.text for c in result.content if hasattr(c, "text"))


def _extract(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _resolve_hold(core_url: str, hold_id: str, *, principal_type: str = "human", principal_id: str = "approver1") -> dict:
    url = f"{core_url}/v1/holds/{hold_id}/resolve"
    body = json.dumps({"decision": "approve", "principal": {"type": principal_type, "id": principal_id}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


async def main(config_path: str, auto_resolve: bool, core_url: str) -> None:
    python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
    params = StdioServerParameters(
        command=python,
        args=["-m", "reeflex_mcp", "--transport", "stdio"],
        env={"REEFLEX_MCP_CONFIG": config_path, "REEFLEX_MODE": "enforce"},
    )

    print(f"[e2e_enforce_holds] launching gateway (enforce mode): {python} -m reeflex_mcp --config {config_path}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ---- (c) safe call -- flows through, decision_id tagged -----
            print("\n=== (c) SAFE CALL: notes__read_note ===")
            result = await session.call_tool("notes__read_note", {"name": "alpha"})
            print(f"isError={result.isError} meta={result.meta} content={_text_of(result)!r}")
            assert not result.isError, "safe read_note was unexpectedly blocked"
            assert result.meta and result.meta.get("decision_id"), "decision_id missing on allow"
            print(f"PASS: allowed, decision_id={result.meta['decision_id']} tagged in _meta")

            # ---- (a) held call: first submission -------------------------
            bulk_names = [f"ghost-note-{i}" for i in range(25)]
            print("\n=== (a) HELD CALL: notes__delete_notes (25 items, production) -- first submission ===")
            result = await session.call_tool("notes__delete_notes", {"names": bulk_names})
            text = _text_of(result)
            print(f"isError={result.isError} content={text!r}")
            assert result.isError, "expected the first submission to be held (isError=True)"
            hold_id = _extract(r"hold_id=([0-9a-f]+)", text)
            original_decision_id = _extract(r"(?<!parent_)decision_id=([0-9a-f]+)", text)
            assert hold_id, f"could not extract hold_id from: {text!r}"
            print(f"PASS: held. hold_id={hold_id} original decision_id={original_decision_id}")

            # ---- retry BEFORE resolving -- "still pending" -----------------
            print("\n=== retry BEFORE resolving -- expect 'still held' (same hold_id, not a new one) ===")
            result = await session.call_tool("notes__delete_notes", {"names": bulk_names})
            text = _text_of(result)
            print(f"isError={result.isError} content={text!r}")
            assert result.isError, "expected still-pending retry to remain blocked"
            assert "still held" in text.lower(), f"expected 'still held' framing, got: {text!r}"
            still_hold_id = _extract(r"hold_id=([0-9a-f]+)", text)
            assert still_hold_id == hold_id, f"expected the SAME hold_id, got {still_hold_id} vs {hold_id}"
            print(f"PASS: still pending, SAME hold_id={still_hold_id} re-surfaced (no duplicate hold minted)")

            # ---- resolve the hold ------------------------------------------
            if auto_resolve:
                print(f"\n=== resolving hold {hold_id} via POST /v1/holds/{hold_id}/resolve (human:approver1) ===")
                resolved = _resolve_hold(core_url, hold_id)
                print(f"resolve response: {resolved}")
                assert resolved.get("status") == "approved", f"hold did not resolve to approved: {resolved}"
            else:
                input(f"\n>>> Resolve hold {hold_id} now (POST {core_url}/v1/holds/{hold_id}/resolve), then press Enter... ")

            # ---- retry AFTER resolving -- should now execute ---------------
            print("\n=== retry AFTER resolving -- expect allow (approved_resubmission), upstream executes ===")
            result = await session.call_tool("notes__delete_notes", {"names": bulk_names})
            text = _text_of(result)
            print(f"isError={result.isError} meta={result.meta} content={text!r}")
            assert not result.isError, f"expected the resolved resubmission to be allowed, got: {text!r}"
            assert result.meta and result.meta.get("decision_id"), "decision_id missing on approved resubmission"
            assert result.meta.get("parent_decision_id") == original_decision_id, (
                f"expected parent_decision_id={original_decision_id}, got {result.meta.get('parent_decision_id')}"
            )
            print(
                f"PASS: approved resubmission executed. decision_id={result.meta['decision_id']} "
                f"parent_decision_id={result.meta['parent_decision_id']} (== original {original_decision_id})"
            )

            # ---- (b) denied call: R3 irreversible+systemic+production -----
            print("\n=== (b) DENIED CALL: notes__frobnicate_widget (unclassifiable -> execute/irreversible/systemic) ===")
            result = await session.call_tool("notes__frobnicate_widget", {"name": "should-never-run"})
            text = _text_of(result)
            print(f"isError={result.isError} content={text!r}")
            assert result.isError, "expected frobnicate_widget to be denied"
            assert "denied" in text.lower(), f"expected a denial message, got: {text!r}"
            assert "frobnicated=" not in text, "the upstream's own return value leaked through a supposedly denied call!"
            print("PASS: denied -- rule + reason + decision_id relayed, upstream never dispatched "
                  "(response is the gateway's own denial text, not the upstream's return value)")

    print("\n[e2e_enforce_holds] ALL CHECKS PASSED")


if __name__ == "__main__":
    argv = sys.argv[1:]
    auto = "--auto-resolve" in argv
    argv = [a for a in argv if a != "--auto-resolve"]
    core_url = os.environ.get("REEFLEX_CORE_URL", "http://127.0.0.1:8080")

    if argv:
        config_arg = argv[0]
    else:
        _python = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable
        config_arg = _generate_config(python=_python)
        print(f"[e2e_enforce_holds] generated config at {config_arg}")

    asyncio.run(main(config_arg, auto, core_url))
