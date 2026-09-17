"""
RFX-338 -- a `file_path` reached `_SENSITIVE_PATH_RE` uncapped.

WHAT THE DEFECT WAS, in one paragraph, because these tests only make sense
against it.  `_classify_write` and `_classify_edit` ran
`_SENSITIVE_PATH_RE.search(file_path_str)` with no length bound.  That pattern
holds `docker-compose.*\\.ya?ml$` -- a `.*` in front of an anchored suffix --
which is quadratic on a long subject that never satisfies the anchor: 64 KB
0.22 s, 256 KB 3.36 s, 1 MB 50.6 s, in ONE `re.search`.  RFX-321's deadline
watchdog does not save it, because the watchdog is a `threading.Timer` and
CPython's `sre` engine holds the GIL for the whole match, so the timer thread
cannot run until the match returns (qa--233 measured the timer firing at +0.01 s
against a Python loop and at work-end against a regex, independent of the
budget).  The hook therefore ran past the 30 s PreToolUse timeout, the runner
killed it, and a killed PreToolUse hook means the tool RUNS -- ungated, and with
no audit line.

WHAT THESE TESTS ARE, split on purpose:

  * TestPathCapIsHeld -- the PERFORMANCE property that changed.  Every test in
    it FAILS on the pre-fix tree (the ladder alone costs ~54 s there).
  * TestClassificationUnchanged -- the BEHAVIOUR that must NOT have changed.
    Every test in it PASSES on the pre-fix tree.  A cap that fires early would
    stop classifying real paths, and only this class would notice.

The split is the point: if the second class failed on the old tree too, the
suite would not be able to tell "I made it fast" from "I made it wrong".
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import (  # noqa: E402
    MAX_FILE_PATH_CHARS,
    classify,
)

# The four routes that reached the uncapped pattern.  Edit/MultiEdit/
# NotebookEdit share `_classify_edit`; Write has its own arm.  Naming all four
# rather than the two functions is deliberate -- the reachable surface is what a
# caller can send, and a future dispatcher change that adds a fifth tool to the
# edit family should be covered by name here.
EDIT_TOOLS = ("Edit", "MultiEdit", "NotebookEdit")
ALL_PATH_TOOLS = ("Write",) + EDIT_TOOLS


def adversarial_path(n: int) -> str:
    """
    The quadratic subject: repeated `docker-compose` never satisfies the
    `\\.ya?ml$` anchor, so the `.*` backtracks over the whole subject.  A random
    or benign string is NOT a substitute -- it finishes immediately and would
    make every guard below vacuous.
    """
    return "docker-compose" * (n // 14)


# ---------------------------------------------------------------------------
# The property that CHANGED.  These fail on the pre-fix tree.
# ---------------------------------------------------------------------------

class TestPathCapIsHeld(unittest.TestCase):

    def test_the_whole_size_ladder_costs_less_than_one_second(self):
        """
        Pre-fix this ladder costs ~54 s -- 50.6 s of it in the 1 MB rung alone,
        against a 30 s runner timeout.  The budget is absolute, not a ratio,
        because after the fix every rung is sub-millisecond and a ratio between
        two sub-millisecond numbers measures the clock, not the code.
        """
        started = time.monotonic()
        for n in (8_000, 64_000, 256_000, 1_000_000):
            classify("Write", {"file_path": adversarial_path(n)})
        spent = time.monotonic() - started
        self.assertLess(
            spent, 1.0,
            f"classifying the path ladder spent {spent:.2f}s; the runner kills "
            f"the hook at 30s and then RUNS the tool")

    def test_every_reachable_route_is_bounded_not_just_write(self):
        """
        qa--233 named Write and Edit.  MultiEdit and NotebookEdit reach the same
        arm, and a fix that bounded one function would still leave the tool
        surface open if the dispatcher grew.
        """
        payload = adversarial_path(1_000_000)
        for tool in ALL_PATH_TOOLS:
            started = time.monotonic()
            cls = classify(tool, {"file_path": payload})
            spent = time.monotonic() - started
            self.assertLess(spent, 1.0, f"{tool} spent {spent:.2f}s on a 1MB path")
            self.assertEqual(cls["danger_signature"], "oversize_path", tool)

    def test_the_oversize_reading_is_the_conservative_one(self):
        path = adversarial_path(1_000_000)
        for tool, verb in (("Write", "create"), ("Edit", "update")):
            cls = classify(tool, {"file_path": path})
            self.assertEqual(cls["reversibility"], "irreversible", tool)
            self.assertEqual(cls["blast_radius"], "systemic", tool)
            self.assertEqual(cls["classification_tier"], "destructive_systemic", tool)
            # The verb is still the caller's: we could not read the target, but
            # the tool name told us what was being done to it.
            self.assertEqual(cls["verb"], verb, tool)

    def test_the_megabyte_does_not_reach_the_envelope(self):
        """
        `envelope.py` puts `file_path` on the wire and into the audit line
        verbatim.  Trading a hung classifier for a megabyte POST to core would
        be a different defect with the same cause, and it would falsify the
        premise hook.py's oversize refusal states out loud ("the envelope is
        small").
        """
        cls = classify("Write", {"file_path": adversarial_path(1_000_000)})
        self.assertIsNone(cls["file_path"])
        self.assertIsNone(cls["target_ref"])
        self.assertLessEqual(len(cls["command_preview"] or ""), 200)

    def test_one_over_the_cap_is_refused(self):
        cls = classify("Write", {"file_path": "a" * (MAX_FILE_PATH_CHARS + 1)})
        self.assertEqual(cls["danger_signature"], "oversize_path")


# ---------------------------------------------------------------------------
# The property that did NOT change.  These pass on the pre-fix tree too.
# ---------------------------------------------------------------------------

class TestClassificationUnchanged(unittest.TestCase):

    def test_at_the_cap_the_path_is_still_read_normally(self):
        """A cap that fires one character early stops classifying real paths."""
        cls = classify("Write", {"file_path": "a" * MAX_FILE_PATH_CHARS})
        self.assertNotEqual(cls["danger_signature"], "oversize_path")
        self.assertEqual(cls["verb"], "create")

    def test_the_cap_is_above_every_path_an_os_will_accept(self):
        """
        4096 is Linux PATH_MAX; macOS is 1024.  If this ever drops below the
        longest path a caller can actually open, the cap has started refusing
        real work instead of refusing payloads.
        """
        self.assertGreaterEqual(MAX_FILE_PATH_CHARS, 4096)

    def test_a_sensitive_path_is_still_broad(self):
        cls = classify("Write", {"file_path": "/srv/app/docker-compose.yml"})
        self.assertEqual(cls["blast_radius"], "broad")
        self.assertEqual(cls["danger_signature"], "sensitive_write")

    def test_an_ordinary_path_is_still_single(self):
        cls = classify("Write", {"file_path": "/tmp/notes.txt"})
        self.assertEqual(cls["blast_radius"], "single")
        self.assertEqual(cls["danger_signature"], "disk_write")

    def test_a_sensitive_edit_is_still_scoped(self):
        for tool in EDIT_TOOLS:
            cls = classify(tool, {"file_path": "/srv/app/.env"})
            self.assertEqual(cls["blast_radius"], "scoped", tool)
            self.assertEqual(cls["danger_signature"], "sensitive_write", tool)

    def test_an_ordinary_edit_is_still_single(self):
        cls = classify("Edit", {"file_path": "/tmp/notes.txt"})
        self.assertEqual(cls["blast_radius"], "single")
        self.assertEqual(cls["verb"], "update")

    def test_an_empty_path_is_not_an_oversize_path(self):
        cls = classify("Write", {"file_path": ""})
        self.assertNotEqual(cls["danger_signature"], "oversize_path")


# ---------------------------------------------------------------------------
# End to end: the adapter's own refusal, against an engine that allows.
# ---------------------------------------------------------------------------

class _AllowHandler(http.server.BaseHTTPRequestHandler):
    """An engine that says allow to everything, so any deny is the adapter's."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        body = json.dumps({
            "decision": "allow",
            "rule_id": "stub/allow_everything",
            "reason": "stub",
            "obligations": [],
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


def _start_allow_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _AllowHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _write_payload(file_path: str, tool: str = "Write") -> str:
    return json.dumps({
        "session_id": "rfx338-test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": file_path, "content": "x"},
        "cwd": "/tmp",
    })


class TestHookRefusesTheOversizePath(unittest.TestCase):

    def _run(self, payload: str, audit_path: str, timeout: float = 30):
        env = dict(os.environ)
        env["REEFLEX_CLAUDE_AUDIT_LOG"] = audit_path
        env["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{self.port}"
        proc = subprocess.run(
            [sys.executable, "-m", "reeflex_claude"],
            input=payload.encode("utf-8"),
            capture_output=True, cwd=_PARENT, env=env, timeout=timeout,
        )
        text = proc.stdout.decode("utf-8", errors="replace").strip()
        lines = [ln for ln in text.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, f"expected one stdout line, got {text!r}")
        return json.loads(lines[0])["hookSpecificOutput"]

    def setUp(self):
        self.server, self.port = _start_allow_server()
        self.addCleanup(self.server.shutdown)
        self.tmp = tempfile.mkdtemp(prefix="rfx338-")

    def test_an_oversize_path_is_denied_by_the_adapter(self):
        """
        Pre-fix this arm does not fail with a wrong answer -- it produces NO
        answer, because the hook is still inside the regex when the timeout
        expires.  That is the fail-open.
        """
        audit = os.path.join(self.tmp, "deny.jsonl")
        out = self._run(_write_payload(adversarial_path(1_000_000)), audit)
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("adapter/path_too_long", out["permissionDecisionReason"])

    def test_the_same_engine_still_allows_a_normal_path(self):
        """
        The control for the test above: the cap is the cause of the deny, not
        the stub and not the hook refusing everything.
        """
        audit = os.path.join(self.tmp, "allow.jsonl")
        out = self._run(_write_payload("/tmp/rfx338-ordinary.txt"), audit)
        self.assertEqual(out["permissionDecision"], "allow")

    def test_the_refused_action_is_recorded(self):
        """
        The other half of the defect: a killed hook writes no audit line, so the
        action was unrecorded as well as ungated.  A refusal that is invisible
        to the ledger has closed only half of this.
        """
        audit = os.path.join(self.tmp, "recorded.jsonl")
        self._run(_write_payload(adversarial_path(1_000_000)), audit)
        self.assertTrue(os.path.exists(audit), "no audit file was written")
        with open(audit, "r", encoding="utf-8") as fh:
            lines = [json.loads(ln) for ln in fh if ln.strip()]
        self.assertTrue(
            any("path_too_long" in json.dumps(ln) for ln in lines),
            f"no audit record names the refusal; got {len(lines)} line(s)")


if __name__ == "__main__":
    unittest.main()
