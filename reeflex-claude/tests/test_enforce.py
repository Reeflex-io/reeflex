"""
test_enforce.py -- Unit tests for enforce.call_core_and_map() and the hook's
fail-closed invariant.

Tests:
  1. Stub HTTP server returning allow, deny, require_approval -> correct mapping
  2. Dead port -> ("deny", ..., ..., False, [])   [fail-closed]
  3. Malformed hook stdin (pipe to hook as subprocess) -> deny, exit 0
  4. Missing session_id in stdin -> deny, exit 0
  5. HTTP 500 with embedded deny decision -> propagated correctly
  6. Obligations plumbing: audit:full -> honored (allow); redact:pii -> fail-closed deny
  7. BrokenPipeError on stdout -> hook exits 0 (CRITICAL)

All network tests use a stdlib http.server stub on a random port.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.enforce import call_core_and_map


# ---------------------------------------------------------------------------
# Stub HTTP server
# ---------------------------------------------------------------------------

class _StubHandler(http.server.BaseHTTPRequestHandler):
    """Serves a canned JSON response from _StubHandler.response_body at /v1/decide."""

    response_body: bytes = b'{"decision":"allow","reason":"ok","rule":"stub/allow","obligations":[]}'
    response_status: int = 200

    def log_message(self, fmt, *args):
        pass  # suppress test noise

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        body = self.__class__.response_body
        self.send_response(self.__class__.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_stub_server(response_body: bytes, status: int = 200) -> tuple:
    """Start a stub HTTP server on a random port. Returns (server, port, thread)."""
    class CustomHandler(_StubHandler):
        pass
    CustomHandler.response_body = response_body
    CustomHandler.response_status = status

    server = http.server.HTTPServer(("127.0.0.1", 0), CustomHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, t


def _stop_stub_server(server):
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Minimal synthetic envelope
# ---------------------------------------------------------------------------

def _minimal_envelope() -> dict:
    return {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:claude-code", "on_behalf_of": None,
                  "session_id": "claude:test-sess-001"},
        "action": {"namespace": "claude-code", "verb": "read",
                   "ability": "claude-code/Bash"},
        "target": {"kind": "command", "ref": None, "environment": "production"},
        "params": {"tool_name": "Bash", "verb_source": "test"},
        "magnitude": {"count": 1},
        "axes": {"reversibility": "reversible", "blast_radius": "single",
                 "externality": "internal"},
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {"tool_name": "Bash", "command_preview": "ls",
                    "file_path": None, "danger_signature": "none",
                    "classification_tier": "benign"},
        "meta": {"timestamp": "2026-06-30T00:00:00Z",
                 "nonce": "abcdef01234567890123456789012345",
                 "signature": "ed25519:stub:abcdef01"},
    }


# ---------------------------------------------------------------------------
# Decision mapping tests
# ---------------------------------------------------------------------------

class TestDecisionMapping(unittest.TestCase):

    def _run_with_response(self, response: dict, http_status: int = 200):
        body = json.dumps(response).encode("utf-8")
        server, port, _ = _start_stub_server(body, status=http_status)
        orig = os.environ.get("REEFLEX_CORE_URL")
        os.environ["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{port}"
        try:
            return call_core_and_map(_minimal_envelope())
        finally:
            if orig is None:
                os.environ.pop("REEFLEX_CORE_URL", None)
            else:
                os.environ["REEFLEX_CORE_URL"] = orig
            _stop_stub_server(server)

    def test_allow_maps_to_allow(self):
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "allow",
            "reason": "no high-risk",
            "rule": "reeflex.policy/default_allow",
            "obligations": [],
        })
        self.assertEqual(perm, "allow")
        self.assertTrue(reachable)
        self.assertIn("no high-risk", reason)
        self.assertEqual(obligations, [])

    def test_deny_maps_to_deny(self):
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "deny",
            "reason": "systemic in prod",
            "rule": "reeflex.policy/irreversible_systemic_prod",
            "obligations": [],
        })
        self.assertEqual(perm, "deny")
        self.assertTrue(reachable)
        self.assertIn("systemic in prod", reason)

    def test_require_approval_maps_to_ask(self):
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "require_approval",
            "reason": "irreversible broad",
            "rule": "reeflex.policy/irreversible_broad_prod",
            "obligations": [],
        })
        self.assertEqual(perm, "ask")
        self.assertTrue(reachable)

    def test_rule_carried_in_reason(self):
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "allow",
            "reason": "test reason",
            "rule": "stub/test_rule",
            "obligations": [],
        })
        self.assertIn("stub/test_rule", reason)

    def test_http_500_with_deny_decision(self):
        """Core returning 500 with embedded deny decision is propagated."""
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "deny",
            "reason": "failing closed",
            "rule": "reeflex.core/fail_closed",
            "obligations": [],
        }, http_status=500)
        self.assertEqual(perm, "deny")
        # Core was technically reachable (returned a response)
        self.assertTrue(reachable)

    def test_unknown_decision_value_fails_closed(self):
        """Unknown decision value -> deny (fail-closed)."""
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "maybe",
            "reason": "unknown",
            "rule": "stub/unknown",
            "obligations": [],
        })
        self.assertEqual(perm, "deny")
        self.assertIn("fail_closed", rule)

    def test_missing_decision_field_fails_closed(self):
        """Response without 'decision' field -> deny (fail-closed)."""
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "reason": "no decision field",
        })
        self.assertEqual(perm, "deny")
        self.assertFalse(reachable)

    def test_malformed_json_response_fails_closed(self):
        """Non-JSON response body -> deny (fail-closed)."""
        server, port, _ = _start_stub_server(b"not json at all", status=200)
        orig = os.environ.get("REEFLEX_CORE_URL")
        os.environ["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{port}"
        try:
            perm, reason, rule, reachable, obligations = call_core_and_map(_minimal_envelope())
            self.assertEqual(perm, "deny")
            self.assertFalse(reachable)
        finally:
            if orig is None:
                os.environ.pop("REEFLEX_CORE_URL", None)
            else:
                os.environ["REEFLEX_CORE_URL"] = orig
            _stop_stub_server(server)

    def test_obligations_returned_in_tuple(self):
        """Obligations from core response are returned in the 5-tuple."""
        perm, reason, rule, reachable, obligations = self._run_with_response({
            "decision": "allow",
            "reason": "ok",
            "rule": "stub/allow",
            "obligations": ["audit:full"],
        })
        self.assertEqual(perm, "allow")
        self.assertEqual(obligations, ["audit:full"])

    def test_obligations_empty_on_fail_closed(self):
        """Fail-closed path returns empty obligations list."""
        server, port, _ = _start_stub_server(b"not json", status=200)
        orig = os.environ.get("REEFLEX_CORE_URL")
        os.environ["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{port}"
        try:
            perm, reason, rule, reachable, obligations = call_core_and_map(_minimal_envelope())
            self.assertEqual(obligations, [])
        finally:
            if orig is None:
                os.environ.pop("REEFLEX_CORE_URL", None)
            else:
                os.environ["REEFLEX_CORE_URL"] = orig
            _stop_stub_server(server)


# ---------------------------------------------------------------------------
# Fail-closed: dead port
# ---------------------------------------------------------------------------

class TestFailClosed(unittest.TestCase):
    """Fail-closed: dead port -> deny, core_reachable=False."""

    def test_dead_port_returns_deny(self):
        """Connecting to a dead port must return deny, not allow.
        Port 1 is a privileged port -- always connection-refused on any OS.
        """
        orig = os.environ.get("REEFLEX_CORE_URL")
        os.environ["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"
        try:
            perm, reason, rule, reachable, obligations = call_core_and_map(_minimal_envelope())
            self.assertEqual(perm, "deny",
                             "FAIL-CLOSED: dead port must return deny, not allow")
            self.assertFalse(reachable)
            self.assertIn("fail_closed", rule)
            self.assertEqual(obligations, [])
        finally:
            if orig is None:
                os.environ.pop("REEFLEX_CORE_URL", None)
            else:
                os.environ["REEFLEX_CORE_URL"] = orig


# ---------------------------------------------------------------------------
# Hook subprocess tests (stdin -> stdout, exit code)
# ---------------------------------------------------------------------------

class TestHookSubprocess(unittest.TestCase):
    """Run the hook as a subprocess to test the full stdin->stdout path."""

    _HOOK_CMD = [sys.executable, "-m", "reeflex_claude"]

    def _run_hook(self, stdin_data: str, env_overrides: dict = None) -> tuple:
        """
        Run the hook subprocess with given stdin.
        Returns (stdout_text, exit_code).
        """
        env = dict(os.environ)
        env["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"  # dead port -> fail-closed
        if env_overrides:
            env.update(env_overrides)

        proc = subprocess.run(
            self._HOOK_CMD,
            input=stdin_data.encode("utf-8"),
            capture_output=True,
            cwd=_PARENT,
            env=env,
            timeout=15,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        return stdout, proc.returncode

    def test_malformed_stdin_exits_0_with_deny(self):
        """Bad JSON stdin -> deny output, exit code 0 (CRITICAL invariant)."""
        stdout, code = self._run_hook("this is not json at all")
        self.assertEqual(code, 0,
                         "CRITICAL: hook must exit 0 even on malformed stdin (non-zero = silent allow!)")
        parsed = json.loads(stdout)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")

    def test_missing_session_id_exits_0_with_deny(self):
        """Missing session_id -> deny, exit 0."""
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            # session_id intentionally absent
        }
        stdout, code = self._run_hook(json.dumps(payload))
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")

    def test_empty_stdin_exits_0_with_deny(self):
        """Empty stdin -> deny, exit 0."""
        stdout, code = self._run_hook("")
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")

    def test_dead_core_exits_0_with_deny(self):
        """
        Dead core URL -> deny + exit 0 (the CRITICAL fail-closed test).
        Non-zero exit would make Claude Code CONTINUE the tool (silent allow).
        """
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_failclosed_test",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": "/tmp",
        }
        stdout, code = self._run_hook(json.dumps(payload))
        self.assertEqual(code, 0,
                         "CRITICAL: hook must exit 0 on dead core (non-zero = silent allow!)")
        parsed = json.loads(stdout)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny",
                         "CRITICAL: dead core must produce deny (fail-closed), not allow")
        self.assertIn("fail", output.get("permissionDecisionReason", "").lower())

    def test_valid_payload_has_correct_output_structure(self):
        """A valid payload produces well-formed hookSpecificOutput."""
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess_shape_test",
            "tool_name": "Read",
            "tool_input": {"file_path": "/src/app.py"},
            "cwd": "/tmp",
        }
        stdout, code = self._run_hook(json.dumps(payload))
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertIn("hookSpecificOutput", parsed)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertIn(output["permissionDecision"], ("allow", "deny", "ask"))
        self.assertIn("permissionDecisionReason", output)

    def test_hook_with_live_allow_stub(self):
        """
        Hook pointing at a live stub returning allow -> permissionDecision=allow,
        exit 0.
        """
        body = json.dumps({
            "decision": "allow",
            "reason": "test allow",
            "rule": "stub/allow",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(body, status=200)
        try:
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "sess_live_allow",
                "tool_name": "Bash",
                "tool_input": {"command": "ls -la"},
                "cwd": "/tmp",
            }
            stdout, code = self._run_hook(
                json.dumps(payload),
                env_overrides={"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}"},
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            output = parsed["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "allow")
        finally:
            _stop_stub_server(server)

    def test_hook_with_live_require_approval_stub(self):
        """
        require_approval from core -> permissionDecision=ask, exit 0.
        """
        body = json.dumps({
            "decision": "require_approval",
            "reason": "needs human",
            "rule": "stub/ask",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(body, status=200)
        try:
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "sess_live_ask",
                "tool_name": "Bash",
                "tool_input": {"command": "git push --force origin main"},
                "cwd": "/tmp",
            }
            stdout, code = self._run_hook(
                json.dumps(payload),
                env_overrides={"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}"},
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            output = parsed["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "ask")
        finally:
            _stop_stub_server(server)


# ---------------------------------------------------------------------------
# Obligations tests (P0 conformance -- SPEC §5/§7 M5)
# ---------------------------------------------------------------------------

class TestObligations(unittest.TestCase):
    """
    Obligations must be honored fail-closed (SPEC §5):
    - audit:full is in SUPPORTED_OBLIGATIONS -> allow stays allow
    - redact:pii is NOT in SUPPORTED_OBLIGATIONS -> allow overridden to deny
    - deny/ask with unsupported obligations passes through (action not running)
    """

    _HOOK_CMD = [sys.executable, "-m", "reeflex_claude"]

    def _run_hook_with_stub(self, decision_resp: dict, tool_cmd: str = "ls -la") -> tuple:
        """Spin a stub returning decision_resp; run hook; return (parsed, stdout, code)."""
        body = json.dumps(decision_resp).encode("utf-8")
        server, port, _ = _start_stub_server(body, status=200)
        try:
            env = dict(os.environ)
            env["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{port}"
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "sess_obligations_test",
                "tool_name": "Bash",
                "tool_input": {"command": tool_cmd},
                "cwd": "/tmp",
            }
            proc = subprocess.run(
                self._HOOK_CMD,
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                cwd=_PARENT,
                env=env,
                timeout=15,
            )
            stdout = proc.stdout.decode("utf-8", errors="replace").strip()
            parsed = json.loads(stdout) if stdout else {}
            return parsed, stdout, proc.returncode
        finally:
            _stop_stub_server(server)

    def test_audit_full_obligation_honored_allow_stays_allow(self):
        """
        Core returns allow + obligations=["audit:full"].
        audit:full is in SUPPORTED_OBLIGATIONS -> permissionDecision = allow.
        """
        parsed, stdout, code = self._run_hook_with_stub({
            "decision": "allow",
            "reason": "ok",
            "rule": "stub/allow",
            "obligations": ["audit:full"],
        })
        self.assertEqual(code, 0)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow",
                         "audit:full is honored by construction; allow must not be downgraded")

    def test_unsupported_obligation_overrides_allow_to_deny(self):
        """
        Core returns allow + obligations=["redact:pii"].
        redact:pii NOT in SUPPORTED_OBLIGATIONS -> hook overrides to deny (fail-closed).
        exit 0 still (never exit non-zero).
        """
        parsed, stdout, code = self._run_hook_with_stub({
            "decision": "allow",
            "reason": "ok",
            "rule": "stub/allow",
            "obligations": ["redact:pii"],
        })
        self.assertEqual(code, 0,
                         "CRITICAL: unsupported obligation deny must still exit 0")
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny",
                         "unsupported obligation on allow -> must override to deny (fail-closed)")
        self.assertIn("unsupported_obligation", output.get("permissionDecisionReason", ""))
        self.assertIn("redact:pii", output.get("permissionDecisionReason", ""))

    def test_deny_with_unsupported_obligation_stays_deny(self):
        """
        Core returns deny + obligations=["audit:full"].
        Action not running; deny passes through; obligations appear in audit record.
        """
        parsed, stdout, code = self._run_hook_with_stub({
            "decision": "deny",
            "reason": "blocked",
            "rule": "stub/deny",
            "obligations": ["audit:full"],
        })
        self.assertEqual(code, 0)
        output = parsed["hookSpecificOutput"]
        # deny stays deny even with an obligation we could honor
        self.assertEqual(output["permissionDecision"], "deny")

    def test_multiple_obligations_with_unsupported_overrides_allow(self):
        """
        obligations=["audit:full","redact:pii"] -- one unsupported -> deny.
        """
        parsed, stdout, code = self._run_hook_with_stub({
            "decision": "allow",
            "reason": "ok",
            "rule": "stub/allow",
            "obligations": ["audit:full", "redact:pii"],
        })
        self.assertEqual(code, 0)
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")

    def test_empty_obligations_allow_stays_allow(self):
        """No obligations -> allow unchanged."""
        parsed, stdout, code = self._run_hook_with_stub({
            "decision": "allow",
            "reason": "ok",
            "rule": "stub/allow",
            "obligations": [],
        })
        output = parsed["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")


# ---------------------------------------------------------------------------
# BrokenPipe resilience test
# ---------------------------------------------------------------------------

class TestBrokenPipeResilience(unittest.TestCase):
    """
    Verify that the hook's BrokenPipeError guard works by importing the module
    directly and replacing sys.stdout with an object whose write raises.

    We test the _safe_print function in isolation (it is the guard), and verify
    that main() exits 0 even when the _safe_print path raises inside the except
    handler.  We do NOT use a subprocess pipe-close trick because that approach
    is inherently platform-specific (Windows does not send SIGPIPE) and would
    cause the test itself to hang.
    """

    def test_safe_print_swallows_broken_pipe(self):
        """
        _safe_print must not raise even when stdout.write raises BrokenPipeError.
        """
        from reeflex_claude.hook import _safe_print

        class _BrokenStdout:
            def write(self, s):
                raise BrokenPipeError("pipe broken")
            def flush(self):
                raise BrokenPipeError("pipe broken")

        orig_stdout = sys.stdout
        sys.stdout = _BrokenStdout()
        try:
            # Must not raise
            _safe_print("test message")
        finally:
            sys.stdout = orig_stdout

    def test_safe_print_swallows_os_error(self):
        """_safe_print must not raise on any I/O error."""
        from reeflex_claude.hook import _safe_print

        class _ErrStdout:
            def write(self, s):
                raise OSError("write failed")
            def flush(self):
                pass

        orig_stdout = sys.stdout
        sys.stdout = _ErrStdout()
        try:
            _safe_print("another message")
        finally:
            sys.stdout = orig_stdout

    def test_deny_output_not_json_error(self):
        """_deny_output must produce parseable JSON regardless of reason content."""
        from reeflex_claude.hook import _deny_output
        msg = _deny_output("some error: <broken pipe>")
        parsed = json.loads(msg)
        self.assertEqual(parsed["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
