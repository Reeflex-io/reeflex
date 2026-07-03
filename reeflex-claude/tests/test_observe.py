"""
test_observe.py -- Tests for REEFLEX_MODE=observe (HIL-DESIGN §8).

Verifies:
  1. observe mode with core returning deny -> emitted permissionDecision=allow,
     audit record has mode=observe and the would-be decision=deny.
  2. observe mode with core unreachable (dead port) -> emitted allow (fail-open),
     audit record written with mode=observe.
  3. _fail_output returns allow in observe, deny in enforce (unit test).
  4. enforce mode (default/unset) with core returning deny -> emitted deny
     (enforce path unchanged).
  5. observe mode early-error paths (bad stdin, missing session_id) -> emitted
     allow (fail-open), exit 0.

All network tests use a stdlib http.server stub on a random port or a dead port.
Tests are hermetic: no real network, audit log redirected to tmp_path via env var.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


# ---------------------------------------------------------------------------
# Stub HTTP server (mirrors test_enforce.py style)
# ---------------------------------------------------------------------------

class _StubHandler(http.server.BaseHTTPRequestHandler):
    response_body: bytes = b'{"decision":"deny","reason":"stubbed deny","rule":"stub/deny","obligations":[]}'
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


def _start_stub_server(response_body: bytes, status: int = 200):
    """Start a stub HTTP server on a random port. Returns (server, port, thread)."""
    class _Handler(_StubHandler):
        pass
    _Handler.response_body = response_body
    _Handler.response_status = status

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, t


def _stop_stub_server(server):
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOOK_CMD = [sys.executable, "-m", "reeflex_claude"]

_VALID_PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "session_id": "sess_observe_test",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /"},
    "cwd": "/tmp",
}


def _run_hook(stdin_data: str, env_overrides: dict = None):
    """Run the hook as a subprocess. Returns (stdout_text, exit_code)."""
    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(
        _HOOK_CMD,
        input=stdin_data.encode("utf-8"),
        capture_output=True,
        cwd=_PARENT,
        env=env,
        timeout=15,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    return stdout, proc.returncode


def _read_last_audit_record(log_path: str) -> dict:
    """Read the last JSONL record from the audit log. Raises if empty."""
    with open(log_path, encoding="utf-8") as fh:
        lines = [l.strip() for l in fh if l.strip()]
    if not lines:
        raise AssertionError(f"Audit log is empty: {log_path}")
    return json.loads(lines[-1])


# ---------------------------------------------------------------------------
# Unit tests for _mode() / _fail_output()
# ---------------------------------------------------------------------------

class TestFailOutputUnit(unittest.TestCase):
    """_fail_output returns allow in observe, deny in enforce."""

    def _set_mode(self, mode: str):
        os.environ["REEFLEX_MODE"] = mode

    def _clear_mode(self):
        os.environ.pop("REEFLEX_MODE", None)

    def tearDown(self):
        self._clear_mode()

    def test_fail_output_enforce_returns_deny(self):
        """In enforce mode, _fail_output must produce deny."""
        from reeflex_claude.hook import _fail_output
        self._set_mode("enforce")
        result = _fail_output("some error")
        parsed = json.loads(result)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_fail_output_observe_returns_allow(self):
        """In observe mode, _fail_output must produce allow (fail-open)."""
        from reeflex_claude.hook import _fail_output
        self._set_mode("observe")
        result = _fail_output("some error")
        parsed = json.loads(result)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "allow"
        )

    def test_fail_output_default_is_enforce(self):
        """With REEFLEX_MODE unset, _fail_output defaults to enforce -> deny."""
        from reeflex_claude.hook import _fail_output
        self._clear_mode()
        result = _fail_output("some error")
        parsed = json.loads(result)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_mode_case_insensitive(self):
        """REEFLEX_MODE=OBSERVE (uppercase) is treated as observe."""
        from reeflex_claude.hook import _mode
        os.environ["REEFLEX_MODE"] = "OBSERVE"
        try:
            self.assertEqual(_mode(), "observe")
        finally:
            self._clear_mode()

    def test_mode_unknown_value_defaults_to_enforce(self):
        """An unrecognised REEFLEX_MODE value is treated as enforce."""
        from reeflex_claude.hook import _mode
        os.environ["REEFLEX_MODE"] = "shadow"
        try:
            self.assertEqual(_mode(), "enforce")
        finally:
            self._clear_mode()


# ---------------------------------------------------------------------------
# Observe mode: core returns deny -> hook emits allow, audit records deny
# ---------------------------------------------------------------------------

class TestObserveDenyBecomesAllow(unittest.TestCase):
    """
    Core returns deny.  In observe mode the emitted permissionDecision must be
    allow, and the audit record must carry mode=observe with the would-be deny.
    """

    def test_observe_deny_emits_allow_and_audits_deny(self):
        deny_body = json.dumps({
            "decision": "deny",
            "reason": "irreversible systemic in prod",
            "rule": "reeflex.policy/deny_test",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(deny_body, status=200)

        with tempfile.NamedTemporaryFile(
            suffix="-observe-audit.jsonl", delete=False
        ) as tmp:
            audit_path = tmp.name

        try:
            stdout, code = _run_hook(
                json.dumps(_VALID_PAYLOAD),
                env_overrides={
                    "REEFLEX_MODE": "observe",
                    "REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                    "REEFLEX_CLAUDE_AUDIT_LOG": audit_path,
                },
            )
            # 1. Exit 0 always
            self.assertEqual(code, 0)

            # 2. Emitted decision must be allow
            parsed = json.loads(stdout)
            output = parsed["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "PreToolUse")
            self.assertEqual(
                output["permissionDecision"], "allow",
                "observe mode: deny from core must emit allow (fail-open)",
            )
            # Reason should mention the would-be verdict
            reason = output.get("permissionDecisionReason", "")
            self.assertIn("observe", reason.lower())
            self.assertIn("deny", reason.lower())

            # 3. Audit record must record the would-be deny and mode=observe
            record = _read_last_audit_record(audit_path)
            self.assertEqual(record.get("mode"), "observe",
                             "audit record must carry mode=observe")
            self.assertIn(
                record.get("permission_decision"), ("deny",),
                "audit record must carry the would-be permission_decision=deny",
            )
            self.assertIn(
                record.get("decision"), ("deny",),
                "audit record decision must be the would-be deny",
            )
        finally:
            _stop_stub_server(server)
            try:
                os.unlink(audit_path)
            except OSError:
                pass

    def test_observe_require_approval_emits_allow_audits_ask(self):
        """Core returns require_approval; observe emits allow, audits ask."""
        ask_body = json.dumps({
            "decision": "require_approval",
            "reason": "needs human review",
            "rule": "reeflex.policy/ask_test",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(ask_body, status=200)

        with tempfile.NamedTemporaryFile(
            suffix="-observe-ask-audit.jsonl", delete=False
        ) as tmp:
            audit_path = tmp.name

        try:
            stdout, code = _run_hook(
                json.dumps(_VALID_PAYLOAD),
                env_overrides={
                    "REEFLEX_MODE": "observe",
                    "REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                    "REEFLEX_CLAUDE_AUDIT_LOG": audit_path,
                },
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            self.assertEqual(
                parsed["hookSpecificOutput"]["permissionDecision"], "allow"
            )
            record = _read_last_audit_record(audit_path)
            self.assertEqual(record.get("mode"), "observe")
            self.assertEqual(record.get("permission_decision"), "ask")
        finally:
            _stop_stub_server(server)
            try:
                os.unlink(audit_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Observe mode: core unreachable -> fail-open (allow), mode=observe in audit
# ---------------------------------------------------------------------------

class TestObserveFailOpen(unittest.TestCase):
    """
    When core is unreachable in observe mode, the hook must emit allow (fail-open),
    audit the record with mode=observe, and exit 0.
    """

    def test_dead_core_observe_emits_allow(self):
        with tempfile.NamedTemporaryFile(
            suffix="-observe-failopen.jsonl", delete=False
        ) as tmp:
            audit_path = tmp.name

        try:
            stdout, code = _run_hook(
                json.dumps(_VALID_PAYLOAD),
                env_overrides={
                    "REEFLEX_MODE": "observe",
                    "REEFLEX_CORE_URL": "http://127.0.0.1:1",  # dead port
                    "REEFLEX_CLAUDE_AUDIT_LOG": audit_path,
                },
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            self.assertEqual(
                parsed["hookSpecificOutput"]["permissionDecision"], "allow",
                "observe+dead core must emit allow (fail-open)",
            )
            # Audit record should also be written and carry mode=observe
            record = _read_last_audit_record(audit_path)
            self.assertEqual(record.get("mode"), "observe")
        finally:
            try:
                os.unlink(audit_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Observe mode: early error paths -> allow (fail-open), exit 0
# ---------------------------------------------------------------------------

class TestObserveEarlyErrors(unittest.TestCase):
    """
    Bad stdin, missing session_id -> allow in observe mode (fail-open), exit 0.
    """

    def test_bad_stdin_observe_emits_allow(self):
        """Bad JSON stdin in observe mode -> allow (fail-open), exit 0."""
        stdout, code = _run_hook(
            "not valid json",
            env_overrides={
                "REEFLEX_MODE": "observe",
                "REEFLEX_CORE_URL": "http://127.0.0.1:1",
            },
        )
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "allow"
        )
        reason = parsed["hookSpecificOutput"].get("permissionDecisionReason", "")
        self.assertIn("observe", reason.lower())

    def test_missing_session_id_observe_emits_allow(self):
        """Missing session_id in observe mode -> allow (fail-open), exit 0."""
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            # session_id intentionally absent
        }
        stdout, code = _run_hook(
            json.dumps(payload),
            env_overrides={
                "REEFLEX_MODE": "observe",
                "REEFLEX_CORE_URL": "http://127.0.0.1:1",
            },
        )
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "allow"
        )


# ---------------------------------------------------------------------------
# Sanity: enforce mode unchanged (deny still emits deny)
# ---------------------------------------------------------------------------

class TestEnforceUnchanged(unittest.TestCase):
    """
    Regression guard: enforce mode (default) with core returning deny must
    still emit deny.  The enforce path must be unaffected by this change.
    """

    def test_enforce_deny_still_emits_deny(self):
        """REEFLEX_MODE=enforce + core deny -> permissionDecision=deny."""
        deny_body = json.dumps({
            "decision": "deny",
            "reason": "blocked in enforce",
            "rule": "stub/enforce_deny",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(deny_body, status=200)

        with tempfile.NamedTemporaryFile(
            suffix="-enforce-sanity.jsonl", delete=False
        ) as tmp:
            audit_path = tmp.name

        try:
            stdout, code = _run_hook(
                json.dumps(_VALID_PAYLOAD),
                env_overrides={
                    "REEFLEX_MODE": "enforce",
                    "REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                    "REEFLEX_CLAUDE_AUDIT_LOG": audit_path,
                },
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            self.assertEqual(
                parsed["hookSpecificOutput"]["permissionDecision"], "deny",
                "enforce mode: deny from core must emit deny (fail-closed unchanged)",
            )
            # Audit record should carry mode=enforce
            record = _read_last_audit_record(audit_path)
            self.assertEqual(record.get("mode"), "enforce")
        finally:
            _stop_stub_server(server)
            try:
                os.unlink(audit_path)
            except OSError:
                pass

    def test_mode_unset_defaults_to_enforce_deny(self):
        """REEFLEX_MODE unset + dead core -> deny (enforce default, fail-closed)."""
        stdout, code = _run_hook(
            json.dumps(_VALID_PAYLOAD),
            env_overrides={
                "REEFLEX_CORE_URL": "http://127.0.0.1:1",  # dead port
            },
        )
        # Remove REEFLEX_MODE if it was set in the outer env
        # (already handled: env_overrides does not set it, subprocess inherits nothing)
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "deny",
            "No REEFLEX_MODE + dead core -> deny (enforce, fail-closed)",
        )

    def test_observe_allow_from_core_still_emits_allow(self):
        """Core returns allow in observe mode -> emitted allow; audit mode=observe."""
        allow_body = json.dumps({
            "decision": "allow",
            "reason": "benign command",
            "rule": "stub/allow",
            "obligations": [],
        }).encode("utf-8")
        server, port, _ = _start_stub_server(allow_body, status=200)

        with tempfile.NamedTemporaryFile(
            suffix="-observe-allow.jsonl", delete=False
        ) as tmp:
            audit_path = tmp.name

        try:
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": "sess_observe_allow",
                "tool_name": "Read",
                "tool_input": {"file_path": "/src/main.py"},
                "cwd": "/tmp",
            }
            stdout, code = _run_hook(
                json.dumps(payload),
                env_overrides={
                    "REEFLEX_MODE": "observe",
                    "REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                    "REEFLEX_CLAUDE_AUDIT_LOG": audit_path,
                },
            )
            self.assertEqual(code, 0)
            parsed = json.loads(stdout)
            # allow stays allow in observe mode
            self.assertEqual(
                parsed["hookSpecificOutput"]["permissionDecision"], "allow"
            )
            record = _read_last_audit_record(audit_path)
            self.assertEqual(record.get("mode"), "observe")
            self.assertEqual(record.get("permission_decision"), "allow")
        finally:
            _stop_stub_server(server)
            try:
                os.unlink(audit_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
