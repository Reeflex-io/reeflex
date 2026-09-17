"""
test_deadline_rfx321.py -- the gate must answer before the runner kills it.

WHAT THESE TESTS ARE ABOUT (RFX-321, RFX-322; qa--221 Findings A and B).

The adapter's fail-closed invariant was "on ANY error, deny".  qa--221 measured
that it holds only while the hook RETURNS before Claude Code's PreToolUse runner
kills it at the settings.json timeout -- because a killed hook is not an error
the hook gets to handle, and the runner then runs the tool (Finding C, arm G).
Two customer-reachable conditions broke the precondition and put an `rm -rf`
through a production fixture with no human:

  A. `REEFLEX_CLAUDE_TIMEOUT=45` (the value a slow-engine operator reaches for)
     against an engine that accepts the connection and never answers.
  B. a Bash command large enough that `classify()` alone overran the timeout
     (700 KB -> 34.15 s measured on the published 0.2.0 wheel).

WHAT A TEST HERE CAN AND CANNOT SEE.  Everything below runs the hook, not
Claude Code: it proves the hook answers in time and with what.  It does NOT
prove what the runner then does with that answer -- that is the substrate
(Finding C) and only a live matrix against the real binary can measure it.  The
live before/after matrix lives in the round's report, not in this file.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude import deadline  # noqa: E402
from reeflex_claude.classify import (  # noqa: E402
    MAX_BASH_COMMAND_CHARS,
    classify,
    max_bash_command_chars,
)
from reeflex_claude.setup_settings import (  # noqa: E402
    DEFAULT_TIMEOUT,
    HOOK_TIMEOUT_ENV,
    deadline_mismatch,
    wired_hook_timeout,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _EnvGuard:
    """
    Set/clear env vars for the duration of a block, restoring exactly.

    `arm=True` also arms the deadline, because the budget binds only inside an
    armed hook process -- a library caller has no runner to beat.  The watchdog
    callback is a no-op here: these tests are about the clamp, and a real
    callback would os._exit() the test runner.
    """

    def __init__(self, arm=False, **values):
        self._values = values
        self._arm = arm
        self._saved = {}
        self._timer = None

    def __enter__(self):
        for key, value in self._values.items():
            self._saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(value)
        deadline.restart_clock()
        if self._arm:
            self._timer = deadline.arm(lambda *_a: None)
        return self

    def __exit__(self, *exc):
        if self._timer is not None:
            self._timer.cancel()
        for key, old in self._saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        deadline.restart_clock()
        return False


def _start_stalling_socket():
    """
    A socket that accepts, reads the request and never writes a byte -- the
    captive portal / hung load balancer / paused container.  qa--221's
    `stub_core.py stall`, inline.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        held = []
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            held.append(conn)  # hold it open, answer nothing
        for conn in held:
            try:
                conn.close()
            except OSError:
                pass
        srv.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, stop


class _AllowHandler(http.server.BaseHTTPRequestHandler):
    """An engine that allows everything -- so a deny here came from the adapter."""

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({
            "decision": "allow",
            "reason": "stub engine allows everything",
            "rule": "stub/allow_all",
            "obligations": [],
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_allow_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _AllowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _payload(command: str, tool: str = "Bash") -> str:
    return json.dumps({
        "session_id": "rfx321-test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": "/tmp",
    })


def _run_hook(stdin_data: str, env_overrides: dict, timeout: float = 30) -> tuple:
    """Run the hook exactly as Claude Code does: one JSON payload on stdin."""
    env = dict(os.environ)
    env["REEFLEX_CLAUDE_AUDIT_LOG"] = os.path.join(
        os.environ.get("TMPDIR", "/tmp"), "rfx321-test-audit.jsonl")
    env.update({k: str(v) for k, v in env_overrides.items()})
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-m", "reeflex_claude"],
        input=stdin_data.encode("utf-8"),
        capture_output=True,
        cwd=_PARENT,
        env=env,
        timeout=timeout,
    )
    return proc, time.monotonic() - started


def _sole_decision(proc) -> dict:
    """Parse stdout and assert the hook wrote EXACTLY ONE answer."""
    text = proc.stdout.decode("utf-8", errors="replace").strip()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected exactly one stdout line, got {len(lines)}: {text!r}"
    return json.loads(lines[0])["hookSpecificOutput"]


# ---------------------------------------------------------------------------
# The one number: it can be lowered and it cannot be raised
# ---------------------------------------------------------------------------

class TestRunnerTimeoutIsOneWay(unittest.TestCase):

    def test_default_is_the_timeout_the_installer_writes(self):
        with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=None):
            self.assertEqual(deadline.runner_timeout(), float(DEFAULT_TIMEOUT))

    def test_a_smaller_declared_timeout_is_honoured(self):
        with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=10):
            self.assertEqual(deadline.runner_timeout(), 10.0)

    def test_a_larger_declared_timeout_is_ignored(self):
        """
        THE Finding-A shape: a second number a customer sets bigger.  Honouring
        600 here would put the deadline at 480 s, five times past the point the
        runner kills the hook -- i.e. exactly the fail-open, renamed.
        """
        with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=600):
            self.assertEqual(deadline.runner_timeout(), float(DEFAULT_TIMEOUT))

    def test_garbage_and_zero_fall_back_to_the_default(self):
        for bad in ("", "   ", "soon", "0", "-5", "NaN-ish"):
            with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=bad):
                self.assertEqual(deadline.runner_timeout(), float(DEFAULT_TIMEOUT),
                                 f"{bad!r} must not change the runner timeout")

    def test_deadline_is_strictly_inside_the_runner_timeout(self):
        for declared in (2, 5, 10, 30):
            with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=declared):
                self.assertLess(deadline.deadline(), deadline.runner_timeout(),
                                f"deadline must leave the runner room at {declared}s")
                self.assertGreater(deadline.deadline(), 0)

    def test_installer_and_clock_share_one_constant(self):
        self.assertEqual(float(DEFAULT_TIMEOUT), deadline.RUNNER_TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# Finding A: the socket timeout is clamped under the deadline
# ---------------------------------------------------------------------------

class TestSocketTimeoutIsClamped(unittest.TestCase):

    def test_budget_never_exceeds_what_is_left(self):
        with _EnvGuard(arm=True, REEFLEX_CLAUDE_HOOK_TIMEOUT=10):
            self.assertLessEqual(deadline.budget_for(45.0), deadline.deadline())
            self.assertLessEqual(deadline.budget_for(60.0), deadline.deadline())
            # a smaller request is still honoured -- the clamp is a ceiling
            self.assertAlmostEqual(deadline.budget_for(1.0), 1.0, places=3)

    def test_budget_is_zero_once_the_deadline_has_passed(self):
        with _EnvGuard(arm=True, REEFLEX_CLAUDE_HOOK_TIMEOUT=1):
            time.sleep(0.6)
            self.assertEqual(deadline.budget_for(45.0), 0.0)

    def test_an_unarmed_library_caller_is_not_clamped(self):
        """
        The regression this scoping exists for.  `call_core_and_map()` is a
        library entry point -- reeflex-litellm's contract suite calls it
        directly -- and a clock started at import turned every such call into a
        permanent deny once the process outlived the deadline.  Measured: that
        suite went red on two cases in a full run and green on the same two in
        isolation.  Outside a hook there is no runner, so there is no clamp.
        """
        with _EnvGuard(REEFLEX_CLAUDE_HOOK_TIMEOUT=1):
            time.sleep(0.6)
            self.assertFalse(deadline.is_armed())
            self.assertEqual(deadline.budget_for(45.0), 45.0)

    def test_stalling_engine_with_timeout_45_still_denies_in_time(self):
        """
        Finding A as a unit: the engine never answers, the operator asked for
        45 s, and the answer must arrive inside the (here: 4 s) runner timeout.
        Before the fix this call blocked for the full 45 s and the runner killed
        the hook mid-wait.
        """
        from reeflex_claude.enforce import call_core_and_map

        port, stop = _start_stalling_socket()
        try:
            with _EnvGuard(arm=True,
                           REEFLEX_CORE_URL=f"http://127.0.0.1:{port}",
                           REEFLEX_CLAUDE_TIMEOUT=45,
                           REEFLEX_CLAUDE_HOOK_TIMEOUT=4):
                started = time.monotonic()
                decision, reason, rule, reachable, _obl = call_core_and_map(
                    {"meta": {"nonce": "n"}})
                waited = time.monotonic() - started
            self.assertEqual(decision, "deny")
            self.assertFalse(reachable)
            self.assertLess(waited, 4.0,
                            f"waited {waited:.1f}s -- the runner would have killed us")
            self.assertIn("clamped from 45.0s", reason)
        finally:
            stop.set()

    def test_hook_end_to_end_denies_before_the_runner_would_kill_it(self):
        """The same, through the real stdin->stdout hook, as a subprocess."""
        port, stop = _start_stalling_socket()
        try:
            proc, wall = _run_hook(
                _payload("rm -rf /tmp/rfx321-fixture"),
                {"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                 "REEFLEX_CLAUDE_TIMEOUT": 45,
                 "REEFLEX_CLAUDE_HOOK_TIMEOUT": 5},
                timeout=30,
            )
        finally:
            stop.set()
        self.assertEqual(proc.returncode, 0, "a non-zero exit is itself a silent allow")
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertLess(wall, 5.0,
                        f"hook took {wall:.1f}s against a 5s runner timeout")


# ---------------------------------------------------------------------------
# The watchdog: something that ignores the budget entirely
# ---------------------------------------------------------------------------

_SLOW_ENFORCE = """
import sys, time
sys.path.insert(0, {parent!r})
import reeflex_claude.enforce as enforce
def _never_returns(envelope):
    time.sleep(120)
    return ("allow", "should never be read", "stub/slow", True, [])
enforce.call_core_and_map = _never_returns
from reeflex_claude import hook
hook.main()
"""


def _run_hook_with_slow_enforce(env_overrides: dict, timeout: float = 30) -> tuple:
    """
    Drive the hook with an ENFORCE step that never returns.

    This is the general case the clamp cannot cover: work inside the hook that
    outlives the budget for a reason the budget does not know about (Finding B
    is the shipped instance of it -- classify() itself).  Only the watchdog can
    answer here.
    """
    env = dict(os.environ)
    env.update({k: str(v) for k, v in env_overrides.items()})
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", _SLOW_ENFORCE.format(parent=_PARENT)],
        input=_payload("rm -rf /tmp/rfx321-fixture").encode("utf-8"),
        capture_output=True,
        cwd=_PARENT,
        env=env,
        timeout=timeout,
    )
    return proc, time.monotonic() - started


class TestWatchdogAnswersAndExits(unittest.TestCase):

    def test_deny_is_written_and_the_process_exits_before_the_deadline(self):
        proc, wall = _run_hook_with_slow_enforce({"REEFLEX_CLAUDE_HOOK_TIMEOUT": 4})
        self.assertEqual(proc.returncode, 0)
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("deadline", out["permissionDecisionReason"])
        self.assertIn("reeflex.core/deadline_exceeded", out["permissionDecisionReason"])
        self.assertLess(wall, 4.0,
                        f"process lived {wall:.1f}s; the runner kills at 4s")

    def test_exactly_one_answer_reaches_stdout(self):
        """
        Two writers, one stdout.  Two JSON lines is an unparseable verdict, and
        qa--221 arm E measured what the runner does with stdout it cannot parse:
        it runs the tool.  So the latch is a safety property, not tidiness.
        """
        proc, _ = _run_hook_with_slow_enforce({"REEFLEX_CLAUDE_HOOK_TIMEOUT": 3})
        _sole_decision(proc)  # asserts exactly one line

    def test_observe_mode_answers_allow_at_the_deadline(self):
        """
        observe must never block the user (HIL-DESIGN §8).  A watchdog that
        denied would convert the non-blocking mode into the blocking one at the
        deadline -- an outage introduced by a safety fix.
        """
        proc, wall = _run_hook_with_slow_enforce(
            {"REEFLEX_CLAUDE_HOOK_TIMEOUT": 4, "REEFLEX_MODE": "observe"})
        self.assertEqual(proc.returncode, 0)
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertLess(wall, 4.0)

    def test_the_deadline_answer_is_audited(self):
        import tempfile
        log = os.path.join(tempfile.mkdtemp(prefix="rfx321-audit-"), "audit.jsonl")
        proc, _ = _run_hook_with_slow_enforce(
            {"REEFLEX_CLAUDE_HOOK_TIMEOUT": 4, "REEFLEX_CLAUDE_AUDIT_LOG": log})
        self.assertEqual(proc.returncode, 0)
        with open(log, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(records), 1, "the deadline answer must leave a record")
        self.assertEqual(records[0]["rule"], "reeflex.core/deadline_exceeded")
        self.assertEqual(records[0]["permission_decision"], "deny")
        # and it says WHICH action, not just that something timed out
        self.assertEqual(records[0]["ability"], "claude-code/Bash")

    def test_a_healthy_call_is_not_slowed_down_or_altered(self):
        """
        The control that makes the rest of this file mean something: with the
        watchdog armed, an ordinary allow still allows, and promptly.
        """
        server, port = _start_allow_server()
        try:
            proc, wall = _run_hook(
                _payload("ls -la"),
                {"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}"},
                timeout=30,
            )
        finally:
            server.shutdown()
        self.assertEqual(proc.returncode, 0)
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertLess(wall, 10.0)


# ---------------------------------------------------------------------------
# Finding B: the classifier is bounded
# ---------------------------------------------------------------------------

class TestBoundedClassifier(unittest.TestCase):

    def test_a_command_past_the_cap_is_not_tokenised(self):
        """
        700 KB took 34.15 s on the published wheel -- past the 30 s hook
        timeout, which is the whole finding.  Here it must be effectively free.
        """
        command = "echo " + "a" * 700_000
        started = time.monotonic()
        cls = classify("Bash", {"command": command})
        spent = time.monotonic() - started
        self.assertLess(spent, 1.0, f"classify spent {spent:.2f}s on an oversize command")
        self.assertEqual(cls["danger_signature"], "oversize_command")

    def test_the_oversize_reading_is_the_conservative_one(self):
        cls = classify("Bash", {"command": "echo " + "a" * (MAX_BASH_COMMAND_CHARS + 1)})
        self.assertEqual(cls["reversibility"], "irreversible")
        self.assertEqual(cls["blast_radius"], "systemic")
        self.assertEqual(cls["classification_tier"], "destructive_systemic")

    def test_at_the_cap_the_command_is_still_read_normally(self):
        """A cap that fires early would silently stop classifying real commands."""
        filler = "a" * (MAX_BASH_COMMAND_CHARS - len("echo "))
        cls = classify("Bash", {"command": "echo " + filler})
        self.assertNotEqual(cls["danger_signature"], "oversize_command")
        self.assertEqual(cls["verb"], "read")

    def test_the_cap_can_be_lowered_and_cannot_be_raised(self):
        with _EnvGuard(REEFLEX_CLAUDE_MAX_COMMAND_CHARS=64):
            self.assertEqual(max_bash_command_chars(), 64)
        with _EnvGuard(REEFLEX_CLAUDE_MAX_COMMAND_CHARS=MAX_BASH_COMMAND_CHARS * 100):
            self.assertEqual(max_bash_command_chars(), MAX_BASH_COMMAND_CHARS)
        for bad in ("", "lots", "0", "-1"):
            with _EnvGuard(REEFLEX_CLAUDE_MAX_COMMAND_CHARS=bad):
                self.assertEqual(max_bash_command_chars(), MAX_BASH_COMMAND_CHARS)

    def test_the_hook_refuses_an_oversize_command_an_allowing_engine_permitted(self):
        """
        The engine says allow to everything.  A deny here is the adapter's own,
        and it must be a deny and not an `ask`: a confirmation dialog over a
        command nobody can read is a dialog, not a decision.
        """
        server, port = _start_allow_server()
        try:
            proc, _ = _run_hook(
                _payload("echo " + "a" * 400),
                {"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                 "REEFLEX_CLAUDE_MAX_COMMAND_CHARS": 128},
                timeout=30,
            )
        finally:
            server.shutdown()
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("adapter/command_too_large", out["permissionDecisionReason"])

    def test_the_same_engine_still_allows_a_command_under_the_cap(self):
        """The control for the test above: the cap, not the stub, is the cause."""
        server, port = _start_allow_server()
        try:
            proc, _ = _run_hook(
                _payload("ls -la"),
                {"REEFLEX_CORE_URL": f"http://127.0.0.1:{port}",
                 "REEFLEX_CLAUDE_MAX_COMMAND_CHARS": 128},
                timeout=30,
            )
        finally:
            server.shutdown()
        out = _sole_decision(proc)
        self.assertEqual(out["permissionDecision"], "allow")


# ---------------------------------------------------------------------------
# The installation: two numbers written from one, and compared
# ---------------------------------------------------------------------------

class TestSettingsCarryTheRunnerTimeout(unittest.TestCase):

    def _settings(self, entry_timeout, env_value):
        settings = {
            "hooks": {"PreToolUse": [{
                "matcher": "*",
                "hooks": [{"type": "command",
                           "command": "/opt/venv/bin/reeflex-claude hook",
                           "timeout": entry_timeout}],
            }]},
        }
        if env_value is not None:
            settings["env"] = {"REEFLEX_CLAUDE_HOOK_TIMEOUT": env_value}
        return settings

    def test_wired_hook_timeout_is_read_from_our_entry(self):
        self.assertEqual(wired_hook_timeout(self._settings(30, None)), 30.0)
        self.assertIsNone(wired_hook_timeout({"hooks": {}}))

    def test_agreeing_numbers_are_not_flagged(self):
        self.assertIsNone(deadline_mismatch(self._settings(30, "30")))
        self.assertIsNone(deadline_mismatch(self._settings(30, "10")))

    def test_an_env_value_above_the_entry_timeout_is_flagged(self):
        note = deadline_mismatch(self._settings(30, "90"))
        self.assertIsNotNone(note)
        self.assertIn("LARGER", note)

    def test_an_entry_hand_lowered_with_nothing_declaring_it_is_flagged(self):
        """
        RFX-321 reached from the other side, and the clamp does NOT save it.
        The operator edits the entry down to 10s and leaves the env block
        alone; the hook still believes it has 30s, puts its deadline at 24s,
        and the runner kills it at 10s -- which is a hook that did not answer,
        and Claude Code runs the tool over one of those.  Nothing inside the
        hook process can see this: it is handed a payload on stdin, not the
        settings file that summoned it.
        """
        note = deadline_mismatch(self._settings(10, None))
        self.assertIsNotNone(note)
        self.assertIn("10s", note)
        self.assertIn(HOOK_TIMEOUT_ENV, note)

    def test_an_entry_at_or_above_the_default_needs_no_env_value(self):
        # The shipped install, and the deliberately-slow one: neither is the
        # dangerous direction, so neither is nagged about.
        self.assertIsNone(deadline_mismatch(self._settings(30, None)))
        self.assertIsNone(deadline_mismatch(self._settings(60, None)))

    def test_setup_writes_both_numbers_from_one_value(self):
        import tempfile
        from reeflex_claude.cli import main as cli_main

        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                rc = cli_main(["setup", "--project", "--core-url",
                               "http://127.0.0.1:8080", "--mode", "enforce",
                               "--verify-ssl", "true", "--env", "dev"])
            finally:
                os.chdir(cwd)
            self.assertEqual(rc, 0)
            written = json.loads(
                open(os.path.join(tmp, ".claude", "settings.json"), encoding="utf-8").read())
        self.assertEqual(written["env"]["REEFLEX_CLAUDE_HOOK_TIMEOUT"], str(DEFAULT_TIMEOUT))
        self.assertIsNone(deadline_mismatch(written))


if __name__ == "__main__":
    unittest.main()
