"""
test_hold_named_rfx318.py -- the human answering the dialog is told a hold exists.

RFX-318.  Core allocates a real hold on `require_approval` and returns
`hold_id`, `expires_ts` and `decision_id` on that SAME /v1/decide response.  The
adapter used to keep none of them: the complete text at the terminal was

    "Reeflex: irreversible broad change in production requires human approval
     [rule=reeflex.policy/irreversible_broad_prod]"

so the reader is told they are the required human, approves, and never learns
that a hold with a deadline is open and that somebody else is being asked the
same question in the portal.

WHAT THESE TESTS PIN, AND WHY EACH ONE EARNS ITS PLACE:
  * the three identifiers reach the string a human reads (the defect itself);
  * WHERE-TO-GO resolves in the documented order -- env, then the credential
    `connect` stored, then the engine URL -- because a fix that only works when
    REEFLEX_PORTAL_URL happens to be set is not a fix for a connected operator,
    who never sets it by hand;
  * a portal is NEVER guessed.  An operator on a self-hosted engine has no
    app.reeflex.io and sending them there is a claim we cannot support;
  * an engine that names no hold is unchanged, so an ordinary allow or deny does
    not grow a clause;
  * the "does not resolve that hold" sentence appears ONLY on ask.  It is a
    claim about this adapter (no resubmission path at all -- see
    test_agent_identity_rfx138.test_no_hold_is_ever_resubmitted_by_this_adapter)
    and it was measured against a live core in qa--250 arm 3: after the hook
    answers, the hold still carries only a `created` event and the adapter has
    made zero resolve-shaped requests;
  * an engine-supplied identifier is bounded before it reaches the dialog.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude import enforce


# A response shaped exactly like the one core v0.2.1 returns for
# `rm -rf /srv/prod/data` in production -- captured in qa--250 arm 1 against a
# scratch core whose image id is byte-identical to the production core's.
HOLD_RESPONSE = {
    "decision": "require_approval",
    "decision_id": "98b26040728b4c73b6abaadf471688d0",
    "expires_ts": "2026-09-18T16:17:49Z",
    "hold_id": "cf6fe1dfb70e4c8b83d2dac75173e758",
    "modulation": None,
    "obligations": [],
    "reason": "irreversible broad change in production requires human approval",
    "rule": "reeflex.policy/irreversible_broad_prod",
}


class _EnvGuard:
    """Set/clear env vars for one test and put the environment back."""

    def __init__(self, **values):
        self._values = values
        self._saved = {}

    def __enter__(self):
        for key, value in self._values.items():
            self._saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, old in self._saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        return False


def _map(response, **env):
    """Map a response with a clean, explicit environment."""
    base = {"REEFLEX_PORTAL_URL": None, "REEFLEX_GATE_ID": None,
            "REEFLEX_CORE_URL": "http://127.0.0.1:8080"}
    base.update(env)
    with _EnvGuard(**base):
        return enforce._map_decision(response, core_reachable=True)


class TestHoldIsNamed(unittest.TestCase):
    """The defect: the three fields core returned reached no screen."""

    def test_reason_names_the_hold_id(self):
        _, reason, _, _, _ = _map(HOLD_RESPONSE)
        self.assertIn(HOLD_RESPONSE["hold_id"], reason)

    def test_reason_names_the_deadline(self):
        _, reason, _, _, _ = _map(HOLD_RESPONSE)
        self.assertIn(HOLD_RESPONSE["expires_ts"], reason)

    def test_reason_names_the_decision_id(self):
        _, reason, _, _, _ = _map(HOLD_RESPONSE)
        self.assertIn(HOLD_RESPONSE["decision_id"], reason)

    def test_the_original_sentence_is_still_there(self):
        """The clause is added to the reason, it does not replace it."""
        _, reason, _, _, _ = _map(HOLD_RESPONSE)
        self.assertIn(HOLD_RESPONSE["reason"], reason)
        self.assertIn(f"[rule={HOLD_RESPONSE['rule']}]", reason)

    def test_decision_is_still_ask(self):
        """Naming the hold must not disturb the mapping itself."""
        perm, _, rule, reachable, obligations = _map(HOLD_RESPONSE)
        self.assertEqual(perm, "ask")
        self.assertEqual(rule, HOLD_RESPONSE["rule"])
        self.assertTrue(reachable)
        self.assertEqual(obligations, [])


class TestWhereToFindIt(unittest.TestCase):
    """"Names the hold AND WHERE TO FIND IT" -- the second half of the criterion."""

    def test_env_portal_is_named(self):
        _, reason, _, _, _ = _map(
            HOLD_RESPONSE, REEFLEX_PORTAL_URL="https://portal.example.test")
        self.assertIn("https://portal.example.test", reason)
        self.assertIn("portal", reason.lower())

    def test_portal_comes_from_the_stored_credential_when_env_is_unset(self):
        """A connected operator never sets REEFLEX_PORTAL_URL by hand."""
        from reeflex_claude import credentials

        with tempfile.TemporaryDirectory() as home:
            with _EnvGuard(HOME=home):
                credentials.store(
                    core_url="http://127.0.0.1:8080",
                    gate_id="gate-318",
                    token="rfx_ac_SYNTHETIC_NOT_A_REAL_CREDENTIAL",
                    portal_url="https://stored.example.test",
                )
                _, reason, _, _, _ = _map(
                    HOLD_RESPONSE, HOME=home, REEFLEX_GATE_ID="gate-318")
        self.assertIn("https://stored.example.test", reason)

    def test_env_wins_over_the_stored_credential(self):
        from reeflex_claude import credentials

        with tempfile.TemporaryDirectory() as home:
            with _EnvGuard(HOME=home):
                credentials.store(
                    core_url="http://127.0.0.1:8080",
                    gate_id="gate-318",
                    token="rfx_ac_SYNTHETIC_NOT_A_REAL_CREDENTIAL",
                    portal_url="https://stored.example.test",
                )
                _, reason, _, _, _ = _map(
                    HOLD_RESPONSE, HOME=home, REEFLEX_GATE_ID="gate-318",
                    REEFLEX_PORTAL_URL="https://env.example.test")
        self.assertIn("https://env.example.test", reason)
        self.assertNotIn("https://stored.example.test", reason)

    def test_with_no_portal_anywhere_the_engine_is_named(self):
        """Still answers "where", using the one URL that is known for certain."""
        _, reason, _, _, _ = _map(
            HOLD_RESPONSE, REEFLEX_CORE_URL="http://engine.example.test:8090")
        self.assertIn("http://engine.example.test:8090", reason)

    def test_a_portal_is_never_guessed(self):
        """No app.reeflex.io for an operator who never mentioned one."""
        _, reason, _, _, _ = _map(
            HOLD_RESPONSE, REEFLEX_CORE_URL="http://engine.example.test:8090")
        self.assertNotIn("app.reeflex.io", reason)

    def test_a_credential_for_a_different_gate_is_not_used(self):
        from reeflex_claude import credentials

        with tempfile.TemporaryDirectory() as home:
            with _EnvGuard(HOME=home):
                credentials.store(
                    core_url="http://127.0.0.1:8080",
                    gate_id="some-other-gate",
                    token="rfx_ac_SYNTHETIC_NOT_A_REAL_CREDENTIAL",
                    portal_url="https://wrong-gate.example.test",
                )
                _, reason, _, _, _ = _map(
                    HOLD_RESPONSE, HOME=home, REEFLEX_GATE_ID="gate-318")
        self.assertNotIn("https://wrong-gate.example.test", reason)


class TestNoHoldNoClause(unittest.TestCase):
    """An engine that names no hold leaves the reason exactly as it was."""

    def test_plain_allow_is_unchanged(self):
        _, reason, _, _, _ = _map({
            "decision": "allow", "reason": "no high-risk",
            "rule": "reeflex.policy/default_allow", "obligations": [],
        })
        self.assertEqual(
            reason, "Reeflex: no high-risk [rule=reeflex.policy/default_allow]")

    def test_plain_deny_is_unchanged(self):
        _, reason, _, _, _ = _map({
            "decision": "deny", "reason": "systemic in prod",
            "rule": "reeflex.policy/irreversible_systemic_prod", "obligations": [],
        })
        self.assertEqual(
            reason,
            "Reeflex: systemic in prod "
            "[rule=reeflex.policy/irreversible_systemic_prod]")

    def test_require_approval_without_a_hold_is_unchanged(self):
        """Some engines may ask without allocating a hold; say nothing extra."""
        _, reason, _, _, _ = _map({
            "decision": "require_approval", "reason": "needs a human",
            "rule": "stub/ask", "obligations": [],
        })
        self.assertEqual(reason, "Reeflex: needs a human [rule=stub/ask]")

    def test_an_empty_hold_id_is_not_a_hold(self):
        response = dict(HOLD_RESPONSE, hold_id="")
        _, reason, _, _, _ = _map(response)
        self.assertNotIn("Reeflex hold", reason)


class TestTheConsequenceSentence(unittest.TestCase):
    """Measured in qa--250 arm 3 against a live core, not assumed."""

    def test_ask_says_answering_here_does_not_resolve_the_hold(self):
        _, reason, _, _, _ = _map(HOLD_RESPONSE)
        self.assertIn("does not resolve that hold", reason)

    def test_a_deny_carrying_a_hold_does_not_claim_a_dialog(self):
        """Nobody is answering anything on a deny, so the sentence would lie."""
        response = dict(HOLD_RESPONSE, decision="deny")
        _, reason, _, _, _ = _map(response)
        self.assertIn(HOLD_RESPONSE["hold_id"], reason)
        self.assertNotIn("Answering this dialog", reason)


class TestEngineSuppliedFieldsAreBounded(unittest.TestCase):
    """The engine's response is external input; it does not get to flood a dialog."""

    def test_an_oversized_hold_id_is_truncated(self):
        response = dict(HOLD_RESPONSE, hold_id="f" * 5000)
        _, reason, _, _, _ = _map(response)
        self.assertLess(len(reason), 1000)
        self.assertIn("truncated", reason)

    def test_an_oversized_expires_ts_is_truncated(self):
        response = dict(HOLD_RESPONSE, expires_ts="z" * 5000)
        _, reason, _, _, _ = _map(response)
        self.assertLess(len(reason), 1000)


class TestItSurvivesTheWholeHook(unittest.TestCase):
    """The criterion is about the RENDERED dialog text, not the mapper's return."""

    def test_reason_reaches_permission_decision_reason(self):
        import http.server
        import threading

        body = json.dumps(HOLD_RESPONSE).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        try:
            import subprocess

            payload = {
                "session_id": "rfx318-test", "transcript_path": "/tmp/none",
                "cwd": "/srv/prod", "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /srv/prod/data"},
            }
            env = dict(os.environ)
            env["REEFLEX_CORE_URL"] = f"http://127.0.0.1:{port}"
            env["REEFLEX_MODE"] = "enforce"
            env["REEFLEX_PORTAL_URL"] = "https://portal.example.test"
            env["PYTHONPATH"] = _PARENT
            proc = subprocess.run(
                [sys.executable, "-m", "reeflex_claude.hook"],
                input=json.dumps(payload), capture_output=True, text=True,
                env=env, timeout=60)
            out = json.loads(proc.stdout)
            rendered = out["hookSpecificOutput"]["permissionDecisionReason"]
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn(HOLD_RESPONSE["hold_id"], rendered)
        self.assertIn(HOLD_RESPONSE["expires_ts"], rendered)
        self.assertIn("https://portal.example.test", rendered)


if __name__ == "__main__":
    unittest.main()
