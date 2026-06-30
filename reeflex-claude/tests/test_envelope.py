"""
test_envelope.py -- Unit tests for envelope.build_envelope().

Verifies:
  - envelope shape: all required SPEC §2 fields present
  - required fields never omitted (action.namespace, action.verb,
    target.environment, axes.*)
  - session_id is propagated and prefixed correctly
  - ValueError raised when session_id is missing
  - meta.signature has the ed25519:stub: prefix
  - context has all required keys for the demo Rego pack
  - approval.present is always False at interception
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import classify
from reeflex_claude.envelope import build_envelope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_payload(tool_name: str, tool_input: dict,
                  session_id: str = "sess_test_001") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": "/tmp/synthetic",
    }


def _build(tool_name: str, tool_input: dict,
           session_id: str = "sess_test_001",
           env: str = "production") -> dict:
    orig = os.environ.get("REEFLEX_CLAUDE_ENVIRONMENT")
    os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = env
    try:
        payload = _make_payload(tool_name, tool_input, session_id=session_id)
        cls = classify(tool_name, tool_input)
        return build_envelope(payload, cls)
    finally:
        if orig is None:
            os.environ.pop("REEFLEX_CLAUDE_ENVIRONMENT", None)
        else:
            os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = orig


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEnvelopeShape(unittest.TestCase):
    """All SPEC §2 required top-level keys must be present."""

    def setUp(self):
        self.env = _build("Bash", {"command": "ls -la"})

    def test_reeflex_version(self):
        self.assertEqual(self.env["reeflex_version"], "0.1")

    def test_agent_keys(self):
        a = self.env["agent"]
        self.assertIn("id", a)
        self.assertIn("on_behalf_of", a)
        self.assertIn("session_id", a)

    def test_action_keys(self):
        a = self.env["action"]
        self.assertIn("namespace", a)
        self.assertIn("verb", a)
        self.assertIn("ability", a)

    def test_target_keys(self):
        t = self.env["target"]
        self.assertIn("kind", t)
        self.assertIn("ref", t)
        self.assertIn("environment", t)

    def test_magnitude_key(self):
        self.assertIn("count", self.env["magnitude"])

    def test_axes_keys(self):
        ax = self.env["axes"]
        self.assertIn("reversibility", ax)
        self.assertIn("blast_radius", ax)
        self.assertIn("externality", ax)

    def test_approval_keys(self):
        ap = self.env["approval"]
        self.assertIn("present", ap)
        self.assertIn("by", ap)
        self.assertIn("role", ap)

    def test_trajectory_ref(self):
        self.assertIn("trajectory_ref", self.env)

    def test_context_keys(self):
        ctx = self.env["context"]
        self.assertIn("tool_name", ctx)
        self.assertIn("command_preview", ctx)
        self.assertIn("file_path", ctx)
        self.assertIn("danger_signature", ctx)
        self.assertIn("classification_tier", ctx)

    def test_meta_keys(self):
        m = self.env["meta"]
        self.assertIn("timestamp", m)
        self.assertIn("nonce", m)
        self.assertIn("signature", m)

    def test_params_keys(self):
        p = self.env["params"]
        self.assertIn("tool_name", p)
        self.assertIn("verb_source", p)


class TestRequiredFieldValues(unittest.TestCase):
    """Required fields are never None or empty."""

    def test_namespace_not_empty(self):
        e = _build("Bash", {"command": "ls"})
        self.assertEqual(e["action"]["namespace"], "claude-code")
        self.assertTrue(e["action"]["namespace"])

    def test_verb_not_empty(self):
        e = _build("Bash", {"command": "ls"})
        self.assertTrue(e["action"]["verb"])

    def test_environment_not_empty(self):
        e = _build("Bash", {"command": "ls"})
        self.assertIn(e["target"]["environment"], ("production", "staging", "dev"))

    def test_axes_not_none(self):
        e = _build("Bash", {"command": "ls"})
        ax = e["axes"]
        self.assertIsNotNone(ax["reversibility"])
        self.assertIsNotNone(ax["blast_radius"])
        self.assertIsNotNone(ax["externality"])

    def test_axes_valid_values(self):
        e = _build("Bash", {"command": "rm -rf /"})
        ax = e["axes"]
        self.assertIn(ax["reversibility"], ("reversible", "recoverable", "irreversible"))
        self.assertIn(ax["blast_radius"], ("single", "scoped", "broad", "systemic"))
        self.assertIn(ax["externality"], ("internal", "outbound", "physical"))

    def test_magnitude_count_ge_1(self):
        e = _build("Bash", {"command": "ls"})
        self.assertGreaterEqual(e["magnitude"]["count"], 1)


class TestSessionIdPropagation(unittest.TestCase):

    def test_session_id_prefixed(self):
        e = _build("Bash", {"command": "ls"}, session_id="abc123")
        self.assertEqual(e["agent"]["session_id"], "claude:abc123")

    def test_session_id_in_agent(self):
        e = _build("Read", {"file_path": "/src/app.py"}, session_id="my-session-42")
        self.assertIn("claude:", e["agent"]["session_id"])

    def test_missing_session_id_raises(self):
        payload = _make_payload("Bash", {"command": "ls"})
        del payload["session_id"]
        cls = classify("Bash", {"command": "ls"})
        with self.assertRaises(ValueError):
            build_envelope(payload, cls)

    def test_empty_session_id_raises(self):
        payload = _make_payload("Bash", {"command": "ls"}, session_id="")
        cls = classify("Bash", {"command": "ls"})
        with self.assertRaises(ValueError):
            build_envelope(payload, cls)


class TestSignatureAndNonce(unittest.TestCase):

    def test_signature_stub_prefix(self):
        e = _build("Bash", {"command": "ls"})
        self.assertTrue(e["meta"]["signature"].startswith("ed25519:stub:"))

    def test_nonce_is_32_hex_chars(self):
        e = _build("Bash", {"command": "ls"})
        nonce = e["meta"]["nonce"]
        self.assertEqual(len(nonce), 32)
        int(nonce, 16)  # must be valid hex

    def test_timestamp_format(self):
        import re
        e = _build("Bash", {"command": "ls"})
        ts = e["meta"]["timestamp"]
        self.assertTrue(re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts))


class TestApprovalAlwaysFalse(unittest.TestCase):

    def test_approval_present_false_on_read(self):
        e = _build("Read", {"file_path": "/etc/hosts"})
        self.assertFalse(e["approval"]["present"])

    def test_approval_present_false_on_delete(self):
        e = _build("Bash", {"command": "rm -rf /tmp/test"})
        self.assertFalse(e["approval"]["present"])

    def test_approval_by_null(self):
        e = _build("Bash", {"command": "ls"})
        self.assertIsNone(e["approval"]["by"])

    def test_approval_role_null(self):
        e = _build("Bash", {"command": "ls"})
        self.assertIsNone(e["approval"]["role"])


class TestEnvironmentPropagation(unittest.TestCase):

    def test_production_env(self):
        e = _build("Bash", {"command": "ls"}, env="production")
        self.assertEqual(e["target"]["environment"], "production")

    def test_staging_env(self):
        e = _build("Bash", {"command": "ls"}, env="staging")
        self.assertEqual(e["target"]["environment"], "staging")

    def test_dev_env(self):
        e = _build("Bash", {"command": "ls"}, env="dev")
        self.assertEqual(e["target"]["environment"], "dev")

    def test_invalid_env_defaults_to_production(self):
        e = _build("Bash", {"command": "ls"}, env="unknown_value")
        self.assertEqual(e["target"]["environment"], "production")


class TestAbilityField(unittest.TestCase):

    def test_bash_ability(self):
        e = _build("Bash", {"command": "ls"})
        self.assertEqual(e["action"]["ability"], "claude-code/Bash")

    def test_write_ability(self):
        e = _build("Write", {"file_path": "/src/new.py", "content": ""})
        self.assertEqual(e["action"]["ability"], "claude-code/Write")

    def test_read_ability(self):
        e = _build("Read", {"file_path": "/src/main.py"})
        self.assertEqual(e["action"]["ability"], "claude-code/Read")


class TestContextBlock(unittest.TestCase):

    def test_classification_tier_values(self):
        valid = {"benign", "moderate", "destructive_broad", "destructive_systemic"}
        for tool, inp in [
            ("Bash", {"command": "ls"}),
            ("Bash", {"command": "rm -rf /tmp/x"}),
            ("Bash", {"command": "rm -rf /"}),
            ("Bash", {"command": "git push --force origin main"}),
        ]:
            e = _build(tool, inp)
            tier = e["context"]["classification_tier"]
            self.assertIn(tier, valid, f"{tool} {inp} -> tier={tier}")

    def test_command_preview_truncated(self):
        long_cmd = "echo " + "x" * 300
        e = _build("Bash", {"command": long_cmd})
        preview = e["context"]["command_preview"]
        if preview is not None:
            self.assertLessEqual(len(preview), 200)

    def test_file_path_in_context_for_write(self):
        e = _build("Write", {"file_path": "/src/app.py", "content": ""})
        self.assertEqual(e["context"]["file_path"], "/src/app.py")


if __name__ == "__main__":
    unittest.main()
