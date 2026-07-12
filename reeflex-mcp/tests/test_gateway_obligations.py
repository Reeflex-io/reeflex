"""
test_gateway_obligations.py -- Track 5.1 (design doc ADDENDUM v1.5 section
25 / SPEC section 5+7#5) integration-style tests: the FULL
_handle_call_tool() flow, with `Gateway._decide()` stubbed to return a
canned Decision carrying a SYNTHETIC obligation (the real base policy pack
emits none today -- see the module docstring in obligations.py), against a
real (fake-connection) upstream so the "never actually dispatched" claim for
a blocked call is genuinely provable, not just asserted.

Covers the 5 scenarios the coordinator's brief lists verbatim:
  (a) allow + empty obligations -> forward
  (b) enforce + allow + a KNOWN synthetic obligation -> applied + forwarded
  (c) enforce + allow + an UNKNOWN obligation -> BLOCKED (isError, reason
      names the obligation) -- proven with a real-ish flow (stubbed decide)
  (d) observe + unknown obligation -> forwarded + recorded (not blocked)
  (e) the approved_resubmission path also honors obligations
"""

from __future__ import annotations

import unittest

import mcp.types as types

from reeflex_mcp import obligations, registry, upstream as upstream_mod
from reeflex_mcp.gateway import Gateway


class _FakeConnection(upstream_mod.UpstreamConnection):
    def __init__(self, name, target_system, target_environment):
        super().__init__(name, target_system, target_environment)
        self.dispatched: list[tuple[str, dict]] = []

    async def connect(self) -> None:
        pass

    async def list_tools(self):
        return [
            types.Tool(name="read_file", description="read", inputSchema={"type": "object", "properties": {}})
        ]

    async def call_tool(self, tool_name, arguments):
        self.dispatched.append((tool_name, arguments))
        return types.CallToolResult(content=[types.TextContent(type="text", text="upstream ran it")], isError=False)

    async def close(self) -> None:
        pass


def _write_yaml(path: str) -> None:
    from pathlib import Path

    Path(path).write_text(
        "mode: enforce\n"
        "upstreams:\n"
        "  - name: fs\n"
        '    command: ["python", "fs.py"]\n'
        "    target: { system: fs, environment: production }\n",
        encoding="utf-8",
    )


class _ObligationsTestBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        import tempfile
        from pathlib import Path

        self.yaml_path = str(Path(tempfile.mkdtemp()) / "reeflex-mcp.yaml")
        _write_yaml(self.yaml_path)
        gw_config = registry.load_config(self.yaml_path)
        self.gateway = Gateway(gw_config)

        self._original_build_connection = upstream_mod.build_connection
        self.fake_conn = _FakeConnection("fs", "fs", "production")
        upstream_mod.build_connection = lambda spec, *, on_list_changed: self.fake_conn
        await self.gateway.upstreams.connect_all(connect_timeout=5.0)

        # Isolate the obligations registry from other tests / the real v1
        # known-set beyond what each test explicitly registers.
        self._saved_handlers = dict(obligations._HANDLERS)

    async def asyncTearDown(self) -> None:
        upstream_mod.build_connection = self._original_build_connection
        obligations._HANDLERS.clear()
        obligations._HANDLERS.update(self._saved_handlers)

    def _stub_decide(self, decision: dict) -> None:
        async def fake_decide(envelope):
            return decision, None

        self.gateway._decide = fake_decide


class TestEnforceObligations(_ObligationsTestBase):
    async def test_a_allow_empty_obligations_forwards(self) -> None:
        self._stub_decide({"decision": "allow", "decision_id": "dec-a", "rule": "r", "obligations": []})
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])
        self.assertEqual(result.meta.get("decision_id"), "dec-a")

    async def test_a2_allow_no_obligations_key_at_all_forwards(self) -> None:
        # Defensive: a Decision with no "obligations" key at all (not even
        # an empty list) must behave identically to an empty list.
        self._stub_decide({"decision": "allow", "decision_id": "dec-a2", "rule": "r"})
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)

    async def test_b_known_synthetic_obligation_applied_and_forwarded(self) -> None:
        applied = []
        obligations.register("test:known", lambda ctx: applied.append(ctx.obligation))
        self._stub_decide(
            {"decision": "allow", "decision_id": "dec-b", "rule": "r", "obligations": ["test:known"]}
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)
        self.assertEqual(applied, ["test:known"])
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])

    async def test_c_unknown_obligation_blocks_before_dispatch(self) -> None:
        self._stub_decide(
            {
                "decision": "allow",
                "decision_id": "dec-c",
                "rule": "reeflex.policy/default_allow",
                "obligations": ["redact:pii"],  # a real SPEC-example string this v1 does NOT implement
            }
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertTrue(result.isError)
        text = result.content[0].text
        self.assertIn("unsupported obligation", text)
        self.assertIn("redact:pii", text)
        self.assertIn("dec-c", text)
        # THE key proof: the upstream was NEVER dispatched.
        self.assertEqual(self.fake_conn.dispatched, [])

    async def test_c2_first_unknown_obligation_blocks_even_if_a_known_one_precedes_it(self) -> None:
        applied = []
        obligations.register("test:known", lambda ctx: applied.append(ctx.obligation))
        self._stub_decide(
            {
                "decision": "allow",
                "decision_id": "dec-c2",
                "rule": "r",
                "obligations": ["test:known", "test:totally-unknown"],
            }
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertTrue(result.isError)
        self.assertIn("test:totally-unknown", result.content[0].text)
        self.assertEqual(applied, ["test:known"])  # the known one before it WAS applied
        self.assertEqual(self.fake_conn.dispatched, [])  # but nothing was dispatched

    async def test_e_approved_resubmission_also_honors_obligations_known(self) -> None:
        applied = []
        obligations.register("test:known", lambda ctx: applied.append(ctx.obligation))
        self._stub_decide(
            {
                "decision": "allow",
                "decision_id": "dec-e1",
                "rule": "reeflex.policy/approved_resubmission",
                "parent_decision_id": "dec-e0",
                "obligations": ["test:known"],
            }
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)
        self.assertEqual(applied, ["test:known"])
        self.assertEqual(result.meta.get("parent_decision_id"), "dec-e0")

    async def test_e2_approved_resubmission_also_fails_closed_on_unknown(self) -> None:
        self._stub_decide(
            {
                "decision": "allow",
                "decision_id": "dec-e2",
                "rule": "reeflex.policy/approved_resubmission",
                "parent_decision_id": "dec-e0b",
                "obligations": ["test:totally-unknown-2"],
            }
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertTrue(result.isError)
        self.assertIn("test:totally-unknown-2", result.content[0].text)
        self.assertEqual(self.fake_conn.dispatched, [])

    async def test_deny_verdict_never_reaches_obligation_handling(self) -> None:
        # A deny should block on the verdict itself -- obligations attached
        # to a deny are not separately "honored" (nothing is being
        # forwarded either way); this just confirms no crash/odd interaction.
        self._stub_decide(
            {"decision": "deny", "decision_id": "dec-f", "rule": "r", "reason": "no", "obligations": ["redact:pii"]}
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertTrue(result.isError)
        self.assertIn("denied", result.content[0].text)
        self.assertEqual(self.fake_conn.dispatched, [])


class TestObserveObligations(_ObligationsTestBase):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.gateway.mode = "observe"

    async def test_d_unknown_obligation_forwarded_and_recorded_not_blocked(self) -> None:
        self._stub_decide(
            {"decision": "allow", "decision_id": "dec-d", "rule": "r", "obligations": ["redact:pii"]}
        )
        import io
        import sys

        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        finally:
            sys.stderr = old_stderr

        self.assertFalse(result.isError)  # observe NEVER blocks
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])  # forwarded
        log_output = captured.getvalue()
        self.assertIn("would-honor", log_output)
        self.assertIn("redact:pii", log_output)  # recorded, not silently dropped

    async def test_observe_known_obligation_is_recorded_not_applied(self) -> None:
        # Observe must NOT invoke the handler's side effect -- only enforce
        # mode actually applies obligations (see gateway.py module docstring).
        applied = []
        obligations.register("test:known", lambda ctx: applied.append(ctx.obligation))
        self._stub_decide(
            {"decision": "allow", "decision_id": "dec-d2", "rule": "r", "obligations": ["test:known"]}
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)
        self.assertEqual(applied, [])  # NOT applied in observe mode
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])

    async def test_observe_core_unreachable_still_forwards_and_no_crash_on_obligations(self) -> None:
        async def fake_decide(envelope):
            return None, "core unreachable: connection refused"

        self.gateway._decide = fake_decide
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])

    async def test_observe_tags_decision_id_in_meta_and_logs_verdict(self) -> None:
        # GAP-1 fix (0.1.1): observe forwards AND tags decision_id in _meta +
        # logs the observed verdict, at parity with enforce's allow path.
        self._stub_decide(
            {"decision": "allow", "decision_id": "dec-obs-1", "rule": "reeflex.policy/default_allow"}
        )
        import io
        import sys

        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        finally:
            sys.stderr = old_stderr

        self.assertFalse(result.isError)  # observe NEVER blocks
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])  # still forwarded
        self.assertEqual(result.meta.get("decision_id"), "dec-obs-1")
        log_output = captured.getvalue()
        self.assertIn("observe", log_output)
        self.assertIn("would-allow", log_output)
        self.assertIn("dec-obs-1", log_output)

    async def test_observe_tags_parent_decision_id_when_present(self) -> None:
        self._stub_decide(
            {
                "decision": "deny",
                "decision_id": "dec-obs-2",
                "parent_decision_id": "dec-obs-0",
                "rule": "reeflex.core/hold_validation",
                "reason": "reeflex_hold_not_approved",
            }
        )
        result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        self.assertFalse(result.isError)  # observe never blocks, even on a deny verdict
        self.assertEqual(self.fake_conn.dispatched, [("read_file", {"path": "x"})])
        self.assertEqual(result.meta.get("decision_id"), "dec-obs-2")
        self.assertEqual(result.meta.get("parent_decision_id"), "dec-obs-0")

    async def test_observe_no_decision_id_key_omitted_from_meta_no_duplicate_warn(self) -> None:
        # decision is None (core unreachable) -- _apply_mode_observe() already
        # logs the fail-open WARN; the GAP-1 verdict log line must NOT also
        # fire (no decision to report), and no decision_id key should be tagged.
        async def fake_decide(envelope):
            return None, "core unreachable: connection refused"

        self.gateway._decide = fake_decide
        import io
        import sys

        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            result = await self.gateway._handle_call_tool("fs__read_file", {"path": "x"})
        finally:
            sys.stderr = old_stderr

        self.assertFalse(result.isError)
        self.assertNotIn("decision_id", result.meta or {})
        log_output = captured.getvalue()
        self.assertIn("WARN", log_output)  # the existing fail-open warning
        self.assertNotIn("would-", log_output)  # no duplicate verdict line


if __name__ == "__main__":
    unittest.main()
