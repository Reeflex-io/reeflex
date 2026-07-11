"""
test_obligations.py -- unit tests for reeflex_mcp.obligations (Track 5.1,
design doc ADDENDUM v1.5 section 25): the handler registry / dispatch
mechanism itself. Gateway-level enforce-block / observe-record behavior is
covered in tests/test_gateway.py (TestObligations*).
"""

from __future__ import annotations

import unittest

from reeflex_mcp import obligations


class TestRegisterAndApply(unittest.TestCase):
    def setUp(self) -> None:
        # Isolate each test from the module-level registry (which carries
        # the real v1 known-set, e.g. "audit:full") by snapshotting and
        # restoring it -- these tests register throwaway synthetic
        # obligations that must not leak into other tests.
        self._saved = dict(obligations._HANDLERS)

    def tearDown(self) -> None:
        obligations._HANDLERS.clear()
        obligations._HANDLERS.update(self._saved)

    def _ctx(self, obligation: str = "test:synthetic") -> obligations.ObligationContext:
        return obligations.ObligationContext(
            obligation=obligation,
            envelope={"action": {"verb": "read"}},
            decision={"decision": "allow", "decision_id": "dec-1", "obligations": [obligation]},
            gateway_correlation_id="corr-1",
            upstream_name="fs",
            tool_name="read_file",
        )

    def test_register_then_apply_calls_handler(self) -> None:
        calls = []
        obligations.register("test:synthetic", lambda ctx: calls.append(ctx.obligation))
        obligations.apply_known("test:synthetic", self._ctx())
        self.assertEqual(calls, ["test:synthetic"])

    def test_apply_unknown_raises(self) -> None:
        with self.assertRaises(obligations.UnknownObligationError):
            obligations.apply_known("test:never-registered", self._ctx("test:never-registered"))

    def test_unknown_obligation_error_carries_name(self) -> None:
        try:
            obligations.apply_known("test:xyz", self._ctx("test:xyz"))
            self.fail("expected UnknownObligationError")
        except obligations.UnknownObligationError as exc:
            self.assertEqual(exc.obligation, "test:xyz")

    def test_known_obligations_reflects_registrations(self) -> None:
        obligations.register("test:a", lambda ctx: None)
        obligations.register("test:b", lambda ctx: None)
        known = obligations.known_obligations()
        self.assertIn("test:a", known)
        self.assertIn("test:b", known)

    def test_last_registration_wins(self) -> None:
        calls = []
        obligations.register("test:dup", lambda ctx: calls.append("first"))
        obligations.register("test:dup", lambda ctx: calls.append("second"))
        obligations.apply_known("test:dup", self._ctx("test:dup"))
        self.assertEqual(calls, ["second"])

    def test_register_rejects_empty_string(self) -> None:
        with self.assertRaises(ValueError):
            obligations.register("", lambda ctx: None)

    def test_handler_receives_full_context(self) -> None:
        seen = {}

        def handler(ctx: obligations.ObligationContext) -> None:
            seen["obligation"] = ctx.obligation
            seen["upstream_name"] = ctx.upstream_name
            seen["tool_name"] = ctx.tool_name
            seen["gateway_correlation_id"] = ctx.gateway_correlation_id
            seen["decision"] = ctx.decision
            seen["envelope"] = ctx.envelope

        obligations.register("test:ctx", handler)
        ctx = self._ctx("test:ctx")
        obligations.apply_known("test:ctx", ctx)
        self.assertEqual(seen["obligation"], "test:ctx")
        self.assertEqual(seen["upstream_name"], "fs")
        self.assertEqual(seen["tool_name"], "read_file")
        self.assertEqual(seen["gateway_correlation_id"], "corr-1")
        self.assertEqual(seen["decision"]["decision_id"], "dec-1")


class TestV1KnownSet(unittest.TestCase):
    """The shipped v1 known-set (design doc section 25: 'may be empty/
    minimal for v1') -- one real, SPEC-referenced example: 'audit:full'."""

    def test_audit_full_is_registered(self) -> None:
        self.assertIn("audit:full", obligations.known_obligations())

    def test_audit_full_applies_without_raising(self) -> None:
        ctx = obligations.ObligationContext(
            obligation="audit:full",
            envelope={"action": {"verb": "read"}, "target": {"environment": "staging"}},
            decision={"decision": "allow", "decision_id": "dec-2", "obligations": ["audit:full"]},
            gateway_correlation_id="corr-2",
            upstream_name="fs",
            tool_name="read_file",
        )
        obligations.apply_known("audit:full", ctx)  # must not raise

    def test_audit_full_logs_to_stderr(self) -> None:
        import io
        import sys

        ctx = obligations.ObligationContext(
            obligation="audit:full",
            envelope={"action": {"verb": "read"}},
            decision={"decision": "allow", "decision_id": "dec-3"},
            gateway_correlation_id="corr-3",
            upstream_name="fs",
            tool_name="read_file",
        )
        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured
        try:
            obligations.apply_known("audit:full", ctx)
        finally:
            sys.stderr = old_stderr
        output = captured.getvalue()
        self.assertIn("audit:full", output)
        self.assertIn("corr-3", output)


if __name__ == "__main__":
    unittest.main()
