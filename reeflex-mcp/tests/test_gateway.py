"""
test_gateway.py -- unit tests for reeflex_mcp.gateway's pure/sync pieces:
result tagging (isError propagation, section 21.4), mode application logic
(observe unchanged from Track 2; enforce's full Track 3 verdict mapping via
`_classify_enforce_verdict`, including the hold/resubmission cases), and
stdio-path session derivation. Full async tools/call wiring against real
upstreams (including the actual hold -> resolve -> resubmit -> execute
round trip against a real reeflex-core) is exercised by the manual E2E (see
reeflex-mcp README / the adapter-builder's final report for the exact
steps), not here.
"""

from __future__ import annotations

import unittest

import mcp.types as types

from reeflex_mcp.gateway import FrontSessionRegistry, Gateway, _error_result, _tag_result
from reeflex_mcp.holds_tracker import PendingHold
from reeflex_mcp.registry import GatewayConfig, UpstreamSpec


def _gw_config(mode: str | None = "observe") -> GatewayConfig:
    return GatewayConfig(
        file_mode=mode,
        upstreams=(
            UpstreamSpec(
                name="fs",
                kind="stdio",
                target_system="filesystem",
                target_environment="staging",
                command="python",
                args=("server.py",),
            ),
        ),
        clients=(),
        source_path="test.yaml",
    )


class TestErrorResult(unittest.TestCase):
    def test_is_error_true(self) -> None:
        result = _error_result("boom")
        self.assertTrue(result.isError)
        self.assertEqual(result.content[0].text, "boom")

    def test_correlation_id_in_meta(self) -> None:
        result = _error_result("boom", gateway_correlation_id="corr-1")
        self.assertEqual(result.meta, {"gateway_correlation_id": "corr-1"})

    def test_no_correlation_id_means_no_meta(self) -> None:
        result = _error_result("boom")
        self.assertIsNone(result.meta)


class TestTagResult(unittest.TestCase):
    def test_preserves_is_error_true(self) -> None:
        # section 21.4: isError must be propagated verbatim, never flattened.
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="upstream failed")],
            isError=True,
        )
        tagged = _tag_result(upstream_result, "corr-2")
        self.assertTrue(tagged.isError)
        self.assertEqual(tagged.content[0].text, "upstream failed")
        self.assertEqual(tagged.meta, {"gateway_correlation_id": "corr-2"})

    def test_preserves_is_error_false(self) -> None:
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            isError=False,
        )
        tagged = _tag_result(upstream_result, "corr-3")
        self.assertFalse(tagged.isError)

    def test_merges_with_existing_meta(self) -> None:
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            isError=False,
            _meta={"upstream_field": "x"},
        )
        tagged = _tag_result(upstream_result, "corr-4")
        self.assertEqual(tagged.meta, {"upstream_field": "x", "gateway_correlation_id": "corr-4"})

    def test_preserves_structured_content(self) -> None:
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="{}")],
            structuredContent={"a": 1},
            isError=False,
        )
        tagged = _tag_result(upstream_result, "corr-5")
        self.assertEqual(tagged.structuredContent, {"a": 1})

    def test_tags_decision_id(self) -> None:
        # Track 3 / design doc section 22: core's decision_id, tagged on allow.
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")], isError=False
        )
        tagged = _tag_result(upstream_result, "corr-6", decision_id="dec-1")
        self.assertEqual(tagged.meta, {"gateway_correlation_id": "corr-6", "decision_id": "dec-1"})

    def test_tags_parent_decision_id_on_resubmission(self) -> None:
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")], isError=False
        )
        tagged = _tag_result(upstream_result, "corr-7", decision_id="dec-2", parent_decision_id="dec-1")
        self.assertEqual(
            tagged.meta,
            {"gateway_correlation_id": "corr-7", "decision_id": "dec-2", "parent_decision_id": "dec-1"},
        )

    def test_no_decision_id_omitted_from_meta(self) -> None:
        upstream_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")], isError=False
        )
        tagged = _tag_result(upstream_result, "corr-8")
        self.assertEqual(tagged.meta, {"gateway_correlation_id": "corr-8"})


class TestApplyModeObserve(unittest.TestCase):
    """observe mode is UNCHANGED from Track 2 -- always forwards, fail-open."""

    def test_forwards_on_allow(self) -> None:
        gw = Gateway(_gw_config("observe"))
        action, reason = gw._apply_mode_observe({"decision": "allow"}, None)
        self.assertEqual(action, "forward")
        self.assertIsNone(reason)

    def test_forwards_on_deny(self) -> None:
        gw = Gateway(_gw_config("observe"))
        action, reason = gw._apply_mode_observe({"decision": "deny", "reason": "x", "rule": "r"}, None)
        self.assertEqual(action, "forward")

    def test_forwards_on_core_unreachable(self) -> None:
        gw = Gateway(_gw_config("observe"))
        action, reason = gw._apply_mode_observe(None, "core unreachable: connection refused")
        self.assertEqual(action, "forward")


class TestClassifyEnforceVerdict(unittest.TestCase):
    """The full Track 3 enforce-mode verdict -> outcome mapping (design doc
    section 9), including the empirically-discovered resubmission semantics
    (core denies with reeflex_hold_not_approved while a hold is still
    pending -- NOT require_approval again)."""

    def setUp(self) -> None:
        self.gw = Gateway(_gw_config("enforce"))

    # -- allow --------------------------------------------------------

    def test_allow_forwards_and_tags_decision_id(self) -> None:
        outcome = self.gw._classify_enforce_verdict({"decision": "allow", "decision_id": "dec-1"}, None, None)
        self.assertEqual(outcome.action, "forward")
        self.assertEqual(outcome.decision_id, "dec-1")
        self.assertIsNone(outcome.parent_decision_id)
        self.assertFalse(outcome.clear_pending)
        self.assertIsNone(outcome.store_pending)

    def test_allow_resubmission_tags_parent_decision_id_and_clears_pending(self) -> None:
        pending = PendingHold(hold_id="h1", decision_id="dec-orig", expires_ts="2099-01-01T00:00:00Z", rule="r", reason="x")
        decision = {
            "decision": "allow",
            "decision_id": "dec-2",
            "rule": "reeflex.policy/approved_resubmission",
            "reason": "approved hold resubmission",
            "parent_decision_id": "dec-orig",
        }
        outcome = self.gw._classify_enforce_verdict(decision, None, pending)
        self.assertEqual(outcome.action, "forward")
        self.assertEqual(outcome.decision_id, "dec-2")
        self.assertEqual(outcome.parent_decision_id, "dec-orig")
        self.assertTrue(outcome.clear_pending)

    # -- deny (terminal) ------------------------------------------------

    def test_deny_blocks_with_rule_reason_decision_id(self) -> None:
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "deny", "reason": "no", "rule": "reeflex.policy/irreversible_systemic_prod", "decision_id": "dec-3"},
            None,
            None,
        )
        self.assertEqual(outcome.action, "block")
        self.assertIn("no", outcome.message)
        self.assertIn("reeflex.policy/irreversible_systemic_prod", outcome.message)
        self.assertIn("dec-3", outcome.message)

    def test_deny_relays_frozen_rule_transparently(self) -> None:
        # design doc section 9 / Track 3 item 3: no gateway-side freeze logic
        # -- core's reeflex.policy/frozen deny is just relayed like any other.
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "deny", "reason": "frozen by operator", "rule": "reeflex.policy/frozen", "decision_id": "dec-4"},
            None,
            None,
        )
        self.assertEqual(outcome.action, "block")
        self.assertIn("reeflex.policy/frozen", outcome.message)

    def test_deny_clears_pending_on_terminal_reason(self) -> None:
        # e.g. reeflex_hold_expired/rejected/consumed/envelope_mismatch/
        # actor_is_approver -- anything other than the specific
        # reeflex_hold_not_approved+hold_validation pair is terminal.
        pending = PendingHold(hold_id="h1", decision_id="dec-orig", expires_ts="2099-01-01T00:00:00Z", rule="r", reason="x")
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "deny", "reason": "reeflex_hold_expired", "rule": "reeflex.core/hold_validation", "decision_id": "dec-5"},
            None,
            pending,
        )
        self.assertEqual(outcome.action, "block")
        self.assertTrue(outcome.clear_pending)

    # -- deny (still pending -- the empirically-discovered case) ---------

    def test_deny_still_pending_reoffers_same_hold_without_clearing(self) -> None:
        pending = PendingHold(
            hold_id="h1", decision_id="dec-orig", expires_ts="2099-01-01T00:00:00Z",
            rule="reeflex.policy/irreversible_broad_prod", reason="irreversible broad change in production requires human approval",
        )
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "deny", "reason": "reeflex_hold_not_approved", "rule": "reeflex.core/hold_validation", "decision_id": "dec-6"},
            None,
            pending,
        )
        self.assertEqual(outcome.action, "block")
        self.assertIn("h1", outcome.message)
        self.assertIn("still held", outcome.message.lower())
        self.assertFalse(outcome.clear_pending)
        self.assertIsNone(outcome.store_pending)

    def test_deny_not_approved_without_pending_is_still_terminal(self) -> None:
        # No local pending entry (e.g. gateway restarted) -- even the
        # "not_approved" reason has nothing to keep re-offering; still a
        # normal (terminal-shaped) block, just without the "still held" framing.
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "deny", "reason": "reeflex_hold_not_approved", "rule": "reeflex.core/hold_validation", "decision_id": "dec-7"},
            None,
            None,
        )
        self.assertEqual(outcome.action, "block")
        self.assertFalse(outcome.clear_pending)

    # -- require_approval -------------------------------------------------

    def test_require_approval_blocks_and_stores_pending(self) -> None:
        outcome = self.gw._classify_enforce_verdict(
            {
                "decision": "require_approval",
                "reason": "irreversible broad change in production requires human approval",
                "rule": "reeflex.policy/irreversible_broad_prod",
                "decision_id": "dec-8",
                "hold_id": "h2",
                "expires_ts": "2099-01-01T00:00:00Z",
            },
            None,
            None,
        )
        self.assertEqual(outcome.action, "block")
        self.assertIn("h2", outcome.message)
        self.assertIn("hold_id=h2", outcome.message)
        self.assertIn("dec-8", outcome.message)
        self.assertIsNotNone(outcome.store_pending)
        self.assertEqual(outcome.store_pending.hold_id, "h2")
        self.assertEqual(outcome.store_pending.decision_id, "dec-8")

    def test_require_approval_without_hold_id_stores_nothing(self) -> None:
        # Defensive: core failed to mint a hold for some reason -- don't
        # store a bogus entry with an empty hold_id.
        outcome = self.gw._classify_enforce_verdict(
            {"decision": "require_approval", "reason": "x", "rule": "r", "decision_id": "dec-9"}, None, None
        )
        self.assertEqual(outcome.action, "block")
        self.assertIsNone(outcome.store_pending)

    # -- core unreachable -------------------------------------------------

    def test_core_unreachable_fails_closed(self) -> None:
        outcome = self.gw._classify_enforce_verdict(None, "core unreachable: connection refused", None)
        self.assertEqual(outcome.action, "block")
        self.assertIn("failing closed", outcome.message)
        self.assertIn("connection refused", outcome.message)

    # -- unknown verdict ---------------------------------------------------

    def test_unknown_verdict_fails_closed(self) -> None:
        outcome = self.gw._classify_enforce_verdict({"decision": "something_weird", "decision_id": "dec-10"}, None, None)
        self.assertEqual(outcome.action, "block")
        self.assertIn("dec-10", outcome.message)


class TestSessionDerivationStdio(unittest.TestCase):
    def test_stdio_front_has_stable_process_session_id(self) -> None:
        gw = Gateway(_gw_config("observe"))
        # No active request context outside a real MCP call -- exercises the
        # LookupError -> stdio branch exactly as it would with ctx.request is None.
        sid1, agent1, obo1 = gw._derive_session_and_agent()
        sid2, agent2, obo2 = gw._derive_session_and_agent()
        self.assertEqual(sid1, sid2)
        self.assertTrue(sid1.startswith("mcp-gateway:"))
        self.assertEqual(agent1, "agent:mcp-client")
        self.assertIsNone(obo1)


class TestFrontSessionRegistry(unittest.IsolatedAsyncioTestCase):
    async def test_broadcast_prunes_dead_sessions(self) -> None:
        class _OkSession:
            def __init__(self):
                self.sent = 0

            async def send_tool_list_changed(self):
                self.sent += 1

        class _DeadSession:
            async def send_tool_list_changed(self):
                raise RuntimeError("connection closed")

        reg = FrontSessionRegistry()
        ok = _OkSession()
        dead = _DeadSession()
        reg.register(ok)
        reg.register(dead)

        await reg.broadcast_tools_list_changed()
        self.assertEqual(ok.sent, 1)

        # dead session pruned -- a second broadcast doesn't touch it again,
        # and doesn't raise.
        await reg.broadcast_tools_list_changed()
        self.assertEqual(ok.sent, 2)


if __name__ == "__main__":
    unittest.main()
