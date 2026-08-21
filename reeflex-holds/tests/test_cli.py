"""
test_cli.py -- unit tests for reeflex_holds.cli (the list/approve/reject
terminal subcommands, RFX-42).

No network: reeflex_holds.client's public functions are monkeypatched, same
pattern as test_server.py's _PatchClientFn. Asserts exactly what cli.py
forwards to client.py, what it prints, and its exit code -- the exit code is
the part that matters most here, since the defect this module fixes was a
silent exit 0.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_holds import cli, client, config  # noqa: E402


class _PatchClientFn(unittest.TestCase):
    def setUp(self) -> None:
        self._originals: dict[str, object] = {}

    def _patch(self, name: str, fn) -> None:
        if name not in self._originals:
            self._originals[name] = getattr(client, name)
        setattr(client, name, fn)

    def tearDown(self) -> None:
        for name, fn in self._originals.items():
            setattr(client, name, fn)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# `list`
# ---------------------------------------------------------------------------

class TestList(_PatchClientFn):
    def test_no_args_forwards_no_status_filter(self) -> None:
        captured = {}

        def fake_list_holds(status=None):
            captured["status"] = status
            return {"items": [], "count": 0}

        self._patch("list_holds", fake_list_holds)
        code, out, _ = _run(["list"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIsNone(captured["status"])
        self.assertIn("No holds found", out)

    def test_status_flag_forwarded(self) -> None:
        captured = {}

        def fake_list_holds(status=None):
            captured["status"] = status
            return {"items": [], "count": 0}

        self._patch("list_holds", fake_list_holds)
        _run(["list", "--status", "pending"])
        self.assertEqual(captured["status"], "pending")

    def test_pending_holds_are_printed_not_silent(self) -> None:
        def fake_list_holds(status=None):
            return {
                "items": [
                    {
                        "id": "abc123",
                        "status": "pending",
                        "rule_id": "reeflex.policy/irreversible_broad_prod",
                        "created_ts": "2026-08-20T10:00:00Z",
                        "expires_ts": "2026-08-20T14:00:00Z",
                        "envelope": {
                            "action": {"ability": "wordpress/bulk-delete-posts"},
                            "magnitude": {"count": 420},
                        },
                    }
                ],
                "count": 1,
            }

        self._patch("list_holds", fake_list_holds)
        code, out, err = _run(["list", "--status", "pending"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("abc123", out)
        self.assertIn("pending", out)
        self.assertIn("wordpress/bulk-delete-posts", out)
        self.assertIn("x420", out)

    def test_json_flag_prints_raw_json(self) -> None:
        self._patch("list_holds", lambda status=None: {"items": [], "count": 0})
        code, out, _ = _run(["list", "--json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(out.strip(), '{"items": [], "count": 0}')

    def test_connection_error_exits_nonzero_with_message_on_stderr(self) -> None:
        def fake_list_holds(status=None):
            raise client.HoldsConnectionError("reeflex-core unreachable at http://x: refused")

        self._patch("list_holds", fake_list_holds)
        code, out, err = _run(["list"])
        self.assertEqual(code, cli.EXIT_SETUP_ERROR)
        self.assertEqual(out, "")
        self.assertIn("unreachable", err)

    def test_api_error_exits_nonzero(self) -> None:
        def fake_list_holds(status=None):
            raise client.HoldsAPIError(500, {"error": "internal"}, "http://x")

        self._patch("list_holds", fake_list_holds)
        code, _, err = _run(["list"])
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("500", err)

    def test_bad_status_choice_rejected_by_argparse(self) -> None:
        with self.assertRaises(SystemExit):
            _run(["list", "--status", "not-a-real-status"])


# ---------------------------------------------------------------------------
# `approve` / `reject`
# ---------------------------------------------------------------------------

class TestApprove(_PatchClientFn):
    def test_forwards_id_decision_reason(self) -> None:
        captured = {}

        def fake_resolve_hold(hold_id, decision, reason=None):
            captured.update(hold_id=hold_id, decision=decision, reason=reason)
            return {"id": hold_id, "status": "approved", "decided_by": "human:leo", "decided_ts": "t"}

        self._patch("resolve_hold", fake_resolve_hold)
        code, out, _ = _run(["approve", "abc123", "--reason", "looks fine"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(captured, {"hold_id": "abc123", "decision": "approve", "reason": "looks fine"})
        self.assertIn("abc123", out)
        self.assertIn("approved", out)
        self.assertIn("human:leo", out)

    def test_reason_optional(self) -> None:
        captured = {}

        def fake_resolve_hold(hold_id, decision, reason=None):
            captured["reason"] = reason
            return {"id": hold_id, "status": "approved"}

        self._patch("resolve_hold", fake_resolve_hold)
        _run(["approve", "abc123"])
        self.assertIsNone(captured["reason"])

    def test_missing_principal_is_a_setup_error_not_a_crash(self) -> None:
        def fake_resolve_hold(hold_id, decision, reason=None):
            raise config.ConfigError("REEFLEX_PRINCIPAL is not set.")

        self._patch("resolve_hold", fake_resolve_hold)
        code, out, err = _run(["approve", "abc123"])
        self.assertEqual(code, cli.EXIT_SETUP_ERROR)
        self.assertEqual(out, "")
        self.assertIn("REEFLEX_PRINCIPAL", err)

    def test_core_rejection_surfaces_verbatim_on_stderr(self) -> None:
        def fake_resolve_hold(hold_id, decision, reason=None):
            raise client.HoldsAPIError(
                403,
                {"error": "actor_is_approver", "reason": "actor cannot approve its own action"},
                "http://x",
            )

        self._patch("resolve_hold", fake_resolve_hold)
        code, out, err = _run(["approve", "abc123"])
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertEqual(out, "")
        self.assertIn("actor_is_approver", err)

    def test_id_is_required(self) -> None:
        with self.assertRaises(SystemExit):
            _run(["approve"])

    def test_no_principal_argument_exists(self) -> None:
        # Anti-impersonation guarantee (same as the MCP tool, server.py):
        # there is no --principal flag on approve (or reject) at all -- the
        # resolving identity can only come from REEFLEX_PRINCIPAL server-side.
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["approve", "abc123", "--principal", "human:someone-else"])


class TestReject(_PatchClientFn):
    def test_forwards_reject_decision(self) -> None:
        captured = {}

        def fake_resolve_hold(hold_id, decision, reason=None):
            captured["decision"] = decision
            return {"id": hold_id, "status": "rejected"}

        self._patch("resolve_hold", fake_resolve_hold)
        code, out, _ = _run(["reject", "abc123", "--reason", "not today"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(captured["decision"], "reject")
        self.assertIn("rejected", out)


# ---------------------------------------------------------------------------
# No subcommand at all (argparse level) -- cli.main itself, not server
# dispatch (see test_server.py for the server.main() dispatch defect fix).
# ---------------------------------------------------------------------------

class TestNoSubcommand(unittest.TestCase):
    def test_no_subcommand_prints_help_and_exits_nonzero(self) -> None:
        code, out, _ = _run([])
        self.assertEqual(code, cli.EXIT_SETUP_ERROR)
        self.assertIn("usage", out.lower())


# ---------------------------------------------------------------------------
# Approver provenance (RFX-149)
#
# Core gained `decided_by_verified` / `principal_source` (RFX-84) precisely so
# that "an unverified claim is no longer indistinguishable from a real human
# decision".  Measured against a core carrying that change, this CLI printed
# ONE identical success sentence for both -- byte-for-byte -- so at the only
# surface a human reads, it stayed exactly indistinguishable.  These tests
# fail if that regresses.
# ---------------------------------------------------------------------------

_VERIFIED = {
    "id": "abc123", "status": "approved", "decided_by": "human:leo",
    "decided_ts": "t", "decided_by_verified": True, "principal_source": "credential",
}
_ASSERTED = {
    "id": "abc123", "status": "approved", "decided_by": "human:leo",
    "decided_ts": "t", "decided_by_verified": False, "principal_source": "asserted",
}


class TestApproverProvenance(_PatchClientFn):
    def _approve(self, record: dict) -> tuple[int, str, str]:
        self._patch("resolve_hold", lambda hold_id, decision, reason=None: record)
        return _run(["approve", "abc123"])

    def test_verified_and_unverified_are_distinguishable(self) -> None:
        _, out_v, err_v = self._approve(_VERIFIED)
        _, out_a, err_a = self._approve(_ASSERTED)
        # The regression this exists for: the two runs producing identical
        # human-readable output.
        self.assertNotEqual(out_v + err_v, out_a + err_a)
        self.assertIn("VERIFIED", err_v)
        self.assertNotIn("UNVERIFIED", err_v)
        self.assertIn("UNVERIFIED", err_a)

    def test_unverified_says_so_without_being_asked_for_json(self) -> None:
        # An operator who never passes --json must still be told.  Core's own
        # warning goes to CORE's stderr, on the other side of the wire.
        code, out, err = self._approve(_ASSERTED)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("approved", out)
        self.assertIn("asserted", err)

    def test_json_output_is_untouched(self) -> None:
        self._patch("resolve_hold", lambda hold_id, decision, reason=None: _ASSERTED)
        code, out, _ = _run(["approve", "abc123", "--json"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(json.loads(out), _ASSERTED)

    def test_old_core_is_not_reported_either_way(self) -> None:
        # A core predating RFX-84 sends neither field.  Claiming "verified" or
        # "unverified" would both be inventing evidence.
        _, _, err = self._approve(
            {"id": "abc123", "status": "approved", "decided_by": "human:leo", "decided_ts": "t"}
        )
        self.assertIn("not reported", err)
        self.assertNotIn("UNVERIFIED", err)
        self.assertNotIn("VERIFIED", err)

    def test_list_of_resolved_holds_names_the_approver(self) -> None:
        # `list --status approved` used to be a list of approvals with no
        # approver: id, rule, timestamps and nothing else.
        self._patch("list_holds", lambda status=None: {"items": [dict(_ASSERTED, rule_id="r", envelope={})], "count": 1})
        code, out, _ = _run(["list", "--status", "approved"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("human:leo", out)
        self.assertIn("UNVERIFIED", out)

    def test_pending_holds_print_no_decider_line(self) -> None:
        self._patch("list_holds", lambda status=None: {
            "items": [{"id": "p1", "status": "pending", "rule_id": "r", "envelope": {}}], "count": 1})
        code, out, err = _run(["list", "--status", "pending"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(err, "")
        self.assertNotIn("decided", out)


if __name__ == "__main__":
    unittest.main()
