"""
test_decide.py — E2E decision pipeline tests for reeflex-core.

All tests drive the REAL decide.process() path end-to-end:
  envelope -> validate -> ledger -> OPA eval -> decision -> audit -> assert.

No mocking of OPA; the real `opa eval` subprocess is invoked.
OPA binary location: env REEFLEX_OPA_BIN (set by test runner or CI).

Test cases:
  T_allow                 read-only internal -> allow
  T_approval              irreversible + broad + production -> require_approval
  T_deny                  irreversible + systemic + production -> deny
  T_fragmentation         same session_id, cumulative deletes crossing budget (>20)
                          -> crossing call returns require_approval; earlier calls NOT blocked
  T_fail_closed           REEFLEX_OPA_BIN points at nonexistent binary -> deny (not allow)
  T_reject_invalid        structurally invalid envelope -> 400, rejected, NOT allow
  T_axis_coercion         F1: non-canonical axis values coerce to most-restrictive -> deny
  T_count_validation      F2: invalid magnitude.count values -> 400
  T_count_audit_parity    F2: count used in decision == count in audit record
  T_session_required      F3: missing/empty agent.session_id -> 400
  T_obligations           F4: obligations field present in every 200 response
  T_audit_readback_env    F5: audit path respects REEFLEX_AUDIT_LOG env var

Run:
  cd reeflex-core
  python -m pytest tests/test_decide.py -v
  # or
  python -m unittest tests.test_decide -v
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest
import uuid

# Make the app package importable from tests/ without install
_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod
from app.decide import process


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_session() -> str:
    """Return a unique session_id so tests don't bleed into each other."""
    return f"test_sess_{uuid.uuid4().hex[:12]}"


def _base_envelope(
    *,
    verb: str = "read",
    environment: str = "staging",
    reversibility: str = "reversible",
    blast_radius: str = "single",
    externality: str = "internal",
    count: int = 1,
    approval_present: bool = False,
    session_id: str | None = None,
    namespace: str = "test",
) -> dict:
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:test-runner",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id or _fresh_session(),
        },
        "action": {
            "namespace": namespace,
            "verb": verb,
            "ability": f"{namespace}/{verb}",
        },
        "target": {
            "kind": "entity",
            "ref": None,
            "environment": environment,
        },
        "params": {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": externality,
        },
        "approval": {"present": approval_present, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-06-29T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


# ---------------------------------------------------------------------------
# T_allow: read-only internal -> allow (R1 or R4)
# ---------------------------------------------------------------------------

class TestAllow(unittest.TestCase):

    def test_allow_read_only_internal(self) -> None:
        env = _base_envelope(
            verb="read",
            environment="production",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        status, resp = process(env)

        print(f"\n[T_allow] status={status} response={json.dumps(resp, indent=2)}")

        self.assertEqual(status, 200, f"expected HTTP 200, got {status}: {resp}")
        self.assertEqual(
            resp["decision"], "allow",
            f"expected allow, got: {resp}"
        )
        self.assertIn(resp["rule"], (
            "reeflex.policy/read_only_internal",
            "reeflex.policy/default_allow",
        ), f"unexpected rule: {resp['rule']}")
        self.assertIn("obligations", resp)
        self.assertIsNone(resp["modulation"])


# ---------------------------------------------------------------------------
# T_approval: irreversible + broad + production -> require_approval (R2)
# ---------------------------------------------------------------------------

class TestRequireApproval(unittest.TestCase):

    def test_irreversible_broad_production_requires_approval(self) -> None:
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        status, resp = process(env)

        print(f"\n[T_approval] status={status} response={json.dumps(resp, indent=2)}")

        self.assertEqual(status, 200, f"expected HTTP 200, got {status}: {resp}")
        self.assertEqual(
            resp["decision"], "require_approval",
            f"expected require_approval, got: {resp}"
        )
        self.assertEqual(resp["rule"], "reeflex.policy/irreversible_broad_prod")


# ---------------------------------------------------------------------------
# T_deny: irreversible + systemic + production -> deny (R3)
# ---------------------------------------------------------------------------

class TestDeny(unittest.TestCase):

    def test_irreversible_systemic_production_denies(self) -> None:
        env = _base_envelope(
            verb="execute",
            environment="production",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
        )
        status, resp = process(env)

        print(f"\n[T_deny] status={status} response={json.dumps(resp, indent=2)}")

        self.assertEqual(status, 200, f"expected HTTP 200, got {status}: {resp}")
        self.assertEqual(
            resp["decision"], "deny",
            f"expected deny, got: {resp}"
        )
        self.assertEqual(resp["rule"], "reeflex.policy/irreversible_systemic_prod")


# ---------------------------------------------------------------------------
# T_fragmentation: SPEC §4.1 cumulative budget (R5)
#
# Same session_id, repeated delete calls each with count=4.
# Budget = 20.  After 5 calls: prior=16, current=4 -> total=20 (NOT over).
# 6th call: prior=20, current=4 -> total=24 > 20 -> require_approval (R5).
# Earlier calls (1-5) must NOT be blocked by R5.
# ---------------------------------------------------------------------------

class TestFragmentation(unittest.TestCase):

    def setUp(self) -> None:
        # Use a shared session_id across all sub-calls in this test
        self.session_id = _fresh_session()
        # Clean any stale ledger state for this session
        ledger_mod.clear_session(self.session_id)

    def _delete_env(self, count: int) -> dict:
        """Build a delete envelope that does NOT trigger R2 or R3 on its own."""
        return {
            "reeflex_version": "0.1",
            "agent": {
                "id": "agent:test-runner",
                "on_behalf_of": "user:synthetic",
                "session_id": self.session_id,
            },
            "action": {
                "namespace": "test",
                "verb": "delete",
                "ability": "test/delete",
            },
            "target": {
                "kind": "row",
                "ref": None,
                "environment": "staging",       # not production -> R2/R3 won't fire
            },
            "params": {},
            "magnitude": {"count": count},
            "axes": {
                "reversibility": "recoverable", # not irreversible -> R2/R3 won't fire
                "blast_radius": "scoped",
                "externality": "internal",
            },
            "approval": {"present": False, "by": None, "role": None},
            "trajectory_ref": None,
            "context": {},
            "meta": {
                "timestamp": "2026-06-29T00:00:00Z",
                "nonce": uuid.uuid4().hex,
                "signature": "ed25519:skeleton_placeholder",
            },
        }

    def test_fragmentation_crossing_call_triggers_budget(self) -> None:
        """
        5 calls of count=4 each: cumulative deletes stay <= 20.
        6th call of count=4: prior=20, current=4 -> total=24 > 20 -> require_approval.

        This proves SPEC §4.1: fragmentation (splitting a >20 delete into many
        small calls) is detected and blocked at the crossing call.
        """
        results = []

        # Calls 1–5: each count=4; cumulative before call N = (N-1)*4
        # Before call 1: prior=0, total=4 -> allow
        # Before call 5: prior=16, total=20 -> allow (not strictly greater)
        for i in range(1, 6):
            env = self._delete_env(count=4)
            status, resp = process(env)
            results.append((i, status, resp["decision"], resp["rule"]))
            print(
                f"\n[T_fragmentation] call {i}: status={status} "
                f"decision={resp['decision']} rule={resp['rule']}"
            )

        # Verify calls 1-5 were NOT blocked by R5
        for call_num, status, decision, rule in results:
            self.assertEqual(status, 200, f"call {call_num}: unexpected status {status}")
            self.assertNotEqual(
                decision, "require_approval" if rule == "reeflex.policy/session_delete_budget" else "__never__",
                f"call {call_num} was prematurely blocked by session_delete_budget"
            )
            # None of calls 1-5 should fire the budget rule
            self.assertNotEqual(
                rule, "reeflex.policy/session_delete_budget",
                f"call {call_num}: budget rule fired too early (call {call_num})"
            )

        # Call 6: prior cumulative deletes = 5*4 = 20, current count = 4 -> total = 24 > 20
        env6 = self._delete_env(count=4)
        status6, resp6 = process(env6)
        print(
            f"\n[T_fragmentation] call 6 (crossing): status={status6} "
            f"decision={resp6['decision']} rule={resp6['rule']}"
        )

        self.assertEqual(status6, 200, f"call 6: unexpected status {status6}")
        self.assertEqual(
            resp6["decision"], "require_approval",
            f"call 6 should require_approval (budget crossed), got: {resp6}"
        )
        self.assertEqual(
            resp6["rule"], "reeflex.policy/session_delete_budget",
            f"call 6 should fire session_delete_budget, got rule: {resp6['rule']}"
        )


# ---------------------------------------------------------------------------
# T_fail_closed: bad OPA binary -> deny (NOT allow)
# ---------------------------------------------------------------------------

class TestFailClosed(unittest.TestCase):

    def test_missing_opa_binary_fails_closed(self) -> None:
        """
        Point REEFLEX_OPA_BIN at a nonexistent path.
        The decision MUST be deny, never allow.
        """
        original = os.environ.get("REEFLEX_OPA_BIN")
        os.environ["REEFLEX_OPA_BIN"] = "/nonexistent/path/to/opa_binary_xyz"

        try:
            env = _base_envelope(
                verb="delete",
                environment="production",
                reversibility="irreversible",
                blast_radius="broad",
            )
            status, resp = process(env)
        finally:
            # Restore
            if original is None:
                os.environ.pop("REEFLEX_OPA_BIN", None)
            else:
                os.environ["REEFLEX_OPA_BIN"] = original

        print(f"\n[T_fail_closed] status={status} response={json.dumps(resp, indent=2)}")

        # Must NOT be allow — fail-closed means deny
        self.assertNotEqual(
            resp.get("decision"), "allow",
            "FAIL-CLOSED VIOLATION: OPA binary missing but decision is 'allow'"
        )
        self.assertIn(
            resp.get("decision"), ("deny", "require_approval"),
            f"expected deny/require_approval on OPA failure, got: {resp}"
        )
        self.assertEqual(
            resp.get("rule"), "reeflex.core/fail_closed",
            f"expected fail_closed rule, got: {resp.get('rule')}"
        )


# ---------------------------------------------------------------------------
# T_reject_invalid: structurally invalid envelope -> 400, not allow
# ---------------------------------------------------------------------------

class TestRejectInvalid(unittest.TestCase):

    def test_missing_verb_rejected(self) -> None:
        """action.verb absent -> structural reject -> HTTP 400."""
        env = _base_envelope()
        del env["action"]["verb"]
        status, resp = process(env)
        print(f"\n[T_reject_invalid/missing_verb] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"expected 400, got {status}: {resp}")
        self.assertIn("error", resp)
        self.assertNotIn("decision", resp, "invalid envelope must not produce a decision")

    def test_missing_environment_rejected(self) -> None:
        """target.environment absent -> structural reject -> HTTP 400."""
        env = _base_envelope()
        del env["target"]["environment"]
        status, resp = process(env)
        print(f"\n[T_reject_invalid/missing_env] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"expected 400, got {status}: {resp}")
        self.assertIn("error", resp)

    def test_missing_action_object_rejected(self) -> None:
        """action object entirely absent -> structural reject -> HTTP 400."""
        env = _base_envelope()
        del env["action"]
        status, resp = process(env)
        print(f"\n[T_reject_invalid/missing_action] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"expected 400, got {status}: {resp}")

    def test_non_dict_body_rejected(self) -> None:
        """Top-level not a dict -> structural reject -> HTTP 400."""
        status, resp = process(["not", "a", "dict"])
        print(f"\n[T_reject_invalid/non_dict] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"expected 400, got {status}: {resp}")

    def test_conservative_defaults_for_missing_axes(self) -> None:
        """
        Missing axes values -> conservative defaults injected -> decision produced
        (NOT a reject; missing axis VALUES are defaulted, not rejected).
        The conservative defaults (irreversible, systemic, physical) should trigger
        a deny in production (R3: irreversible + systemic + production).
        """
        env = _base_envelope(environment="production")
        env["axes"] = {}  # all axis values missing -> defaults injected
        status, resp = process(env)
        print(
            f"\n[T_reject_invalid/conservative_defaults] status={status} "
            f"response={json.dumps(resp, indent=2)}"
        )
        # Should produce a decision (200), not 400 — axes VALUES can be defaulted
        self.assertEqual(status, 200, f"missing axis values must be defaulted, not rejected: {resp}")
        # Conservative defaults: irreversible + systemic + production -> deny (R3)
        self.assertEqual(
            resp["decision"], "deny",
            f"conservative defaults should yield deny (R3), got: {resp}"
        )


# ---------------------------------------------------------------------------
# Bonus: audit read-back proof (SELECT-after-write equivalent)
# F5: use REEFLEX_AUDIT_LOG env var with same precedence as audit.py
# ---------------------------------------------------------------------------

def _audit_path() -> pathlib.Path:
    """Return the audit log path using the same env-var logic as audit.py."""
    env_path = os.environ.get("REEFLEX_AUDIT_LOG", "")
    if env_path:
        return pathlib.Path(env_path)
    return pathlib.Path(_repo_root) / "audit" / "decisions.jsonl"


class TestAuditReadback(unittest.TestCase):

    def test_audit_record_written_and_readable(self) -> None:
        """
        After a decision, the audit JSONL file must contain a record with
        matching session_id, decision, and rule.
        F5: audit path is resolved via _audit_path() which honours REEFLEX_AUDIT_LOG.
        """
        audit_path = _audit_path()

        env = _base_envelope(
            verb="read",
            environment="staging",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        session_id = env["agent"]["session_id"]

        status, resp = process(env)
        self.assertEqual(status, 200)

        # Read back from audit log
        self.assertTrue(audit_path.exists(), f"audit file not found: {audit_path}")
        records = []
        with open(audit_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        # Find the record for this call
        matching = [r for r in records if r.get("session_id") == session_id]
        self.assertTrue(
            len(matching) >= 1,
            f"no audit record found for session_id={session_id}"
        )
        last = matching[-1]
        print(f"\n[T_audit_readback] record={json.dumps(last, indent=2)}")
        self.assertEqual(last["decision"], resp["decision"])
        self.assertEqual(last["rule"], resp["rule"])


# ---------------------------------------------------------------------------
# F1: Axis coercion — non-canonical values must coerce to most-restrictive
#     and produce deny (not allow) on a deny-class combination.
# ---------------------------------------------------------------------------

class TestAxisCoercion(unittest.TestCase):
    """
    SPEC §2 + §4: adapters MUST send canonical lowercase values.
    Non-canonical (wrong case, typo, unknown) -> coerce to most-restrictive.
    This is the P0 regression test: the old code passed non-canonical through
    verbatim, causing a silent allow on a deny-class action.
    """

    def _deny_combo_env(self, reversibility: str, blast_radius: str = "systemic") -> dict:
        """Build an envelope whose axes, once coerced, must yield deny (R3)."""
        env = _base_envelope(
            verb="execute",
            environment="production",
            reversibility=reversibility,
            blast_radius=blast_radius,
            externality="internal",
        )
        return env

    def test_titlecase_irreversible_coerces_to_deny(self) -> None:
        """'Irreversible' (title-case) -> coerced to 'irreversible' -> deny (R3)."""
        env = self._deny_combo_env(reversibility="Irreversible")
        status, resp = process(env)
        print(f"\n[T_axis_coercion/Irreversible] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["decision"], "deny",
            f"'Irreversible' must coerce to deny-class, got: {resp}"
        )

    def test_uppercase_irreversible_coerces_to_deny(self) -> None:
        """'IRREVERSIBLE' (all-caps) -> coerced to 'irreversible' -> deny (R3)."""
        env = self._deny_combo_env(reversibility="IRREVERSIBLE")
        status, resp = process(env)
        print(f"\n[T_axis_coercion/IRREVERSIBLE] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["decision"], "deny",
            f"'IRREVERSIBLE' must coerce to deny-class, got: {resp}"
        )

    def test_typo_permanent_coerces_to_deny(self) -> None:
        """'permanent' (not in enum) -> coerced to 'irreversible' -> deny (R3)."""
        env = self._deny_combo_env(reversibility="permanent")
        status, resp = process(env)
        print(f"\n[T_axis_coercion/permanent] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["decision"], "deny",
            f"'permanent' must coerce to deny-class, got: {resp}"
        )

    def test_unknown_axis_value_xyz_coerces_to_deny(self) -> None:
        """'xyz' (completely unknown) -> coerced to most-restrictive -> deny (R3)."""
        env = _base_envelope(
            verb="execute",
            environment="production",
        )
        env["axes"] = {
            "reversibility": "xyz",
            "blast_radius": "xyz",
            "externality": "xyz",
        }
        status, resp = process(env)
        print(f"\n[T_axis_coercion/xyz] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["decision"], "deny",
            f"Unknown axis values must coerce to most-restrictive (deny), got: {resp}"
        )

    def test_canonical_reversible_still_allows(self) -> None:
        """Sanity check: canonical 'reversible' still produces allow (not broken by F1)."""
        env = _base_envelope(
            verb="read",
            environment="production",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        status, resp = process(env)
        print(f"\n[T_axis_coercion/canonical_allow] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200)
        self.assertEqual(resp["decision"], "allow", f"canonical axes should allow: {resp}")


# ---------------------------------------------------------------------------
# F2: magnitude.count validation — invalid values -> HTTP 400
# ---------------------------------------------------------------------------

class TestCountValidation(unittest.TestCase):
    """
    F2: magnitude.count must be int >= 1.
    Floats, strings, bools, zero, and negatives are rejected with HTTP 400.
    Absent count -> treated as 1 (conservative default, not rejected).
    """

    def _env_with_count(self, count) -> dict:
        env = _base_envelope(verb="read", environment="staging")
        env["magnitude"] = {"count": count}
        return env

    def test_float_count_rejected(self) -> None:
        """count = 3.9 (float) -> HTTP 400."""
        env = self._env_with_count(3.9)
        status, resp = process(env)
        print(f"\n[T_count/float_3.9] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"float count must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_negative_count_rejected(self) -> None:
        """count = -5 -> HTTP 400."""
        env = self._env_with_count(-5)
        status, resp = process(env)
        print(f"\n[T_count/negative] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"negative count must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_zero_count_rejected(self) -> None:
        """count = 0 -> HTTP 400."""
        env = self._env_with_count(0)
        status, resp = process(env)
        print(f"\n[T_count/zero] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"zero count must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_string_count_rejected(self) -> None:
        """count = "20" (string) -> HTTP 400."""
        env = self._env_with_count("20")
        status, resp = process(env)
        print(f"\n[T_count/string] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"string count must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_bool_true_count_rejected(self) -> None:
        """count = True (bool) -> HTTP 400 (bool subclasses int but is not valid)."""
        env = self._env_with_count(True)
        status, resp = process(env)
        print(f"\n[T_count/bool_True] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"bool count must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_absent_count_defaults_to_1(self) -> None:
        """Absent magnitude.count -> conservative default of 1 -> 200 (not 400)."""
        env = _base_envelope(verb="read", environment="staging")
        del env["magnitude"]
        status, resp = process(env)
        print(f"\n[T_count/absent] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200, f"absent count should default to 1, not reject: {resp}")

    def test_valid_int_count_accepted(self) -> None:
        """count = 5 (valid int) -> 200."""
        env = self._env_with_count(5)
        status, resp = process(env)
        print(f"\n[T_count/valid_5] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200, f"valid int count should be accepted: {resp}")


# ---------------------------------------------------------------------------
# F2: count parity — count used for decision == count stored in audit record
# ---------------------------------------------------------------------------

class TestCountAuditParity(unittest.TestCase):
    """
    F2: The count fed to OPA must equal the count written to the audit log.
    We use a fragmentation-style call and verify the audit record's
    magnitude_count matches the envelope's count exactly.
    """

    def test_count_in_audit_matches_decision_input(self) -> None:
        """
        Submit count=7; after the decision, the audit record must store
        magnitude_count == 7 (not a float, not a different value).
        """
        audit_path = _audit_path()
        count_sent = 7
        env = _base_envelope(
            verb="delete",
            environment="staging",
            reversibility="recoverable",
            blast_radius="scoped",
            externality="internal",
            count=count_sent,
        )
        session_id = env["agent"]["session_id"]

        status, resp = process(env)
        self.assertEqual(status, 200, f"expected 200, got {status}: {resp}")

        # Read audit log and find the record for this session
        self.assertTrue(audit_path.exists(), f"audit file not found: {audit_path}")
        records = []
        with open(audit_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        matching = [r for r in records if r.get("session_id") == session_id]
        self.assertTrue(len(matching) >= 1, f"no audit record for session_id={session_id}")
        last = matching[-1]
        print(f"\n[T_count_parity] audit record magnitude_count={last.get('magnitude_count')}, sent={count_sent}")

        self.assertEqual(
            last.get("magnitude_count"), count_sent,
            f"audit magnitude_count {last.get('magnitude_count')} != sent {count_sent}"
        )
        # Also verify it is an integer, not a float
        self.assertIsInstance(
            last.get("magnitude_count"), int,
            f"audit magnitude_count must be int, got {type(last.get('magnitude_count'))}"
        )


# ---------------------------------------------------------------------------
# F3: session_id required — missing or empty -> HTTP 400
# ---------------------------------------------------------------------------

class TestSessionRequired(unittest.TestCase):
    """
    F3: agent.session_id is a conformance requirement (SPEC §7).
    Missing or empty session_id must be rejected with HTTP 400.
    """

    def test_missing_session_id_rejected(self) -> None:
        """agent.session_id absent -> HTTP 400."""
        env = _base_envelope()
        del env["agent"]["session_id"]
        status, resp = process(env)
        print(f"\n[T_session/missing] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"missing session_id must be rejected: {resp}")
        self.assertIn("error", resp)
        self.assertIn("session_id", resp.get("detail", ""), f"detail should mention session_id: {resp}")

    def test_empty_string_session_id_rejected(self) -> None:
        """agent.session_id = "" -> HTTP 400."""
        env = _base_envelope()
        env["agent"]["session_id"] = ""
        status, resp = process(env)
        print(f"\n[T_session/empty_string] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"empty session_id must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_whitespace_session_id_rejected(self) -> None:
        """agent.session_id = "   " (whitespace only) -> HTTP 400."""
        env = _base_envelope()
        env["agent"]["session_id"] = "   "
        status, resp = process(env)
        print(f"\n[T_session/whitespace] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"whitespace-only session_id must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_missing_agent_object_rejected(self) -> None:
        """agent object entirely absent -> HTTP 400 (session_id cannot be present)."""
        env = _base_envelope()
        del env["agent"]
        status, resp = process(env)
        print(f"\n[T_session/missing_agent] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 400, f"missing agent object must be rejected: {resp}")
        self.assertIn("error", resp)

    def test_valid_session_id_accepted(self) -> None:
        """Sanity: valid session_id -> 200."""
        env = _base_envelope(
            verb="read",
            environment="staging",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        status, resp = process(env)
        print(f"\n[T_session/valid] status={status} response={json.dumps(resp, indent=2)}")
        self.assertEqual(status, 200, f"valid session_id should produce 200: {resp}")


# ---------------------------------------------------------------------------
# F4: obligations field present in every 200 Decision response
# ---------------------------------------------------------------------------

class TestObligations(unittest.TestCase):
    """
    F4: SPEC §5 — obligations is a required field in every Decision response.
    Empty list is acceptable; the field must not be absent.
    """

    def test_obligations_present_in_allow_response(self) -> None:
        env = _base_envelope(
            verb="read",
            environment="staging",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
        )
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertIn("obligations", resp, f"obligations key missing from allow response: {resp}")
        self.assertIsInstance(resp["obligations"], list, f"obligations must be a list: {resp}")

    def test_obligations_present_in_deny_response(self) -> None:
        env = _base_envelope(
            verb="execute",
            environment="production",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
        )
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertIn("obligations", resp, f"obligations key missing from deny response: {resp}")
        self.assertIsInstance(resp["obligations"], list, f"obligations must be a list: {resp}")

    def test_obligations_present_in_require_approval_response(self) -> None:
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        status, resp = process(env)
        self.assertEqual(status, 200)
        self.assertIn("obligations", resp, f"obligations key missing from require_approval response: {resp}")
        self.assertIsInstance(resp["obligations"], list, f"obligations must be a list: {resp}")

    def test_obligations_present_in_fail_closed_response(self) -> None:
        """Even the fail-closed deny path must include obligations (it's hardcoded [])."""
        original = os.environ.get("REEFLEX_OPA_BIN")
        os.environ["REEFLEX_OPA_BIN"] = "/nonexistent/path/opa_xyz"
        try:
            env = _base_envelope(verb="read", environment="staging")
            status, resp = process(env)
        finally:
            if original is None:
                os.environ.pop("REEFLEX_OPA_BIN", None)
            else:
                os.environ["REEFLEX_OPA_BIN"] = original
        # Fail-closed returns 500
        self.assertEqual(status, 500)
        self.assertIn("obligations", resp, f"obligations key missing from fail-closed response: {resp}")
        self.assertIsInstance(resp["obligations"], list)


# ---------------------------------------------------------------------------
# F6: Crash-surface robustness — malformed-but-structurally-plausible inputs
#
# Every shape must yield a clean (status, dict) tuple and NEVER raise.
# None of these shapes may produce decision == "allow".
# ---------------------------------------------------------------------------

class TestCrashSurface(unittest.TestCase):
    """
    Regression suite for the five crash sites identified in the robustness
    review.  Each test verifies:
      1. process() returns a tuple (no exception raised).
      2. decision != "allow" (fail-closed).
      3. Specific shape-specific expectation (400 or deny-class).
    """

    # ---- helpers -----------------------------------------------------------

    def _call(self, env: dict) -> tuple[int, dict]:
        """Call process() and assert it returns a tuple (never raises)."""
        result = process(env)
        self.assertIsInstance(result, tuple, "process() must return a tuple, never raise")
        self.assertEqual(len(result), 2, "process() tuple must be (status, dict)")
        status, resp = result
        self.assertIsInstance(status, int)
        self.assertIsInstance(resp, dict)
        return result

    def _assert_not_allow(self, resp: dict, label: str) -> None:
        self.assertNotEqual(
            resp.get("decision"), "allow",
            f"[{label}] FAIL-CLOSED VIOLATION: got allow from malformed input"
        )

    # ---- crash site 1: axis value is unhashable (list/dict) ----------------

    def test_axis_reversibility_list_coerced_not_crash(self) -> None:
        """
        axes.reversibility = [1,2] (list) -> unhashable -> must coerce to
        most-restrictive default (irreversible), not crash.
        Use ALL axes as garbage so ALL coerce to most-restrictive defaults:
        irreversible + systemic + physical + production -> deny (R3).
        """
        env = _base_envelope(verb="execute", environment="production")
        env["axes"] = {
            "reversibility": [1, 2],    # list -> coerce to irreversible
            "blast_radius": "systemic",  # canonical -> kept as-is
            "externality": "internal",
        }
        status, resp = self._call(env)
        print(f"\n[T_crash/axis_list] status={status} resp={json.dumps(resp)}")
        # Coerced to most-restrictive; production + systemic + irreversible -> deny
        self._assert_not_allow(resp, "axis_list")
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "deny",
                         f"list axis value must coerce to most-restrictive (deny): {resp}")

    def test_axis_blast_radius_dict_coerced_not_crash(self) -> None:
        """
        axes.blast_radius = {"x":1} (dict) -> unhashable -> must coerce to
        most-restrictive default (systemic), not crash.
        Combined with irreversible + production -> deny (R3).
        """
        env = _base_envelope(verb="execute", environment="production")
        env["axes"] = {
            "reversibility": "irreversible",  # canonical -> kept
            "blast_radius": {"x": 1},          # dict -> coerce to systemic
            "externality": "internal",
        }
        status, resp = self._call(env)
        print(f"\n[T_crash/axis_dict] status={status} resp={json.dumps(resp)}")
        self._assert_not_allow(resp, "axis_dict")
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("decision"), "deny",
                         f"dict axis value must coerce to most-restrictive (deny): {resp}")

    # ---- crash site 2: magnitude is a non-dict -----------------------------

    def test_magnitude_string_rejected_not_crash(self) -> None:
        """magnitude = "lots" (string) -> must return 400, not crash."""
        env = _base_envelope(verb="read", environment="staging")
        env["magnitude"] = "lots"
        status, resp = self._call(env)
        print(f"\n[T_crash/magnitude_str] status={status} resp={json.dumps(resp)}")
        self._assert_not_allow(resp, "magnitude_string")
        self.assertEqual(status, 400,
                         f"string magnitude must be rejected with 400: {resp}")
        self.assertIn("error", resp)

    def test_magnitude_list_rejected_not_crash(self) -> None:
        """magnitude = [1] (list) -> must return 400, not crash."""
        env = _base_envelope(verb="read", environment="staging")
        env["magnitude"] = [1]
        status, resp = self._call(env)
        print(f"\n[T_crash/magnitude_list] status={status} resp={json.dumps(resp)}")
        self._assert_not_allow(resp, "magnitude_list")
        self.assertEqual(status, 400,
                         f"list magnitude must be rejected with 400: {resp}")
        self.assertIn("error", resp)

    # ---- crash site 3: approval is a non-dict ------------------------------

    def test_approval_string_coerced_not_crash(self) -> None:
        """
        approval = "yes" (string) -> coerced to not-approved, not a crash.
        A low-risk read/staging action may legitimately allow even without approval,
        so we only assert: no crash, returns a clean tuple, and the coercion
        does NOT misidentify the approval as present=True.
        We verify the coercion by using an action that requires approval and
        checking it does NOT flip to allow.
        """
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        env["approval"] = "yes"
        status, resp = self._call(env)
        print(f"\n[T_crash/approval_str] status={status} resp={json.dumps(resp)}")
        # Must not crash; the string "yes" does NOT grant approval ->
        # approval.present=False -> require_approval (not allow, not crash)
        self.assertEqual(status, 200)
        self.assertIn(resp.get("decision"), ("deny", "require_approval"),
                      f"string approval must not grant the action: {resp}")

    def test_approval_string_does_not_clear_budget_gate(self) -> None:
        """
        approval = "yes" on a budget-crossing delete must NOT grant approval.
        R2: irreversible + broad + production -> require_approval even when
        approval is a garbage string (coerced to present=False).
        """
        env = _base_envelope(
            verb="delete",
            environment="production",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            count=42,
        )
        env["approval"] = "yes"
        status, resp = self._call(env)
        print(f"\n[T_crash/approval_no_gate_clear] status={status} resp={json.dumps(resp)}")
        self._assert_not_allow(resp, "approval_no_gate_clear")
        self.assertEqual(status, 200)
        # Garbage approval coerces to present=False -> require_approval, not allow
        self.assertEqual(
            resp.get("decision"), "require_approval",
            f"string approval must not clear the gate: {resp}"
        )

    # ---- crash site 4: agent.session_id is a number ------------------------

    def test_session_id_number_rejected_not_crash(self) -> None:
        """agent.session_id = 12345 (int) -> must return 400, not crash."""
        env = _base_envelope(verb="read", environment="staging")
        env["agent"]["session_id"] = 12345
        status, resp = self._call(env)
        print(f"\n[T_crash/session_int] status={status} resp={json.dumps(resp)}")
        self._assert_not_allow(resp, "session_int")
        self.assertEqual(status, 400,
                         f"numeric session_id must be rejected with 400: {resp}")
        self.assertIn("error", resp)

    # ---- crash site 5: params is a non-dict --------------------------------

    def test_params_string_decision_produced_not_crash(self) -> None:
        """
        params = "x" (string) -> decision still produced AND audited (no crash).
        params is free passthrough; a non-dict value is coerced to {} and the
        pipeline continues.  Either 200 (decision) or 400 (if impl rejects) is
        acceptable; what is NOT acceptable is a raised exception.
        A low-risk read/staging action will legitimately allow; we only assert
        clean tuple return and no exception.
        """
        env = _base_envelope(verb="read", environment="staging")
        env["params"] = "x"
        status, resp = self._call(env)
        print(f"\n[T_crash/params_str] status={status} resp={json.dumps(resp)}")
        # Implementation coerces to {} -> pipeline continues -> 200
        self.assertIn(status, (200, 400),
                      f"params=string must yield 200 or 400, not {status}: {resp}")

    # ---- belt test: generic tuple guarantee --------------------------------

    def test_process_always_returns_tuple(self) -> None:
        """
        A battery of malformed shapes — each must return a (status, dict) tuple
        and never raise an exception.  The fail-closed assertion (no allow on a
        deny-class shape) is already covered per shape in dedicated tests above;
        this test asserts only the tuple guarantee across all shapes.
        """
        # Deny-class shapes: axis garbage on production+execute -> must not allow
        deny_class_shapes = [
            # reversibility=list -> coerce to irreversible; blast_radius=systemic -> deny
            {**_base_envelope(verb="execute", environment="production"),
             "axes": {"reversibility": [1, 2], "blast_radius": "systemic", "externality": "internal"}},
            # blast_radius=dict -> coerce to systemic; reversibility=irreversible -> deny
            {**_base_envelope(verb="execute", environment="production"),
             "axes": {"reversibility": "irreversible", "blast_radius": {"x": 1}, "externality": "internal"}},
            # session_id non-str -> 400 (no decision)
            {**_base_envelope(), "agent": {**_base_envelope()["agent"], "session_id": 12345}},
        ]
        # Shapes that 400 (magnitude non-dict)
        reject_shapes = [
            {**_base_envelope(), "magnitude": "lots"},
            {**_base_envelope(), "magnitude": [1]},
        ]
        # Shapes that coerce and may allow (low-risk action) - only tuple guarantee needed
        coerce_shapes = [
            {**_base_envelope(), "approval": "yes"},
            {**_base_envelope(), "approval": 42},
            {**_base_envelope(), "params": "x"},
            {**_base_envelope(), "params": [1, 2]},
        ]

        for i, shape in enumerate(deny_class_shapes):
            with self.subTest(kind="deny_class", shape_index=i):
                result = process(shape)
                self.assertIsInstance(result, tuple,
                    f"deny_class[{i}]: process() must return tuple, not raise")
                status, resp = result
                self.assertNotEqual(resp.get("decision"), "allow",
                    f"deny_class[{i}]: FAIL-CLOSED VIOLATION: deny-class shape returned allow")

        for i, shape in enumerate(reject_shapes):
            with self.subTest(kind="reject", shape_index=i):
                result = process(shape)
                self.assertIsInstance(result, tuple,
                    f"reject[{i}]: process() must return tuple, not raise")
                status, resp = result
                self.assertEqual(status, 400,
                    f"reject[{i}]: non-dict magnitude must yield 400, got {status}: {resp}")

        for i, shape in enumerate(coerce_shapes):
            with self.subTest(kind="coerce", shape_index=i):
                result = process(shape)
                self.assertIsInstance(result, tuple,
                    f"coerce[{i}]: process() must return tuple, not raise")
                status, resp = result
                self.assertIn(status, (200, 400),
                    f"coerce[{i}]: must yield 200 or 400, not {status}: {resp}")

    # ---- sanitized error: internal_error path must not leak traceback ------

    def test_internal_error_response_has_no_traceback(self) -> None:
        """
        The HTTP 500 internal_error response body must not contain a traceback
        or an absolute file path.  We trigger via the belt by passing an object
        that will cause the belt to fire after envelope validation passes but
        something unexpected happens downstream.

        Strategy: patch the `evaluate` name in app.decide's module namespace
        (not opa_mod) so that decide.py's already-bound reference is replaced.
        Raises bare RuntimeError (not OpaEvalError) to bypass the OpaEvalError
        handler and hit the outer except Exception belt.
        """
        import app.decide as decide_mod

        original_evaluate = decide_mod.evaluate

        def _raise_unexpected(*_a, **_kw):
            raise RuntimeError("synthetic unexpected crash for belt test")

        decide_mod.evaluate = _raise_unexpected
        try:
            env = _base_envelope(verb="read", environment="staging")
            status, resp = process(env)
        finally:
            decide_mod.evaluate = original_evaluate

        print(f"\n[T_crash/belt_sanitized] status={status} resp={json.dumps(resp)}")

        self.assertEqual(status, 500,
                         f"belt should return 500 on unexpected exception: {resp}")
        self.assertEqual(resp.get("decision"), "deny",
                         "belt must deny, not allow")
        self.assertEqual(resp.get("rule"), "reeflex.core/internal_error")

        # Verify no traceback text or absolute path in response body
        body_str = json.dumps(resp)
        self.assertNotIn("Traceback", body_str,
                         "response body must not contain traceback text")
        self.assertNotIn("File \"", body_str,
                         "response body must not contain file path from traceback")
        self.assertNotIn("reeflex-core", body_str,
                         "response body must not contain internal path")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
