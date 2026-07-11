"""
test_canonical.py -- unit tests for reeflex_mcp.canonical.canonical_hash.

These pin the algorithm against the exact behavior read from
reeflex-core/app/holds.py canonical_hash (allowlist, sort_keys JSON, sha256
hex) -- see canonical.py's module docstring for why this is deliberately
duplicated rather than imported.
"""

from __future__ import annotations

import hashlib
import json
import unittest

from reeflex_mcp import canonical

_BASE_ENVELOPE = {
    "reeflex_version": "0.1",
    "agent": {"id": "agent:mcp-client", "on_behalf_of": None, "session_id": "sess-1"},
    "action": {"namespace": "notes", "verb": "delete", "ability": "notes/delete_notes"},
    "target": {"kind": "delete_notes", "ref": None, "environment": "production"},
    "params": {"upstream": "notes", "tool_name": "delete_notes", "arguments": {"names": ["a", "b"]}},
    "magnitude": {"count": 2},
    "axes": {"reversibility": "irreversible", "blast_radius": "scoped", "externality": "internal"},
    "approval": {"present": False, "hold_id": None},
    "trajectory_ref": None,
    "context": {"gateway": "reeflex-mcp"},
    "meta": {"timestamp": "2026-07-11T00:00:00Z", "nonce": "abc123", "signature": "ed25519:stub:abc"},
}


class TestCanonicalHash(unittest.TestCase):
    def test_matches_manual_projection(self) -> None:
        expected_projection = {
            "action": _BASE_ENVELOPE["action"],
            "axes": _BASE_ENVELOPE["axes"],
            "magnitude": _BASE_ENVELOPE["magnitude"],
            "target": _BASE_ENVELOPE["target"],
        }
        expected = hashlib.sha256(
            json.dumps(expected_projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(canonical.canonical_hash(_BASE_ENVELOPE), expected)

    def test_stable_across_approval_change(self) -> None:
        # SPEC 5.1: the hash must be identical between the original submission
        # (approval.present=False) and a resubmission (approval={present:True,
        # hold_id:...}) -- approval is explicitly NOT in the allowlist.
        original = dict(_BASE_ENVELOPE)
        original["approval"] = {"present": False, "hold_id": None}

        resubmission = dict(_BASE_ENVELOPE)
        resubmission["approval"] = {"present": True, "hold_id": "h1", "parent_decision_id": "dec-1"}

        self.assertEqual(canonical.canonical_hash(original), canonical.canonical_hash(resubmission))

    def test_stable_across_agent_meta_context_change(self) -> None:
        # None of agent/meta/context/trajectory_ref/reeflex_version/params
        # are in the allowlist -- changing them must not change the hash.
        a = dict(_BASE_ENVELOPE)
        b = dict(_BASE_ENVELOPE)
        b["agent"] = {"id": "agent:someone-else", "on_behalf_of": "user:bob", "session_id": "sess-2"}
        b["meta"] = {"timestamp": "2030-01-01T00:00:00Z", "nonce": "different", "signature": "ed25519:stub:zzz"}
        b["context"] = {"gateway": "reeflex-mcp", "extra": "field"}
        b["trajectory_ref"] = "traj_1"
        b["params"] = {"upstream": "notes", "tool_name": "delete_notes", "arguments": {"names": ["different"]}}

        self.assertEqual(canonical.canonical_hash(a), canonical.canonical_hash(b))

    def test_changes_when_magnitude_changes(self) -> None:
        a = dict(_BASE_ENVELOPE)
        b = dict(_BASE_ENVELOPE)
        b["magnitude"] = {"count": 999}
        self.assertNotEqual(canonical.canonical_hash(a), canonical.canonical_hash(b))

    def test_changes_when_axes_change(self) -> None:
        a = dict(_BASE_ENVELOPE)
        b = dict(_BASE_ENVELOPE)
        b["axes"] = dict(_BASE_ENVELOPE["axes"], blast_radius="broad")
        self.assertNotEqual(canonical.canonical_hash(a), canonical.canonical_hash(b))

    def test_changes_when_target_changes(self) -> None:
        a = dict(_BASE_ENVELOPE)
        b = dict(_BASE_ENVELOPE)
        b["target"] = dict(_BASE_ENVELOPE["target"], environment="staging")
        self.assertNotEqual(canonical.canonical_hash(a), canonical.canonical_hash(b))

    def test_changes_when_action_changes(self) -> None:
        a = dict(_BASE_ENVELOPE)
        b = dict(_BASE_ENVELOPE)
        b["action"] = dict(_BASE_ENVELOPE["action"], verb="read")
        self.assertNotEqual(canonical.canonical_hash(a), canonical.canonical_hash(b))

    def test_missing_allowlist_key_is_tolerated(self) -> None:
        # Defensive: an envelope missing one of the allowlist keys should not
        # raise -- just projects whatever IS present (mirrors core's `if k in
        # envelope` guard).
        partial = {"action": _BASE_ENVELOPE["action"]}
        result = canonical.canonical_hash(partial)
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # sha256 hex length

    def test_key_order_in_source_dict_does_not_matter(self) -> None:
        reordered = {
            "target": _BASE_ENVELOPE["target"],
            "action": _BASE_ENVELOPE["action"],
            "magnitude": _BASE_ENVELOPE["magnitude"],
            "axes": _BASE_ENVELOPE["axes"],
        }
        self.assertEqual(canonical.canonical_hash(_BASE_ENVELOPE), canonical.canonical_hash(reordered))


if __name__ == "__main__":
    unittest.main()
