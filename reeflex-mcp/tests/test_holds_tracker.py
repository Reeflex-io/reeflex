"""
test_holds_tracker.py -- unit tests for reeflex_mcp.holds_tracker.PendingHoldTracker.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from reeflex_mcp.holds_tracker import PendingHold, PendingHoldTracker


def _future_ts(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _past_ts(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestPendingHoldTracker(unittest.TestCase):
    def test_get_returns_none_when_absent(self) -> None:
        tracker = PendingHoldTracker()
        self.assertIsNone(tracker.get("sess-1", "hash-1"))

    def test_put_then_get_roundtrips(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts=_future_ts(), rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        self.assertEqual(tracker.get("sess-1", "hash-1"), entry)

    def test_scoped_by_session_and_hash(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts=_future_ts(), rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        self.assertIsNone(tracker.get("sess-2", "hash-1"))  # different session
        self.assertIsNone(tracker.get("sess-1", "hash-2"))  # different action

    def test_clear_removes_entry(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts=_future_ts(), rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        tracker.clear("sess-1", "hash-1")
        self.assertIsNone(tracker.get("sess-1", "hash-1"))

    def test_clear_on_missing_entry_is_a_no_op(self) -> None:
        tracker = PendingHoldTracker()
        tracker.clear("sess-1", "hash-1")  # must not raise

    def test_put_overwrites_existing_entry(self) -> None:
        tracker = PendingHoldTracker()
        entry1 = PendingHold(hold_id="h1", decision_id="d1", expires_ts=_future_ts(), rule="r", reason="x")
        entry2 = PendingHold(hold_id="h2", decision_id="d2", expires_ts=_future_ts(), rule="r2", reason="y")
        tracker.put("sess-1", "hash-1", entry1)
        tracker.put("sess-1", "hash-1", entry2)
        self.assertEqual(tracker.get("sess-1", "hash-1"), entry2)

    def test_expired_entry_is_pruned_on_get(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts=_past_ts(), rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        self.assertIsNone(tracker.get("sess-1", "hash-1"))
        # pruned -- a second get also returns None without error (already gone)
        self.assertIsNone(tracker.get("sess-1", "hash-1"))

    def test_blank_expires_ts_never_treated_as_expired(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts="", rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        self.assertEqual(tracker.get("sess-1", "hash-1"), entry)

    def test_unparseable_expires_ts_conservatively_not_expired(self) -> None:
        tracker = PendingHoldTracker()
        entry = PendingHold(hold_id="h1", decision_id="d1", expires_ts="not-a-timestamp", rule="r", reason="x")
        tracker.put("sess-1", "hash-1", entry)
        self.assertEqual(tracker.get("sess-1", "hash-1"), entry)


if __name__ == "__main__":
    unittest.main()
