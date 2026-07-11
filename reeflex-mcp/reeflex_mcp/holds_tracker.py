"""
holds_tracker.py -- gateway-local, in-memory tracking of pending Reeflex
holds, keyed by (session_id, canonical action hash), so a client's retry of
the EXACT SAME action is recognized as a resubmission and the gateway
attaches `approval={present:true, hold_id, parent_decision_id}` automatically
(design doc section 9: "when the client retries, the gateway re-sends
/v1/decide with approval:{present:true, hold_id}").

NOT the source of truth. reeflex-core's hold store (holds.jsonl, via
/v1/holds) is authoritative -- this tracker only remembers "the last hold
WE minted for this exact action in this session" so:
  1. the gateway knows to attach approval on the client's next matching call
     (SPEC 5.1: single-use, TTL-bound, hash-bound holds -- a modified action
     gets a fresh hash and is treated as a brand-new request, never rides an
     old approval);
  2. a client that retries repeatedly BEFORE a human resolves the hold does
     not spawn a new hold on every retry -- the SAME hold_id is re-surfaced
     (see gateway.py's handling of core's "reeflex_hold_not_approved" deny,
     discovered empirically in the Track-3 E2E -- core does NOT re-return
     require_approval on a still-pending resubmission, it denies with that
     specific reason; the gateway must recognize this and keep re-offering
     the same hold rather than treating it as a terminal denial).

Process-local, in-memory, best-effort. If the gateway process restarts, this
state is lost -- the client's next call for that action falls back to a
normal (non-resubmission) request, and core mints a brand-new hold. This is a
documented degradation, not a correctness bug: core remains the sole
authority on hold state; losing this cache only means one extra hold gets
created instead of the old one being resumed.
"""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class PendingHold:
    hold_id: str
    decision_id: str  # the ORIGINAL decision_id that created this hold (SPEC 5.1 parent_decision_id)
    expires_ts: str  # ISO8601 UTC, as returned by core in the require_approval response
    rule: str
    reason: str


class PendingHoldTracker:
    """In-memory map: (session_id, canonical_hash) -> PendingHold."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], PendingHold] = {}

    def get(self, session_id: str, action_hash: str) -> PendingHold | None:
        """Return the pending hold for this (session, action), pruning it
        first if it looks past its own expires_ts (best-effort local
        housekeeping only -- core independently and authoritatively re-checks
        expiry on every resubmission regardless of what this cache thinks)."""
        key = (session_id, action_hash)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if _is_expired(entry.expires_ts):
            del self._entries[key]
            return None
        return entry

    def put(self, session_id: str, action_hash: str, entry: PendingHold) -> None:
        self._entries[(session_id, action_hash)] = entry

    def clear(self, session_id: str, action_hash: str) -> None:
        self._entries.pop((session_id, action_hash), None)


def _is_expired(expires_ts: str) -> bool:
    """Best-effort ISO8601 UTC ('YYYY-MM-DDTHH:MM:SSZ') expiry check.

    Any parse failure -> treat as NOT expired (conservative: a local parsing
    bug must never silently drop a still-usable pending hold reference; if it
    really is expired, core's own authoritative check denies it anyway with
    'reeflex_hold_expired', which this module's caller treats as a terminal
    deny that clears the entry -- see gateway.py).
    """
    if not expires_ts:
        return False
    try:
        struct = time.strptime(expires_ts, "%Y-%m-%dT%H:%M:%SZ")
        epoch = calendar.timegm(struct)
    except (ValueError, OverflowError):
        return False
    return time.time() >= epoch
