"""
holds.py — Event-sourced, append-only JSONL hold store for reeflex-core HIL Phase 1.

Design contract
---------------
HOLD STORE: append-only JSONL at env REEFLEX_HOLDS_PATH
(default: alongside the audit log, e.g. <repo>/reeflex-core/audit/holds.jsonl).

EVENT-SOURCED: every state change is a NEW appended record — never rewrite.
An in-memory index is rebuilt at boot by folding all records to current hold
state, and updated on every append.

Hold record fields (§6 design):
  id            uuid4 hex (no dashes)
  created_ts    ISO8601 UTC  "2026-07-04T12:00:00Z"
  expires_ts    created_ts + TTL (default 4h; env REEFLEX_HOLD_TTL_SECONDS)
  envelope      full validated envelope dict
  envelope_hash sha256 hex of the CANONICAL envelope JSON
  rule_id       string, e.g. "reeflex.policy/irreversible_broad_prod"
  status        pending|approved|rejected|expired|consumed
  decided_by    "{type}:{identity}", e.g. "human:leo"   (None until resolved)
  decided_ts    ISO8601 UTC or None
  reason        optional string or None
  consumed_ts   ISO8601 UTC or None
  decision_id   uuid4 hex of the /v1/decide transit that created this hold
                (traceability; "" for holds created before this field existed)

Expiry is LAZY:
  - evaluated on read/validate
  - a pending hold past expires_ts folds to status=expired the FIRST time it
    is observed; an `expired` record is appended and the hold.expired webhook
    fires once
  - no background thread

THREAD SAFETY: a single module-level lock protects both file I/O and the
in-memory index.

IDIOMS: follows audit.py exactly — json.dumps(rec, separators=(",",":"))+"\n",
lock on write, read-back proof after write.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
import time
import uuid
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_TTL_SECONDS = 4 * 3600  # 4 hours


def _holds_path() -> pathlib.Path:
    env_path = os.environ.get("REEFLEX_HOLDS_PATH", "")
    if env_path:
        return pathlib.Path(env_path)
    here = pathlib.Path(__file__).resolve()
    return here.parent.parent / "audit" / "holds.jsonl"


def _ttl_seconds() -> int:
    try:
        return int(os.environ.get("REEFLEX_HOLD_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS)))
    except (ValueError, TypeError):
        return _DEFAULT_TTL_SECONDS


# ---------------------------------------------------------------------------
# Time helpers — ISO 8601 UTC strings; no datetime objects in the hold record
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_from_epoch(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _epoch_from_iso(iso: str) -> float:
    """Parse an ISO8601 UTC string 'YYYY-MM-DDTHH:MM:SSZ' -> epoch float.

    Uses calendar.timegm which correctly interprets the struct as UTC
    (unlike time.mktime which assumes local time).
    Returns 0.0 on parse failure (conservative: treat as already expired).
    """
    import calendar
    try:
        struct = time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        return float(calendar.timegm(struct))
    except (ValueError, OverflowError):
        return 0.0


# ---------------------------------------------------------------------------
# Canonical envelope hash
# ---------------------------------------------------------------------------

# ALLOWLIST of top-level envelope keys that define WHAT would execute.
# Excluded deliberately:
#   approval  — the carrier field that changes between original and resubmission
#   agent     — identity/session (who), not what
#   meta      — nonce + timestamp + signature (per-request volatile fields)
#   context   — enforcement mode, not the action itself
#   trajectory_ref — provenance ref, not the action
#   reeflex_version — protocol version, not the action
#
# Design §13: "a modified action cannot ride an old approval."
# Using an ALLOWLIST (not a denylist) means unknown volatile fields cannot
# sneak in and produce a spurious hash match or mismatch.
_HASH_ALLOWLIST: frozenset[str] = frozenset({"action", "axes", "magnitude", "target"})


def canonical_hash(envelope: dict) -> str:
    """Return sha256 hex of the action-defining projection of the envelope.

    Only the fields in _HASH_ALLOWLIST (action, axes, magnitude, target) are
    included.  This makes the hash stable across the original submission
    (approval absent) and the resubmission (approval={present, hold_id}),
    while still binding the hash to exactly WHAT would execute.

    Projection is sorted by key at every level for full determinism.
    """
    projection = {
        k: envelope[k]
        for k in _HASH_ALLOWLIST
        if k in envelope
    }
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# In-memory index + lock
# ---------------------------------------------------------------------------

# { hold_id -> hold_dict } — folded current state (not the raw event log)
_index: dict[str, dict] = {}
_lock = threading.Lock()
_loaded = False  # True once _boot_load() has run


def _boot_load() -> None:
    """Fold all records from the JSONL file into the in-memory index.

    Called once, lazily, on first use.  Must be called under _lock.
    """
    global _loaded
    path = _holds_path()
    _index.clear()
    if not path.exists():
        _loaded = True
        return

    try:
        with open(path, encoding="utf-8") as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    rec = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue  # skip corrupt line; never raises
                _fold_record(rec)
    except OSError:
        pass  # file unreadable at boot -> start with empty index

    _loaded = True


def _fold_record(rec: dict) -> None:
    """Apply one event record to the in-memory index.

    Rules:
      - event_type == "created"   : insert new hold
      - event_type == "resolved"  : update status + decided_by + decided_ts + reason
      - event_type == "expired"   : update status to expired
      - event_type == "consumed"  : update status to consumed + consumed_ts
    """
    hold_id = rec.get("id")
    if not hold_id:
        return
    event_type = rec.get("event_type", "created")

    if event_type == "created":
        _index[hold_id] = dict(rec)
    elif hold_id in _index:
        existing = _index[hold_id]
        if event_type == "resolved":
            existing["status"] = rec.get("status", existing["status"])
            existing["decided_by"] = rec.get("decided_by")
            existing["decided_ts"] = rec.get("decided_ts")
            existing["reason"] = rec.get("reason")
        elif event_type == "expired":
            existing["status"] = "expired"
        elif event_type == "consumed":
            existing["status"] = "consumed"
            existing["consumed_ts"] = rec.get("consumed_ts")


def _ensure_loaded() -> None:
    """Ensure the index has been loaded (no-op after first call)."""
    global _loaded
    if not _loaded:
        _boot_load()


# ---------------------------------------------------------------------------
# Webhook fire — imported lazily to avoid circular imports
# ---------------------------------------------------------------------------

def _fire_webhook(event: str, payload: dict) -> None:
    """Fire a webhook event. Fail-open: any exception is swallowed."""
    try:
        from app.webhook import fire  # type: ignore[import]
        fire(event, payload)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Hold-resolution audit (Art.14 evidence) — imported lazily, same pattern as
# _fire_webhook, to avoid a module-load-order dependency between holds.py
# and audit.py.  Fail-open: an audit write failure here must never break the
# hold state-machine transition that already succeeded (the append+readback
# into holds.jsonl above is the source of truth for the hold's own state;
# this is an ADDITIONAL evidence record on the separate decisions.jsonl
# stream -- see audit.record_hold_resolution() docstring).
#
# Emission points in THIS module (ALL at the resolution/decision moment, so
# every hold resolution is evidenced regardless of any later consumption):
#   "approved"/"rejected" -- resolve_hold(), immediately after the human's
#                 approve/reject decision is durably written to the hold store.
#                 Emitted symmetrically: the audited fact is the HUMAN OVERSIGHT
#                 DECISION (Art.14), which happens here whether or not an
#                 approved hold is ever resubmitted/consumed. decision_id="" at
#                 this point; the eventual resubmission's decision record carries
#                 this hold_id, correlating the executed action to the approval.
#   "expired"  -- _append_expired_event(), immediately after the lazy expiry
#                 transition is durably written (see its docstring: expiry
#                 is detected on next read/access, not by a background
#                 sweep, so this event fires the FIRST time a pending hold
#                 is observed past its expires_ts).
# ---------------------------------------------------------------------------

def _audit_hold_resolution(
    hold_id: str,
    resolution: str,
    decided_by: str,
    resolved_ts: str,
    decision_id: str = "",
) -> None:
    """Best-effort hold_resolution audit write. Fail-open: swallows all errors."""
    try:
        from app.audit import record_hold_resolution  # type: ignore[import]
        record_hold_resolution(
            hold_id, resolution, decided_by,
            decision_id=decision_id, resolved_ts=resolved_ts,
        )
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Expiry evaluation (lazy; called on read/validate)
# ---------------------------------------------------------------------------

def _check_expiry(hold: dict) -> dict:
    """If the hold is pending and past its expires_ts, flip it to expired.

    Appends an `expired` record and fires the webhook the FIRST time.
    Returns the (possibly mutated) hold dict.
    Must be called WITHOUT holding _lock (it will acquire _lock internally
    for the append).
    """
    if hold.get("status") != "pending":
        return hold
    expires_ts = hold.get("expires_ts", "")
    if not expires_ts:
        return hold
    # Conservative: if we can't parse the expiry, treat as non-expired
    # (the record will be caught on the next explicit validate_hold call).
    expires_epoch = _epoch_from_iso(expires_ts)
    if expires_epoch == 0.0:
        return hold
    if time.time() >= expires_epoch:
        # Flip to expired — append the record
        _append_expired_event(hold["id"])
    return hold  # caller re-reads from index to get updated status


def _append_expired_event(hold_id: str) -> None:
    """Append an expired event record and update the index.

    Fire-and-forget on webhook.
    """
    path = _holds_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    expired_ts = _iso_now()
    rec: dict = {
        "id": hold_id,
        "event_type": "expired",
        "expired_ts": expired_ts,
        "ts": expired_ts,
    }
    line = json.dumps(rec, separators=(",", ":")) + "\n"
    with _lock:
        _ensure_loaded()
        if hold_id not in _index:
            return
        if _index[hold_id].get("status") != "pending":
            # Already transitioned — skip duplicate expiry
            return
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        _fold_record(rec)
    # Fire webhook outside the lock
    hold = _index.get(hold_id, {})
    _fire_webhook("hold.expired", {
        "hold_id": hold_id,
        "rule_id": hold.get("rule_id", ""),
        "status": "expired",
        "ts": expired_ts,
    })
    # Art.14 evidence: expiry has no deciding principal (a timeout, not a
    # decision by any actor) -- "system:reeflex-core" is a documented
    # best-effort sentinel for decided_by, distinct from any real
    # "human:*"/"agent:*" principal format so it is never mistaken for one.
    _audit_hold_resolution(
        hold_id, "expired", "system:reeflex-core", expired_ts,
    )


# ---------------------------------------------------------------------------
# Core write helper
# ---------------------------------------------------------------------------

def _append_and_readback(rec: dict) -> dict:
    """Append one record to the JSONL file, update the index, read-back to verify.

    Must be called UNDER _lock.
    Raises OSError on I/O failure.
    """
    path = _holds_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(rec, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())

    # Read-back proof — same pattern as audit.py
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        if size == 0:
            raise OSError("holds file empty immediately after write")
        pos = size - 1
        while pos > 0:
            fh.seek(pos)
            ch = fh.read(1)
            if ch == b"\n" and pos < size - 1:
                break
            pos -= 1
        fh.seek(max(pos, 0))
        last_line = fh.read().decode("utf-8").strip()

    written = json.loads(last_line)
    if written.get("id") != rec.get("id"):
        raise OSError(
            f"holds read-back mismatch: wrote id={rec.get('id')!r}, read back id={written.get('id')!r}"
        )

    # Update in-memory index
    _fold_record(rec)
    return rec


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_hold(envelope: dict, rule_id: str, *, decision_id: str = "") -> dict:
    """Create a new pending hold for the given envelope + rule.

    decision_id (additive, keyword-only, default ""): the decision_id of the
    /v1/decide transit that produced the require_approval verdict creating
    this hold — so the hold names the decision that created it.  On
    resubmission, core falls back to this value for parent_decision_id when
    the adapter did not pass one back (see decide.py).

    Returns the hold record dict that was written.
    Fail-closed: any exception propagates to the caller (decide.py wraps in try/except).
    """
    hold_id = uuid.uuid4().hex  # no dashes
    now_epoch = time.time()
    now_iso = _iso_from_epoch(now_epoch)
    expires_iso = _iso_from_epoch(now_epoch + _ttl_seconds())
    env_hash = canonical_hash(envelope)

    rec: dict = {
        "id": hold_id,
        "event_type": "created",
        "created_ts": now_iso,
        "expires_ts": expires_iso,
        "envelope": envelope,
        "envelope_hash": env_hash,
        "rule_id": rule_id,
        "status": "pending",
        "decided_by": None,
        "decided_ts": None,
        "reason": None,
        "consumed_ts": None,
        "decision_id": decision_id,
        "ts": now_iso,
    }

    with _lock:
        _ensure_loaded()
        _append_and_readback(rec)

    return rec


def get_hold(hold_id: str) -> dict | None:
    """Return the current hold state for hold_id, or None if not found.

    Evaluates expiry lazily before returning.
    """
    with _lock:
        _ensure_loaded()
        hold = _index.get(hold_id)
        if hold is None:
            return None
        hold_copy = dict(hold)

    # Lazy expiry check — outside the lock (it re-acquires internally if needed)
    _check_expiry(hold_copy)

    # Re-read to get the post-expiry state
    with _lock:
        hold = _index.get(hold_id)
        return dict(hold) if hold is not None else None


def list_holds(
    status: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> tuple[list[dict], str | None]:
    """Return a paged list of holds, sweeping expiry first.

    Parameters
    ----------
    status : optional filter (pending|approved|rejected|expired|consumed)
    limit  : max records to return (default 100)
    cursor : opaque pagination token (hold_id of the last item on the previous page)

    Returns
    -------
    (items, next_cursor)
        items       : list of hold dicts (copies)
        next_cursor : hold_id of the last item if there are more, else None
    """
    with _lock:
        _ensure_loaded()
        all_ids = list(_index.keys())

    # Lazy-expire all pending holds (outside the lock; _check_expiry re-acquires)
    for hid in all_ids:
        with _lock:
            hold = _index.get(hid)
        if hold and hold.get("status") == "pending":
            _check_expiry(dict(hold))

    # Re-read the index after expiry sweep
    with _lock:
        snapshot = [dict(h) for h in _index.values()]

    # Sort deterministically by created_ts then id
    snapshot.sort(key=lambda h: (h.get("created_ts", ""), h.get("id", "")))

    # Apply status filter
    if status is not None:
        snapshot = [h for h in snapshot if h.get("status") == status]

    # Apply cursor (start AFTER the cursor item)
    if cursor:
        cursor_positions = [i for i, h in enumerate(snapshot) if h.get("id") == cursor]
        if cursor_positions:
            snapshot = snapshot[cursor_positions[0] + 1:]

    # Apply limit
    has_more = len(snapshot) > limit
    page = snapshot[:limit]
    next_cursor = page[-1]["id"] if has_more and page else None

    return page, next_cursor


def resolve_hold(
    hold_id: str,
    decision: str,
    principal_type: str,
    principal_id: str,
    reason: str | None = None,
) -> dict | None:
    """Resolve (approve or reject) a pending hold.

    Returns the updated hold dict, or None if the hold does not exist.
    The caller is responsible for the business-logic validation checks
    (T3: status==pending, not expired, non-resolvable guard, actor!=approver);
    this function only writes the state-change record.

    decision : "approved" | "rejected"
    """
    decided_ts = _iso_now()
    decided_by = f"{principal_type}:{principal_id}"
    new_status = "approved" if decision == "approve" else "rejected"

    rec: dict = {
        "id": hold_id,
        "event_type": "resolved",
        "status": new_status,
        "decided_by": decided_by,
        "decided_ts": decided_ts,
        "reason": reason,
        "ts": decided_ts,
    }

    with _lock:
        _ensure_loaded()
        if hold_id not in _index:
            return None
        _append_and_readback(rec)
        result = dict(_index[hold_id])

    # Art.14 evidence: emit the hold_resolution event HERE, at the HUMAN
    # DECISION point (resolve time), for BOTH "approved" and "rejected" --
    # outside _lock, immediately once the resolution is durably in the hold
    # store. Symmetric on purpose: the audited fact is the human's oversight
    # DECISION, which happens here regardless of whether an approved hold is
    # ever resubmitted/consumed. (An approved-but-never-consumed hold must
    # still be evidenced.) There is no /v1/decide transit at this point, so
    # decision_id is "" -- the eventual resubmission's decision record carries
    # this hold_id, so the two correlate. "expired" is emitted separately in
    # _append_expired_event(). See audit.record_hold_resolution() docstring.
    if new_status in ("approved", "rejected"):
        _audit_hold_resolution(hold_id, new_status, decided_by, decided_ts)

    return result


def mark_consumed(hold_id: str) -> dict | None:
    """Mark an approved hold as consumed (called after a successful resubmission).

    CAS (compare-and-set) GUARANTEE: this is a true single-use guard.  The
    status check (`status == "approved"`) and the append that flips it to
    "consumed" both happen INSIDE the same `_lock` acquisition, so the two
    steps are atomic with respect to any other thread calling mark_consumed
    concurrently.  Exactly one concurrent caller can observe status ==
    "approved" and win the consume; every other caller -- whether it arrives
    a nanosecond later on another thread or reads a hold that was never
    approved -- observes status != "approved" (already "consumed", or
    "pending"/"rejected"/"expired") and is refused.  This is what makes a
    single-use hold single-use under concurrency: it prevents an approved-
    once irreversible action from being double-consumed and double-executed.

    Returns the updated hold dict on a successful consume, or None if the
    hold does not exist OR the hold is not currently "approved".  Both None
    cases are "refuse consumption" from the caller's point of view -- the
    caller (decide.py) MUST treat a None return as "do not allow", not as
    "nothing happened".
    """
    consumed_ts = _iso_now()
    rec: dict = {
        "id": hold_id,
        "event_type": "consumed",
        "status": "consumed",
        "consumed_ts": consumed_ts,
        "ts": consumed_ts,
    }

    with _lock:
        _ensure_loaded()
        if hold_id not in _index:
            return None
        # CAS guard: only an "approved" hold may be consumed.  Checking this
        # status AND appending the consumed record both happen under the
        # single module-level _lock, so no other thread can observe
        # "approved" between this check and the append below -- exactly one
        # racing caller wins the consume.
        if _index[hold_id].get("status") != "approved":
            return None
        _append_and_readback(rec)
        return dict(_index[hold_id])


def is_expired(hold: dict) -> bool:
    """Return True if the hold is past its expires_ts (status-independent check).

    Used by the decision path and resolve API to guard without mutating state.
    """
    expires_ts = hold.get("expires_ts", "")
    if not expires_ts:
        return False
    expires_epoch = _epoch_from_iso(expires_ts)
    if expires_epoch == 0.0:
        return False  # unparseable -> treat as non-expired (conservative)
    return time.time() >= expires_epoch


# ---------------------------------------------------------------------------
# Test utilities — reset/reload
# ---------------------------------------------------------------------------

def _reset(path: str | None = None) -> None:
    """FOR TESTS ONLY: re-point the holds path and rebuild the index from scratch.

    If path is None, the module default (_holds_path()) is used.
    This allows tests to point at a temp file without side effects.
    """
    global _loaded
    if path is not None:
        os.environ["REEFLEX_HOLDS_PATH"] = path
    else:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
    with _lock:
        _index.clear()
        _loaded = False
        _boot_load()
