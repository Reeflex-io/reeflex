"""
webhook.py — Outbound webhook emitter for reeflex-core HIL Phase 1.

=============================================================================
THE INVARIANT — READ THIS FIRST
=============================================================================

  "Fail-closed for decisions, fail-open for webhooks."

Webhooks are FIRE-AND-FORGET.  At-most-once delivery.  No retries.

  - A bounded in-memory queue holds outbound HTTP POST payloads.
  - One background daemon thread drains the queue and does ALL network I/O.
  - The fire() call from the decision path is NON-BLOCKING: it calls
    queue.put_nowait() inside a try/except queue.Full and returns
    immediately.  It MUST NEVER raise into /v1/decide.
  - Network errors, DNS failures, slow/unreachable endpoints, HTTP 5xx, and
    any other I/O exception are ALL swallowed in the worker thread.
  - It is IMPOSSIBLE to configure the emitter into blocking or breaking the
    decision gate.

  DESIGN CONSEQUENCE: if REEFLEX_WEBHOOK_URL is unset (the default), the
  module-level singleton's fire() is a one-line guard check — zero overhead
  on the decision path, no thread spawned.

=============================================================================
CONFIGURATION
=============================================================================

  REEFLEX_WEBHOOK_URL   (unset)   Webhook URL.  Absent -> no-op everywhere.
                                   When set, POST to this URL for every event.
  REEFLEX_WEBHOOK_QUEUE_SIZE 1000  Max in-memory queue depth before drop.

=============================================================================
EVENTS
=============================================================================

  hold.created    hold was created (pending)
  hold.resolved   hold was approved or rejected by a principal
  hold.expired    pending hold passed its expires_ts
  freeze.flipped  REEFLEX_FREEZE state changed (on->off or off->on)

  Payload shape (always JSON):
  {
    "event":      "<event_type>",
    "ts":         "<ISO8601 UTC>",
    "hold_id":    "<hex>",        // present for hold.* events
    "rule_id":    "<string>",     // present for hold.* events
    "status":     "<string>",     // present for hold.* events
    "decided_by": "<string>",     // present for hold.resolved
    "freeze_on":  <bool>,         // present for freeze.flipped
  }

=============================================================================
DROPPED EVENTS COUNTER
=============================================================================

  Module-level integer `dropped_events`. Incremented (thread-safely) each
  time queue.put_nowait() raises queue.Full.  Readable via get_dropped_count().

=============================================================================
TESTABILITY
=============================================================================

  - WebhookEmitter URL is injectable (constructor arg overrides env).
  - flush(timeout_s) drains the queue synchronously — for tests only.
  - fire() is a module-level function that delegates to the singleton.
  - reset_emitter(**kwargs) replaces the singleton — for tests only.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Dropped-events counter (module-level, thread-safe via GIL + atomic incr)
# ---------------------------------------------------------------------------

dropped_events: int = 0
_dropped_lock = threading.Lock()


def get_dropped_count() -> int:
    """Return the number of webhook events dropped due to queue overflow."""
    return dropped_events


def _increment_dropped() -> None:
    global dropped_events
    with _dropped_lock:
        dropped_events += 1


# ---------------------------------------------------------------------------
# WebhookEmitter
# ---------------------------------------------------------------------------

_WEBHOOK_TIMEOUT_SECONDS = 3


class WebhookEmitter:
    """
    Fire-and-forget HTTP POST emitter for reeflex-core HIL events.

    THE INVARIANT: fire() is non-blocking.  A failed put_nowait increments
    dropped_events and returns immediately.  The background daemon thread does
    all network I/O.  ALL exceptions in the worker are swallowed and NEVER
    propagate to the caller.

    Usage:
        emitter = WebhookEmitter()   # reads REEFLEX_WEBHOOK_URL from env
        emitter.start()              # spawns daemon thread (no-op if disabled)
        emitter.fire("hold.created", {...})
        emitter.stop()
    """

    _QUEUE_MAXSIZE: int = int(os.environ.get("REEFLEX_WEBHOOK_QUEUE_SIZE", "1000"))

    def __init__(self, *, url: str | None = None) -> None:
        # Injectable url overrides env for testability
        raw_url = url if url is not None else os.environ.get("REEFLEX_WEBHOOK_URL", "")
        self._url: str = raw_url.strip()
        self._enabled: bool = bool(self._url)

        self._queue: queue.Queue[dict | None] = queue.Queue(maxsize=self._QUEUE_MAXSIZE)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the background daemon thread.  No-op if URL is unset."""
        if not self._enabled:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="reeflex-webhook-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout_s: float = 2.0) -> None:
        """Signal worker to drain and exit.  Blocks up to timeout_s."""
        if not self._enabled or self._thread is None:
            return
        try:
            self._queue.put_nowait(None)  # sentinel
        except queue.Full:
            pass
        self._thread.join(timeout=timeout_s)

    def flush(self, timeout_s: float = 5.0) -> None:
        """Synchronously drain the queue — FOR TESTS ONLY."""
        if not self._enabled:
            return
        deadline = time.monotonic() + timeout_s
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)

    # ------------------------------------------------------------------
    # Public fire method (non-blocking per THE INVARIANT)
    # ------------------------------------------------------------------

    def fire(self, event: str, payload: dict) -> None:
        """
        Enqueue one webhook POST.

        THE INVARIANT: non-blocking.  Any failure (queue full, disabled,
        unexpected exception) is silently swallowed.  NEVER raises into
        the decision path.
        """
        # Guard: if disabled, this is a one-line check — zero overhead
        if not self._enabled:
            return
        # Build the message payload; add ts if not already present
        msg = dict(payload)
        msg["event"] = event
        if "ts" not in msg:
            msg["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._enqueue(msg)

    # ------------------------------------------------------------------
    # Internal: non-blocking enqueue (THE INVARIANT enforcement point)
    # ------------------------------------------------------------------

    def _enqueue(self, msg: dict) -> None:
        """
        INVARIANT ENFORCEMENT: non-blocking put.

        If the queue is full, increment dropped_events and return immediately.
        This method MUST NEVER raise; it is called from the decision path.
        """
        try:
            self._queue.put_nowait(msg)
        except queue.Full:
            _increment_dropped()

    # ------------------------------------------------------------------
    # Background worker thread — ALL network I/O lives here
    # ------------------------------------------------------------------

    def _worker(self) -> None:
        """
        Background daemon thread: dequeue messages and POST them.

        Runs until it receives the sentinel (None) or the process exits.
        ALL network errors are swallowed — they NEVER propagate.
        """
        _last_error_msg: str = ""

        while True:
            try:
                msg = self._queue.get(block=True, timeout=1.0)
            except queue.Empty:
                continue

            # Sentinel: drain remaining then exit
            if msg is None:
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                        if remaining is None:
                            break
                        _last_error_msg = self._send(remaining, _last_error_msg)
                    except queue.Empty:
                        break
                break

            _last_error_msg = self._send(msg, _last_error_msg)

    def _send(self, msg: dict, last_error_msg: str) -> str:
        """
        POST one message to self._url.

        Swallows ALL exceptions — logged to stderr (deduplicated).
        Returns the new last_error_msg string.
        """
        try:
            payload_bytes = json.dumps(msg, separators=(",", ":")).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=payload_bytes,
                method="POST",
            )
            req.add_header("Content-Type", "application/json; charset=utf-8")
            req.add_header("Content-Length", str(len(payload_bytes)))
            req.add_header("User-Agent", "reeflex-core-webhook/1")
            with urllib.request.urlopen(req, timeout=_WEBHOOK_TIMEOUT_SECONDS) as resp:
                resp.read()  # drain the response body
            return ""  # success: clear last error
        except Exception as exc:  # noqa: BLE001
            # INVARIANT: swallow all errors in the worker thread.
            err_str = f"{type(exc).__name__}: {exc}"
            if err_str != last_error_msg:
                print(
                    f"[reeflex-core] WARN: webhook POST to {self._url!r} failed: {err_str}",
                    file=sys.stderr,
                )
                return err_str
            return last_error_msg


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

# THE INVARIANT: when REEFLEX_WEBHOOK_URL is unset, fire() is a one-line no-op.
# No thread is spawned, no socket is opened.
_emitter: WebhookEmitter = WebhookEmitter()


def get_emitter() -> WebhookEmitter:
    """Return the process-wide WebhookEmitter singleton."""
    return _emitter


def fire(event: str, payload: dict) -> None:
    """Fire-and-forget: enqueue a webhook POST.

    THE INVARIANT: non-blocking.  Never raises.  Drop on overflow.
    """
    try:
        _emitter.fire(event, payload)
    except Exception:  # noqa: BLE001 — belt: must never raise into caller
        pass


def reset_emitter(**kwargs: Any) -> WebhookEmitter:
    """Replace the module-level singleton — FOR TESTS ONLY.

    Stops the current emitter's worker thread before replacing it.
    """
    global _emitter
    _emitter.stop(timeout_s=1.0)
    _emitter = WebhookEmitter(**kwargs)
    return _emitter


def start() -> None:
    """Start the module-level singleton's worker thread (called from server.py)."""
    _emitter.start()
