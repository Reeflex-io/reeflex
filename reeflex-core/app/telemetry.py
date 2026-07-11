"""
telemetry.py — SIEM/syslog telemetry emitter for reeflex-core.

STDLIB ONLY: socket, ssl, queue, threading, json, datetime, os, time, socket.
Zero external dependencies. This module is intentionally self-contained.

=============================================================================
THE INVARIANT — READ THIS FIRST
=============================================================================

  "Fail-closed for decisions, fail-open for telemetry."

Telemetry is FIRE-AND-FORGET.

  - A bounded in-memory queue holds outbound syslog messages.
  - One background daemon thread drains the queue and does ALL socket I/O.
  - The emit call from the decision path is NON-BLOCKING: it calls
    queue.put_nowait() inside a try/except queue.Full and returns
    immediately. It MUST NEVER raise into /v1/decide.
  - Socket errors, DNS failures, slow/unreachable endpoints, TLS handshake
    failures, and reconnection delays are ALL swallowed in the worker thread.
    At most a single stderr log line is emitted per error class.
  - It is IMPOSSIBLE to configure the emitter into blocking or breaking the
    decision gate. The audit JSONL remains the authoritative record.

  DESIGN CONSEQUENCE: if REEFLEX_SYSLOG_ENABLED is false (the default), no
  thread is spawned and every emit() call is a one-line guard check — zero
  overhead on the decision path.

=============================================================================
CONFIGURATION (all optional, via environment variables)
=============================================================================

  REEFLEX_SYSLOG_ENABLED    false       Master switch. Any value other than
                                         "true" (case-insensitive) = disabled.
  REEFLEX_SYSLOG_ADDRESS    <unset>     host:port required when enabled.
                                         If enabled but unset: log one warning,
                                         stay no-op, never crash.
  REEFLEX_SYSLOG_PROTOCOL   udp         udp | tcp | tls
  REEFLEX_SYSLOG_FORMAT     json        json | cef
  REEFLEX_SYSLOG_FACILITY   local0      syslog facility name
  REEFLEX_SYSLOG_TLS_VERIFY true        tls only; True = verify with default CA
                                         context; False = no-verify (self-signed
                                         collectors). Uses ssl default context /
                                         standard env variables (SSL_CERT_FILE etc.)

=============================================================================
TRANSPORTS
=============================================================================

  UDP  — one datagram per syslog message (RFC 5424 PRI + header + MSG).
  TCP  — RFC 6587 octet-counted framing: "<len> <syslog-msg>\n". Reconnect on
         drop, inside the worker thread.
  TLS  — RFC 5425: TCP + ssl wrap. Honour REEFLEX_SYSLOG_TLS_VERIFY.
         Reconnect on drop/handshake failure, inside the worker thread.

=============================================================================
WIRE FORMAT — RFC 5424
=============================================================================

  PRI = facility * 8 + severity
  Header: <PRI>1 TIMESTAMP(RFC3339) HOSTNAME reeflex PROCID MSGID STRUCTURED-DATA MSG
  APP-NAME = "reeflex"
  PROCID   = os.getpid() as string
  MSGID    = event type tag (e.g. "decision", "lifecycle", "kill_switch")

  format=json  -> MSG is the structured JSON object (one line, no indent)
  format=cef   -> MSG is a CEF:0 string (see CEF FORMAT section below)

=============================================================================
CEF FORMAT MAPPING
=============================================================================

  CEF:0|Reeflex|reeflex-core|<VERSION>|<rule_id>|<verdict>|<severity>|<extensions>

  Extensions (standard CEF key -> reeflex field):
    rt           -> ts (milliseconds since epoch, RFC 5424 §6 recommends rt in ms)
    act          -> verb (action verb: read, delete, execute …)
    suser        -> on_behalf_of (user the agent acts for)
    cs1          -> session_id         cs1Label=session_id
    cs2          -> agent_id           cs2Label=agent_id
    cs3          -> axes.reversibility cs3Label=reversibility
    cs4          -> axes.blast_radius  cs4Label=blast_radius
    cs5          -> axes.externality   cs5Label=externality
    cs6          -> environment        cs6Label=environment
    cn1          -> magnitude_count    cn1Label=magnitude_count
    cn2          -> decision_latency_ms cn2Label=decision_latency_ms
    msg          -> reason (human-readable reason from OPA)
    deviceCustomString1  = cs1/cs1Label pattern (handled above)

  Non-standard (no standard CEF key exists; use cs/cn slots):
    The mode (enforce|observe) and rule_id are included in the prefix
    (rule_id as the EventID field) and as extensions:
    flexString1  -> mode               flexString1Label=mode

  Traceability extensions (added for decision_id / hold / envelope / trace
  correlation; see TRACEABILITY note below):
    externalId   -> decision_id (standard CEF key for "the event ID as
                    reported by the source" -- an exact semantic match for
                    our per-decision primary key). Always present.
    envelopeHash -> envelope_hash (non-standard custom key; no cs/cn slot
                    left, so a self-describing key is used). Always present.
    holdId       -> hold_id (non-standard). Present only when a hold is
                    involved (hold creation, or the consumed hold on
                    resubmission).
    parentDecisionId -> parent_decision_id (non-standard). Present only on
                    a resolved resubmission.
    traceparent  -> traceparent (non-standard). Present only when the
                    envelope carried one; echoed verbatim, unescaped beyond
                    the standard CEF pipe/backslash/equals escaping.

  VERSION is read dynamically from app._version.CORE_VERSION.
  CEF_MAPPING_TABLE constant at the bottom of this module documents all fields
  so that docs/siem.md can be generated from it without re-reading source.

=============================================================================
TRACEABILITY (decision_id / hold_id / envelope_hash / parent_decision_id /
traceparent) — additive fields on the decision event
=============================================================================

  decision_id          uuid4 hex; the primary key of the /v1/decide transit
                        that produced this event.  Always present.
  envelope_hash         sha256 hex of the {action, axes, magnitude, target}
                        projection (same value as holds.canonical_hash() /
                        the hold record's envelope_hash).  Always present.
  hold_id               present only when a hold is involved: the hold this
                        decision just created (require_approval), or the
                        hold this decision just consumed (resubmission
                        allow).  Absent (key omitted) otherwise.
  parent_decision_id    present only on a resolved resubmission: the
                        decision_id of the original require_approval
                        decision that created the consumed hold.  Absent
                        otherwise.
  traceparent           opaque W3C trace-context string, echoed verbatim
                        from envelope.context.traceparent.  No OpenTelemetry
                        SDK, no spans -- pure passthrough.  Absent when the
                        envelope did not carry one.

  emit_decision() accepts all five as keyword-only arguments defaulting to
  "" -- additive, non-breaking for any existing call site.

=============================================================================
EVENTS
=============================================================================

  1. decision     — emitted AFTER every /v1/decide response, just before
                    returning to the caller.  Fields: see DECISION_EVENT_FIELDS.
  2. lifecycle    — emitted on engine start and stop.
  3. kill_switch  — TODO Phase 1: emit_kill_switch() is fully designed and
                    wired here. The kill-switch enforcement module (Phase 1)
                    MUST call emit_kill_switch(action, reason) to fire it.
                    Shape: see KILL_SWITCH_EVENT_FIELDS.

=============================================================================
SEVERITY MAP (RFC 5424)
=============================================================================

  allow            -> 6  (informational)
  require_approval -> 4  (warning)
  deny             -> 3  (error)
  lifecycle        -> 5  (notice)
  kill_switch      -> 2  (critical) — a kill-switch flip is a critical event;
                          it overrides all normal traffic and must page on-call.

=============================================================================
DROPPED EVENTS COUNTER
=============================================================================

  Module-level integer `dropped_events`. Incremented (thread-safely) each time
  queue.put_nowait() raises queue.Full. Readable via get_dropped_count().
  Tests can assert on it; the server can log it on shutdown.

=============================================================================
TESTABILITY DESIGN
=============================================================================

  - The SyslogEmitter address is injectable (constructor arg overrides env).
  - flush(timeout_s) drains the queue synchronously — for use in tests only.
  - format_decision_json() and format_decision_cef() are module-level callables
    that accept a plain dict and return a string. Tests can call them directly
    without a socket.
  - The _connect/_send methods are separated so tests can subclass or monkey-
    patch the transport.
"""

from __future__ import annotations

import datetime
import json
import os
import queue
import socket
import ssl
import sys
import threading
import time
from typing import Any

# ---------------------------------------------------------------------------
# Version (read dynamically; avoid circular imports)
# ---------------------------------------------------------------------------

def _core_version() -> str:
    """Read the core version string without importing the full app package."""
    try:
        from app._version import CORE_VERSION  # type: ignore[import]
        return CORE_VERSION
    except Exception:
        pass
    # Fallback: read from CHANGELOG first line that matches [x.y.z]
    return "0.1"


# ---------------------------------------------------------------------------
# RFC 5424 facility names -> integer codes
# ---------------------------------------------------------------------------

_FACILITY_CODES: dict[str, int] = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

# RFC 5424 severity -> integer code
_SEVERITY: dict[str, int] = {
    "allow":            6,   # informational
    "require_approval": 4,   # warning
    "deny":             3,   # error
    "lifecycle":        5,   # notice
    "kill_switch":      2,   # critical
}


def _pri(facility_code: int, severity_code: int) -> int:
    return facility_code * 8 + severity_code


# ---------------------------------------------------------------------------
# RFC 3339 timestamp (UTC, second precision — no clock in decision path,
# this is called AFTER the decision is already computed)
# ---------------------------------------------------------------------------

def _rfc3339_now() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms_now() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# DECISION_EVENT_FIELDS — canonical field list for documentation
# ---------------------------------------------------------------------------

DECISION_EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("ts",                   "RFC3339 UTC timestamp of the decision"),
    ("event",                "always 'decision'"),
    ("verdict",              "allow | deny | require_approval"),
    ("rule_id",              "fired OPA rule identifier"),
    ("verb",                 "action verb (read, delete, execute …)"),
    ("ability",              "fully-qualified ability name (namespace/verb)"),
    ("axes.reversibility",   "reversibility axis value"),
    ("axes.blast_radius",    "blast_radius axis value"),
    ("axes.externality",     "externality axis value"),
    ("magnitude_count",      "magnitude.count integer from the envelope"),
    ("session_id",           "agent session identifier"),
    ("agent_id",             "agent identifier"),
    ("on_behalf_of",         "user the agent acts on behalf of"),
    ("environment",          "target environment (production, staging …)"),
    ("mode",                 "enforcement mode: enforce | observe"),
    ("decision_latency_ms",  "wall-clock ms between start and end of decide.process()"),
    ("reeflex_version",      "reeflex-core engine version string"),
)


# ---------------------------------------------------------------------------
# KILL_SWITCH_EVENT_FIELDS — shape for the kill-switch event
# ---------------------------------------------------------------------------
# TODO Phase 1: the kill-switch enforcement module MUST call emit_kill_switch()
#   below.  This constant documents the event shape so docs/siem.md can be
#   generated independently.

KILL_SWITCH_EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("ts",             "RFC3339 UTC timestamp of the kill-switch flip"),
    ("event",          "always 'kill_switch'"),
    ("action",         "flipped | cleared | queried"),
    ("reason",         "human-readable reason for the flip"),
    ("reeflex_version","reeflex-core engine version string"),
)


# ---------------------------------------------------------------------------
# CEF mapping table — lifted verbatim into docs/siem.md by the docs agent
# ---------------------------------------------------------------------------

CEF_MAPPING_TABLE: tuple[tuple[str, str, str], ...] = (
    # (CEF key,      CEF label/note,       reeflex field)
    ("rt",           "timestamp ms",       "epoch_ms of the decision"),
    ("act",          "action verb",        "verb"),
    ("suser",        "subject user",       "on_behalf_of"),
    ("cs1",          "session_id",         "session_id"),
    ("cs1Label",     "label for cs1",      "literal 'session_id'"),
    ("cs2",          "agent_id",           "agent_id"),
    ("cs2Label",     "label for cs2",      "literal 'agent_id'"),
    ("cs3",          "reversibility",      "axes.reversibility"),
    ("cs3Label",     "label for cs3",      "literal 'reversibility'"),
    ("cs4",          "blast_radius",       "axes.blast_radius"),
    ("cs4Label",     "label for cs4",      "literal 'blast_radius'"),
    ("cs5",          "externality",        "axes.externality"),
    ("cs5Label",     "label for cs5",      "literal 'externality'"),
    ("cs6",          "environment",        "target environment"),
    ("cs6Label",     "label for cs6",      "literal 'environment'"),
    ("cn1",          "magnitude_count",    "magnitude.count integer"),
    ("cn1Label",     "label for cn1",      "literal 'magnitude_count'"),
    ("cn2",          "decision_latency_ms","decision latency in ms"),
    ("cn2Label",     "label for cn2",      "literal 'decision_latency_ms'"),
    ("msg",          "reason",             "human-readable reason from OPA"),
    ("flexString1",  "mode",               "enforce | observe"),
    ("flexString1Label","label",           "literal 'mode'"),
    ("externalId",   "decision_id",        "uuid4 hex primary key of this /v1/decide transit"),
    ("envelopeHash", "envelope_hash",      "sha256 hex of the {action,axes,magnitude,target} projection"),
    ("holdId",       "hold_id",            "present only when a hold is involved (created or consumed)"),
    ("parentDecisionId", "parent_decision_id", "present only on a resolved resubmission"),
    ("traceparent",  "traceparent",        "opaque W3C trace-context string, echoed verbatim; present only if the envelope carried one"),
)


# ---------------------------------------------------------------------------
# Dropped-events counter (module-level, thread-safe via GIL + atomic incr)
# ---------------------------------------------------------------------------

dropped_events: int = 0
_dropped_lock = threading.Lock()


def get_dropped_count() -> int:
    """Return the number of telemetry messages dropped due to queue overflow."""
    return dropped_events


def _increment_dropped() -> None:
    global dropped_events
    with _dropped_lock:
        dropped_events += 1


# ---------------------------------------------------------------------------
# Format helpers — callable in isolation (no socket required)
# ---------------------------------------------------------------------------

def format_decision_json(event: dict[str, Any]) -> str:
    """
    Format a decision event dict as a single-line JSON string.

    Callable without a live socket — suitable for golden-sample tests.
    """
    return json.dumps(event, separators=(",", ":"), default=str)


def _cef_escape(value: str) -> str:
    """Escape special characters per CEF spec (backslash, pipe, equals)."""
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    value = value.replace("=", "\\=")
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    return value


def format_decision_cef(event: dict[str, Any], version: str = "") -> str:
    """
    Format a decision event dict as a CEF:0 string.

    Callable without a live socket — suitable for golden-sample tests.

    CEF:0|Reeflex|reeflex-core|<version>|<rule_id>|<verdict>|<severity>|<ext>
    """
    if not version:
        version = _core_version()

    verdict = str(event.get("verdict", ""))
    rule_id = str(event.get("rule_id", ""))
    severity_code = _SEVERITY.get(verdict, 5)

    # CEF header fields (pipe-delimited, special chars escaped)
    vendor  = "Reeflex"
    product = "reeflex-core"
    dev_ver = _cef_escape(version)
    event_id = _cef_escape(rule_id)
    event_name = _cef_escape(verdict)
    severity_str = str(severity_code)

    # Extensions (key=value pairs, space-separated)
    axes = event.get("axes", {})
    epoch_ms = event.get("epoch_ms", _epoch_ms_now())
    ext_pairs: list[str] = [
        f"rt={epoch_ms}",
        f"act={_cef_escape(str(event.get('verb', '')))}",
        f"suser={_cef_escape(str(event.get('on_behalf_of', '')))}",
        f"cs1={_cef_escape(str(event.get('session_id', '')))}",
        "cs1Label=session_id",
        f"cs2={_cef_escape(str(event.get('agent_id', '')))}",
        "cs2Label=agent_id",
        f"cs3={_cef_escape(str(axes.get('reversibility', '')))}",
        "cs3Label=reversibility",
        f"cs4={_cef_escape(str(axes.get('blast_radius', '')))}",
        "cs4Label=blast_radius",
        f"cs5={_cef_escape(str(axes.get('externality', '')))}",
        "cs5Label=externality",
        f"cs6={_cef_escape(str(event.get('environment', '')))}",
        "cs6Label=environment",
        f"cn1={int(event.get('magnitude_count', 1))}",
        "cn1Label=magnitude_count",
        f"cn2={int(event.get('decision_latency_ms', 0))}",
        "cn2Label=decision_latency_ms",
        f"msg={_cef_escape(str(event.get('reason', '')))}",
        f"flexString1={_cef_escape(str(event.get('mode', 'enforce')))}",
        "flexString1Label=mode",
    ]

    # Traceability extensions (additive). decision_id / envelope_hash are
    # always present on a real decision event; hold_id / parent_decision_id /
    # traceparent are conditional -- only emitted when the underlying value
    # is non-empty, to avoid noise on every allow/deny line.
    decision_id = event.get("decision_id", "")
    if decision_id:
        ext_pairs.append(f"externalId={_cef_escape(str(decision_id))}")
    envelope_hash = event.get("envelope_hash", "")
    if envelope_hash:
        ext_pairs.append(f"envelopeHash={_cef_escape(str(envelope_hash))}")
    hold_id = event.get("hold_id", "")
    if hold_id:
        ext_pairs.append(f"holdId={_cef_escape(str(hold_id))}")
    parent_decision_id = event.get("parent_decision_id", "")
    if parent_decision_id:
        ext_pairs.append(f"parentDecisionId={_cef_escape(str(parent_decision_id))}")
    traceparent = event.get("traceparent", "")
    if traceparent:
        ext_pairs.append(f"traceparent={_cef_escape(str(traceparent))}")

    extensions = " ".join(ext_pairs)

    return (
        f"CEF:0|{vendor}|{product}|{dev_ver}|{event_id}|{event_name}"
        f"|{severity_str}|{extensions}"
    )


# ---------------------------------------------------------------------------
# RFC 5424 syslog message builder
# ---------------------------------------------------------------------------

def _build_syslog_msg(
    pri: int,
    msgid: str,
    hostname: str,
    procid: str,
    msg_body: str,
) -> str:
    """
    Assemble a RFC 5424 syslog message.

    Format: <PRI>1 TIMESTAMP HOSTNAME APPNAME PROCID MSGID STRUCTURED-DATA MSG

    STRUCTURED-DATA is "-" (nil) — structured data lives in MSG for json format;
    CEF format embeds everything in the CEF string.
    """
    ts = _rfc3339_now()
    # RFC 5424: nil values use "-"
    return (
        f"<{pri}>1 {ts} {hostname} reeflex {procid} {msgid} - {msg_body}"
    )


# ---------------------------------------------------------------------------
# SyslogEmitter
# ---------------------------------------------------------------------------

class SyslogEmitter:
    """
    Fire-and-forget syslog emitter for reeflex-core.

    THE INVARIANT: emit() is non-blocking. A failed put_nowait increments
    the module-level `dropped_events` counter and returns immediately.
    The background worker thread does all I/O. Socket errors are swallowed
    (logged to stderr at most once per error burst) and NEVER propagate to
    the caller.

    Usage:
        emitter = SyslogEmitter()   # reads config from env
        emitter.start()             # spawns daemon thread (no-op if disabled)
        emitter.emit_decision(...)  # non-blocking
        emitter.emit_lifecycle("start")
        emitter.stop()              # signal worker to drain and exit
    """

    # Maximum messages buffered before drop-on-overflow
    _QUEUE_MAXSIZE: int = 1000

    def __init__(
        self,
        *,
        address: str | None = None,        # injectable (overrides env)
        enabled: bool | None = None,       # injectable (overrides env)
        protocol: str | None = None,       # injectable (overrides env)
        fmt: str | None = None,            # injectable (overrides env)
        facility: str | None = None,       # injectable (overrides env)
        tls_verify: bool | None = None,    # injectable (overrides env)
    ) -> None:
        # Read config from env; injectable args override for testability
        self._enabled: bool = _parse_bool(
            enabled if enabled is not None
            else os.environ.get("REEFLEX_SYSLOG_ENABLED", "false")
        )

        raw_address = (
            address
            if address is not None
            else os.environ.get("REEFLEX_SYSLOG_ADDRESS", "")
        )
        self._host: str = ""
        self._port: int = 514
        self._address_valid: bool = False
        if raw_address:
            parsed = _parse_address(raw_address)
            if parsed:
                self._host, self._port = parsed
                self._address_valid = True

        self._protocol: str = (
            (protocol or os.environ.get("REEFLEX_SYSLOG_PROTOCOL", "udp")).lower()
        )
        self._format: str = (
            (fmt or os.environ.get("REEFLEX_SYSLOG_FORMAT", "json")).lower()
        )

        facility_name = (
            facility or os.environ.get("REEFLEX_SYSLOG_FACILITY", "local0")
        ).lower()
        self._facility_code: int = _FACILITY_CODES.get(facility_name, 16)  # default local0

        tls_verify_env = os.environ.get("REEFLEX_SYSLOG_TLS_VERIFY", "true")
        self._tls_verify: bool = (
            tls_verify if tls_verify is not None
            else _parse_bool(tls_verify_env)
        )

        self._hostname: str = _safe_hostname()
        self._procid: str = str(os.getpid())
        self._version: str = _core_version()

        self._queue: queue.Queue[str | None] = queue.Queue(maxsize=self._QUEUE_MAXSIZE)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sock: socket.socket | ssl.SSLSocket | None = None
        self._sock_lock = threading.Lock()

        # Warn once if enabled but no valid address
        if self._enabled and not self._address_valid:
            print(
                "[reeflex-core] WARN: REEFLEX_SYSLOG_ENABLED=true but "
                "REEFLEX_SYSLOG_ADDRESS is unset or invalid — "
                "telemetry emitter is a no-op.",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Spawn the background worker daemon thread.

        No-op if disabled or address is invalid.
        Must be called once at application startup (FastAPI lifespan / server start).
        """
        if not self._enabled or not self._address_valid:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="reeflex-syslog-worker",
            daemon=True,   # daemon=True: does not prevent interpreter shutdown
        )
        self._thread.start()

    def stop(self, timeout_s: float = 2.0) -> None:
        """
        Signal the worker to finish the current queue and exit.

        Puts a sentinel None onto the queue; the worker drains pending messages
        then exits.  Blocks until the thread joins or timeout_s elapses.
        """
        if not self._enabled or self._thread is None:
            return
        try:
            self._queue.put_nowait(None)  # sentinel
        except queue.Full:
            pass
        self._thread.join(timeout=timeout_s)
        self._close_socket()

    def flush(self, timeout_s: float = 5.0) -> None:
        """
        Synchronously drain the queue — FOR TESTS ONLY.

        Blocks until the queue is empty or timeout_s elapses. Does not stop
        the worker thread. Not suitable for production use.
        """
        if not self._enabled or not self._address_valid:
            return
        deadline = time.monotonic() + timeout_s
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)

    # ------------------------------------------------------------------
    # Public emit methods (all non-blocking per THE INVARIANT)
    # ------------------------------------------------------------------

    def emit_decision(
        self,
        *,
        verdict: str,
        rule_id: str,
        verb: str,
        ability: str,
        axes: dict[str, str],
        magnitude_count: int,
        session_id: str,
        agent_id: str,
        on_behalf_of: str,
        environment: str,
        mode: str = "enforce",
        decision_latency_ms: int = 0,
        reason: str = "",
        namespace: str = "",
        src_ip: str = "",
        target_ref: str = "",
        params: dict | None = None,
        decision_id: str = "",
        hold_id: str = "",
        envelope_hash: str = "",
        parent_decision_id: str = "",
        traceparent: str = "",
    ) -> None:
        """
        Emit one decision event.

        INVARIANT: non-blocking. Any failure (queue full, disabled) is silently
        swallowed — never raises into /v1/decide.

        Traceability fields (additive, keyword-only, default ""):
          decision_id, envelope_hash   always populated by the decision path;
                                       always included in the event dict.
          hold_id, parent_decision_id  conditional -- included only when
                                       non-empty (a hold is involved / a
                                       resubmission resolved its parent).
          traceparent                  conditional -- included only when the
                                       envelope carried one.
        """
        # Guard: if disabled, this is a one-line check, zero overhead
        if not self._enabled or not self._address_valid:
            return

        ts = _rfc3339_now()
        epoch_ms = _epoch_ms_now()
        severity_code = _SEVERITY.get(verdict, 5)
        pri = _pri(self._facility_code, severity_code)

        event: dict[str, Any] = {
            "ts": ts,
            "event": "decision",
            "verdict": verdict,
            "rule_id": rule_id,
            "verb": verb,
            "ability": ability,
            "axes": {
                "reversibility": axes.get("reversibility", ""),
                "blast_radius": axes.get("blast_radius", ""),
                "externality": axes.get("externality", ""),
            },
            "magnitude_count": magnitude_count,
            "session_id": session_id,
            "agent_id": agent_id,
            "on_behalf_of": on_behalf_of,
            "environment": environment,
            "mode": mode,
            "decision_latency_ms": decision_latency_ms,
            "reason": reason,
            "namespace": namespace,
            "srcip": src_ip,
            "target_ref": target_ref,
            "params": params or {},
            "reeflex_version": self._version,
            "epoch_ms": epoch_ms,
            "decision_id": decision_id,
            "envelope_hash": envelope_hash,
        }
        if hold_id:
            event["hold_id"] = hold_id
        if parent_decision_id:
            event["parent_decision_id"] = parent_decision_id
        if traceparent:
            event["traceparent"] = traceparent

        if self._format == "cef":
            msg_body = format_decision_cef(event, version=self._version)
        else:
            msg_body = format_decision_json(event)

        syslog_msg = _build_syslog_msg(
            pri=pri,
            msgid="decision",
            hostname=self._hostname,
            procid=self._procid,
            msg_body=msg_body,
        )
        self._enqueue(syslog_msg)

    def emit_lifecycle(self, phase: str) -> None:
        """
        Emit an engine lifecycle event.

        phase: "start" | "stop"
        Severity: notice (5).
        """
        if not self._enabled or not self._address_valid:
            return

        severity_code = _SEVERITY["lifecycle"]
        pri = _pri(self._facility_code, severity_code)
        ts = _rfc3339_now()

        event: dict[str, Any] = {
            "ts": ts,
            "event": "lifecycle",
            "phase": phase,
            "reeflex_version": self._version,
        }

        if self._format == "cef":
            # CEF for lifecycle: minimal header, no decision-specific extensions
            dev_ver = _cef_escape(self._version)
            msg_body = (
                f"CEF:0|Reeflex|reeflex-core|{dev_ver}|lifecycle|{phase}"
                f"|{severity_code}|rt={_epoch_ms_now()} msg={_cef_escape(phase)}"
            )
        else:
            msg_body = format_decision_json(event)

        syslog_msg = _build_syslog_msg(
            pri=pri,
            msgid="lifecycle",
            hostname=self._hostname,
            procid=self._procid,
            msg_body=msg_body,
        )
        self._enqueue(syslog_msg)

    def emit_kill_switch(self, action: str, reason: str) -> None:
        """
        Emit a kill-switch flip event.

        action: "flipped" | "cleared" | "queried"
        reason: human-readable explanation of the flip.
        Severity: critical (2) — a kill-switch flip is a critical event.

        TODO Phase 1: the kill-switch enforcement module MUST call this method
        when the kill switch is activated or deactivated. The event shape is
        defined in KILL_SWITCH_EVENT_FIELDS above. This method is fully
        implemented and ready to call; Phase 1 only needs to add the call site.
        """
        if not self._enabled or not self._address_valid:
            return

        severity_code = _SEVERITY["kill_switch"]
        pri = _pri(self._facility_code, severity_code)
        ts = _rfc3339_now()

        event: dict[str, Any] = {
            "ts": ts,
            "event": "kill_switch",
            "action": action,
            "reason": reason,
            "reeflex_version": self._version,
        }

        if self._format == "cef":
            dev_ver = _cef_escape(self._version)
            msg_body = (
                f"CEF:0|Reeflex|reeflex-core|{dev_ver}|kill_switch|{action}"
                f"|{severity_code}|rt={_epoch_ms_now()}"
                f" msg={_cef_escape(reason)}"
            )
        else:
            msg_body = format_decision_json(event)

        syslog_msg = _build_syslog_msg(
            pri=pri,
            msgid="kill_switch",
            hostname=self._hostname,
            procid=self._procid,
            msg_body=msg_body,
        )
        self._enqueue(syslog_msg)

    # ------------------------------------------------------------------
    # Internal: non-blocking enqueue (THE INVARIANT enforcement point)
    # ------------------------------------------------------------------

    def _enqueue(self, syslog_msg: str) -> None:
        """
        INVARIANT ENFORCEMENT: non-blocking put.

        If the queue is full, increment dropped_events and return immediately.
        This method MUST NEVER raise; it is called from the decision path.
        """
        try:
            self._queue.put_nowait(syslog_msg)
        except queue.Full:
            _increment_dropped()
            # No stderr log here — a full queue under high load would flood stderr.
            # The dropped_events counter is the observable signal.

    # ------------------------------------------------------------------
    # Background worker thread
    # ------------------------------------------------------------------

    def _worker(self) -> None:
        """
        Background daemon thread: dequeue messages and send via socket.

        Runs until it receives the sentinel (None) or the process exits.
        All socket errors are caught and logged (at most once per burst);
        they NEVER propagate out of this thread.
        """
        _last_error_msg: str = ""

        while True:
            try:
                msg = self._queue.get(block=True, timeout=1.0)
            except queue.Empty:
                continue

            # Sentinel: drain remaining then exit
            if msg is None:
                # Drain any remaining messages (best-effort)
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                        if remaining is None:
                            break
                        self._send(remaining, last_error_ref=[_last_error_msg])
                    except queue.Empty:
                        break
                break

            _last_error_ref: list[str] = [_last_error_msg]
            self._send(msg, last_error_ref=_last_error_ref)
            _last_error_msg = _last_error_ref[0]

    def _send(self, msg: str, last_error_ref: list[str]) -> None:
        """
        Send one syslog message via the configured transport.

        Swallows all exceptions — they are logged to stderr (deduplicated).
        last_error_ref is a mutable 1-element list used to deduplicate error logs.
        """
        encoded = msg.encode("utf-8", errors="replace")
        try:
            if self._protocol == "udp":
                self._send_udp(encoded)
            else:
                # TCP and TLS share the persistent-connection path
                self._send_tcp_or_tls(encoded)
            # Success: clear the last error so the next real error is logged
            last_error_ref[0] = ""
        except Exception as exc:  # noqa: BLE001
            # INVARIANT: swallow all errors in the worker thread.
            err_str = f"{type(exc).__name__}: {exc}"
            if err_str != last_error_ref[0]:
                # Log once per unique error class to avoid log spam
                print(
                    f"[reeflex-core] WARN: syslog emit failed "
                    f"({self._protocol} {self._host}:{self._port}): {err_str}",
                    file=sys.stderr,
                )
                last_error_ref[0] = err_str
            # Close the socket so the next attempt reconnects
            self._close_socket()

    # ------------------------------------------------------------------
    # Transport implementations
    # ------------------------------------------------------------------

    def _send_udp(self, encoded: bytes) -> None:
        """Send one datagram. Creates a new socket per message (stateless)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(encoded, (self._host, self._port))

    def _send_tcp_or_tls(self, encoded: bytes) -> None:
        """
        Send via persistent TCP or TLS connection.

        RFC 6587 octet-counted framing: "<length> <syslog-msg>\n"
        Reconnects automatically if the socket is closed or broken.
        """
        frame = f"{len(encoded)} ".encode("ascii") + encoded + b"\n"
        with self._sock_lock:
            if self._sock is None:
                self._sock = self._connect()
            try:
                self._sock.sendall(frame)
            except OSError:
                # Socket broken; close it so next call reconnects
                self._close_socket_unsafe()
                self._sock = self._connect()
                self._sock.sendall(frame)

    def _connect(self) -> socket.socket | ssl.SSLSocket:
        """
        Open a new TCP or TLS connection.

        Raises OSError / ssl.SSLError on failure — the worker catches this.
        """
        raw = socket.create_connection((self._host, self._port), timeout=5.0)
        raw.settimeout(5.0)
        _enable_keepalive(raw)
        if self._protocol == "tls":
            if self._tls_verify:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(raw, server_hostname=self._host)
        return raw

    def _close_socket(self) -> None:
        """Close the persistent socket (thread-safe)."""
        with self._sock_lock:
            self._close_socket_unsafe()

    def _close_socket_unsafe(self) -> None:
        """Close without acquiring the lock — caller must hold _sock_lock."""
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:  # noqa: BLE001
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _parse_address(raw: str) -> tuple[str, int] | None:
    """
    Parse "host:port" into (host, int(port)).

    Returns None if the format is invalid (never raises).
    """
    raw = raw.strip()
    if not raw:
        return None
    # Handle IPv6 bracketed addresses like [::1]:514
    if raw.startswith("["):
        bracket_end = raw.find("]")
        if bracket_end == -1:
            return None
        host = raw[1:bracket_end]
        rest = raw[bracket_end + 1:]
        if not rest.startswith(":"):
            return None
        try:
            port = int(rest[1:])
        except ValueError:
            return None
        return host, port
    # host:port or host (no port)
    if ":" in raw:
        parts = raw.rsplit(":", 1)
        try:
            port = int(parts[1])
        except ValueError:
            return None
        return parts[0], port
    # No port specified — cannot default safely; require explicit port
    return None


def _safe_hostname() -> str:
    """Return the machine hostname without raising."""
    try:
        return socket.gethostname() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _enable_keepalive(sock: socket.socket) -> None:
    """
    Enable TCP keepalive on a freshly connected socket.

    WHY: the syslog stream is low-volume and long-idle. If the collector (e.g.
    wazuh-remoted) restarts while our connection is idle, the peer goes away but
    a subsequent sendall() can SUCCEED — the bytes are buffered locally and only
    a delayed RST later surfaces the break. That is a half-open connection: the
    message is silently lost and the reconnect path in _send_tcp_or_tls never
    fires. Keepalive makes the OS actively probe the idle peer, so a dead
    connection raises on the next send and triggers the reconnect+retry.

    Best-effort and platform-guarded: SO_KEEPALIVE is portable; the interval
    knobs are Linux-specific (TCP_KEEP*) and skipped where absent. Never raises —
    a socket without keepalive still works, just detects drops more slowly.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    # Fast detection tuned for an idle, low-volume stream: start probing after
    # 15s idle, probe every 5s, drop after 3 failed probes (~30s to detect).
    for opt_name, value in (("TCP_KEEPIDLE", 15), ("TCP_KEEPINTVL", 5), ("TCP_KEEPCNT", 3)):
        opt = getattr(socket, opt_name, None)
        if opt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, value)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Module-level singleton (created at import; started at server lifecycle)
# ---------------------------------------------------------------------------

# THE INVARIANT: this singleton is the single emitter for the process.
# When REEFLEX_SYSLOG_ENABLED is false (the default), this object's emit
# methods are one-line no-ops. No thread is spawned, no socket is opened.
_emitter: SyslogEmitter = SyslogEmitter()


def get_emitter() -> SyslogEmitter:
    """Return the process-wide SyslogEmitter singleton."""
    return _emitter


def reset_emitter(**kwargs: Any) -> SyslogEmitter:
    """
    Replace the module-level singleton — FOR TESTS ONLY.

    Stops the current emitter's worker thread before replacing it.
    """
    global _emitter
    _emitter.stop(timeout_s=1.0)
    _emitter = SyslogEmitter(**kwargs)
    return _emitter
