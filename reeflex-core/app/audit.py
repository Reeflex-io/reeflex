"""
audit.py — Append-only JSONL audit log for reeflex-core decisions.

Each call to POST /v1/decide appends one record to the audit log.
Records are immutable once written: we append, never update or delete.

Log path: env REEFLEX_AUDIT_LOG (default: <repo>/reeflex-core/audit/decisions.jsonl).

Three record shapes share this SAME append-only stream (one ordered, tamper-
evident log; same lock, same fsync, same read-back-after-write discipline):

  1. DECISION records (record(), no "event" key on the historical shape —
     see below) — one per /v1/decide transit.
  2. HOLD_RESOLUTION events (record_hold_resolution(), "event": "hold_resolution")
     — one per hold state resolution (approved / rejected / expired). This is
     the AI Act Art.14 human-oversight evidence trail: it captures WHO decided
     and WHEN, keyed to the decision_id of the transit the resolution enabled
     (see record_hold_resolution() docstring for exact emission points).
  3. LEDGER_EPOCH events (record_ledger_epoch(), "event": "ledger_epoch") —
     one per process boot, saying what cumulative session state this core
     restored and whether it can remember at all (RFX-197).

WHY (3) IS ON THIS STREAM AND NOT ONLY IN A LOG LINE (RFX-197).  The decision
records above carry `cumulative_injected`, which is the counter R5's budgets
are enforced against.  Before RFX-197 that counter lived in a process-local
dict, so a restart silently reset it — and the reset was invisible HERE, on the
one stream an auditor actually reads.  Two consecutive rows for one session,
eleven seconds apart, both asserting `window_seconds: 3600`, carried
`count_by_verb.delete` 20 then 0: a monotonic counter moving backwards inside
its own declared window.  The contradiction was machine-detectable and nothing
detected it, because `grep -icE 'start|boot|restart|ledger|reset|epoch'` over
the whole file returned 0 — there was no event that could explain it.

So a counter that falls now has a named cause on the same append-only stream
that carries the contradiction: every boot writes one ledger_epoch event, and
every decision record carries the `ledger_epoch` it was decided under.  A
consumer diffing two rows of one session can distinguish "spend was forgotten
because this core restarted" (epoch changed, and an event says so) from "spend
was forgotten and nobody knows why" (epoch identical — a real defect).

The shapes are distinguished by the "event" key (absent/omitted on legacy
decision records for backward compatibility with existing consumers that
never looked for it; present and equal to "hold_resolution" / "ledger_epoch"
on the event shapes). A consumer that only understands decision records can
keep filtering on `"decision" in record` / ignoring unknown "event" values.

SKELETON SHORTCUTS (upgrade path documented):
  - Signing: TODO — sign each record with an ed25519 key (Vault-backed) so
    the audit trail is tamper-evident end to end (SPEC §2).
    Upgrade path: add `audit_signature` field = ed25519.sign(json_bytes, private_key).
  - Storage: JSONL file (append-only). TODO: replace with Postgres for the
    production signed audit trail; keep JSONL as a local dev / test fallback.
    Upgrade path: write to Postgres `audit_decisions` table with a UNIQUE
    constraint on (session_id, action_nonce) to prevent duplicate inserts.
  - Read-back proof: after each write we immediately re-read the last line to
    confirm the record landed (GET-after-POST equivalent for a file log).
    TODO: in the Postgres upgrade, run a SELECT by record_id after INSERT.
"""

from __future__ import annotations

import json
import os
import pathlib
import threading
import time

_lock = threading.Lock()


def _log_path() -> pathlib.Path:
    env_path = os.environ.get("REEFLEX_AUDIT_LOG", "")
    if env_path:
        return pathlib.Path(env_path)
    here = pathlib.Path(__file__).resolve()
    return here.parent.parent / "audit" / "decisions.jsonl"


def _append_and_readback(rec: dict, *, verify: dict) -> dict:
    """Append one JSONL line to the audit log and read the last line back.

    Shared by record() and record_hold_resolution() so both record shapes
    get the identical append-only + fsync + read-back-proof discipline on
    the SAME file/lock.

    `verify` is a small dict of {key: expected_value} checked against the
    read-back line; a mismatch raises OSError (tamper-evident / write-torn
    detection). Returns `rec` unchanged on success.
    """
    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(rec, separators=(",", ":")) + "\n"

    with _lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

        # Read-back proof: verify the last line matches what we wrote.
        with open(log_path, "rb") as fh:
            # Seek to end, walk back past final newline to find the last record
            fh.seek(0, 2)
            size = fh.tell()
            if size == 0:
                raise OSError("audit file empty immediately after write")
            # Walk backwards to find start of last line
            pos = size - 1
            while pos > 0:
                fh.seek(pos)
                ch = fh.read(1)
                if ch == b"\n" and pos < size - 1:
                    break
                pos -= 1
            fh.seek(max(pos, 0))
            last_line = fh.read().decode("utf-8").strip()

        written_rec = json.loads(last_line)
        for key, expected in verify.items():
            if written_rec.get(key) != expected:
                raise OSError(
                    f"audit read-back mismatch: wrote {rec!r}, read back {written_rec!r}"
                )

    return rec


def record(
    session_id: str,
    envelope: dict,
    cumulative: dict,
    decision_result: dict,
    *,
    decision_id: str = "",
    hold_id: str = "",
    expires_ts: str = "",
    envelope_hash: str = "",
    parent_decision_id: str = "",
    traceparent: str = "",
    ledger_epoch: str = "",
) -> dict:
    """
    Append one audit record and immediately read it back to prove it landed.

    Returns the record dict that was written.
    Raises OSError if the write or read-back fails (caller should treat as
    an internal error but NOT change the decision — audit failure != deny).

    Traceability fields (additive, keyword-only, all default ""):
      decision_id         primary key for this /v1/decide transit (uuid4 hex).
      envelope_hash        canonical_hash(envelope) — same key holds.py stores,
                            so audit / SIEM / hold records join on the exact
                            same value.
      hold_id               present when a hold is involved: on require_approval
                            hold-creation, on resubmission the consumed hold_id,
                            and on a hold-validation DENIAL that was decided
                            against a hold this store actually holds (e.g.
                            reeflex_hold_expired -- see decide.py's fail_resp
                            branch).  Omitted (key absent) when not applicable,
                            including when the claimed hold does not exist, so a
                            hold_id on an audit line always names a real hold.
      expires_ts            the hold's DEADLINE, present only on the
                            require_approval line that CREATED the hold (the
                            same value /v1/decide returns in its response).
                            Written here so a downstream consumer of this log --
                            the evidence connector's tail, a SIEM -- learns when
                            the hold times out WITHOUT having to guess it from a
                            locally-configured TTL that can drift from this
                            core's REEFLEX_HOLD_TTL_SECONDS.  A hold nobody
                            answers can then be shown as timed out by whoever
                            holds the human's inbox, instead of sitting pending
                            forever because only core knew the deadline.
                            Omitted (key absent) when no hold was created.
      parent_decision_id    present on a resubmission once resolved (adapter-
                            supplied or hold-fallback).  Omitted when not
                            applicable.
      traceparent           opaque W3C trace-context string, echoed verbatim
                            from envelope.context.traceparent.  Omitted when
                            the envelope did not carry one.

    Attest evidence fields (additive, v0.1.13):
      action.target_system  envelope.target.system (e.g. the backend/system
                            name an adapter is fronting — "wordpress-prod-db",
                            "s3-eu-west-1"). Sits alongside the pre-existing
                            action.environment key (itself sourced from
                            envelope.target.environment, not renamed/moved —
                            this is additive nesting under the same "action"
                            sub-object for consistency with that established,
                            if originally target-shaped, convention). Empty
                            string if envelope.target.system is absent — this
                            is non-load-bearing metadata, fail-open on absence
                            (consistent with every other `.get(..., "")` in
                            this record; it never affects the decision).
      agent_id               envelope.agent.id — one of the identities
                            principal.actor_identities() uses for the hold
                            actor==approver check (RFX-CORE-2 widened that
                            check to also cover agent.on_behalf_of and
                            agent.session_id, and to compare NORMALIZED
                            values, so it is no longer a single verbatim
                            field). Empty string if absent.

    Ledger continuity (additive, RFX-197):
      ledger_epoch          keyword-only, default "" (key omitted when empty).
                            The epoch_id of the ledger state that
                            `cumulative_injected` was computed against, stamped
                            for every decision record by decide._try_audit().
                            This is what makes a cumulative counter that FELL
                            inside its own declared window diagnosable rather
                            than merely visible: the same epoch_id on both rows
                            means the spend was lost with no explanation (a real
                            defect), a different epoch_id means this core
                            rebooted -- and the matching "ledger_epoch" event on
                            this same stream says what it restored, from where,
                            and whether it is durable at all.
    """
    rec: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": session_id,
        "agent_id": (envelope.get("agent") or {}).get("id", ""),
        "action": {
            "namespace": (envelope.get("action") or {}).get("namespace", ""),
            "verb": (envelope.get("action") or {}).get("verb", ""),
            "ability": (envelope.get("action") or {}).get("ability", ""),
            "environment": (envelope.get("target") or {}).get("environment", ""),
            "target_system": (envelope.get("target") or {}).get("system", ""),
        },
        "magnitude_count": int((envelope.get("magnitude") or {}).get("count", 1)),
        "cumulative_injected": cumulative,
        "decision": decision_result.get("decision", ""),
        "rule": decision_result.get("rule", ""),
        "reason": decision_result.get("reason", ""),
        "decision_id": decision_id,
        "envelope_hash": envelope_hash,
        # TODO: add audit_signature = ed25519.sign(record_bytes, vault_key)
    }
    if hold_id:
        rec["hold_id"] = hold_id
    if expires_ts:
        rec["expires_ts"] = expires_ts
    if parent_decision_id:
        rec["parent_decision_id"] = parent_decision_id
    if traceparent:
        rec["traceparent"] = traceparent
    # RFX-197: which ledger continuity boundary was `cumulative_injected`
    # computed under. Two rows of one session whose counter went DOWN are a
    # defect if this value is identical on both, and an explained restart if it
    # is not -- and the "ledger_epoch" event on this same stream says which.
    # Omitted (key absent) when unknown, matching every other additive field
    # above, so a consumer that never looked for it is unaffected.
    if ledger_epoch:
        rec["ledger_epoch"] = ledger_epoch

    return _append_and_readback(
        rec,
        verify={
            "session_id": rec["session_id"],
            "decision": rec["decision"],
            "rule": rec["rule"],
            "decision_id": rec["decision_id"],
        },
    )


def record_hold_resolution(
    hold_id: str,
    resolution: str,
    decided_by: str,
    *,
    decision_id: str = "",
    resolved_ts: str = "",
    observed_ts: str = "",
    verified: bool = False,
    principal_source: str = "asserted",
) -> dict:
    """
    Append ONE hold_resolution audit event to the SAME append-only JSONL
    stream as decision records (same file, same lock, same fsync + read-back
    discipline) — one ordered, tamper-evident stream a connector/SIEM can
    consume without joining two logs.

    This is the AI Act Art.14 human-oversight evidence trail: it is the
    record that a hold (a require_approval verdict put on hold) was
    RESOLVED, by whom, and — for the "approved" case — which decision that
    resolution went on to allow.

    Parameters
    ----------
    hold_id      the hold this event resolves.
    resolution   "approved" | "rejected" | "expired".
    decided_by   the principal who decided, "{type}:{id}" (e.g. "human:leo"),
                 matching holds.py's `decided_by` format. For "expired" there
                 is no deciding principal (a timeout, not a decision by any
                 actor) — callers pass a documented best-effort sentinel
                 (see holds.py._append_expired_event()).
    decision_id  keyword-only, default "". Always "" for v0.1.13: all three
                 resolutions are emitted at the DECISION moment (approve/reject
                 in holds.resolve_hold(), expiry in _append_expired_event()),
                 before any /v1/decide transit exists. For "approved", the
                 eventual resubmission's decision record carries this hold_id,
                 so the executed action correlates back to the approval without
                 a decision_id on this event. (The field is kept in the shape
                 for forward-compat / a future emission that has a transit.)
    resolved_ts  keyword-only, default "" (falls back to "now" if empty).
                 ISO8601 UTC — the timestamp of the ACTUAL resolution
                 (holds.py's `decided_ts` for approve/reject; for "expired",
                 the hold's own `expires_ts` — the DEADLINE, i.e. the moment
                 the action actually timed out, NOT the moment core happened
                 to notice. Expiry is lazy: on a stock deployment nothing may
                 read a pending hold for weeks, and stamping this field with
                 the detection time made the append-only Art.14 stream claim
                 actions timed out a month after their real deadline. An
                 append-only evidence stream that records the wrong time is
                 worse than one that records nothing.)
    observed_ts  keyword-only, default "" (key omitted when empty). ISO8601
                 UTC — when core DETECTED the resolution, written only when it
                 differs from `resolved_ts`, i.e. only for a lazily-detected
                 expiry. Both facts are kept, neither is invented: the
                 auditor sees when the action timed out AND how long it took
                 anyone to look. Hiding the detection lag would be its own
                 dishonesty; recording it as the timeout was the defect.

    Discriminator field: "event": "hold_resolution" lets a connector/SIEM
    distinguish this from a decision record (decision records have no
    "event" key — see the module docstring) — additive and non-breaking for
    any existing decision-record consumer, which never looked at "event".

    Returns the record dict that was written. Raises OSError on write/
    read-back failure (same fail-mode as record(): audit failure is reported
    to the caller but must NOT be turned into a decision-path failure by a
    caller that is not itself on the decision path — see call sites).
    """
    rec: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "hold_resolution",
        "hold_id": hold_id,
        "resolution": resolution,
        "decided_by": decided_by,
        # RFX-CORE-2: is `decided_by` VERIFIED, or only what the caller claimed?
        # This stream is what an Art.14 human-oversight report is built from, so
        # an unverified approver must be visible HERE -- otherwise a report has
        # no way to tell a real human decision from a fabricated one, which is
        # exactly the defect RFX-74 saw from the reporting side. Additive:
        # existing consumers that ignore these keys are unaffected.
        "decided_by_verified": bool(verified),
        "principal_source": principal_source,
        "decision_id": decision_id,
        "resolved_ts": resolved_ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if observed_ts and observed_ts != rec["resolved_ts"]:
        rec["observed_ts"] = observed_ts

    return _append_and_readback(
        rec,
        verify={
            "event": rec["event"],
            "hold_id": rec["hold_id"],
            "resolution": rec["resolution"],
        },
    )


def record_ledger_epoch(epoch: dict) -> dict:
    """Append one "ledger_epoch" event: what cumulative state this boot restored.

    RFX-197.  Called once per process, from ledger._mint_epoch(), the first
    time the session ledger is folded.  The point is not the log line — it is
    that the ONE stream carrying `cumulative_injected` also carries the only
    event that can legitimately explain a cumulative counter which fell inside
    its own declared window.

    Fields (all sourced from ledger.ledger_epoch(), none caller-supplied):
      epoch_id           uuid4 hex naming this continuity boundary.  Every
                         decision record carries the epoch_id it was decided
                         under, so a consumer can join a counter reset to the
                         boot that caused it.
      durable            False means REEFLEX_LEDGER_PERSIST is explicitly off,
                         i.e. this core is back to the RFX-197 behaviour: every
                         session budget resets on restart and is shared with no
                         other replica.  An operator who turned persistence off
                         has said so in the evidence, which is the difference
                         between a documented choice and a silent regression.
      path               the ledger file this core reads and writes.  Two
                         replicas showing the SAME path share one budget; two
                         showing different paths (or different volumes behind
                         the same path) do not — the residual this fix cannot
                         close, made visible instead of assumed.
      window_seconds     the rolling window the restored spend is counted over.
      restored_sessions  how many sessions had live spend at boot.
      restored_entries   how many entries were folded.  0 with durable=true on
                         a core that has served traffic before is itself a
                         finding: the volume is not the one it was writing to.
      scan_truncated     True if the bounded boot scan hit its byte cap while
                         still inside the window, so the restored spend may
                         UNDER-count.  Visible rather than silent.

    Raises OSError on write/read-back failure, exactly like record() and
    record_hold_resolution().  The caller (ledger._mint_epoch) treats that as
    best-effort: a missing marker must not stop the engine deciding, and it
    already prints to stderr.  This is the same asymmetry the module documents
    — audit is evidence, the ledger itself is enforcement.
    """
    rec: dict = {
        "ts": epoch.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "ledger_epoch",
        "epoch_id": epoch.get("epoch_id", ""),
        "durable": bool(epoch.get("durable")),
        "path": epoch.get("path", ""),
        "window_seconds": int(epoch.get("window_seconds") or 0),
        "restored_sessions": int(epoch.get("restored_sessions") or 0),
        "restored_entries": int(epoch.get("restored_entries") or 0),
        "scan_truncated": bool(epoch.get("scan_truncated")),
    }

    return _append_and_readback(
        rec,
        verify={
            "event": rec["event"],
            "epoch_id": rec["epoch_id"],
        },
    )
