"""
audit.py — Append-only JSONL audit log for reeflex-core decisions.

Each call to POST /v1/decide appends one record to the audit log.
Records are immutable once written: we append, never update or delete.

Log path: env REEFLEX_AUDIT_LOG (default: <repo>/reeflex-core/audit/decisions.jsonl).

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


def record(
    session_id: str,
    envelope: dict,
    cumulative: dict,
    decision_result: dict,
) -> dict:
    """
    Append one audit record and immediately read it back to prove it landed.

    Returns the record dict that was written.
    Raises OSError if the write or read-back fails (caller should treat as
    an internal error but NOT change the decision — audit failure != deny).
    """
    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    rec: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": session_id,
        "action": {
            "namespace": (envelope.get("action") or {}).get("namespace", ""),
            "verb": (envelope.get("action") or {}).get("verb", ""),
            "ability": (envelope.get("action") or {}).get("ability", ""),
            "environment": (envelope.get("target") or {}).get("environment", ""),
        },
        "magnitude_count": int((envelope.get("magnitude") or {}).get("count", 1)),
        "cumulative_injected": cumulative,
        "decision": decision_result.get("decision", ""),
        "rule": decision_result.get("rule", ""),
        "reason": decision_result.get("reason", ""),
        # TODO: add audit_signature = ed25519.sign(record_bytes, vault_key)
    }

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
        # Verify key fields match (tamper-evident readback)
        if (
            written_rec.get("session_id") != rec["session_id"]
            or written_rec.get("decision") != rec["decision"]
            or written_rec.get("rule") != rec["rule"]
        ):
            raise OSError(
                f"audit read-back mismatch: wrote {rec!r}, read back {written_rec!r}"
            )

    return rec
