"""
adapter.py -- CONTRACT-CONFORMANT mock adapter (SPEC §6).

Implements the four Reeflex adapter responsibilities:
  1. INTERCEPT  -- apply(intent) receives the agent's declared intent BEFORE
                   the store is touched.
  2. NORMALIZE  -- builds a valid, signed Action Envelope (SPEC §2) from the
                   intent.  Axis mapping is documented per operation below.
  3. ENFORCE    -- POST /v1/decide; parses the Decision and applies it
                   faithfully:
                     allow            -> execute on store
                     deny             -> block, surface reason, store UNTOUCHED
                     require_approval -> hold, store UNTOUCHED
                   FAIL-CLOSED: if core is unreachable or returns a non-200,
                   deny/hold -- NEVER silently allow.
  4. AUDIT      -- appends one JSONL record per decision to
                   reeflex-mock/adapter-audit.jsonl (and stdout summary).

The agent NEVER touches the store directly.  This file IS the enforcement seam.

Axis mapping decisions (NORMALIZE contract rationale):
  read/get           -> reversible  / single  / internal  (no state change)
  delete single      -> recoverable / single  / internal  (backend is mock-soft-delete)
  delete bulk <20    -> recoverable / scoped  / internal
  delete bulk >=20   -> irreversible/ broad   / internal  (treat as hard, cannot undo in bulk)
  update single      -> recoverable / single  / internal
  bulk_delete in prod with count=50 -> irreversible / broad / production  (hits R2)
  delete in staging  -> recoverable / single or scoped    (does NOT hit prod rules)

Conservative defaults applied everywhere per SPEC §2:
  - unknown reversibility -> irreversible
  - unknown blast_radius  -> systemic
  - unknown externality   -> physical
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from store import PostStore

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_CORE_URL_DEFAULT = "http://127.0.0.1:8181"
CORE_URL = os.environ.get("REEFLEX_CORE_URL", _CORE_URL_DEFAULT)

_AUDIT_LOG_DEFAULT = os.path.join(os.path.dirname(__file__), "adapter-audit.jsonl")
AUDIT_LOG = os.environ.get("REEFLEX_MOCK_AUDIT_LOG", _AUDIT_LOG_DEFAULT)


# ---------------------------------------------------------------------------
# Outcome constants returned to the caller
# ---------------------------------------------------------------------------

OUTCOME_EXECUTED = "executed"
OUTCOME_BLOCKED  = "blocked"
OUTCOME_HELD     = "held"
OUTCOME_ERROR    = "error"


# ---------------------------------------------------------------------------
# Result dataclass (plain dict for stdlib-only constraint)
# ---------------------------------------------------------------------------

def _result(
    outcome: str,
    decision: str,
    rule: str,
    reason: str,
    store_changed: bool,
    envelope_summary: dict,
    obligations: list,
    store_value: Any = None,
) -> dict:
    return {
        "outcome": outcome,
        "decision": decision,
        "rule": rule,
        "reason": reason,
        "store_changed": store_changed,
        "envelope_summary": envelope_summary,
        "obligations": obligations,
        "store_value": store_value,
    }


# ---------------------------------------------------------------------------
# Adapter class
# ---------------------------------------------------------------------------

class MockAdapter:
    """
    Reeflex adapter for the mock PostStore backend.

    Usage:
        store = PostStore()
        adapter = MockAdapter(store, session_id="sess_demo_001")
        result = adapter.apply({"op": "delete", "ids": [42], "environment": "production"})
    """

    def __init__(self, store: PostStore, session_id: str) -> None:
        self._store = store
        self._session_id = session_id

    # ------------------------------------------------------------------
    # INTERCEPT: public entry point
    # ------------------------------------------------------------------

    def apply(self, intent: dict) -> dict:
        """
        INTERCEPT -> NORMALIZE -> ENFORCE -> AUDIT.

        intent shape:
          op          : "get" | "list" | "delete" | "bulk_delete" | "update"
          ids         : List[int]  (for delete/bulk_delete)
          id          : int        (for get/update)
          fields      : dict       (for update)
          environment : str        (production | staging | dev)
          force_delete: bool       (optional; if True -> irreversible)
          approved    : bool       (optional; True = re-submission after human hold)
        """
        # -- NORMALIZE: build the Action Envelope
        envelope = self._normalize(intent)

        # -- ENFORCE: ask core
        decision_resp = self._call_core(envelope)

        # -- ENFORCE: apply the decision
        result = self._enforce(intent, envelope, decision_resp)

        # -- AUDIT: write one record
        self._audit(intent, envelope, decision_resp, result)

        return result

    # ------------------------------------------------------------------
    # NORMALIZE: map backend intent -> Action Envelope (SPEC §2)
    # ------------------------------------------------------------------

    def _normalize(self, intent: dict) -> dict:
        op = intent.get("op", "unknown")
        env = intent.get("environment", "production")
        force = bool(intent.get("force_delete", False))
        approved = bool(intent.get("approved", False))

        ids: List[int] = intent.get("ids", [])
        if "id" in intent:
            ids = [intent["id"]]

        count = max(len(ids), 1)

        # -- Verb mapping (SPEC §3) ----------------------------------------
        # read -> read; delete/bulk_delete -> delete; update -> update
        if op in ("get", "list"):
            verb = "read"
        elif op in ("delete", "bulk_delete"):
            verb = "delete"
        elif op == "update":
            verb = "update"
        else:
            verb = "execute"  # unknown op: conservative execute

        # -- ability (backend-specific operation id) -----------------------
        ability = f"mock/{op}"

        # -- target.kind / ref ---------------------------------------------
        kind = "post"
        if op == "list":
            ref = None
        elif count == 1 and ids:
            ref = f"post:{ids[0]}"
        else:
            ref = None  # bulk

        # -- AXIS MAPPING (per module docstring) ---------------------------
        #
        # reversibility:
        #   read/list            -> reversible  (no state change at all)
        #   update               -> recoverable (can be reverted by another update)
        #   delete single        -> recoverable (mock backend supports soft-delete)
        #   bulk delete >= 20    -> irreversible (treat large bulk as unrecoverable)
        #   bulk delete < 20     -> recoverable  (small batch)
        #   force_delete = True  -> irreversible (explicit hard delete)
        #   unknown op           -> irreversible (safe-conservative default)
        #
        # blast_radius:
        #   count == 1           -> single
        #   1 < count < 20       -> scoped
        #   count >= 20          -> broad
        #   list (all records)   -> broad
        #
        # externality:
        #   all mock ops stay internal (mock backend has no outbound side-effects)
        #   -> internal

        if verb == "read":
            reversibility = "reversible"
        elif verb == "update":
            reversibility = "recoverable"
        elif verb == "delete":
            if force:
                reversibility = "irreversible"
            elif count >= 20:
                reversibility = "irreversible"
            else:
                reversibility = "recoverable"
        else:
            # safe-conservative default for unknown verbs (SPEC §2)
            reversibility = "irreversible"

        if op == "list":
            blast_radius = "broad"   # list touches all records
        elif count == 1:
            blast_radius = "single"
        elif count < 20:
            blast_radius = "scoped"
        else:
            blast_radius = "broad"

        externality = "internal"

        # -- meta: timestamp, nonce, stub signature ------------------------
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = _make_nonce(self._session_id, ts, op, str(ids))
        signature = f"ed25519:stub:{nonce[:16]}"  # stub; real signing = Vault key

        envelope = {
            "reeflex_version": "0.1",
            "agent": {
                "id": "agent:mock-demo-agent",
                "on_behalf_of": "user:synthetic-user",
                "session_id": self._session_id,
            },
            "action": {
                "namespace": "mock",
                "verb": verb,
                "ability": ability,
            },
            "target": {
                "kind": kind,
                "ref": ref,
                "environment": env,
            },
            "params": {
                "op": op,
                "ids": ids,
                "fields": intent.get("fields", {}),
            },
            "magnitude": {
                "count": count,
            },
            "axes": {
                "reversibility": reversibility,
                "blast_radius": blast_radius,
                "externality": externality,
            },
            "approval": {
                "present": approved,
                "by": "user:synthetic-approver" if approved else None,
                "role": "admin" if approved else None,
            },
            "trajectory_ref": None,
            "context": {},
            "meta": {
                "timestamp": ts,
                "nonce": nonce,
                "signature": signature,
            },
        }
        return envelope

    # ------------------------------------------------------------------
    # ENFORCE: call core and apply the decision
    # ------------------------------------------------------------------

    def _call_core(self, envelope: dict) -> dict:
        """
        POST /v1/decide to reeflex-core.

        FAIL-CLOSED: on ANY exception (connection refused, timeout, non-200,
        JSON parse error) return a deny decision.  NEVER silently allow.
        """
        url = f"{CORE_URL}/v1/decide"
        body = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # HTTP 4xx/5xx from core -- read body for fail-closed decision
            try:
                raw = exc.read()
                status = exc.code
                parsed = json.loads(raw.decode("utf-8"))
                # If core returned a decision object (e.g. 500+deny), use it
                if "decision" in parsed:
                    return parsed
            except Exception:
                pass
            # Fallback fail-closed
            return _fail_closed_decision(f"core HTTP {exc.code}: {exc.reason}")
        except Exception as exc:
            # Connection refused, timeout, etc. -> FAIL CLOSED
            return _fail_closed_decision(f"core unreachable: {exc}")

        # Parse response
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return _fail_closed_decision(f"core response not JSON: {exc}")

        # Non-200 with a decision in the body (e.g. 500 fail-closed from core)
        if status != 200:
            if "decision" in parsed:
                return parsed
            return _fail_closed_decision(f"core returned HTTP {status}")

        # Validate decision field present
        if "decision" not in parsed:
            return _fail_closed_decision("core response missing 'decision' field")

        return parsed

    def _enforce(self, intent: dict, envelope: dict, decision_resp: dict) -> dict:
        """
        Apply the decision faithfully:
          allow            -> execute the op on the store
          deny             -> block; store UNTOUCHED
          require_approval -> hold; store UNTOUCHED
          anything else    -> treat as deny (fail-closed)
        """
        decision = decision_resp.get("decision", "deny")
        rule = decision_resp.get("rule", "unknown")
        reason = decision_resp.get("reason", "")
        obligations: list = decision_resp.get("obligations", [])

        # Envelope summary for audit (no full dump of large params)
        env_summary = {
            "verb": envelope["action"]["verb"],
            "ability": envelope["action"]["ability"],
            "environment": envelope["target"]["environment"],
            "count": envelope["magnitude"]["count"],
            "axes": envelope["axes"],
            "session_id": envelope["agent"]["session_id"],
        }

        if decision == "allow":
            # Execute the op on the store
            store_value = self._execute_on_store(intent)
            return _result(
                outcome=OUTCOME_EXECUTED,
                decision=decision,
                rule=rule,
                reason=reason,
                store_changed=True,
                envelope_summary=env_summary,
                obligations=obligations,
                store_value=store_value,
            )

        elif decision == "deny":
            # Block -- store UNTOUCHED
            return _result(
                outcome=OUTCOME_BLOCKED,
                decision=decision,
                rule=rule,
                reason=reason,
                store_changed=False,
                envelope_summary=env_summary,
                obligations=obligations,
            )

        elif decision == "require_approval":
            # Hold -- store UNTOUCHED; caller must re-submit with approved=True
            return _result(
                outcome=OUTCOME_HELD,
                decision=decision,
                rule=rule,
                reason=reason,
                store_changed=False,
                envelope_summary=env_summary,
                obligations=obligations,
            )

        else:
            # Unknown decision value -> fail-closed (deny)
            return _result(
                outcome=OUTCOME_BLOCKED,
                decision="deny",
                rule="adapter/unknown_decision_fail_closed",
                reason=f"unknown decision value '{decision}' -- failing closed",
                store_changed=False,
                envelope_summary=env_summary,
                obligations=obligations,
            )

    def _execute_on_store(self, intent: dict) -> Any:
        """Execute the approved operation on the store. Called ONLY on allow."""
        op = intent.get("op")
        if op == "get":
            return self._store.get(intent["id"])
        elif op == "list":
            return self._store.list()
        elif op == "delete":
            pid = intent.get("id") or (intent.get("ids", [None])[0])
            return self._store.delete(pid)
        elif op == "bulk_delete":
            ids = intent.get("ids", [])
            return self._store.bulk_delete(ids)
        elif op == "update":
            return self._store.update(intent["id"], intent.get("fields", {}))
        else:
            return None

    # ------------------------------------------------------------------
    # AUDIT: one record per decision (SPEC §6, SPEC §7)
    # ------------------------------------------------------------------

    def _audit(
        self,
        intent: dict,
        envelope: dict,
        decision_resp: dict,
        result: dict,
    ) -> None:
        """
        Emit one adapter-side audit record per decision to JSONL.

        Fields: intent summary, envelope summary, decision, applied outcome,
        store_changed bool.
        """
        record = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_id": self._session_id,
            "intent_op": intent.get("op"),
            "intent_env": intent.get("environment"),
            "intent_count": len(intent.get("ids", [])) or 1,
            "envelope": result["envelope_summary"],
            "decision": decision_resp.get("decision"),
            "rule": decision_resp.get("rule"),
            "reason": decision_resp.get("reason"),
            "obligations": decision_resp.get("obligations", []),
            "applied": result["outcome"],
            "store_changed": result["store_changed"],
        }
        line = json.dumps(record, separators=(",", ":")) + "\n"
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        except OSError as exc:
            # Audit failure must NOT affect the decision
            import sys
            print(f"[adapter] WARN: audit write failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_nonce(session_id: str, ts: str, op: str, ids_str: str) -> str:
    """Generate a determinism-safe nonce from the call context."""
    # Use a counter-appended hash to avoid replay collisions within same second.
    raw = f"{session_id}:{ts}:{op}:{ids_str}:{time.monotonic_ns()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _fail_closed_decision(reason: str) -> dict:
    """
    Return a deny Decision when core is unreachable or returns unusable output.

    FAIL-CLOSED invariant: this is called on ANY core communication failure.
    We NEVER silently allow on error.
    """
    return {
        "decision": "deny",
        "reason": f"reeflex-core unreachable or error -- failing closed: {reason}",
        "rule": "reeflex.core/fail_closed",
        "obligations": [],
        "modulation": None,
    }
