"""
wire.py -- the three HTTP planes this seat talks to, stdlib only.

1. CORE  `POST <gate_url>/v1/decide`  (Bearer = the engine credential).
   Never raises.  Every failure (refused, DNS, timeout, non-JSON, a 200 with no
   decision, an unknown decision string) comes back as an UNREACHABLE verdict,
   and the analyzer -- not this module -- decides what an unreachable gate
   means (fail="closed" -> SecurityRisk.UNKNOWN).  A core that answers
   HTTP 500 with its own `fail_closed` deny is NOT unreachable: core decided,
   and that decision is a deny.

2. EVIDENCE  `POST <portal>/api/v1/evidence`  -- docs/EVIDENCE-INGEST-SPEC-v1.md
   (reeflex-app), §4 record schema and §5 signing, both FROZEN.  `wire_record()`
   is a closed allowlist built by NAMING each §4 field; `assert_wire_clean()`
   re-checks the output before every send, because the server rejects the
   WHOLE batch on one unknown key (422).

   §4 HAS NO "source" FIELD, so "these rows came from OpenHands" is carried by
   the two fields §4 already has for it: `agent_id` (= the envelope's
   `agent.id`, `agent:openhands/<agent>/<conversation>`) and
   `action.target_system` (= the namespace, `openhands`, which is what §4.2
   says a connector derives it from).  No field is added to the wire.

3. HOLDS  `POST <portal>/api/v1/holds` (holds-v1 DIR-1, same signing as §5) and
   `GET <portal>/api/v1/holds/resolutions?since=` (DIR-2, gate token).  The
   evidence route stores `hold.hold_id` on an evidence row but creates no inbox
   row; only DIR-1 does (measured by the LiteLLM seat on the deployed app,
   2026-09-08).  So a hold that is not pushed here was never put in front of a
   human, and `hold_announced` in the analyzer's record says which it was.

SECRETS ARE NEVER IN AN EXCEPTION, A LOG LINE OR A RETURN VALUE.  Error text
names the URL path and the HTTP status only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

SIG_ALG_V1 = "hmac-sha256"

DECISIONS = ("allow", "deny", "require_approval")

# EVIDENCE-INGEST-SPEC-v1 §4, verbatim.
WIRE_TOP_LEVEL_FIELDS = frozenset({
    "decision_id", "verdict", "rule", "envelope_hash", "occurred_ts",
    "action", "magnitude", "agent_id", "traceparent", "hold", "sig_alg",
})
WIRE_ACTION_FIELDS = frozenset({"verb", "target_system", "target_environment"})
WIRE_HOLD_FIELDS = frozenset({"hold_id", "parent_decision_id", "resolution", "decided_by"})
WIRE_DECIDED_BY_FIELDS = frozenset({"type", "id"})
WIRE_VERBS = frozenset({"read", "create", "update", "delete", "execute", "transact", "emit"})
HOLD_RESOLUTIONS = frozenset({"approved", "rejected", "expired"})
DECIDED_BY_TYPES = frozenset({"human", "agent"})

# holds-v1 DIR-1 (reeflex-app `api/holds.py` `_ALLOWED` / `_REQUIRED`).
HOLD_TOP_LEVEL_FIELDS = frozenset({
    "hold_id", "decision_id", "verb", "target_system", "target_environment",
    "magnitude_count", "rule", "agent_id", "envelope_hash", "reason",
    "created_ts", "expires_ts", "sig_alg",
})
HOLD_REQUIRED_FIELDS = ("hold_id", "decision_id", "verb", "target_environment",
                        "rule", "envelope_hash", "created_ts")

# reeflex-core `holds.canonical_hash()`'s projection (`_HASH_ALLOWLIST`), the
# same one the LiteLLM seat duplicates and pins.
_HASH_ALLOWLIST = ("action", "axes", "magnitude", "target")


class Verdict:
    """Core's answer, or the fact that there was none.

    reachable=False means core never decided (transport or protocol failure);
    `decision` is then "" and the analyzer applies its `fail` mode.
    """

    __slots__ = ("reachable", "decision", "rule", "reason", "decision_id",
                 "hold_id", "expires_ts", "http_status", "error")

    def __init__(self, *, reachable, decision="", rule="", reason="",
                 decision_id=None, hold_id=None, expires_ts=None,
                 http_status=None, error=None):
        self.reachable = reachable
        self.decision = decision
        self.rule = rule
        self.reason = reason
        self.decision_id = decision_id
        self.hold_id = hold_id
        self.expires_ts = expires_ts
        self.http_status = http_status
        self.error = error

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def envelope_hash(envelope: dict) -> str:
    projection = {k: envelope[k] for k in _HASH_ALLOWLIST if k in envelope}
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ssl_context(url: str):
    if url.lower().startswith("https://"):
        return ssl.create_default_context()
    return None


def _request(url: str, *, method: str, body: Optional[bytes], headers: dict,
             timeout: float) -> tuple[Optional[int], Any, Optional[str]]:
    """(status, parsed JSON body or None, error).  Never raises."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(url)) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read()
        except Exception:  # pragma: no cover - defensive
            raw = b""
    except Exception as exc:  # URLError, timeout, TLS, reset ...
        return None, None, "%s %s: %s" % (method, urllib.parse.urlsplit(url).path,
                                          type(exc).__name__)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    return status, parsed, None


# ---------------------------------------------------------------------------
# 1. core
# ---------------------------------------------------------------------------

def decide(gate_url: str, api_key: Optional[str], envelope: dict, *,
           timeout: float) -> Verdict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    status, body, err = _request(gate_url.rstrip("/") + "/v1/decide", method="POST",
                                 body=json.dumps(envelope).encode("utf-8"),
                                 headers=headers, timeout=timeout)
    if err is not None:
        return Verdict(reachable=False, error=err)
    if not isinstance(body, dict) or body.get("decision") not in DECISIONS:
        detail = body.get("error") if isinstance(body, dict) else None
        return Verdict(reachable=False, http_status=status,
                       error="HTTP %s from /v1/decide with no decision%s"
                       % (status, " (%s)" % detail if detail else ""))
    return Verdict(reachable=True, decision=body["decision"],
                   rule=str(body.get("rule") or ""), reason=str(body.get("reason") or ""),
                   decision_id=body.get("decision_id"), hold_id=body.get("hold_id"),
                   expires_ts=body.get("expires_ts"), http_status=status)


# ---------------------------------------------------------------------------
# 2./3. the portal's signed planes
# ---------------------------------------------------------------------------

def canonical_body(records: list) -> bytes:
    """§5.1: UTF-8, keys sorted at every level, compact, no trailing newline."""
    return json.dumps(records, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sign(body: bytes, timestamp: int, signing_key: bytes) -> str:
    """§5: HMAC-SHA256 over `"<ts>.\\n"` + the canonical body."""
    return hmac.new(signing_key, ("%d.\n" % timestamp).encode("utf-8") + body,
                    hashlib.sha256).hexdigest()


def signing_key_from_hex(value: str) -> bytes:
    """The 32-byte key the portal shows once at gate registration as
    `REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY` (hex).  §5 / RFX-44."""
    key = bytes.fromhex(value.strip())
    if len(key) != 32:
        raise ValueError("evidence signing key must be 32 bytes (64 hex characters)")
    return key


def wire_record(*, decision_id: str, verdict: str, rule: str, envelope_hash: str,
                occurred_ts: str, verb: str, target_environment: str,
                target_system: Optional[str] = None, magnitude_count: Optional[int] = None,
                agent_id: Optional[str] = None, hold_id: Optional[str] = None,
                resolution: Optional[str] = None, decided_by_type: Optional[str] = None,
                decided_by_id: Optional[str] = None) -> dict:
    """One §4 record, built by naming each field."""
    missing = [n for n, v in (("decision_id", decision_id), ("verdict", verdict),
                              ("rule", rule), ("envelope_hash", envelope_hash),
                              ("occurred_ts", occurred_ts), ("action.verb", verb),
                              ("action.target_environment", target_environment)) if not v]
    if missing:
        raise ValueError("cannot build a §4 evidence record, missing: %s" % ", ".join(missing))
    rec: dict = {
        "decision_id": decision_id,
        "verdict": verdict,
        "rule": rule,
        "envelope_hash": envelope_hash,
        "occurred_ts": occurred_ts,
        "action": {"verb": verb, "target_environment": target_environment},
        "sig_alg": SIG_ALG_V1,
    }
    if target_system:
        rec["action"]["target_system"] = target_system
    if isinstance(magnitude_count, int) and not isinstance(magnitude_count, bool) \
            and magnitude_count >= 0:
        rec["magnitude"] = {"count": magnitude_count}
    if agent_id:
        rec["agent_id"] = agent_id
    if hold_id:
        hold: dict = {"hold_id": hold_id}
        if resolution in HOLD_RESOLUTIONS:
            hold["resolution"] = resolution
        # §4 constrains decided_by.type to an enum; anything else is dropped,
        # which §4 reads as "not stated", never as "no human".
        if decided_by_type in DECIDED_BY_TYPES and isinstance(decided_by_id, str) \
                and decided_by_id.strip():
            hold["decided_by"] = {"type": decided_by_type, "id": decided_by_id.strip()}
        rec["hold"] = hold
    assert_wire_clean(rec)
    return rec


def assert_wire_clean(rec: dict) -> None:
    extra = set(rec) - WIRE_TOP_LEVEL_FIELDS
    if extra:
        raise ValueError("§4 forbids top-level field(s): %s" % sorted(extra))
    if set(rec.get("action", {})) - WIRE_ACTION_FIELDS:
        raise ValueError("§4 forbids action field(s): %s"
                         % sorted(set(rec["action"]) - WIRE_ACTION_FIELDS))
    if rec.get("verdict") not in DECISIONS:
        raise ValueError("§4 verdict must be one of %s" % (DECISIONS,))
    if rec.get("action", {}).get("verb") not in WIRE_VERBS:
        raise ValueError("§4 action.verb %r is not one the ingest accepts"
                         % rec.get("action", {}).get("verb"))
    if "magnitude" in rec and set(rec["magnitude"]) - {"count"}:
        raise ValueError("§4 forbids magnitude field(s) other than count")
    hold = rec.get("hold")
    if hold is not None:
        if set(hold) - WIRE_HOLD_FIELDS:
            raise ValueError("§4 forbids hold field(s): %s" % sorted(set(hold) - WIRE_HOLD_FIELDS))
        if "decided_by" in hold and set(hold["decided_by"]) - WIRE_DECIDED_BY_FIELDS:
            raise ValueError("§4 forbids decided_by field(s)")


def hold_record(*, hold_id: str, decision_id: str, verb: str, target_environment: str,
                rule: str, envelope_hash: str, created_ts: str,
                target_system: Optional[str] = None, magnitude_count: Optional[int] = None,
                agent_id: Optional[str] = None, reason: Optional[str] = None,
                expires_ts: Optional[str] = None) -> dict:
    rec = {"hold_id": hold_id, "decision_id": decision_id, "verb": verb,
           "target_environment": target_environment, "rule": rule,
           "envelope_hash": envelope_hash, "created_ts": created_ts, "sig_alg": SIG_ALG_V1}
    missing = [f for f in HOLD_REQUIRED_FIELDS if not isinstance(rec.get(f), str) or not rec[f]]
    if missing:
        raise ValueError("cannot build a pending-hold record, missing: %s" % ", ".join(missing))
    if target_system:
        rec["target_system"] = target_system
    if isinstance(magnitude_count, int) and not isinstance(magnitude_count, bool) \
            and magnitude_count >= 0:
        rec["magnitude_count"] = magnitude_count
    if agent_id:
        rec["agent_id"] = agent_id
    if reason:
        rec["reason"] = reason
    if expires_ts:
        rec["expires_ts"] = expires_ts
    extra = set(rec) - HOLD_TOP_LEVEL_FIELDS
    if extra:  # pragma: no cover - built by naming, cannot happen
        raise ValueError("holds-v1 forbids field(s): %s" % sorted(extra))
    return rec


class PushResult:
    __slots__ = ("ok", "status", "body", "error")

    def __init__(self, ok, status=None, body=None, error=None):
        self.ok, self.status, self.body, self.error = ok, status, body, error

    def as_dict(self) -> dict:
        return {"ok": self.ok, "status": self.status, "body": self.body, "error": self.error}


def push_signed(portal_url: str, path: str, records: list, *, gate_token: str,
                signing_key: bytes, timeout: float, now: Optional[int] = None) -> PushResult:
    """POST a signed JSON-array batch (evidence §5 / holds-v1 DIR-1).  Never raises."""
    body = canonical_body(records)
    ts = int(now if now is not None else time.time())
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + gate_token,
        "X-Reeflex-Timestamp": str(ts),
        "X-Reeflex-Signature": "%s=%s" % (SIG_ALG_V1, sign(body, ts, signing_key)),
    }
    status, parsed, err = _request(portal_url.rstrip("/") + path, method="POST",
                                   body=body, headers=headers, timeout=timeout)
    if err is not None:
        return PushResult(False, error=err)
    return PushResult(status == 200, status=status, body=parsed,
                      error=None if status == 200 else "HTTP %s from %s" % (status, path))


def pull_resolutions(portal_url: str, *, gate_token: str, since: Optional[str],
                     timeout: float) -> tuple[Optional[list], Optional[str]]:
    """holds-v1 DIR-2.  Returns (resolutions, error); never raises."""
    url = portal_url.rstrip("/") + "/api/v1/holds/resolutions"
    if since:
        url += "?" + urllib.parse.urlencode({"since": since})
    status, parsed, err = _request(url, method="GET", body=None,
                                   headers={"Authorization": "Bearer " + gate_token},
                                   timeout=timeout)
    if err is not None:
        return None, err
    if status != 200 or not isinstance(parsed, list):
        return None, "HTTP %s from /api/v1/holds/resolutions" % status
    return parsed, None
