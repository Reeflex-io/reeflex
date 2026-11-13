"""
analyzer.py -- `ReeflexSecurityAnalyzer`, an OpenHands `SecurityAnalyzerBase`
whose risk for each action is a Reeflex gate's verdict on it.

THE SEAM, AS MEASURED ON openhands-sdk 1.56.0
=============================================
`Agent._analyze_for_confirmation()` calls `security_analyzer.analyze_actions()`
on every batch of actions the model proposes, before any of them runs, and
emits one `SecurityAnalysisEvent` carrying `risks[action.id]` and
`details[action.id]`.  It then asks `confirmation_policy.should_confirm(risk)`
for each risk; if any says yes the conversation stops in
`WAITING_FOR_CONFIRMATION` with the batch unexecuted.

This class overrides `analyze_action()` (not just `security_risk()`) so the
Reeflex decision -- decision id, verdict, rule, hold id -- lands in that
event's `details`, i.e. in the conversation's own event log.  The same record
is kept in `self.decisions[action.id]` for the confirmation policy, which the
SDK hands only a risk level and therefore cannot otherwise tell a deny from a
hold.

VERDICT -> RISK
===============
    allow, verb == read        LOW
    allow, anything else       MEDIUM
    require_approval (hold)    HIGH
    deny                       HIGH
    gate unreachable           UNKNOWN  (fail="closed", the default)
                               LOW      (fail="open" -- opt-in, documented)

With the SDK's own `ConfirmRisky()` (threshold HIGH, confirm_unknown True) that
already stops on every deny, hold and unreachable gate.  `ReeflexConfirmation
Policy` adds the part a risk level cannot carry: reject a deny automatically,
and resolve a hold from the Reeflex portal.

WHAT THIS IS NOT
================
A supervisory layer.  The verdict is a decision about a PROPOSED action, made
before it runs; it is not a record of what happened.  Two paths skip it, both
measured in the SDK source: `conversation.execute_tool()` (its docstring: "This
method bypasses the agent loop, including confirmation policies and security
analyzer checks"), and a caller who answers `WAITING_FOR_CONFIRMATION` with a
bare `conversation.run()`, which is the SDK's "approve" and executes the
pending batch whatever the verdict was.

SECRETS
=======
The engine credential, gate token and evidence signing key are PRIVATE
attributes: they are not pydantic fields, so they are not in `model_dump()`
and never reach a persisted `base_state.json`.  Passed explicitly or read from
the environment by name (REEFLEX_CORE_TOKEN, REEFLEX_CONNECTOR_GATE_TOKEN,
REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY -- the names the portal prints at gate
registration).  A conversation resumed from disk therefore re-reads them from
the environment; with none set it fails closed (UNKNOWN), it does not run
ungoverned.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Literal, Optional

from pydantic import Field, PrivateAttr

from openhands.sdk.event.llm_convertible import ActionEvent
from openhands.sdk.security.analyzer import SecurityAnalysis, SecurityAnalyzerBase
from openhands.sdk.security.risk import SecurityRisk

from . import mapping, wire

ENV_CORE_URL = "REEFLEX_CORE_URL"
ENV_CORE_TOKEN = "REEFLEX_CORE_TOKEN"
ENV_PORTAL_URL = "REEFLEX_PORTAL_URL"
ENV_GATE_TOKEN = "REEFLEX_CONNECTOR_GATE_TOKEN"
ENV_SIGNING_KEY = "REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY"

# Whether a held action was actually put in front of a human.
ANNOUNCED = "announced"
ANNOUNCE_NOT_CONFIGURED = "not_configured"
ANNOUNCE_FAILED = "failed"


class ReeflexSecurityAnalyzer(SecurityAnalyzerBase):
    """Risk = the Reeflex gate's verdict on the action.

    ReeflexSecurityAnalyzer(gate_url, api_key, *, org_id=None,
                            agent_id="openhands", timeout=3.0, fail="closed",
                            environment="production", portal_url=None,
                            gate_token=None, evidence_signing_key=None)
    """

    gate_url: str = Field(default="", description="Reeflex core base URL (POST /v1/decide).")
    org_id: Optional[str] = Field(default=None, description="A label carried in the "
                                  "envelope context. Never a decision input: tenancy is "
                                  "decided by the credential the gate sees.")
    agent_id: str = Field(default="openhands")
    environment: Literal["production", "staging", "dev"] = Field(default="production")
    on_behalf_of: Optional[str] = Field(default=None)
    timeout: float = Field(default=3.0, gt=0)
    fail: Literal["closed", "open"] = Field(default="closed")
    portal_url: Optional[str] = Field(default=None, description="Reeflex portal base URL "
                                      "for evidence, pending holds and resolutions.")
    push_evidence: bool = Field(default=True)
    trust_mcp_annotations: bool = Field(default=False)
    tool_map: dict[str, str] = Field(default_factory=dict)

    _api_key: Optional[str] = PrivateAttr(default=None)
    _gate_token: Optional[str] = PrivateAttr(default=None)
    _signing_key: Optional[bytes] = PrivateAttr(default=None)
    _conversation: Any = PrivateAttr(default=None)
    _session_id: str = PrivateAttr(default_factory=lambda: uuid.uuid4().hex)
    _decisions: dict = PrivateAttr(default_factory=dict)
    _deferred_evidence: dict = PrivateAttr(default_factory=dict)
    _evidence_log: list = PrivateAttr(default_factory=list)
    _lock: Any = PrivateAttr(default_factory=threading.Lock)

    def __init__(self, gate_url: Optional[str] = None, api_key: Optional[str] = None,
                 /, *, gate_token: Optional[str] = None,
                 evidence_signing_key: Optional[str] = None, **data: Any) -> None:
        if gate_url is not None:
            data["gate_url"] = gate_url
        super().__init__(**data)
        # Explicit values win over the environment model_post_init read.
        if api_key:
            self._api_key = api_key
        if gate_token:
            self._gate_token = gate_token
        if evidence_signing_key:
            self._signing_key = wire.signing_key_from_hex(evidence_signing_key)

    def model_post_init(self, __context: Any) -> None:
        # Runs on BOTH construction paths: `__init__` and the SDK's
        # `model_validate()` when a persisted conversation is resumed, which
        # does not call `__init__`.  Secrets therefore come back by reference.
        super().model_post_init(__context)
        if not self.gate_url:
            self.gate_url = os.environ.get(ENV_CORE_URL, "")
        if self.portal_url is None and os.environ.get(ENV_PORTAL_URL):
            self.portal_url = os.environ[ENV_PORTAL_URL]
        self._api_key = os.environ.get(ENV_CORE_TOKEN) or None
        self._gate_token = os.environ.get(ENV_GATE_TOKEN) or None
        key = os.environ.get(ENV_SIGNING_KEY) or None
        self._signing_key = wire.signing_key_from_hex(key) if key else None

    # ------------------------------------------------------------------ wiring

    def attach(self, conversation: Any, policy: Any = None) -> "ReeflexSecurityAnalyzer":
        """Register on a conversation: this analyzer, and a confirmation policy
        (a `ReeflexConfirmationPolicy` bound to this analyzer by default).

        Binding the conversation gives the envelope its session (the
        conversation id, so R5's cumulative budget is per conversation) and
        lets MCP tool annotations be read off `conversation.agent.tools_map`.
        """
        from .policy import ReeflexConfirmationPolicy

        self._conversation = conversation
        conv_id = getattr(conversation, "id", None)
        if conv_id:
            self._session_id = str(conv_id)
        conversation.set_security_analyzer(self)
        conversation.set_confirmation_policy(policy or ReeflexConfirmationPolicy(self))
        return self

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def decisions(self) -> dict:
        """action id -> the Reeflex record for that action (side map)."""
        return self._decisions

    @property
    def evidence_log(self) -> list:
        """One entry per evidence/hold push attempt: what was sent and the answer."""
        return self._evidence_log

    @property
    def portal_configured(self) -> bool:
        return bool(self.portal_url and self._gate_token and self._signing_key)

    def _annotations_for(self, tool_name: str) -> Optional[dict]:
        conv = self._conversation
        if conv is None:
            return None
        try:
            tool = conv.agent.tools_map.get(tool_name)
        except Exception:
            return None
        ann = getattr(tool, "annotations", None) if tool is not None else None
        if ann is None:
            return None
        try:
            return ann.model_dump(mode="json", exclude_none=True)
        except Exception:  # pragma: no cover - defensive
            return None

    def _cwd(self) -> Optional[str]:
        conv = self._conversation
        try:
            wd = conv.workspace.working_dir if conv is not None else None
        except Exception:
            wd = None
        return str(wd) if wd else None

    # ------------------------------------------------------------------ the seam

    def security_risk(self, action: ActionEvent) -> SecurityRisk:
        return self.analyze_action(action).risk

    def analyze_action(self, action: ActionEvent) -> SecurityAnalysis:
        record = self.decide(action)
        return SecurityAnalysis(risk=SecurityRisk(record["risk"]), details=record)

    def decide(self, action: ActionEvent) -> dict:
        """Map, decide, record.  Returns the record stored in `decisions`."""
        # Annotations are read for MCP tools ONLY.  The SDK's built-in tools
        # carry annotations too (the terminal's own declaration is a property
        # of "a shell", not of this command); applying them would price `ls`
        # like `rm -rf /`.  A built-in tool is priced from its arguments.
        annotations = (self._annotations_for(getattr(action, "tool_name", ""))
                       if mapping.is_mcp_action(action) else None)
        mapped = mapping.map_action(
            action, tool_map=self.tool_map, annotations=annotations,
            trust_mcp_annotations=self.trust_mcp_annotations)
        envelope = mapping.build_envelope(
            mapped, session_id=self._session_id, agent_id=self.agent_id,
            environment=self.environment, on_behalf_of=self.on_behalf_of,
            cwd=self._cwd(), org_id=self.org_id)
        occurred_ts = wire.rfc3339_now()
        verdict = wire.decide(self.gate_url, self._api_key, envelope, timeout=self.timeout)
        risk = self._risk(verdict, mapped)

        record = {
            "reeflex_decision_id": verdict.decision_id,
            "verdict": verdict.decision if verdict.reachable else "unreachable",
            "rule": verdict.rule or None,
            "reason": verdict.reason or None,
            "hold_id": verdict.hold_id,
            "expires_ts": verdict.expires_ts,
            "risk": risk.value,
            "gate_reachable": verdict.reachable,
            "gate_error": verdict.error,
            "fail_mode": self.fail,
            "verb": envelope["action"]["verb"],
            "axes": envelope["axes"],
            "environment": self.environment,
            "envelope_hash": wire.envelope_hash(envelope),
            "agent_id": envelope["agent"]["id"],
            "session_id": envelope["agent"]["session_id"],
            "tool_name": mapped.tool_name,
            "classifier_tool": mapped.classifier_tool,
            "mapping_source": mapped.mapping_source,
            "overlays": list(mapped.overlays),
            "occurred_ts": occurred_ts,
            "hold_announced": None,
            "evidence_pushed": None,
        }
        if verdict.reachable:
            self._record_evidence(record, envelope)
        action_id = getattr(action, "id", None)
        with self._lock:
            if action_id:
                self._decisions[action_id] = record
        return record

    def _risk(self, verdict: wire.Verdict, mapped: mapping.MappedAction) -> SecurityRisk:
        if not verdict.reachable:
            return SecurityRisk.UNKNOWN if self.fail == "closed" else SecurityRisk.LOW
        if verdict.decision in ("deny", "require_approval"):
            return SecurityRisk.HIGH
        return SecurityRisk.LOW if mapped.read_only else SecurityRisk.MEDIUM

    # ------------------------------------------------------------------ evidence

    def _wire_kwargs(self, record: dict, envelope: dict) -> dict:
        return dict(decision_id=record["reeflex_decision_id"], verdict=record["verdict"],
                    rule=record["rule"], envelope_hash=record["envelope_hash"],
                    occurred_ts=record["occurred_ts"], verb=record["verb"],
                    target_environment=self.environment,
                    target_system=envelope["action"]["namespace"],
                    magnitude_count=envelope["magnitude"]["count"],
                    agent_id=record["agent_id"])

    def _record_evidence(self, record: dict, envelope: dict) -> None:
        if not (self.push_evidence and self.portal_configured and record["reeflex_decision_id"]):
            record["evidence_pushed"] = "not_configured"
            if record["hold_id"]:
                record["hold_announced"] = ANNOUNCE_NOT_CONFIGURED
            return
        kwargs = self._wire_kwargs(record, envelope)
        if record["hold_id"]:
            # Put the hold in front of a human (holds-v1 DIR-1) now; defer the
            # §4 evidence row until the hold is resolved, because evidence is
            # idempotent on decision_id (§6) -- a row pushed now could never
            # later carry who resolved it.
            hold = wire.hold_record(
                hold_id=record["hold_id"], decision_id=record["reeflex_decision_id"],
                verb=record["verb"], target_environment=self.environment,
                rule=record["rule"], envelope_hash=record["envelope_hash"],
                created_ts=record["occurred_ts"], target_system=kwargs["target_system"],
                magnitude_count=kwargs["magnitude_count"], agent_id=record["agent_id"],
                reason=record["reason"], expires_ts=record["expires_ts"])
            res = self._push("/api/v1/holds", [hold])
            record["hold_announced"] = ANNOUNCED if res.ok else ANNOUNCE_FAILED
            with self._lock:
                self._deferred_evidence[record["hold_id"]] = kwargs
            record["evidence_pushed"] = "deferred_until_resolved"
            return
        res = self._push("/api/v1/evidence", [wire.wire_record(**kwargs)])
        record["evidence_pushed"] = "accepted" if res.ok else "failed"

    def _push(self, path: str, records: list) -> wire.PushResult:
        res = wire.push_signed(self.portal_url, path, records, gate_token=self._gate_token,
                               signing_key=self._signing_key, timeout=self.timeout)
        # Never let an evidence failure change a decision already made: the
        # same rule core applies to its own audit.
        self._evidence_log.append({"path": path, "records": records, "result": res.as_dict()})
        return res

    def complete_hold(self, hold_id: str, *, resolution: Optional[str],
                      decided_by_type: Optional[str] = None,
                      decided_by_id: Optional[str] = None) -> Optional[wire.PushResult]:
        """Push the deferred §4 row for a held decision, now carrying how it
        was resolved (approved / rejected / expired, and by whom)."""
        with self._lock:
            kwargs = self._deferred_evidence.pop(hold_id, None)
        if kwargs is None or not self.portal_configured:
            return None
        rec = wire.wire_record(**kwargs, hold_id=hold_id, resolution=resolution,
                               decided_by_type=decided_by_type, decided_by_id=decided_by_id)
        return self._push("/api/v1/evidence", [rec])

    def flush(self) -> list:
        """Push every still-deferred held decision without a resolution, e.g.
        when a session ends with holds nobody answered.  §4 reads the absent
        resolution as "not stated"."""
        with self._lock:
            pending = list(self._deferred_evidence)
        return [self.complete_hold(h, resolution=None) for h in pending]

    # ------------------------------------------------------------------ portal

    def pull_resolutions(self, since: Optional[str] = None):
        if not (self.portal_url and self._gate_token):
            return None, "portal not configured (portal_url + gate token)"
        return wire.pull_resolutions(self.portal_url, gate_token=self._gate_token,
                                     since=since, timeout=self.timeout)
