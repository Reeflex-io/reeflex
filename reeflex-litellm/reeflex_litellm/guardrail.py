"""
guardrail.py -- the LiteLLM seat: a CustomGuardrail on the POST-CALL hook.

Wire it into a LiteLLM proxy config (see `proxy/config.yaml` in this package):

    guardrails:
      - guardrail_name: "reeflex-action-gate"
        litellm_params:
          guardrail: reeflex_litellm.guardrail.ReeflexActionGuardrail
          mode: post_call
          default_on: true

LiteLLM instantiates a dotted `guardrail:` value through
`GuardrailRegistry.initialize_custom_guardrail()` with
`guardrail_name=`, `event_hook=<mode>`, `default_on=` plus whatever else is in
`litellm_params`, which is why `__init__` takes `**kwargs`.

WHERE IN THE REQUEST THIS SITS, AND WHY POST-CALL
=================================================
`async_post_call_success_hook` runs after the model has answered and before the
proxy returns that answer to the caller.  Verified in
`litellm/proxy/utils.py`: the return value replaces the response
(`if guardrail_response is not None: response = guardrail_response`), and an
exception raised here propagates to the caller instead of a response.

POST-CALL IS THE ONLY HOOK THAT CAN SEE AN ACTION.  The pre-call hook sees the
prompt and the tool SCHEMA -- which tools exist -- not which tool the model
chose or with what arguments.  The action does not exist until the model has
answered.  That is also the source of this seat's central limit: what it sees is
a tool call PROPOSED.  See the README.

WHAT IT DOES
============
Resolve the tenant, then for each choice, for each tool call, in order:
normalize -> classify (the ONE classifier) -> envelope -> POST /v1/decide ->
enforce -> record.  Allowed calls are left untouched; refused calls are removed
and replaced by a structured refusal carrying `stage: "refused_at_gateway"`.
A response with no tool calls is returned unchanged and never even reaches core.

TENANCY IS RESOLVED BEFORE ANY DECISION (RFX-243)
=================================================
The hook's SECOND argument, `user_api_key_dict`, is the proxy's own
authentication result -- the virtual key, the team, the user -- and the caller
cannot set it.  `tenancy.resolve()` maps it to a Reeflex org from an explicit
map, and a caller the map does not bind is REFUSED before core is called: no
decision lands in another department's evidence, and no R5 budget is charged to
a session that belongs to nobody.  There is no default org; tenancy.py says why
at length.

The resolved tenant is not just a label.  It is in `agent.id` (so core's hold
check 8 cannot let one department spend another's approval) and in
`agent.session_id` (so R5's cumulative budget does not straddle departments).

WHAT IT RECORDS, AND THE ONE THING IT MUST NOT CLAIM
====================================================
Every decision produces a line in the adapter's own evidence ledger carrying
`enforcement_stage`, `prevents_execution: false` and `gateway_routing` -- which
model answered, on a declared on-prem or cloud endpoint, for which key/team.
When `REEFLEX_LITELLM_EVIDENCE_PUSH` is on, the §4 projection of those lines is
signed with the TENANT'S gate credentials and pushed to the evidence ingest,
which is what puts two departments' decisions in two orgs.  `gateway_routing`
and `enforcement_stage` are NOT on that wire: §4 is a closed schema and the
contract is frozen.  evidence.py has the measurement and the consequence.

FAILURE POSTURE
===============
The hook itself is wrapped: if THIS code raises for a reason
`enforce.rule_one_call()` did not already handle, the outer handler refuses
every tool call on the response rather than letting the exception escape.  An
exception escaping a post-call hook would either 500 the request (denying text
answers too) or, depending on the caller's error handling, be swallowed -- and a
swallowed governance error is a fail-open.

WHAT IT DOES NOT DO
===================
No prompt reading, no PII masking, no content scoring, no LLM anywhere in the
decision path.  This seat is blind to prose by construction; text guardrails
keep their own seat and this one does not duplicate them.

STREAMING (`stream: true`) IS COVERED TOO, BY A SECOND HOOK (RFX-242)
====================================================================
`async_post_call_success_hook` only ever sees a BUFFERED response.  A streaming
request is delivered through `async_post_call_streaming_iterator_hook`, which
this class now also implements: tool-call deltas are buffered until each call is
complete, the calls are decided in the same order and by the same code as on the
buffered path, and only then are the chunks released, replaced by the structured
refusal, or withheld while a hold waits for a human.  Text deltas that carry no
tool call stream through untouched.  See streaming.py, and the README's
streaming section for what it costs in time-to-first-token.

Implementing it also REMOVES a second, quieter defect.  Measured on litellm
1.100.0 before this change: a streamed response was assembled after delivery and
run through `async_post_call_success_hook` by
`ProxyBaseLLMRequestProcessing._run_deferred_stream_guardrails` -- which that
function's own docstring calls "audit-only -- content has already been delivered
to the client".  So a streamed `rm -rf /` produced a `deny` row in core's audit
log AND reached the caller intact: the record contradicted the wire.  LiteLLM
skips that deferred pass for any guardrail that defines
`async_post_call_streaming_iterator_hook` in its class `__dict__`
(`common_request_processing.py`, the `type(cb).__dict__` check), so the decision
is now taken once, before delivery, instead of twice with only the late one
mattering.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Optional

from . import core as _core
from . import enforce as _enforce
from . import evidence as _evidence
from . import normalize as _normalize
from . import response as _response
from . import routing as _routing
from . import streaming as _streaming
from . import tenancy as _tenancy

_logger = logging.getLogger("reeflex_litellm")


def _log(message: str) -> None:
    """One place for the operator-facing log line.

    WARNING level, not INFO: every line this emits is either a governance
    refusal an operator has to fix (an unmapped key) or a gap in the evidence
    record.  Neither should need a log-level change to become visible.
    Newlines are stripped -- the values interpolated in include operator- and
    key-supplied aliases, and a forged extra log line would be a way to write
    a false governance record into a text log.
    """
    _logger.warning("reeflex: %s", message.replace("\n", " ").replace("\r", " "))

# LiteLLM is an OPTIONAL dependency of this package (extra: `proxy`).  The
# decision logic in enforce.py / normalize.py / envelope.py / core.py imports
# nothing from litellm and is tested without it; only this module needs it.
#
# The fallback base class below exists so that `import reeflex_litellm.guardrail`
# does not explode in an environment without litellm (the package's own test
# venv, a CLI-only install).  It is NOT a test double: tests that exercise the
# LiteLLM contract assert `LITELLM_AVAILABLE is True` first and skip loudly
# otherwise, so a green suite can never mean "the shim passed".
try:  # pragma: no cover - exercised by both branches in CI, not by one run
    from litellm.integrations.custom_guardrail import CustomGuardrail as _Base
    LITELLM_AVAILABLE = True
except Exception:  # pragma: no cover
    LITELLM_AVAILABLE = False

    class _Base:  # type: ignore[no-redef]
        """Stand-in base used ONLY when litellm is not installed."""

        def __init__(self, **kwargs):
            self.guardrail_name = kwargs.get("guardrail_name")

        def should_run_guardrail(self, data, event_type):  # noqa: D401
            return True


DEFAULT_SESSION_HEADER = "x-reeflex-session"


class ReeflexActionGuardrail(_Base):
    """Rule on every tool call an LLM behind this gateway proposes."""

    def __init__(self, guardrail_name: Optional[str] = None, **kwargs):
        self.reeflex_environment = kwargs.pop("reeflex_environment", None)
        self.reeflex_principal = kwargs.pop("reeflex_principal", None)
        self.reeflex_hold_wait = kwargs.pop("reeflex_hold_wait", None)
        self.reeflex_session_header = kwargs.pop(
            "reeflex_session_header", DEFAULT_SESSION_HEADER)
        kwargs.setdefault("default_on", True)
        super().__init__(guardrail_name=guardrail_name or "reeflex-action-gate",
                         **kwargs)

    # -- the hook ----------------------------------------------------------

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict,
                                           response) -> Any:
        try:
            return await self._rule_on_response(data or {}, response,
                                                user_api_key_dict)
        except Exception as exc:  # fail closed on our own bugs, loudly
            return self._refuse_everything(response, exc)

    async def async_post_call_streaming_iterator_hook(
            self, user_api_key_dict, response, request_data: dict):
        """Rule on the tool calls in a STREAMED response (RFX-242).

        THE CONTRACT, READ OFF litellm 1.100.0 RATHER THAN OFF THE DOCS:

          * `ProxyLogging.async_post_call_streaming_iterator_hook`
            (`proxy/utils.py`) calls this with KEYWORD arguments
            `user_api_key_dict=`, `response=`, `request_data=`, where `response`
            is the upstream async iterator of chunks.  The parameter names are
            therefore part of the contract and are asserted in the suite.
          * It must be an ASYNC GENERATOR.  Its output is what the caller
            receives; `async_streaming_data_generator` serializes each yielded
            chunk to SSE.
          * The chain is only entered at all when
            `"async_post_call_streaming_iterator_hook" in type(cb).__dict__`
            -- a leaf-class check.  Defining it on THIS class is what registers
            it; inheriting it from a base would not.
          * `should_run_guardrail(..., GuardrailEventHooks.post_call)` is
            checked by the proxy before we are called, so `mode: post_call` in
            the config governs this hook as well as the buffered one.  No second
            config key, and no way to end up with one path governed and the
            other not.

        WHAT IS YIELDED, AND WHEN.  Chunks with no tool-call fragment are
        yielded IMMEDIATELY and untouched -- prose does not wait for a
        governance decision.  From the first chunk carrying a `tool_calls`
        delta the stream is buffered to its end (including the empty
        `finish_reason` frame, which would otherwise arrive before the calls it
        finishes), the assembled calls are decided, and only then is the tail
        released.  streaming.py documents the assembly and the rewrite.

        FAIL CLOSED, INCLUDING ON OUR OWN BUGS.  Anything raised by the
        decision or the rewrite refuses every assembled call rather than
        releasing buffered fragments.  A chunk the ACCUMULATOR could not absorb
        is worse than that -- the call it belonged to may not be in the
        assembled list at all, so "refuse the assembled calls" would leave its
        fragments unaccounted for and release them.  That case drops the
        buffered tail entirely and emits a refusal in its place.

        `GeneratorExit` / `CancelledError` (the client hanging up) and an
        exception from the UPSTREAM iterator (the provider failing mid-stream)
        are propagated untouched.  Neither is a governance failure, and in both
        cases the buffered fragments are simply never yielded, which is the
        outcome we want anyway.
        """
        data = request_data or {}
        accumulator = _streaming.ToolCallAccumulator()
        buffered = []
        armed = False
        unabsorbed = None
        # Whether prose has already reached the caller.  Carried into the
        # rewrite because the buffered path puts its refusal notice on a NEW
        # line after any content the assistant already produced, and a stream
        # that streamed that content out before the first tool call has to
        # reproduce the same assembled message.
        released_content = False

        async for chunk in response:
            if not armed and not _streaming.chunk_has_tool_call(chunk):
                released_content = released_content or bool(
                    _streaming.chunk_content(chunk))
                yield chunk
                continue
            armed = True
            buffered.append(chunk)
            try:
                accumulator.feed(chunk)
            except Exception as exc:  # pragma: no cover - defensive
                # Recorded, not swallowed.  Swallowing it would leave a tool
                # call the accumulator never saw, whose index is therefore in
                # no `denied` set -- and `_emit_stream` releases anything it was
                # not told to strip.  That is the fail-open this line exists to
                # prevent, so the whole tail is dropped below instead.
                unabsorbed = unabsorbed or exc

        if not armed:
            return

        if unabsorbed is not None:
            for out in self._refuse_stream_opaque(buffered, unabsorbed):
                yield out
            return

        try:
            chunks, ledger_lines, tenant = await self._rule_on_stream(
                data, user_api_key_dict, buffered, accumulator,
                released_content)
        except Exception as exc:  # fail closed on our own bugs, loudly
            chunks, ledger_lines, tenant = (
                self._refuse_stream_everything(buffered, accumulator, exc,
                                               released_content),
                [], None)

        for out in chunks:
            yield out

        # AFTER the caller has the chunks, for the reason `_rule_on_response`
        # gives: an evidence outage must not delay or change a decision that is
        # already enforced.
        if ledger_lines:
            await self._record_evidence(ledger_lines, tenant,
                                        asyncio.get_running_loop())

    async def _rule_on_stream(self, data: dict, user_api_key_dict,
                              buffered: list, accumulator,
                              released_content: bool = False) -> tuple:
        """Decide every assembled call and rewrite the buffered tail.

        Returns `(chunks_to_yield, ledger_lines, tenant)`.  The decision loop is
        deliberately the same shape as `_rule_on_response`'s -- same
        `rule_one_call`, same order, same executor -- because the property that
        matters is that a request does not get a different answer for having
        been streamed.
        """
        calls = accumulator.assembled()
        if not calls:
            # Fragments arrived that assembled into nothing rulable.  Release
            # the tail: there is no action in it.
            return list(buffered), [], None

        resolution = _tenancy.resolve(user_api_key_dict)
        if not resolution.resolved:
            _log("tenancy: REFUSED every streamed tool call -- unmapped "
                 "gateway caller [%s]" % resolution.identity.describe())
            refusals = [
                _enforce.refuse_unmapped_tenant(
                    _normalize.normalize_tool_call(raw), resolution.reason
                ).refusal
                for _, raw in calls
            ]
            return (self._emit_stream(buffered, {idx for idx, _ in calls},
                                      refusals, released_content),
                    [], None)

        tenant = resolution.tenant
        last = buffered[-1] if buffered else None
        session_id = self.session_id(data)
        model = self.model_name(data, last)
        gateway_routing = _routing.build(
            data=data, response=last, tenant=tenant,
            identity=resolution.identity, model=model)

        loop = asyncio.get_running_loop()
        denied, refusals, ledger_lines = set(), [], []
        for idx, raw in calls:
            call = _normalize.normalize_tool_call(raw)
            outcome = await loop.run_in_executor(
                _core._get_executor(),
                lambda c=call: _enforce.rule_one_call(
                    c, session_id=session_id, model=model,
                    principal=self.reeflex_principal or None,
                    environment=self.reeflex_environment or None,
                    hold_wait=_as_float(self.reeflex_hold_wait),
                    tenant=tenant, gateway_routing=gateway_routing),
            )
            if not outcome.allowed:
                denied.add(idx)
                refusals.append(outcome.refusal)
            if outcome.ledger is not None:
                ledger_lines.append(outcome.ledger)

        return (self._emit_stream(buffered, denied, refusals,
                                  released_content),
                ledger_lines, tenant)

    def _emit_stream(self, buffered: list, denied: set, refusals: list,
                     released_content: bool = False) -> list:
        """The tail of the stream, as the caller should receive it.

        With nothing denied the buffered chunks are returned AS THEY ARE -- the
        same objects, in the same order, so an allowed stream is
        indistinguishable from one that never met this seat.  That identity is
        asserted against a hook-off proxy in the suite, not assumed here.
        """
        if not denied:
            return list(buffered)

        all_denied = denied >= {i for c in buffered
                                for i in _streaming.chunk_tool_indices(c)}
        out, saw_content = [], bool(released_content)
        finish_at = None
        for chunk in buffered:
            rewritten, carries = _streaming.strip_tool_indices(chunk, denied)
            if not carries:
                continue
            if all_denied and _streaming.chunk_finish_reason(rewritten):
                # Every call on this response was refused, so "call these
                # tools" is no longer what the response is doing.  Same rule,
                # and the same reason, as response.apply_refusals().
                rewritten = _streaming.set_finish_reason(rewritten, "stop")
            if _streaming.chunk_finish_reason(rewritten) and finish_at is None:
                finish_at = len(out)
            else:
                saw_content = saw_content or bool(
                    _streaming.chunk_content(rewritten))
            out.append(rewritten)

        template = buffered[-1]
        notice = _streaming.build_refusal_chunk(
            template, _streaming.refusal_notice(refusals, saw_content))
        out.insert(len(out) if finish_at is None else finish_at, notice)
        return out

    def _refuse_stream_opaque(self, buffered: list, exc: Exception) -> list:
        """Drop the buffered tail and say why, when we cannot enumerate it.

        Reached only when a chunk could not be absorbed at all, so the adapter
        does not know how many tool calls it is holding or which fragments
        belong to which.  There is no safe partial answer: releasing anything
        would release a fragment nothing ruled on, and naming per-call refusals
        would name calls that may not be the ones in the buffer.  So the tail
        goes nowhere and one frame carrying a fail-closed refusal goes out in
        its place -- with `finish_reason: "stop"`, so the client is not left
        waiting to be told the response ended.
        """
        _log("streaming: DROPPED the buffered tail -- a chunk could not be "
             "read, so no tool call in it was ruled on: %s: %s"
             % (type(exc).__name__, exc))
        payload = json.dumps({"reeflex": {"version": 1, "refused": [{
            "error": _enforce.ERROR_UNAVAILABLE,
            "rule": _core.FAIL_CLOSED_RULE,
            "stage": "refused_at_gateway",
            "reason": ("Reeflex: a chunk of this streamed response could not "
                       "be read, so no tool call on it was ruled on and the "
                       "whole tail is withheld [rule=%s]: %s"
                       % (_core.FAIL_CLOSED_RULE, type(exc).__name__)),
        }]}}, sort_keys=True)
        try:
            notice = _streaming.build_refusal_chunk(buffered[-1], payload)
            return [notice, _streaming.set_finish_reason(
                _streaming.build_refusal_chunk(buffered[-1], ""), "stop")]
        except Exception:  # pragma: no cover - defensive
            return []

    def _refuse_stream_everything(self, buffered: list, accumulator,
                                  exc: Exception,
                                  released_content: bool = False) -> list:
        """Refuse every assembled call after an unexpected error.

        The mirror of `_refuse_everything` for the streaming path.  If even
        this fails there is nothing safe left to yield, so the buffered tail is
        DROPPED rather than released: on this path "return the response
        anyway" would mean handing over the very fragments that were never
        ruled on.
        """
        reason = ("Reeflex: the gateway's governance hook failed, so no tool "
                  "call on this streamed response was cleared and all are "
                  "refused [rule=%s]: %s: %s"
                  % (_core.FAIL_CLOSED_RULE, type(exc).__name__, exc))
        _log("streaming: REFUSED every tool call -- %s: %s"
             % (type(exc).__name__, exc))
        try:
            calls = accumulator.assembled()
            refusals = [
                _enforce.refusal(_normalize.normalize_tool_call(raw),
                                 _enforce.ERROR_UNAVAILABLE,
                                 _core.FAIL_CLOSED_RULE, reason)
                for _, raw in calls
            ]
            return self._emit_stream(buffered, {idx for idx, _ in calls},
                                     refusals, released_content)
        except Exception:  # pragma: no cover - defensive
            return []

    # -- the work ----------------------------------------------------------

    async def _rule_on_response(self, data: dict, response,
                                user_api_key_dict=None) -> Any:
        if not _response.has_tool_calls(response):
            # Not an action.  Untouched, core is never called and TENANCY IS
            # NOT RESOLVED -- which is why a text answer still flows when core
            # is down AND when the caller's key is not in the tenancy map.  A
            # gateway that refused prose from an unmapped key would be a text
            # guardrail, and this seat is not one.
            return response

        # TENANCY FIRST, BEFORE ANY DECISION.  An unresolved caller is refused
        # here: core is never asked, so no decision lands in the wrong org's
        # evidence and no R5 budget is charged to a session that belongs to
        # nobody.  `resolve()` never raises and never invents a tenant.
        resolution = _tenancy.resolve(user_api_key_dict)
        if not resolution.resolved:
            return self._refuse_unmapped_tenant(response, resolution)

        tenant = resolution.tenant
        session_id = self.session_id(data)
        model = self.model_name(data, response)
        principal = self.reeflex_principal or None
        environment = self.reeflex_environment or None
        hold_wait = _as_float(self.reeflex_hold_wait)
        gateway_routing = _routing.build(
            data=data, response=response, tenant=tenant,
            identity=resolution.identity, model=model)

        loop = asyncio.get_running_loop()
        ledger_lines = []

        for idx, choice in enumerate(_response.get_choices(response)):
            raw_calls = _response.get_tool_calls(choice)
            if not raw_calls:
                continue
            keep, refusals = [], []
            for raw in raw_calls:
                call = _normalize.normalize_tool_call(raw)
                # Off the event loop: rule_one_call does blocking HTTP and may
                # poll a hold for tens of seconds.
                outcome = await loop.run_in_executor(
                    _core._get_executor(),
                    lambda c=call: _enforce.rule_one_call(
                        c, session_id=session_id, model=model,
                        principal=principal, environment=environment,
                        hold_wait=hold_wait, tenant=tenant,
                        gateway_routing=gateway_routing),
                )
                if outcome.allowed:
                    keep.append(raw)
                else:
                    refusals.append(outcome.refusal)
                if outcome.ledger is not None:
                    ledger_lines.append(outcome.ledger)
            if refusals:
                _response.apply_refusals(response, idx, keep, refusals)

        # AFTER the response is final, so the recorded stage is what the caller
        # actually received, and so an evidence outage can never delay or
        # change a decision that has already been enforced.
        await self._record_evidence(ledger_lines, tenant, loop)

        return response

    # -- evidence ----------------------------------------------------------

    async def _record_evidence(self, ledger_lines: list, tenant, loop) -> None:
        """Append the ledger and, when enabled, push the §4 records.

        Both are best-effort and NEITHER can raise: the decision is already
        made and applied by the time this runs, so an evidence failure is a gap
        in the record -- surfaced in the proxy log -- not a reason to change a
        verdict.  Core applies the same rule to its own audit ("audit failure
        != deny").

        The push is per TENANT, signed with that tenant's gate credentials.
        That is where isolation between two departments is actually enforced:
        EVIDENCE-INGEST-SPEC-v1 §3 resolves `(gate_id, org_id)` from the token
        server-side and "a record may not name a different org", so presenting
        the right credential is the whole of it -- there is no org field on the
        wire to get wrong.  See evidence.py.
        """
        if not ledger_lines:
            return
        try:
            for line in ledger_lines:
                _evidence.append_ledger(line)
            if not _evidence.push_enabled():
                return
            wire = []
            for line in ledger_lines:
                try:
                    wire.append(_evidence.wire_record(line))
                except Exception as exc:
                    # One unmappable record must not drop the batch: the others
                    # are valid evidence and §6 makes a resend of a duplicate a
                    # no-op, so partial delivery is safe.
                    _log("evidence: skipped one record for org=%s: %s"
                         % (getattr(tenant, "org", None), exc))
            if not wire:
                return
            result = await loop.run_in_executor(
                _core._get_executor(),
                lambda: _evidence.push(wire, tenant))
            if not result.ok:
                _log("evidence: push FAILED for org=%s (%d records): %s"
                     % (result.org, result.records, result.error))
        except Exception as exc:  # pragma: no cover - defensive
            _log("evidence: recording failed: %s: %s"
                 % (type(exc).__name__, exc))

    # -- tenancy refusal ---------------------------------------------------

    def _refuse_unmapped_tenant(self, response, resolution) -> Any:
        """Refuse every tool call on this response: the caller has no org.

        Logged once per response with the identity that arrived, because this
        is an operator configuration problem and the refusal the model sees may
        never reach the operator.  The log line carries the key HASH PREFIX and
        the aliases, never key material -- see `GatewayIdentity.describe()`.
        """
        _log("tenancy: REFUSED every tool call -- unmapped gateway caller [%s]"
             % resolution.identity.describe())
        for idx, choice in enumerate(_response.get_choices(response)):
            raw_calls = _response.get_tool_calls(choice)
            if not raw_calls:
                continue
            refusals = [
                _enforce.refuse_unmapped_tenant(
                    _normalize.normalize_tool_call(raw), resolution.reason
                ).refusal
                for raw in raw_calls
            ]
            _response.apply_refusals(response, idx, [], refusals)
        return response

    # -- identity ----------------------------------------------------------

    def session_id(self, data: dict) -> str:
        """The session R5's cumulative budget is charged against.

        Precedence:
          1. the request header named by `reeflex_session_header`
             (default `x-reeflex-session`) -- the explicit, operator-controlled
             answer, and the one to use today;
          2. OpenAI's `user` field on the request body;
          3. the per-request `litellm_call_id`.

        KNOWN LIMIT, unchanged by RFX-243: when neither a session header nor
        `user` is supplied, the fallback is PER REQUEST, so R5's cumulative
        session budget cannot accumulate across a conversation.  The budget is
        not wrong -- it is scoped to one request.  Anything that needs a real
        cumulative budget must supply 1 or 2.

        WHAT TENANCY DID CHANGE is the NAMESPACE, not this value: whatever this
        returns is prefixed with the tenant's org in `envelope.py`
        (`litellm:<org>:<session>`), so two departments that both send
        `x-reeflex-session: nightly` no longer share one budget.  The virtual
        key is deliberately NOT used as a session id -- a key is a long-lived
        credential and a session is a conversation, and conflating them would
        give a whole department one cumulative budget for all time.
        """
        header_name = (self.reeflex_session_header or DEFAULT_SESSION_HEADER).lower()
        psr = data.get("proxy_server_request") or {}
        headers = psr.get("headers") if isinstance(psr, dict) else None
        if isinstance(headers, dict):
            for k, v in headers.items():
                if isinstance(k, str) and k.lower() == header_name:
                    if isinstance(v, str) and v.strip():
                        return v.strip()
        user = data.get("user")
        if isinstance(user, str) and user.strip():
            return user.strip()
        call_id = data.get("litellm_call_id")
        if isinstance(call_id, str) and call_id.strip():
            return call_id.strip()
        return "litellm-" + uuid.uuid4().hex

    def model_name(self, data: dict, response) -> str:
        for candidate in (data.get("model"),
                          getattr(response, "model", None)
                          if not isinstance(response, dict)
                          else response.get("model")):
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return "unknown"

    # -- last-resort failure ----------------------------------------------

    def _refuse_everything(self, response, exc: Exception):
        """Refuse every tool call on the response after an unexpected error.

        Reached only if this module raises where enforce.py did not already
        handle it.  The response still returns -- with no executable tool call
        on it and a reason the model can read.
        """
        reason = ("Reeflex: the gateway's governance hook failed, so no tool "
                  "call on this response was cleared and all are refused "
                  "[rule=%s]: %s: %s"
                  % (_core.FAIL_CLOSED_RULE, type(exc).__name__, exc))
        try:
            for idx, choice in enumerate(_response.get_choices(response)):
                raw_calls = _response.get_tool_calls(choice)
                if not raw_calls:
                    continue
                refusals = []
                for raw in raw_calls:
                    call = _normalize.normalize_tool_call(raw)
                    refusals.append(_enforce.refusal(
                        call, _enforce.ERROR_UNAVAILABLE,
                        _core.FAIL_CLOSED_RULE, reason))
                _response.apply_refusals(response, idx, [], refusals)
        except Exception:
            # Even the refusal path failed.  Raise, so the caller gets an error
            # rather than a response whose tool calls were never ruled on.
            raise
        return response


def _as_float(v) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
