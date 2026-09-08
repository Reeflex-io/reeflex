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
For each choice, for each tool call, in order: normalize -> classify (the ONE
classifier) -> envelope -> POST /v1/decide -> enforce.  Allowed calls are left
untouched; refused calls are removed and replaced by a structured refusal
carrying `stage: "refused_at_gateway"`.  A response with no tool calls is
returned unchanged and never even reaches core.

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

STREAMING IS NOT COVERED BY THIS HOOK.  `mode: post_call` fires for a buffered
response.  A streaming request (`stream: true`) is delivered through
`async_post_call_streaming_iterator_hook`, which this class does not implement,
so a streamed tool call is NOT ruled on.  That is measured, not assumed -- the
measurement and the ticket are in the README.  Until it is closed, a deployment
that must not have an ungoverned path should refuse `stream: true` at the
gateway.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Optional

from . import core as _core
from . import enforce as _enforce
from . import normalize as _normalize
from . import response as _response

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
            return await self._rule_on_response(data or {}, response)
        except Exception as exc:  # fail closed on our own bugs, loudly
            return self._refuse_everything(response, exc)

    # -- the work ----------------------------------------------------------

    async def _rule_on_response(self, data: dict, response) -> Any:
        if not _response.has_tool_calls(response):
            # Not an action.  Untouched, and core is never called -- which is
            # why a text answer still flows when core is down.
            return response

        session_id = self.session_id(data)
        model = self.model_name(data, response)
        principal = self.reeflex_principal or None
        environment = self.reeflex_environment or None
        hold_wait = _as_float(self.reeflex_hold_wait)

        loop = asyncio.get_running_loop()

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
                        hold_wait=hold_wait),
                )
                if outcome.allowed:
                    keep.append(raw)
                else:
                    refusals.append(outcome.refusal)
            if refusals:
                _response.apply_refusals(response, idx, keep, refusals)

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

        KNOWN LIMIT, and the reason tenancy is the next ticket: when neither a
        session header nor `user` is supplied, the fallback is PER REQUEST, so
        R5's cumulative session budget cannot accumulate across a conversation.
        The budget is not wrong -- it is scoped to one request. Anything that
        needs a real cumulative budget must supply 1 or 2.  Mapping a gateway
        virtual key or team to a Reeflex session/org is out of scope for this
        spike and is named in the README.
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
