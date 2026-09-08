"""
envelope.py -- the gateway's Action Envelope (SPEC §2).

Built by CALLING `reeflex_claude.envelope.build_envelope()` and then overlaying
the gateway's own identity on top of it.  Nothing about the axes, the magnitude,
the danger signature, the nonce or the signature stub is recomputed here.

WHY AN OVERLAY AND NOT A SECOND BUILDER
=======================================
`build_envelope()` is identity-BOUND, not identity-neutral: it hardcodes
`action.namespace = "claude-code"`, `action.ability = "claude-code/<tool>"` and
`agent.id = "agent:claude-code"`, and it reads REEFLEX_CLAUDE_PRINCIPAL /
REEFLEX_CLAUDE_ENVIRONMENT from the process environment.  A gateway is a
different seat with a different actor, so those five fields have to change.

The alternative -- setting REEFLEX_CLAUDE_* in `os.environ` around each call to
steer the builder -- was rejected: `os.environ` is process-global and this hook
runs on a proxy serving concurrent requests, so two requests with different
principals would read each other's values.  That is a data-correctness bug that
only appears under load, which is exactly the class this seat must not have.
The overlay is thread-safe because it touches only the dict it was just handed.

WHAT THE OVERLAY CHANGES, AND WHY EACH ONE
==========================================
  agent.id           `agent:litellm-gateway/<model>`
                     RFX-138: an approval is granted to a PARTY, and core's
                     hold check 8 compares the requester's agent block against
                     the one the human approved.  Every agent behind one gateway
                     shipping the same `agent.id` is that ticket's defect
                     exactly, so the MODEL -- the one thing that differs per
                     request behind a shared proxy today -- is in the id.
                     A gateway virtual key / team would be the better
                     discriminator; that is tenancy and it is the next ticket
                     (out of scope for this spike, and SAID SO in the README).

  agent.session_id   `litellm:<session>`
                     Namespaced so a gateway session can never collide with a
                     `claude:` one in core's session ledger -- R5's cumulative
                     budget is keyed on this, so a collision would make two
                     unrelated callers spend one budget.

  agent.on_behalf_of REEFLEX_LITELLM_PRINCIPAL (default None).
                     Read HERE rather than via REEFLEX_CLAUDE_PRINCIPAL so a box
                     running both adapters does not have one seat's principal
                     leak into the other's envelopes.

  action.namespace   `litellm-gateway`
  action.ability     `litellm/<gateway tool name>`
                     The gateway's OWN tool name, not the classifier tool it was
                     mapped to.  Two measured reasons, both in normalize.py's
                     docstring: core's verb canon reads the ability's first
                     token (so `litellm/delete_file` becomes verb=delete inside
                     core), and core's audit line carries `action.ability` -- so
                     this is the string a human reads in the record.  Writing
                     `litellm/Bash` there instead would tell that human the model
                     asked for a tool it never named.

  target.environment REEFLEX_LITELLM_ENVIRONMENT, defaulting to `production`
                     (conservative, same default as every other seat).  This is
                     a decision input for R2/R3.

  context.*          the gateway facts a human needs to read the record:
                     model, gateway tool name, tool_call id, and whether this
                     adapter could map the call at all.  Recorded, never a
                     decision input.

WHAT IS NOT OVERLAID
====================
`axes`, `magnitude`, `params.verb_source`, `context.danger_signature`,
`context.classification_tier`, `meta.nonce` and `meta.signature` are left
exactly as `reeflex_claude` produced them.  If the pricing of an action is
wrong, it is wrong in one place for every seat, and it is fixed there.

`provenance` is NOT set here and must not be: core computes it unconditionally
from the raw request and discards a caller-supplied block (RFX-132/143).

Env:
  REEFLEX_LITELLM_PRINCIPAL    on_behalf_of (default: None)
  REEFLEX_LITELLM_ENVIRONMENT  production | staging | dev (default: production)
"""

from __future__ import annotations

import copy
import hashlib
import os
import time
from typing import Any, Optional

from reeflex_claude import classify as _claude_classify
from reeflex_claude import envelope as _claude_envelope

NAMESPACE = "litellm-gateway"
AGENT_PREFIX = "agent:litellm-gateway"
SESSION_PREFIX = "litellm"


def build_gateway_envelope(
    *,
    session_id: str,
    model: str,
    call,
    principal: Optional[str] = None,
    environment: Optional[str] = None,
) -> dict:
    """Build one Action Envelope for one normalized gateway tool call.

    `call` is a `normalize.NormalizedCall`.

    Raises ValueError when session_id is empty -- inherited from
    `build_envelope()` and deliberately not softened: an envelope with no
    session cannot be charged to a cumulative budget, so accepting one would
    make R5 unenforceable for that request.
    """
    cls = _claude_classify.classify(call.tool_name, call.tool_input)

    env = _claude_envelope.build_envelope(
        {
            "session_id": session_id,
            "tool_name": call.tool_name,
            "tool_input": call.tool_input,
        },
        cls,
    )

    model = model or "unknown"

    env["agent"]["id"] = "%s/%s" % (AGENT_PREFIX, model)
    env["agent"]["session_id"] = "%s:%s" % (SESSION_PREFIX, session_id)
    env["agent"]["on_behalf_of"] = (
        principal
        if principal is not None
        else (os.environ.get("REEFLEX_LITELLM_PRINCIPAL") or None)
    )

    env["action"]["namespace"] = NAMESPACE
    env["action"]["ability"] = "litellm/%s" % call.gateway_tool

    env["target"]["environment"] = _environment(environment)

    env["params"]["gateway"] = "litellm"
    env["params"]["gateway_tool"] = call.gateway_tool

    env["context"]["gateway"] = "litellm"
    env["context"]["gateway_model"] = model
    env["context"]["gateway_tool_name"] = call.gateway_tool
    env["context"]["gateway_tool_call_id"] = call.call_id
    env["context"]["classifier_tool_name"] = call.tool_name
    env["context"]["normalization"] = call.mapping_source
    env["context"]["arguments_parsed"] = bool(call.arguments_ok)

    return env


def with_approval(envelope: dict, hold_id: str, approver: Optional[str] = None) -> dict:
    """A copy of `envelope` carrying an approval, ready to RESUBMIT.

    Two things must both be true for core to accept a resubmission, and they
    pull in opposite directions.  Both were measured against
    ghcr.io/reeflex-io/reeflex-core:v0.2.0 on 2026-09-08:

      * The envelope must be the SAME one the human approved.  Hold check 5
        compares `canonical_hash()` over {action, axes, magnitude, target},
        check 7 compares the decision inputs in `params` that the hash omits,
        and check 8 (RFX-138) compares the whole `agent` block.  So this cannot
        be a REBUILT envelope -- a rebuild would carry a new timestamp, and any
        drift in the mapping between the two builds would read as an altered
        action.  Hence the deepcopy of the original.

      * The nonce must be DIFFERENT.  `envelope._check_nonce()` in core is a
        hard 400 `{"error":"invalid_envelope","detail":"replay: nonce already
        seen"}` on a repeat, and the raise that created the hold already spent
        the original nonce.  Confirmed: resubmitting with the original nonce
        returns 400 and the approval cannot be spent at all.

    `canonical_hash()`'s projection excludes `meta`, which is why these two
    facts are compatible: a fresh nonce does not move the hash the hold is
    bound to.
    """
    out = copy.deepcopy(envelope)
    out["approval"] = {
        "present": True,
        "hold_id": hold_id,
        "by": approver,
        "role": "human" if approver else None,
    }
    prev = ((out.get("meta") or {}).get("nonce") or "")
    out.setdefault("meta", {})["nonce"] = hashlib.sha256(
        ("%s:%s:%s" % (prev, hold_id, time.monotonic_ns())).encode("utf-8")
    ).hexdigest()[:32]
    return out


def _environment(explicit: Optional[str]) -> str:
    raw = explicit if explicit is not None else os.environ.get(
        "REEFLEX_LITELLM_ENVIRONMENT", "production")
    v = (raw or "").strip().lower()
    return v if v in ("production", "staging", "dev") else "production"
