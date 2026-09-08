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
  agent.id           `agent:litellm-gateway/<tenant-org>/<model>`
                     RFX-138: an approval is granted to a PARTY, and core's
                     hold check 8 compares the requester's agent block against
                     the one the human approved.  Every agent behind one gateway
                     shipping the same `agent.id` is that ticket's defect
                     exactly.  0.1.0 discriminated on the MODEL alone, which
                     left two departments on one model sharing an identity;
                     RFX-243 puts the TENANT ORG in front of it, resolved from
                     the virtual key / team by `tenancy.py`.  The org segment is
                     `unscoped` only on the library API with no tenant -- the
                     hook always resolves one or refuses.
                     This is also the ONLY adapter-controlled field that reaches
                     an Attest report: core's audit line carries `agent_id` from
                     here and the evidence connector puts it on the §4 wire.

  agent.session_id   `litellm:<tenant-org>:<session>`
                     Namespaced so a gateway session can never collide with a
                     `claude:` one in core's session ledger -- R5's cumulative
                     budget is keyed on this, so a collision would make two
                     unrelated callers spend one budget.  The tenant segment
                     makes that true BETWEEN departments too: without it, two
                     teams that both call their session `nightly` share one
                     budget, and the first team's bulk job denies the second's.

  agent.on_behalf_of the tenant's `principal`, else REEFLEX_LITELLM_PRINCIPAL
                     (default None).  Read from the tenant first because one
                     proxy-wide principal would name the wrong person on a
                     department's action.  Read HERE rather than via
                     REEFLEX_CLAUDE_PRINCIPAL so a box running both adapters
                     does not have one seat's principal leak into the other's
                     envelopes.

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

  target.environment the tenant's `environment`, else
                     REEFLEX_LITELLM_ENVIRONMENT, defaulting to `production`
                     (conservative, same default as every other seat).  This is
                     a decision input for R2/R3, which is why the tenant's value
                     wins: a department running a staging gateway behind a proxy
                     configured `production` would otherwise be priced against
                     the wrong branch.

  context.*          the gateway facts a human needs to read the record:
                     model, gateway tool name, tool_call id, whether this
                     adapter could map the call at all, the resolved tenancy,
                     and `gateway_routing` (which model answered, where it ran,
                     whose key asked -- see routing.py).  Recorded, never a
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

from . import tenancy as _tenancy

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
    tenant=None,
    gateway_routing: Optional[dict] = None,
) -> dict:
    """Build one Action Envelope for one normalized gateway tool call.

    `call` is a `normalize.NormalizedCall`.
    `tenant` is a `tenancy.Tenant` -- `tenancy.UNSCOPED` when a caller of the
    library API supplied none.  `guardrail.py` NEVER passes an unscoped tenant:
    a request that reaches the hook is resolved to an org or refused.

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
    scope = _tenancy.session_scope(tenant)

    # THE TENANT IS IN THE ACTOR IDENTITY, NOT ONLY IN A LABEL.  Core's hold
    # check 8 (RFX-138) compares `agent.id` between the envelope a human
    # approved and the envelope resubmitted against that approval, so putting
    # the org here is what makes one department's approval unspendable by
    # another's agent behind the same proxy.  A `context` field would be a
    # record of the tenant; this is an enforcement of it.
    env["agent"]["id"] = "%s/%s/%s" % (AGENT_PREFIX, scope, model)
    # R5's cumulative budget keys on session_id, so the scope is in it too:
    # two departments that both name their session `nightly` must not share one
    # budget, and without the scope they would.
    env["agent"]["session_id"] = "%s:%s:%s" % (SESSION_PREFIX, scope, session_id)
    env["agent"]["on_behalf_of"] = _principal(tenant, principal)

    env["action"]["namespace"] = NAMESPACE
    env["action"]["ability"] = "litellm/%s" % call.gateway_tool

    env["target"]["environment"] = _environment_for(tenant, environment)

    env["params"]["gateway"] = "litellm"
    env["params"]["gateway_tool"] = call.gateway_tool

    env["context"]["gateway"] = "litellm"
    env["context"]["gateway_model"] = model
    env["context"]["gateway_tool_name"] = call.gateway_tool
    env["context"]["gateway_tool_call_id"] = call.call_id
    env["context"]["classifier_tool_name"] = call.tool_name
    env["context"]["normalization"] = call.mapping_source
    env["context"]["arguments_parsed"] = bool(call.arguments_ok)
    env["context"]["tenancy"] = {
        "org": getattr(tenant, "org", None),
        "scope": scope,
        "matched_on": getattr(tenant, "matched_on", None),
    }
    if gateway_routing is not None:
        # Recorded, never a decision input -- no core rule reads `context`.
        # It is on the envelope (rather than only in the adapter's ledger) so
        # that the routing facts are inside the artefact `meta.signature` will
        # cover once envelope signing lands (SPEC §6), and so a core that later
        # learns to record them has them already.  It does NOT move
        # `envelope_hash`: core's projection is {action, axes, magnitude,
        # target}, so adding context cannot invalidate a hold binding.
        env["context"]["gateway_routing"] = gateway_routing

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


def _principal(tenant, explicit: Optional[str]) -> Optional[str]:
    """`agent.on_behalf_of`, most specific source first.

    A tenant's principal wins over the proxy-wide one: the proxy-wide value is
    one setting for every department, and taking it in preference would name
    the wrong person on a department's action.
    """
    tenant_principal = getattr(tenant, "principal", None)
    if tenant_principal:
        return tenant_principal
    if explicit is not None:
        return explicit
    return os.environ.get("REEFLEX_LITELLM_PRINCIPAL") or None


def _environment_for(tenant, explicit: Optional[str]) -> str:
    """`target.environment`, most specific source first.

    Same precedence as the principal, and it matters more: `environment` is a
    DECISION input for R2/R3, so one department running a staging gateway
    behind a proxy configured `production` would otherwise be priced against
    the wrong branch.  `tenancy.parse_map()` has already validated the tenant's
    value against the allowed enum, so it is not re-defaulted here.
    """
    tenant_env = getattr(tenant, "environment", None)
    if tenant_env:
        return tenant_env
    return _environment(explicit)


def _environment(explicit: Optional[str]) -> str:
    raw = explicit if explicit is not None else os.environ.get(
        "REEFLEX_LITELLM_ENVIRONMENT", "production")
    v = (raw or "").strip().lower()
    return v if v in ("production", "staging", "dev") else "production"
