---
title: "Use case: an LLM-gateway fleet behind LiteLLM"
description: >-
  Many agents, many teams, one LiteLLM proxy. How the reeflex-litellm guardrail
  decides the tool calls a model proposes through the proxy, per tenant, before
  the response reaches the client.
---

# An LLM-gateway fleet behind LiteLLM

## The situation

A platform team runs a LiteLLM proxy that every internal agent uses to reach
its models. The agents are not theirs — each product team writes its own —
but every model response passes through the proxy. The **reeflex-litellm**
guardrail runs there, after the model answers and before the response goes
back, and builds one Action Envelope per tool call the model proposed.

## What goes wrong without a gate

The platform team can see that a team's agent asked the model to call
`run_shell` with `kubectl delete namespace payments`, and has no place to stop
it: the tool runs in the team's own process, after the response leaves the
proxy. Multiply by every team and every agent framework, and the one place
that sees all the proposed actions is the place that cannot refuse any of them.

## Three representative actions

The guardrail reuses reeflex-claude's classifier: a gateway tool it can match
by name and argument shape (a shell, a file tool) is priced as that tool; one
it cannot match takes the classifier's unknown-tool path. Each envelope is
what `reeflex_litellm.envelope.build_gateway_envelope` emits for tenant
`org-acme-demo`, trimmed of transport fields.

**`bash` with `ls -la /srv/app`.** Matched as a shell, priced as a read.
Allowed.

**Verdict:** `allow` · **rule** `reeflex.policy/read_only_internal`

```json
{
  "agent":     { "id": "agent:litellm-gateway/org-acme-demo/gpt-x",
                 "session_id": "litellm:org-acme-demo:sess-1" },
  "action":    { "namespace": "litellm-gateway", "verb": "read", "ability": "litellm/bash" },
  "target":    { "kind": "command", "ref": null, "environment": "production" },
  "params":    { "tool_name": "Bash", "verb_source": "bash_intent_parse:ls -la /srv/app",
                 "gateway": "litellm", "gateway_tool": "bash" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

**`run_shell` with `kubectl delete namespace payments`.** Matched as a shell;
the classifier recognises a namespace delete and prices it irreversible/broad.
Held. The response is withheld for up to `reeflex_hold_wait` seconds while the
hold is polled. If a person approves it in that window, the response is
released, and only if core then allows the resubmitted envelope. If nobody
decides in time, the call is refused, and the refusal names the open hold so
the caller can retry.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:litellm-gateway/org-acme-demo/gpt-x",
                 "session_id": "litellm:org-acme-demo:sess-1" },
  "action":    { "namespace": "litellm-gateway", "verb": "delete", "ability": "litellm/run_shell" },
  "target":    { "kind": "resource", "ref": "payments", "environment": "production" },
  "params":    { "tool_name": "Bash", "verb_source": "bash_intent_parse:kubectl delete namespace payments",
                 "gateway": "litellm", "gateway_tool": "run_shell" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

**`lookup_order` — a tool the gateway cannot match.** The unknown-tool floor
is execute / irreversible / broad / outbound, so in production even a harmless
lookup is held. That is a wrong hold, not a wrong allow, and it is fixed by
telling the guardrail what the tool is (`REEFLEX_LITELLM_TOOL_MAP`), not by
loosening the floor.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:litellm-gateway/org-acme-demo/gpt-x",
                 "session_id": "litellm:org-acme-demo:sess-1" },
  "action":    { "namespace": "litellm-gateway", "verb": "execute", "ability": "litellm/lookup_order" },
  "target":    { "kind": "resource", "ref": null, "environment": "production" },
  "params":    { "tool_name": "lookup_order", "verb_source": "tool_name_map:lookup_order",
                 "gateway": "litellm", "gateway_tool": "lookup_order" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "outbound" },
  "approval":  { "present": false }
}
```

## How to deploy it

```bash
pip install 'reeflex-litellm[proxy]'
export REEFLEX_CORE_URL=http://your-core:8080
export REEFLEX_LITELLM_TENANCY_MAP_FILE=/etc/reeflex/tenancy.json
```

and in the proxy's `config.yaml`, the guardrail with
`guardrail: reeflex_litellm.guardrail.ReeflexActionGuardrail`, `mode: post_call`,
`default_on: true`. The line that matters is the **tenancy map**: it binds each
virtual key or team to a Reeflex org, there is no default org, and a key the
map does not name is refused without core being asked. Full guide:
[LiteLLM in Docker](../guides/litellm-docker.md).

## What Reeflex does NOT do here

- It gates the **proposal**, not the execution. The tool runs in the client;
  if the client runs a tool the model never proposed through the proxy, or a
  client keeps a tool call it was told was refused, Reeflex does not see it.
- It does not see agents that reach a model without the proxy.
- It does not authenticate the session half of the session id. The org is
  bound to the key by the tenancy map; the session within an org is what the
  caller sends (`x-reeflex-session`, then the request's `user`, then the
  call id), so a caller that rotates it rotates its budgets.
- It does not judge the model's text. A response with no tool call is not an
  action and passes untouched.
