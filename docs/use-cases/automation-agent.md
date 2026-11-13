---
title: "Use case: an automation agent in n8n"
description: >-
  An AI agent inside an n8n workflow calling business systems. How the Reeflex
  Gate node routes a step on the verdict, what the base pack decides, and why
  an unconfigured node is refused.
---

# An automation agent in n8n

## The situation

An operations team builds n8n workflows in which an AI Agent node decides the
next step — refund an order, update the CRM, post to a channel. A **Reeflex
Gate** node sits before each consequential step and routes the item to one of
three outputs: *Allowed*, *Held for Approval*, *Denied*.

## What goes wrong without a gate

Workflows run unattended and in loops. A trigger that fires twice, a retry
that re-runs a payment branch, an agent that decides every row in a sheet
needs a refund — each produces many correct-looking executions of the same
node, and nobody is watching the canvas at 03:00.

## Three representative actions

The n8n node does not classify anything: **you declare** the verb, axes and
environment on the node, and it sends them as written. The envelopes below are
the shape the node assembles (`ReeflexGate.node.ts`), trimmed of transport
fields; the session id defaults to the workflow id.

**A lookup, declared as a read.** Allowed under R1.

**Verdict:** `allow` · **rule** `reeflex.policy/read_only_internal`

```json
{
  "agent":     { "id": "agent:n8n/58213", "session_id": "wf-refunds" },
  "action":    { "namespace": "shop", "verb": "read", "ability": "shop/get-order" },
  "target":    { "kind": "shop", "ref": null, "environment": "production" },
  "params":    { },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

**The second €2,600 refund in one workflow session.** With Amount and Currency
set on the node, the money budget can price it: €5,200 against a EUR 5,000
default is held, and the item leaves on *Held for Approval*.

**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget` · **call** 2 · **reason contains** `money` — the first refund is this same envelope, and it is allowed.

```json
{
  "agent":     { "id": "agent:n8n/58213", "session_id": "wf-refunds-0612" },
  "action":    { "namespace": "shop", "verb": "transact", "ability": "shop/refund-order" },
  "target":    { "kind": "shop", "ref": "order:A-1009", "environment": "production" },
  "params":    { "amount": 2600, "currency": "EUR" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "outbound" },
  "approval":  { "present": false }
}
```

**A node left at its defaults.** The node's defaults are its most restrictive
values — irreversible, systemic, outbound, production — so a Gate node nobody
configured describes an action R3 refuses. The item leaves on *Denied*. That is
deliberate: an unconfigured gate fails toward safety, and the fix is to
declare what the step does.

**Verdict:** `deny` · **rule** `reeflex.policy/irreversible_systemic_prod`

```json
{
  "agent":     { "id": "agent:n8n/58213", "session_id": "wf-refunds" },
  "action":    { "namespace": "crm", "verb": "read", "ability": "crm/sync-contacts" },
  "target":    { "kind": null, "ref": null, "environment": "production" },
  "params":    { },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "systemic", "externality": "outbound" },
  "approval":  { "present": false }
}
```

## How to deploy it

Install the community node `n8n-nodes-reeflex` (Settings → Community Nodes)
and create a **Reeflex API** credential with your core's **Core URL** and
token. Wire the three outputs. The line that matters is on each node:
**Reversibility / Blast Radius / Externality** — they are your declaration of
what the step does, and the verdict is only as right as they are. A `transact`
step must also carry Amount and Currency; the node refuses one without them
before core is asked. Full guide: [n8n](../guides/n8n.md).

## What Reeflex does NOT do here

- It does not look at the step after the gate. The node decides on what you
  declared; if the next node does something else, Reeflex does not know.
- It does not classify. Two Gate nodes with the same declarations get the
  same verdict whatever the steps after them do.
- It does not gate a branch that does not pass through a Gate node. A
  workflow edited to route around the node runs ungated.
- Its session is the workflow by default. Separate workflows are separate
  budgets; a refund loop split across two workflows is two half-budgets.
