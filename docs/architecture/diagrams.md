---
title: Architecture diagrams
description: >-
  How Reeflex fits together: the decision round-trip, the hold lifecycle,
  self-hosted deployment, and source-side vs resource-side adapter placement.
---

# Architecture diagrams

The single-path system overview (agent -> adapter -> core -> decision) is on
the [Concepts](../concepts/index.md) page. This page goes one level deeper: the
`/v1/decide` round-trip, the hold lifecycle, where things run, and the honest
trade-off between the two ways to place an adapter. For the prose architecture
(seams, guarantees, traceability), see the
[architecture reference](../architecture.md).

## The decision round-trip

```mermaid
sequenceDiagram
    autonumber
    participant Ag as AI agent
    participant Ad as Adapter
    participant Co as reeflex-core
    participant Op as OPA/Rego
    Ag->>Ad: attempt a backend action
    Ad->>Ad: normalize to Action Envelope
    Ad->>Co: POST /v1/decide (envelope)
    Co->>Co: inject cumulative session ledger
    Co->>Op: evaluate policy (pure, no LLM)
    Op-->>Co: allow / deny / require_approval
    Co->>Co: append audit record
    Co-->>Ad: Decision (+ decision_id)
    Ad->>Ad: enforce - run, block, or hold
    Ad-->>Ag: result, or a reason it can read
```

*The `/v1/decide` round-trip. The adapter never touches the backend until the
verdict is in; `reeflex-core` decides deterministically over the per-session
ledger and records an audit entry either way. On `require_approval` the adapter
stores a hold instead of executing (next diagram). Same envelope in, same
decision out.*

## Hold lifecycle

```mermaid
stateDiagram-v2
    [*] --> pending: require_approval creates a hold
    pending --> approved: an approver you trust resolves it
    pending --> rejected: approver rejects
    pending --> expired: TTL elapses
    approved --> consumed: adapter re-submits, envelope-hash matches
    rejected --> [*]
    expired --> [*]
    consumed --> [*]
```

*A hold is single-use and time-bound. Core enforces `actor != approver` (the
agent that raised the hold can never resolve it), the TTL (`expires_ts`), and
envelope-hash binding (the approved action is the exact one submitted). Resolve
holds from wp-admin, the [`reeflex-holds` MCP server](../operations/index.md),
or the resolution API. See
[HIL / HOTL / AIL](../why-reeflex.md#ail) for who may resolve what.*

## Deployment: self-hosted, adapters call core

```mermaid
flowchart TB
    subgraph net["Your network / infrastructure"]
        core["reeflex-core (stateless container)"]
        subgraph src["Source-side adapters"]
            cc["Claude Code hook"]
            n8["n8n gate node"]
        end
        subgraph res["Resource-side adapters"]
            wp["WordPress gate"]
            gw["MCP gateway proxy"]
        end
    end
    cc -- "POST /v1/decide" --> core
    n8 -- "POST /v1/decide" --> core
    wp -- "POST /v1/decide" --> core
    gw -- "POST /v1/decide" --> core
```

*The only production-supported topology is on-prem: everything runs inside your
own network and no decision data leaves it. `reeflex-core` is a stateless
container; every adapter reaches it over one HTTP call. (An opt-in public eval
endpoint exists for trying it - see [Getting started](../getting-started/index.md).)*

## Adapter placement: source-side vs resource-side

```mermaid
flowchart LR
    subgraph SRC["Source-side (adapter in the agent)"]
        AG["one agent"] --> AD1["adapter"]
    end
    AD1 --> B1["Postgres"]
    AD1 --> B2["S3"]
    AD1 --> B3["files"]
    subgraph RES["Resource-side (adapter in the backend)"]
        AD2["adapter"] --> DB["one backend"]
    end
    C1["any caller"] --> AD2
    C2["another agent"] --> AD2
```

*The honest trade-off. A **source-side** adapter (Claude Code, n8n) governs one
agent wherever it acts - across every backend it touches - but only that agent;
another agent hitting the same backend is ungoverned. A **resource-side**
adapter (WordPress, MCP gateway) governs every caller of one backend, but only
that backend. Neither is strictly better; place adapters at the seam that
matches your threat model, and combine them for defense in depth.*
