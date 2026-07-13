---
title: Action Envelope
description: >-
  The universal, backend-agnostic shape every adapter produces and reeflex-core
  decides on — verb, three risk axes, magnitude, session, and approval.
---

# Action Envelope

The Action Envelope is the portable contract between any adapter and the
engine. An adapter's whole job is to normalize a backend action into this
shape; `reeflex-core` reasons only about the envelope and knows nothing about
WordPress, Postgres, or S3. The canonical, versioned definition lives in
[`reeflex-spec/SPEC.md` §2](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md),
with machine-readable JSON schemas alongside it — this page is the reader's
tour.

## Shape

```json
{
  "agent":     { "id": "agent:demo", "session_id": "sess_01H…" },
  "action":    { "namespace": "store", "verb": "delete", "ability": "store/bulk-delete-products" },
  "target":    { "environment": "production" },
  "magnitude": { "count": 200 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

## Fields

| Field | Meaning |
|---|---|
| `agent.id` | Who is acting. |
| `agent.session_id` | Ties actions into one trajectory. R5 tracks cumulative deletes per session, so splitting a big action into many small ones (fragmentation) buys nothing. |
| `action.namespace` | The backend domain (e.g. `store`, `infra`). |
| `action.verb` | The **normalized** verb — `read`, `create`, `update`, `delete`, … — not the backend's raw method name. Normalization is the adapter's responsibility (SPEC §3). |
| `action.ability` | The specific backend capability being invoked. |
| `target.environment` | `production`, `staging`, or `dev`. Some rules only arm in `production`. |
| `magnitude.count` | How many items the action touches. |
| `axes` | The three risk axes (below) — the heart of the model. |
| `approval` | `{ "present": false }` on a first attempt; on a resubmission after a hold is approved, carries the approval so core can bind it to the exact envelope. |

## The three risk axes

Reeflex prices an action on impact, not on identity. Every action is scored on
three axes:

| Axis | Values | Question |
|---|---|---|
| `reversibility` | `reversible` · `recoverable` · `irreversible` | Can this be undone? |
| `blast_radius` | `single` · `scoped` · `broad` · `systemic` | How much does it touch? |
| `externality` | `internal` · `outbound` · `physical` | Does its effect leave the system? |

The base policy packs (open, Apache-2.0) reason over these axes plus cumulative
session state. For example, `irreversible` + `broad` + `production` →
`require_approval`; `irreversible` + `systemic` + `production` → `deny`
(refused even with approval). See the [policy guide](../policy-guide.md) and
[what the base policy does *not* catch](../concepts/index.md).

## The Decision

`/v1/decide` returns one of three decisions with total precedence
(`deny > require_approval > allow`):

- <span class="rf-verdict rf-allow">allow</span> — the action proceeds.
- <span class="rf-verdict rf-hold">require_approval</span> — a hold; it waits for an approver you trust (a human, or an agent you trust — HIL / AIL).
- <span class="rf-verdict rf-deny">deny</span> — blocked, with a reason the agent can read.

The engine **fails closed**: if OPA is unreachable or a policy is ambiguous, the
answer is `deny`, never `allow`. The full decision shape — including
`decision_id`, `obligations`, and (for holds) `hold_id` / `expires_ts` — is in
the [REST API reference](rest-api.md#response-fields).
