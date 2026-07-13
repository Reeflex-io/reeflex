---
title: REST API
description: >-
  The reeflex-core HTTP API — POST /v1/decide, the holds API, health, auth, and
  errors. Every request and response on this page was captured live against the
  public evaluation endpoint.
---

# REST API

`reeflex-core` exposes one small, stable HTTP surface. An adapter's entire
dependency on Reeflex is a single `POST /v1/decide` call; the holds API is for
resolving actions that come back `require_approval`.

!!! note "Captured live"
    Every request/response below was captured on **2026-07-13** against
    `https://api-dev.reeflex.io`, running **reeflex-core v0.1.12**. The
    `/v1/decide` contract is unchanged across the v0.1.11–v0.1.12 line (v0.1.12
    added only the kill-switch SIEM emit and the `reeflex-mcp` 0.1.1 adapter —
    neither touches the decision path). `decision_id` / `hold_id` values are
    per-request and will differ in your responses.

## Base URL & the evaluation endpoint

```
POST https://<your-core-host>/v1/decide
```

For trying Reeflex without installing anything, a shared public evaluation
endpoint is available at `https://api-dev.reeflex.io`. It has a
publicly-trusted certificate (keep TLS verification **on** — no `-k` needed),
is rate-limited, and is for **dev/eval only, not production**. Run your own
`reeflex-core` for anything real (see [Configuration](configuration.md) and
[ADR-0001](../adr/0001-deployment-model.md)).

## Authentication

When the server is started with `REEFLEX_AUTH_TOKEN` set, **every route except
`GET /healthz` requires** a bearer token:

```
Authorization: Bearer <token>
```

A missing or wrong token returns `401`. The public eval endpoint accepts the
public token `reeflex-eval-public-2026` (dev/eval only).

## `POST /v1/decide`

Send an [Action Envelope](action-envelope.md); receive a `Decision`. The engine
evaluates it with pure OPA/Rego over the per-session ledger — **zero LLM, no
network, no wall-clock in the decision path** (see
[ADR-0002](../adr/0002-no-llm-in-decision-path.md)).

**Request**

```bash title="POST /v1/decide — a bulk delete in production"
curl -s https://api-dev.reeflex.io/v1/decide \
  -H "Authorization: Bearer reeflex-eval-public-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":     { "id": "agent:demo", "session_id": "ref-hold" },
    "action":    { "namespace": "store", "verb": "delete", "ability": "store/bulk-delete-products" },
    "target":    { "environment": "production" },
    "magnitude": { "count": 200 },
    "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
    "approval":  { "present": false }
  }'
```

### Response — `require_approval` (a hold)

An irreversible, broad change in production is held for an approver rather than
run. The response carries a `hold_id` and a TTL (`expires_ts`):

```json
{
  "decision": "require_approval",
  "reason": "irreversible broad change in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "obligations": [],
  "modulation": null,
  "decision_id": "1a941b6398444bbf9ef212afa5c0de5a",
  "hold_id": "89cd7ee97e374eed8dd4db8a73f07731",
  "expires_ts": "2026-07-13T10:45:07Z"
}
```

### Response — `allow`

A small, reversible action clears every risk axis:

```json
{
  "decision": "allow",
  "reason": "no high-risk axis matched",
  "rule": "reeflex.policy/default_allow",
  "obligations": [],
  "modulation": null,
  "decision_id": "65ecc4bd6e4d432592565ccb760cd228"
}
```

### Response — `deny`

An irreversible, systemic change in production is refused outright — a hold
would not help, because no approver should be able to authorize it:

```json
{
  "decision": "deny",
  "reason": "irreversible systemic change in production is not allowed even with approval",
  "rule": "reeflex.policy/irreversible_systemic_prod",
  "obligations": [],
  "modulation": null,
  "decision_id": "ca335517144c47729f967298517daab0"
}
```

### Response fields

| Field | Type | Meaning |
|---|---|---|
| `decision` | string | `allow`, `deny`, or `require_approval`. Total precedence: `deny > require_approval > allow`. |
| `reason` | string | Human-readable explanation the agent can surface. |
| `rule` | string | The rule that fired (e.g. `reeflex.policy/irreversible_broad_prod`). |
| `obligations` | array | Conditions an adapter must honor before executing (empty when none). An enforce-mode adapter that meets an unknown obligation must fail closed. |
| `modulation` | object \| null | Reserved for future policy output; `null` today. |
| `decision_id` | string | Stable id for this decision, written to the audit log and echoed by adapters — the traceability anchor. |
| `hold_id` | string | *(require_approval only)* the hold to resolve via the holds API. |
| `expires_ts` | string | *(require_approval only)* ISO-8601 TTL after which the hold expires. |

## Holds API

When `/v1/decide` returns `require_approval`, the adapter stores the hold
instead of executing. These routes list and resolve holds. All require auth.

| Route | Purpose |
|---|---|
| `GET /v1/holds?status=&limit=&cursor=` | List holds, filterable by status, paged. |
| `GET /v1/holds/{id}` | Full detail for one hold. |
| `POST /v1/holds/{id}/resolve` | Approve or reject a pending hold. |

A hold is **single-use** and **time-bound**. Core enforces `actor != approver`
(the agent that raised the hold can never resolve it), the TTL, and
**envelope-hash binding** — an approved hold authorizes the exact action that
was submitted, and consumption is concurrency-safe (a single-use approved hold
cannot be double-consumed). See the [hold lifecycle diagram](../architecture/diagrams.md#hold-lifecycle).

## Health

```
GET /healthz   ->   {"status": "ok"}      # 200, always unauthenticated
```

## Errors

| Status | Body | When |
|---|---|---|
| `400` | `{"error": "invalid_json"}` | Malformed request body. |
| `401` | — | Missing/invalid bearer token (when auth is enabled). |
| `500` | `{"decision": "deny", "rule": "reeflex.core/internal_error", …}` | The engine **fails closed**: if evaluation cannot complete, the answer is `deny`, never `allow`. |

The fail-closed `500` shape mirrors a decision so an adapter's normal
enforcement path handles an engine fault the safe way — by blocking.
