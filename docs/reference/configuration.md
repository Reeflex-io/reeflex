---
title: Configuration
description: >-
  Environment variables for reeflex-core and the adapters — the engine server,
  policy, audit, holds, freeze, SIEM, and the canonical adapter → core client
  settings.
---

# Configuration

Reeflex is configured entirely by environment variables — nothing is
hardcoded, and secrets are passed by reference (Vault / env), never committed.
Defaults below are the code defaults; only `REEFLEX_CORE_URL` (adapters) is
effectively required.

## Adapter → core (the canonical trio)

Every adapter that talks to `reeflex-core` over HTTP uses the same three
variables:

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_CORE_URL` | — | Base URL of the engine, e.g. `https://reeflex-core.internal`. Required. |
| `REEFLEX_CORE_TOKEN` | — | Bearer token, when the engine enforces auth. |
| `REEFLEX_VERIFY_SSL` | `true` | TLS certificate verification. Every adapter offers a verify-**off** switch for self-signed/invalid certs, at the user's risk — default is on. |

Adapters also expose a mode:

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_MODE` | `enforce` | `observe` records the verdict it *would* have applied and lets the action proceed (fails **open**); `enforce` applies it (fails **closed**). Calibrate in observe, then switch. |

## Engine server

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_HOST` | `127.0.0.1` | Bind address. |
| `REEFLEX_PORT` | `8080` | Bind port. |
| `REEFLEX_AUTH_TOKEN` | — | If set, all routes except `GET /healthz` require this bearer token. |
| `REEFLEX_MAX_BODY_BYTES` | `262144` | Max request body (256 KiB). |

## Policy engine (OPA)

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_OPA_BIN` | `opa` | Path to the OPA binary. |
| `REEFLEX_POLICY_DIR` | *(bundled)* | Directory of Rego policy packs; empty uses the bundled base policy. |
| `REEFLEX_OPA_TIMEOUT` | `10` | OPA evaluation timeout (seconds). |
| `REEFLEX_WINDOW_SECONDS` | `3600` | Rolling window for cumulative session state (e.g. R5 delete budget). |

## Audit & holds

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_AUDIT_LOG` | *(off)* | Path to the append-only JSONL audit log. Empty disables file audit. |
| `REEFLEX_HOLDS_PATH` | *(in-memory)* | Path to the holds store. |
| `REEFLEX_HOLD_TTL_SECONDS` | `14400` | Default hold TTL (4 hours) before `expires_ts`. |
| `REEFLEX_RESOLUTION_POLICY` | — | Which principal **type** may resolve a hold (HIL / AIL policy). See [Why Reeflex](../why-reeflex.md#ail). |
| `REEFLEX_RESOLVER_TOKENS` | — | Binds a bearer token to the principal it **is**: `{"tok": {"type":"human","id":"alice"}}`. Without it the approving principal is only *asserted* by the caller — and since 0.2.0 an unverifiable approver is **refused**, not recorded. |
| `REEFLEX_REQUIRE_VERIFIED_APPROVER` | **`true`** (since 0.2.0) | Refuse to resolve a hold whose approver cannot be verified (`403 principal_not_verified`). `false`/`0`/`no`/`off` opts out; anything unrecognised reads as the default. |

`REEFLEX_RESOLUTION_POLICY` checks the principal type the caller *claims*; `REEFLEX_RESOLVER_TOKENS` is what establishes *who the caller is*. See [reeflex-core README → Approver verification](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/README.md#approver-verification-rfx-core-2).

### Verified approvers

**Since reeflex-core 0.2.0 this is on by default, and it is a breaking change for anyone who was resolving holds with a self-asserted approver.** The image sets `REEFLEX_REQUIRE_VERIFIED_APPROVER=true`; upgrading a deployment that never configured `REEFLEX_RESOLVER_TOKENS` turns every hold resolution into `403 principal_not_verified`.

Two ways forward, and the refusal itself names both:

```bash
# THE FIX — bind each approver's bearer token to the principal it IS.
# Inline JSON, or a path to a JSON file. Re-read per request: no restart.
REEFLEX_RESOLVER_TOKENS='{"tok_live_alice": {"type": "human", "id": "alice@example.com"}}'

# THE ESCAPE HATCH — pre-0.2.0 behaviour while you wire the above up.
# Holds resolve on the caller's word, and every record says so
# (decided_by_verified: false), so the deployment cannot claim four-eyes.
REEFLEX_REQUIRE_VERIFIED_APPROVER=false
```

Why the default moved: with it off, one bearer token could raise an irreversible production hold and approve it as `human:totally-invented-auditor`, and core minted and persisted the Art. 14 record saying a human had overseen it (RFX-84, reproduced live). Shipping an artefact whose *default* accepts an invented approver, in a product whose claim is evidence of human oversight, is not defensible.

The `403` carries a machine-readable `remedy` alongside `error`/`reason`:

```jsonc
{
  "error": "principal_not_verified",
  "reason": "the approver human:alice@example.com is asserted by the caller and this core cannot check it: ...",
  "hold_id": "…",
  "remedy": {
    "principal": "human:alice@example.com",
    "why": "verification_not_configured",   // or "unbound_credential"
    "actions": ["set REEFLEX_RESOLVER_TOKENS to …", "or … REEFLEX_REQUIRE_VERIFIED_APPROVER=false"],
    "docs": "https://github.com/Reeflex-io/reeflex/blob/main/docs/reference/configuration.md#verified-approvers"
  }
}
```

## Freeze (operator kill-switch)

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_FREEZE` | `false` | When true, every non-read action is denied under `reeflex.policy/frozen`; a state change fires a `freeze.flipped` webhook + audit entry and a SIEM `kill_switch` event. |

## SIEM export & webhooks

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_SYSLOG_ENABLED` | `false` | Emit decision/lifecycle events over syslog to a SIEM. |
| `REEFLEX_SYSLOG_ADDRESS` | — | `host:port` of the syslog collector. |
| `REEFLEX_SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp`, or `tls`. |
| `REEFLEX_SYSLOG_FORMAT` | `json` | Wire format. |
| `REEFLEX_SYSLOG_FACILITY` | `local0` | Syslog facility. |
| `REEFLEX_SYSLOG_TLS_VERIFY` | `true` | Verify the collector's TLS cert (when protocol is `tls`). |
| `REEFLEX_WEBHOOK_URL` | *(off)* | Endpoint for hold/freeze webhooks. |
| `REEFLEX_WEBHOOK_QUEUE_SIZE` | `1000` | Bounded outbound webhook queue. |

See [SIEM export](../siem.md) for the event shapes and the syslog wiring.

!!! tip "Adapter-specific settings"
    Each adapter documents its own additional variables (e.g. the MCP gateway's
    `REEFLEX_MCP_CONFIG`, upstream mappings, and timeouts) in its own README —
    [`reeflex-mcp/`](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-mcp),
    [`reeflex-wordpress/`](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress),
    [`reeflex-claude/`](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-claude).
