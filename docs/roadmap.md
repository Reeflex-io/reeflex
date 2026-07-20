---
title: Roadmap
description: >-
  What ships today versus what is planned or in progress — adapters, approval
  flow, persistence, policy packs, and audit signing. Honest about the line.
---

# Roadmap

What is **planned or in progress** — not yet fully delivered. For what already
ships and is tested today, see the [Changelog](reference/changelog.md) and the
component READMEs. The canonical, full list lives in
[ROADMAP.md](https://github.com/Reeflex-io/reeflex/blob/main/ROADMAP.md).

!!! note "How to read this"
    Reeflex documents the line between shipped and planned deliberately. If a
    thing is roadmap, this page says so — nothing here is presented as a current
    capability.

## Shipped today

- **`reeflex-core`** — the `/v1/decide` engine, OPA/Rego, JSONL audit, the
  [holds API](reference/rest-api.md#holds-api), and the `REEFLEX_FREEZE`
  kill-switch.
- **Reference adapters** — Claude Code, WordPress, n8n, and the MCP gateway
  (`reeflex-mcp`), all conformance-tested against the spec.
- **Approval flow (HIL Phase 1–2)** — the holds queue, resolution API, approval
  principals (`actor != approver`, single-use, TTL, envelope-hash binding), the
  outbound webhook, the wp-admin "Pending approvals" surface, and the
  `reeflex-holds` MCP server.
- **SIEM/syslog telemetry** — RFC 5424, JSON/CEF (see [SIEM export](siem.md)).

## Planned / in progress

**Adapters** — a live-deployment milestone for WordPress (real posts + a
WooCommerce path), and community adapters against the [Adapter Contract](reference/action-envelope.md):
`reeflex-postgres`, `reeflex-s3`, and others (Git, outbound email, Kubernetes)
as interest develops. PyPI publication of `reeflex-mcp` is gated on a human GO.

**Approval flow (Phase 3)** — a Slack notifier + daily digest + a CLI; N-of-M /
quorum approvals; a core endpoint to read and flip freeze from a surface.

**Persistence** — moving the in-memory session ledger and the audit log to
Postgres for durability and cross-process deployments.

**Tamper-evident audit** — ed25519 envelope + audit-record signing
(Vault-managed keys) and chain-linked audit records, so any deletion or
modification is detectable. Today's records are append-only JSONL but not
cryptographically signed.

**Policy packs** — pre-built Rego packs (content safety, data protection,
financial safety) and cumulative session budgets for `transact` (spend) and
`emit` (egress), extending the existing delete-budget ledger. Also an open
decision on the [R5 delete-budget scope](policy-guide.md)
(all-verbs vs destructive-only).

**OKF constitution bundle** — publishing the Rego policy pack as an Open
Knowledge Format bundle for provenance and version discovery. *(OKF documents
are never a decision input — a publication format, not runtime; see
[ADR-0002](adr/0002-no-llm-in-decision-path.md).)*

**Hosted variant** — the subscription model where a thin adapter calls a
Reeflex-operated engine, versus today's on-prem-only model. Rationale and
sequencing (on-prem first) are in [ADR-0001](adr/0001-deployment-model.md); the
open-core boundary is unchanged in either variant ([Open core](open-core.md)).
