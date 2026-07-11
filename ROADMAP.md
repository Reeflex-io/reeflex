# Reeflex Roadmap

This page describes work that is **planned or in progress**, not yet fully
delivered. For what already ships and is tested today — including the
`reeflex-core` engine and the Claude Code, WordPress, and MCP gateway
(`reeflex-mcp`) reference adapters — see [CHANGELOG.md](CHANGELOG.md) and the
component READMEs.

---

## Adapters

### WordPress adapter — live deployment (in progress)

The WordPress adapter itself is **built and conformance-tested**: delivered as
a standard plugin (installed from the wp-admin UI, configured via a Settings
screen) and as a must-use plugin (configured via `wp-config.php` constants).
Both intercept at the Abilities API seam (`WP_Ability::execute()` via
`wp_register_ability_args`), normalize abilities into the Action Envelope
(verb + 3 axes + stable `session_id`), enforce decisions faithfully, emit
audit records, and pass the conformance demo end-to-end against a live core.
See [`reeflex-wordpress/`](reeflex-wordpress/).

What remains is the **live deployment milestone**:

- A documented install on a real WordPress instance, with hooks firing on
  actual posts (before/after on real data), not just the stubbed conformance harness.
- WooCommerce-specific coverage (orders, refunds, bulk product edits).

### MCP gateway adapter — SHIPPED (`reeflex-mcp` v0.1.0)

`reeflex-mcp` is **built and conformance-tested**: a transparent MCP proxy
that governs any MCP upstream (stdio or streamable-HTTP) — dynamic tool
discovery and namespacing, declarative per-server mappings (starters:
filesystem, github, postgres) with a name-heuristic fallback and a
conservative default, obligations honored (SPEC §5/§7), and lifecycle
subcommands (`setup`/`add`/`import`/`doctor`) that migrate a client's MCP
config onto a single governed path and detect drift. 113 unit tests passing.
See [`reeflex-mcp/`](reeflex-mcp/) and [docs/mcp-gateway.md](docs/mcp-gateway.md).

What remains: **PyPI publication** — gated on a human GO, same as every other
Reeflex package; install from source until then.

### Community adapters (planned — not built)

Adapters for other backends, following the same SPEC §6 contract:

- `reeflex-postgres` — governs database operations (SELECT, INSERT, UPDATE,
  DELETE, DDL) against a Postgres instance.
- `reeflex-s3` — governs object storage operations (PutObject, DeleteObject,
  bucket-level operations).
- Others (Git, outbound email, Kubernetes) as community interest develops.

Any adapter that passes the conformance suite (SPEC §7) and does not require
a license broader than Apache 2.0 is welcome.

---

## Hosted tier (Variant B) (planned — not built)

A hosted / subscription variant where the client installs only a thin adapter
and calls a Reeflex-operated engine at reeflex.io over HTTPS. The current
delivery model is Variant A (full on-prem, engine runs on the client's own
infrastructure). See [docs/adr/0001-deployment-model.md](docs/adr/0001-deployment-model.md)
for the full rationale and sequencing.

The hosted model is justified by centralized value — shared threat intelligence
across deployments, automatic policy-pack updates, and compliance-as-a-service
— NOT by merely hosting the API.

Work on the hosted tier begins after on-prem adoption justifies operating
infrastructure.

---

## Approval flow — SHIPPED (core v0.1.5)

Human-in-the-loop (and agent/automation) async approval for `require_approval`
decisions is **implemented in core** (HIL Phase 1, v0.1.5):

- **Shipped:** the holds queue (event-sourced JSONL + in-memory index), the
  resolution API (`GET /v1/holds`, `GET /v1/holds/{id}`, `POST
  /v1/holds/{id}/resolve`), approval principals (human | agent | automation,
  human-only by default, operator policy per rule), `actor != approver`
  enforced, single-use + TTL + action-hash binding, the kill-switch
  (`REEFLEX_FREEZE`), and the outbound hold webhook. Re-submission carries
  `approval={present, hold_id}` and the ORIGINAL actor identity; the approver
  is recorded as the resolver, never the actor.
- **Shipped surfaces (Phase 2):** WordPress adapter re-submission +
  "Reeflex — Pending approvals" wp-admin page; the `reeflex-holds` MCP server
  (any MCP client, e.g. Claude Desktop, becomes a holds surface).
- **Still planned:** Slack notifier + daily digest + a CLI (Phase 3); N-of-M /
  quorum approvals (v2+); a core endpoint to read/flip freeze from a surface.

SIEM/syslog telemetry (RFC 5424, JSON/CEF) shipped earlier, in core v0.1.4.

---

## Policy (planned — not built)

### Framework policy packs

Pre-built Rego policy packs for common governance postures:

- Content safety (WordPress: bulk operations, media upload limits, role
  escalation guards).
- Data protection (Postgres: production DDL gates, PII-tagged table locks).
- Financial safety: cumulative budget caps for `transact` and `emit` verbs
  across a session.

### Cumulative budgets for transact and emit

Extend the in-session cumulative ledger (currently tracking `delete` verb
counts) to cover `transact` (monetary amount, EUR/RON) and `emit` (outbound
call count per session). Policy rules can then gate on spend and egress
budgets, not just destructive operations.

### R5 session-delete-budget scope (open decision)

R5 (`reeflex.policy/session_delete_budget`, SPEC §4.1) currently holds **every**
verb once a session's cumulative delete budget is exceeded — including read-only
actions — as a whole-session fragmentation guard. This is deterministically
correct (the session is flagged for human review) but surprised operators during
live testing: a plain read returned HOLD after enough prior deletes accumulated
in the same session. Decision needed: keep the guard all-verbs (strongest
fragmentation resistance — the whole session is reviewed) or scope it to
destructive verbs only (`delete` / `transact` / `emit`), letting reads through
while the budget is blown. Not a bug — a policy-posture choice. `reeflex-verify`
mitigates the surprise for testing by using a fresh session per run (each run
starts with a clean budget).

### ed25519 envelope signing and audit record signing

The SPEC (§6) specifies that envelopes are signed at interception
(`meta.signature`) and that audit records are tamper-evident. In v0.1 the
signature field is populated with a stub value and audit records do not carry
a cryptographic signature. Full ed25519 signing, backed by Vault-managed
keys, is on the roadmap. Until then, audit records in v0.1 are append-only
JSONL but not cryptographically verified.

---

## Persistence (planned — not built)

### In-memory ledger to Postgres

The current per-session cumulative action ledger lives in memory. It is reset
when the engine process restarts, and it does not survive crashes or restarts.
Moving the ledger (and the audit log) to Postgres provides durability, enables
cross-process deployments, and is a prerequisite for the hosted tier.

### Tamper-evident audit

Postgres-backed audit store with chain-linked records (each record hashes the
previous) so that deletion or modification of any record is detectable. This
is a prerequisite for the forensic trail use case.

---

## OKF — agent constitution as a bundle (planned — narrow scope)

Publish the agent constitution (the Rego policy pack) as an OKF (Open
Knowledge Format) bundle, enabling standard tooling to discover and inspect
the policy version, provenance, and change history.

A provenance module that records which policy version evaluated each decision
and links it to the OKF bundle hash.

**Important constraint:** OKF documents and free text are never inputs to the
`/v1/decide` decision path. The decision engine evaluates structured Action
Envelopes against compiled Rego rules. This is not changing. The OKF bundle
is a publication format for the policy constitution, not a runtime input.
(See ADR-0002.)

---

*Reeflex — a seatbelt for the AI acting on your systems.*
