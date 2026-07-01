# Reeflex Roadmap

This page describes work that is **planned or in progress**, not yet fully
delivered. For what already ships and is tested today — including the
`reeflex-core` engine and the Claude Code and WordPress reference adapters —
see [CHANGELOG.md](CHANGELOG.md) and the component READMEs.

---

## Adapters

### WordPress adapter — live deployment (in progress)

The WordPress adapter itself is **built and conformance-tested**: a must-use
plugin that intercepts at the Abilities API seam (`WP_Ability::execute()` via
`wp_register_ability_args`), normalizes abilities into the Action Envelope
(verb + 3 axes + stable `session_id`), enforces decisions faithfully, emits
audit records, and passes the conformance demo end-to-end against a live core.
See [`reeflex-wordpress/`](reeflex-wordpress/).

What remains is the **live deployment milestone**:

- A documented install on a real WordPress instance, with hooks firing on
  actual posts (before/after on real data), not just the stubbed conformance harness.
- WooCommerce-specific coverage (orders, refunds, bulk product edits).

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

## Approval flow (planned — not built)

Human-in-the-loop async approval for `require_approval` decisions:

- An approval queue that holds actions pending human review.
- A minimal review interface (email notification + one-click approve/reject,
  or an API for integration with existing ticketing systems).
- Multi-approver / quorum support: require N-of-M approvers for high-risk
  actions.
- Re-submission of the approved envelope with `approval.present = true` and
  the approver principal recorded.

Currently, `require_approval` decisions are returned correctly by the engine
but the approval routing and queue are not implemented. An adapter integrating
today handles the hold logic itself.

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

*Reeflex — governance that isn't another AI.*
