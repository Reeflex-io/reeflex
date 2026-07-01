# Reeflex — Deterministic Governance for AI-Agent Actions

> **A seatbelt for the AI acting on your systems.** A deterministic gate that
> decides what an AI agent is allowed to do — across any backend — before the
> action runs.

AI agents can now write to your database, edit your store, send your emails.
That's wonderful — until the day one of them gets it catastrophically wrong.
Reeflex sits between AI agents and the systems they act on. When an agent tries
to do something — delete a record, send an email, execute a transaction — Reeflex
intercepts the request, evaluates it against a deterministic policy, and returns
one of three decisions: **allow**, **deny**, or **require_approval**. The decision
is made by OPA/Rego + classical logic. **Zero LLM in the decision path.**

### 💚 We love open source — so the core is free, forever

The engine, the specification, the policy language, the reference adapters — all
**Apache-2.0**, yours to run, fork, and build on. No lock-in, no metering on the
decision path, no asterisks. Safety infrastructure should belong to everyone who
needs it. We'd rather earn your trust than trap it.

---

## The problem

AI agents can now write to databases, manage content, execute payments, and send
messages. The capability layer is racing ahead. The trust layer is not.

- A single action can be irreversible: a hard delete, a sent email, an executed
  payment.
- Agents can fragment dangerous actions into smaller ones to evade per-call
  thresholds (the fragmentation attack).
- Existing API-level controls are per-tool, per-backend, not unified.
- "AI governance" products that use another AI to govern AI decisions introduce
  the same non-determinism they claim to fix.

---

## The solution

One universal shape for every action — the **Action Envelope** — and one engine
that governs it.

```
backend action --[ adapter ]--> Action Envelope --> reeflex-core --> Decision --[ adapter ]--> proceed / block / hold
```

Every dangerous thing an agent can do — `DELETE` on Postgres, `delete-post` on
WordPress, `PutObject` on S3, an outbound email — is normalized into one
envelope. One deterministic engine governs all of them. Policy authors write
rules once in a single vocabulary, not per tool, not per backend.

---

## What is in v0.1

The following components are built, tested, and available:

**`reeflex-spec` (this repo)**
- Action Envelope — the normalized JSON shape every adapter must produce (§2).
- Adapter Contract — four responsibilities every compliant adapter must implement:
  intercept, normalize, enforce, audit (§6).
- Conformance suite specification — deterministic input/output test cases that
  prove an adapter is compliant (§7).
- JSON schemas for the envelope and decision.

**`reeflex-core` engine**
- `POST /v1/decide` — full request pipeline: envelope validation, axis coercion,
  cumulative ledger, OPA/Rego evaluation, decision, audit write.
- `GET /healthz` — liveness check.
- Fail-closed: any OPA error, missing binary, or unexpected exception produces
  `deny`, never `allow`.
- Append-only JSONL audit of every decision.
- Per-session cumulative action ledger for fragmentation resistance (SPEC §4.1).
- 55/55 Python unit tests passing; 9/9 OPA policy tests passing.

**Base policy pack (R1–R5)**
- R1 — allow read-only internal actions.
- R2 — require approval: irreversible + broad + production.
- R3 — deny: irreversible + systemic + production (even with prior approval).
- R4 — default allow when no high-risk rule fires.
- R5 — session delete budget: cumulative deletes exceeding 20 items per session
  require approval (fragmentation guard, SPEC §4.1).

**`reeflex-claude` — Claude Code adapter (reference, conformance-tested)**
- A PreToolUse hook that governs Claude Code tool calls (Bash, Write, Edit, …)
  at the source: intercept → classify into an Action Envelope → decide → enforce.
- Pure classification logic (`classify.py`) mapping shell/SQL/file operations to
  the three axes: `rm -rf /` → irreversible+systemic, `DROP TABLE` → irreversible+broad, etc.
- 133 unit tests passing; end-to-end demo blocks `rm -rf /` and force-push.

**`reeflex-wordpress` — WordPress adapter (reference, conformance-tested)**
- A must-use plugin that intercepts at the WordPress Abilities API seam
  (`WP_Ability::execute()` via `wp_register_ability_args`), normalizes the
  action into an Action Envelope, calls core, and enforces the verdict.
- A normalizer (`class-reeflex-normalizer.php`) that computes verb + three axes
  from the ability name and input, with a strict rule: agent-supplied input may
  only *raise* risk, never lower it (a forged approval flag cannot bypass a hold).
- Passes the WordPress conformance demo end-to-end against a live core: read →
  allow, bulk force-delete → hold, systemic delete → deny, forged approval →
  still held, fail-closed when core is unreachable.
- Live install on a real WordPress instance is the next step (see ROADMAP.md).

**`reeflex-mock` — reference adapter + demo**
- A runnable mock adapter (`adapter.py`) demonstrating all four adapter
  responsibilities (INTERCEPT, NORMALIZE, ENFORCE, AUDIT).
- End-to-end demo (`demo.py`): starts the engine, runs 5 scenarios (allow,
  single delete, bulk delete requiring approval, fragmentation resistance,
  fail-closed on broken OPA path), prints read-back assertions, exits with
  `STATUS: PASS` or `STATUS: FAIL`.
- The worked reference for adapter authors building against this spec.

---

## What is planned (not yet built)

**Live WordPress deployment** — The WordPress adapter is conformance-tested
against a live core (see above); the remaining step is a documented install on a
real WordPress instance with hooks firing on actual posts. See [ROADMAP.md](../ROADMAP.md).

**WooCommerce, content, and user policy packs** — Framework Rego rule sets
targeting WordPress-specific abilities (bulk operations, media upload limits,
role escalation guards, WooCommerce financial gates). See
[ROADMAP.md](../ROADMAP.md).

**Database & GraphQL adapters** — `reeflex-postgres` (a wire-protocol proxy that
computes real row-impact before forwarding) and a GraphQL resolver hook. The
decision logic already exists; these are adapter surfaces. See
[ROADMAP.md](../ROADMAP.md).

**Community adapters** — `reeflex-s3` and others, built against this spec.

**Hosted / subscription tier** — A Reeflex-operated engine plus curated,
regulation-mapped policy packs (GDPR / NIS2 / WooCommerce) and managed policy
distribution. The open core never depends on it. See
[docs/adr/0001-deployment-model.md](../docs/adr/0001-deployment-model.md).

---

## Example policy snippet

Policies are plain Rego — readable, testable, version-controlled, reviewed in
pull requests. The decision object shape is defined in SPEC §5:

```rego
package reeflex.policy

# Deny everything unless a rule explicitly allows it (base pack R3/R4 pattern).

# Read-only internal is always fine (R1).
decision := {"decision": "allow",
             "reason": "read-only internal action",
             "rule": "reeflex.policy/read_only_internal"} if {
    input.action.verb == "read"
    input.axes.externality == "internal"
}

# Irreversible bulk change in production requires a human (R2).
decision := {"decision": "require_approval",
             "reason": "irreversible broad change in production requires human approval",
             "rule": "reeflex.policy/irreversible_broad_prod"} if {
    input.axes.reversibility == "irreversible"
    input.axes.blast_radius == "broad"
    input.target.environment == "production"
    not input.approval.present
}

# Session delete budget: fragmentation guard (R5, SPEC §4.1).
decision := {"decision": "require_approval",
             "reason": "session delete budget exceeded (fragmentation guard)",
             "rule": "reeflex.policy/session_delete_budget"} if {
    prior := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
    prior + input.magnitude.count > 20
    not input.approval.present
}
```

The full shipped policy is at
[`reeflex-core/policy/reeflex.rego`](../reeflex-core/policy/reeflex.rego).

---

## Decision object shape

`reeflex-core` returns (SPEC §5):

```jsonc
{
  "decision": "require_approval",
  "reason": "irreversible broad change in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "obligations": ["audit:full"],
  "modulation": null
}
```

Every decision is deterministic: same envelope in, same decision out.

---

## Three universal risk axes

Every action is evaluated on three axes (SPEC §4). Policy rules reason in this
vocabulary across any backend:

| Axis | Values |
|---|---|
| `reversibility` | `reversible` → `recoverable` → `irreversible` |
| `blast_radius` | `single` → `scoped` → `broad` → `systemic` |
| `externality` | `internal` → `outbound` → `physical` |

A rule such as *"irreversible + broad + production → require human approval"*
protects Postgres, S3, and WordPress identically.

---

## Deployment

`reeflex-core` runs as an HTTP service. Adapters reach it with one call:

```
POST /v1/decide   { ActionEnvelope }  ->  { Decision }
```

**On-prem (available now, free):** the client runs `reeflex-core` themselves.
All open-source components, zero commercial dependency.

**Hosted / subscription (ROADMAP — not built, not available):** a thin adapter
calls a Reeflex-operated engine over HTTPS. See
[docs/adr/0001-deployment-model.md](../docs/adr/0001-deployment-model.md).

---

## License

Apache License 2.0 — use it, fork it, build on it.

---

*Reeflex — deterministic governance for AI agents, on any backend.*
