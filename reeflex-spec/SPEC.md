# Reeflex — Action Envelope & Adapter Contract (v0.1)

> The portable heart of Reeflex. This spec defines **how any backend action is described** (the Action Envelope) and **what any integration must implement** (the Adapter Contract) so it can be governed by `reeflex-core`.
>
> `reeflex-core` knows nothing about WordPress, Postgres, or S3. It decides on **actions**, not tools. An adapter's whole job is to translate a backend-specific action into one universal shape, ask core for a decision, and enforce it.

---

## 1. Why one shape

Every dangerous thing an agent can do — `DELETE` on Postgres, `delete-post` on WordPress, `PutObject` on S3, a force-push to Git, an outbound email — is the same kind of event: *an agent wants to perform an action with some cost, some blast radius, and some effect on the outside world.*

If all of these are normalized into one envelope, **one deterministic engine governs all of them**, and the policy author writes rules once in a single vocabulary — not per tool, not per backend.

```
backend action --[ adapter ]--> Action Envelope --> reeflex-core --> Decision --[ adapter ]--> proceed / block / hold
```

---

## 2. The Action Envelope

The normalized representation every adapter MUST produce. JSON. This is the contract surface between adapters and core.

```jsonc
{
  "reeflex_version": "0.1",

  "agent": {
    "id": "agent:cursor-claude",          // who is acting
    "on_behalf_of": "user:alice",           // the authorized human principal (nullable)
    "session_id": "sess_01H..."           // ties actions into a trajectory
  },

  "action": {
    "namespace": "wordpress",             // backend family — set by the adapter
    "verb": "delete",                     // normalized verb (see section 3)
    "ability": "wordpress/delete-post"    // full backend-specific action id
  },

  "target": {
    "kind": "post",                       // what is being acted on
    "ref": "post:1481",                   // stable identifier (nullable for bulk)
    "environment": "production"           // production | staging | dev
  },

  "params": { },                          // adapter-specific, structured, typed

  "magnitude": {
    "count": 1                            // how many entities this action affects
  },

  "axes": {                               // the three universal risk axes (section 4)
    "reversibility": "irreversible",      // reversible | recoverable | irreversible
    "blast_radius": "single",             // single | scoped | broad | systemic
    "externality": "internal"            // internal | outbound | physical
  },

  "approval": {
    "present": false,                     // has a human already approved?
    "by": null,                           // principal who approved
    "role": null                          // their role at approval time
  },

  "trajectory_ref": "traj_01H...",        // pointer to cumulative action path (optional in v0.1)

  "context": { },                         // free passthrough for policy use

  "meta": {
    "timestamp": "2026-06-29T10:00:00Z",
    "nonce": "9f2c...",                   // replay protection
    "signature": "ed25519:..."           // envelope signed at interception
  }
}
```

**Rules**

- `action.namespace`, `action.verb`, `target.environment`, and `axes.*` are REQUIRED. Everything an adapter cannot determine MUST be set to a safe-conservative default (e.g. unknown reversibility -> `irreversible`), never omitted.
- The adapter SHOULD provide a first estimate of the three axes. `reeflex-core`'s cost estimator MAY refine them, but a missing axis is a conformance failure.
- The envelope is signed at interception (`meta.signature`) so the audit trail is tamper-evident end to end. (See the v0.1 implementation-status note in §6 — signing is a normative requirement currently fulfilled by a stub; full signing is on the roadmap.)

---

## 3. Normalized verbs

Adapters map backend operations onto a small, fixed verb set. This keeps policy portable.

| verb       | meaning                              | examples                                  |
|------------|--------------------------------------|-------------------------------------------|
| `read`     | observe, no state change             | `SELECT`, `GetObject`, `get-site-info`    |
| `create`   | add new state                        | `INSERT`, `create-post`, `PutObject` (new)|
| `update`   | modify existing state                | `UPDATE`, `edit-page`, role change        |
| `delete`   | remove state                         | `DELETE`, `delete-post`, `DeleteObject`   |
| `execute`  | run / trigger / deploy               | `kubectl apply`, run job, deploy          |
| `transact` | move money or commit an obligation   | refund, payment, sign contract            |
| `emit`     | send to the outside world            | send email, outbound API call, publish    |

The backend-specific operation is preserved in `action.ability` for fine-grained rules; `verb` exists so a policy can say "no `delete` in production over N items" regardless of backend.

---

## 4. The three universal axes

Every action is priced on three axes. This is what makes coverage intrinsic instead of per-tool.

**`reversibility`** — can it be undone?
- `reversible` — trivially undone (toggle a draft)
- `recoverable` — undone with effort/backup (soft-deleted row)
- `irreversible` — gone (hard delete, sent email, executed payment)

**`blast_radius`** — how much is affected?
- `single` — one entity
- `scoped` — a bounded set
- `broad` — a large set / whole table / bucket
- `systemic` — could affect the system itself (schema, infra, all users)

**`externality`** — does it reach beyond the system?
- `internal` — stays inside the controlled system
- `outbound` — reaches third parties (email, API, publish)
- `physical` — affects the physical world (SCADA, robotics, energy)

Policy reasons in these axes. A rule like *"irreversible + broad + production -> require human approval"* protects Postgres, S3, and WordPress identically.

---

## 4.1 Cumulative state — fragmentation resistance

A per-action policy is gameable. A rule like *"require approval when `count > 5`"* is trivially bypassed by deleting 5 at a time, ten times: the agent fragments one dangerous action into many small ones, each individually under the threshold. Per-call evaluation alone is not enough.

Reeflex defeats this by reasoning over **cumulative state per session**, not just the single action.

- The adapter supplies a stable `agent.session_id` (**REQUIRED** for fragmentation resistance).
- `reeflex-core` keeps a per-session **action ledger** — it already records every decision in the observation plane. Before evaluating policy, core injects a `cumulative` object into the policy input, derived from that ledger over a configurable rolling window:

```jsonc
"cumulative": {
  "window_seconds": 3600,
  "count_by_verb":      { "delete": 47, "transact": 2 },
  "count_by_ability":   { "wordpress/delete-post": 47 },
  "amount_by_currency": { "EUR": 480.00 }
}
```

- `cumulative` is computed by core, not the adapter — core is the only component that sees every action in a session. The adapter's sole new obligation is to supply a stable `session_id`.
- Real policy packs SHOULD gate on cumulative totals, not only `magnitude.count`:

```rego
# Bulk delete is bounded per session, however the agent splits it.
decision := {"decision": "require_approval",
             "reason": "session delete budget exceeded (fragmentation guard)"} {
    input.cumulative.count_by_verb.delete + input.magnitude.count > 20
    not input.approval.present
}
```

This is the discrete-decision equivalent of the cumulative-cost idea at the project's origin: **fragmentation buys nothing**, because the budget is tracked across the whole session rather than reset per call. `trajectory_ref` (optional in v0.1) is the hook for richer sequence/drift analysis later.

---

## 5. The Decision

`reeflex-core` returns:

```jsonc
{
  "decision": "require_approval",         // allow | deny | require_approval
  "reason": "irreversible bulk delete in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",   // which rule fired — for audit
  "obligations": ["audit:full"],          // things the adapter MUST also do
  "modulation": null                      // reserved for future use
}
```

- `allow` -> adapter lets the action run.
- `deny` -> adapter blocks it and returns `reason` to the agent.
- `require_approval` -> adapter holds the action and routes it to a human; on approval it re-submits the envelope with `approval.present = true`.
- `obligations` are mandatory side-effects (e.g. `redact:pii`, `rate_limit`). An adapter that ignores an obligation is non-conformant.

Every decision is deterministic: same envelope in, same decision out. No LLM in this path.

---

## 6. The Adapter Contract

An adapter is anything that connects a backend to Reeflex. To be **Reeflex-compliant**, it MUST implement four responsibilities:

1. **INTERCEPT** — capture the backend action *before* it executes (via MCP gateway, API proxy, hook, or eBPF — adapter's choice).
2. **NORMALIZE** — produce a valid, signed Action Envelope (section 2). This is the hard, valuable part and where adapter quality lives.
3. **ENFORCE** — submit the envelope to core, receive the Decision, and apply it faithfully: proceed, block, or hold-for-approval. Fail **closed** — if core is unreachable, deny or hold; never silently allow.
4. **AUDIT** — emit the signed decision record to the observation plane.

Core exposes one call the adapter depends on:

```
POST /v1/decide   { ActionEnvelope }  ->  { Decision }
```

That single, stable interface is the entire dependency surface. Everything else (how you intercept, how you hold for approval) is the adapter's concern.

> **Implementation status (skeleton — v0.1):** Envelope signing (`meta.signature`) and
> audit-record signing are specified above as normative requirements of the v0.1 contract.
> These requirements stand. In the current `reeflex-core` skeleton, `meta.signature` is
> populated with a stub value (`ed25519:stub:...`) and audit records do not carry a
> cryptographic signature — the signing path is on the roadmap. Adapters MUST populate
> `meta.signature` and MUST emit an audit record per decision; full ed25519 signing will
> be enforced once the Vault-backed key management path is implemented.

---

## 7. Conformance

An adapter claiming Reeflex compliance MUST pass the **conformance suite**: a fixed set of input scenarios with expected behavior. This is what lets the community trust third-party adapters — the same way a signed agent card lets agents trust each other.

A conformance case looks like:

```jsonc
{
  "name": "fails closed when core unreachable",
  "given": { "core": "unreachable", "envelope": { "action": { "verb": "delete" } } },
  "expect": { "applied": "deny_or_hold", "never": "silent_allow" }
}
```

Minimum conformance for v0.1:
- Produces a schema-valid, signed envelope for every intercepted action.
- Sets all three axes (conservative defaults when unknown).
- Applies `allow` / `deny` / `require_approval` correctly.
- Fails closed on core error.
- Honors every returned obligation.
- Emits an audit record per decision.
- Supplies a stable `session_id` so cumulative (anti-fragmentation) policies can bind.

---

## 8. Repository layout

```
reeflex-core/         # the engine: /v1/decide, policy eval (OPA/Rego), audit. Backend-agnostic.
reeflex-spec/         # this document + JSON schemas + conformance suite
reeflex-mock/         # runnable mock reference adapter + demo (ships with v0.1)
reeflex-wordpress/    # WordPress reference adapter — planned (see ROADMAP.md)
reeflex-postgres/     # future / community
reeflex-s3/           # future / community
```

The core and the contract are the product. Adapters are the ecosystem — `reeflex-mock` is the shipped reference adapter (v0.1); `reeflex-wordpress` is the production-grade reference adapter on the roadmap. The rest the community can build against this spec.

---

*Reeflex — a deterministic gate, not another AI. Governance for any agent action, on any backend.*
