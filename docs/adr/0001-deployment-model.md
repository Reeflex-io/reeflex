# ADR-0001 — Deployment Model

**Status:** Accepted — 2026-06-29

---

## Context

Reeflex governs AI-agent actions by evaluating a normalized Action Envelope against OPA/Rego
policies and returning one of three deterministic decisions: `allow`, `deny`, or
`require_approval` (SPEC §5). The engine that performs this evaluation is `reeflex-core`,
exposed at `POST /v1/decide` (SPEC §6).

Before launch the following questions needed a single, recorded answer:

- Is `reeflex-core` a library embedded in each adapter, or an independent service?
- Which components are open-source and which are commercial?
- On what hosting topologies can the product run at launch, and which topologies are planned
  but not yet available?
- What is the sequencing rationale for bringing these topologies to market?

Without a recorded decision, adapter authors, contributors, and the website risk inconsistent
assumptions about where the engine lives and what "installing Reeflex" means.

---

## Decision

### 1. Engine-as-service

`reeflex-core` is a **service** called over HTTP, not a library embedded in an adapter or
plugin. Adapters reach the engine via one HTTP call:

```
POST /v1/decide   { ActionEnvelope }  ->  { Decision }
```

This is the entire dependency surface (SPEC §6: "That single, stable interface is the entire
dependency surface"). The engine's implementation language (currently Python + OPA/Rego — see
[CONTRIBUTING.md](../../CONTRIBUTING.md) §2 for the stack) is irrelevant to the adapter
— the adapter sees only HTTP JSON.

### 2. Open-core boundary

| Tier | Components | License |
|---|---|---|
| Open-source | `reeflex-core`, all adapters, base policy packs, `reeflex-spec` | Apache 2.0 |
| Commercial / closed | Multi-tenancy, authentication, billing, regulated compliance reporting (NIS2/DORA/GDPR), ANAF/SmartBill integrations | Proprietary — never in a public repo |

The closed tier never appears in any public repository. This is an absolute project limit;
see [docs/open-core.md](../open-core.md) for the full boundary definition.

### 3. Two delivery variants — same engine, same adapter

The engine and adapters are identical in both variants. The only difference is **where the
engine process runs**.

---

**Variant A — Full on-prem (available now, free)**

The client runs every component. Decision data never leaves the client's infrastructure.

```
CLIENT INFRASTRUCTURE
+--------------------------------------------------+
|                                                  |
|  AI Agent                                        |
|      |                                           |
|      v                                           |
|  Adapter (e.g. reeflex-wordpress plugin)         |
|      |  POST /v1/decide {ActionEnvelope}          |
|      v                                           |
|  reeflex-core                                    |
|    +-- OPA/Rego policy evaluation                |
|    +-- audit log (JSONL today; Postgres roadmap) |
|      |                                           |
|      v                                           |
|  Decision {allow|deny|require_approval}          |
|      |                                           |
|      v                                           |
|  Adapter enforces decision                       |
|                                                  |
+--------------------------------------------------+
```

Target users: regulated organizations (RO/EU), developers with a VPS or dedicated server.

Constraint: requires a long-lived Python service process. Does NOT work on shared hosting
(GoDaddy, cPanel, and equivalent environments cannot run persistent background services).
Users on shared hosting are NOT served by this variant.

---

**Variant B — Hosted / subscription (ROADMAP — not built, not available)**

> **This variant is planned. It does not exist today. No hosted engine is operated. Do not
> present Variant B as a delivered or current capability.**

The client installs only a thin adapter (plugin). The adapter calls a hosted engine operated
by Reeflex at reeflex.io over HTTPS. Works on any hosting environment, including shared
hosting.

```
CLIENT INFRASTRUCTURE            REEFLEX.IO (hosted by us)
+------------------------+       +------------------------------------------+
|                        |       |                                          |
|  AI Agent              |       |  reeflex-core (hosted)                   |
|      |                 |       |    +-- OPA/Rego evaluation               |
|      v                 |       |    +-- audit log (Postgres; roadmap)     |
|  Adapter (thin plugin) |       |                                          |
|      |                 |       |  evaluates the Action Envelope,          |
|      v                 |       |  returns the Decision                    |
|  Adapter enforces      |       |                                          |
|  the decision          |       +------------------------------------------+
|                        |
+------------------------+

Flow (HTTPS):  Adapter --POST /v1/decide {ActionEnvelope}-->  reeflex.io
               reeflex.io --{allow | deny | require_approval}-->  Adapter enforces
(decision data leaves the client and transits reeflex.io infrastructure)
```

In this variant, decision data (the Action Envelope) transits Reeflex-operated infrastructure.
Reeflex operates the engine; clients pay a subscription. Multi-tenancy, authentication, and
billing are part of the closed commercial tier.

---

### 4. Sequence: on-prem first

The on-prem variant ships at the GitHub launch. The hosted variant is built only when adoption
justifies operating infrastructure. Rationale: on-prem has zero operating cost, eliminates
any "trust the vendor with my agent data" objection, and is the natural entry point for the
regulated-org segment. Hosted follows traction.

### 5. Determinism is invariant across both variants

Both variants run the identical OPA/Rego evaluation path. Zero LLM is in the decision path in
either variant. Free text, OKF documents, and markdown are never inputs to the decision
(see ADR-0002). The invariant holds:

> Same Action Envelope in → same Decision out, regardless of where the engine runs.

---

## Consequences

### Positive

- **Clean adapter contract.** Adapter authors implement one HTTP call. They need no knowledge
  of OPA, Rego, or the engine's internals. The SPEC §6 adapter contract is fully sufficient.
- **Language independence for adapters.** A PHP plugin, a Go service, and a Python script all
  interact identically with the engine.
- **Determinism is enforceable at a boundary.** A process boundary is easier to audit than an
  embedded library; the engine's isolation from the adapter process is structurally enforced.
- **Open-core boundary is clean.** The closed tier (multi-tenancy, billing, compliance
  reporting) can be layered onto the hosted deployment without touching open-source
  repositories.
- **On-prem-first eliminates operating cost at launch** and removes vendor-trust friction for
  regulated-org early adopters.

### Negative / trade-offs

- **Shared-hosting users are not served today.** Variant A requires a persistent service
  process; Variant B (which would serve shared hosting) is roadmap. This is a known gap,
  accepted deliberately. It will be closed when the hosted variant is built.
- **Network hop within the client.** On-prem deployments introduce a loopback or LAN HTTP
  call per governed action. For typical governance use cases this latency is acceptable; for
  high-frequency bulk operations it should be measured.
- **Operational burden on client for on-prem.** The client is responsible for running,
  updating, and monitoring `reeflex-core`. This is appropriate for the target segment
  (developers, regulated orgs with IT staff) but is a barrier for non-technical users — who
  again are served only by the hosted variant once built.
- **Variant B introduces data-transit trust requirement.** When the engine is hosted, the
  Action Envelope leaves the client's infrastructure. This must be addressed with a clear
  data-processing agreement and appropriate contractual commitments before Variant B launches.
  This is a gate for Variant B, not a problem for the current launch.

---

## Alternatives considered

### Embed the engine inside the adapter (PHP library or WASM module)

Rejected for three reasons:

1. **Loss of isolated-OPA determinism guarantee.** OPA is a purpose-built policy engine with a
   defined evaluation model. Embedding a PHP or WASM re-implementation of the same logic
   would introduce a second, diverging evaluation path. The invariant "same envelope in, same
   decision out" could silently break across hosts if the two implementations drift. There is
   no practical way to enforce behavioral equivalence between the canonical OPA engine and an
   embedded re-implementation without re-running the full conformance suite on every release
   of every adapter.

2. **Per-language re-implementation cost and drift risk.** Reeflex's value proposition is one
   policy vocabulary that governs any backend. If the engine is embedded per adapter, every
   new adapter language (PHP, Go, Ruby, Node) requires a faithful re-implementation of the
   same Rego evaluation semantics. Drift is structurally inevitable; correctness becomes
   per-adapter rather than per-spec.

3. **Destroys the core differentiator.** The product's identity is "a deterministic gate, not
   another AI" (SPEC footer; see also ADR-0002). An embedded, per-language re-implementation
   cannot credibly claim canonical determinism. The HTTP service boundary is what makes the
   claim auditable: one engine, one evaluation, one audit trail.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
