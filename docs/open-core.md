# Reeflex — Open-Core Boundary

This document defines which components of Reeflex are open-source and which are commercial
and closed. It is intended for contributors, adapter authors, and evaluators who need to
know what they can build on, fork, and redistribute — and what they cannot see.

The boundary is **absolute** (see [ADR-0001](adr/0001-deployment-model.md) §2): closed-tier material never appears in
any public repository, in any form — no code, no configuration, no schema, no secrets.

---

## The boundary at a glance

| Component | Tier | License | Status |
|---|---|---|---|
| `reeflex-core` engine (`/v1/decide`, OPA integration, audit JSONL) | Open | Apache 2.0 | Available |
| `reeflex-spec` (Action Envelope + Adapter Contract + conformance suite + JSON schemas) | Open | Apache 2.0 | Available |
| `reeflex-claude` reference adapter (Claude Code) | Open | Apache 2.0 | Available |
| `reeflex-wordpress` reference adapter | Open | Apache 2.0 | Available |
| Community adapters (`reeflex-postgres`, `reeflex-s3`, etc.) | Open | Apache 2.0 | Community-built against the spec |
| Base policy packs (Rego rules for the Action Envelope) | Open | Apache 2.0 | Available |
| Mock adapter + demo | Open | Apache 2.0 | Available |
| Regulated compliance mapping and reporting (NIS2, DORA, GDPR) | Commercial / closed | Proprietary | Not in any public repo |
| ANAF / SmartBill integrations (RO fiscal) | Commercial / closed | Proprietary | Not in any public repo |
| Hosted multi-tenancy, authentication, billing | Commercial / closed | Proprietary | **[ROADMAP — not built, not available]** |
| Management UI | Commercial / closed | Proprietary | **[ROADMAP — not built, not available]** |

## The line, in one sentence

**Everything that keeps you safe is free. What you pay for is help proving it.**

The gate, the decisions, the adapters, the base policy packs, and the full
audit trail are open — permanently. The planned commercial tier does not add
safety; it adds *attestation*: curated mappings from Reeflex decisions to
specific regulatory obligations (NIS2, DORA, GDPR), auditor-ready reports,
managed policy-pack updates as regulations change, and a hosted engine for
teams that don't want to operate one. Evidence is free; packaging that
evidence in the language a regulator expects is the product.

### For auditors: the open tier is already an evidence source

Every decision Reeflex makes — allowed, held, or denied — is written to an
append-only JSONL audit log with the ability name, the computed impact axes,
the rule that fired, the session, and the timestamp. That gives an auditor
something rare in AI-agent deployments: **a pre-execution record of what an
agent attempted, not just a post-hoc log of what happened.** You can answer
"what could this agent have done, and what stopped it?" from the open tier
alone, today. (Cryptographic tamper-evidence for audit records is on the
[roadmap](https://github.com/Reeflex-io/reeflex/blob/main/ROADMAP.md); current records are append-only but not signed.)

---

## Open tier — what it contains and what you can do with it

Everything in the open tier is Apache 2.0. You can use it, fork it, redistribute it, and
build commercial products on top of it, subject to the Apache 2.0 terms.

### `reeflex-core`

The governance engine. Exposes one endpoint:

```
POST /v1/decide   { ActionEnvelope }  ->  { Decision: allow | deny | require_approval }
```

Implemented in Python + OPA/Rego. Decision evaluation is deterministic: same envelope in,
same decision out, every time. Zero LLM in this path (see ADR-0002). The engine stores an
audit log in JSONL format; Postgres audit persistence is on the roadmap.

### `reeflex-spec`

The portable contract that makes all adapters interoperable:

- **Action Envelope** — the normalized JSON shape every adapter must produce (SPEC §2).
- **Adapter Contract** — four responsibilities every compliant adapter must implement:
  intercept, normalize, enforce, audit (SPEC §6).
- **Conformance suite** — deterministic input/output test cases that prove an adapter is
  compliant (SPEC §7).
- **JSON schemas** — machine-readable envelope and decision schemas.

The spec is backend-agnostic. `reeflex-core` knows nothing about WordPress, Postgres, or
S3. It evaluates envelopes. The spec defines what a valid envelope looks like.

### `reeflex-wordpress` — reference adapter

The reference implementation of the Adapter Contract. It proves the contract is
implementable, serves as the primary adoption surface (WordPress runs a large proportion
of the web), and is the template from which community adapters are built.

### Community adapters

Any adapter that passes the conformance suite can call itself Reeflex-compliant.
`reeflex-postgres`, `reeflex-s3`, and others are open-source community projects built
against the public spec. They carry their own licenses (Apache 2.0 recommended) and are
not part of the commercial tier.

### Base policy packs

Rego rule sets that govern the Action Envelope out of the box. Policies reason over the
three universal axes (`reversibility`, `blast_radius`, `externality`) and cumulative
session state (SPEC §4, §4.1). They are starting points; operators are expected to extend
them for their context.

### Mock adapter + demo

A minimal adapter implementation used for testing, demonstrations, and contributor
onboarding. Synthetic data only — no real PII or client data in any example.

---

## Commercial / closed tier — what it contains and why it is separate

The closed tier is never published to any public repository. Contributors will not find it
here. If you believe you are looking at closed-tier material in a public Reeflex repository,
that is a bug — report it.

### Regulated compliance mapping and reporting

Structured mappings between the Reeflex decision vocabulary and the specific obligations
of NIS2, DORA, and GDPR. Pre-built reporting templates and evidence packages for regulated
organizations in the EU/RO market. This is the commercial value-add for regulated
organizations; it is not part of the open-source governance engine.

### ANAF / SmartBill integrations

Integrations with Romanian fiscal authority systems (ANAF) and the SmartBill invoicing
platform. These are RO-market-specific commercial integrations. They do not belong in the
open-source layer.

### Hosted multi-tenancy, authentication, and billing

**[ROADMAP — not built, not available today.]**

When the hosted variant of Reeflex is built (see ADR-0001 §3, Variant B), it will require
multi-tenancy isolation, authentication, and subscription billing. These components are
part of the closed commercial tier. The open-source engine and adapters are identical in
the hosted and on-prem variants; only the operational wrapper is closed.

No hosted engine is operated today. Do not present hosted availability as a current
capability.

### Management UI

**[ROADMAP — not built, not available today.]**

A web-based management interface for policy authoring, approval workflow, and audit review
is planned as part of the commercial tier. It is not available and is not part of the
open-source repositories.

---

## The boundary is absolute

The open-core boundary is absolute: open repositories are Apache 2.0 and public; the
commercial/closed tier never enters any public repository. This is stated as an absolute
project limit in [ADR-0001](adr/0001-deployment-model.md) §2 and is repeated throughout
the project documentation — it is not merely a preference.

Concretely this means:

- No compliance-mapping code, schema, or configuration in `reeflex-core`, `reeflex-spec`,
  `reeflex-wordpress`, or any open community repository.
- No ANAF/SmartBill integration code or configuration in any open repository.
- No multi-tenancy, authentication, or billing code in any open repository.
- No secrets, API keys, or credentials anywhere in any repository (open or closed) — secrets
  are referenced by name via Vault or environment variables only.

If you are contributing to the open-source layer and are unsure whether something belongs
in an open repository, the default is: it does not. Ask before adding it.

---

## Deployment model and this boundary

The deployment model is recorded in ADR-0001. In summary:

- **On-prem (available now):** the client runs `reeflex-core` themselves. All open-source
  components, zero commercial dependency.
- **Hosted / subscription (ROADMAP):** a thin adapter calls a Reeflex-operated engine over
  HTTPS. The engine is identical open-source code; the operational wrapper (multi-tenancy,
  auth, billing) is the closed commercial tier. This variant is not built and not available
  today.

The open-core boundary is the same in both variants. The engine code is open regardless of
where it runs.

---

## Frequently asked questions

**Can I fork `reeflex-core` and run it commercially?**
Yes. Apache 2.0 permits commercial use. You are running the open-source engine; you are
not accessing the closed commercial tier.

**Can I build a managed/hosted Reeflex service myself?**
Yes, using the open-source components. The "hosted" tier in the table above refers to
Reeflex's own operated service, which is roadmap. You may build your own using the
open-source engine.

**Can I contribute a compliance-mapping policy pack under Apache 2.0?**
Contributions that map the Reeflex Rego vocabulary to regulatory frameworks (as open,
generic policy packs) are welcome in the open tier. The closed tier refers specifically to
Reeflex's commercial, opinionated, supported compliance product — not to open community
policy authoring.

**Where is the line between a base policy pack (open) and the compliance product (closed)?**
A base policy pack is a generic Rego rule set that any operator can read, modify, and
extend. The commercial compliance product adds structured evidence mapping, reporting
templates, and supported maintenance against specific regulatory texts. The Rego rules
themselves are open; the commercial reporting layer is closed.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
