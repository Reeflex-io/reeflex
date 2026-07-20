---
title: "ADR-0002: why reeflex-core keeps a zero LLM decision path"
description: >-
  The recorded decision to keep /v1/decide OPA/Rego-only with zero LLM calls
  or free-text input: a deterministic, auditable proof point, not a headline
  claim.
---

# ADR-0002 — No LLM in the Decision Path

**Status:** Accepted — 2026-06-30

> **Note (superseded framing):** Hold resolution is **not human-only** in the shipped model — the resolving principal may be a human, an agent, or automation you designate (see [why-reeflex.md#ail](../why-reeflex.md#ail)). This ADR records the original decision; its "held for a human reviewer" wording predates the AIL model. The zero-LLM-in-`/v1/decide` decision itself stands.

---

## Context

`reeflex-core` is a deterministic governance engine for AI-agent actions. Its sole runtime
contract is:

```
POST /v1/decide   { ActionEnvelope }  ->  { Decision: allow | deny | require_approval }
```

(SPEC §5, §6; ADR-0001 §1.)

A governance layer for AI agents will inevitably face the question: should an AI model be
part of the decision? The argument for is surface-level intuitive — AI can reason about
ambiguous situations. The argument against is structural: the risk Reeflex exists to govern
is precisely the non-deterministic, context-dependent behavior of AI agents. Using the same
class of system as the judge reintroduces that risk inside the governance layer itself.

A second related question arises from Google OKF (Open Knowledge Format, v0.1, published
12 June 2026): can structured knowledge documents, markdown files, or OKF bundles serve as
context fed into the decision engine? They cannot, for the same structural reason detailed
below. The decided position on OKF is recorded in §3 of this ADR.

This ADR records the decision and its rationale so that:

- Engine implementers cannot inadvertently add an LLM call to the `/v1/decide` path.
- Policy authors know the decision vocabulary is Rego over the Action Envelope — nothing else.
- Adapter authors know what the engine accepts: a typed JSON envelope, not prose.
- Evaluators, auditors, and contributors understand the guarantee being made and why.

---

## Decision

### 1. The `/v1/decide` path contains zero LLM calls and zero free-text input

`reeflex-core` evaluates the Action Envelope using **OPA/Rego + classical logic only**.
Every field the engine reasons over is typed and structured (SPEC §2: the Action Envelope
schema). The engine receives no natural language, no markdown, no OKF documents, and no
model-generated summaries.

The invariant is absolute and load-bearing:

> **Same Action Envelope in → same Decision out.**
> (SPEC §5: "Every decision is deterministic: same envelope in, same decision out.
> No LLM in this path.")

This invariant is absolute: zero LLM in the decision path, in any deployment variant.
Free text, markdown, and OKF documents are never inputs to `/v1/decide`.

This decision applies to all deployment variants (on-prem and future hosted — see ADR-0001
§3 and §5). The OPA/Rego evaluation path is identical in both; the invariant is not
topology-dependent.

### 2. An LLM may serve only as a human-facing advisor at escalation time

When the engine returns `require_approval`, the action is held for a human reviewer. At
that point, and only at that point, an LLM may be used to **summarize context for the
human** — for example, explaining why the rule fired or what the action would affect. This
is a user-interface concern, not a governance concern.

Constraints on this advisory use:

- The LLM summary is presented to a human. The human makes the approval decision.
- The LLM output is never fed back into `/v1/decide` as a decision input.
- The LLM is never the decider and never sits in the `/v1/decide` call chain.
- This advisory role is outside `reeflex-core` entirely; it is an optional layer in the
  approval UI or orchestration layer.

### 3. OKF and free-text documents are not decision inputs — roadmap use only

The decided position on OKF, consistent with §1 of this ADR:

> OKF is NOT a decision input to `reeflex-core`. Feeding markdown or prose to the
> deterministic engine would break the "no LLM in the decision path" guarantee.

OKF has two legitimate, narrowly scoped future uses for Reeflex, neither of which touches
the decision path:

1. **[ROADMAP] Publish the Reeflex agent constitution as an OKF bundle** (`type: Policy`)
   for discovery purposes — a cheap discoverability layer, after the core engine is
   production-stable.
2. **[ROADMAP] A future "Reeflex Provenance" module** that signs and verifies OKF
   knowledge bundles against knowledge-poisoning attacks. This module defends the *input*
   end of the AI attack chain (poisoned knowledge entering an agent); Reeflex governs the
   *output* end (dangerous actions leaving an agent). They are complementary and separate.
   This module will not be merged into the action engine.

Neither roadmap item changes what the engine accepts at `/v1/decide`. Both are explicitly
not available today and must not be presented as delivered capabilities.

OKF as a decision input is prohibited at the project level, not merely inadvisable.
This is an absolute limit consistent with the zero-LLM invariant stated in §1 above.

---

## Consequences

### Positive

**Auditability.** A single OPA/Rego evaluation against a typed envelope is deterministic
and reproducible. Given the same policy pack and the same envelope, any auditor can re-run
the evaluation and confirm the output. This is not true of LLM-based decisions, which may
differ across runs, versions, or temperature settings.

**Security posture.** LLM-in-the-loop decisions are subject to prompt injection — an
adversarial agent could craft action parameters or context fields that manipulate a model
into returning `allow` for a dangerous action. Rego operates over typed fields; it cannot
be prompted.

**The core differentiator is structurally enforced, not just claimed.** The product
position is "a deterministic gate, not another AI" (SPEC footer). Keeping
LLMs out of the decision path makes this claim auditable: there is no model call in the
`/v1/decide` code path, and this ADR documents why that must remain true. An AI governance
layer that itself uses AI to decide is a circular, unauditable arrangement.

**Policy portability.** Because the decision vocabulary is Rego over the Action Envelope,
a policy rule written for one backend (e.g. WordPress) applies without modification to any
other backend (Postgres, S3) that produces the same envelope fields. This portability
depends on the policy language being deterministic and the input being typed — both
properties that free-text input would destroy.

**Simplicity and testability.** The conformance suite (SPEC §7) can be fully specified as
deterministic input/output pairs. There are no stochastic elements to account for in
conformance testing.

### Negative / constraints accepted

**Policies must be expressible in Rego over the Action Envelope.** Governance use cases
that cannot be reduced to typed fields and Rego logic cannot be handled by the engine
directly. This is a deliberate scope constraint, not an oversight. Edge cases requiring
human judgment are handled by `require_approval` — the human reviewer (optionally assisted
by an LLM advisor, per §2 above) provides the judgment; the engine provides the gate.

**Free-text "context" fields in the envelope are passthrough only.** The Action Envelope
includes a `context` field (SPEC §2: `"context": { }`) for adapter-supplied passthrough
data. Rego rules MAY inspect structured subfields of `context` if those subfields are
typed and the policy treats them as typed values. Free-text `context` values MUST NOT be
fed to a model for interpretation inside `/v1/decide`.

---

## Alternatives considered

### LLM-as-judge ("AI grades AI")

The alternative: use a language model to evaluate the Action Envelope and return
`allow | deny | require_approval`.

**Rejected.** Non-determinism is the decisive objection: the same Action Envelope submitted
twice to the same model may produce different decisions. An audit trail built on
non-deterministic decisions cannot be used to demonstrate compliance. Regulated
organizations (the primary target for the EU/RO compliance tier) require reproducible,
traceable decisions.

Additional objections:

- **Prompt injection surface.** An adversarial agent can craft the `context` or `params`
  fields of the envelope to manipulate a model into allowing a dangerous action.
  Rego cannot be prompted; a model can.
- **Unverifiable reasoning.** A model's explanation for a decision ("I decided `deny`
  because...") is not the same as a Rego rule firing. The rule that fired can be named,
  version-pinned, and re-run. A model explanation cannot.
- **It reintroduces the risk Reeflex governs.** Reeflex exists because AI agents produce
  non-deterministic behavior that needs a deterministic gate. Placing another AI agent at
  that gate does not resolve the problem; it re-embeds it.
- **Circular architecture.** Governing an AI agent's actions by consulting another AI model
  creates a circular arrangement with no auditable ground truth.

### Feeding OKF / markdown knowledge into the decision as context

The alternative: load OKF knowledge bundles or markdown documents into the decision
evaluation so that the engine can "understand" the semantic intent behind an action.

**Rejected.** This requires an LLM to interpret the prose (Rego cannot reason over
unstructured text), which reintroduces the LLM-as-judge problem above. Additionally, it
makes the decision dependent on the contents of an external document that can change
between evaluations, breaking reproducibility. The decided position (§3 of this ADR):
feeding markdown or prose to the deterministic engine breaks the "no LLM in the decision
path" guarantee.

The correct encoding of semantic intent is a Rego rule operating on typed Action Envelope
fields — not prose fed into a model.

---

## References

- SPEC §5: "Every decision is deterministic: same envelope in, same decision out.
  No LLM in this path."
- SPEC §2: Action Envelope schema (typed, structured inputs).
- ADR-0001 §5: "Zero LLM is in the decision path in either variant [on-prem or hosted].
  Free text, OKF documents, and markdown are never inputs to the decision."
- This ADR §3: OKF is not a decision input; two narrow roadmap uses defined.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
