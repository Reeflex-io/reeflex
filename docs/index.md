---
title: Reeflex documentation
description: >-
  Reeflex governs what AI agents may do to your systems — before it happens. It
  decides allow, hold, or deny on the impact an action would have, on any
  backend, deterministically (zero LLM in the decision path).
hide:
  - navigation
  - toc
---

<div class="reeflex-hero" markdown>

<span class="tag">Action governance — decided on impact, not identity</span>

# Govern agents you don't own — the documentation

Reeflex governs what an AI agent may do to your systems — *before it happens*.
It decides on the **impact** an action would actually have (how reversible, how
wide its blast radius, whether it reaches outside your system) and on everything
the session has already done — not just whether the caller is allowed. On any
backend, and deterministically: same action in, same decision out (zero LLM in
the decision path).

<div class="cta" markdown>
[Get started](getting-started/index.md){ .md-button .md-button--primary }
[How it works](concepts/index.md){ .md-button }
[View on GitHub](https://github.com/Reeflex-io/reeflex){ .md-button }
</div>

<p class="hero-tease" markdown>Or **[try a real decision in 30 seconds](getting-started/index.md#try-a-real-decision-in-30-seconds)** — one `curl`, no install.</p>

</div>

---

## Where to go

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } &nbsp; **Get started**

    ---

    Install an adapter and watch Reeflex hold a destructive action in minutes —
    Claude Code, n8n, WordPress, or an existing MCP server. Observe-mode
    first, so nothing breaks.

    [:octicons-arrow-right-24: Quickstart](getting-started/index.md)

-   :material-cube-outline:{ .lg .middle } &nbsp; **Concepts**

    ---

    The Action Envelope, the five rules, allow / hold / deny, the fail-closed
    invariant, sessions and anti-fragmentation, and HIL / HOTL / AIL.

    [:octicons-arrow-right-24: Core concepts](concepts/index.md)

-   :material-power-plug-outline:{ .lg .middle } &nbsp; **Adapters**

    ---

    An adapter turns a backend action into an Action Envelope and enforces the
    verdict. Claude Code, WordPress, n8n, MCP gateway — or write your own
    against the spec.

    [:octicons-arrow-right-24: Adapters](adapters/index.md)

</div>

---

## What Reeflex is, in 30 seconds

An AI agent can now write to your database, edit your store, send your emails.
Reeflex sits at that boundary. Every write is intercepted, normalized into a
universal **Action Envelope** (verb + three risk axes + magnitude + session),
and evaluated by an OPA/Rego policy that asks a sharper question than *"is this
user allowed?"* — it asks **"is this action safe, given the impact it would
actually have?"** The answer is one of three:

- <span class="rf-verdict rf-allow">allow</span> — the action proceeds.
- <span class="rf-verdict rf-hold">hold</span> — it waits for an approver you trust (a human, or an agent you trust — HITL / AIL).
- <span class="rf-verdict rf-deny">deny</span> — it is blocked, with a reason the agent can read.

Because the engine reasons over the whole **session**, splitting one destructive
action into many small ones buys nothing — it is the *cumulative* impact that is
judged, not each call in isolation. That per-session memory is the core of the
model.

Determinism is how you can trust it: the engine runs on OPA/Rego plus classical
logic — no LLM, no network, no wall-clock in the decision path — so the same
action always yields the same decision, auditable and reproducible. If the
engine is unreachable it **fails closed**: nothing goes through.

!!! tip "We publish what it does *not* catch"
    A governance tool you can trust is one that tells you where it stops. Reeflex
    documents [**what the base policy does not catch**](concepts/index.md) up
    front — a first-class page, not an appendix.

!!! note "This is documentation, not the marketing site"
    For the product pitch, see [reeflex.io](https://reeflex.io/). These docs are
    the reference: concepts, architecture, adapters, policy, operations,
    compliance, and the REST API — organized from the honest content already in
    the repository.

---

*New here? Start with **[Getting started](getting-started/index.md)**. Common
questions are in the [FAQ](faq.md); what's shipped vs planned is on the
[Roadmap](roadmap.md).*
