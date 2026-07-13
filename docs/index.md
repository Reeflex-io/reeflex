---
title: Reeflex documentation
description: >-
  Reeflex is a deterministic gate that decides allow, hold, or deny on an
  AI agent's action before it runs — on any backend, with zero LLM in the
  decision path.
hide:
  - navigation
  - toc
---

<div class="reeflex-hero" markdown>

<span class="tag">Deterministic governance for agent actions</span>

# A seatbelt for the AI acting on your systems

Reeflex decides — *before* an agent's action reaches your data — whether it is
safe to run, needs a human, or must be blocked. Across any backend, with
**zero LLM in the decision path**: same action in, same decision out, every time.

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

The engine is OPA/Rego plus classical logic. **No LLM, no network, no
wall-clock in the decision path** — because a safety mechanism should be
auditable and reproducible, not a second guess. If the engine is unreachable,
it **fails closed**: nothing goes through.

!!! note "This is documentation, not the marketing site"
    For the product pitch, see [reeflex.io](https://reeflex.io/). These docs are
    the reference: concepts, architecture, adapters, policy, operations,
    compliance, and the REST API. Everything here is organized from the honest
    content already in the repository — including [what the base policy does
    **not** catch](concepts/index.md).

---

*New here? Start with **[Getting started](getting-started/index.md)**. Common
questions are in the [FAQ](faq.md); what's shipped vs planned is on the
[Roadmap](roadmap.md).*
