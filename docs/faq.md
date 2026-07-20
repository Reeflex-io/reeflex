---
title: FAQ
description: >-
  Short answers to the questions people ask first about Reeflex — what it is,
  how to run it, what leaves your infrastructure, and what is open vs commercial.
---

# Frequently asked questions

## About Reeflex

**What is Reeflex?**
Reeflex governs what an AI agent may do to your systems — **before it happens**.
It decides allow / hold / deny on the *impact* an action would actually have
(reversibility, blast radius, externality) and on the session's cumulative
activity — not just whether the caller is allowed. On any backend, and
deterministically (zero LLM in the decision path). See [Concepts](concepts/index.md).

**What is a decision firewall?**
A decision firewall is a control point between an AI agent and your systems that
judges each action by its real-world impact — how reversible it is, how wide its
blast radius, whether it reaches outside your systems — and allows it, holds it
for a human, or denies it before it runs. Reeflex is a decision firewall: the
checkpoint idea of a network firewall, moved from packets to **agent actions**.
See [Concepts](concepts/index.md).

**Is there an LLM in the decision path?**
No. `/v1/decide` is OPA/Rego plus classical logic — no LLM, no network, no
wall-clock. Free text, markdown, and OKF documents are never decision inputs.
This is an absolute limit, not a preference — see
[ADR-0002](adr/0002-no-llm-in-decision-path.md).

**What backends does it work with?**
Any, through an **adapter** that normalizes a backend's actions into the
[Action Envelope](reference/action-envelope.md). Shipped today: Claude Code,
WordPress, n8n, and the MCP gateway. Others (`reeflex-postgres`, `reeflex-s3`,
…) are community-built against the public spec — see [Adapters](adapters/index.md).

## How it compares

**How is this different from an AI firewall or an agent firewall?**
It depends on what the firewall inspects. Most tools called an "AI firewall" or
"agent firewall" inspect **traffic**: they scan prompts, tokens, and requests at
the network or model edge for injection, data exfiltration, or policy strings —
useful, and complementary. A **decision firewall** inspects the **action**: it
prices what the action would actually do — reversibility, blast radius,
externality, and the session's cumulative total — and rules allow / hold / deny
before it runs. A prompt can be perfectly clean and the traffic perfectly
authorized while the action itself deletes 500 products; that is the case a
decision firewall is built for. Run both: the traffic scanner for what is said,
the decision firewall for what gets *done*.

**How is this different from Microsoft's Agent Governance Toolkit?**
They cover different halves, and compose. Microsoft's toolkit governs the agents
*you build and run* — an agent-side harness: identity, registration, and
guardrails on the agent itself. Reeflex sits **resource-side**, at the backend
an agent acts on, and decides each action on its **impact** — and on the
*cumulative* impact across a session, so splitting one destructive action into
many small steps (fragmentation) is caught rather than waved through. Use their
harness for agents you own; use Reeflex for the agents — yours *or* others' —
that reach your systems. (The two are complementary, not competitors.)

**How is this different from an identity or permissions layer (IAM, Cerbos, Permit.io)?**
Those answer *"is this caller allowed to do this?"* — identity and role. Reeflex
answers a different question: *"given the impact this action would actually
have, and everything this session has already done, is it safe now?"* A
permission check returns the same **yes** for deleting one record and for
deleting fifty thousand; Reeflex decides on reversibility, blast radius,
externality, and cumulative session state. They compose — keep your access layer
for *who*, add Reeflex for *what the action does*.

## Running it

**How do I stop an AI agent from deleting production data?**
Put a decision firewall in front of the action and run it in **enforce** mode.
Reeflex prices each action on impact, so a bulk or irreversible delete against a
production target is denied or held for a human before it executes — and because
it also tracks the session's cumulative total, an agent can't slip the same
destructive action through by splitting it into many small deletes
(fragmentation). Point your adapter's `target.environment` at `production`, keep
the base policy's bulk-delete and irreversible-action rules (R1–R5), and start in
observe to calibrate, then switch to enforce. Walkthrough:
[Getting started](getting-started/index.md) and the [policy guide](policy-guide.md).

**How do I try it without installing anything?**
One `curl` against the public evaluation endpoint — see
[Getting started](getting-started/index.md#try-a-real-decision-in-30-seconds).
It's dev/eval only, not production.

**What's the difference between observe and enforce mode?**
**Observe** records the verdict it *would* have applied and lets the action
proceed (fails **open**); **enforce** applies it (fails **closed**). Calibrate
in observe against real traffic, then switch — the
[observe → enforce playbook](getting-started/index.md#the-observe-enforce-playbook)
walks through it.

**Does my data leave my infrastructure?**
In the on-prem model — the only production-supported model today — no. You run
`reeflex-core` yourself and no decision data leaves your network. A hosted
variant is on the [roadmap](roadmap.md); its data-transit implications are
covered in [ADR-0001](adr/0001-deployment-model.md).

**Does it run on shared hosting?**
The on-prem engine needs a long-lived process, so it does **not** run on shared
hosting (cPanel/GoDaddy-class). Shared-hosting users are served by the hosted
variant, which is roadmap — see [ADR-0001](adr/0001-deployment-model.md).

**Who can approve a held action?**
An approver you designate — a human (HIL) or an agent you trust (AIL). Core
enforces `actor != approver` (the agent that raised the hold can never resolve
it), a TTL, and envelope-hash binding, and holds are single-use. See
[Why Reeflex](why-reeflex.md#ail) and the [holds API](reference/rest-api.md#holds-api).

**What does the base policy *not* catch?**
Documented honestly rather than hidden — see
[what the base policy does not catch](concepts/index.md) and the
[policy guide](policy-guide.md).

## Open source & licensing

**Is it free?**
The open tier is Apache 2.0 and free — permanently. *Everything that keeps you
safe is free; what you pay for is help proving it.* See
[Open core](open-core.md).

**Can I fork `reeflex-core` and run it commercially?**
Yes — Apache 2.0 permits commercial use. You're running the open-source engine,
not accessing the closed commercial tier. Details in [Open core](open-core.md).

**What's open vs commercial?**
The engine, the adapters, the base policy packs, and the full audit trail are
open. The commercial tier adds *attestation* (audit-ready evidence) and managed
operation — it never appears in any public repo. The exact boundary is in
[Open core](open-core.md).
