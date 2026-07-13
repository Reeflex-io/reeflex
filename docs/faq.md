---
title: FAQ
description: >-
  Short answers to the questions people ask first about Reeflex — what it is,
  how to run it, what leaves your infrastructure, and what is open vs commercial.
---

# Frequently asked questions

## About Reeflex

**What is Reeflex?**
A deterministic gate that decides **allow / hold / deny** on an AI agent's
action *before* it runs — on any backend, with **zero LLM in the decision
path**. Same action in, same decision out, every time. See [Concepts](concepts/index.md).

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

## Running it

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
