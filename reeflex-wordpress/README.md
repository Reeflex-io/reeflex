# reeflex-wordpress

> **Status: planned — no adapter code yet.**

The **reference WordPress adapter** and primary beachhead for Reeflex. Its job is to normalize WordPress actions into the universal **Action Envelope**, call `reeflex-core /v1/decide`, and enforce the decision before any WordPress operation executes.

---

## What this adapter does

WordPress is the first concrete target because it is the largest AI-agent attack surface in the SMB segment. The adapter sits at the boundary between an AI agent and WordPress, intercepting operations via the WordPress Abilities API / MCP Adapter and translating them into the three-axis Action Envelope that the engine evaluates.

Four responsibilities (the full contract is in [`../reeflex-spec/SPEC.md`](../reeflex-spec/SPEC.md#6-the-adapter-contract)):

1. **INTERCEPT** — capture the WordPress action before it executes.
2. **NORMALIZE** — produce a valid Action Envelope (verb + three axes + stable `session_id`).
3. **ENFORCE** — submit to core, receive the decision, and apply it: proceed, block, or hold for human approval. Fail closed if core is unreachable.
4. **AUDIT** — emit a signed decision record to the observation plane.

---

## Stack

PHP, hooked into the WordPress Abilities API / MCP Adapter.

---

## Current state

This repository is a scaffold. No adapter code has been written yet. The planned implementation is tracked in [ROADMAP.md](../ROADMAP.md).

The contract this adapter must satisfy is defined in [`../reeflex-spec/SPEC.md`](../reeflex-spec/SPEC.md). The mock adapter in `../reeflex-mock/` is the current worked example for adapter authors; it uses an in-memory store instead of WordPress and demonstrates the full intercept/normalize/enforce/audit loop.

---

## Contributing

Contributions are welcome. If you want to build this adapter, start with the Adapter Contract in [`../reeflex-spec/SPEC.md §6`](../reeflex-spec/SPEC.md#6-the-adapter-contract) and the examples in [`../reeflex-spec/ADAPTER-EXAMPLES.md`](../reeflex-spec/ADAPTER-EXAMPLES.md).

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for build, test, and PR expectations.

---

*Reeflex — governance that isn't another AI.*
