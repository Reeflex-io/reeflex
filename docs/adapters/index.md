---
title: Adapters
description: >-
  An adapter turns a backend action into an Action Envelope and enforces the
  verdict. Claude Code, WordPress, n8n — or write your own against the spec.
---

# Adapters

An adapter is the only backend-specific part of Reeflex. It has four jobs:
**intercept** the action before it runs, **normalize** it into an Action
Envelope, **enforce** the verdict (`POST /v1/decide`), and **audit** the
decision. `reeflex-core` knows nothing about the backend — it decides on the
envelope alone.

| Adapter | Seam it intercepts | Placement | Status |
|---|---|---|---|
| **Claude Code** | PreToolUse hook (every tool call) | Source-side (in the agent) | Reference, on PyPI |
| **WordPress / WooCommerce** | `WP_Ability::execute()` (Abilities API) | Resource-side (in WordPress) | Reference, release ZIP + WP.org queue |
| **n8n** | A gate node before a risky step | Source-side (in the workflow) | Published (`n8n-nodes-reeflex`) |
| **MCP Gateway** | JSON-RPC `tools/call` at the boundary | Network boundary | In development |
| **Your own** | Anywhere you can intercept | Your choice | Build against the spec |

!!! info "Source-side vs resource-side — an honest trade-off"
    A **source-side** adapter (Claude Code, n8n) governs one agent wherever it
    acts, but only that agent. A **resource-side** adapter (WordPress) governs
    *every* caller of a backend, but only that backend. Neither is strictly
    better — the architecture section covers where each leaves gaps.

## The adapters

- **Claude Code** — `pip install reeflex-claude`, then `setup` + `check`.
  Enforce or observe mode, fail-closed by construction. Honest limit: a hook
  the agent can disable is source-side; treat it as a strong default, not a
  sandbox.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-claude)
- **WordPress / WooCommerce** — wraps the Abilities API seam; governs core,
  WooCommerce, and any plugin that registers abilities, with no
  backend-specific code. [Repo](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress)
- **n8n** — a community node (or a plain HTTP Request node) that calls
  `/v1/decide` and routes on the verdict.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/n8n-nodes-reeflex)
- **Writing your own** — implement the four responsibilities against the
  [Adapter Contract](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md).

---

*Full per-adapter pages (setup, environment variables, fail-closed proofs, and
the "what bypasses it" honesty notes) are being added under this section.*
