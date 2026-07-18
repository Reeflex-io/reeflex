---
title: Adapters
description: >-
  An adapter turns a backend action into an Action Envelope and enforces the
  verdict. Claude Code, WordPress, n8n, MCP gateway — or write your own
  against the spec.
---

# Adapters

An adapter is the only backend-specific part of Reeflex. It has four jobs:
**intercept** the action before it runs, **normalize** it into an Action
Envelope, **enforce** the verdict (`POST /v1/decide`), and **audit** the
decision. `reeflex-core` knows nothing about the backend — it decides on the
envelope alone.

Reeflex's home ground is **resource-side**: put a gate at the backend an agent
acts on and you govern *every* caller of it — the agents you don't own included.
Source-side adapters sit inside an agent instead, and cover the other direction:
they also protect you from **your own** agents. The table leads with the
resource-side and network-boundary adapters for that reason.

| Adapter | Seam it intercepts | Placement | Status |
|---|---|---|---|
| **MCP gateway** | JSON-RPC `tools/call`, in front of any MCP upstream | Network boundary — governs every caller through it | Reference, conformance-tested — source-install (`reeflex-mcp/`); not yet on PyPI |
| **WordPress / WooCommerce** | `WP_Ability::execute()` (Abilities API) | Resource-side (in WordPress) — governs every caller of the site | Reference, release ZIP + WP.org queue |
| **n8n** | A gate node before a risky step | Source-side (in the workflow) | Published (`n8n-nodes-reeflex`) |
| **Claude Code** | PreToolUse hook (every tool call) | Source-side (in the agent) — protects you from your *own* agent | Reference, on PyPI |
| **Your own** | Anywhere you can intercept | Your choice | Build against the spec |

!!! info "Source-side vs resource-side vs network-boundary — an honest trade-off"
    A **source-side** adapter (Claude Code, n8n) governs one agent wherever it
    acts, but only that agent. A **resource-side** adapter (WordPress) governs
    *every* caller of a backend, but only that backend. A **network-boundary**
    adapter (the MCP gateway) governs every call that flows *through* it, but
    a server added directly to the client bypasses it (`doctor` detects this,
    cannot prevent it — see the lifecycle section of
    [docs/mcp-gateway.md](../mcp-gateway.md)). None is strictly better — the
    architecture section covers where each leaves gaps.

## The adapters

- **MCP gateway (`reeflex-mcp`)** — a transparent MCP proxy in front of any MCP
  upstream: aggregates and namespaces every configured upstream's tools,
  intercepts `tools/call`, normalizes via declarative per-server mappings
  (filesystem/github/postgres starters) or a heuristic fallback, and enforces
  the verdict. Governs every caller that flows through it. Both stdio and
  streamable-HTTP transports; `setup`/`add`/`import`/`doctor` migrate and
  drift-check client MCP configs. Not yet on PyPI — install from source.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-mcp) ·
  [Full guide](../mcp-gateway.md)
- **WordPress / WooCommerce** — wraps the Abilities API seam; governs core,
  WooCommerce, and any plugin that registers abilities — *every* agent that
  reaches the site — with no backend-specific code.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress)
- **n8n** — a community node (or a plain HTTP Request node) that calls
  `/v1/decide` and routes on the verdict.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/n8n-nodes-reeflex)
- **Claude Code** — `pip install reeflex-claude`, then `setup` + `check`. The
  source-side case: it **also protects you from your own agent**, gating every
  tool call before it runs. Enforce or observe mode, fail-closed by
  construction. Honest limit: a hook the agent can disable is source-side —
  treat it as a strong default, not a sandbox.
  [Repo](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-claude)
- **Writing your own** — implement the four responsibilities against the
  [Adapter Contract](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md).

---

*Full per-adapter pages (setup, environment variables, fail-closed proofs, and
the "what bypasses it" honesty notes) are being added under this section.*
