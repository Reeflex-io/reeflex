---
title: Getting started
description: >-
  Install a Reeflex adapter and watch it hold a destructive action in minutes —
  Claude Code, n8n, WordPress, or an existing MCP server. Observe-mode first,
  so nothing breaks.
---

# Getting started

Reeflex governs an agent's actions through an **adapter** that intercepts each
action, normalizes it into an Action Envelope, asks `reeflex-core` for a
verdict, and enforces it. Pick the adapter that matches where your agent runs.

!!! tip "Observe first, enforce later"
    Every adapter supports **observe mode**: it records the verdict it *would*
    have applied and lets the action proceed, so you can calibrate policy
    against real traffic before turning enforcement on. In observe mode a core
    outage fails **open** (never blocks); in enforce mode it fails **closed**.

## Pick your path

=== "Claude Code"

    Governs every tool call a coding agent makes (Bash, Write, Edit, …) through
    the official PreToolUse hook — a real `rm -rf /` is held or denied before it
    runs.

    ```bash
    # Requires Python 3.8+ (upgrade pip on an old box:
    #   python3 -m pip install --upgrade pip)
    pip install reeflex-claude
    reeflex-claude setup    # writes the PreToolUse hook, fail-closed by default
    reeflex-claude check    # verifies the deny path
    ```

    Full guide: [`reeflex-claude/`](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-claude).

=== "n8n"

    Drop the **Reeflex Gate** node before a risky step; route the workflow on
    the returned verdict (allow / hold / deny).

    ```bash
    npm i n8n-nodes-reeflex   # requires Node.js >= 20.15
    ```

    Five importable demo workflows against the public eval endpoint:
    [`n8n-nodes-reeflex/examples/n8n`](https://github.com/Reeflex-io/reeflex/tree/main/n8n-nodes-reeflex/examples/n8n).

=== "WordPress"

    The reference adapter. It wraps every WordPress Abilities API action at
    `WP_Ability::execute()` — the seam every REST, MCP, and direct-PHP path
    converges on — and returns allow / hold / deny.

    Install the standard plugin from a
    [release ZIP](https://github.com/Reeflex-io/reeflex/releases), set the core
    URL in **Settings → Reeflex Gate**, and trigger a bulk delete to see a hold.
    Full guide:
    [`reeflex-wordpress/`](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress).

=== "MCP gateway"

    Puts the same governance in front of any existing MCP server —
    filesystem, GitHub, Postgres, or your own — with no client rewrite.
    `observe` mode by default; `setup` migrates a client's MCP config for you.

    ```bash
    # Not yet published to PyPI — install from source (repo root):
    cd reeflex-mcp && pip install -e .
    cp reeflex-mcp.yaml.example reeflex-mcp.yaml   # edit: point upstreams: at a real MCP server
    reeflex-mcp --config reeflex-mcp.yaml --transport stdio
    ```

    Full guide: [docs/mcp-gateway.md](../mcp-gateway.md).

## Try it in 30 seconds (no install)

Point any adapter — or a single `curl` — at the public evaluation endpoint
`https://api-dev.reeflex.io` (publicly-trusted certificate; a shared,
rate-limited dev endpoint, not for production). The full request/response
examples live in the **Reference → REST API** section as it lands, each tested
live before it ships.

---

*More detailed getting-started pages (per-adapter walkthroughs, the eval-token
curl, and the observe → enforce playbook) are being added under this section.*
