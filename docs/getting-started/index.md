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

## Try a real decision in 30 seconds

No install, no signup. Send one action to the public evaluation endpoint and
watch Reeflex **hold** a dangerous bulk delete instead of running it:

```bash title="Ask Reeflex to approve deleting 200 products in production"
curl -s https://api-dev.reeflex.io/v1/decide \
  -H "Authorization: Bearer reeflex-eval-public-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":     { "id": "agent:demo", "session_id": "try-it-30s" },
    "action":    { "namespace": "store", "verb": "delete", "ability": "store/bulk-delete-products" },
    "target":    { "environment": "production" },
    "magnitude": { "count": 200 },
    "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
    "approval":  { "present": false }
  }'
```

Reeflex returns `require_approval` — the delete is held for a human, not run:

```json
{
  "decision": "require_approval",
  "reason": "irreversible broad change in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "hold_id": "1bdbbcd1...",
  "expires_ts": "2026-07-11T18:24:35Z"
}
```

!!! note "About the eval endpoint"
    `api-dev.reeflex.io` is a shared, rate-limited evaluation endpoint with a
    publicly-trusted certificate (keep `verify_ssl` **on** — no `-k` needed).
    The token above is a public eval token: dev/eval only, not for production.
    Change `target.environment` to `dev` or `staging` and the same action is
    allowed — R2/R3 only arm in `production`.

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

    ```bash title="Claude Code — install & wire the hook"
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

    ```bash title="n8n — install the node"
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

    ```bash title="MCP gateway — run from source"
    # Not yet published to PyPI — install from source (repo root):
    cd reeflex-mcp && pip install -e .
    cp reeflex-mcp.yaml.example reeflex-mcp.yaml   # edit: point upstreams: at a real MCP server
    reeflex-mcp --config reeflex-mcp.yaml --transport stdio
    ```

    Full guide: [docs/mcp-gateway.md](../mcp-gateway.md).

---

*More detailed getting-started pages (per-adapter walkthroughs and the
observe → enforce playbook) are being added under this section. The full REST
API reference — every request/response tested live — lands in
[Reference](../reference/index.md).*
