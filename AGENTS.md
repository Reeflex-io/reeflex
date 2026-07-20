# AGENTS.md — install Reeflex from this file alone

This file is the install-from-a-URL standard for AI coding agents (a
companion to [`docs/llms.txt`](docs/llms.txt), which serves the same summary
on the docs site). An agent with only this document should be able to
install a Reeflex adapter, configure it, and verify it end-to-end — no other
page required.

## What Reeflex is

Reeflex is a **decision firewall** for AI agents. A decision firewall is a
deterministic gate that judges what an AI agent's action would DO — its
reversibility, blast radius, and cumulative session impact — and allows,
holds, or denies it before it reaches your systems, independent of which
agent is asking.

The decision is made by OPA/Rego plus classical logic against a universal
**Action Envelope** ([`reeflex-spec/SPEC.md`](reeflex-spec/SPEC.md)). Zero
LLM in the decision path; free text (including OKF/markdown) is never a
decision input.

## Install (pick your adapter)

Each adapter implements the same four contract responsibilities
(intercept -> normalize -> enforce -> audit) against the same
`reeflex-core` `/v1/decide` endpoint.

### Claude Code (`reeflex-claude`)

```bash
pip install reeflex-claude
reeflex-claude setup   # writes the fail-closed PreToolUse hook into .claude/settings.json
reeflex-claude check   # verifies the deny path: fails closed if core is unreachable
```

Restart Claude Code after `setup`. From the next tool call on, every action
passes through the gate. Details: [`reeflex-claude/README.md`](reeflex-claude/README.md).

### MCP gateway (`reeflex-mcp`)

```bash
pip install reeflex-mcp
reeflex-mcp setup    # migrates client MCP configs (Claude Desktop, Claude Code, etc.) onto the governed path; backs up the originals
reeflex-mcp check    # fail-closed self-probe: a real tools/call is denied when core is unreachable
```

`reeflex-mcp` is a transparent proxy in front of any MCP upstream (stdio or
streamable-HTTP). Details: [`reeflex-mcp/README.md`](reeflex-mcp/README.md),
[`docs/mcp-gateway.md`](docs/mcp-gateway.md).

### n8n (`n8n-nodes-reeflex`)

Install the community node from n8n's UI — **Settings -> Community Nodes ->
Install** -> package name `n8n-nodes-reeflex` — or via npm:

```bash
npm install n8n-nodes-reeflex
```

Add the **Reeflex Gate** node to a workflow. Details:
[`n8n-nodes-reeflex/`](n8n-nodes-reeflex/).

### WordPress (`reeflex-gate`)

Download the plugin zip from the
[latest GitHub release](https://github.com/Reeflex-io/reeflex/releases),
then in wp-admin: **Plugins -> Add New -> Upload Plugin** -> choose the zip
-> **Install Now** -> **Activate** -> configure under **Settings -> Reeflex
Gate**. (A WordPress.org directory listing is submitted and pending review —
the GitHub release zip is the current install path.) Details:
[`reeflex-wordpress/README.md`](reeflex-wordpress/README.md).

## Configure

Every adapter reads the same two core variables:

| Variable | Meaning |
|---|---|
| `REEFLEX_CORE_URL` | your `reeflex-core` endpoint, e.g. `http://127.0.0.1:8080` (self-hosted), or `https://api-dev.reeflex.io` for the public eval endpoint (see Verify, below) |
| `REEFLEX_CORE_TOKEN` | optional bearer token, sent as `Authorization: Bearer <token>` |
| `REEFLEX_VERIFY_SSL` | default `true` (full TLS verification); set `false` only for a self-signed/internal core, at your own risk |

Start each adapter in **observe** mode first — every verdict is recorded to
the audit log, nothing is enforced, so a policy misconfiguration or
connectivity issue cannot block real work. Switch to **enforce** once you
have reviewed the observe-mode audit log. Each adapter's own `REEFLEX_MODE`
env var (or its `setup --mode` flag) controls this; see the per-adapter
README linked above for the exact variable name and default.

## Verify (30 seconds)

Self-hosted core exposes `POST /v1/decide`. You can also try the same call
right now against the public development endpoint, no deployment required
(copied byte-for-byte from the repo README so this block, the README, and
the site's `llms.txt` stay in sync):

```bash
curl -s https://api-dev.reeflex.io/v1/decide \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer reeflex-eval-public-2026' \
  -d '{"action": {"verb": "delete", "ability": "wordpress/delete-post"}, "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"}, "magnitude": {"count": 50}, "target": {"environment": "production"}, "agent": {"session_id": "sess-eval"}}'
```

Expected shape (allow / require_approval / deny — this example trips the
irreversible-broad-prod rule, so expect `require_approval`):

```json
{
  "decision": "require_approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "reason": "irreversible broad change in production requires human approval"
}
```

Token: `reeflex-eval-public-2026` — **public dev/eval endpoint and token: may
reset or rate-limit anytime; not for production.** It carries a valid,
publicly-trusted Let's Encrypt certificate, so keep `REEFLEX_VERIFY_SSL` at
its secure default (`true`) — no change needed to reach it.

For a self-hosted core instead, swap the URL/token and drop the `Bearer`
header if your deployment has no auth configured:

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## Fail-closed, always

If an adapter cannot reach `reeflex-core` (timeout, connection error, bad
response) in **enforce** mode, it fails **CLOSED** — the action is blocked
or held, never silently allowed. This is true even for a malformed or
unexpected core response. **Observe** mode is the one intentional exception:
it fails OPEN (never blocks) because its entire purpose is dry-run
calibration, not enforcement — the tradeoff is documented per adapter.

## Links

- [`reeflex-spec/SPEC.md`](reeflex-spec/SPEC.md) — the Action Envelope and Adapter Contract (the four responsibilities: intercept, normalize, enforce, audit)
- [`reeflex-spec/IMPACT-MODEL.md`](reeflex-spec/IMPACT-MODEL.md) — how impact is computed, including [what the base policy does not catch](reeflex-spec/IMPACT-MODEL.md#what-the-base-policy-does-not-catch) (honest limits, not a claim to catch every harm)
- [https://docs.reeflex.io](https://docs.reeflex.io) — full documentation site (getting started, concepts, architecture, reference)
- Per-adapter READMEs: [`reeflex-claude/README.md`](reeflex-claude/README.md) · [`reeflex-wordpress/README.md`](reeflex-wordpress/README.md) · [`reeflex-mcp/README.md`](reeflex-mcp/README.md) · [`n8n-nodes-reeflex/`](n8n-nodes-reeflex/)
- [`reeflex-mock/`](reeflex-mock/) — a worked in-memory reference adapter, for writing your own against the spec
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build a new adapter or extend the base policy
