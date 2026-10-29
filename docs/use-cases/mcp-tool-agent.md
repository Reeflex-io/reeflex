---
title: "Use case: any MCP tool-using agent"
description: >-
  An agent connected to MCP servers you did not write. How reeflex-mcp prices a
  tool it has a mapping for, one it can guess from the name, and one it knows
  nothing about.
---

# Any MCP tool-using agent

## The situation

An agent — Claude Desktop, an IDE assistant, a home-grown agent loop — is
connected to several MCP servers: a CRM, a ticketing system, a file store,
some of them third-party. [reeflex-mcp](../mcp-gateway.md) is the MCP server
the client actually talks to; it fronts the real ones and asks core about each
`tools/call` it relays.

## What goes wrong without a gate

An MCP server's tool list is the server author's description of their own
tools, and nothing more. A tool called `sync_contacts` might read, overwrite or
delete; the agent finds out by calling it. Servers are added in a minute, by
whoever configures the client, and every tool on every server is one call away.

## Three representative actions

reeflex-mcp prices a tool in this order: a declarative mapping file, then the
server's own MCP annotations (only if you set `trust_annotations: true` for
that upstream), then the tool's name, then a floor. Each envelope is what
`reeflex_mcp.normalize.build_envelope` emits for a CRM upstream with no
mapping file, trimmed of transport fields.

**`get_contact` — priced from the name.** A read prefix with no mutating word
after it is believed. Allowed.

**Verdict:** `allow` · **rule** `reeflex.policy/read_only_internal`

```json
{
  "agent":     { "id": "agent:desk", "session_id": "sess-desk-0193" },
  "action":    { "namespace": "crm", "verb": "read", "ability": "crm/get_contact" },
  "target":    { "kind": "get_contact", "ref": "c_88", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

**`sync_contacts` — a tool reeflex-mcp knows nothing about.** No mapping, no
trusted annotation, no recognisable verb in the name. reeflex-mcp declares the
floor: `execute`, irreversible, systemic, outbound. In production that is R3 —
refused, until someone tells the gateway what the tool is.

**Verdict:** `deny` · **rule** `reeflex.policy/irreversible_systemic_prod`

```json
{
  "agent":     { "id": "agent:desk", "session_id": "sess-desk-0193" },
  "action":    { "namespace": "crm", "verb": "execute", "ability": "crm/sync_contacts" },
  "target":    { "kind": "sync_contacts", "ref": null, "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "systemic", "externality": "outbound" },
  "approval":  { "present": false }
}
```

**`delete_contact` on one contact — priced from the name, and allowed.** The
`delete_` prefix gives delete / irreversible, and one id gives `single`. No
base rule holds an irreversible delete of one record (R2 needs `broad`; R6
needs a declared protected asset). It is allowed and counted toward the
session's `deletions` budget. If one contact matters, that is a mapping or a
protected-asset entry you add.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:desk", "session_id": "sess-desk-0193" },
  "action":    { "namespace": "crm", "verb": "delete", "ability": "crm/delete_contact" },
  "target":    { "kind": "delete_contact", "ref": "c_88", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

## How to deploy it

```bash
pip install reeflex-mcp
reeflex-mcp setup      # points your MCP client at reeflex-mcp instead of the upstreams
```

Each upstream in `reeflex-mcp.yaml` declares `target: { system: …, environment: … }`.
The line that matters is **`REEFLEX_MODE=enforce`** — the default is
`observe`, which records verdicts and blocks nothing. Run in observe first,
read which tools hit the floor, and write mappings for the ones you use: a
mapping is how a floor `deny` becomes the right verdict. Full guide:
[MCP gateway](../mcp-gateway.md).

## What Reeflex does NOT do here

- It does not trust the server's description of its own tools unless you
  turn that on per upstream (`trust_annotations: true`).
- It does not make the floor gentle. In production an unknown tool is
  refused; that is a wrong *deny* by design, and it is noisy until mapped.
- **In `staging` and `dev`, the floor is not refused.** R3 is production-only,
  so the same unknown tool on an upstream declared `staging` is allowed (and
  charged to the `external_sends` budget). If a staging upstream has real
  side effects — a HIL rig, a shared sandbox with real customers' data — map
  its tools.
- It does not authenticate the agent or the user. Identity, consent and
  routing for MCP traffic stay with your MCP gateway or IdP.
