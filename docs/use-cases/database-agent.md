---
title: "Use case: a database agent on Postgres"
description: >-
  An agent with a Postgres MCP server: schema inspection, ad-hoc SQL, data
  fixes. What reeflex-mcp's shipped Postgres mapping declares, what the base
  pack decides, and the limit of a mapping that cannot see the SQL.
---

# A database agent on Postgres

## The situation

An analyst or an ops team gives an agent a Postgres MCP server
(`crystaldba/postgres-mcp`) so it can answer questions and fix data: list
schemas, explain a query, run SQL. [reeflex-mcp](../mcp-gateway.md) sits
between the agent's MCP client and that server, with the Postgres mapping it
ships.

## What goes wrong without a gate

The useful tool and the dangerous tool are the same tool: `execute_sql`. A
`DELETE` with a mistyped `WHERE`, an `UPDATE` with none, a `TRUNCATE` to "reset
the test data" against the wrong connection — each is one call, and each
completes before anyone reads it. An agent fixing data at scale issues
hundreds of them.

## Three representative actions

Each envelope is what `reeflex_mcp.normalize.build_envelope` emits with the
shipped `postgres.yaml` mapping, trimmed of transport fields.

**Listing the objects in a schema.** Mapped as a read. Allowed.

**Verdict:** `allow` · **rule** `reeflex.policy/read_only_internal`

```json
{
  "agent":     { "id": "agent:analyst", "session_id": "sess-pg-3310" },
  "action":    { "namespace": "postgres", "verb": "read", "ability": "postgres/list_objects" },
  "target":    { "kind": "list_objects", "ref": null, "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

**`execute_sql` with a `DELETE`.** The mapping declares `execute_sql` as the
worst case it can be — delete / irreversible / broad — because it cannot see
the statement. In production that is R2: held for a person to decide.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:analyst", "session_id": "sess-pg-3310" },
  "action":    { "namespace": "postgres", "verb": "delete", "ability": "postgres/execute_sql" },
  "target":    { "kind": "execute_sql", "ref": null, "environment": "production" },
  "params":    { "upstream": "postgres", "tool_name": "execute_sql",
                 "arguments": { "sql": "DELETE FROM orders WHERE created_at < '2024-01-01'" } },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

**`execute_sql` with a `SELECT`.** The same tool, the same declaration, the
same hold. This is the cost of a mapping that cannot read SQL: every
`execute_sql` in production asks a person, including the harmless ones. It is
a wrong *hold*, not a wrong *allow*, and it is the honest default.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:analyst", "session_id": "sess-pg-3310" },
  "action":    { "namespace": "postgres", "verb": "delete", "ability": "postgres/execute_sql" },
  "target":    { "kind": "execute_sql", "ref": null, "environment": "production" },
  "params":    { "upstream": "postgres", "tool_name": "execute_sql",
                 "arguments": { "sql": "SELECT count(*) FROM orders" } },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

If the noise is too much, the fix is to give the agent the read-only tools for
reads (they are mapped as reads), not to soften `execute_sql`'s mapping.

## How to deploy it

```bash
pip install reeflex-mcp
```

In `reeflex-mcp.yaml`, the upstream declares its environment
(`target: { system: postgres, environment: production }`), and the shipped
`postgres.yaml` mapping applies. The line that matters is **`REEFLEX_MODE`**
(or `mode:` in the YAML): reeflex-mcp **defaults to `observe`**, which records
every verdict and blocks nothing. Set `enforce` when you have read the
observe-mode log. Full guide: [MCP gateway](../mcp-gateway.md).

## What Reeflex does NOT do here

- It does not parse SQL. The mapping prices the tool, not the statement, so
  a `SELECT` and a `DROP` through `execute_sql` get the same verdict.
- It does not count rows. `magnitude.count` is 1 for every call; how many
  rows a `DELETE … WHERE` hits is not in the call, and the mapping has no
  magnitude rule for it.
- It does not hold anything in `staging` or `dev` on these axes: R2 is
  production-only. The same `DELETE` against an upstream declared `staging`
  is allowed (and counted).
- It does not see a connection that does not go through reeflex-mcp — a
  second MCP server, `psql` in a shell (that is
  [the coding-agent page](coding-agent.md)), the application itself.
