---
title: "Use case: industrial setpoints over OPC-UA / Modbus"
description: >-
  An agent tuning a process line through OPC-UA or Modbus writes. What the base
  pack decides for an in-range step, an interlock override and an out-of-range
  request, and how forty small steps are caught as one move.
---

# Industrial setpoints over OPC-UA / Modbus

--8<-- "docs/use-cases/_snippets/ot-not-a-safety-system.md"

## The situation

A process engineer gives an agent write access to a line's OPC-UA server (or a
Modbus gateway) so it can tune setpoints — reactor temperature, feed rate,
dwell time — from the historian's trends. The agent reaches the server through
an MCP tool, and Reeflex sits in that tool path.

## What goes wrong without a gate

Nothing per-command looks wrong. The agent wants the reactor hotter and, being
careful, moves the temperature setpoint in steps of 2.5% of the declared safe
range: 40 writes, each in range, each small, a few seconds apart. A per-write
limit passes every one of them. Forty of them is a full-range sweep, done at
machine tempo in a few minutes, by something that never stopped to look at
the product. The same agent, asked to "clear the alarm", is one tool call away
from muting the high-temperature limit.

## Three representative actions

**An in-range step on the live line.** A 5% move, inside the declared range,
on a tag that is not a safety function. Nothing in the pack objects; the step
is counted toward the session's budgets.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-line3-0417" },
  "action":    { "namespace": "opcua", "verb": "set", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempSP",
                 "environment": "production", "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.05, "unit": "degC",
                               "requested": 68.5, "range": [20.0, 90.0] } },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Muting the high-temperature alarm limit.** The target is a safety function,
so R8 refuses it in production. No approval releases it; the fix is a change
made through your plant's own management-of-change process, not by the agent.

**Verdict:** `deny` · **rule** `reeflex.policy/safety_function_override_prod`

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-line3-0417" },
  "action":    { "namespace": "opcua", "verb": "override", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempHH.Enable",
                 "environment": "production", "safety_function": true },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**A setpoint outside the declared safe range.** `envelope_fraction` above 1.0
means the requested value lies outside the range the mapping declares safe. R10a
refuses it in production and staging.

**Verdict:** `deny` · **rule** `reeflex.policy/outside_operating_envelope_prod`

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-line3-0417" },
  "action":    { "namespace": "opcua", "verb": "set", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempSP",
                 "environment": "production", "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 1.1, "unit": "degC",
                               "requested": 97.0, "range": [20.0, 90.0] } },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

### The forty steps

Core keeps a per-session ledger, and two of its budgets are physical:
`physical_writes` (10 per session by default) counts physical writes, and
`physical_envelope` (1.0 per session by default) sums `envelope_fraction` —
"a full-range sweep once per session without a human". Both are policy data in
`budgets.rego`, editable per deployment and per principal.

Replay the forty 2.5% steps through one session. On the shipped defaults the
**write count** is what trips, at step 11 — the fractions have only added up to
0.275 by then:

**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget` · **call** 11 · **reason contains** `physical_writes` — steps 1–10 are this same envelope, each allowed.

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-line3-0417" },
  "action":    { "namespace": "opcua", "verb": "set", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempSP",
                 "environment": "production", "safety_function": false },
  "magnitude": { "count": 1, "physical": { "envelope_fraction": 0.025 } },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

The **envelope** budget is the one that sees fewer, larger moves. Six steps of
18% each stay under the write count, and the sixth takes the session's sum
from 0.90 to 1.08:

**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget` · **call** 6 · **reason contains** `physical_envelope` — steps 1–5 are this same envelope, each allowed.

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-line3-0418" },
  "action":    { "namespace": "opcua", "verb": "set", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempSP",
                 "environment": "production", "safety_function": false },
  "magnitude": { "count": 1, "physical": { "envelope_fraction": 0.18 } },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

If you raise `physical_writes` for a principal (say, to 40 for a tuning
agent), the forty-step sequence is then held on `physical_envelope` instead, at
the step whose running sum first exceeds 1.0.

**The same forty steps against the digital twin** — `environment: dev` — are not
held by any physical rule or budget. Exploring a twin is what twins are for. The
writes are still recorded in the session's ledger, so run twin work in its own
session: the same session moving on to the live line carries its twin writes
with it.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow` · **call** 11 — steps 1–10 are this same envelope, each allowed.

```json
{
  "agent":     { "id": "agent:line3-tuner", "session_id": "sess-twin-0417" },
  "action":    { "namespace": "opcua", "verb": "set", "ability": "opcua/write_node" },
  "target":    { "kind": "opcua_node", "ref": "ns=2;s=Line3.Reactor1.TempSP",
                 "environment": "dev", "safety_function": false },
  "magnitude": { "count": 1, "physical": { "envelope_fraction": 0.025 } },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

## How to deploy it

Put [`reeflex-mcp`](../mcp-gateway.md) between the agent and the OPC-UA (or
Modbus) MCP server, with a mapping file that declares, per node or register:
the verb, `safety_function`, and the safe range from which
`magnitude.physical.envelope_fraction` is computed. The line that matters is
the safe range — it is what R10a and the envelope budget read.

A tool the mapping does not name is not passed through as harmless:
reeflex-mcp gives it the most restrictive axes (see the
[MCP tool-using agent](mcp-tool-agent.md) page). That floor's externality is
`outbound`, not `physical`, so an unmapped tool is decided by R3 and the IT
rules and never reaches R8–R11 or the physical budgets. In `production` R3
refuses it; in `staging` — a rig with real actuators — no rule does, and it is
allowed. Map every write tool on an OT upstream; a per-upstream physical floor
is tracked as RFX-431.

## What Reeflex does NOT do here

- It does not know the reactor's temperature. `envelope_fraction` is what the
  mapping declares from the requested value and the range in the mapping file;
  Reeflex reads no sensor and does not confirm the step happened.
- It does not stop a step that is in range, small, and early in the session.
  The first ten 2.5% steps run.
- It does not replace the high-temperature trip. If the agent's writes, or
  anything else, drive the process to the trip point, the SIS trips it,
  whatever Reeflex decided.
- It does not see a write that does not go through the gated tool — an
  engineering workstation, a second MCP server without reeflex-mcp in front of
  it, a script on the historian.
- A wrong `range` in the mapping is a wrong verdict. Treat mapping files as
  controlled documents: reviewed, versioned, and changed under your plant's
  change process.
