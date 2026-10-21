---
title: "Use case: building management (HVAC, access control)"
description: >-
  An agent operating a building management system: HVAC setpoints, operating
  modes, door and access control. What the base pack decides, and what it does
  not do.
---

# Building management: HVAC and access control

--8<-- "docs/use-cases/_snippets/ot-not-a-safety-system.md"

## The situation

A facilities team gives an agent access to the BMS through a Home Assistant or
BACnet MCP server, so it can save energy overnight and answer tenants'
complaints: setpoints, schedules, occupied/unoccupied modes, a door when a
contractor is locked out. Reeflex is in the tool path.

## What goes wrong without a gate

Energy saving and comfort pull the same knobs in opposite directions, and an
agent optimising one will do it on every floor at once. "Save energy tonight"
becomes forty air handlers switched to unoccupied mode at 18:00 in a building
with a night shift; "let the contractor in" becomes a door group unlocked
instead of one door. Each call is a legitimate API call; the problem is the
tempo and the reach.

## Three representative actions

**A zone setpoint, in range.** A small move on one zone's setpoint is the
routine work the agent was given.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:facilities", "session_id": "sess-bms-1102" },
  "action":    { "namespace": "bms", "verb": "set", "ability": "climate/set_temperature" },
  "target":    { "kind": "zone", "ref": "climate.floor4_east", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.1, "unit": "degC",
                               "requested": 21.0, "range": [17.0, 27.0] } },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Switching an air handler to unoccupied mode.** An operating-mode change on a
live unit is held for a person under R11. It is resolvable — a facilities
manager approves it in the portal and the agent's call proceeds.

**Verdict:** `require_approval` · **rule** `reeflex.policy/mode_change_live`

```json
{
  "agent":     { "id": "agent:facilities", "session_id": "sess-bms-1102" },
  "action":    { "namespace": "bms", "verb": "mode", "ability": "hvac/set_occupancy_mode" },
  "target":    { "kind": "air_handler", "ref": "ahu.block_b_2", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Disabling a fire-door hold-open release.** A fire door's release on alarm is
a safety function. Changing it in production is refused under R8, whatever the
agent's reason.

**Verdict:** `deny` · **rule** `reeflex.policy/safety_function_override_prod`

```json
{
  "agent":     { "id": "agent:facilities", "session_id": "sess-bms-1102" },
  "action":    { "namespace": "bms", "verb": "update", "ability": "access/set_door_config" },
  "target":    { "kind": "door", "ref": "door.stair_b_l3.fire_release", "environment": "production",
                 "safety_function": true },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

## How to deploy it

[`reeflex-mcp`](../mcp-gateway.md) in front of the BMS's MCP server, with a
mapping that tags every door-release, fire-damper and smoke-control point
`safety_function: true` and every occupancy/run/stop command `mode`. The line
that matters is the `safety_function` tag — R8 reads nothing else to know a
point is one.

## What Reeflex does NOT do here

- It does not know which points in your BMS are life-safety points. The
  mapping says so, or R8 never fires. A fire-release point mapped as an
  ordinary `update` is an ordinary update.
- It does not hold a single door unlock (`actuate`, reversible) on its own. R9
  holds only **irreversible** physical effects; a door that relocks is not one.
  Count-based budgets still apply.
- It is not the fire panel. Doors, dampers and alarms keep their own hardwired
  behaviour; Reeflex decides only whether the agent's command is issued.
- It does not see the BMS front-end, a technician's laptop, or schedules that
  were written before the agent was gated.
