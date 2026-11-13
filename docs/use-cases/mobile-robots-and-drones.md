---
title: "Use case: mobile robots and drones"
description: >-
  An agent dispatching missions to mobile robots or drones: arming, missions,
  geofences. What the base pack decides, and what it does not do.
---

# Mobile robots and drones

--8<-- "docs/use-cases/_snippets/ot-not-a-safety-system.md"

## The situation

An operations team lets an agent dispatch a fleet — warehouse AMRs, or
inspection drones over a site — through the fleet manager's MCP server: plan
a mission, arm a vehicle, start it, adjust its geofence. Reeflex is in the
tool path.

## What goes wrong without a gate

Fleet APIs are designed for a dispatcher who checks the map first. An agent
retrying a mission that "failed" because the vehicle was already flying it
arms and launches a second one; an agent asked to "inspect the north fence"
widens the geofence to reach it. Each call is valid, and each one moves mass
in the real world.

## Three representative actions

**Uploading a mission plan to a parked vehicle.** A parameter write to a
vehicle that is not moving, inside the declared geofence. Allowed, and counted.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:dispatch", "session_id": "sess-fleet-0731" },
  "action":    { "namespace": "fleet", "verb": "set", "ability": "mission/upload" },
  "target":    { "kind": "vehicle", "ref": "uav-07", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.2, "unit": "m",
                               "requested": 400.0, "range": [0.0, 2000.0] } },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Arming the vehicle.** Arming is a change of operating mode on a live
vehicle. R11 holds it for the pilot in command, who can see the airspace and
the agent cannot.

**Verdict:** `require_approval` · **rule** `reeflex.policy/mode_change_live`

```json
{
  "agent":     { "id": "agent:dispatch", "session_id": "sess-fleet-0731" },
  "action":    { "namespace": "fleet", "verb": "mode", "ability": "vehicle/arm" },
  "target":    { "kind": "vehicle", "ref": "uav-07", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Moving a geofence boundary past its declared limit.** The geofence is the
safe range; a request beyond it has an `envelope_fraction` above 1.0, and R10a
refuses it in production.

**Verdict:** `deny` · **rule** `reeflex.policy/outside_operating_envelope_prod`

```json
{
  "agent":     { "id": "agent:dispatch", "session_id": "sess-fleet-0731" },
  "action":    { "namespace": "fleet", "verb": "set", "ability": "geofence/set_radius" },
  "target":    { "kind": "geofence", "ref": "site-north", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 1.25, "unit": "m",
                               "requested": 2500.0, "range": [0.0, 2000.0] } },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

If your vehicles' geofence is enforced on board as a safety function, map it
`safety_function: true` instead: any change to it is then refused under R8,
inside or outside the range.

## How to deploy it

[`reeflex-mcp`](../mcp-gateway.md) in front of the fleet manager's MCP server.
The mapping declares `arm`, `disarm`, `takeoff`, `land` and `return-to-home`
as `mode`, and the geofence's limits as the range. The line that matters is
the `mode` mapping for arm/disarm — it is what puts a person in front of every
vehicle leaving the ground.

## What Reeflex does NOT do here

- It does not fly or drive anything, and it is not in the vehicle. Collision
  avoidance, failsafes and return-to-home are on board and act on their own.
- It does not hold a `disarm` or `land` any less than an `arm`: R11 holds every
  mode change on a live vehicle. If you want an agent to be able to land a
  vehicle without asking, that is a policy edit you make and own.
- It does not know where the vehicle is. The geofence range is the mapping's
  declaration; the position is the fleet manager's.
- A pilot's own ground station is not gated. Reeflex governs the agent's
  commands, not the pilot's.
