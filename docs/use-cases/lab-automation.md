---
title: "Use case: lab automation and robotics"
description: >-
  An agent driving liquid handlers, dosing pumps and robot arms in a lab or
  pilot plant. Dose, dispense, move: what the base pack decides, and what it
  does not do.
---

# Lab automation and robotics

--8<-- "docs/use-cases/_snippets/ot-not-a-safety-system.md"

## The situation

A research group lets an agent run experiments end to end: it plans a run,
programs the liquid handler, doses reagents into a reactor, and moves samples
with a robot arm, through the instruments' MCP servers. Reeflex sits in that
tool path.

## What goes wrong without a gate

A planning error turns into material in one step. A unit mistake (mL for µL)
in a dose is a thousand-fold overdose, executed in seconds, and a dispensed
reagent cannot be un-dispensed. An agent retrying a failed step will retry it
again, and each retry is another real dose.

## Three representative actions

**Moving a plate between deck positions.** A reversible, non-parametric
motion — the arm can move it back. Allowed, and counted.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:lab-runner", "session_id": "sess-run-2291" },
  "action":    { "namespace": "robot", "verb": "actuate", "ability": "arm/move_labware" },
  "target":    { "kind": "deck_position", "ref": "deck.B2", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Dosing a reagent into the reactor.** An irreversible physical effect on the
live rig: R9 holds it for the scientist on duty, who sees the declared
quantity and approves or rejects.

**Verdict:** `require_approval` · **rule** `reeflex.policy/physical_irreversible`

```json
{
  "agent":     { "id": "agent:lab-runner", "session_id": "sess-run-2291" },
  "action":    { "namespace": "pump", "verb": "actuate", "ability": "dosing/dispense" },
  "target":    { "kind": "reactor", "ref": "reactor.R2.inlet_a", "environment": "production",
                 "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.3, "unit": "mL",
                               "requested": 15.0, "range": [0.0, 50.0] } },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

**Disabling the enclosure's door interlock to "speed up the run".** The
interlock is a safety function. Overriding it in production is refused under
R8, with no approval path.

**Verdict:** `deny` · **rule** `reeflex.policy/safety_function_override_prod`

```json
{
  "agent":     { "id": "agent:lab-runner", "session_id": "sess-run-2291" },
  "action":    { "namespace": "robot", "verb": "override", "ability": "enclosure/set_interlock" },
  "target":    { "kind": "interlock", "ref": "cell1.door_interlock", "environment": "production",
                 "safety_function": true },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

The same dose against the instrument's simulator (`environment: dev`) is not
held — a dry run is the place for the agent to find its unit mistakes.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:lab-runner", "session_id": "sess-sim-2291" },
  "action":    { "namespace": "pump", "verb": "actuate", "ability": "dosing/dispense" },
  "target":    { "kind": "reactor", "ref": "reactor.R2.inlet_a", "environment": "dev",
                 "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.3, "unit": "mL",
                               "requested": 15.0, "range": [0.0, 50.0] } },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "physical" },
  "approval":  { "present": false }
}
```

## How to deploy it

[`reeflex-mcp`](../mcp-gateway.md) in front of each instrument's MCP server.
The mapping declares dispense and dose tools as `actuate` with
`reversibility: irreversible`; the line that matters is that one — it is what
makes R9 hold the dose instead of counting it.

## What Reeflex does NOT do here

- It does not check the chemistry. A dose inside the declared range, of the
  wrong reagent, is a dose inside the declared range.
- It does not measure what was dispensed. The verdict is about the command;
  the instrument's own log is the record of what happened.
- It does not stop the arm mid-motion. Light curtains, force limits and the
  E-stop are the cell's safety functions and act at their own speed.
- A tool mapped `reversible` that is not, is a dose R9 never sees. The mapping
  is a controlled document.
