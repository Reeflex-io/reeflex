---
title: "Reeflex above the safety PLC"
description: >-
  Where Reeflex sits when an AI agent can reach physical equipment: above the
  safety PLC / SIS, at the agent boundary, deciding whether the agent may issue
  a supervisory command. What it is not, the environment mapping, and the
  regulatory context, with sources.
---

# Reeflex above the safety PLC

An AI agent that can write a setpoint, switch a unit to manual, or start a
mission is an operator with no hands on the panel and no fatigue. This page is
about where Reeflex sits in that picture, and what it is not.

--8<-- "docs/use-cases/_snippets/ot-not-a-safety-system.md"

## The layers

```text
  reasoning model / agent          decides WHAT it wants to do
          │  tool call (OPC-UA write, Modbus register, mission upload, …)
          ▼
  adapter (reeflex-mcp mapping)    declares verb, axes, safety_function,
          │                         magnitude.physical  ← controlled document
          ▼
  REEFLEX  /v1/decide              may the agent ISSUE this command?
          │                         allow · require_approval (a human) · deny
          ▼  (only if allowed or approved)
  control system / PLC / BMS       runs the loop, milliseconds
          │
  safety PLC / SIS                 SIL-rated; trips regardless of what is above it
          │
          ▼
  actuator / plant                 the physical outcome
```

Reeflex is the second box from the top. Everything below it keeps working
exactly as it did before you installed it, including — above all — the safety
PLC. Reeflex adds a decision before the command leaves the agent's side; it
removes nothing underneath.

## What it adds at that layer

The physical-impact additions to the Action Envelope (see the
[Action Envelope reference](../reference/action-envelope.md#physical-impact-fields))
give the base pack four questions it can ask about a supervisory command:

| question | envelope field | rule |
|---|---|---|
| Does this touch a safety function, an interlock, an E-stop, an alarm limit? | `action.verb: override`, or `target.safety_function: true` | **R8** `safety_function_override_prod` — deny, no approval overrides it |
| Does the requested value lie outside the declared safe range? | `magnitude.physical.envelope_fraction > 1.0` | **R10a** `outside_operating_envelope_prod` — deny |
| Is it an irreversible physical effect (dose, cut, launch, firmware)? | `verb: actuate` / `flash`, `reversibility: irreversible` | **R9** `physical_irreversible` — a human approves |
| Is it a change of operating mode on a live unit? | `verb: mode` | **R11** `mode_change_live` — a human approves |
| Have many small, in-range steps added up to a large move? | the session's cumulative `physical_envelope` and `physical_writes` | **R10b** — the budget mechanism, a human approves |

The last row is the one no per-command check can see. Forty setpoint steps of
2.5% each are forty in-range commands, and together they are a full-range
sweep. Reeflex's session ledger counts the writes and sums the fractions, and
a human is asked before the session gets there — see
[industrial setpoints](industrial-setpoints.md) for the worked sequence and
which of the two budgets trips first on the shipped defaults.

## The environment mapping

`target.environment` keeps its three values. For physical equipment they mean:

| `target.environment` | means | R8 / R10a (deny) | R9 / R11 (hold) |
|---|---|---|---|
| `production` | the live plant, the real device | armed | armed |
| `staging` | a HIL rig or shadow controller — **real actuators** | armed | not armed |
| `dev` | a digital twin or simulator | not armed | not armed |

`staging` is armed for the deny rules on purpose: a hardware-in-the-loop rig has
real valves on it, and an override there is still an override. In `dev`, none of
R8–R11 arm, so an agent can explore a twin freely — the same command, against
the twin, is allowed.

Which environment a target is in is the adapter's declaration, like
everything else in the envelope. A mapping that labels a live plant `dev`
switches every rule on this page off for it.

## Regulatory context, stated carefully

None of the instruments below names Reeflex, requires a product like it, or is
satisfied by installing one. What follows is where the record Reeflex keeps can
serve as evidence toward an obligation you have — not a claim that it meets
one.

| instrument | what is relevant | applies from | source |
|---|---|---|---|
| EU AI Act, Regulation (EU) 2024/1689, **Annex III point 2** | "AI systems intended to be used as safety components in the management and operation of critical digital infrastructure, road traffic, or in the supply of water, gas, heating or electricity" are high-risk | **2 December 2027** for Annex III systems (Chapter III, Sections 1–3, as amended by the Digital Omnibus on AI) | Regulation (EU) 2026/1744, Art. 1(40), amending Art. 113 third paragraph point (c)(i) of 2024/1689; OJ L, 24.7.2026, [ELI](http://data.europa.eu/eli/reg/2026/1744/oj) |
| EU AI Act **Art. 12** (record-keeping) and **Art. 14** (human oversight) | for high-risk systems: automatic logging of events; measures that let a natural person oversee, intervene, and stop | same date — both are in Chapter III, Section 2 | as above |
| EU AI Act, AI as a safety component of a product under **Annex I** (which lists machinery) | the Annex I route, distinct from Annex III | **2 August 2028** | Regulation (EU) 2026/1744, Art. 1(40), point (c)(ii) |
| **Machinery Regulation (EU) 2023/1230** | replaces Directive 2006/42/EC; covers safety components and machinery with self-evolving behaviour | **20 January 2027** (Art. 54; some provisions earlier). The Digital Omnibus amends Art. 8, 20 and 47 of 2023/1230 and does not change Art. 54 | Regulation (EU) 2023/1230, Art. 54, [ELI](http://data.europa.eu/eli/reg/2023/1230/oj); Regulation (EU) 2026/1744, Art. 3 |
| **NIS2**, Directive (EU) 2022/2555 | cybersecurity risk-management measures (Art. 21) for entities in the energy, transport, drinking water, waste water and manufacturing sectors, among others (Annexes I and II) | Member States apply their transposing measures from **18 October 2024** (Art. 41); national transposition varies | Directive (EU) 2022/2555, [ELI](http://data.europa.eu/eli/dir/2022/2555/oj) |
| **IEC 62443** | the industrial-automation security series. Used on these pages as **vocabulary** (zones, conduits, security levels) — Reeflex is not assessed or certified against it | — | IEC 62443 series |

Two things on that table are easy to misread:

- The AI Act obligations fall on the **provider and deployer of the high-risk
  AI system** — the agent you run. Reeflex is a component you may use to
  produce the logging and oversight record those articles ask for. It does not
  make the system compliant.
- **Art. 14 asks that a human can stop the system.** A `require_approval` hold
  is one mechanism for that at the command level. It is not the only one, and
  it does not replace the operator's own stop.

For what the decision record is and is not as evidence, see
[evidence for an auditor](evidence-for-an-auditor.md).

## Related

- [Industrial setpoints over OPC-UA / Modbus](industrial-setpoints.md)
- [Building management](building-management.md)
- [Lab automation and robotics](lab-automation.md)
- [Mobile robots and drones](mobile-robots-and-drones.md)
- [MCP gateway](../mcp-gateway.md) — the adapter that carries the OT mappings
