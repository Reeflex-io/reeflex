---
title: Action Envelope
description: >-
  The universal, backend-agnostic shape every adapter produces and reeflex-core
  decides on — verb, three risk axes, magnitude, session, and approval.
---

# Action Envelope

The Action Envelope is the portable contract between any adapter and the
engine. An adapter's whole job is to normalize a backend action into this
shape; `reeflex-core` reasons only about the envelope and knows nothing about
WordPress, Postgres, or S3. The canonical, versioned definition lives in
[`reeflex-spec/SPEC.md` §2](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md),
with machine-readable JSON schemas alongside it — this page is the reader's
tour.

## Shape

```json
{
  "agent":     { "id": "agent:demo", "session_id": "sess_01H…" },
  "action":    { "namespace": "store", "verb": "delete", "ability": "store/bulk-delete-products" },
  "target":    { "environment": "production" },
  "magnitude": { "count": 200 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

## Fields

| Field | Meaning |
|---|---|
| `agent.id` | Who is acting. |
| `agent.session_id` | Ties actions into one trajectory. R5 tracks cumulative deletes per session, so splitting a big action into many small ones (fragmentation) buys nothing. |
| `action.namespace` | The backend domain (e.g. `store`, `infra`). |
| `action.verb` | The **normalized** verb — `read`, `create`, `update`, `delete`, … — not the backend's raw method name. Normalization is the adapter's responsibility (SPEC §3). Five verbs for physical equipment — `set`, `mode`, `override`, `actuate`, `flash` — are described [below](#physical-impact-fields). |
| `action.ability` | The specific backend capability being invoked. |
| `target.environment` | `production`, `staging`, or `dev`. Some rules only arm in `production`. |
| `target.safety_function` | Optional, default `false`. `true` when the target is a safety function — see [below](#physical-impact-fields). |
| `magnitude.count` | How many items the action touches. |
| `magnitude.physical` | Optional. The declared size of a physical change — see [below](#physical-impact-fields). |
| `axes` | The three risk axes (below) — the heart of the model. |
| `approval` | `{ "present": false }` on a first attempt; on a resubmission after a hold is approved, carries the approval so core can bind it to the exact envelope. |

## The three risk axes

Reeflex prices an action on impact, not on identity. Every action is scored on
three axes:

| Axis | Values | Question |
|---|---|---|
| `reversibility` | `reversible` · `recoverable` · `irreversible` | Can this be undone? |
| `blast_radius` | `single` · `scoped` · `broad` · `systemic` | How much does it touch? |
| `externality` | `internal` · `outbound` · `physical` | Does its effect leave the system? |

The base policy packs (open, Apache-2.0) reason over these axes plus cumulative
session state. For example, `irreversible` + `broad` + `production` →
`require_approval`; `irreversible` + `systemic` + `production` → `deny`
(refused even with approval). See the [policy guide](../policy-guide.md) and
[what the base policy does *not* catch](../concepts/index.md).

## Physical-impact fields

!!! note "Requires a core that carries RFX-427"

    These fields and verbs are additive and optional: an envelope without them
    is decided exactly as before. They are read by rules R8–R11 and two
    budgets, added to the base pack under RFX-427. **reeflex-core v0.2.3 and
    earlier do not read them** — on those versions `set` is treated as
    `update`, the other four verbs fall to core's unknown-verb default, and
    `safety_function` / `magnitude.physical` are ignored.

`axes.externality: physical` has always existed in the model ("SCADA,
robotics, energy"). These fields give the policy something to read about a
physical action beyond that one value.

```json
{
  "action":    { "verb": "set" },
  "target":    { "environment": "production", "safety_function": false },
  "magnitude": { "count": 1,
                 "physical": { "envelope_fraction": 0.4, "unit": "degC",
                               "requested": 48.0, "range": [20.0, 90.0] } },
  "axes":      { "externality": "physical" }
}
```

| Field | Meaning |
|---|---|
| `target.safety_function` | `true` when the target is a safety function, interlock, E-stop, alarm limit, SIL-rated logic, or a safety-PLC parameter. Read by R8. |
| `magnitude.physical.envelope_fraction` | The size of the requested change relative to the declared safe operating range, `>= 0`. `1.0` is a full-range step; **above `1.0` means the requested value lies outside the declared safe range**. Read by R10a and summed per session by the `physical_envelope` budget. How it is computed from a raw request is the adapter mapping's job — see the [MCP gateway](../mcp-gateway.md). |
| `magnitude.physical.unit`, `.requested`, `.range` | Informational. Carried into the decision record so a reviewer can see what the fraction was computed from; no rule reads them. |

| Verb | Meaning | Typical raw actions |
|---|---|---|
| `set` | write a setpoint / parameter / recipe value | OPC-UA write, Modbus write register, `set_temperature`, `write_tag` |
| `mode` | change operating mode | auto↔manual, maintenance, bypass, arm/disarm, start/stop a unit |
| `override` | bypass or alter a safety function | disable interlock, mute an alarm limit, override E-stop, change a SIL parameter |
| `actuate` | cause a physical, non-parametric effect | open valve, move axis, dose, dispense, launch, release, cut |
| `flash` | replace firmware / control logic | firmware update, PLC program download, controller config load |

The five verbs are canonical **only on an envelope that declares
`axes.externality: physical`**, and only spelled whole: a `set` on an
`internal` or `outbound` envelope is still read as `update`, and
`set_temperature` is not `set`. An adapter that cannot classify a physical
action maps it to `update` with `axes.externality: physical` and the most
restrictive axes.

**These are declarations.** `safety_function` and `envelope_fraction` are what
the adapter's mapping says, not something core measures — a wrong safe range in
a mapping is a wrong verdict, so mapping files are controlled documents. For
where this sits relative to the safety PLC, and what it does not claim, see
[Reeflex above the safety PLC](../use-cases/above-the-safety-plc.md).

The hold binding covers these fields: an approval granted for a 0.4 step does
not release a 0.9 step, and an approval for a non-safety target does not
release the same verb on a safety target.

## The Decision

`/v1/decide` returns one of three decisions with total precedence
(`deny > require_approval > allow`):

- <span class="rf-verdict rf-allow">allow</span> — the action proceeds.
- <span class="rf-verdict rf-hold">require_approval</span> — a hold; it waits for an approver you trust (a human, or an agent you trust — HIL / AIL).
- <span class="rf-verdict rf-deny">deny</span> — blocked, with a reason the agent can read.

The engine **fails closed**: if OPA is unreachable or a policy is ambiguous, the
answer is `deny`, never `allow`. The full decision shape — including
`decision_id`, `obligations`, and (for holds) `hold_id` / `expires_ts` — is in
the [REST API reference](rest-api.md#response-fields).
