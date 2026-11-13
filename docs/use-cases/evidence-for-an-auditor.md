---
title: "Use case: evidence for an auditor"
description: >-
  What the decision stream is, and is not, as evidence that a control over
  AI-agent actions operated — and how an auditor can replay a decision instead
  of trusting the log's account of it.
---

# Evidence for an auditor

## The situation

An organisation runs AI agents against production systems and is audited —
under NIS2 Art. 21(2) today, under DORA if it is a financial entity, and under
the EU AI Act's Art. 12 and 14 for high-risk systems from 2 December 2027. The
auditor asks the question every control is asked: *show me it operated.*

## What goes wrong without a gate

Without a decision point there is nothing to show but logs written after the
fact: the agent's own transcript, the target system's access log. Neither says
whether anything was checked *before* the action ran, by what rule, or who
approved it. And an agent's actions arrive fragmented — four hundred small
calls in a session — so reconstructing "did a person see the dangerous one"
from logs is archaeology, done after the incident.

## Three representative actions

Each of these is a decision an auditor can re-run. The gate is OPA/Rego with no
language model in the decision path, so the same envelope through the same
policy gives the same verdict — the auditor does not have to accept the
record's account of why an action was allowed, held or refused.

**An allowed action** — the record shows the rule that let it through, not just
that nothing stopped it.

**Verdict:** `allow` · **rule** `reeflex.policy/read_only_internal`

```json
{
  "agent":     { "id": "agent:reporting", "session_id": "sess-audit-0001" },
  "action":    { "namespace": "postgres", "verb": "read", "ability": "postgres/query" },
  "target":    { "kind": "table", "ref": "public.invoices", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "reversible", "blast_radius": "scoped", "externality": "internal" },
  "approval":  { "present": false }
}
```

**A held action** — the record carries the hold, and the holds inbox carries
who decided it and when. Those are two sources, and the report reconciles them.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:ops", "session_id": "sess-audit-0002" },
  "action":    { "namespace": "postgres", "verb": "delete", "ability": "postgres/delete_rows" },
  "target":    { "kind": "table", "ref": "public.customers", "environment": "production" },
  "magnitude": { "count": 3200 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

**An action the adapter could not classify** — the adapter sent no axes, core
filled in its most restrictive defaults, and the result is held under its own
rule id rather than refused or allowed. In an Attest report it is counted
separately (`ART14_UNCLASSIFIED_ACTION_HELD`, `DORA9_CONTROL_DID_NOT_CLASSIFY`),
so it cannot read as evidence that a rule caught something.

**Verdict:** `require_approval` · **rule** `reeflex.policy/unclassified_action`

```json
{
  "agent":     { "id": "agent:ops", "session_id": "sess-audit-0003" },
  "action":    { "namespace": "custom", "verb": "delete", "ability": "custom/purge_tenant" },
  "target":    { "kind": "tenant", "ref": "tenant:4471", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { },
  "approval":  { "present": false }
}
```

## How to deploy it

Every adapter writes the decision stream; nothing extra is installed for it.
Core appends each decision to its audit log and can stream it to your SIEM
([SIEM export](../siem.md)). The commercial Attest tier assembles that stream
into a report for one organisation and one period. The line that matters is
the one that keeps the evidence complete: **every gate that acts on
production is registered**, because a report's scope section lists the gates
it covered, and an unregistered gate is invisible to it. The full doctrine —
what each field establishes and what it does not — is
[Evidence for auditors](../compliance/evidence-for-auditors.md).

## What Reeflex does NOT do here

- It does not make you compliant, keep you compliant, or certify anything.
  Reeflex attests; your auditor certifies.
- It cannot see an action a gate never sent it. An agent with a path around
  the gate leaves no record here, and every report states that before its
  evidence.
- It records the decision, not the outcome. An allowed action that then
  failed, or did something other than its envelope declared, is recorded as
  allowed. (For physical equipment: verdict ≠ outcome; Reeflex reads no
  sensor.)
- It cannot detect a fabricated record pushed over the real wire with a real
  gate token. Where a count rests on the gate's account alone, the report
  labels it self-attested.
- The envelope is the adapter's declaration. A replay proves the policy gave
  this verdict for this envelope; it does not prove the envelope described the
  action truthfully.
