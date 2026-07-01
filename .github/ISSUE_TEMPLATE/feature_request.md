---
name: Feature request
about: Propose an addition or improvement to the open core
labels: enhancement
---

## Problem

<!-- Describe the problem you are trying to solve, or the gap in the current behavior.
     Be specific: what can you not do today, or what does the current design get wrong? -->

## Proposed solution

<!-- Describe how you would like to see this addressed. If you have a draft
     implementation in mind, outline the approach. -->

## Alternatives considered

<!-- What other approaches did you consider and why did you rule them out? -->

## Scope and open-core note

<!--
Reeflex has an open-core model. The open core covers:
  - reeflex-core (the engine, policy evaluation, audit)
  - reeflex-spec (the Action Envelope + Adapter Contract)
  - Community adapters that implement the SPEC §6 adapter contract
  - reeflex-claude and reeflex-wordpress (reference adapters)

Out of scope for community contributions:
  - The commercial compliance tier (NIS2/DORA/GDPR reporting, ANAF/SmartBill
    integrations) — this code does not live in the open repos
  - Any change that introduces an LLM or stochastic model into the /v1/decide
    decision path (see ADR-0002 — this is a hard limit)

Please confirm your proposal is in scope, or ask here if unsure.
-->

Does this proposal target the open core? (yes / no / unsure):

Does it affect the decision path (`POST /v1/decide`)? If so, does it
introduce any non-determinism or LLM call? (it must not):

## Additional context

<!-- Anything else — links to relevant issues, specs, prior art. -->
