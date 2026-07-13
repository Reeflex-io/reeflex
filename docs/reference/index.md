---
title: Reference
description: >-
  The exact contracts and records behind Reeflex — the REST API, the Action
  Envelope, configuration, the changelog, and the architecture decisions.
---

# Reference

The precise, load-bearing records the rest of these docs point back to.

<div class="grid cards" markdown>

-   **[REST API](rest-api.md)**

    ---

    `POST /v1/decide`, the holds API, health, auth, and errors — every request
    and response captured live against the engine.

-   **[Action Envelope](action-envelope.md)**

    ---

    The universal shape every adapter produces: verb, three risk axes,
    magnitude, session, and approval.

-   **[Configuration](configuration.md)**

    ---

    Every environment variable — the engine server, policy, audit, holds,
    freeze, SIEM, and the adapter → core client trio.

-   **[Changelog](changelog.md)**

    ---

    The versioned history of `reeflex-core` and the adapters, and how releases
    are cut.

</div>

## Recorded decisions & process

- [ADR 0001: deployment model](../adr/0001-deployment-model.md) — engine-as-service,
  the open-core boundary, and the two delivery variants (on-prem now, hosted
  on the roadmap).
- [ADR 0002: no LLM in the decision path](../adr/0002-no-llm-in-decision-path.md) —
  why `/v1/decide` contains zero LLM calls and zero free-text input, and where
  an LLM may legitimately sit (advisory only, outside the decision).
- [Releasing](../RELEASING.md) — the tagged-release flow that publishes to
  GitHub Releases, PyPI, npm, and GHCR from one commit.
