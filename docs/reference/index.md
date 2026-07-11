---
title: Reference
description: >-
  Recorded architecture decisions and the release process — the load-bearing
  records behind how Reeflex is built and shipped.
---

# Reference

The recorded decisions and processes that other pages in this documentation
point back to.

- [ADR 0001: deployment model](../adr/0001-deployment-model.md) — engine-as-service,
  the open-core boundary, and the two delivery variants (on-prem now, hosted
  on the roadmap).
- [ADR 0002: no LLM in the decision path](../adr/0002-no-llm-in-decision-path.md) —
  why `/v1/decide` contains zero LLM calls and zero free-text input, and
  where an LLM may legitimately sit (advisory only, outside the decision).
- [Releasing](../RELEASING.md) — the tagged-release flow that publishes to
  GitHub Releases, PyPI, npm, and GHCR from one commit.
