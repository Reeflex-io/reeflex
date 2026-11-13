---
title: Changelog
description: >-
  Where to find the versioned history of reeflex-core and the adapters, and how
  releases are cut.
---

# Changelog

The canonical, versioned history lives in the repository, kept in
[Keep a Changelog](https://keepachangelog.com/) form:

- **[CHANGELOG.md](https://github.com/Reeflex-io/reeflex/blob/main/CHANGELOG.md)** — every release, with an `Added` / `Changed` / `Fixed` breakdown and the rationale.
- **[GitHub Releases](https://github.com/Reeflex-io/reeflex/releases)** — tagged artifacts (PyPI, npm, GHCR) published from one commit; see [Releasing](../RELEASING.md).

## Current release

**reeflex-core v0.2.3** (2026-10-05). Recent line:

| Version | Summary |
|---|---|
| **0.2.3** | RFX-350: a compound verb whose only known words are reads, declared `irreversible`, is no longer elected `read` — **breaking** for a caller that declares a read irreversible. `/healthz` reports the running commit (`revision`). `reeflex-claude` 0.2.2, `reeflex-holds` 0.2.1, `reeflex-litellm` 0.2.1, `reeflex-mcp` 0.1.5 published. |
| 0.2.2 | See the [CHANGELOG](https://github.com/Reeflex-io/reeflex/blob/main/CHANGELOG.md). |
| 0.2.0 | `REEFLEX_REQUIRE_VERIFIED_APPROVER` defaults to true (**breaking**); an unclassifiable action resolves to a hold under its own rule id (`unclassified_action`), not a deny. |

The [CHANGELOG](https://github.com/Reeflex-io/reeflex/blob/main/CHANGELOG.md)
is the authority for every version; this table is a pointer to it.

## Not in a release yet

- **Physical-impact rules (RFX-427).** Five verbs (`set`, `mode`,
  `override`, `actuate`, `flash`), `target.safety_function`,
  `magnitude.physical`, rules R8–R11 and the `physical_writes` /
  `physical_envelope` budgets — additive; no existing rule id or verdict
  changes. Documented in the [Action Envelope](action-envelope.md#physical-impact-fields)
  and the [policy guide](../policy-guide.md#physical-impact-rules-r8r11-and-two-budgets).
  **reeflex-core v0.2.3 does not have them.**
- **Use cases** (RFX-429): a [section](../use-cases/index.md) with one page
  per scenario, IT and OT. Every printed verdict is checked against the
  engine by `scripts/docs_envelopes_check.py`.
