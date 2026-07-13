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

**reeflex-core v0.1.12.** Recent line:

| Version | Summary |
|---|---|
| **0.1.12** | Kill-switch SIEM emit on a freeze flip; `reeflex-mcp` 0.1.1. No `/v1/decide` contract change. |
| 0.1.11 | Decision traceability (`decision_id`) + concurrency-safe hold consumption (CAS guard); `reeflex-mcp` 0.1.0 (MCP gateway adapter). Additive; no decision-verdict change. |

The engine follows semantic versioning; the `/v1/decide` request/response
contract in this Reference is stable across the current line (v0.1.11–v0.1.12).
Adapter and channel releases may consume version numbers where `reeflex-core`
itself is unchanged — the CHANGELOG notes each case.
