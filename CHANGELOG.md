# Changelog

All notable changes to Reeflex are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project is pre-release.

## [0.1.2] - Unreleased

### Changed
- **`reeflex-verify` — fresh agent session per run.** The CLI now sends a unique `Mcp-Session-Id`
  header on every run (override with `--session-id` to pin one). The core binds cumulative
  anti-fragmentation policy state to `session_id` (SPEC §4.1); without a fresh session, repeated
  runs against the same site accumulate into one per-session delete budget and eventually the gate
  holds even read-only actions (rule `reeflex.policy/session_delete_budget`), producing false
  mismatches. Validated 5/5 on a live WordPress site in both the standard and mu install forms.

### Docs
- `reeflex-verify/README.md` now shows a real clean-run screenshot (`docs/img/reeflex-verify-output.png`).
- `ROADMAP.md` records the open policy decision on R5 scope (all-verbs vs destructive-verbs-only).

## [0.1.1] - Unreleased

API hardening ahead of network exposure. The decision path is unchanged.

### Added
- **Optional bearer-token auth on `POST /v1/decide`** — set `REEFLEX_AUTH_TOKEN` to require
  `Authorization: Bearer <token>` (constant-time comparison). Unset/empty = disabled (backward
  compatible — identical behavior to 0.1.0). Missing or invalid token → HTTP 401, fail-closed.
  `GET /healthz` is always unauthenticated so liveness probes work without credentials.
- **Request body size cap** — `REEFLEX_MAX_BODY_BYTES` (default 256 KiB); oversized request → HTTP 413.
- **WordPress adapter — admin Settings page** — Settings > Reeflex Gate (API URL, Token, Verify TLS),
  with wp-config constants taking precedence over and locking the fields; bearer core token
  (`REEFLEX_CORE_TOKEN`) and an optional TLS-verify toggle (`REEFLEX_VERIFY_SSL`, default on; disable
  only for dev/staging certs such as api-dev.reeflex.io).
- **`reeflex-verify` CLI** — operator tool that fires real actions at a live install and prints the
  allow / hold / deny verdict per scenario. Transports over the system `curl` (browser UA + retry) so it
  works against WAF-protected sites, with UTF-8 output. Cross-platform (Windows / Linux / macOS).
- **Release packages** — the WordPress gate as `reeflex-gate-wordpress-standard.zip` and `-mu.zip`, plus
  `reeflex-verify.zip` (the CLI) and `reeflex-test-abilities.zip` (safe test abilities to exercise the gate).

### Security
- Suppressed the HTTP server version banner (no stack / Python-version disclosure).
- Added `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` to every response.
- Sanitized the `invalid_json` error response (no JSON-parser detail leaked to the client).
- Unsupported methods (PUT / DELETE / PATCH) → clean `405` JSON instead of the default HTML page.
- The container now runs as an unprivileged non-root user (uid 10001).

### Notes
- Decision path unchanged: determinism, fail-closed on OPA error, the five reference behaviors, and the
  55/55 engine + 9/9 policy tests all hold. Auth is off by default, so adapters and demos are unaffected.
- TLS termination, rate limiting, and DNS are handled at the deployment edge (reverse proxy), not in-engine.

## [0.1.0] - Unreleased

First public preview: the deterministic decision engine, its contract, a reference adapter, and onboarding.

### Added
- **Action Envelope & Adapter Contract** (`reeflex-spec/`) — the universal action shape (three axes:
  reversibility, blast_radius, externality), the four adapter responsibilities (intercept → normalize →
  enforce → audit), the Decision object, and the v0.1 conformance minimums.
- **`reeflex-core` decision engine** — `POST /v1/decide` (Python + OPA/Rego): envelope validation with
  fail-closed conservative defaults (non-canonical axis values coerce to most-restrictive), strict
  `magnitude.count`, required `agent.session_id`, a per-session cumulative ledger with a fragmentation
  guard (SPEC §4.1), and an append-only JSONL audit. Fail-closed on any OPA error — never `allow`.
  Zero LLM in the decision path. 55/55 engine tests; 9/9 policy tests.
- **Base policy pack (R1–R5)** — read-only-internal → allow; irreversible + broad + production →
  require_approval; irreversible + systemic + production → deny; default allow; session delete-budget
  fragmentation guard.
- **`reeflex-mock` reference adapter + demo** — a contract-conformant adapter over an in-memory store, and
  a five-scenario end-to-end demo (allow; single delete; bulk-delete requiring approval; fragmentation
  resistance; fail-closed on broken OPA) with store before→after read-back assertions.
- **Onboarding** — `INSTALL.md`, `QUICKSTART.md` (clone → "watch it stop a delete"), and per-component READMEs.
- **Architecture & decisions** — `docs/adr/0001-deployment-model.md` (engine-as-service, open-core,
  on-prem-first; hosted = roadmap), `docs/adr/0002-no-llm-in-decision-path.md`, `docs/open-core.md`,
  and `docs/architecture.md` (Mermaid diagrams).
- **Community health** — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md`,
  issue / pull-request templates, and a (not-yet-activated) CI workflow that runs `opa test` + the engine tests.

### Notes
- v0.1 is an early preview. Cryptographic signing of envelopes and audit records, a Postgres-backed
  audit/ledger, a live WordPress install on a real instance, the hosted tier, and an approval workflow are on the
  roadmap (see [ROADMAP.md](ROADMAP.md)) — not yet built. The Claude Code and WordPress reference adapters
  are included and conformance-tested.
- `reeflex-spec/` is the maintained source of truth for the Action Envelope, Adapter Contract, and conformance requirements.
