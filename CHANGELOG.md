# Changelog

All notable changes to Reeflex are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project is pre-release.

## [Unreleased]

## [0.1.11] - 2026-07-11

Core decision traceability + concurrency-safe hold consumption — the dependency baseline for the `reeflex-mcp` gateway, which ships in this same tag (0.1.0, its first release). No core decision verdict or decision-logic change; additive only. (Core version realigns to the release tag here: 0.1.9 and 0.1.10 were adapter/channel releases where `reeflex-core` was unchanged, so core skipped them.)

### Added
- **Hold consumption CAS (compare-and-set) guard.** `holds.mark_consumed()` now checks the hold's current status (`== "approved"`) INSIDE the same lock acquisition it uses to append the `consumed` event, instead of appending unconditionally once the hold is found. This closes a latent double-consume race: two concurrent resubmissions of the same approved single-use hold could previously both pass `_validate_approval()` and both reach `mark_consumed()`, and both would be marked consumed and both would be allowed to execute — double-executing an approved-once irreversible action. With the CAS guard, exactly one concurrent caller observes `status == "approved"` and wins the consume; every other caller (racing or merely late) observes a non-`"approved"` status and gets `None` back. `decide.py`'s resubmission path now treats a `None` return from `mark_consumed()` as a hard deny (`reeflex_hold_already_consumed`, rule `reeflex.core/hold_validation`) rather than proceeding to allow, and audits it with both `decision_id` (this refused transit) and `parent_decision_id` (the hold's creating decision). This was previously masked because `server.py` runs a single-threaded `http.server.HTTPServer`; hardened now, ahead of the upcoming threaded `reeflex-mcp` gateway. No API surface change, no new endpoints, no server threading change.
- **`reeflex-mcp` 0.1.0 — MCP gateway adapter (new component).** A transparent MCP proxy that governs any MCP upstream, stdio or streamable-HTTP: aggregates and namespaces every configured upstream's tools (`<upstream>__<tool>`) with zero hardcoded tool knowledge, intercepts `tools/call`, normalizes it into the Action Envelope via a 3-tier resolution (declarative per-server mapping > name-heuristic > conservative default — starters ship for `filesystem`/`github`/`postgres`), asks `reeflex-core`'s `POST /v1/decide`, and enforces the verdict. `allow` forwards and tags core's `decision_id`; `deny` blocks with `rule`/`reason`/`decision_id`; `require_approval` surfaces `hold_id`/`expires_ts` and tracks the pending hold (keyed by session + the canonical action hash) so a client retry is recognized as a resubmission (`approval.parent_decision_id`) — core never executes, the gateway executes after the allow. `observe` mode (default) always forwards and fails open; `enforce` + core unreachable fails closed, proven by the `reeflex-mcp check` self-probe (mirrors `reeflex-claude check`). Obligations (SPEC §5/§7 minimum #5) are read on every decision in both modes — enforce blocks on an unknown obligation (fail closed), observe records it. Lifecycle subcommands `setup`/`restore`/`add`/`import`/`doctor` migrate a client's MCP config (Claude Desktop, `.mcp.json`, `.claude/settings.json`) onto a single governed gateway entry, with backup/restore, and detect configs that bypass the gateway (single-path drift). 287 unit tests pass; conformance-tested per SPEC §7 (all minimums). Zero LLM anywhere near the decision path. See [docs/mcp-gateway.md](docs/mcp-gateway.md). **Not yet published to PyPI** — publication is a gate (human GO), same as every other Reeflex package.
- **Decision traceability: `decision_id` primary key.** Every `/v1/decide` transit (allow / deny / require_approval) now generates a `decision_id` (uuid4 hex), added to the Decision response, the audit record, and the SIEM decision event, so those three surfaces join on an exact key instead of a ts+session heuristic. `envelope_hash` (reusing `holds.canonical_hash()` — the `{action, axes, magnitude, target}` projection already used to bind a hold to its approval) is likewise carried into the audit record and SIEM event. Holds now store the `decision_id` of the decision that created them (`create_hold(..., decision_id=...)`), and a resolved approval resubmission carries `parent_decision_id` — either adapter-supplied via `approval.parent_decision_id` or, as a fallback, resolved from the consumed hold's `decision_id` — so `decision -> hold -> approval -> re-decision` is fully navigable. An opaque W3C trace-context string at `envelope.context.traceparent`, if present, is echoed verbatim into the audit record and SIEM event (no OpenTelemetry SDK, no spans — pure passthrough). All additions are additive/keyword-only with safe defaults; no decision verdict, decision logic, or existing field is changed. SPEC.md and ADAPTER-EXAMPLES.md gain a SHOULD: adapters propagate `decision_id` onto the executed effect (their own log / audit note) so the final link of the chain stitches too.

## [0.1.10] - 2026-07-06

PyPI publish path: `reeflex-claude` and `reeflex-holds` now ship through CI with SLSA provenance via PyPI Trusted Publishing. No runtime behaviour change to either package.

### Changed
- **`reeflex-claude` 0.1.7** — docs: README now states the **Python 3.8+** prerequisite and clarifies that R2/R3 are production-gated and that custom policy environments are supported (from #30). This is the first `reeflex-claude` release published to PyPI **through CI with provenance** (0.1.6 was published manually, without provenance).
- **`reeflex-holds` 0.1.1** — no functional change; the bump exists solely to cut the **first `reeflex-holds` release published to PyPI through CI with provenance** (0.1.0 was published manually, without provenance). Version bumped honestly to carry the provenance publish, since PyPI rejects re-publishing an existing version.

## [0.1.9] - 2026-07-06

n8n community node release-path fix. No change to any component's runtime behaviour.

### Fixed
- **`n8n-nodes-reeflex` now publishes with provenance (0.1.1).** The release workflow's n8n build failed because `npm ci` compiled `isolated-vm` (native, pulled transitively by `@n8n/node-cli`), which is not needed to build/lint/pack the node — so `npm ci --ignore-scripts` is used, and the npm publish job runs npm ≥ 11.5.1 and authenticates via npm OIDC Trusted Publishing (tokenless), which signs the `--provenance` attestation. The node keeps **zero runtime dependencies**. (The previously published `n8n-nodes-reeflex@0.1.0` had no provenance because it was published manually.)

## [0.1.8] - 2026-07-06

Core telemetry hardening for SIEM consumption (Wazuh integration + launch readiness). No decision-path behaviour change; the GHCR core image is rebuilt so `api-dev` runs a baked image rather than a container hotpatch.

### Added
- **Decision telemetry enrichment for SIEM.** The syslog decision event now carries `srcip` (caller IP from `X-Forwarded-For` / peer, named `srcip` so Wazuh GeoIP can enrich it), `namespace` + `agent_id` (the originating module/adapter — e.g. wordpress / claude / n8n), and `target_ref` + `params` (the executed command that produced the decision). The fire-and-forget, non-blocking decision-path invariant is unchanged.

### Fixed
- **Syslog TCP keepalive.** Enable `SO_KEEPALIVE` (plus Linux `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`, ~30s detection) on the syslog connection so a restarted collector (e.g. `wazuh-remoted`) is detected and delivery resumes, instead of silently dropping events on a half-open connection until the core container is restarted.

## [0.1.7] - 2026-07-05

Patch release for the **WordPress adapter** (`reeflex-gate` → 0.1.7). Other components unchanged from 0.1.6 (`reeflex-core` v0.1.5 on GHCR; PyPI/npm unchanged).

### Fixed
- **WordPress adapter — hold fan-out.** A single gated action triggered one `/v1/decide` call — and, when held, one hold — per *registered ability* instead of once, producing duplicate "Pending approvals" rows (the "Reeflex N" badge). A request-scoped decision memo collapses the permission-callback fan-out across all registered abilities to exactly one decision (one hold) per action. The guarantees are unchanged (actor ≠ approver, single-use holds, double-execution dedup).

## [0.1.6] - 2026-07-05

First multi-channel release: the Claude adapter, the holds MCP server, and the n8n community node ship to PyPI / npm alongside the GitHub release and the GHCR core image.

### Added
- **`reeflex-holds` MCP server (first release).** A FastMCP server exposing `list_holds` / `get_hold` / `resolve_hold` / `get_freeze_status` over reeflex-core's Holds API, so an MCP client (e.g. Claude Desktop) can be the approval surface. Env-configured (`REEFLEX_CORE_URL` / `REEFLEX_TOKEN` / `REEFLEX_PRINCIPAL` / `REEFLEX_VERIFY_SSL`); TLS-verify opt-out at parity with the adapters.
- **`n8n-nodes-reeflex` community node (first release).** The "Reeflex Gate" node (allow / hold / deny outputs) + "Reeflex API" credential, plus five importable, story-driven demo workflows preconfigured against the public api-dev eval endpoint — each with an embedded GIF of a real run.
- **reeflex-claude: `REEFLEX_VERIFY_SSL` + `REEFLEX_CORE_TOKEN`.** TLS-verify opt-out (user's risk, default on) and bearer auth, at parity with the WordPress adapter; enables dev/self-signed + authenticated core endpoints (e.g. `api-dev.reeflex.io`).

### Fixed
- **WordPress adapter — double-gating dedup (reeflex-gate 0.1.5).** An MCP-originated action gated twice (the ability's own gate + the MCP adapter layer) created two holds for one call; approving both re-ran the action twice. The adapter now deduplicates by canonical envelope hash + session within a tight creation-time window, so a double-gated action executes **at most once** — the second approval closes its record without re-executing. Corrected the wp-admin docblock/notice that wrongly claimed the companion approval never executes. Regression test (`hold-dedup-regression-demo.php`, D1–D8) added.
- **n8n demo 3 (approval loop).** Resolves holds with a `human` principal (api-dev's default resolution policy is human-only) with an id distinct from the actor (avoids `actor_is_approver`), and regenerates `meta.nonce` on resubmit (core rejects a reused nonce as a replay) — so the decide → hold → resolve → resubmit → allow loop runs end-to-end out of the box in a real n8n.

## [0.1.5] - 2026-07-04

### Added

- **HIL Phase 1: holds queue and resolution API.** `reeflex-core` now materializes `require_approval` verdicts as persistent holds (`app/holds.py`): event-sourced, append-only JSONL store (`audit/holds.jsonl`), in-memory index rebuilt at boot, lazy expiry. Three new HTTP endpoints share the same bearer auth as `/v1/decide`: `GET /v1/holds` (paged list, expiry sweep on list), `GET /v1/holds/{id}` (full detail including envelope), `POST /v1/holds/{id}/resolve` (approve or reject, four-step validation chain).
- **Approval principals: human, agent, automation.** All three types resolve holds via the same API. Shipped default: human-only for all rules (`REEFLEX_RESOLUTION_POLICY` absent). Operators configure allowed types per rule short-name via `REEFLEX_RESOLUTION_POLICY` (JSON string or file path). The `decided_by` field records `type:identity` verbatim (e.g. `human:leo`, `agent:triage-bot`, `automation:camunda-proc-123`) and is the EU AI Act Art. 14 oversight-allocation evidence.
- **Actor != approver, enforced in core.** The agent whose action raised the hold cannot resolve it on any surface via any principal type. Enforced both at resolve time (`POST /v1/holds/{id}/resolve` returns 403 `actor_is_approver`) and at resubmission time (`/v1/decide` returns deny `reeflex_hold_actor_is_approver`).
- **Systemic deny stays terminal.** `irreversible_systemic_prod` is always a terminal `deny`; it never creates a hold and is rejected at resolve time with 403 `rule_not_resolvable`.
- **Single-use, TTL-bound, action-hash binding.** Each hold stores the `sha256` of the action-defining projection (`action`, `axes`, `magnitude`, `target`). A modified action cannot ride an old approval. Holds expire after `REEFLEX_HOLD_TTL_SECONDS` (default 14400 s / 4 h). A consumed hold cannot be reused.
- **Kill-switch / freeze.** `REEFLEX_FREEZE=true` (or `1` / `yes`) denies all non-read verbs immediately with reason `"frozen by operator"`, rule `reeflex.policy/frozen`. Hot-reloadable — no restart required. Read verbs pass through. Freeze flips are audited and fire a webhook event.
- **Outbound hold webhook.** `REEFLEX_WEBHOOK_URL` (optional). Events: `hold.created`, `hold.resolved`, `hold.expired`, `freeze.flipped`. Fire-and-forget, bounded queue (default 1000 slots), drop-on-overflow, 3 s timeout, no retries, at-most-once. Never blocks `/v1/decide`. Enables BPMN/SOAR/n8n automation without vendor connectors — core builds the socket, not the engines.
- **`app/holds.py`**, **`app/webhook.py`** — new modules (Python stdlib only, no new dependencies).
- **`tests/test_hil.py`** — HIL Phase 1 test suite: T1 (hold store), T2a (freeze), T2b/T2c (approval decision path, OPA-dependent), T3 (holds HTTP API), T4 (webhook). OPA-dependent tests are skipped when OPA is absent, consistent with the existing pattern.

### Notes

- Core only. Adapters are unchanged in Phase 1. Phase 2 = adapter re-submission surfaces (WordPress admin, Slack notifier, CLI subcommands).
- Zero LLM in the decision path is unchanged. The `agent` principal type in the resolution policy is AIL: an AI judge the operator explicitly designates, recorded in the audit trail — the first decision (OPA/Rego) remains fully deterministic and LLM-free.
- The `/v1/decide` response gains `hold_id` and `expires_ts` only when the verdict is `require_approval` and hold creation succeeds.

## [0.1.4] - 2026-07-03

### Added
- **SIEM / syslog telemetry.** `reeflex-core` can stream every decision to a configured syslog endpoint — RFC 5424 over UDP (default), TCP (RFC 6587 octet-counted framing), or TLS (RFC 5425) — as structured JSON (default) or CEF. Consumed by Splunk, QRadar, Wazuh, FortiSIEM, Graylog, Grafana Loki, Datadog and friends with zero vendor connectors. Also emits engine lifecycle events; a kill-switch event type is designed for Phase 1. Disabled by default (`REEFLEX_SYSLOG_ENABLED=false`); configured entirely by env (`REEFLEX_SYSLOG_ADDRESS`/`_PROTOCOL`/`_FORMAT`/`_FACILITY`/`_TLS_VERIFY`). Python stdlib only — no new dependencies.
- **The telemetry invariant:** emission is fire-and-forget — a bounded in-memory queue, drop-on-overflow with a dropped-events counter, all socket I/O on a background daemon thread. It can never block or fail `/v1/decide`. "Fail-closed for decisions, fail-open for telemetry." The append-only audit JSONL stays authoritative. Verified: a dead / slow / unreachable endpoint adds zero decision latency.
- `docs/siem.md` — quickstart, the decision-event JSON schema, the CEF mapping + severity tables, and short consuming guides for 11 platforms (Splunk, QRadar, Wazuh, FortiSIEM, Graylog, Loki/promtail, Datadog, Logstash, Filebeat, Fluentd, and a Fluentd/Logstash/Vector → Kafka bridge). Guides only — no vendor code.

### Notes
- Adapters unchanged: the core emits, and observe-mode decisions flow through the same channel (observe + SIEM = "monitor mode").

## [0.1.3] - 2026-07-03

### Added
- **Observe mode (HIL-DESIGN §8, Phase 0)** in both adapters. WordPress: `REEFLEX_MODE` constant (`enforce`|`observe`, default `enforce`) + a Settings "Enforcement mode" dropdown (same locked-field precedence). Claude adapter: `REEFLEX_MODE=observe` env var. In observe, the adapter requests the decision and writes an audit record annotated `mode=observe` with the would-be verdict, but never enforces (the action always proceeds); a core outage **fails open** (never blocks). Enforce behaviour is unchanged. Zero core changes.
- Conformance harness gains observe scenarios (all actions proceed; core-down proceeds + outage audited); Claude adapter gains observe unit tests.

## [0.1.2] - 2026-07-02

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

## [0.1.1] - 2026-07-02

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

## [0.1.0] - 2026-07-02

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
