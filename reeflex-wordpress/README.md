# reeflex-wordpress

The **reference WordPress adapter** for Reeflex. Its job is to intercept
every WordPress Abilities API action before it executes, normalize the
operation into the universal **Action Envelope** (SPEC §2), ask
`reeflex-core POST /v1/decide`, and enforce the decision: allow the action,
block it with a `WP_Error`, or hold it for human approval. Every decision is
deterministic — OPA/Rego evaluated in `reeflex-core`, zero LLM in the
decision path.

> **Open-core boundary.** This adapter (like `reeflex-core` and
> `reeflex-spec`) is Apache 2.0 / open source. The commercial compliance
> tier (NIS2/DORA/GDPR reporting, ANAF/SmartBill integrations) is a
> separate, closed package and is never present in this repository.

---

## Two interception methods

### Method 1 — mu-plugin (primary, recommended)

The files `reeflex-gate.php` + `reeflex-gate/` are dropped into
`wp-content/mu-plugins/`. Must-use plugins load before regular plugins and
cannot be disabled from wp-admin.

Two hooks are registered:

- **Hook A** — `wp_register_ability_args` (filter, WordPress Abilities API).
  This is the **primary blocking seam**. It wraps every registered ability's
  `permission_callback` so that Reeflex gates the action before
  `WP_Ability::execute()` can reach `do_execute()`. Because all paths
  through WordPress — REST API, direct PHP call, and MCP-originated
  `tools/call` — terminate at `WP_Ability::execute()`, Hook A governs all of
  them with a single intercept point.

- **Hook B** — `mcp_adapter_pre_tool_call` (filter, MCP Adapter plugin).
  Defense-in-depth for the MCP tool layer. Fires only for the
  `mcp-adapter/execute-ability` tool and adds MCP-layer fidelity (reads the
  `Mcp-Session-Id` header for session tracking). A `WP_Error` return
  short-circuits `ToolsHandler::call_tool()`. MCP-originated calls activate
  both hooks independently — that double-gate is intentional.

**Use this method** for any WordPress install where the mu-plugins directory
is accessible. It is the most complete form of protection.

### Method 2 — external MCP proxy (defense-in-depth / when WP is not modifiable)

Reeflex sits **between** the AI agent and the WordPress MCP endpoint. The
proxy intercepts `tools/call` JSON-RPC requests, normalizes them into an
Action Envelope, and forwards or drops them based on the core decision.

- Transport: JSON-RPC 2.0 over Streamable HTTP.
- WordPress MCP endpoint: `POST /wp-json/mcp/{namespace}/{route}`
  (default namespace: `mcp-adapter-default-server`).
- The tool name for ability execution: `mcp-adapter/execute-ability`.
- Auth: WordPress Application Passwords; the `Mcp-Session-Id` header from
  the `initialize` handshake must be relayed on every subsequent request.
- On **allow**: the proxy forwards the original request unchanged.
- On **deny** or **require_approval**: the proxy drops the request and
  returns a JSON-RPC error object without reaching WordPress.
- On **core unreachable**: fail closed — drop the request.

**Use this method** when the WordPress install cannot be modified (no
mu-plugins access) or as a network-boundary complement to Method 1. Note:
since Hook A already covers MCP-originated calls, the proxy adds a
network-layer block independently of the in-WP hook.

---

## Quickstart — Method 1

1. Copy `reeflex-gate.php` and the `reeflex-gate/` directory into your
   site's `wp-content/mu-plugins/`.
2. Set the required constant in `wp-config.php`:

   ```php
   define( 'REEFLEX_CORE_URL', 'https://your-reeflex-core-host' );
   ```

3. Verify: trigger any registered ability (e.g. a REST call that exercises
   a delete ability in production) and confirm that a destructive action is
   blocked. Check `wp-content/reeflex-audit.jsonl` for the decision record.

Full install steps for both methods: [INSTALL.md](INSTALL.md).

---

## Configuration

All configuration is read from PHP constants defined in `wp-config.php`.
No secrets are accepted inline — reference them via environment or Vault.

| Constant             | Required     | Default                                    | Description |
|----------------------|--------------|--------------------------------------------|-------------|
| `REEFLEX_CORE_URL`   | **Yes**      | `''` (fail-closed until set)              | Base URL of `reeflex-core`. Must be `https://` in production. `http://` is accepted only for loopback hosts (`127.0.0.1`, `localhost`, `::1`) or when `REEFLEX_ENV=dev`. Any other `http://` URL is rejected as a misconfiguration and every call fails closed. No filter override is possible (the URL is a trust anchor; a later-loading plugin cannot redirect decisions). |
| `REEFLEX_ENV`        | No           | `production`                               | Environment label written into every envelope's `target.environment`. Values: `production`, `staging`, `dev`. |
| `REEFLEX_AGENT_ID`   | No           | `agent:wordpress`                          | Agent identity string for `agent.id` in the envelope. |
| `REEFLEX_AUDIT_LOG`  | No           | `WP_CONTENT_DIR/reeflex-audit.jsonl`      | Absolute filesystem path for the append-only JSONL audit log. The default is outside `uploads/` so the file is not web-accessible. Paths containing `..` are rejected; a path inside `uploads/` generates a warning. |
| `REEFLEX_TIMEOUT`    | No           | `5`                                        | HTTP timeout in seconds for `POST /v1/decide`. Short is correct — the fail-closed path fires on timeout; a long timeout only delays the deny. |

`REEFLEX_CORE_URL` has no built-in default remote host. If the constant is
unset, every decision fails closed immediately. Set it explicitly.

---

## How enforcement behaves

The adapter produces one of four outcomes for every ability execution
attempt:

| Core decision        | HTTP status | `WP_Error` code       | Meaning |
|----------------------|-------------|------------------------|---------|
| `allow`              | —           | —                      | Ability runs normally. |
| `deny`               | 403         | `reeflex_denied`       | A policy rule fired. Action is blocked. |
| `require_approval`   | 202         | `reeflex_hold`         | Action is held for human approval. **Terminal in v0.1** — the re-submission flow is not yet implemented (see roadmap below). |
| Core unreachable / error | 503     | `reeflex_unavailable`  | Infrastructure failure. **Fail closed** — action is denied. This also fires when `REEFLEX_CORE_URL` is unset, when a non-200 HTTP status is returned by core, when the response is not valid JSON, or when the `decision` field is missing. |

Public-facing error messages are intentionally generic. Internal detail
(the rule that fired, the transport failure reason) is written to PHP
`error_log` and to the JSONL audit record, not surfaced to the calling
agent.

### Obligations

When core returns `allow` with obligations, the adapter:

- Fires `do_action('reeflex_obligation', $obligation, $envelope, $decision)` for each obligation, so operators can hook custom handlers.
- Acknowledges `audit:full` (the audit record is already written before enforcement).
- Logs a warning for any obligation it does not recognize, so nothing passes silently.

---

## Status

**Proven:**
- Adapter code (all five classes in `reeflex-gate/`) is written and code-reviewed.
- Offline conformance harness (`tests/conformance-demo.php`) runs the real
  adapter classes against a live `reeflex-core` with WordPress stubbed. All
  seven scenarios pass. Fail-closed behaviour against a dead port is verified.
  See [DEMO.md](DEMO.md) for the full output.
- The in-WordPress live demo (hooks firing inside a real WordPress install,
  before/after verification on actual posts) is described in [DEMO.md](DEMO.md).

**v0.1 roadmap items (not yet implemented):**
- `meta.signature` in the Action Envelope is a stub (`ed25519:stub:...`).
  Full ed25519 signing is pending Vault-backed key management (SPEC §6).
- The human-approval re-submission flow is not implemented. `require_approval`
  decisions are terminal: the action is held and an operator must act manually.
- Audit record cryptographic signing is likewise pending the Vault signing path.
- `trajectory_ref` is emitted as `null`; richer sequence/drift analysis is roadmap.

---

## References

- [SPEC.md](../reeflex-spec/SPEC.md) — Action Envelope, Adapter Contract, conformance requirements.
- [INSTALL.md](INSTALL.md) — full installation instructions for both methods.
- [DEMO.md](DEMO.md) — reproducible demo: offline conformance table + in-WordPress walkthrough.
- [tests/README.md](tests/README.md) — test harness documentation.
- [tests/conformance-demo.php](tests/conformance-demo.php) — the conformance harness itself.

---

*Reeflex — governance that isn't another AI.*
