# INSTALL.md — Reeflex WordPress Adapter

The adapter ships in **two delivery forms** — a standard plugin (installed from
the wp-admin UI, configured via a Settings screen) and a mu-plugin (dropped
into `wp-content/mu-plugins/`, configured via constants). Both register the
same hooks, POST to the same `reeflex-core /v1/decide` endpoint, and enforce
the same decisions. A quick overview of both forms is in
[README.md](README.md#installing-the-adapter--two-delivery-forms); this file
is the detailed procedure.

---

## Prerequisites

| Requirement | Version |
|---|---|
| PHP | 7.4 or higher |
| WordPress | **6.9 or higher** (Abilities API is core as of 6.9) |
| MCP Adapter (`wordpress/mcp-adapter`) | v0.5.0; required only if you use MCP traffic or Hook B |
| `reeflex-core` | Running and reachable — your own deployment, or `https://api-dev.reeflex.io` for testing (see the note below) |

> **Testing against `api-dev.reeflex.io`:** our public dev endpoint carries a
> valid, publicly-trusted Let's Encrypt certificate, so no special TLS
> configuration is needed — leave certificate verification at its secure
> default (**on**), both in the standard plugin's Settings checkbox and in
> the mu-plugin's `REEFLEX_VERIFY_SSL` constant. It is still a shared dev/eval
> endpoint, not for production, and may reset or change at any time.

---

## Option A — Standard plugin (installs from the UI)

1. Download `reeflex-gate-wordpress-standard.zip` from the
   [latest release](https://github.com/Reeflex-io/reeflex/releases).
2. wp-admin → **Plugins → Add New → Upload Plugin** → choose the zip →
   **Install Now** → **Activate**.
3. **Settings → Reeflex Gate**: set **API URL** (required), **Token**
   (optional), and leave **Verify TLS certificate** on — including when
   pointing at `api-dev.reeflex.io`.
4. Verify (see "Verification" at the end of this file).

Constants in `wp-config.php` (below) override Settings fields and lock them
in the UI — useful for pinning configuration in code on managed hosts.

---

## Option B — mu-plugin (must-use, hardened)

The mu-plugin intercepts at the WordPress Abilities API layer. Every ability
execution — whether triggered via REST API, direct PHP call, or an MCP
`tools/call` — passes through `WP_Ability::execute()`, which invokes the
wrapped `permission_callback`. That single seam is the gate.

Must-use plugins cannot be deactivated from wp-admin.

### Files

```
wp-content/
  mu-plugins/
    reeflex-gate.php          <-- loader; requires the class files below
    reeflex-gate/
      class-reeflex-config.php
      class-reeflex-normalizer.php
      class-reeflex-core-client.php
      class-reeflex-audit.php
      class-reeflex-gate.php
```

### Install steps

1. **Copy the files.**

   Copy `reeflex-gate.php` and the entire `reeflex-gate/` directory into
   your site's `wp-content/mu-plugins/` directory. The directory must sit
   alongside the loader file, not nested inside it:

   ```
   wp-content/mu-plugins/reeflex-gate.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-config.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-normalizer.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-core-client.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-audit.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-gate.php
   ```

2. **Set configuration constants in `wp-config.php`.**

   At minimum, set `REEFLEX_CORE_URL`. Without it, every decision fails
   closed immediately.

   ```php
   // Required — base URL of your reeflex-core instance.
   // https:// is always accepted.
   // http:// is accepted only for loopback hosts (127.0.0.1, localhost, ::1).
   // Any other http:// URL is rejected unconditionally; decide() fails closed.
   define( 'REEFLEX_CORE_URL', 'https://your-reeflex-core-host' );

   // Optional — defaults shown.
   define( 'REEFLEX_ENV',      'production' );  // production | staging | dev
   define( 'REEFLEX_AGENT_ID', 'agent:wordpress' );
   define( 'REEFLEX_AUDIT_LOG', '/var/www/html/wp-content/reeflex-audit.jsonl' );
   define( 'REEFLEX_TIMEOUT',  5 );
   ```

   `REEFLEX_CORE_URL` is read-only from constants; no WordPress filter can
   override it at runtime. This prevents a compromised plugin from redirecting
   governance decisions to an attacker-controlled endpoint.

3. **Verify the audit log path.**

   The default audit log is `uploads/reeflex-gate/reeflex-audit.jsonl`; the
   directory is created with a deny-all `.htaccess` + `index.php` (protected on
   Apache). Confirm the web server process has write permission to that path. On
   nginx (which ignores `.htaccess`), set `REEFLEX_AUDIT_LOG` to a path outside
   the web root, since nginx will not honor the generated deny rule.

4. **Load WordPress and confirm the plugin is active.**

   Navigate to **wp-admin > Plugins > Must-Use** and confirm "Reeflex Gate"
   appears in the list. The mu-plugin is active from the first page load after
   the files are in place.

### What interception looks like

When Hook A (`wp_register_ability_args`) fires, the adapter wraps the
ability's `permission_callback` at registration time. From that point forward,
every call to that ability goes through this sequence:

1. Original `permission_callback` runs. If it denies, Reeflex does not
   widen access — the original denial stands.
2. If the original grants, the adapter normalizes the call into an
   Action Envelope and POSTs to `REEFLEX_CORE_URL/v1/decide`.
3. Based on the Decision:
   - `allow` → `permission_callback` returns `true`; the ability executes.
   - `deny` → returns `WP_Error('reeflex_denied', ..., ['status' => 403])`.
   - `require_approval` → returns `WP_Error('reeflex_hold', ..., ['status' => 202])`.
     **This is terminal in v0.1.** The action does not run. The full
     human-approval re-submission flow is on the roadmap.
   - Core unreachable / any error → returns
     `WP_Error('reeflex_unavailable', ..., ['status' => 503])`.
     The adapter never silently allows on error.
4. An audit record is written to the JSONL log before enforcement.

For MCP-originated calls, Hook B (`mcp_adapter_pre_tool_call`) also fires at
the `ToolsHandler` layer, before the ability executes. Both hooks call
`/v1/decide` independently — this is intentional defense-in-depth. There is
no deduplication between them.

### Verifying it works

Run the offline conformance harness (WordPress not required):

```bash
php tests/conformance-demo.php https://your-reeflex-core-host
```

All seven scenarios should print `PASS`. See [DEMO.md](DEMO.md) for the
expected output table and the in-WordPress walkthrough.

Check the audit log after triggering any ability:

```bash
tail -n 5 uploads/reeflex-gate/reeflex-audit.jsonl | python3 -m json.tool
```

Each line is one JSON decision record. Fields include `ts`, `ability`,
`verb`, `axes`, `decision`, `rule`, `applied`.

---

## Advanced — external MCP proxy (defense-in-depth / when WP is not modifiable)

This method places Reeflex at the network boundary between the AI agent and
the WordPress MCP endpoint. It does not require access to the mu-plugins
directory.

**When to use this method:**
- The WordPress install cannot be modified (shared hosting, managed WP).
- You want network-layer blocking in addition to the in-WP hook (defense-in-depth).
- You are protecting a WordPress instance where mu-plugins is unavailable.

**Limitation:** the external proxy only intercepts MCP-originated calls
(`POST /wp-json/mcp/...`). Direct PHP calls or REST calls that do not go
through the MCP Adapter are not covered by the proxy alone.

### MCP endpoint details

| Item | Value |
|---|---|
| WordPress MCP endpoint | `POST /wp-json/mcp/{namespace}/{route}` |
| Default namespace | `mcp-adapter-default-server` |
| Protocol | JSON-RPC 2.0 over Streamable HTTP |
| Tool name for ability execution | `mcp-adapter/execute-ability` |
| Auth | WordPress Application Passwords |
| Session header | `Mcp-Session-Id` (from `initialize` handshake) |

A `tools/call` request body looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp-adapter/execute-ability",
    "arguments": {
      "ability_name": "core/delete-post",
      "parameters": { "ids": [101, 102, 103] }
    }
  }
}
```

### Proxy implementation requirements

The proxy MUST implement the full adapter contract (SPEC §6):

1. **INTERCEPT** — sit in front of `POST /wp-json/mcp/...` and capture every `tools/call` request.
2. **NORMALIZE** — extract `ability_name` and `parameters` from the JSON-RPC arguments; produce a valid Action Envelope (SPEC §2) with the three axes set conservatively.
3. **ENFORCE** — POST the envelope to `reeflex-core /v1/decide` and apply the decision:
   - `allow` → forward the original request to WordPress unchanged.
   - `deny` → drop the request; return a JSON-RPC error object to the agent (do not forward to WordPress).
   - `require_approval` → drop the request; return a JSON-RPC error with a hold notification.
   - Core unreachable → fail closed; drop the request.
4. **AUDIT** — emit a decision record per action.

The proxy must relay the `Mcp-Session-Id` header from the MCP `initialize`
handshake on every subsequent request. Core uses `session_id` for cumulative
(anti-fragmentation) policy evaluation (SPEC §4.1).

### Auth

The proxy authenticates to WordPress using an **Application Password**
generated in the user account that will act on behalf of the agent. Set the
credential by reference — never hardcode it. Example env-var pattern:

```
REEFLEX_WP_APP_PASSWORD=<value from Vault or env>
```

Forward the `Authorization: Basic <base64(username:app-password)>` header
unchanged when proxying allowed requests to WordPress.

### Verifying it works

1. Start the proxy and confirm it is reachable.
2. Issue a `tools/call` for a destructive ability (e.g. `core/delete-post` with
   a large `ids` array).
3. Confirm the proxy returns a JSON-RPC error and does not forward the call.
4. Check the proxy's audit log for the `reeflex_denied` or `reeflex_hold` record.
5. Stop `reeflex-core` and confirm the proxy drops every request (fail-closed).

---

## Configuration reference

**Standard plugin install:** go to **Settings > Reeflex Gate** in wp-admin. The
page has three fields — API URL (mandatory), Token (optional), and Verify TLS
(default on). Settings are stored in `wp_options` under `reeflex_gate_options`.

**All install methods:** `wp-config.php` constants always take precedence over
the Settings page and lock those fields read-only. Use constants for any
production deployment. See [README.md](README.md#configuration) for the full
constants table.

Quick reference for `wp-config.php` (required for mu-plugin; overrides Settings
page for standard plugin):

```php
define( 'REEFLEX_CORE_URL',  'https://your-reeflex-core-host' );  // required
define( 'REEFLEX_CORE_TOKEN', '' );                                 // optional (core auth)
define( 'REEFLEX_VERIFY_SSL', true );                               // default; disable only for a self-signed/internal core
define( 'REEFLEX_ENV',      'production' );                         // optional
define( 'REEFLEX_AGENT_ID', 'agent:wordpress' );                    // optional
define( 'REEFLEX_AUDIT_LOG', '/absolute/path/to/reeflex-audit.jsonl' );  // optional
define( 'REEFLEX_TIMEOUT',  5 );                                    // optional
```

---

## Security notes

- `REEFLEX_CORE_URL` must use `https://`. The adapter rejects any `http://` URL
  whose host is not a loopback address (127.0.0.1, localhost, ::1), regardless
  of environment. This restriction is unconditional — there is no dev-mode
  exception — because permitting `http://` to arbitrary hosts is an SSRF and
  token-exfiltration risk. Developers who genuinely need `http://` to a
  non-loopback host must define `REEFLEX_CORE_URL` as a wp-config.php constant
  (an explicit, operator-privileged act); they cannot use the Settings page for
  this.
- The audit log must not be web-accessible. The default path is
  `uploads/reeflex-gate/reeflex-audit.jsonl`, whose directory is created with a
  deny-all `.htaccess` + `index.php` (Apache); on nginx, point
  `REEFLEX_AUDIT_LOG` outside the web root.
- Never set credentials (Application Passwords, Vault tokens) as PHP
  constants. Use environment variables or a secrets manager and reference
  them by name.
- `meta.signature` in the Action Envelope is currently a stub
  (`ed25519:stub:...`). Full envelope signing is on the roadmap pending
  Vault-backed key management.
