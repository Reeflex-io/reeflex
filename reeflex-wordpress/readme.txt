=== Reeflex Gate ===
Contributors: reeflex
Tags: security, governance, ai, mcp, abilities
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 0.1.1
License: Apache-2.0
License URI: https://www.apache.org/licenses/LICENSE-2.0

Deterministic governance gate for WordPress agent actions — blocks or holds abilities via an external decision engine.

== Description ==

Reeflex Gate is a governance adapter for WordPress. It intercepts every agent
action before it executes — deterministically, without any LLM in the decision
path — and enforces an allow, deny, or require_approval verdict from an external
reeflex-core decision engine.

**How it works**

Two hooks are registered:

* **Hook A — `wp_register_ability_args`** (WordPress Abilities API, built into
  WP 6.9 core). This is the primary blocking seam. It wraps every registered
  ability's `permission_callback` at registration time, so Reeflex gates the
  action before `WP_Ability::execute()` can reach `do_execute()`. All execution
  paths — REST API, direct PHP call, and MCP-originated `tools/call` — converge
  at `WP_Ability::execute()`, so Hook A covers all of them at a single point.

* **Hook B — `mcp_adapter_pre_tool_call`** (MCP Adapter plugin v0.5.0+,
  required only for MCP traffic). Defense-in-depth for the MCP tool layer.
  Fires only for the `mcp-adapter/execute-ability` tool. A `WP_Error` return
  short-circuits execution before it reaches the ability.

For every ability call the adapter:

1. Normalizes the action into a universal Action Envelope (three axes:
   reversibility, blast radius, externality).
2. POSTs the envelope to `reeflex-core POST /v1/decide`.
3. Enforces the decision:
   * `allow` — ability runs normally.
   * `deny` — ability is blocked; `WP_Error('reeflex_denied')` returned.
   * `require_approval` — ability is held; `WP_Error('reeflex_hold')` returned.
   * Core unreachable / any error — **fail closed**: `WP_Error('reeflex_unavailable')`.
4. Writes an audit record to the JSONL audit log before enforcement.

The decision engine (reeflex-core) uses OPA/Rego and classical logic. There is
zero LLM in the decision path. Free text is never a decision input.

**Two install forms**

The plugin ships in two forms:

* **Standard plugin** (this package) — installed via Plugins > Add New or
  uploaded as a zip. Can be deactivated from wp-admin.
* **Must-use (mu-plugin) form** — `reeflex-gate.php` and the `reeflex-gate/`
  folder dropped directly into `wp-content/mu-plugins/`. Cannot be deactivated
  from wp-admin and loads before regular plugins. Recommended for production.

**Open-core boundary**

This adapter, like reeflex-core and reeflex-spec, is Apache 2.0 / open source.
The commercial compliance tier (NIS2/DORA/GDPR reporting, ANAF/SmartBill
integrations) is a separate, closed package and is never present in this
repository.

*Reeflex — governance that isn't another AI.*

== Installation ==

=== Standard plugin ===

1. In wp-admin, go to **Plugins > Add New Plugin**.
2. Click **Upload Plugin** and select the `reeflex-gate` zip file.
3. Click **Install Now**, then **Activate Plugin**.
4. Go to **Settings > Reeflex Gate**.
5. Enter the **API URL** — the base URL of your running reeflex-core instance
   (e.g. `https://reeflex-core.example.com`). This field is mandatory; without
   it, Reeflex blocks every agent action (fail-closed).
6. Optionally enter a **Token** — the bearer token for the Authorization header
   sent to reeflex-core. Leave blank if your core instance is not token-protected.
7. Click **Save Settings**.

Constants defined in `wp-config.php` (`REEFLEX_CORE_URL`, `REEFLEX_CORE_TOKEN`)
always take precedence over the Settings page values and lock those fields
read-only. See the FAQ for details.

=== Must-use (mu-plugin) — recommended for production ===

1. Copy `reeflex-gate.php` and the entire `reeflex-gate/` directory into your
   site's `wp-content/mu-plugins/` directory. The directory must sit alongside
   the loader file:

   ```
   wp-content/mu-plugins/reeflex-gate.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-config.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-normalizer.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-core-client.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-audit.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-gate.php
   wp-content/mu-plugins/reeflex-gate/class-reeflex-settings.php
   ```

2. Configure via `wp-config.php` constants. At minimum, set `REEFLEX_CORE_URL`:

   ```php
   // Required — base URL of your reeflex-core instance.
   define( 'REEFLEX_CORE_URL', 'https://reeflex-core.example.com' );

   // Optional — bearer token for Authorization header.
   define( 'REEFLEX_CORE_TOKEN', 'your-token' );  // reference from Vault/env

   // Optional — other defaults shown.
   define( 'REEFLEX_ENV',      'production' );
   define( 'REEFLEX_AGENT_ID', 'agent:wordpress' );
   define( 'REEFLEX_TIMEOUT',  5 );
   ```

   `REEFLEX_CORE_URL` is required. Without it, every decision fails closed
   immediately. `REEFLEX_CORE_TOKEN` is optional.

3. Load any wp-admin page. Go to **wp-admin > Plugins > Must-Use** and confirm
   "Reeflex Gate" appears. The mu-plugin is active from the first page load
   after the files are in place.

For full installation details and verification steps for both methods, see
`INSTALL.md` in the plugin directory.

== Frequently Asked Questions ==

= Where are settings stored? =

Settings are stored in the WordPress options table under the option name
`reeflex_gate_options` (a single array option with keys `core_url` and
`core_token`). They are written and read via the standard WordPress Settings API
(`register_setting()` / `get_option()`).

= Do wp-config.php constants override the Settings page? =

Yes — constants are trust anchors and always win. When `REEFLEX_CORE_URL` is
defined and non-empty, it overrides the Settings page value and the API URL
field is rendered read-only ("Locked"). When `REEFLEX_CORE_TOKEN` is defined
(even if empty), it overrides the Settings token value and that field is
likewise locked.

This precedence is intentional: a constant defined in `wp-config.php` is an
explicit, server-side operator decision. Allowing a database value (editable
through wp-admin) to override it would let a compromised or malicious admin
re-point the governance gate to an attacker-controlled endpoint.

= What happens if the API URL is not set or reeflex-core is unreachable? =

The adapter **fails closed**. If no API URL is configured, or if reeflex-core
returns a non-200 status, returns invalid JSON, or is unreachable within the
timeout, every agent action is blocked with `WP_Error('reeflex_unavailable')`.
The adapter never silently allows an action when governance is unavailable.

= Does it need the MCP Adapter plugin? =

The MCP Adapter plugin (`wordpress/mcp-adapter` v0.5.0+) is required only if
you use MCP-originated traffic and want Hook B (the defense-in-depth MCP layer).
The WordPress Abilities API (Hook A, the primary seam) is built into WordPress
6.9 core and requires no additional plugin.

= What does uninstall remove? =

Uninstall removes the stored settings, including the token, from `wp_options`
(the `reeflex_gate_options` option). It does **not** remove the audit log
(`reeflex-audit.jsonl`). Audit records are append-only and are not deleted on
uninstall; remove the file manually if you no longer need it.

== Changelog ==

= 0.1.0 =

First release — reference WordPress adapter for reeflex-core.

* Action Envelope normalization across three axes (reversibility, blast radius,
  externality) for every WordPress Abilities API ability.
* Hook A (`wp_register_ability_args`) — primary blocking seam; wraps every
  ability's `permission_callback` at registration time; covers REST, direct PHP,
  and MCP execution paths.
* Hook B (`mcp_adapter_pre_tool_call`) — defense-in-depth MCP layer; adds
  MCP-layer fidelity and cleaner MCP error propagation.
* Fail-closed enforcement: any error, timeout, or missing configuration blocks
  the action with `WP_Error('reeflex_unavailable')`.
* Admin Settings page (Settings > Reeflex Gate) with two fields: API URL
  (mandatory) and Token (optional). Constants defined in `wp-config.php` take
  precedence and lock those fields read-only.
* Bearer auth support: `Authorization: Bearer <token>` header sent when a token
  is configured.
* Ships in both standard plugin form and must-use (mu-plugin) form.
* JSONL audit log written before enforcement; one record per decision.

== Upgrade Notice ==

= 0.1.0 =

Initial release. No upgrade path required.
