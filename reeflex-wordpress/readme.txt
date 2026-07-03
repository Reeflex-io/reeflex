=== Reeflex Gate ===
Contributors: reeflexio
Tags: security, ai-agents, governance, woocommerce, abilities-api
Requires at least: 6.9
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 0.1.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Deterministic governance gate for AI-agent actions in WordPress: allow, hold for a human, or block, decided on real impact. Fail-closed.

== Description ==

Reeflex Gate is a safety layer for the AI agents acting on your WordPress site.
When an agent (over the REST API, the MCP Adapter, or a direct call) triggers a
WordPress Abilities API action, Reeflex intercepts it *before* it runs, works out
how much impact it would actually have, and returns one of three verdicts:

* **allow** — the action runs normally.
* **hold** — the action is held for a human to approve.
* **deny** — the action is blocked outright.

The decision is **deterministic**: it is made by an external engine (`reeflex-core`)
using OPA/Rego and classical logic. There is **no LLM in the decision path**, and
free text is never a decision input. Every decision — allow, hold, or deny — is
written to an append-only audit log first, so you have a pre-execution record of
what an agent *attempted*, not just what happened.

**Why this, when the Abilities API already checks permissions?**

A `permission_callback` answers "is this user allowed to do this?" — it returns
the same "yes" for deleting one item and for deleting five thousand. Reeflex
answers a different question: "is this action safe, given the impact it would
actually have?" It looks at the action itself — how many items, force-delete vs.
trash, site-wide vs. single, and everything already done this session — and
decides on that. Think of the permission check as the access badge that opens the
door, and Reeflex as the check that stops you walking in with a bulldozer.

**How it works**

The gate wraps every registered ability's `permission_callback` via the
`wp_register_ability_args` filter, so it governs every path an agent can take —
REST API, direct PHP, and MCP-originated `tools/call` all converge at
`WP_Ability::execute()`. For MCP traffic it adds a second, defense-in-depth hook
(`mcp_adapter_pre_tool_call`). For each attempt it normalizes the action into a
universal **Action Envelope** (three axes: reversibility, blast radius,
externality), asks `reeflex-core` to decide, and enforces the verdict. If the
engine is unreachable, misconfigured, or errors, the gate **fails closed** —
nothing gets through.

**Works with WooCommerce (and anything else on the Abilities API)**

There is no WooCommerce-specific code in Reeflex, and none is needed. WooCommerce
exposes its agent operations through the same Abilities API, so a `woocommerce/*`
action (bulk product delete, order changes) is gated at the same seam as core
actions — held or denied on impact when an agent tries something destructive to
your store. Any plugin that registers abilities is covered the moment its actions
go through the Abilities API.

**Two install forms**

* **Standard plugin** (this package) — install from the WordPress plugin directory
  or upload the zip; configure on the Settings page.
* **Must-use (mu-plugin) form** — dropped into `wp-content/mu-plugins/` and
  configured with `wp-config.php` constants; loads before regular plugins and
  cannot be deactivated from wp-admin. Distributed from the project's GitHub
  releases, for hardened production installs.

**Open-core & licensing**

This plugin is free and open source, licensed GPLv2-or-later. `reeflex-core` and
the specification are Apache-2.0. The planned commercial compliance tier
(NIS2/DORA/GDPR reporting) is a separate, closed package and is never bundled
here.

== External services ==

This plugin relies on one external service to make its decisions: the
**reeflex-core decision engine**, running at a URL that **you** configure.

**No default endpoint.** Out of the box the plugin has an empty endpoint and makes
**no external requests at all** — with no URL configured it simply fails closed
(every agent action is blocked and nothing is sent anywhere). It contacts a server
only after a site administrator explicitly enters one on the Settings page or via
a `wp-config.php` constant. That configuration step is your explicit consent.

**When a request is sent.** Once an endpoint is configured, on every gated agent
action the plugin sends a single HTTPS `POST` to `<your-endpoint>/v1/decide`
*before* the action executes, and waits for the allow/hold/deny verdict.

**What is sent.** Only a structured "Action Envelope" describing the *attempt*:
the normalized verb (e.g. `delete`), an item count, three risk axes
(reversibility, blast radius, externality), an environment label
(`production`/`staging`/`dev`), an agent identifier, a per-session identifier, a
timestamp, and a nonce. If you configure a token, an `Authorization: Bearer`
header is included to authenticate you to your own engine. **The plugin does NOT
send post/page content, user personal data, passwords, order data, or the
action's payload** — only the risk-relevant metadata above.

**Where it is sent.** To the reeflex-core deployment you configure — normally your
own, self-hosted, on your own infrastructure. For evaluation only, the project
also runs a public development endpoint at `https://api-dev.reeflex.io` (it uses a
staging TLS certificate and requires turning TLS verification off; it is not for
production).

**Service information.**

* Privacy policy: https://reeflex.io/privacy — Terms of use: https://reeflex.io/terms
* Project home: https://reeflex.io
* Source code, the exact Action Envelope schema, and documentation:
  https://github.com/Reeflex-io/reeflex
* `reeflex-core` is open source (Apache-2.0) and can be self-hosted, so the data
  never has to leave your infrastructure.

== Installation ==

1. Install "Reeflex Gate" from **Plugins > Add New**, or upload the zip via
   **Plugins > Add New > Upload Plugin**, then **Activate**.
2. Go to **Settings > Reeflex Gate**.
3. Enter the **API URL** — the base URL of your running `reeflex-core` instance
   (for example `https://reeflex-core.example.com`). This is required: while it is
   empty, Reeflex blocks every agent action (fail-closed) and contacts nothing.
4. Optionally enter a **Token** — the bearer token, if your core has auth enabled.
5. Leave **Verify TLS certificate** on for any real deployment. Turn it off only
   when pointing at the public dev endpoint `https://api-dev.reeflex.io`, which
   carries a staging certificate.
6. Save. The gate now intercepts and decides on every ability call.

To try it without deploying core first, set the API URL to
`https://api-dev.reeflex.io` and uncheck **Verify TLS certificate**.

Constants defined in `wp-config.php` (`REEFLEX_CORE_URL`, `REEFLEX_CORE_TOKEN`,
`REEFLEX_VERIFY_SSL`) always take precedence over the Settings page and lock those
fields read-only — a server-side trust anchor an admin cannot override.

== Frequently Asked Questions ==

= Does this plugin send my site's content anywhere? =

No. It sends only a small "Action Envelope" of risk metadata (the verb, item
count, and risk axes of the attempted action) to the decision engine you
configure. It never sends post or page content, user personal data, passwords, or
order data. And with no endpoint configured, it sends nothing at all.

= Is there an AI/LLM making the decisions? =

No. Decisions are made by `reeflex-core` using OPA/Rego policy and classical
logic — fully deterministic. Free text is never a decision input. The gate is a
safety layer *for* AI agents, not another AI.

= What happens if the engine is unreachable or not configured? =

The plugin **fails closed**. If no API URL is set, or the engine returns a
non-200 status, invalid JSON, or is unreachable within the timeout, every agent
action is blocked with a `reeflex_unavailable` error. It never silently allows an
action when governance is unavailable.

= Does it require the MCP Adapter plugin? =

No. The primary seam is the WordPress Abilities API, built into WordPress 6.9
core. The MCP Adapter is only needed if you use MCP traffic and want the extra
defense-in-depth hook.

= Does it work with WooCommerce? =

Yes, with no extra configuration. WooCommerce actions run through the same
Abilities API seam, so destructive store operations (bulk product delete, etc.)
are held or denied on impact like any other action.

= What does uninstalling remove? =

Uninstall deletes the stored settings (including the token) from `wp_options`. It
does not delete the audit log file (`wp-content/reeflex-audit.jsonl`), because that
is an append-only governance record; remove it manually if you no longer need it.

== Screenshots ==

1. Settings > Reeflex Gate — configure the decision engine URL, optional token,
   and TLS verification. Constants set in wp-config.php show as locked.
2. Verdicts enforced live: a read and a single delete are allowed, bulk and
   force-deletes are held for a human, and a site-wide wipe is denied.

== Changelog ==

= 0.1.2 =

* Relicensed the plugin to GPLv2-or-later for WordPress.org directory
  compatibility (the rest of the project remains Apache-2.0; we hold the
  copyright and dual-license the plugin).
* readme.txt brought to WordPress.org directory standard, including an explicit
  External services disclosure.
* No functional change to the decision path, enforcement, or configuration.

= 0.1.1 =

* Added the **Verify TLS certificate** setting (and `REEFLEX_VERIFY_SSL`
  constant) so the adapter can connect to development endpoints with staging
  certificates; defaults to on.
* Added the admin **Settings > Reeflex Gate** page (API URL, Token, Verify TLS),
  with wp-config.php constants taking precedence and locking the fields.
* Bearer-token support: sends `Authorization: Bearer <token>` when a token is
  configured.

= 0.1.0 =

* First release — reference WordPress adapter for reeflex-core.
* Action Envelope normalization (reversibility, blast radius, externality) for
  every Abilities API ability.
* Hook A (`wp_register_ability_args`) primary blocking seam covering REST, direct
  PHP, and MCP execution paths; Hook B (`mcp_adapter_pre_tool_call`) as MCP-layer
  defense-in-depth.
* Fail-closed enforcement on any error, timeout, or missing configuration.
* Ships in standard plugin and must-use (mu-plugin) forms.
* Append-only JSONL audit log written before enforcement.

== Upgrade Notice ==

= 0.1.2 =

Licensing and readme update for the WordPress.org directory. No functional
change — safe to update.

= 0.1.0 =

Initial release. No upgrade path required.
