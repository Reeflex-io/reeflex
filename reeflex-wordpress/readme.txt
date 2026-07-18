=== Reeflex Gate ===
Contributors: reeflexio
Tags: security, ai-agents, governance, woocommerce, abilities-api
Requires at least: 6.9
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 0.1.8
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Governs what AI agents may do to your WordPress site — before it happens. Held or blocked on real impact, not just permissions. Fail-closed.

== Description ==

Reeflex Gate governs what AI agents may do to your WordPress site — before it
happens. When an agent (over the REST API, the MCP Adapter, or a direct call) triggers a
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

**Observe mode — calibrate before you enforce**

Observe mode records every verdict to the audit log but enforces nothing — the
action always proceeds. Use it to see what Reeflex would have stopped before you
turn enforcement on. In observe, a core outage does NOT block the site: the gate
fails OPEN (the opposite of enforce's fail-closed), because observe must never
break a production site. Enable it with `REEFLEX_MODE=observe` in `wp-config.php`
or via the **Enforcement mode** dropdown in Settings > Reeflex Gate (default:
`enforce`). *Every verdict recorded, nothing enforced — see what Reeflex would
have stopped, before you turn it on.*

**Open-core & licensing**

This plugin is free and open source, licensed GPLv2-or-later. `reeflex-core` and
the specification are Apache-2.0. The commercial tier (audit-ready compliance
evidence and managed operation) is a separate, closed package and is never
bundled here.

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
also runs a public development endpoint at `https://api-dev.reeflex.io` (it
carries a valid, publicly-trusted certificate, so no special TLS configuration
is needed; it is still a shared dev/eval endpoint, not for production).

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
5. Leave **Verify TLS certificate** on — the secure default. This includes when
   pointing at the public dev endpoint `https://api-dev.reeflex.io`, which
   carries a valid, publicly-trusted certificate.
6. Optionally set **Enforcement mode** — `enforce` (default, fail-closed) or
   `observe` (records verdicts but never blocks; gate fails OPEN on a core
   outage so it never breaks your site). Start with `observe` to see what
   Reeflex would have stopped, then switch to `enforce` when ready.
7. Save. The gate now intercepts and decides on every ability call.

To try it without deploying core first, set the API URL to
`https://api-dev.reeflex.io` and leave **Verify TLS certificate** on.

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
does not delete the audit log file (`uploads/reeflex-gate/reeflex-audit.jsonl`), because that
is an append-only governance record; remove it manually if you no longer need it.

= What is observe mode? =

Observe mode records every verdict to the audit log but enforces nothing — the
action always proceeds. Use it to see what Reeflex would have stopped before you
turn enforcement on. In observe, a core outage does NOT block the site: the gate
fails OPEN (the opposite of enforce's fail-closed), because observe must never
break a production site.

Enable it via the `REEFLEX_MODE` constant in `wp-config.php` (set to `observe`)
or via the **Enforcement mode** dropdown in Settings > Reeflex Gate. The default
is `enforce`. Switching back to `enforce` re-enables fail-closed behaviour
immediately — no other changes needed.

== Screenshots ==

1. Settings > Reeflex Gate — configure the decision engine URL, optional token,
   and TLS verification. Constants set in wp-config.php show as locked.
2. Verdicts enforced live: a read and a single delete are allowed, bulk and
   force-deletes are held for a human, and a site-wide wipe is denied.

== Changelog ==

= 0.1.8 =
* Security: the session identifier sent to the decision service and written to the audit log is now a salted SHA-256 derivation instead of the raw WordPress session token. No authentication material leaves the site. Same-session correlation (and the cumulative per-session budget) is preserved.
* The audit log now defaults to `uploads/reeflex-gate/reeflex-audit.jsonl`, following the WordPress convention for plugin-written files. The directory is created with a deny-all `.htaccess` and an `index.php` so the log is not web-accessible on Apache. The `REEFLEX_AUDIT_LOG` constant still overrides the location (recommended on nginx, to a path outside the web root).
* No change to allow / deny / approval enforcement.

= 0.1.7 =
* Fan-out fix: a single gated action now triggers exactly one core decision (and, for a held action, exactly one hold) instead of one per registered ability. A request-scoped memo collapses the permission-callback fan-out across all registered abilities; the guarantees (actor != approver, single-use holds, dedup) are unchanged.

= 0.1.5 =
* Double-gating dedup: when an MCP-originated action is gated twice (the ability's own gate plus the MCP adapter layer) and both resulting holds are approved, the action now executes at most once instead of twice (dedup by envelope hash + session within a tight window). No change to allow / deny / approval behaviour otherwise.

= 0.1.4 =
* Hold-aware: require_approval responses carry hold_id; approved holds can be re-run (approval flow, core >= 0.1.5).

= 0.1.3 =
* Observe mode: a new Enforcement mode (enforce default / observe) via the REEFLEX_MODE constant or the Settings dropdown. In observe, every verdict is recorded to the audit log with mode=observe but nothing is enforced — the action always proceeds — and a core outage fails OPEN (never blocks the site). Enforce behaviour is unchanged.

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

= 0.1.8 =
Security update: the session id is now a salted hash, so no WordPress authentication material is ever transmitted or logged. The audit log moves to uploads/reeflex-gate/ (protected by .htaccess); set REEFLEX_AUDIT_LOG to keep a custom path. Recommended update. No change to allow/deny/approval behaviour.

= 0.1.7 =
Fixes a hold fan-out: one gated action now creates one hold, not one per registered ability (the source of duplicate 'Pending approvals' rows). Recommended update. No change to allow/deny/approval behaviour.

= 0.1.5 =
Fixes a double-execution edge case: approving both holds of a double-gated MCP action now runs the action once, not twice. Safe update; no change to allow/deny/approval behaviour.

= 0.1.4 =
Held actions now carry a hold_id and can be resubmitted after a human approves them via reeflex-core's holds API (requires core >= 0.1.5; older core versions keep the previous terminal-hold behaviour). No change to deny/allow enforcement.

= 0.1.3 =
Adds observe mode: record verdicts without enforcing, so you can calibrate before enabling enforce. No change to enforce behaviour — safe to update.

= 0.1.2 =

Licensing and readme update for the WordPress.org directory. No functional
change — safe to update.

= 0.1.0 =

Initial release. No upgrade path required.
