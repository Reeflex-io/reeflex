---
title: "Use case: a CMS / ops agent on WordPress and WooCommerce"
description: >-
  An agent managing content, products and plugins through the WordPress
  Abilities API. What the reeflex-gate plugin's normaliser declares, what the
  base pack decides, and what it does not do.
---

# A CMS / ops agent on WordPress and WooCommerce

## The situation

A shop or publisher lets an agent run the site through WordPress's Abilities
API: tidy posts, update products, install the plugin a task needs. The
[reeflex-gate plugin](../adapters/woocommerce.md) intercepts every ability
call inside WordPress and asks core before it runs.

## What goes wrong without a gate

A CMS admin account can do everything, and an agent with one will. "Clean up
old drafts" becomes a bulk delete past the trash; "add a contact form" becomes
a plugin installed from the directory onto production, running code with full
database access. Each call is a normal admin action.

## Three representative actions

Each envelope is what the plugin's `Reeflex_Normalizer::normalize()` emits for
the ability and input shown, trimmed of transport fields.

**Deleting one post.** Posts go to the trash, so the normaliser prices this
recoverable/single. Allowed, and counted toward the session's `deletions`
budget (20 by default).

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:wordpress", "on_behalf_of": "user:7", "session_id": "wpsess:4be1" },
  "action":    { "namespace": "wordpress", "verb": "delete", "ability": "core/delete-post" },
  "target":    { "kind": "post", "ref": "post:7", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

**Deleting 25 posts in one call.** Twenty or more ids is `broad`, and a bulk
delete is priced irreversible. In production that is R2: held.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:wordpress", "on_behalf_of": "user:7", "session_id": "wpsess:4be1" },
  "action":    { "namespace": "wordpress", "verb": "delete", "ability": "core/delete-posts" },
  "target":    { "kind": "resource", "ref": null, "environment": "production" },
  "magnitude": { "count": 25 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

**Installing a plugin.** The axes are mild — one plugin, recoverable — and no
axis rule fires. R7 does: installing a plugin changes what code runs in
production, so it is held under the authority rule.

**Verdict:** `require_approval` · **rule** `reeflex.policy/authority_change_prod`

```json
{
  "agent":     { "id": "agent:wordpress", "on_behalf_of": "user:7", "session_id": "wpsess:4be1" },
  "action":    { "namespace": "wordpress", "verb": "create", "ability": "core/install-plugin" },
  "target":    { "kind": "plugin", "ref": null, "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "recoverable", "blast_radius": "single", "externality": "internal" },
  "approval":  { "present": false }
}
```

## How to deploy it

Install the reeflex-gate plugin (Plugins → Add New → Upload Plugin), or as a
must-use plugin with one line in `wp-config.php`:

```php
define( 'REEFLEX_CORE_URL', 'https://your-reeflex-core-host' );
```

The plugin enforces by default. The other line that matters is `REEFLEX_ENV`:
it defaults to `production`, which arms R2 and R7; set it on a staging site,
not on a production one to quiet it. Full guide:
[WooCommerce adapter](../adapters/woocommerce.md).

## What Reeflex does NOT do here

- It does not judge content. A post rewritten into nonsense, or a price set
  to €0.01 on one product, is a single reversible update and is allowed.
- It does not review the plugin. The hold asks a person whether this plugin
  may be installed; it does not scan the plugin's code.
- It does not see writes that bypass the Abilities API — direct SQL from
  another plugin, WP-CLI, a file uploaded over SFTP.
- One post at a time stays allowed until the session's `deletions` budget is
  spent: the 21st single delete in a session is held, the first 20 are not.
