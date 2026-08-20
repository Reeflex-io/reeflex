---
title: "WooCommerce: governing agents in your store"
description: >-
  Reeflex already governs WooCommerce — no WooCommerce-specific code exists or
  is needed. woocommerce/* abilities pass through the same WP_Ability::execute()
  seam as every other WordPress action.
---

# WooCommerce: governing agents in your store

**There is no WooCommerce adapter.** WooCommerce registers its agent-facing
operations (product changes, order management, and similar) as abilities on
the same [WordPress Abilities API](https://github.com/WordPress/abilities-api)
that WordPress core uses — and Reeflex Gate already wraps that API's single
execution seam, `WP_Ability::execute()`. A `woocommerce/*` ability is governed
the moment it registers, exactly like a `core/*` ability. Nothing was built
for WooCommerce specifically, and nothing needs to be.

This page is the marketing/use-case story over coverage the
[reeflex-wordpress](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress)
adapter already has — see [Adapters](index.md) for the general architecture
and [reeflex-wordpress/readme.txt](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-wordpress/readme.txt)
for the plugin-directory copy this mirrors.

## Why a store needs this

An AI agent with store access — a support bot, an inventory-sync agent, an
automation acting "on behalf of" an admin — reaches WooCommerce through the
same abilities every human-driven UI action does. A `permission_callback`
answers *"is this caller allowed to touch orders/products at all?"* — the
same "yes" for refunding one order and for refunding five thousand. Reeflex
answers a different question: *"is this specific action safe, given the
impact it would actually have?"* It looks at the action itself — how many
items, single order vs. every order, a soft change vs. one with no way back —
and decides on that, before the store is touched.

Think of the permission check as the badge that lets an agent into the
warehouse, and Reeflex as the check that stops it walking out with a
forklift.

## How a WooCommerce action gets governed

The path is identical to any other Abilities API action (see
[docs/architecture.md](../architecture.md) for the full sequence):

1. WooCommerce (or a WooCommerce extension) registers an ability — e.g. a
   bulk product delete, an order refund, an order-status change — via
   `wp_register_ability_args`, the same registration path core WordPress
   abilities use.
2. Reeflex Gate's Hook A wraps that ability's `permission_callback` the
   moment it registers. No WooCommerce-aware code runs here; the wrapper
   doesn't know or care that the ability came from WooCommerce.
3. On a call, `Reeflex_Normalizer` turns the ability name + input into an
   [Action Envelope](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md#2-the-action-envelope)
   using the same name-segment heuristic every adapter shares — no
   WooCommerce-specific vocabulary, no special-cased ability list.
4. `reeflex-core` decides `allow` / `hold` / `deny` with the same OPA/Rego
   policy every other action goes through. Zero LLM in the decision path.

## What the existing heuristic does with WooCommerce ability names

The table below illustrates how the **generic** normalizer (see
[`class-reeflex-normalizer.php`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-wordpress/reeflex-gate/class-reeflex-normalizer.php))
would classify representative `woocommerce/*` ability names, from its
existing segment tables — not a WooCommerce-specific rule set:

| Illustrative ability name | Verb (segment match) | Reversibility | Blast radius | Why |
|---|---|---|---|---|
| `woocommerce/refund-order` | `transact` (`refund` segment) | irreversible | single | payment/refund verbs are always treated as irreversible |
| `woocommerce/delete-product` (single id) | `delete` | recoverable (WP trash default) | single | one id in the `ids` array |
| `woocommerce/bulk-delete-products` | `delete` | irreversible at count ≥ 20 | broad (`bulk` segment overrides count) | the `bulk` segment forces broad regardless of how many ids are actually sent |
| `woocommerce/update-order-status` | `update` | recoverable | single/scoped (by `ids` length) | a status change is a mutation, not a deletion |

These follow directly from the segment tables (`delete`/`trash`/`remove`… →
`delete`; `pay`/`refund`/`charge`/`invoice`… → `transact`; `bulk`/`batch`/
`mass`/`all`… → broad) documented in the adapter source — the same tables
that classify `core/delete-post` or `core/bulk-delete-users`. A WooCommerce
extension that names its abilities differently is classified by the same
rules, for better or worse: **ability-name quality is adapter-classification
quality**, the same honesty Reeflex states for every adapter's normalization
layer (see [mcp-gateway.md](../mcp-gateway.md) for the same point made about
`reeflex-mcp`'s mappings).

## What this does not require

- **No WooCommerce plugin dependency.** Reeflex Gate does not check for
  WooCommerce, does not hook any WooCommerce-specific action, and works
  identically whether WooCommerce is active or not.
- **No separate configuration.** The Settings > Reeflex Gate page (API URL,
  token, enforcement mode) is the only configuration surface — there is no
  WooCommerce-specific setting.
- **No new adapter code.** Everything on this page describes behavior the
  reference [reeflex-wordpress](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress)
  adapter already has, unchanged.

## Honest limit

Reeflex governs a WooCommerce action **only if WooCommerce (or the extension
performing it) registers that operation through the Abilities API.** An
operation that reaches the database some other way — a direct SQL query, a
legacy REST endpoint that bypasses `WP_Ability::execute()`, an old
non-abilities integration — has nothing for Reeflex to intercept, the same
coverage boundary that applies to any `core/*` action outside the Abilities
API. This is the resource-side trade-off described in [Adapters](index.md#the-adapters):
Reeflex governs every caller that goes through the seam it wraps, not every
possible path into WordPress.

## Try it

Install Reeflex Gate ([reeflex-wordpress](https://github.com/Reeflex-io/reeflex/tree/main/reeflex-wordpress),
also queued for the WordPress.org plugin directory), point it at a running
`reeflex-core` (or the public dev endpoint, `https://api-dev.reeflex.io`, for
evaluation only), start in **observe** mode to see what Reeflex would have
stopped on your store's real agent traffic, then switch to **enforce** when
ready. See [reeflex-wordpress/readme.txt](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-wordpress/readme.txt)
for the full install/configuration walkthrough.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
