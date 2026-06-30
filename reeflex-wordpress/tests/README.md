# tests/README.md — Reeflex WordPress Adapter Test Harness

---

## What the harness is

`tests/conformance-demo.php` is a **PHP CLI script** that loads and exercises
the real Reeflex adapter classes (`reeflex-gate/*.php`) against a live
`reeflex-core` instance, with the WordPress runtime stubbed by
`tests/wp-stubs.php`.

It is not a unit test suite with mocked HTTP. Decision authority stays
entirely in `reeflex-core` — the stubs do not make any allow/deny choice.
The harness proves that the adapter's intercept-normalize-enforce-audit
pipeline produces the correct enforced outcome for each scenario when
evaluated by the real engine.

### What is stubbed

`wp-stubs.php` provides minimal shims for the WordPress functions and classes
that the adapter classes call at runtime:

- Constants: `ABSPATH`, `WP_CONTENT_DIR`, `AUTH_SALT`, `LOGGED_IN_COOKIE`.
- WordPress hook system: `add_filter()`, `apply_filters()`, `do_action()` (no-op).
- `WP_Error` class and `is_wp_error()`.
- A synthetic `WP_User` (user ID 7, role `editor`).
- WordPress utility functions: `wp_get_current_user()`, `wp_get_session_token()`,
  `wp_hash()`, `wp_generate_uuid4()`, `wp_json_encode()`, `sanitize_text_field()`,
  `trailingslashit()`, `untrailingslashit()`.
- WordPress HTTP API: `wp_remote_post()` is implemented as a real HTTP call
  using PHP stream contexts (no cURL dependency). It actually POSTs to the
  `reeflex-core` URL you supply. `wp_remote_retrieve_response_code()` and
  `wp_remote_retrieve_body()` extract from the response array.

### What is not stubbed (and therefore not proven)

- That WordPress's filter system fires `wp_register_ability_args` at the
  correct timing relative to ability registration (this is WordPress core
  behaviour, not adapter behaviour).
- Hook B (`mcp_adapter_pre_tool_call`) firing in a real MCP Adapter
  (`wordpress/mcp-adapter`) context.
- The audit JSONL file being written to `WP_CONTENT_DIR` in a live WordPress
  process (the harness writes to the system temp directory).
- The `do_action('reeflex_obligation', ...)` hook reaching real operator-defined
  handlers (`do_action` is a no-op in the harness).

The in-WordPress walkthrough in [../DEMO.md](../DEMO.md) covers the live-WP
verification.

---

## How to run

### Prerequisites

- PHP 7.4 or higher (CLI).
- A running `reeflex-core` instance reachable over HTTP/HTTPS.
- The `reeflex-gate/` class files present at their standard path relative to
  `tests/` (i.e., `../reeflex-gate/*.php`).

### Command

From the `reeflex-wordpress/` root:

```bash
php tests/conformance-demo.php [core_url]
```

`core_url` defaults to `http://127.0.0.1:8099`.

Examples:

```bash
# Against a local core on default port.
php tests/conformance-demo.php

# Against a named core host.
php tests/conformance-demo.php https://your-reeflex-core-host

# Fail-closed check: point at a dead port.
php tests/conformance-demo.php http://127.0.0.1:9
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All scenarios passed. |
| `1`  | One or more scenarios failed (FAIL lines in output). |
| `2`  | Harness error — Hook A (`wp_register_ability_args`) was not registered after `Reeflex_Gate::register_hooks()`. This indicates a class loading problem, not a policy failure. |

---

## Scenarios

The harness runs seven scenarios, each defined by an ability name, input
array, and expected enforced outcome:

| # | Scenario | Expected outcome |
|---|---|---|
| 1 | `core/get-post`, `{id: 42}` | `allow` (read, single, internal) |
| 2 | `core/delete-post`, `{ids: [42]}` | `allow` (soft delete, single, recoverable) |
| 3 | `core/delete-post`, `{ids: [1..50], force_delete: true}` | `reeflex_hold` (irreversible, broad, production) |
| 4 | `core/delete-post`, `{ids: [1..25]}` | `reeflex_hold` (>=20 items -> irreversible, broad) |
| 5 | `core/delete-site-wide-data`, `{force_delete: true}` | `reeflex_denied` (systemic blast radius, deny) |
| 6 | `core/delete-post`, `{ids: [1..50], force_delete: true, _reeflex_approved: '1'}` | `reeflex_hold` (bypass attempt; forged approval stripped by normalizer) |
| 7 | `core/fetch-and-delete-posts`, `{ids: [1..30]}` | `reeflex_hold` (verb collision resolved to `delete` by danger-priority) |

For a fail-closed run (dead port), all scenarios expect `reeflex_unavailable`.

---

## How the harness drives Hook A

The harness calls `Reeflex_Gate::register_hooks()`, then retrieves the
registered callback for `wp_register_ability_args` from the stub filter
registry (`$GLOBALS['__filters']`). For each scenario it:

1. Builds a minimal `$args` array with a `permission_callback` that returns
   `true` (the ability grants by default).
2. Calls `$hookA($args, $ability_name)` to get the wrapped args.
3. Invokes the wrapped `permission_callback` with the scenario input.
4. Reads the result: `true` = PROCEED (allow); `WP_Error` = BLOCKED with the
   error code.

This exercises the full normalize → decide → audit → enforce path in
`Reeflex_Gate::wrap_permission_callback()` and the classes it calls.

---

## Relationship to the conformance suite

This harness serves as the practical conformance demonstration while a
formal conformance suite (as described in SPEC §7) is being specified. The
seven scenarios test the most critical behaviours:

- Conservative allow for low-risk actions.
- Hold for irreversible/broad actions in production.
- Deny (harder block) for systemic blast radius.
- Bypass resistance (forged approval stripped).
- Verb collision resolved in the danger-priority direction.
- Fail-closed on core unreachable.

An adapter that passes all seven scenarios against a production policy pack
demonstrates the core requirements of SPEC §7 for this scenario set. The
full formal conformance suite, once defined, will supersede this harness as
the compliance gate.
