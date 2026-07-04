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

- Constants: `ABSPATH`, `WP_CONTENT_DIR`, `AUTH_SALT`, `LOGGED_IN_COOKIE`, `HOUR_IN_SECONDS`.
- WordPress hook system: `add_filter()`, `apply_filters()`, `do_action()` (no-op).
- `WP_Error` class and `is_wp_error()`.
- A synthetic `WP_User` (user ID 7, role `editor`).
- WordPress utility functions: `wp_get_current_user()`, `wp_get_session_token()`,
  `wp_hash()`, `wp_generate_uuid4()`, `wp_json_encode()`, `sanitize_text_field()`,
  `trailingslashit()`, `untrailingslashit()`.
- WordPress Options API: `get_option()` / `update_option()` / `delete_option()`
  backed by a process-local `$GLOBALS['__options']` array — real persistence
  *within one harness run* (needed by `Reeflex_Holds_Store`, HIL Phase 2), but
  never touches a real database and never survives past the PHP process.
- A minimal Abilities API: `WP_Ability`, `WP_Abilities_Registry`, `wp_get_ability()`,
  `wp_register_ability()`. `wp_register_ability()` applies the REAL
  `wp_register_ability_args` filter before storing the ability — the exact seam
  Hook A hangs off in production — so `wp_get_ability($name)->execute($input)`
  in the harness exercises the real wrapped `permission_callback`, not a shortcut.
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
| 4 | `core/delete-post`, `{ids: [1..25]}` | `reeflex_hold` (>=20 items → irreversible, broad) |
| 5 | `core/delete-site-wide-data`, `{force_delete: true}` | `reeflex_denied` (systemic blast radius, deny) |
| 6 | `core/delete-post`, `{ids: [1..50], force_delete: true, _reeflex_approved: '1'}` | `reeflex_hold` (bypass attempt; forged approval stripped by normalizer) |
| 7 | `core/fetch-and-delete-posts`, `{ids: [1..30]}` | `reeflex_hold` (verb collision resolved to `delete` by danger-priority) |

For a fail-closed run (dead port), all scenarios expect `reeflex_unavailable`.

---

## How the harness drives Hook A

The harness calls `Reeflex_Gate::register_hooks()`, then for each scenario
`get_or_register_demo_ability()` registers (once per ability name, idempotent)
a real ability via `wp_register_ability()`, which applies the REAL
`wp_register_ability_args` filter (Hook A) before storing it — exactly as
`WP_Abilities_Registry::register()` does in production. It then calls
`wp_get_ability($ability)->execute($input)`:

1. `WP_Ability::execute()` calls the WRAPPED `permission_callback`
   (`Reeflex_Gate::wrap_permission_callback()`'s closure) first.
2. On `true`, it runs the ability's `execute_callback`, which returns an array
   marking the ability as executed — a real (if trivial) side effect, not a
   stub return value.
3. On `WP_Error`, `execute()` short-circuits and returns that error — the
   ability body never runs.

`run_ability()` reads the result: `true`/array = PROCEED (allow, executed);
`WP_Error` = BLOCKED with the error code. This exercises the full
normalize → decide → audit → enforce path in
`Reeflex_Gate::wrap_permission_callback()` and the classes it calls.

---

## HIL Phase 2 (T1) — hold-aware resubmission scenarios

After the seven baseline scenarios, `conformance-demo.php` runs ten more
(`H1`–`H10`) that exercise the full hold → resolve → resubmit lifecycle
against the SAME live `reeflex-core` (>= v0.1.5, HIL Phase 1 holds queue).
These are SKIPPED (not counted as a failure) when run in `observe` mode or
against an unreachable core — there is no live hold to resolve in either case.

| # | Scenario | Proves |
|---|---|---|
| H1 | Fresh bulk force-delete (ids 201–245) | Core returns `require_approval` + `hold_id` |
| H2 | `hold_id` + `expires_ts` in the public `WP_Error` data | T1.1: hold metadata surfaced to the caller |
| H3 | `Reeflex_Holds_Store::get($hold_id)` returns the entry | T1.1: pending action stored at hold time |
| H4 | `POST /v1/holds/{id}/resolve` (approve, principal `human:conformance-tester`) | Driving core's real holds API |
| H5 | `Reeflex_Gate::resubmit_hold($hold_id)` → ability's `execute_callback` runs, store entry deleted | T1.2: approved hold re-executes the ORIGINAL action; single-use |
| H6 | `resubmit_hold('deadbeef...')` → `reeflex_hold_unknown` | Fails closed on an unknown hold_id |
| H7 | `resubmit_hold($hold_id)` again after H5 | Fails closed — a consumed hold cannot be replayed |
| H8 | Fresh hold (ids 401–445), reject via the resolve API, then resubmit | `reject` → `resubmit_hold()` denied, never executes |
| H9 | Fresh hold (ids 501–545), approve, then wait past `expires_ts` before resubmitting | `expired` → `resubmit_hold()` denied. **Only runs when `REEFLEX_HOLD_TTL_SECONDS` is set in the environment to a value ≤ 60** (must match the value the core process was started with) — otherwise printed as `SKIP` (waiting out a real 4h TTL is not practical in CI) |
| H10 | Fresh hold (ids 601–645); resolve using `principal.id == Reeflex_Config::agent_id()` (the envelope's own actor identity) | `actor == approver` → core's resolve endpoint itself refuses with 403 `actor_is_approver`; the hold stays unresolved, so `resubmit_hold()` is also denied |

Running with the short-TTL scenario enabled (core must be started with the
SAME value):

```bash
REEFLEX_HOLD_TTL_SECONDS=8 php.exe tests/conformance-demo.php http://127.0.0.1:8299
```

### Proof of the LOCKED DECISION (actor stays actor)

T1.2 requires that a resubmitted action carries the ORIGINAL agent identity —
never the identity of whoever resolves/resubmits the hold
(`Reeflex_Gate::$active_resubmission_agent`, threaded into
`Reeflex_Normalizer::normalize()`'s `$agent_override` parameter). This is
verifiable directly from the adapter's own audit JSONL
(`REEFLEX_AUDIT_LOG`, default `sys_get_temp_dir() . '/reeflex-harness-audit.jsonl'`):
find the `applied:"hold"` record for a `hold_id`, and the later
`applied:"allow"` record whose `approval.hold_id` matches it — `session_id`
and `on_behalf_of` must be identical between the two, even though H5's
`resubmit_hold()` call executes from a completely different point in the
script (a different logical "requester") than H1's original call.

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
