# DEMO.md — Reeflex WordPress Adapter

Two demonstration tracks:

- **(a) Offline conformance harness** — runs the real adapter classes against a
  live `reeflex-core`, with WordPress stubbed. No WordPress install required.
  Reproducible on any machine with PHP 7.4+ and access to a running core.
- **(b) In-WordPress walkthrough** — hooks firing inside a real WordPress
  install; before/after on actual posts.
- **(c) Fail-closed check** — stop core, confirm every action is blocked.

---

## (a) Offline conformance harness

### What the harness is

`tests/conformance-demo.php` loads the five real adapter classes from
`reeflex-gate/`, stubs the small WordPress surface they touch
(`tests/wp-stubs.php`), and drives Hook A (`wp_register_ability_args`) end
to end — intercept, normalize (Action Envelope), POST to `reeflex-core
/v1/decide`, enforce. Decision authority stays entirely in `reeflex-core`; no
stub makes an allow/deny choice.

What the harness **does prove:**
- The adapter classes (normalizer, core client, gate, audit, config) load and
  function correctly outside a WordPress process.
- The Action Envelope produced for each scenario is evaluated by a real
  `reeflex-core` Rego policy.
- The enforced outcome (allow / deny / hold / fail-closed) matches the
  expected result for each scenario.

What the harness **does not prove:**
- That WordPress's `wp_register_ability_args` filter actually fires (WordPress
  is stubbed). The in-WordPress walkthrough below covers this.
- Hook B (`mcp_adapter_pre_tool_call`) firing in a real MCP Adapter context.
- The audit JSONL file being written at the configured `WP_CONTENT_DIR` path
  (the harness writes to the system temp directory).

### Command

```bash
php tests/conformance-demo.php https://your-reeflex-core-host
```

`core_url` defaults to `http://127.0.0.1:8099` when omitted.

Exit codes: `0` = all scenarios pass, `1` = a scenario failed,
`2` = harness error (Hook A not registered).

### Results (run against a live reeflex-core)

```
----------------------------------------------------------------------------------------------------
reeflex-wordpress conformance demo   CORE=https://your-reeflex-core-host
----------------------------------------------------------------------------------------------------
SCENARIO (agent action in WordPress)               | ENFORCED OUTCOME           | RESULT
----------------------------------------------------------------------------------------------------
1. read a post                                     | PROCEED (allow)            | PASS
2. delete 1 post (soft / trash)                    | PROCEED (allow)            | PASS
3. bulk delete 50 posts FORCE                      | BLOCKED (reeflex_hold)     | PASS
4. bulk SOFT delete 25 (>=20 -> irreversible)      | BLOCKED (reeflex_hold)     | PASS
5. delete site-wide data FORCE (systemic)          | BLOCKED (reeflex_denied)   | PASS
6. forged _reeflex_approved=1 (no bypass)          | BLOCKED (reeflex_hold)     | PASS
7. verb collision: fetch-and-delete 30 posts       | BLOCKED (reeflex_hold)     | PASS
----------------------------------------------------------------------------------------------------
ALL SCENARIOS PASS
```

**Policy rules that fired:**
- Scenarios 3, 4, 6, 7: `reeflex.policy/irreversible_broad_prod` (hold).
- Scenario 5: `reeflex.policy/irreversible_systemic_prod` (deny — harder block for systemic blast radius).
- Scenario 6 demonstrates bypass resistance: the normalizer strips
  `_reeflex_approved` from input before building the envelope, so the forged
  approval signal never reaches core. The envelope carries `approval.present: false`.

**Scenario notes:**
- Scenario 4: a soft delete of 25 posts maps to `reversibility: irreversible`
  because bulk count >= 20 is treated as irreversible regardless of trash status
  (mirrors the normalizer's documented rule).
- Scenario 7: `fetch-and-delete` contains both `fetch` (a read segment) and
  `delete`. The verb is resolved by danger-priority: `delete` wins over `read`.

### Fail-closed check (offline)

Point the harness at a port with nothing listening:

```bash
php tests/conformance-demo.php http://127.0.0.1:9
```

Every scenario returns `reeflex_unavailable` (the fail-closed deny, HTTP 503).
The policy rule in each record is `reeflex.adapter/fail_closed`.

```
----------------------------------------------------------------------------------------------------
reeflex-wordpress conformance demo   CORE=http://127.0.0.1:9   (expect fail-closed everywhere)
----------------------------------------------------------------------------------------------------
SCENARIO (agent action in WordPress)               | ENFORCED OUTCOME           | RESULT
----------------------------------------------------------------------------------------------------
1. read a post                                     | BLOCKED (reeflex_unavailable) | PASS
2. delete 1 post (soft / trash)                    | BLOCKED (reeflex_unavailable) | PASS
3. bulk delete 50 posts FORCE                      | BLOCKED (reeflex_unavailable) | PASS
4. bulk SOFT delete 25 (>=20 -> irreversible)      | BLOCKED (reeflex_unavailable) | PASS
5. delete site-wide data FORCE (systemic)          | BLOCKED (reeflex_unavailable) | PASS
6. forged _reeflex_approved=1 (no bypass)          | BLOCKED (reeflex_unavailable) | PASS
7. verb collision: fetch-and-delete 30 posts       | BLOCKED (reeflex_unavailable) | PASS
----------------------------------------------------------------------------------------------------
ALL SCENARIOS PASS
```

The adapter never silently allows when core is unreachable. This is a
hard invariant in `Reeflex_Core_Client::decide()`.

---

## (b) In-WordPress walkthrough

This walkthrough demonstrates the mu-plugin hooks firing inside a live
WordPress install with real posts. Run it in a staging environment — not
production — because you will register a test ability and trigger a bulk
delete attempt.

### Prerequisites

- WordPress 6.8+ with the WordPress Abilities API active.
- The Reeflex mu-plugin installed per [INSTALL.md](INSTALL.md).
- `REEFLEX_CORE_URL` set to a running `reeflex-core` instance.
- `REEFLEX_ENV` set to `production` (so the production policy pack fires).
- WP-CLI or access to a PHP file you can drop and remove from the install.

### Step 1 — Register a test ability

In a must-use plugin or a temporary plugin file, register an ability that
represents a bulk delete. A real ability registration looks like:

```php
// Register after 'wp_abilities_api_init'.
add_action( 'wp_abilities_api_init', function() {
    WP_Abilities_Registry::get_instance()->register(
        'mysite/bulk-delete-posts',
        array(
            'permission_callback' => static function( $input ) {
                return current_user_can( 'delete_posts' );
            },
            // Optional: declare the verb explicitly so the normalizer
            // does not rely on name heuristics.
            'reeflex_verb' => 'delete',
        )
    );
} );
```

Reeflex's Hook A (`wp_register_ability_args`) wraps the
`permission_callback` at registration time.

### Step 2 — Note the current post count (before)

```bash
wp post list --post_status=publish --format=count
# e.g. 47
```

### Step 3 — Have an MCP agent (or REST call) attempt a bulk delete

Using an MCP client or a direct `tools/call` (via WP-CLI or curl):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp-adapter/execute-ability",
    "arguments": {
      "ability_name": "mysite/bulk-delete-posts",
      "parameters": {
        "ids": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24, 25],
        "force_delete": true
      }
    }
  }
}
```

### Step 4 — Observe the outcome

**HTTP response from the MCP Adapter (Hook B fires first):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32603,
    "message": "Action requires human approval.",
    "data": { "status": 202, "reeflex_decision": "require_approval" }
  }
}
```

If the call had gone through REST directly (bypassing Hook B), Hook A would
have returned `WP_Error('reeflex_hold', 'Action requires human approval.',
['status' => 202, 'reeflex_decision' => 'require_approval'])` from the
wrapped `permission_callback`, and `WP_Ability::execute()` would have
surfaced the error without calling `do_execute()`.

### Step 5 — Verify the posts are untouched (after)

```bash
wp post list --post_status=publish --format=count
# 47  (unchanged)
```

The count is the same. No posts were deleted.

### Step 6 — Read the audit record

```bash
tail -n 1 uploads/reeflex-gate/reeflex-audit.jsonl | python3 -m json.tool
```

The last record should contain:

```json
{
  "ts": "2026-06-30T10:00:00Z",
  "ability": "mysite/bulk-delete-posts",
  "verb": "delete",
  "environment": "production",
  "count": 25,
  "axes": {
    "reversibility": "irreversible",
    "blast_radius": "broad",
    "externality": "internal"
  },
  "decision": "require_approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "applied": "hold"
}
```

The `signature` field will contain a stub value (`ed25519:stub:...`) in v0.1.
Full cryptographic signing is on the roadmap (SPEC §6).

---

## (c) Fail-closed check (live install)

This check confirms that stopping `reeflex-core` causes the adapter to block
all actions, never silently allow.

1. Stop `reeflex-core` (or change `REEFLEX_CORE_URL` to point at a dead
   port).
2. Trigger any ability — even a simple read: have the MCP agent call
   `core/get-post` with a valid post ID.
3. Observe the response:

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "error": {
       "code": -32603,
       "message": "Reeflex governance temporarily unavailable.",
       "data": { "status": 503 }
     }
   }
   ```

4. Check the audit log:

   ```bash
   tail -n 1 uploads/reeflex-gate/reeflex-audit.jsonl | python3 -m json.tool
   ```

   The record's `rule` field will be `reeflex.adapter/fail_closed` and
   `applied` will be `fail_closed_deny`.

5. Restart `reeflex-core`. Normal operation resumes on the next request.

The adapter never allows an action when core is unreachable, returns a
non-200 status, returns invalid JSON, or returns a response without a
`decision` field. All of these trigger the same fail-closed deny path.

---

## v0.1 stubs and roadmap items

The following items are stubs or not yet implemented. They are documented
here to set accurate expectations:

- **`meta.signature`** in the Action Envelope is `ed25519:stub:<nonce-prefix>`.
  Full ed25519 signing is pending Vault-backed key management.
- **Audit record signing** is likewise pending the Vault signing path.
- **`require_approval` is terminal.** The hold is recorded in the audit log
  but there is no built-in mechanism to store the hold, notify an approver,
  or accept a re-submission. An operator must act manually. The full
  server-side approval flow (hold record in WP options, HMAC-signed approval
  token, one-time-use receipt) is on the roadmap.
- **`trajectory_ref`** is emitted as `null`. Richer sequence/drift analysis
  is roadmap.
