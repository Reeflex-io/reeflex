# Reeflex — Adapter Examples: WordPress & PostgreSQL

Two backends, two completely different interception mechanisms, **one envelope, one policy.** This is the whole thesis made concrete: write the rule once, govern everything.

Each adapter does the same four things from the contract: **intercept -> normalize -> enforce -> audit.** Only *intercept* and *normalize* differ per backend. The decision call and the policy are shared.

---

## A. WordPress adapter (PHP)

**Interception seam:** the WordPress Abilities API executes registered abilities through the MCP Adapter. The adapter binds a filter at the ability-execution boundary, *before* the ability's callback runs. (The exact hook binds to your Abilities API version — the seam is "just before execute". Confirm against the live API when building the production adapter.)

```php
<?php
// reeflex-wordpress: gate every agent ability before it runs.

add_filter( 'reeflex_ability_pre_execute', 'reeflex_gate', 10, 3 );

function reeflex_gate( $proceed, string $ability, array $input ) {
    $envelope = reeflex_normalize( $ability, $input );
    $decision = reeflex_decide( $envelope );   // POST -> core /v1/decide

    reeflex_audit( $envelope, $decision );     // observation plane

    if ( $decision['decision'] === 'deny' ) {
        return new WP_Error( 'reeflex_denied', $decision['reason'], [ 'status' => 403 ] );
    }
    if ( $decision['decision'] === 'require_approval' && empty( $input['_reeflex_approved'] ) ) {
        return new WP_Error( 'reeflex_hold', $decision['reason'], [ 'status' => 202 ] );
    }
    return $proceed;   // allow -> WordPress runs the ability
}

// NORMALIZE: map a WordPress ability into the universal envelope.
function reeflex_normalize( string $ability, array $input ): array {
    // Example: core/delete-post
    $count = isset( $input['ids'] ) ? count( $input['ids'] ) : 1;
    $force = ! empty( $input['force_delete'] );   // skip trash = unrecoverable

    return [
        'reeflex_version' => '0.1',
        'agent'  => [
            'id'           => reeflex_current_agent_id(),
            'on_behalf_of' => 'user:' . wp_get_current_user()->user_login,
            'session_id'   => reeflex_session_id(),
        ],
        'action' => [
            'namespace' => 'wordpress',
            'verb'      => 'delete',
            'ability'   => $ability,                 // "core/delete-post"
        ],
        'target' => [
            'kind'        => 'post',
            'ref'         => $count === 1 ? 'post:' . $input['ids'][0] : null,
            'environment' => REEFLEX_ENV,            // "production"
        ],
        'params'    => $input,
        'magnitude' => [ 'count' => $count ],
        'axes'      => [
            'reversibility' => $force ? 'irreversible' : 'recoverable', // trash = recoverable
            'blast_radius'  => $count > 20 ? 'broad' : ( $count > 1 ? 'scoped' : 'single' ),
            'externality'   => 'internal',
        ],
        'approval' => [ 'present' => ! empty( $input['_reeflex_approved'] ), 'by' => null, 'role' => null ],
        'meta'     => reeflex_sign( /* timestamp + nonce */ ),
    ];
}
```

The agent asks to delete 50 posts permanently -> envelope says `verb: delete, irreversible, broad, production`.

---

## B. PostgreSQL adapter (Python)

**Interception seam:** a thin proxy sits in front of Postgres (or wraps a Postgres MCP server). It parses the incoming SQL and uses `EXPLAIN` to estimate cardinality *before* execution. Completely different mechanism — identical envelope.

```python
# reeflex-postgres: gate every agent statement before it hits the database.

def on_statement(sql: str, conn) -> None:
    envelope = normalize(sql, conn)
    decision = reeflex_decide(envelope)        # POST -> core /v1/decide
    reeflex_audit(envelope, decision)          # observation plane

    if decision["decision"] == "deny":
        raise PolicyDenied(decision["reason"])
    if decision["decision"] == "require_approval" and not conn.ctx.approved:
        raise PolicyHold(decision["reason"])
    conn.execute(sql)                          # allow

# NORMALIZE: map a SQL statement into the universal envelope.
def normalize(sql: str, conn) -> dict:
    stmt  = parse_sql(sql)                      # verb, table, where-clause
    rows  = estimate_rows(sql, conn)           # EXPLAIN -> estimated affected rows
    has_backup = conn.ctx.pitr_enabled         # point-in-time recovery available?

    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": conn.ctx.agent_id,
            "on_behalf_of": conn.ctx.principal,
            "session_id": conn.ctx.session_id,
        },
        "action": {
            "namespace": "postgres",
            "verb": stmt.verb,                  # "delete"
            "ability": f"postgres/{stmt.verb}-rows",
        },
        "target": {
            "kind": "table",
            "ref": stmt.table,                  # "users"
            "environment": conn.ctx.environment,  # "production"
        },
        "params": {"where": stmt.where},
        "magnitude": {"count": rows},
        "axes": {
            "reversibility": "recoverable" if has_backup else "irreversible",
            "blast_radius": "broad" if rows > 20 else ("scoped" if rows > 1 else "single"),
            "externality": "internal",
        },
        "approval": {"present": conn.ctx.approved, "by": None, "role": None},
        "meta": reeflex_sign(),                 # timestamp + nonce + signature
    }
```

The agent issues `DELETE FROM users WHERE active = false` with no backup, affecting 1,206 rows -> envelope says `verb: delete, irreversible, broad, production`.

> Note: this is the same failure class behind widely-reported AI-agent incidents — an agent issuing a destructive bulk action against production. The same envelope a WordPress bulk-delete produces.

---

## C. The shared policy (Rego) — governs BOTH

Neither rule mentions WordPress or Postgres. It reasons in the universal vocabulary, so it fires identically for both adapters.

```rego
package reeflex.policy

default decision := {"allow": false, "reason": "denied by default"}

# Read-only is always fine, anywhere.
decision := {"decision": "allow"} {
    input.action.verb == "read"
}

# Irreversible + broad + production -> a human must approve. Any backend.
decision := {
    "decision": "require_approval",
    "reason": "irreversible broad action in production requires human approval",
    "rule": "reeflex.policy/irreversible_broad_prod",
    "obligations": ["audit:full"],
} {
    input.target.environment == "production"
    input.axes.reversibility == "irreversible"
    input.axes.blast_radius == "broad"
    not input.approval.present
}

# Everything else within a single, recoverable entity -> allow.
decision := {"decision": "allow"} {
    input.axes.blast_radius == "single"
    input.axes.reversibility != "irreversible"
}
```

---

## What just happened

| | WordPress | PostgreSQL |
|---|---|---|
| Intercept | PHP filter on ability execution | SQL proxy + `EXPLAIN` |
| Backend action | `core/delete-post`, 50 posts, force | `DELETE FROM users`, 1,206 rows, no backup |
| Normalized envelope | `delete - irreversible - broad - production` | `delete - irreversible - broad - production` |
| Policy hit | `irreversible_broad_prod` | `irreversible_broad_prod` |
| Outcome | **held for human approval** | **held for human approval** |

One rule. Two backends it has never heard of. Both dangerous deletes stopped before they ran.

That is why an adapter author only has to answer one question — *"how do I turn my backend's actions into the envelope?"* — and gets the entire deterministic policy engine, audit trail, and approval flow for free. That single, small surface is what lets the community build `reeflex-s3`, `reeflex-git`, `reeflex-kafka` without ever touching the core.
