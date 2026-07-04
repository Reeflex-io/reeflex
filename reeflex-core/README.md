# reeflex-core

The deterministic decision engine for Reeflex. Exposes `POST /v1/decide`, taking
an **Action Envelope** (see [`../reeflex-spec/SPEC.md`](../reeflex-spec/SPEC.md))
and returning a Decision (`allow` | `deny` | `require_approval`).

## Status

Working. The engine is complete and functional:

- `POST /v1/decide` — full request pipeline: envelope validation → axis coercion
  → cumulative ledger → OPA/Rego evaluation → decision → audit write.
- `GET /healthz` — liveness check, returns `{"status":"ok"}`.
- Fail-closed on any OPA error, connection failure, or unexpected exception.
- Append-only JSONL audit of every decision (cryptographic record signing is on the roadmap — see SPEC §6).
- Per-session cumulative action ledger for fragmentation-resistance (SPEC §4.1).
- Every decision can stream to a SIEM as syslog — see [`../docs/siem.md`](../docs/siem.md).

## Hard constraints (see ADR-0002)

- **Determinism is the product.** Decision path = OPA/Rego + classical logic.
  **Zero LLM** in the decision path.
- Same envelope in → same decision out.
- Fail-closed is structural: a missing or broken OPA binary produces
  `deny` with `rule: reeflex.core/fail_closed` — never `allow`.
- Free text, markdown, and OKF files are never decision inputs.

## Stack

- Language: **Python 3.12** (stdlib only — no pip dependencies).
- Policy engine: **OPA 1.18.x** (invoked as a subprocess via `opa eval`).
- Audit store: append-only **JSONL** file (path configurable via env var).

---

## Run the engine

From the repo root:

```bash
# Windows (cmd)
set REEFLEX_OPA_BIN=opa
python reeflex-core\main.py

# Linux / macOS
export REEFLEX_OPA_BIN=opa
python reeflex-core/main.py
```

The server binds to `127.0.0.1:8080` by default. Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_HOST` | `127.0.0.1` | Bind address |
| `REEFLEX_PORT` | `8080` | Bind port |
| `REEFLEX_OPA_BIN` | `opa` | OPA binary path or name |
| `REEFLEX_POLICY_DIR` | `./policy` | Directory containing `reeflex.rego` |
| `REEFLEX_AUDIT_LOG` | `./audit/decisions.jsonl` | Audit log path |
| `REEFLEX_WINDOW_SECONDS` | `3600` | Ledger rolling window in seconds |
| `REEFLEX_OPA_TIMEOUT` | `10` | OPA subprocess timeout in seconds |

### SIEM / syslog environment variables

Disabled by default — set `REEFLEX_SYSLOG_ENABLED=true` to activate.
Full integration guide: [`../docs/siem.md`](../docs/siem.md).

| Variable | Default | Meaning |
|---|---|---|
| `REEFLEX_SYSLOG_ENABLED` | `false` | Master switch. Any value other than `"true"` (case-insensitive) leaves the emitter as a no-op. |
| `REEFLEX_SYSLOG_ADDRESS` | _(unset)_ | Collector endpoint as `host:port`. Required when enabled; if omitted a one-time warning is printed and the emitter stays silent. |
| `REEFLEX_SYSLOG_PROTOCOL` | `udp` | Transport: `udp` (one datagram per message), `tcp` (RFC 6587 octet-counted, persistent connection), or `tls` (RFC 5425, TCP + TLS). |
| `REEFLEX_SYSLOG_FORMAT` | `json` | Wire format of the syslog MSG body: `json` (single-line JSON) or `cef` (CEF:0 string). |
| `REEFLEX_SYSLOG_FACILITY` | `local0` | RFC 5424 syslog facility name (e.g. `local0`–`local7`). |
| `REEFLEX_SYSLOG_TLS_VERIFY` | `true` | TLS only. `true` = verify server certificate using the system CA bundle (respects `SSL_CERT_FILE`). `false` = no-verify (self-signed collectors). |

Verify the server is running:

```bash
curl http://127.0.0.1:8080/healthz
# -> {"status":"ok"}
```

See [../INSTALL.md](../INSTALL.md) for OPA installation and troubleshooting.

---

## Run the tests

### Python unit tests

Run from the `reeflex-core/` directory:

```bash
# Windows
cd reeflex-core
python -m unittest discover -s tests -v

# Linux / macOS
cd reeflex-core
python -m unittest discover -s tests -v
```

Or using pytest if you have it available:

```bash
cd reeflex-core
python -m pytest tests/ -v
```

This runs all 55 tests across `test_decide.py` (decision pipeline),
`test_auth.py` (bearer-token auth), and `test_hardening.py` (limits,
error surface).

Tests drive the real `decide.process()` pipeline end-to-end. OPA is invoked as
a real subprocess — no mocking. `REEFLEX_OPA_BIN` must resolve to a working OPA
binary for the tests to pass (the fail-closed test intentionally points at a
nonexistent path and asserts `deny`).

Test coverage:

- `T_allow` — read-only internal → allow
- `T_approval` — irreversible + broad + production → require_approval (R2)
- `T_deny` — irreversible + systemic + production → deny (R3)
- `T_fragmentation` — same session_id, cumulative deletes crossing 20-item
  budget → require_approval at the crossing call (SPEC §4.1)
- `T_fail_closed` — nonexistent OPA binary → deny, never allow
- `T_reject_invalid` — missing required fields → HTTP 400
- `T_axis_coercion` — non-canonical axis values coerce to most-restrictive
- `T_count_validation` — invalid `magnitude.count` values → HTTP 400
- `T_count_audit_parity` — count in decision equals count in audit record
- `T_session_required` — missing/empty `session_id` → HTTP 400
- `T_obligations` — `obligations` field present in every 200 response
- `T_audit_readback_env` — `REEFLEX_AUDIT_LOG` env var respected
- `TestCrashSurface` — malformed inputs never raise; always return a clean
  `(status, dict)` tuple; fail-closed on deny-class shapes

### OPA policy tests

Run from the repo root (requires OPA on `PATH` or `REEFLEX_OPA_BIN` set):

```bash
opa test reeflex-core/policy/ -v
```

This runs `reeflex_test.rego` against `reeflex.rego` and covers all five policy
rules: R1 allow, R2 require_approval, R3 deny, R4 default allow, R5 session
delete budget (fragmentation resistance), plus approval-present bypass and
absent-cumulative defensive defaults.

---

## Run the demo

The demo is the fastest way to see the engine working end-to-end. It starts core
automatically — you do not need a running server.

From the repo root:

```bash
python reeflex-mock/demo.py
```

For a full walkthrough of what the demo does and how to read its output, see
[../QUICKSTART.md](../QUICKSTART.md).

---

## Directory layout

```
reeflex-core/
  main.py              Entry point; reads env vars, starts HTTP server
  app/
    server.py          HTTP layer: GET /healthz, POST /v1/decide, holds API
    decide.py          Decision pipeline: validate -> ledger -> OPA -> audit
    envelope.py        Envelope validation and axis coercion
    opa.py             OPA subprocess wrapper (opa eval)
    ledger.py          In-memory per-session cumulative action ledger
    audit.py           Append-only JSONL audit writer
    holds.py           Event-sourced JSONL hold store (HIL Phase 1)
    webhook.py         Outbound hold webhook emitter (HIL Phase 1)
  policy/
    reeflex.rego       Policy rules R1–R5 (OPA/Rego)
    reeflex_test.rego  OPA unit tests for the policy
  tests/
    test_decide.py     Python unit tests for the full pipeline
    test_hil.py        HIL Phase 1 tests (holds store, freeze, approval, API, webhook)
  audit/
    decisions.jsonl    Audit log (created on first decision)
    holds.jsonl        Hold event log (created on first hold)
```

---

## Holds and human-in-the-loop (Phase 1)

<!-- doc-version: HIL-Phase-1, source: app/holds.py app/webhook.py app/decide.py app/server.py design/HIL-DESIGN.md §16-18 -->

### The handover model

A hold is not a pending approval — it is a **transfer of jurisdiction**.

"The first decision is deterministic. The second decision is yours."

"We flag. You rule."

The first decision (OPA/Rego + classical logic, zero LLM) ends when the flag is raised. From that moment the outcome belongs to the operator, judged under their rules and procedures, by the principal they designate. Core provides the mechanism (the holds API, the audit of the handover) — never the gray-zone judgment. The liability line is absolute: core never makes the second call.

Core never executes actions. Re-submission after approval is the adapter's responsibility (Phase 2 — adapter surfaces). Core validates the approval and returns `allow`; the adapter then executes the original action.

### What creates a hold

When the OPA verdict is `require_approval` and no valid approval is already attached to the envelope, core creates a **pending hold** and returns it in the `/v1/decide` response:

```json
{
  "decision": "require_approval",
  "reason": "irreversible bulk delete in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "obligations": [],
  "modulation": null,
  "hold_id": "a3f8c1d2e4b7...",
  "expires_ts": "2026-07-04T16:00:00Z"
}
```

The `hold_id` and `expires_ts` fields are only present when the decision is `require_approval` and hold creation succeeded.

Rules that produce `require_approval` (and therefore holds) include `irreversible_broad_prod` and `session_delete_budget`. The systemic rule (`irreversible_systemic_prod`) always produces a terminal `deny` — it is never a hold and cannot be resolved by any principal.

### Holds API

All holds endpoints use the same `Authorization: Bearer <token>` authentication as `POST /v1/decide`. If `REEFLEX_AUTH_TOKEN` is unset, auth is disabled (backward-compatible with the main decide endpoint).

#### GET /v1/holds

List holds, with optional status filter and cursor-based pagination.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `status` | string | Filter: `pending`, `approved`, `rejected`, `expired`, `consumed`. Absent = all statuses. |
| `limit` | integer | Max items per page (default 100, max 1000). |
| `cursor` | string | Opaque pagination token (`hold_id` of the last item on the previous page). |

Expiry is swept lazily on each list call: any pending hold past its `expires_ts` transitions to `expired` before the result is returned.

**Request:**

```
GET /v1/holds?status=pending&limit=50 HTTP/1.1
Authorization: Bearer <token>
```

**Response (200):**

```json
{
  "items": [
    {
      "id": "a3f8c1d2e4b7...",
      "created_ts": "2026-07-04T12:00:00Z",
      "expires_ts": "2026-07-04T16:00:00Z",
      "rule_id": "reeflex.policy/irreversible_broad_prod",
      "status": "pending",
      "decided_by": null,
      "decided_ts": null,
      "reason": null,
      "consumed_ts": null
    }
  ],
  "count": 1,
  "next_cursor": null
}
```

When there are more items, `next_cursor` contains the `hold_id` of the last item on this page. Pass it as `cursor=` in the next request. When `next_cursor` is absent, this is the last page.

#### GET /v1/holds/{id}

Retrieve full detail for one hold, including the original action envelope.

**Request:**

```
GET /v1/holds/a3f8c1d2e4b7... HTTP/1.1
Authorization: Bearer <token>
```

**Response (200):**

```json
{
  "id": "a3f8c1d2e4b7...",
  "event_type": "created",
  "created_ts": "2026-07-04T12:00:00Z",
  "expires_ts": "2026-07-04T16:00:00Z",
  "envelope": { "action": { "verb": "delete", ... }, "axes": { ... }, ... },
  "envelope_hash": "7f3e8a...",
  "rule_id": "reeflex.policy/irreversible_broad_prod",
  "status": "pending",
  "decided_by": null,
  "decided_ts": null,
  "reason": null,
  "consumed_ts": null
}
```

**Response (404):** `{"error":"not_found","hold_id":"a3f8c1d2e4b7..."}`

#### POST /v1/holds/{id}/resolve

Resolve a pending hold. The caller supplies their identity as a principal.

**Request body:**

```json
{
  "decision": "approve",
  "principal": {
    "type": "human",
    "id": "leo.david"
  },
  "reason": "reviewed the scope; approved"
}
```

- `decision`: `"approve"` or `"reject"`. Required.
- `principal.type`: must be one of the types allowed by the resolution policy for this rule. Required.
- `principal.id`: the caller's identity string. Required.
- `reason`: optional free text.

**Response (200):** the updated hold record with `status`, `decided_by`, and `decided_ts` filled in.

```json
{
  "id": "a3f8c1d2e4b7...",
  "status": "approved",
  "decided_by": "human:leo.david",
  "decided_ts": "2026-07-04T12:34:56Z",
  "reason": "reviewed the scope; approved",
  ...
}
```

**Resolve error codes:**

| HTTP | `error` field | Meaning |
|---|---|---|
| 404 | `not_resolvable` | Hold not found, or status is not `pending`, or hold has expired. |
| 403 | `rule_not_resolvable` | The rule that triggered this hold cannot be resolved by any principal (e.g. `irreversible_systemic_prod`). |
| 403 | `principal_type_not_allowed` | The `principal.type` is not in the allowed list for this rule under the current resolution policy. |
| 403 | `actor_is_approver` | `principal.id` matches the `agent.id` that raised the hold. An agent cannot approve its own action. |

#### Approval-validation deny reason codes (on resubmission to /v1/decide)

When an envelope carries `approval.present=true` and validation fails, `/v1/decide` returns `decision=deny` with the reason field set to one of:

| Reason code | Meaning |
|---|---|
| `reeflex_hold_not_found` | The `hold_id` does not exist in the store. |
| `reeflex_hold_not_approved` | The hold exists but its status is not `approved`. |
| `reeflex_hold_expired` | The hold's `expires_ts` has passed. |
| `reeflex_hold_consumed` | The hold was already used for a prior resubmission. Single-use. |
| `reeflex_hold_envelope_mismatch` | The `sha256` of the action-defining fields in this envelope does not match the hash stored when the hold was created (the action was modified). |
| `reeflex_hold_actor_is_approver` | The resubmitting agent's identity matches the identity that resolved the hold. |

### Approval principals

Three principal types may resolve a hold, all via `POST /v1/holds/{id}/resolve`:

- **human** — a human operator (the only type enabled by default).
- **agent** — AIL. The AIL definition (verbatim from design/HIL-DESIGN.md §17):

  > "AIL (agent-in-the-loop): the resolution of a governance hold by an AI principal that the operator designates, under the operator's resolution policy — with the principal's identity recorded in the audit trail, and never the agent whose action raised the hold."

- **automation** — resolution by the operator's workflow or decision system (BPMN process, DMN table, SOAR playbook), recorded as such.

**Core-enforced guarantees (surfaces cannot bypass these):**

- The resolution policy is the operator's, per rule. The shipped default is human-only for all rules.
- Actor != approver is enforced on identity: the agent whose action raised the hold can never resolve it, on any surface, via any principal type.
- `irreversible_systemic_prod` is resolvable by no principal — its deny is terminal.
- `decided_by` records `type:identity` verbatim — for example `human:leo`, `agent:triage-bot`, `automation:camunda-proc-123`. This record is the EU AI Act Art. 14 oversight-allocation evidence (the Attest input). Zero AI is in the first decision path; principal choice is the operator's documented governance.

### Resolution policy configuration

**Environment variable:** `REEFLEX_RESOLUTION_POLICY`

Set to either a JSON string or a path to a JSON file. Shape:

```json
{
  "default": ["human"],
  "session_delete_budget": ["human", "agent"]
}
```

- Keys are rule short-names — the part after the last `/` in the `rule_id` (e.g. `irreversible_broad_prod` for `reeflex.policy/irreversible_broad_prod`).
- The `"default"` key applies to any rule not explicitly listed.
- **Absent or malformed:** treated as `{"default": ["human"]}` — human-only everywhere.

If `REEFLEX_RESOLUTION_POLICY` is unset, every hold requires a human principal to resolve it.

### The hash binding

Each hold stores the `sha256` of the **action-defining projection** of the original envelope — the fields `action`, `axes`, `magnitude`, and `target`, sorted by key at every level. This is the `envelope_hash`.

When the adapter resubmits an envelope with `approval={present:true, hold_id:"..."}`, core recomputes the hash over the same projection. If the hashes do not match, the resubmission is denied with `reeflex_hold_envelope_mismatch`.

The `approval` field is deliberately excluded from the projection: the hash is identical for the original submission (where `approval.present=false`) and the resubmission (where `approval` carries the `hold_id`). Adding the approval field does not break the binding. A modified action — different verb, count, target, or axes — produces a different hash and cannot ride the old approval.

TTL default is 4 hours (`REEFLEX_HOLD_TTL_SECONDS`). A hold past its `expires_ts` evaluates to `deny` with reason `reeflex_hold_expired`.

### Kill-switch / freeze

**Environment variable:** `REEFLEX_FREEZE`

Set to `true`, `1`, or `yes` (case-insensitive) to freeze all non-read write actions immediately. Re-read on every request — no restart required.

**When frozen:**
- Any non-read verb (`delete`, `create`, `update`, `execute`, `transact`, `emit`, etc.) → `deny`, reason `"frozen by operator"`, rule `reeflex.policy/frozen`.
- Read verbs (`read`, `list`, `get`, `query`, `search`, `describe`, `inspect`) pass through to normal evaluation so investigation tooling keeps working.

**Freeze flips** (on → off or off → on) are audited to the JSONL audit log and fire a `freeze.flipped` webhook event.

Set `REEFLEX_FREEZE=false`, `0`, `no`, or unset it to lift the freeze.

### Outbound hold webhook

**Environment variable:** `REEFLEX_WEBHOOK_URL`

When set, core POSTs a JSON payload to this URL for each hold event. When unset (the default), no thread is spawned and there is zero overhead on the decision path.

**Delivery invariant:** fire-and-forget, at-most-once. A bounded in-memory queue (default depth 1000, configurable via `REEFLEX_WEBHOOK_QUEUE_SIZE`) drains on a single background daemon thread. `fire()` is non-blocking: if the queue is full, the event is dropped and a counter is incremented. 3-second timeout per POST. No retries. The webhook emitter can never block or fail `/v1/decide`.

**Events:**

| Event | When fired |
|---|---|
| `hold.created` | A new pending hold is materialized from a `require_approval` verdict. |
| `hold.resolved` | A hold is approved or rejected via `POST /v1/holds/{id}/resolve`. |
| `hold.expired` | A pending hold is observed past its `expires_ts` (lazy, on first read after expiry). |
| `freeze.flipped` | `REEFLEX_FREEZE` state changes between consecutive requests. |

**Sample payload (`hold.created`):**

```json
{
  "event": "hold.created",
  "ts": "2026-07-04T12:00:00Z",
  "hold_id": "a3f8c1d2e4b7...",
  "rule_id": "reeflex.policy/irreversible_broad_prod",
  "status": "pending",
  "expires_ts": "2026-07-04T16:00:00Z"
}
```

**Sample payload (`hold.resolved`):**

```json
{
  "event": "hold.resolved",
  "ts": "2026-07-04T12:34:56Z",
  "hold_id": "a3f8c1d2e4b7...",
  "rule_id": "reeflex.policy/irreversible_broad_prod",
  "status": "approved",
  "decided_by": "human:leo.david"
}
```

**Sample payload (`freeze.flipped`):**

```json
{
  "event": "freeze.flipped",
  "ts": "2026-07-04T13:00:00Z",
  "freeze_on": true
}
```

Consumers (Camunda, Flowable, n8n, SOAR playbooks) are documented as integration guides — core builds the outbound socket, not the workflow engines. Any HTTP endpoint that can receive a POST and call back `POST /v1/holds/{id}/resolve` is a valid consumer.

### HIL Phase 1 environment variables

| Variable | Default | Meaning |
|---|---|---|
| `REEFLEX_HOLDS_PATH` | `<repo>/reeflex-core/audit/holds.jsonl` | Path to the JSONL hold event log. Created on first hold. |
| `REEFLEX_HOLD_TTL_SECONDS` | `14400` (4 hours) | Time-to-live for a pending hold. A hold past this TTL evaluates to `deny`. |
| `REEFLEX_FREEZE` | _(unset / false)_ | Set to `true`, `1`, or `yes` to deny all non-read verbs immediately. Hot-reloadable without restart. |
| `REEFLEX_RESOLUTION_POLICY` | _(unset)_ | JSON string or file path. Shape: `{"default":["human"],"<rule_short_name>":["human","agent"]}`. Absent = human-only everywhere. |
| `REEFLEX_WEBHOOK_URL` | _(unset)_ | Outbound webhook endpoint. Absent = no webhook, no background thread. |
| `REEFLEX_WEBHOOK_QUEUE_SIZE` | `1000` | Max in-memory queue depth before events are dropped. |
