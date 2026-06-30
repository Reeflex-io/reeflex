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
python -m unittest tests.test_decide -v

# Linux / macOS
cd reeflex-core
python -m unittest tests.test_decide -v
```

Or using pytest if you have it available:

```bash
cd reeflex-core
python -m pytest tests/test_decide.py -v
```

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
    server.py          HTTP layer: GET /healthz, POST /v1/decide
    decide.py          Decision pipeline: validate -> ledger -> OPA -> audit
    envelope.py        Envelope validation and axis coercion
    opa.py             OPA subprocess wrapper (opa eval)
    ledger.py          In-memory per-session cumulative action ledger
    audit.py           Append-only JSONL audit writer
  policy/
    reeflex.rego       Policy rules R1–R5 (OPA/Rego)
    reeflex_test.rego  OPA unit tests for the policy
  tests/
    test_decide.py     Python unit tests for the full pipeline
  audit/
    decisions.jsonl    Audit log (created on first decision)
```
