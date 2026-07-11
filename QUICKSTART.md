# Reeflex — Quickstart (under 10 minutes)

> **Variant A — full on-prem.** This guide runs the engine on your own machine. A hosted/subscription variant is on the roadmap and not yet available — see [docs/adr/0001-deployment-model.md](docs/adr/0001-deployment-model.md).

This guide takes you from zero to watching Reeflex stop a bulk delete in
production, with no prior knowledge of the codebase.

---

## Fastest path — zero to verdict without a clone

If you just want a verdict right now and already have Docker, skip the clone
and the source setup entirely:

```bash
docker run -d -p 8080:8080 ghcr.io/reeflex-io/reeflex-core:latest
```

(`:latest` tracks the newest published image. To pin a specific version instead
— e.g. `:v0.1.5` at the time of writing — check the
[Releases page](https://github.com/Reeflex-io/reeflex/releases) for the current tag.)

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

Now send one decision request — a bulk delete of 50 posts in production
(irreversible, broad blast radius):

```bash
curl -s -X POST http://localhost:8080/v1/decide \
  -H 'content-type: application/json' \
  -d '{
    "action":    { "verb": "delete", "ability": "wordpress/delete-post" },
    "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
    "magnitude": { "count": 50 },
    "target":    { "environment": "production" },
    "agent":     { "session_id": "sess-quickstart-1" }
  }'
```

Expected response (core v0.1.5+; `hold_id` and `expires_ts` are additive HIL
fields — see [SPEC.md §5](reeflex-spec/SPEC.md#5-the-decision) — an older core
image returns the same `decision`/`reason`/`rule`/`obligations`/`modulation`
without them). Your own `hold_id` and `expires_ts` will differ — they are a
freshly generated ID and a timestamp 4 hours from your request:

```json
{
  "decision": "require_approval",
  "reason": "irreversible broad change in production requires human approval",
  "rule": "reeflex.policy/irreversible_broad_prod",
  "obligations": [],
  "modulation": null,
  "hold_id": "b2bece3cf6ff45f7b738ee3f48978c4e",
  "expires_ts": "2026-07-04T20:07:04Z"
}
```

That is the whole engine: one HTTP call, a deterministic verdict, zero LLM
anywhere in the decision path. The rest of this guide walks the same result
from source, plus the fail-closed and fragmentation-resistance scenarios the
one-shot `curl` above doesn't show.

---

## Step 0 — get the code (30 seconds)

```bash
git clone https://github.com/Reeflex-io/reeflex.git
cd reeflex
```

All commands below run from this directory (the repo root).

---

## Prerequisites check (2 minutes)

Open a terminal in the repo root and run the following:

```bash
python --version
```

Expected: `Python 3.12.x`. On some systems substitute `python3`.

```bash
opa version
```

Expected: a line beginning `Version: 1.18.` (the binary prints `Version: 1.18.0`; a compatible 1.x release is also acceptable).

### If OPA is not installed, install it now (1 minute)

OPA is a single static binary — no package manager required.

1. Download it for your OS:
   - **Windows:** `https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe` — rename the downloaded file to `opa.exe`.
   - **Linux:** `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static`
   - **macOS:** `curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64`
2. Make it executable and put it on your `PATH` (Linux/macOS: `chmod +x opa && sudo mv opa /usr/local/bin/opa`; Windows: place `opa.exe` in a folder already on your user `PATH`, e.g. `C:\tools\`). If you cannot install to a system location, skip this and just remember the full path — you will pass it as `REEFLEX_OPA_BIN` in the next step.
3. Re-run `opa version` to confirm.

Full per-OS detail and troubleshooting: [INSTALL.md](INSTALL.md).

---

## Set the minimal environment (30 seconds)

The demo reads two variables from the environment. The defaults are correct if
you run from the repo root and `opa` is on your `PATH`.

**Windows (cmd):**

```cmd
set REEFLEX_OPA_BIN=opa
set REEFLEX_POLICY_DIR=reeflex-core\policy
```

**Windows (PowerShell):**

```powershell
$env:REEFLEX_OPA_BIN = "opa"
$env:REEFLEX_POLICY_DIR = "reeflex-core\policy"
```

**Linux / macOS:**

```bash
export REEFLEX_OPA_BIN=opa
export REEFLEX_POLICY_DIR=reeflex-core/policy
```

If `opa` is not on your `PATH`, replace `opa` with the full absolute path to
the binary (e.g. `C:\tools\opa.exe` on Windows, `/home/user/bin/opa` on Linux).

---

## Run the demo (1 minute)

Note on ports: this demo starts its own `reeflex-core` subprocess on **8181**
(and a second throwaway instance on 8182 for the fail-closed scenario) — this
is separate from the **8080** default used by a standalone or Docker-run core
(as in the "Fastest path" section above). If you `curl` your own `/v1/decide`
call while the demo is running, make sure you target the port for the core
instance you actually mean to hit.

From the repo root:

```bash
python reeflex-mock/demo.py
```

The script:

1. Starts `reeflex-core` as a subprocess on port **8181** and waits until
   `/healthz` responds.
2. Runs 5 scenarios end-to-end (agent intent → normalized envelope → POST
   `/v1/decide` → verdict → enforced on the in-memory store).
3. Prints the normalized envelope, the verdict, and the store state
   before/after each scenario.
4. Starts a second core instance on port **8182** with a broken OPA binary
   path for the fail-closed scenario, then shuts it down.
5. Terminates the core subprocess cleanly.
6. Prints a per-scenario PASS/FAIL summary and an overall `STATUS: PASS` or
   `STATUS: FAIL`.

The demo takes approximately 15–30 seconds on a typical development machine.

No `make` is required. The Makefile in `reeflex-mock/` is a Unix convenience
wrapper that calls the same command.

---

## Reading the output

Each scenario block looks like this:

```
========================================================================
SCENARIO 3: Bulk delete 50 posts in production -> REQUIRE_APPROVAL (store UNTOUCHED)
========================================================================
NORMALIZED ENVELOPE:
{
  "reeflex_version": "0.1",
  "agent": { "session_id": "sess_demo_main_001", ... },
  "action": { "verb": "delete", "ability": "mock/bulk_delete", ... },
  "target": { "environment": "production", ... },
  "magnitude": { "count": 50 },
  "axes": {
    "reversibility": "irreversible",
    "blast_radius": "broad",
    "externality": "internal"
  },
  ...
}
VERDICT:
  decision  : require_approval
  rule      : reeflex.policy/irreversible_broad_prod
  reason    : irreversible broad change in production requires human approval
STORE BEFORE->AFTER:
  before: 99 posts  ids=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10] ... +89
  after : 99 posts  ids=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10] ... +89
  ASSERT [PASS] decision == require_approval
  ASSERT [PASS] outcome == held
  ASSERT [PASS] store_changed == False
  ASSERT [PASS] store count UNCHANGED (read-back)
  ASSERT [PASS] store IDs UNCHANGED (read-back)
```

The store before/after lines are a read-back verification: the adapter reads the
store state independently after enforcement to confirm the decision was applied
faithfully.

---

## What just happened — the 5 scenarios explained

### Scenario 1: Read a post — ALLOW, store unchanged

**Intent:** `GET post:10` in production.

The adapter maps `get` to verb `read`, axis `reversibility=reversible`,
`blast_radius=single`, `externality=internal`. None of the deny or
require-approval rules match. Core returns `allow`. The adapter executes the
read. The store is not mutated — confirmed by read-back.

**Key point:** a read-only internal action always passes regardless of
environment. The policy is deterministic: same envelope, same outcome, every
time.

### Scenario 2: Delete 1 post — ALLOW, post actually gone

**Intent:** delete post 42, `force_delete=False`, production.

A single soft-delete maps to `reversibility=recoverable`, `blast_radius=single`.
The combination does not trigger any high-risk rule. Core returns `allow`. The
adapter deletes from the store. The read-back confirms post 42 is gone and the
count dropped by one.

**Key point:** not every delete is blocked — only the ones whose normalized axes
match a rule. The policy governs by risk profile, not by operation name.

### Scenario 3: Bulk delete 50 posts in production — REQUIRE_APPROVAL, store intact

**Intent:** bulk delete 50 posts, `force_delete=True`, production.

50 posts with `force_delete=True` maps to `reversibility=irreversible`,
`blast_radius=broad`, `target.environment=production`. Rule R2 fires:

```
irreversible + broad + production -> require_approval
```

Core returns `require_approval`. The adapter holds the action — the store is
never touched. The read-back confirms the count and IDs are identical before and
after.

**Recovery path for this class of action:** Rule R2 (`irreversible + broad +
production`) does NOT check `approval.present`. Re-submitting this envelope with
`approval.present=true` will still return `require_approval` from R2 — approval
does not clear this gate. To proceed, the action must be **re-scoped**: reduce the
blast radius (fewer items at a time) or switch to a reversible/recoverable delete
mode so the envelope no longer matches the irreversible-broad-production profile.

Note: `approval.present=true` DOES clear the session delete-budget gate (Rule R5,
Scenario 4), which is a separate rule that explicitly checks `not input.approval.present`.

**Key point:** this is the headline scenario. The governance layer stopped a
dangerous action before it executed, not by matching a keyword in a prompt, but
by evaluating deterministic rules against a structured risk profile (the three
axes).

### Scenario 4: Fragmentation resistance — REQUIRE_APPROVAL at the crossing batch

**Intent:** repeated small deletes (5 at a time, new session) against a 20-item
cumulative budget.

This scenario uses a fresh session ID (`sess_demo_frag_002`). The adapter sends
batches of 5 to core. Each batch is individually below the threshold that would
trigger R2 or R3. Core tracks the cumulative delete count in an in-memory ledger
keyed by `session_id`. Rule R5:

```rego
prior_deletes + input.magnitude.count > delete_session_budget  (budget = 20)
not input.approval.present
```

Batches 1–4 bring the session's cumulative deletes to exactly 20 (each is
allowed). Batch 5 would push the total to 25 > 20, so it is HELD
(`require_approval`, rule `reeflex.policy/session_delete_budget`). That batch is
not executed; the store is unchanged for those IDs.

**Key point:** fragmentation — splitting a large dangerous action into many
small ones to evade per-call thresholds — is defeated. The budget is tracked
across the whole session. Fragmenting buys nothing. (SPEC §4.1)

### Scenario 5: OPA unavailable — DENY, store intact (fail-closed)

**Intent:** any action, but the core instance is started with a broken OPA
binary path (`/nonexistent/path/to/opa_does_not_exist`).

When the OPA subprocess cannot be invoked, the decision pipeline cannot evaluate
policy. The core engine fails closed and returns HTTP 500 with:

```json
{
  "decision": "deny",
  "rule": "reeflex.core/fail_closed",
  "reason": "policy evaluation unavailable - failing closed"
}
```

The adapter receives this response, enforces `deny`, blocks the action, and
leaves the store untouched. The read-back confirms no change.

**Separate path:** if the adapter cannot reach core at all (connection refused,
timeout), the adapter itself emits its own fallback deny with reason
`"reeflex-core unreachable or error — failing closed: <detail>"` — this is
adapter-side fail-closed, distinct from the core's OPA-error path above.

**Key point:** fail-closed is an invariant. A governance layer that silently
allows on error is not a governance layer. There is no configuration to change
this behaviour — it is structural.

---

## Govern an existing MCP fleet (reeflex-mcp)

If your agents already talk to MCP servers (filesystem, GitHub, Postgres, or
your own), `reeflex-mcp` puts the same `reeflex-core` decision in front of
all of them — without opening core to the internet or rewriting a client's
logic. It is **not yet published to PyPI**; install from source, from the
repo root:

```bash
cd reeflex-mcp
python -m venv .venv
.venv/Scripts/pip install -e .          # Windows; .venv/bin/pip on Linux/macOS

cp reeflex-mcp.yaml.example reeflex-mcp.yaml
# edit reeflex-mcp.yaml: point upstreams: at your real MCP server(s)

reeflex-mcp --config reeflex-mcp.yaml --transport stdio
```

Point your MCP client (Claude Desktop, Claude Code's `.mcp.json`, …) at
`reeflex-mcp` instead of the upstream directly — `reeflex-mcp setup` can do
that migration for you, with a backup and a `restore` undo. Every
`tools/call` is normalized into the same Action Envelope this guide's `curl`
examples use, decided by the same `reeflex-core` you just started, and (in
`observe` mode, the default) recorded without changing anything — flip to
`enforce` once you've watched what it would have held. Full guide:
[docs/mcp-gateway.md](docs/mcp-gateway.md).

---

## Wire your own backend

To connect a new backend (a database, an API, a file system), you implement a
Reeflex adapter. The adapter contract has four responsibilities (SPEC §6). The
worked reference implementation is `reeflex-mock/adapter.py`.

### Responsibility 1 — INTERCEPT

Capture the backend action *before* it executes. Your interception point is
adapter-specific: an API hook, a middleware layer, an MCP gateway, a database
driver wrapper. The key constraint is that the store must not be touched until
the decision is received and applied.

In `adapter.py`, the entry point is `MockAdapter.apply(intent)`. The agent
calls `apply()` with a structured intent; `apply()` is the enforcement seam
between the agent and the store. The store is never accessed directly by the
agent.

### Responsibility 2 — NORMALIZE

Translate the backend-specific intent into a valid Action Envelope (SPEC §2).
This is where your adapter's quality lives: every field in the envelope is
derived from what you know about the action, and unknown values MUST default to
the most-restrictive option (never omitted).

The three axes are the load-bearing output of normalization:

| Axis | Values (least to most restrictive) |
|---|---|
| `reversibility` | `reversible` → `recoverable` → `irreversible` |
| `blast_radius` | `single` → `scoped` → `broad` → `systemic` |
| `externality` | `internal` → `outbound` → `physical` |

The normalized verb (`read`, `create`, `update`, `delete`, `execute`,
`transact`, `emit`) is also required. The backend-specific operation id is
preserved in `action.ability` for fine-grained rules.

A stable `agent.session_id` is **required** — it is the key the ledger uses for
fragmentation-resistance tracking. A missing or empty `session_id` is rejected
with HTTP 400.

In `adapter.py`, the function is `MockAdapter._normalize(intent)`. Read the
module docstring for the axis-mapping decisions used by the mock backend.

### Responsibility 3 — ENFORCE

POST the envelope to core and apply the decision faithfully:

```
POST /v1/decide   Content-Type: application/json
{ ActionEnvelope }
->
{ "decision": "allow"|"deny"|"require_approval",
  "reason": "...",
  "rule": "reeflex.policy/...",
  "obligations": [...],
  "modulation": null }
```

Apply the decision:

- `allow` — execute the action on the backend.
- `deny` — block it. Surface `reason` to the caller. Backend untouched.
- `require_approval` — hold it. Route to a human reviewer. On approval,
  re-submit the envelope with `approval.present = true`. Backend untouched
  until the re-submission is allowed.

**Fail-closed is mandatory.** If core is unreachable, returns a non-200, or
returns a response without a `decision` field, the adapter MUST deny or hold.
It must never silently allow on error. In `adapter.py`, `MockAdapter._call_core()`
and the module-level `_fail_closed_decision()` implement this invariant.

If an `obligations` list is returned, every obligation in it must be honored.
Ignoring an obligation is a conformance failure.

### Responsibility 4 — AUDIT

Emit one append-only audit record per decision to the observation plane (JSONL,
a database, or your audit sink of choice). The record must include at minimum the
envelope summary, the decision, the rule that fired, and the applied outcome.
(Cryptographic signing of audit records is on the roadmap — see SPEC §6.)

In `adapter.py`, the function is `MockAdapter._audit(intent, envelope,
decision_resp, result)`. Note that an audit write failure must never affect the
decision — the audit path is wrapped in a try/except that logs to stderr and
continues.

### Minimal integration example

```python
from my_backend import execute_action
from reeflex_adapter import MyAdapter

adapter = MyAdapter(session_id="sess_abc123")

# INTERCEPT: receive intent before execution
intent = {
    "op": "delete",
    "ids": [1001, 1002, 1003],
    "environment": "production",
}

result = adapter.apply(intent)

if result["outcome"] == "executed":
    # action ran; result["store_value"] holds the backend return value
    pass
elif result["outcome"] == "held":
    # queue for human approval; re-submit with approved=True when cleared
    pass
elif result["outcome"] == "blocked":
    # surface result["reason"] to the caller
    raise PermissionError(result["reason"])
```

For the full worked example, including axis mapping, fail-closed wiring, and
JSONL audit output, read `reeflex-mock/adapter.py` end-to-end. The four
responsibilities map directly to these functions:

| Responsibility | Function in adapter.py |
|---|---|
| INTERCEPT | `MockAdapter.apply()` |
| NORMALIZE | `MockAdapter._normalize()` |
| ENFORCE | `MockAdapter._call_core()` + `MockAdapter._enforce()` |
| AUDIT | `MockAdapter._audit()` |

---

## What Reeflex is not

The decision path (`POST /v1/decide`) is OPA/Rego plus classical logic. There
is no LLM in this path. Free text, markdown, and OKF files are never decision
inputs. The same envelope in produces the same decision out, every time.

---

## Where to next

You just watched a deterministic gate stop a bulk delete, defeat fragmentation,
and fail closed — in under ten minutes, on your own machine. That is the whole
product in miniature.

- Put it in front of something real: the [WordPress adapter](reeflex-wordpress/)
  installs from the wp-admin UI in minutes.
- Point Claude Code at it: the [Claude Code adapter](reeflex-claude/) gates
  every tool call. It requires **Python 3.8+** (`pip install reeflex-claude`).
- Already running MCP servers? The [MCP gateway](reeflex-mcp/)
  (`reeflex-mcp`) governs any of them without a client rewrite — see the
  [gateway quickstart](#govern-an-existing-mcp-fleet-reeflex-mcp) above and
  [docs/mcp-gateway.md](docs/mcp-gateway.md).
- Build your own adapter: the [SPEC](reeflex-spec/SPEC.md) is deliberately
  simple — one envelope shape, four responsibilities — and
  [contributions are genuinely welcome](CONTRIBUTING.md).

*Reeflex — a seatbelt for the AI acting on your systems.*
