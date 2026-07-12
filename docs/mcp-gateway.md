# Reeflex MCP Gateway (`reeflex-mcp`)

<!-- doc-version: mcp-gateway-v1.0 | source: design/MCP-GATEWAY-DESIGN.md (v1 + addenda v1.1-v1.5), reeflex-mcp/ (README.md, reeflex_mcp/*.py, reeflex-mcp.yaml.example), reeflex-spec/SPEC.md -->

`reeflex-mcp` is a transparent MCP proxy that governs any MCP upstream. It
sits in the MCP path, intercepts `tools/call`, normalizes the call into a
Reeflex [Action Envelope](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md#2-the-action-envelope),
asks `reeflex-core`'s `POST /v1/decide`, and enforces the verdict —
everything else (`initialize`, `tools/list`, `resources/*`, `prompts/*`,
notifications) passes through unmodified. One seam, the entire MCP ecosystem
in front of it.

**The decision path is unchanged by putting it behind a gateway.** The
verdict is computed by OPA/Rego plus classical logic in `reeflex-core` —
deterministic, zero LLM. `reeflex-mcp` does not add a second decision engine;
it normalizes deterministically (name-based, declarative, or a fixed
conservative default — never an inference) and calls the same
`/v1/decide` every other adapter calls. Free text, markdown, and OKF
documents are never inputs to that decision, here or anywhere else in
Reeflex.

**Status:** built, conformance-tested against [SPEC §7](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md#7-conformance)
(all minimums, including obligations). **Not yet published to PyPI** —
install from source (§9 below); publishing is a gate (human GO), same as
every other Reeflex package.

For the competitive framing against commodity "MCP gateway" products (identity
/ routing, not impact judgment), see
[why-reeflex.md](why-reeflex.md#reeflex-mcp--governance-judgment-at-the-mcp-seam).
This page is the operator guide: architecture, config, mappings, obligations,
lifecycle, and the honest limits.

---

## 1. Architecture — one stateless process, all state in core

`reeflex-mcp` is a single stateless process with three internal stages:

```
 MCP client (Claude Desktop, agent, …)
        │  JSON-RPC (stdio | streamable-HTTP)
        ▼
 ┌─────────────────────────────────────────────┐
 │ reeflex-mcp                                  │
 │  [FRONT]  MCP server  (dual transport)       │
 │     │ intercept tools/call ; pass all else   │
 │  [HOOK]   normalize → POST /v1/decide → enforce│
 │  [BACK]   MCP client → upstream(s)           │
 └─────────────────────────────────────────────┘
        │  stdio child-proc | streamable-HTTP
        ▼
 upstream MCP server(s)          reeflex-core /v1/decide + /v1/holds
```

- **No decision state in the gateway.** R5's cumulative per-session ledger,
  holds, and audit all live in `reeflex-core`, keyed by `agent.session_id`
  (see §2 below). The gateway holds only its loaded config (upstream
  registry + mappings), live upstream client sessions, and per-connection
  session identity. A crash loses nothing that matters.
- Every `tools/call` gets a fresh `/v1/decide` — the gateway never caches or
  short-circuits a verdict. Caching would defeat the R5 fragmentation guard
  (an allow the gateway "remembers" is exactly what the guard exists to
  prevent).
- **Dynamic discovery, zero hardcoded tool knowledge.** On connect, the
  gateway calls `tools/list` on each configured upstream, namespaces every
  tool as `<upstream>__<tool>` (so multiple upstreams never collide), and
  presents the union to the client. It re-emits `tools/list_changed` when an
  upstream's tool set changes.

---

## 2. Deployment modes (both shipped)

### 2.1 stdio / local child-process (the desktop/dev default)

The client launches `reeflex-mcp` itself as a stdio MCP server (the same way
Claude Desktop launches any MCP server); the gateway in turn launches each
stdio upstream as its own child process. A client restart restarts the
gateway, which restarts the upstreams — which is exactly what makes the
startup drift check (§7) reliable: one connection is one agent is one stable
`session_id` for `reeflex-core`'s R5 ledger.

```bash
reeflex-mcp --config reeflex-mcp.yaml --transport stdio
```

### 2.2 streamable-HTTP / service mode (the multi-agent, hardened model)

The gateway runs as a long-lived process/container; clients connect over
streamable-HTTP with per-client auth (§4), and upstreams may be HTTP and/or
stdio. Single-path (§7) is enforced by network topology in this mode:
upstreams should be reachable only from the gateway, never directly from a
client.

```bash
reeflex-mcp --config reeflex-mcp.yaml --transport streamable-http --host 127.0.0.1 --port 8000
```

In this mode, `session_id` is derived from the authenticated client identity
(the `clients:` block in `reeflex-mcp.yaml`, §3) rather than one-per-process,
so each agent keeps its own R5 budget across reconnects and two agents can't
dilute each other's.

---

## 3. Config reference

### `reeflex-mcp.yaml` — the operator-owned multi-upstream registry

```yaml
# observe (default, never breaks traffic) | enforce. REEFLEX_MODE overrides this.
mode: observe

upstreams:
  # A local, stdio-launched MCP server — the gateway spawns it as a child process.
  - name: fs
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    target:
      system: filesystem       # matches the bundled mappings/filesystem.yaml starter automatically
      environment: staging     # production | staging | dev — the strictness lever
    required: true              # default true: unreachable at boot -> refuse to boot

  # A remote, streamable-HTTP MCP server.
  - name: gh
    url: https://mcp.internal/github
    auth:
      token_env: GH_MCP_TOKEN   # by-reference; read fresh at connect time — never inline
    target:
      system: github            # matches the bundled mappings/github.yaml starter automatically
      environment: production
    required: true

# OPTIONAL — service-mode per-client auth + session scaffold. Maps a presented
# bearer token (streamable-HTTP front only) to a stable session_id, so core's
# R5 cumulative per-agent ledger stays intact across reconnects.
clients:
  - token_env: CLIENT_ALICE_TOKEN
    session_id: agent:alice

# OPTIONAL — directory of declarative <system>.yaml mapping files (§5). Omit
# to use the package's own bundled starter mappings (filesystem/github/postgres).
# mappings_dir: ./mappings
```

A runnable copy ships as `reeflex-mcp/reeflex-mcp.yaml.example`. Secrets are
**always by-reference** — an env var *name* (`token_env`), never a value —
in this file, in logs, or in any report. `target.environment` is the
strictness lever: the same five base policy rules read harder or softer
purely from this axis (`production` trips R2/R3; `staging`/`dev` don't) —
there is no separate "prod mode" switch to forget.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_CORE_URL` | `http://127.0.0.1:8080` | `reeflex-core` base URL |
| `REEFLEX_CORE_TOKEN` | unset | bearer token for `reeflex-core` (never logged) — the project-standard name (see the note below) |
| `REEFLEX_MODE` | `observe` | `observe` \| `enforce` — overrides the YAML `mode:` if set |
| `REEFLEX_VERIFY_SSL` | `true` | set to `0`/`false`/`no`/`off` to disable TLS verification (dev/self-signed only, at your own risk) |
| `REEFLEX_MCP_TIMEOUT` | `10` | seconds, HTTP timeout to `reeflex-core` |
| `REEFLEX_MCP_CONFIG` | `./reeflex-mcp.yaml` | path to the registry file |
| `REEFLEX_MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` |
| `REEFLEX_MCP_HOST` / `REEFLEX_MCP_PORT` | `127.0.0.1` / `8000` | streamable-HTTP bind address |
| `REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT` | `10` | seconds, per-upstream connect timeout at boot (fail-closed-at-boot) |
| `REEFLEX_MCP_CALL_TIMEOUT` | `30` | seconds, per-call dispatch timeout to an upstream |
| `REEFLEX_MCP_MAPPINGS_DIR` | unset | directory of declarative mappings — overrides the YAML `mappings_dir:`; unset on both → the bundled starter mappings |
| `REEFLEX_MCP_ADMIN_TOKEN` | unset | optional shared-token gate on the `/admin/reload` hot-reload route; unset → no auth required (fine for a gateway bound to `127.0.0.1`, the default) |

**Note on `REEFLEX_CORE_TOKEN`:** this is the project-standard bearer-token
env var name, used by `reeflex-claude` and `reeflex-wordpress`. The earlier
`reeflex-holds` MCP server used the outlier name `REEFLEX_TOKEN`; that is a
documented inconsistency in that one component, not a second standard —
`reeflex-mcp` uses `REEFLEX_CORE_TOKEN` from day one.

---

## 4. Mappings — declarative normalization (Track 4)

Every `tools/call` is normalized into an Action Envelope via a **3-tier
resolution**, highest precedence first:

1. **Declarative mapping** — `mappings/<target.system>.yaml` has an entry for
   this exact tool name. Source tag: `mapping`.
2. **Name-heuristic** — the tool name matches a `delete_*`/`remove_*`/
   `drop_*` (→ `delete`, irreversible), `send_*`/`post_*`/`create_*`/`push_*`
   (→ `create`, outbound), or `get_*`/`list_*`/`read_*`/`search_*` (→ `read`)
   prefix. Source tag: `heuristic:<bucket>`.
3. **Conservative default** — nothing above matched; axes are forced to the
   restrictive floor (`irreversible`/`systemic`/`internal`), same fail-closed
   spirit as core's own axis coercion. Source tag: `heuristic:default`.

Every envelope carries which tier fired at `context.classification_source`,
and the gateway logs it to stderr on every call
(`[reeflex-mcp] classified '<tool>' via '<tier>' -> verb='<verb>'`).

**GIGO honesty (design doc §8, verbatim):**

> Mapping quality is adapter quality. A tool the gateway maps wrong is
> governed wrong. The starter mappings are a floor you can read and correct,
> not a guarantee — the same candor we apply to what the base policy does
> not catch.

### The 3 starter mappings (real, verified tool names — not invented)

| File | Targets (real server) | Honest limitation |
|---|---|---|
| `filesystem.yaml` | `@modelcontextprotocol/server-filesystem` (the official reference filesystem MCP server, 14 real tools) | **No delete tool exists** on this server — the split is read vs. **irreversible-write** (`write_file`/`edit_file`, classified from their own real `destructiveHint: true` MCP annotation), not read-vs-delete. |
| `github.yaml` | `modelcontextprotocol/servers-archived` GitHub server (the archived but canonical, widely-mirrored reference surface, 26 real tools) | **No delete-anything tool either** — the irreversible/broad/outbound example is `merge_pull_request` (a merge has no "unmerge"). Operators on the current official `github/github-mcp-server` (Go) must adjust tool names — this starter is a floor-to-correct (GIGO), flagged in the mapping file itself. |
| `postgres.yaml` | `crystaldba/postgres-mcp` ("Postgres MCP Pro", a real, actively-maintained community server) | `execute_sql` takes **one opaque `sql: str`** — no row-count argument exists on any real Postgres MCP server, so the original "magnitude-from-args DELETE/UPDATE row count" idea does not apply here. `execute_sql` is instead conservatively classified worst-case (`delete`/`irreversible`/`broad`) so it still engages R5's session delete budget. The genuine "magnitude scales with a real list-typed argument" demonstration lives in `filesystem.yaml` (`read_multiple_files`'s `paths`) and `github.yaml` (`push_files`'s `files`) instead. |

Each starter file comments its own reasoning inline against the real tool's
own MCP annotations — read the files, don't just trust this table.

### Writing your own mapping

Create `mappings/<your-system-name>.yaml` (matching the `target.system` you
gave that upstream):

```yaml
tools:
  send_email:
    verb: emit
    axes: { reversibility: irreversible, blast_radius: single, externality: outbound }
  list_drafts:
    verb: read
    axes: { reversibility: reversible, blast_radius: single, externality: internal }
  bulk_archive:
    verb: update
    # axes.externality omitted on purpose — see "partial axes" below
    axes: { reversibility: recoverable, blast_radius: scoped }

# OPTIONAL — count = len(arguments[<name>]) if it's a list, else 1.
# Omit entirely if no tool takes a structured/countable argument.
magnitude:
  from_arg: message_ids
```

**Partial axes are fine.** Any axis you omit is filled with `reeflex-core`'s
own restrictive default (`irreversible`/`systemic`/`physical`) — never a
different, gateway-invented guess. Point `reeflex-mcp.yaml`'s
`mappings_dir:` (or `REEFLEX_MCP_MAPPINGS_DIR`) at the directory containing
your file, or drop it into the package's own `reeflex_mcp/mappings/` in a
source checkout.

---

## 5. Verdicts, obligations, and holds

Every `tools/call` → normalize → `POST /v1/decide`:

- **`allow`** → forward to the upstream; tag core's `decision_id` in the
  result (and `parent_decision_id` on an approved resubmission).
- **`deny`** → return `isError: true`, text = `rule` + `reason` +
  `decision_id`. Not forwarded.
- **`require_approval` (hold)** → return an error result carrying `hold_id` +
  `expires_ts` and the instruction to resolve via `reeflex-holds` (or the
  `/v1/holds` API directly); not forwarded. When the client retries, the
  gateway re-sends `/v1/decide` with `approval: {present: true, hold_id,
  parent_decision_id}`; on the resulting `allow` (rule
  `reeflex.policy/approved_resubmission`) it forwards and the upstream
  executes. **`reeflex-core` never executes — the gateway executes after the
  allow.** A modified retry (different verb/count/target/axes) is denied
  with `reeflex_hold_envelope_mismatch`, because the hold is bound to the
  canonical `{action, axes, magnitude, target}` hash.
- **`observe` (default)** → call `/v1/decide`, write the audit trail,
  **always forward**, and **fail open** — observe must never break traffic.
  Holds are still minted by core on every `require_approval` regardless of
  gateway mode (core does not branch on mode); in observe they self-expire
  unused, standing as the record of what *would* have been held.
- **`REEFLEX_FREEZE`** → honored centrally by core (`reeflex.policy/frozen`
  deny on non-read verbs); the gateway just relays it.
- **`enforce` + core unreachable → fail-closed = deny.** Proven by
  `reeflex-mcp check` (§6): a real gateway subprocess pointed at an
  unreachable core, driven by a real MCP client, asserting a real
  `tools/call` comes back `isError: true`.

### Obligations (SPEC §5/§7 minimum #5)

SPEC §5: *"`obligations` are mandatory side-effects… An adapter that ignores
an obligation is non-conformant."* The gateway reads `decision["obligations"]`
on **every** decision, in both modes:

- **Enforce mode:** on an `allow` (or an approved resubmission), each
  obligation is dispatched to a registered handler if one exists; an
  **unknown** obligation **blocks the call before dispatch** — `isError`,
  reason `unsupported obligation '<x>' — cannot honor, failing closed`. An
  empty list forwards normally, same as today.
- **Observe mode:** every obligation is **recorded** (stderr, "would-honor")
  and forwarding proceeds regardless — never applied (no side effect for a
  call that isn't really being allowed) and never silently dropped either.
- Dispatch is a deterministic string lookup only — no LLM, no fuzzy
  matching. `reeflex_mcp/obligations.py` documents how to register a new
  handler. The base policy pack in this repo emits no obligations today
  (`[]`); real coverage comes from the test suite's synthetic obligations,
  plus one shipped example handler for `audit:full` (the string SPEC §5's
  own example and `ADAPTER-EXAMPLES.md` §C's shared Rego rule use).

---

## 6. `reeflex-mcp check` — the fail-closed self-probe

```bash
reeflex-mcp check   # exit 0 = PASS, 1 = FAIL
```

Launches a real gateway subprocess against a deliberately unreachable core in
enforce mode, drives it with a real MCP client, and asserts a real
`tools/call` is denied. A pass that does **not** deny is exactly the
fail-open bug this probe exists to catch — mirrors `reeflex-claude`'s `check`.

---

## 7. Lifecycle — setup / add / import / doctor

### The single-path limit — read this first (design doc §13, verbatim)

> The gateway governs only what flows *through* it. A server added directly
> to the client is an **ungoverned path** — `doctor` detects it, cannot
> prevent it. On hostile/multi-user machines, single-path must be enforced
> at the OS/network level. In service mode, single-path is enforced by
> network topology (upstreams reachable only from the gateway) — the robust
> model.

Everything below is UX around that limit, not a way around it.

- **`reeflex-mcp setup`** — reads `mcpServers` from the standard MCP client
  config locations (Claude Desktop's `claude_desktop_config.json`, a
  project's `.mcp.json`, `.claude/settings.json`), derives a
  `reeflex-mcp.yaml` upstream from each, **backs up the client config**
  (`<path>.reeflex-mcp-backup`, never overwritten by a later run), and
  **rewrites it to a single `reeflex-mcp` entry**. Idempotent. Never copies
  an inline secret out of a client config — it warns and tells you to set
  `auth: { token_env: ... }` yourself.
- **`reeflex-mcp restore`** — undoes `setup`/`import`'s rewrite from the
  backup it made.
- **`reeflex-mcp add <name>`** — registers a new upstream and, in
  streamable-HTTP mode, hot-reloads an already-running gateway (POSTs
  `/admin/reload`, which reconnects the upstream and broadcasts
  `tools/list_changed` to every connected front session) — **already-open
  clients see the new tools without reconnecting.** A selling point over
  native MCP clients, which require a full restart to pick up any new
  server.
- **`reeflex-mcp import <name>`** — the one-command fix `doctor` suggests:
  pulls one named server's definition out of a client config where it was
  registered directly into `reeflex-mcp.yaml`, and removes just that one
  entry — surgical, unlike `setup`.
- **`reeflex-mcp doctor`** — the client-config drift check: compares each
  standard client config's `mcpServers` against the single-gateway-entry
  invariant, reporting a `foreign_server` (ungoverned path) or
  `gateway_missing` finding. **Runs automatically at every gateway startup**
  (non-fatal) and on demand. No file-watching (YAGNI) — a stdio client
  restart already restarts the gateway, which is exactly when a
  manually-edited client config matters.

---

## 8. What this does not do

- **No direct-to-API upstreams.** v1 is strictly MCP-in / MCP-out. Native
  HTTP/GraphQL upstreams are a future, demand-driven extension.
- **No elicitation-based holds.** A hold surfaces via the error-result
  pattern only (§5 above) — client elicitation support across MCP clients is
  too uneven to depend on.
- **No config file-watching.** Drift is caught at startup (§7), not by a
  background watcher.
- **No LLM anywhere near the decision path** — normalization is deterministic
  (declarative mapping → name-heuristic → conservative default); the
  decision itself is `reeflex-core`'s OPA/Rego. This is a v1 invariant, not
  an incidental fact.

---

## 9. Install (source, pre-PyPI)

```bash
cd reeflex-mcp
python -m venv .venv
.venv/Scripts/pip install -e .          # Windows
# .venv/bin/pip install -e .            # Linux/macOS

cp reeflex-mcp.yaml.example reeflex-mcp.yaml
# edit reeflex-mcp.yaml: point upstreams: at your real MCP server(s)

reeflex-mcp --config reeflex-mcp.yaml --transport stdio
```

`reeflex-mcp` is **not yet published to PyPI** — `pip install reeflex-mcp`
does not resolve yet. Publishing is a gate (human GO), same as every other
Reeflex package; this page will be updated with the PyPI command once that
gate clears.

---

## References

- [`reeflex-mcp/README.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-mcp/README.md) — the package README (declarative mappings, obligations, lifecycle commands, full env-var reference)
- [`reeflex-spec/SPEC.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md) — Action Envelope, Adapter Contract, conformance requirements
- [`docs/why-reeflex.md`](why-reeflex.md#reeflex-mcp--governance-judgment-at-the-mcp-seam) — the MCP-gateway competitive framing (complementary, not "only/first")
- [`docs/architecture.md`](architecture.md) — the interception seams across all adapters, including this one
- [`docs/open-core.md`](open-core.md) — the open-core boundary (`reeflex-mcp` is Apache-2.0, open)

*Reeflex — a seatbelt for the AI acting on your systems.*
