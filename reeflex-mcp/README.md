# reeflex-mcp

A transparent MCP gateway that governs any MCP upstream: it sits in the MCP
path, aggregates every configured upstream's tools (namespaced
`<upstream>__<tool>`), intercepts `tools/call`, normalizes it into a Reeflex
Action Envelope (`reeflex-spec/SPEC.md` section 2), asks `reeflex-core`'s
`POST /v1/decide`, and (in `enforce` mode) applies the verdict. Everything
else passes through untouched. Zero LLM anywhere near the decision path.

See `design/MCP-GATEWAY-DESIGN.md` (v1 + addenda) for the full design.

## Status: Track 5.1 (obligations -- conformance fix) of the design's roadmap

This build implements:

- The multi-upstream registry (`reeflex-mcp.yaml` -- see
  `reeflex-mcp.yaml.example`), both stdio and streamable-HTTP upstreams.
- Dynamic tool discovery + namespacing, zero hardcoded tool knowledge.
- **Declarative per-server mappings** (`reeflex_mcp/mappings/*.yaml`,
  design doc section 8) -- per-tool `verb`/`axes` overrides + an optional
  `magnitude.from_arg` rule, resolved AHEAD of the heuristic. See
  "Declarative mappings" below.
- A minimal, heuristic-only normalizer (name-prefix based -- see
  `reeflex_mcp/normalize.py`'s module docstring for the exact table) as the
  fallback for any tool a mapping doesn't name.
- A fail-closed, stdlib-only `reeflex-core` client (`reeflex_mcp/core_client.py`).
- `observe` mode (default): every `tools/call` is normalized and submitted to
  `reeflex-core` (so the decision lands in core's audit trail), but the
  gateway **always forwards** -- observe must never break traffic.
- `enforce` mode (Track 3, full design section 9 mapping): `allow` forwards
  and tags core's `decision_id` (+ `parent_decision_id` on an approved
  resubmission) on the result; `deny` blocks with `rule` + `reason` +
  `decision_id`; `require_approval` blocks, surfaces `hold_id` + `expires_ts`,
  and the gateway remembers the pending hold (`reeflex_mcp/holds_tracker.py`,
  keyed by session + the same canonical action-hash core binds a hold to --
  `reeflex_mcp/canonical.py`) so a client's retry is recognized as a
  resubmission -- resolve the hold via `reeflex-core`'s holds API, then retry
  the exact same call to have it execute. `reeflex-core` unreachable fails
  closed. No gateway-side freeze logic -- core's own `reeflex.policy/frozen`
  deny is relayed transparently.
- `reeflex-mcp check`: a fail-closed self-probe (mirrors reeflex-claude's
  `check`) -- launches a real gateway subprocess against an unreachable core
  in enforce mode and asserts a real `tools/call` is denied.
- **Lifecycle subcommands** (design doc section 13): `setup` / `restore` /
  `add` / `import` / `doctor` -- see "Lifecycle: setup / add / import /
  doctor" below. Client-config import + rewrite, live hot-add of an upstream
  into an already-running streamable-HTTP gateway (`tools/list_changed`
  pushed to already-open sessions -- proven live, not just unit-tested, see
  the adapter-builder's Track 5 report), and a drift check that runs
  automatically at every gateway startup.
- Dual transport (stdio | streamable-HTTP), following the section 21
  lifecycle findings (upstream connections are process-level, not
  per-session; see `reeflex_mcp/gateway.py`'s module docstring for exactly
  how the streamable-HTTP front avoids the per-session reconnect bug).
- **Obligations, honored** (design doc ADDENDUM v1.5 section 25; SPEC
  section 5/7 minimum #5) -- `decision["obligations"]` is read on every
  decision, in both modes. `enforce`: a known obligation is applied via its
  registered handler and the call proceeds; an UNKNOWN one **blocks the call
  before dispatch** (`isError`, fail closed -- never silently forwarded past
  an obligation the gateway cannot honor). `observe`: every obligation is
  **recorded** ("would-honor", stderr) then forwarded regardless -- not
  applied (no side effect for a call that isn't really being allowed), but
  never silently dropped either. See "Obligations" below.

Track 6 (docs, per the design doc) is done: see
[`docs/mcp-gateway.md`](../docs/mcp-gateway.md) for the full operator guide
(architecture, deployment modes, config, mappings, obligations, lifecycle,
and the honest limits) and [`docs/why-reeflex.md`](../docs/why-reeflex.md#reeflex-mcp--governance-judgment-at-the-mcp-seam)
for the competitive positioning. Not yet built: PyPI publication (Track 7 —
gated on a human GO).

## Declarative mappings (Track 4, design doc section 8)

**Resolution order for one `tools/call`, highest precedence first:**

1. **declarative mapping** -- `mappings/<target.system>.yaml` has an entry
   for this exact tool name. Source tag: `mapping`.
2. **name-heuristic** -- the tool name matches one of the `delete_*`/
   `send_*`/`get_*`/etc. prefixes (see `reeflex_mcp/normalize.py`). Source
   tag: `heuristic:<bucket>`.
3. **conservative default** -- nothing above matched; axes are forced to the
   restrictive floor (`irreversible`/`systemic`/`internal`). Source tag:
   `heuristic:default`.

Every envelope carries which tier fired at `context.classification_source`,
and the gateway logs it to stderr on every call
(`[reeflex-mcp] classified '<tool>' via '<tier>' -> verb='<verb>'`) -- both
for the GIGO story below and for debugging a mapping that isn't matching the
way you expect.

**GIGO honesty (design doc section 8, verbatim):**

> Mapping quality is adapter quality. A tool the gateway maps wrong is
> governed wrong. The starter mappings are a floor you can read and correct,
> not a guarantee -- the same candor we apply to what the base policy does
> not catch.

**The 3 starter mappings ship with the package** (`reeflex_mcp/mappings/`),
targeting real, verified tool names -- not invented ones:

| File | Targets (real server) | Covers |
|---|---|---|
| `filesystem.yaml` | `@modelcontextprotocol/server-filesystem` (the official reference filesystem MCP server) | read vs. write/overwrite split. **Honest limitation:** the real server has NO delete tool at all -- `write_file`/`edit_file` are classified `irreversible` based on their own real `destructiveHint: true` MCP annotation, not a fictitious `delete_file`. |
| `github.yaml` | `modelcontextprotocol/servers-archived` GitHub server (the canonical, widely-mirrored reference tool surface) | external write (`externality: outbound`) + the irreversible/broad case. **Honest limitation:** the real server has NO delete-anything tool either -- the irreversible+broad+outbound example is `merge_pull_request` (a PR merge has no "unmerge"), not a fictitious `delete_repository`. |
| `postgres.yaml` | `crystaldba/postgres-mcp` ("Postgres MCP Pro", a real, actively-maintained community server with explicit read/write modes) | the single generic `execute_sql(sql: str)` write primitive. **Honest limitation:** no real Postgres MCP server (this one or the older read-only reference server) exposes row counts as a callable argument, so the "magnitude from args" case this file was originally meant to cover doesn't apply to it -- `execute_sql` is instead conservatively classified `delete`/`irreversible`/`broad` (the worst a raw, unparsed SQL string could be) so it correctly engages core's R5 session delete budget. |

The genuine "magnitude scales with a real list-typed argument" demonstration
lives in `filesystem.yaml` (`read_multiple_files`'s `paths`) and `github.yaml`
(`push_files`'s `files`) instead.

**Every mapping choice above is commented in its own YAML file** with the
real tool's own MCP annotations (`destructiveHint`, `readOnlyHint`, etc.)
where they exist -- read the files, don't just trust this table.

### How to write your own mapping

Create `mappings/<your-system-name>.yaml` (matching the `target.system` you
gave that upstream in `reeflex-mcp.yaml`):

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
    # axes.externality omitted on purpose -- see "partial axes" below
    axes: { reversibility: recoverable, blast_radius: scoped }

# OPTIONAL -- count = len(arguments[<name>]) if it's a list, else 1.
# Omit this block entirely if no tool takes a structured/countable argument
# (see mappings/postgres.yaml for exactly that case, documented).
magnitude:
  from_arg: message_ids
```

**Partial axes are fine.** Any axis you don't specify for a tool is filled
with reeflex-core's OWN restrictive default (`irreversible`/`systemic`/
`physical` -- `reeflex_mcp/mappings.py`'s `CORE_AXIS_DEFAULTS`, verified to
match `reeflex-core/app/envelope.py` exactly) -- never a different,
gateway-invented guess. An axis you omit here ends up exactly where core
would have coerced it anyway if you had sent nothing at all.

Point `reeflex-mcp.yaml`'s `mappings_dir:` (or `REEFLEX_MCP_MAPPINGS_DIR`) at
the directory containing your file, or drop it directly into this package's
own `reeflex_mcp/mappings/` if you're running from a source checkout.

## Obligations (Track 5.1, design doc ADDENDUM v1.5 section 25)

SPEC section 5: *"`obligations` are mandatory side-effects (e.g. `redact:pii`,
`rate_limit`). An adapter that ignores an obligation is non-conformant."*
Every `reeflex-core` Decision carries an `obligations` field (a list of
strings) alongside `decision`/`reason`/`rule` -- the gateway reads it on
**every** decision, in both modes.

**Enforce mode:** once the verdict itself is `allow` (original or an
approved resubmission), the gateway iterates `obligations` in order:
- **known** (a handler is registered for that exact string) -> the handler
  runs, then the loop continues.
- **unknown** -> the call is **blocked right there, before any upstream
  dispatch** -- `CallToolResult(isError=True)`, text:
  `reeflex-mcp: unsupported obligation '<x>' -- cannot honor, failing closed
  decision_id=<...>`. The gateway never silently forwards past an obligation
  it cannot honor -- an empty obligations list (or none at all) forwards
  normally, same as today.

**Observe mode:** every obligation on every decision is **recorded** (stderr:
`observe mode -- would-honor obligation(s) for ...: [...]`), never *applied*
(a handler's side effect should only fire for a call that is really being
allowed, which observe mode never actually decides) and never *silently
dropped* -- forwarding then proceeds exactly as before (observe must never
break traffic).

Dispatch is a deterministic string lookup only -- **no LLM, no fuzzy/partial
matching** of an unrecognized obligation against a known one.

### v1 known-set

Deliberately minimal (design doc section 25 explicitly allows "empty" for
v1) -- the base policy pack in this repo emits no obligations today, so real
coverage comes from tests with synthetic ones
(`tests/test_gateway_obligations.py`, `tests/fixtures/e2e_obligations.py`).
One example ships anyway, to prove the mechanism against a REAL string
rather than nothing:

| Obligation | Handler behavior |
|---|---|
| `audit:full` | Logs the full envelope to stderr, tagged with `gateway_correlation_id`. The exact obligation string SPEC section 5's own Decision example uses, and the one `reeflex-spec/ADAPTER-EXAMPLES.md` section C's shared Rego rule emits. Does not replace `reeflex-core`'s own unconditional audit record (SPEC section 6) -- purely additive, gateway-side visibility. |

### How to add an obligation handler

```python
from reeflex_mcp import obligations

def _handle_rate_limit(ctx: obligations.ObligationContext) -> None:
    # ctx.obligation, ctx.envelope, ctx.decision, ctx.gateway_correlation_id,
    # ctx.upstream_name, ctx.tool_name are all available. A handler may do
    # local I/O (e.g. logging, updating an in-memory counter) but must NEVER
    # call an LLM, make its own network decision call, or otherwise re-decide
    # anything -- SPEC's zero-LLM-in-the-decision-path invariant extends here.
    print(f"[myext] rate_limit obligation seen for {ctx.upstream_name}__{ctx.tool_name}")

obligations.register("rate_limit", _handle_rate_limit)
```

Call `obligations.register(...)` from any module imported before the gateway
starts serving (e.g. at the top of a small extension module you import in
your own entry point, or by editing `reeflex_mcp/obligations.py` directly for
a source checkout). Last registration for a given string wins. An obligation
with NO registered handler is, by design, treated as unknown -- it blocks in
enforce mode and is recorded (not applied) in observe mode; there is no
"soft" middle option, matching SPEC's non-conformance language verbatim.

## Lifecycle: setup / add / import / doctor (Track 5, design doc section 13)

### SINGLE-PATH LIMIT -- read this first (design doc section 13, verbatim)

> The gateway governs only what flows *through* it. A server added directly
> to the client is an ungoverned path -- `doctor` detects it, cannot prevent
> it. On hostile/multi-user machines, single-path must be enforced at the
> OS/network level. In service mode, single-path is enforced by network
> topology (upstreams reachable only from the gateway) -- the robust model.

Everything below is UX around that limit, not a way around it. `setup` and
`import` rewrite a client config so it launches ONLY the gateway; `doctor`
notices when that invariant has drifted. None of it can stop an operator (or
anyone with filesystem access to the client config) from adding a server
back directly five minutes later -- that is a structural property of "the
client decides what to launch," not a bug here.

### `reeflex-mcp setup`

Reads `mcpServers` from the standard MCP client config locations:

| Client | Path |
|---|---|
| Claude Desktop | OS-specific `claude_desktop_config.json` (`%APPDATA%\Claude\...` / `~/Library/Application Support/Claude/...` / `~/.config/Claude/...`) |
| Claude Code (project) | `./.mcp.json` |
| Claude Code settings | `.claude/settings.json` (project or global) |

For each server found there, it derives a reeflex-mcp.yaml upstream (the
server's own `command`/`args` or `url`; `target.system` defaults to the
server's own name -- so a server named `filesystem`/`github`/`postgres`
automatically picks up this package's bundled Track 4 mapping), then
**backs up the client config** (`<path>.reeflex-mcp-backup` -- never
overwritten by a later run, so it always holds the true pre-gateway state)
and **rewrites it to a single `reeflex-mcp` entry**. Idempotent: re-running
`setup` on an already-migrated config is a clean no-op; re-running it after
a NEW server was added directly imports just that one.

An inline secret on a remote server's `Authorization` header is **never**
copied into reeflex-mcp.yaml (secrets by-reference only) -- `setup` warns
and tells you to set `auth: { token_env: ... }` by hand instead.

```bash
reeflex-mcp setup                                   # every standard location that exists
reeflex-mcp setup --client claude-desktop            # just one
reeflex-mcp setup --path ./my-client-config.json     # an explicit file
reeflex-mcp setup --environment staging              # skip the per-server prompt
```

### `reeflex-mcp restore`

Undoes `setup`/`import`'s rewrite of a client config from the backup it made:

```bash
reeflex-mcp restore --client claude-desktop
```

### `reeflex-mcp add <name>`

Registers a new upstream directly (not read from any client config) and, in
streamable-HTTP mode, hot-reloads an ALREADY-RUNNING gateway: it POSTs to the
gateway's `/admin/reload` route, which reconnects the new upstream and
broadcasts `notifications/tools/list_changed` to every currently-connected
front session (reusing the Track-2 `FrontSessionRegistry`) -- **already-open
clients see the new tools without reconnecting.** Native MCP clients require
a full restart to pick up ANY new server; this doesn't. (stdio front doesn't
need this: one client = one gateway process, and a client restart already
restarts the gateway.)

```bash
reeflex-mcp add filesystem --command npx -y @modelcontextprotocol/server-filesystem /data \
  --environment staging
```

If no gateway is reachable at `--gateway-url` (default derived from
`$REEFLEX_MCP_HOST`/`$REEFLEX_MCP_PORT`), the config is still saved -- it
just takes effect on the next gateway start.

### `reeflex-mcp import <name>`

The one-command fix `doctor` suggests: pulls ONE named server's definition
out of a client config where it was found registered directly (bypassing
the gateway) into reeflex-mcp.yaml, and removes just that one entry from the
client config -- surgical, unlike `setup` (which migrates everything). Any
OTHER foreign entry in the same file is left untouched.

```bash
reeflex-mcp import sneaky-slack --client claude-desktop
```

### `reeflex-mcp doctor`

The client-config DRIFT check: compares each standard client config's
`mcpServers` against the single-gateway-entry invariant. Reports a
`foreign_server` finding for anything registered directly (an ungoverned
path) and a `gateway_missing` finding if the gateway entry itself is absent.
**Runs automatically at every gateway startup** (non-fatal -- see `cmd_run`
in `cli.py`) and on demand. **No file-watching** (YAGNI, design doc section
13): a stdio client restart already restarts the gateway, which is exactly
when a manually-edited client config matters -- there is nothing a
background watcher would catch that this doesn't already catch for free.

```bash
reeflex-mcp doctor           # every standard location that exists
reeflex-mcp doctor --client claude-desktop
```

Exits 0 (clean) or 1 (findings) -- scriptable.

## Install (development)

```bash
cd reeflex-mcp
python -m venv .venv
.venv/Scripts/pip install -e .          # Windows
# .venv/bin/pip install -e .            # Linux/macOS
```

## Configure

Copy `reeflex-mcp.yaml.example` to `reeflex-mcp.yaml` and edit the
`upstreams:` list. See `reeflex_mcp/registry.py`'s module docstring for the
full field reference.

## Run

```bash
reeflex-mcp --config reeflex-mcp.yaml --transport stdio
reeflex-mcp --config reeflex-mcp.yaml --transport streamable-http --host 127.0.0.1 --port 8000
```

Or `python -m reeflex_mcp ...` (same flags).

```bash
reeflex-mcp check   # fail-closed self-probe -- exit 0 = PASS, 1 = FAIL
```

## Env vars

| Variable | Default | Purpose |
|---|---|---|
| `REEFLEX_CORE_URL` | `http://127.0.0.1:8080` | `reeflex-core` base URL |
| `REEFLEX_CORE_TOKEN` | unset | bearer token for `reeflex-core` (never logged) |
| `REEFLEX_MODE` | `observe` | `observe` \| `enforce` -- overrides the YAML `mode:` if set |
| `REEFLEX_VERIFY_SSL` | `true` | set to `0`/`false`/`no`/`off` to disable TLS verification (dev/self-signed only) |
| `REEFLEX_MCP_TIMEOUT` | `10` | seconds, HTTP timeout to `reeflex-core` |
| `REEFLEX_MCP_CONFIG` | `./reeflex-mcp.yaml` | path to the registry file |
| `REEFLEX_MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` |
| `REEFLEX_MCP_HOST` / `REEFLEX_MCP_PORT` | `127.0.0.1` / `8000` | streamable-HTTP bind address |
| `REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT` | `10` | seconds, per-upstream connect timeout at boot (fail-closed-at-boot) |
| `REEFLEX_MCP_CALL_TIMEOUT` | `30` | seconds, per-call dispatch timeout to an upstream |
| `REEFLEX_MCP_MAPPINGS_DIR` | unset | directory of declarative `<system>.yaml` mappings (Track 4) -- overrides the YAML `mappings_dir:` key; unset on both -> this package's own bundled starter mappings |
| `REEFLEX_MCP_ADMIN_TOKEN` | unset | optional shared-token gate on the `/admin/reload` hot-reload route (Track 5); unset -> no auth required (fine for a gateway bound to 127.0.0.1, the default -- your own risk to widen without setting this) |

## Tests

```bash
.venv/Scripts/python -m pytest tests/ -q
```

`tests/fixtures/` also contains manual, real end-to-end fixtures (two
throwaway upstream servers -- one stdio, one streamable-HTTP -- plus driver
scripts, including `e2e_enforce_holds.py` for the full hold -> resolve ->
resubmit -> execute round trip, and `e2e_obligations.py` +
`stub_core_obligations.py` for the obligations enforce-block/observe-record
proof against a real gateway subprocess and a real HTTP stand-in for
`reeflex-core` -- the real base policy pack emits no obligations today, so
this is the only way to drive a genuinely live obligations scenario without
touching `reeflex-core` itself) used to prove the full intercept -> normalize
-> decide -> audit -> dispatch path against a real local `reeflex-core` (or,
for obligations, its stub stand-in). These are not part of the pytest suite
(they need real processes already running) -- see the adapter-builder's
report for the exact commands and the raw transcript.
