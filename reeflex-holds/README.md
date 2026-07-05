# reeflex-holds

An MCP server that turns [Reeflex](https://reeflex.io)'s Human-in-the-Loop (HIL)
holds queue into a socket any MCP client can talk to. Any MCP-capable client
(Claude Desktop, a coding agent, a custom bot) can list pending governance
holds, inspect one, and approve or reject it -- without a bespoke integration
per client.

**What it is:** a thin MCP wrapper around three `reeflex-core` HTTP endpoints
(`GET /v1/holds`, `GET /v1/holds/{id}`, `POST /v1/holds/{id}/resolve`), plus a
best-effort reachability probe.

**What it is NOT:** it does not decide, enforce, or execute anything. Every
governance rule -- who may resolve which hold, whether the resolving identity
is allowed to act, whether a hold has expired -- is enforced by `reeflex-core`
(OPA/Rego + classical logic), exactly as it is for every other adapter. This
package forwards HTTP calls and relays `reeflex-core`'s response, success or
error, verbatim. A rejection from core (409, 403, 404, ...) is never retried,
softened, or overridden here -- it surfaces to the MCP client as a real tool
error.

## Tools

| Tool                | Arguments                              | Calls                              |
|---------------------|-----------------------------------------|-------------------------------------|
| `list_holds`        | `status?` (pending\|approved\|rejected\|expired\|consumed) | `GET /v1/holds?status=`            |
| `get_hold`          | `id`                                    | `GET /v1/holds/{id}`               |
| `resolve_hold`      | `id`, `decision` (approve\|reject), `reason?` | `POST /v1/holds/{id}/resolve`      |
| `get_freeze_status` | (none)                                  | `GET /healthz` (best-effort; see below) |

`resolve_hold` never accepts a principal argument. The resolving identity
always comes from this server's own `REEFLEX_PRINCIPAL` configuration -- an
MCP client cannot resolve a hold "as" an arbitrary identity by simply asking
to. `reeflex-core` still independently enforces the operator's resolution
policy (which principal types may resolve which rule), the R3/systemic
immunity guard (`irreversible_systemic_prod` holds can never be resolved by
anyone), and the actor-is-approver check (the agent whose action raised the
hold can never resolve it, on any surface, including this one). None of that
enforcement lives in this package -- it lives in `reeflex-core/app/server.py`.

## Honest two-step reality for WordPress (and other adapter) holds

**Resolving a hold via MCP marks it approved IN REEFLEX-CORE ONLY.** It does
not execute anything. The underlying action still has to run on the adapter
that raised it:

- For the **WordPress adapter**: the hold's `approved` status in core does
  not, by itself, delete the 50 posts (or whatever the held action was). The
  WordPress action completes WordPress-side, either via the wp-admin "run
  approved" button, or automatically the next time the adapter resubmits the
  same envelope (e.g. on the admin's next matching request) and core sees a
  matching, approved, unconsumed hold.
- The same is true for any other adapter: `reeflex-holds` is a **read/resolve
  console for the hold record**, not an execution engine. It has no way to
  reach into WordPress, a CI pipeline, or anything else and run the action.

If you approve a hold here and the "thing" doesn't visibly happen, that is
expected -- check the originating adapter for its own resubmission /
"run approved" mechanism.

## Config (env)

| Variable                | Required | Default                   | Purpose |
|--------------------------|----------|----------------------------|---------|
| `REEFLEX_CORE_URL`       | no       | `http://127.0.0.1:8080`   | `reeflex-core` base URL |
| `REEFLEX_TOKEN`          | no       | unset                      | optional bearer token; adds `Authorization: Bearer <token>` to every request. Never logged. Holds the same `reeflex-core` bearer token the other adapters call `REEFLEX_CORE_TOKEN` — see the naming note below. |
| `REEFLEX_PRINCIPAL`      | only for `resolve_hold` | unset      | `"type:id"` of the resolving identity, e.g. `human:leo` or `agent:triage-bot`. Split on the *first* colon (an id may itself contain colons). `list_holds`, `get_hold`, and `get_freeze_status` do not need it. |
| `REEFLEX_VERIFY_SSL`     | no       | `true` (full TLS verification) | set to `0`/`false`/`no`/`off` (case-insensitive) to **disable** TLS certificate verification -- dev/self-signed endpoints only, at the operator's own risk. Same env name and semantics as `reeflex-claude` and the WordPress adapter, per the project's standing TLS-verify-opt-out rule. |
| `REEFLEX_HOLDS_TIMEOUT`  | no       | `10` (seconds)              | hard socket timeout for every HTTP request to core; this package never issues an unbounded request |

> **Naming note.** `REEFLEX_CORE_TOKEN` is the project-wide name for the
> `reeflex-core` bearer token, used by the `reeflex-claude` and
> `reeflex-wordpress` adapters. `reeflex-holds` is the one exception: it
> reads the *same* bearer token, but from **`REEFLEX_TOKEN`** instead, per
> its own original brief. Same credential, same purpose, just a different
> env var name for this one package — set `REEFLEX_TOKEN` here to whatever
> value the other adapters put in `REEFLEX_CORE_TOKEN`. A non-breaking
> unification (accepting `REEFLEX_CORE_TOKEN` with `REEFLEX_TOKEN` as a
> fallback) is a candidate for a future 0.1.1, not implemented here.

## Why the `mcp` SDK

This package's *only* dependency is the official
[MCP Python SDK](https://pypi.org/project/mcp/) (`mcp.server.fastmcp.FastMCP`).
`reeflex-core` itself stays dependency-free by contract (stdlib + OPA
subprocess only), and the other two adapters (`reeflex-claude`,
`reeflex-wordpress`) are also zero/near-zero-dependency by design -- but this
package's entire job is to speak the MCP protocol correctly to arbitrary MCP
clients, and hand-rolling that protocol (JSON-RPC framing, capability
negotiation, tool schema generation, notification handling, the streaming and
`stdio` transport edge cases) is exactly the kind of thing a widely-used
official SDK exists to get right once. Depending on `mcp` here is the
proportional choice for a thin, single-purpose MCP surface -- this is not a
change to `reeflex-core`'s or the other adapters' dependency posture.

## Install

```bash
pip install reeflex-holds
```

`reeflex-holds` is published on PyPI (`reeflex-holds==0.1.0`). To work from a
local checkout instead (for development, or to track `main`):

```bash
git clone https://github.com/Reeflex-io/reeflex.git
cd reeflex/reeflex-holds
pip install -e .
```

## Running it directly

```bash
export REEFLEX_CORE_URL=http://127.0.0.1:8080
export REEFLEX_PRINCIPAL=human:leo
python -m reeflex_holds
```

This starts the stdio MCP server and blocks, waiting for a client to speak
the protocol on stdin/stdout. You normally do not run it manually -- an MCP
client (below) launches it as a subprocess.

## Claude Desktop demo

Add this to Claude Desktop's `claude_desktop_config.json` (Settings ->
Developer -> Edit Config), using the **absolute path** to your checkout:

```json
{
  "mcpServers": {
    "reeflex-holds": {
      "command": "python",
      "args": ["-m", "reeflex_holds"],
      "env": {
        "REEFLEX_CORE_URL": "http://127.0.0.1:8080",
        "REEFLEX_TOKEN": "",
        "REEFLEX_PRINCIPAL": "human:leo",
        "REEFLEX_VERIFY_SSL": "true"
      }
    }
  }
}
```

Notes:
- `command` must resolve to a Python that has this package installed
  (`pip install reeflex-holds`, or `pip install -e .` from a local
  checkout, as above) -- use an absolute interpreter path (e.g.
  `"C:\\path\\to\\venv\\Scripts\\python.exe"` or `/path/to/venv/bin/python`)
  if `python` is not reliably on Claude Desktop's `PATH`.
- Leave `REEFLEX_TOKEN` empty (or omit it) if your core has no
  `REEFLEX_AUTH_TOKEN` configured.
- Set `REEFLEX_VERIFY_SSL` to `false` only against a dev/self-signed core
  endpoint (e.g. a staging deployment) -- never in production.
- Restart Claude Desktop after editing the config.

### Expected transcript

Assume `reeflex-core` is running locally with a pending hold already in its
queue (e.g. a WordPress adapter submitted a 50-post bulk-delete that scored
`require_approval` under rule `reeflex.policy/irreversible_broad_prod`).

**You type:** "List pending Reeflex holds"

**What happens:** Claude recognizes this maps to the `list_holds` tool,
calls it with `{"status": "pending"}`, and gets back something like:

```json
{
  "items": [
    {
      "id": "279ac798cf8f40eb85b5ebbdecafec70",
      "status": "pending",
      "rule_id": "reeflex.policy/irreversible_broad_prod",
      "created_ts": "2026-07-04T19:53:26Z",
      "expires_ts": "2026-07-04T23:53:26Z",
      "envelope": {
        "action": {"namespace": "wordpress", "verb": "delete", "ability": "wordpress/delete-post"},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
        "magnitude": {"count": 50}
      }
    }
  ],
  "count": 1
}
```

**Claude responds** (paraphrasing the JSON, e.g.): "There is 1 pending hold:
a WordPress bulk-delete of 50 posts (irreversible, broad, in production),
created a few minutes ago, expiring in about 4 hours. Hold id
`279ac798...`. Would you like to approve or reject it?"

**You type:** "Approve hold 279ac798cf8f40eb85b5ebbdecafec70"

**What happens:** Claude calls `resolve_hold` with
`{"id": "279ac798cf8f40eb85b5ebbdecafec70", "decision": "approve"}`. The
tool never asks for or sends a principal -- it resolves as whatever
`REEFLEX_PRINCIPAL` was configured in the server's env (`human:leo` above).
The response:

```json
{
  "id": "279ac798cf8f40eb85b5ebbdecafec70",
  "status": "approved",
  "decided_by": "human:leo",
  "decided_ts": "2026-07-04T19:58:40Z",
  "reason": null
}
```

**Claude responds:** "Hold `279ac798...` is now approved (by `human:leo`).
Note: this marks it approved in Reeflex core only -- the actual WordPress
bulk-delete still needs the adapter to resubmit or run it (e.g. the
wp-admin 'run approved' button), it does not happen automatically from this
approval alone."

If the agent that raised the hold and `REEFLEX_PRINCIPAL` are the same
identity, or the hold has already been resolved/expired, or the resolution
policy does not allow this principal type for this rule, `resolve_hold`
comes back as a genuine MCP tool error carrying core's exact reason (e.g.
`actor_is_approver`, `not_resolvable`, `principal_type_not_allowed`) --
Claude will surface that error text, not a fabricated success.

## `get_freeze_status` -- an honest limitation

`reeflex-core` has **no dedicated freeze-status endpoint**. The operator
kill-switch (`REEFLEX_FREEZE`) is an environment variable read fresh on every
`/v1/decide` call inside core (see `reeflex-core/app/decide.py`), and it is
never exposed via the HTTP API. Per this package's brief, we do **not**
invent a core endpoint to answer this question.

`get_freeze_status` therefore does the only honest thing available from
outside core: a `GET /healthz` reachability probe (the one universally
unauthenticated, side-effect-free endpoint core exposes). It always returns:

```json
{
  "core_reachable": true,
  "freeze_state": "unknown",
  "note": "reeflex-core has no dedicated freeze-status endpoint; REEFLEX_FREEZE is an operator-side environment variable re-read on every /v1/decide call ... This is a best-effort GET /healthz reachability probe only -- it cannot report the actual REEFLEX_FREEZE value. To infer freeze state: ask the operator directly, or watch for repeated 'reeflex.policy/frozen' denials in /v1/decide responses or the audit log."
}
```

`freeze_state` is always `"unknown"` -- this tool cannot and does not claim
otherwise. Upgrade path: if/when `reeflex-core` ships a real freeze-status
endpoint, this function should call it directly and drop the `/healthz`
fallback.

## Running the tests

```bash
cd reeflex-holds
pip install -e .
python -m unittest discover -s tests -v
```

`test_config.py` and most of `test_client.py` / `test_server.py` need no
network (pure parsing, or a local stub HTTP server standing in for
`reeflex-core` on an ephemeral port). Every test that talks HTTP applies a
hard timeout -- this suite cannot hang.

**Live smoke (owned by a separate task, T7):** the tests above mock
`reeflex-core`. A full live smoke test -- a real local `reeflex-core`
instance (with OPA configured), a genuine bulk-delete envelope raising a
real hold, and a real MCP client (`mcp.client.stdio.stdio_client` +
`ClientSession`) driving `python -m reeflex_holds` as a subprocess against
it -- was run manually during implementation to validate the end-to-end
wiring (see the implementer's report for the transcript). That full
live-smoke harness is expected to live in `reeflex-verify` or an equivalent
T7 conformance step, not in this package's unit test suite.

## Limits / upgrade paths

- **No pagination exposed.** `reeflex-core`'s `GET /v1/holds` supports
  `limit`/`cursor`, but `list_holds` here only exposes `status` (per this
  package's brief). UPGRADE: add optional `limit`/`cursor` arguments to
  `list_holds` if a queue ever exceeds core's page size (currently 100).
- **`get_freeze_status` is best-effort only** -- see the section above.
  UPGRADE: call a real freeze-status endpoint once `reeflex-core` ships one.
- **`REEFLEX_TOKEN` (this package) vs `REEFLEX_CORE_TOKEN`** (`reeflex-claude`,
  `reeflex-wordpress`) -- same bearer token, different env var name for this
  package only; see the naming note in Config above. UPGRADE: accept
  `REEFLEX_CORE_TOKEN` with `REEFLEX_TOKEN` as a fallback in a future
  non-breaking release.
- **stdio transport only.** FastMCP also supports `sse` and
  `streamable-http`; this package only wires up `stdio` (matching the brief
  and the primary Claude Desktop use case). UPGRADE: expose `transport` as a
  CLI flag or env var if a hosted/remote MCP surface is ever needed.
