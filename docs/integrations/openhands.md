# OpenHands

`reeflex-openhands` puts a Reeflex gate behind the security-analyzer seam of the
[OpenHands Software Agent SDK](https://github.com/OpenHands/software-agent-sdk).
Every action an OpenHands agent proposes (a shell command, a file edit, a browser
step, an MCP tool call) is turned into a Reeflex Action Envelope and decided by
your gate **before it runs**. Allowed actions run. Denied actions are rejected. Held
actions wait for a human in the Reeflex portal's Holds inbox. Every decision is
recorded as signed evidence, so OpenHands sessions show up in Attest.

Measured against `openhands-sdk` **1.56.0**. Nothing older has been tested.

## Quickstart (self-hosted SDK)

```bash
pip install ./integrations/openhands   # from a checkout of this repo; not on PyPI yet
export REEFLEX_CORE_URL=https://core.example.internal  REEFLEX_CORE_TOKEN=...
export REEFLEX_PORTAL_URL=https://app.reeflex.io
export REEFLEX_CONNECTOR_GATE_TOKEN=...  REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY=...
```

```python
from reeflex_openhands import ReeflexSecurityAnalyzer, run_governed

conversation = Conversation(agent=agent, workspace="./repo")
ReeflexSecurityAnalyzer(environment="production").attach(conversation)
conversation.send_message("Clean the build and push the fix.")
run_governed(conversation)   # denies rejected, holds resolved in the portal
```

The three `REEFLEX_CONNECTOR_*` / portal values are the ones the portal shows
once when you register a gate (**Gates → Register a gate**). Secrets are read
from the environment by name. They are never fields of the analyzer, so they
are never written into a persisted conversation's state file. Without the portal
values the analyzer still decides, but it cannot put a hold in front of a human,
so a held action is rejected rather than waited on.

## What the analyzer returns

`ReeflexSecurityAnalyzer(gate_url, api_key, *, org_id=None, agent_id="openhands", timeout=3.0, fail="closed")`

| Reeflex verdict | `SecurityRisk` | what `run_governed` does |
|---|---|---|
| `allow`, verb `read` | `LOW` | runs |
| `allow`, any other verb | `MEDIUM` | runs |
| `require_approval` (hold) | `HIGH` | waits for the portal: approve → runs, deny → rejected with the resolver's reason, expired or `max_wait` (900 s) → rejected |
| `deny` | `HIGH` | rejected: `Reeflex denied: <rule>` |
| gate unreachable or no decision | `UNKNOWN` (`fail="closed"`, the default) | rejected |
| gate unreachable, `fail="open"` | `LOW` | runs. Opt-in; this makes the gate advisory whenever it is down |

`ReeflexConfirmationPolicy` stops on `HIGH` and `UNKNOWN`. The SDK's own
`ConfirmRisky()` (threshold `HIGH`, `confirm_unknown=True`) stops on the same
set. The SDK hands a confirmation policy only a risk level, so the policy
cannot tell a deny from a hold. Telling them apart happens after the stop, in
`run_governed()` / `resolve_holds()`, which read the Reeflex record for each
pending action.

The record (`reeflex_decision_id`, `verdict`, `rule`, `hold_id`, the axes, the
evidence status) is written into the SDK's own `SecurityAnalysisEvent.details`
for that action. It is also kept in `analyzer.decisions[action.id]`.

## How actions are priced

The adapter does not price actions itself. It expresses each one in the
vocabulary of the Reeflex classifier the Claude Code hook and the LiteLLM seat
use (`reeflex_claude.classify`), and that classifier prices it:

| OpenHands tool | priced as |
|---|---|
| `terminal` (command) | `Bash` (the command, byte for byte) |
| `file_editor` view / create / str_replace, insert, undo_edit | `Read` / `Write` / `Edit` |
| `browser_navigate` (url), and browser reads of the open page | `WebFetch` |
| `task_tracker` | the agent's own task list (session-local) |
| an MCP tool | its name and arguments, plus its annotations (below) |
| anything else, including `browser_click` / `browser_type` and keystrokes sent to a running process | the unknown-tool path: irreversible / broad / outbound, which is a **hold** in production |

Two adjustments, both of which can only raise a price, and both named in the
envelope's `context.overlays`:

* **A shell command that talks to the network is `outbound`.** It counts as
  network if one of its words is a network client (`curl`, `wget`, `ssh`,
  `scp`, `rsync`, `nc`, …) or it carries a `scheme://` URL. The shared
  classifier puts a plain `curl <url>` GET in its `execute` bucket with
  `externality: internal`.
* **MCP annotations.** `destructiveHint: true` raises the price to
  irreversible and at least broad. `openWorldHint: true` raises it to outbound.
  `readOnlyHint: true` is the one hint that would lower a price, and it is ignored unless you pass
  `trust_mcp_annotations=True`. The MCP specification treats annotations as
  untrusted, and the server declaring them is the party being governed. The
  hints are passed through in `context.mcp_annotations`. Annotations on the
  SDK's built-in tools are not read. The SDK's own `terminal` declares
  `destructiveHint: true`, which describes "a shell", not the command in front
  of it.

An operator who knows a tool can route it explicitly:
`ReeflexSecurityAnalyzer(..., tool_map={"acme_runner": "Bash"})`.

## Three decisions, as the base pack makes them

These are the envelopes the adapter emits for the commands shown. The verdicts
were measured on core `e0f06f0` and on `v0.2.3` (the version api-dev runs), with
`environment: production`, and are re-checked by `scripts/docs_envelopes_check.py`.
In `staging` the base pack allows all three.

`rm -rf ./build` is held for a human:

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "reeflex_version": "0.1",
  "agent": {
    "id": "agent:openhands/openhands/5f0c2a7e-demo",
    "on_behalf_of": null,
    "session_id": "openhands:5f0c2a7e-demo"
  },
  "action": {
    "namespace": "openhands",
    "verb": "delete",
    "ability": "openhands/terminal"
  },
  "target": {
    "kind": "command",
    "ref": "./build",
    "environment": "production"
  },
  "params": {
    "tool_name": "terminal",
    "verb_source": "openhands:terminal->Bash"
  },
  "magnitude": {
    "count": 1
  },
  "axes": {
    "reversibility": "irreversible",
    "blast_radius": "broad",
    "externality": "internal"
  },
  "approval": {
    "present": false,
    "by": null,
    "role": null
  },
  "trajectory_ref": null,
  "context": {
    "tool_name": "terminal",
    "command_preview": "rm -rf ./build",
    "file_path": "./build",
    "danger_signature": "rm_recursive",
    "classification_tier": "destructive_broad",
    "classifier_tool": "Bash",
    "mapping_source": "builtin"
  },
  "meta": {
    "timestamp": "2026-10-21T14:40:14Z",
    "nonce": "00000000000000000000000000000000",
    "signature": "ed25519:stub:0000000000000000"
  }
}
```

Dropping a database is denied, and `run_governed` rejects it without asking:

**Verdict:** `deny` · **rule** `reeflex.policy/irreversible_systemic_prod`

```json
{
  "reeflex_version": "0.1",
  "agent": {
    "id": "agent:openhands/openhands/5f0c2a7e-demo",
    "on_behalf_of": null,
    "session_id": "openhands:5f0c2a7e-demo"
  },
  "action": {
    "namespace": "openhands",
    "verb": "delete",
    "ability": "openhands/terminal"
  },
  "target": {
    "kind": "resource",
    "ref": null,
    "environment": "production"
  },
  "params": {
    "tool_name": "terminal",
    "verb_source": "openhands:terminal->Bash"
  },
  "magnitude": {
    "count": 1
  },
  "axes": {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "internal"
  },
  "approval": {
    "present": false,
    "by": null,
    "role": null
  },
  "trajectory_ref": null,
  "context": {
    "tool_name": "terminal",
    "command_preview": "psql -h 127.0.0.1 -p 1 -c \"DROP DATABASE rfx_demo_nonexistent\"",
    "file_path": null,
    "danger_signature": "sql_drop_database",
    "classification_tier": "destructive_systemic",
    "classifier_tool": "Bash",
    "mapping_source": "builtin"
  },
  "meta": {
    "timestamp": "2026-10-21T14:40:14Z",
    "nonce": "00000000000000000000000000000000",
    "signature": "ed25519:stub:0000000000000000"
  }
}
```

A plain `curl` to a host the gate has never seen is **allowed** by the base
pack. It is priced `outbound`, so it is charged to the session's
`external_sends` budget, and a session that keeps sending is held when the
budget runs out. A single call is not stopped. If you want every outbound call
to an unknown host held, that is a policy change, not an adapter setting.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "reeflex_version": "0.1",
  "agent": {
    "id": "agent:openhands/openhands/5f0c2a7e-demo",
    "on_behalf_of": null,
    "session_id": "openhands:5f0c2a7e-demo"
  },
  "action": {
    "namespace": "openhands",
    "verb": "execute",
    "ability": "openhands/terminal"
  },
  "target": {
    "kind": "command",
    "ref": null,
    "environment": "production"
  },
  "params": {
    "tool_name": "terminal",
    "verb_source": "openhands:terminal->Bash"
  },
  "magnitude": {
    "count": 1
  },
  "axes": {
    "reversibility": "recoverable",
    "blast_radius": "scoped",
    "externality": "outbound"
  },
  "approval": {
    "present": false,
    "by": null,
    "role": null
  },
  "trajectory_ref": null,
  "context": {
    "tool_name": "terminal",
    "command_preview": "curl -sS https://unknown.example/",
    "file_path": null,
    "danger_signature": "none",
    "classification_tier": "moderate",
    "classifier_tool": "Bash",
    "mapping_source": "builtin",
    "overlays": [
      "network_shell:outbound"
    ]
  },
  "meta": {
    "timestamp": "2026-10-21T14:40:14Z",
    "nonce": "00000000000000000000000000000000",
    "signature": "ed25519:stub:0000000000000000"
  }
}
```

`git push --force origin main` is priced `emit` / irreversible / broad /
outbound and held by the same rule as the `rm -rf` above.

## Resolving holds

**In the portal (default).** When the gate holds an action, the analyzer pushes
the pending hold to the portal's Holds inbox (`POST /api/v1/holds`). The
conversation stays stopped while `run_governed` polls `GET /api/v1/holds/resolutions`
for the outcome. The person who approves or denies is recorded with the
decision, and the evidence row for a held action is sent after the hold is
resolved, so it carries the resolution and who made it.

**At the terminal.** `run_governed(conversation, resolver=console_confirm)` asks
`Run these actions? [y/N]` for holds instead. A deny is never offered for
override there either.

The engine is not told about a portal approval. This adapter does not re-submit
a held action to core: the agent runs it on the human's approval, and core's own
hold record stays pending until its TTL.

## Limits

**This is a supervisory layer, and a verdict is not an outcome.** Reeflex
decides on an action the agent *proposed*. It does not observe what the action
did. Things to know:

* **`conversation.execute_tool()` bypasses it.** The SDK's docstring says the
  method "bypasses the agent loop, including confirmation policies and security
  analyzer checks". Anything your own code runs through it is ungoverned.
* **A bare `conversation.run()` is the SDK's "approve".** If your code answers
  `WAITING_FOR_CONFIRMATION` by calling `run()` again, the pending actions run,
  whatever Reeflex said, denies included (measured: `tests/test_policy.py`).
  Use `run_governed()`, or call `resolve_holds()` before you call `run()`.
* **Approval is per batch.** The SDK runs or rejects every pending action
  together. A batch with one denied action is rejected whole. A batch with a
  held action runs only when every hold in it is approved.
* **Clicks, typing and keystrokes are held in production** until you map them,
  because nothing on the event says which click submits a form.

## OpenHands Cloud

**Untested.** What the SDK source shows: a remote conversation sends the
analyzer to the agent server as JSON (`kind: ReeflexSecurityAnalyzer` plus its
non-secret settings). So the agent server must have `reeflex-openhands`
installed and the `REEFLEX_*` variables in its environment, because no secret
travels with it. Whether OpenHands Cloud lets you install a package into its
agent server is not something we have checked. `run_governed` on the client
reads the verdicts from the `SecurityAnalysisEvent`s in the event stream, so the
driver side does not need the analyzer in the same process.

## Reading a decision in the portal

* **Decisions**: one row per action, with `agent:openhands/<agent_id>/<conversation id>`
  as the agent and `openhands` as the target system. These are the two fields
  the evidence wire carries that identify the source.
* **Holds**: what was held, who resolved it, when, and the reason they gave.
* **Attest**: the OpenHands decisions your gates delivered in the period are in
  the evidence chain, with the human resolution for each hold (measured on one
  5-decision session; a row whose evidence push failed is not there).

The decision id on each portal row is the `reeflex_decision_id` in the SDK
event's details, so a portal row and a line of the conversation's event log
can be matched one to one.

## Alongside the SDK's own analyzers

openhands-sdk 1.56.0 also ships `LLMSecurityAnalyzer` (the model's own risk
rating), the local rule-based `PatternSecurityAnalyzer` and
`PolicyRailSecurityAnalyzer`, `GraySwanAnalyzer`, and `EnsembleSecurityAnalyzer`.
What this adapter adds is a decision made by your organisation's gate under
your policy, with holds a human resolves and evidence an auditor can read.
Running it inside `EnsembleSecurityAnalyzer` has not been tested.
