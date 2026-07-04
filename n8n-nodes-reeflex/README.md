# n8n-nodes-reeflex

This is an n8n community node. It lets you use [Reeflex](https://reeflex.io)
- deterministic governance for AI-agent actions - in your n8n workflows.

Reeflex decides `allow` / `deny` / `require_approval` on a universal Action
Envelope via `reeflex-core`'s `POST /v1/decide`. The decision path is pure
OPA/Rego and classical logic - zero LLM, ever. This package ships one node,
**Reeflex Gate**, that is a thin, zero-business-logic consumer of that single
endpoint: it builds an envelope from its parameters, submits it, and routes
the item to one of three outputs based on the verdict.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/)
workflow automation platform.

[Installation](#installation)
[Operations](#operations)
[Credentials](#credentials)
[Compatibility](#compatibility)
[Usage](#usage)
[Fail-closed behavior](#fail-closed-behavior)
[Conformance](#conformance)
[Zero-code alternative](#zero-code-alternative)
[Resources](#resources)
[Version history](#version-history)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation-and-management/)
in the n8n community nodes documentation, and install `n8n-nodes-reeflex`.

## Operations

The package ships a single node, **Reeflex Gate**. It has one input and
three outputs:

| Output | Fires when |
|---|---|
| Allowed | reeflex-core returned `decision: "allow"` |
| Held for Approval | reeflex-core returned `decision: "require_approval"` (a hold was created - see [Usage](#usage)) |
| Denied | reeflex-core returned `decision: "deny"`, an unrecognized decision value, or the request itself failed (see [Fail-closed behavior](#fail-closed-behavior)) |

Every output item carries the original input JSON plus a `reeflex` field
with the full Decision object returned by core (`decision`, `reason`,
`rule`, `obligations`, `modulation`, and - for held items - `hold_id` and
`expires_ts`), **plus the exact Action Envelope this node sent**
(`reeflex.envelope`) - present on all three outputs, not just Denied, so a
downstream "resolve the hold, then resubmit" flow can reuse it verbatim
(flip `approval.present`/`approval.hold_id` and POST it back to
`/v1/decide`) without reconstructing it by hand. See [Usage](#usage).

**Node parameters** map directly onto the Action Envelope
(`reeflex-spec/SPEC.md` SS2):

| Parameter | Envelope field |
|---|---|
| Action / Ability | `action.ability` (also derives `action.namespace` from the text before the first `/`) |
| Verb | `action.verb` |
| Environment | `target.environment` |
| Reversibility, Blast Radius, Externality | `axes.*` |
| Count | `magnitude.count` |
| Target System | `target.kind` (informational) |
| Session ID | `agent.session_id` (required - see [Usage](#usage)) |
| Agent ID | `agent.id` |
| Additional Fields -> On Behalf Of | `agent.on_behalf_of` |
| Additional Fields -> Target Ref | `target.ref` |

The Reversibility / Blast Radius / Externality dropdowns default to the
most restrictive value in each set (`irreversible` / `systemic` /
`outbound`). This is deliberate: an unconfigured node fails toward a hold
or a deny rather than silently allowing. Set them to describe your actual
action.

## Credentials

You need a **Reeflex API** credential:

- **Core URL** - the base URL of your `reeflex-core` instance, e.g.
  `http://127.0.0.1:8080` or `https://core.example.com`. No trailing slash,
  no path.
- **API Token** - the Bearer token matching the server's
  `REEFLEX_AUTH_TOKEN`. Leave empty only if the server has auth disabled.
- **Ignore SSL Issues (Insecure)** - off by default. Enable only for
  trusted development or self-signed endpoints; this removes protection
  against man-in-the-middle attacks.

Prerequisite: a running `reeflex-core` instance. See
[`../reeflex-core/README.md`](../reeflex-core/README.md) to run one, and
[`../INSTALL.md`](../INSTALL.md) for OPA installation.

The credential's **Test** button calls `GET /v1/holds?limit=1` - a
read-only endpoint that requires the same Bearer auth as `/v1/decide`, so a
pass genuinely validates both reachability and the token (unlike
`/healthz`, which is always unauthenticated). This requires reeflex-core
v0.1.5 or later (the Holds API, HIL Phase 1). See the code comment in
`credentials/ReeflexApi.credentials.ts` for a known limitation: the Test
button does not currently honor "Ignore SSL Issues" against a self-signed
Core URL, even though the node's real `/v1/decide` calls do.

## Compatibility

- Requires n8n with community nodes support and Node.js >= 20.15.
- Requires `reeflex-core` v0.1.5 or later for the credential test (the
  Holds API). `POST /v1/decide` itself works against any reeflex-core v0.1.x.
- Built and tested against `n8n-workflow` as a peer dependency (no pinned
  version - see `package.json`).

## Usage

**Session ID is required.** reeflex-core uses `agent.session_id` to detect
fragmented bulk actions across multiple calls in the same session (SPEC
SS4.1 - "fragmentation resistance": ten single-item deletes in the same
session are evaluated cumulatively, not as ten independent small actions).
The node defaults this field to the expression `={{$execution.id}}`, which
is stable for the lifetime of one workflow execution. Reuse the same
session id across a longer-lived process (e.g. a chat session spanning
several executions) if you want cumulative budgets to apply across it.

**This node does not resolve holds or re-execute anything.** When the
verdict is `require_approval`, the output item on "Held for Approval"
carries `reeflex.hold_id` and `reeflex.expires_ts`. Getting a human decision
and re-submitting the envelope (with `approval.present: true` and the same
`hold_id`) is your workflow's job - see
[`/docs/guides/n8n.md`](../docs/guides/n8n.md)
for a worked pattern using n8n's built-in Wait node and reeflex-core's
outbound hold webhook. Reeflex never executes actions on any surface (SPEC
SS5.1): core only ever returns a verdict.

## Fail-closed behavior

Per the Reeflex Adapter Contract (SPEC SS6, responsibility #3 ENFORCE), an
adapter must never treat a core failure as `allow`. If the HTTP call to
`/v1/decide` fails outright (network error, timeout, TLS failure - no HTTP
response at all), or comes back with an HTTP error status that carries no
usable `decision` field, the node **unconditionally routes the item to
Denied** with a synthetic reason (`rule: "n8n-nodes-reeflex/fail_closed"`)
- it never throws for this error class, and it never routes to Allowed.

This is deliberate, not gated behind "Continue On Fail": a governance gate
that halts the entire workflow on a core outage defeats the purpose of
having a Denied branch to alert on, and it mirrors every other Reeflex
adapter (`reeflex-claude`, `reeflex-wordpress`) - never silently allow,
never crash past the gate, always emit a definitive, auditable deny.
**Wire real monitoring (Slack, email, a logging node) on the Denied
output** - a `reeflex-core` outage should page someone, not vanish silently.

If `reeflex-core` DOES return an HTTP 500 with a usable `decision` field
(its own internal-error fail-closed path, see `reeflex-core/app/decide.py`
`process()`), this node reads that real `reason`/`rule` instead of
substituting a generic message, so you get the same detail you would from
`reeflex-core`'s own audit log.

**This is a different error class from this node's own configuration
errors** (missing Action/Ability, missing Session ID): those still throw a
`NodeOperationError` and halt the workflow by default (standard n8n
behavior), or route to Denied with a plain `error` field (no `reeflex` key)
if you enable **Continue On Fail** on the node - "core said no or is
unreachable" and "this node was misconfigured" are handled differently on
purpose.

## Conformance

This node satisfies the applicable parts of the SPEC SS7 conformance
checklist for a source-side adapter:

- Produces a schema-valid envelope with all three axes always set (never
  omitted - see the safe-conservative defaults above).
- Applies `allow` / `require_approval` / `deny` correctly by routing to the
  matching output.
- Fails closed on any core error (see above).
- Supplies a stable `session_id`.
- Passes `obligations` through on the `reeflex` output field for the
  workflow to act on. **The node does not itself enforce any obligation**
  (e.g. `redact:pii`) - build that as downstream workflow logic that
  branches on `{{$json.reeflex.obligations}}`. This is deliberate given the
  node's "zero business logic" scope; it is not a facade - obligations are
  visible, not silently dropped, and no rule in the shipped policy pack
  currently emits a non-empty obligations array.
- Envelope signing (`meta.signature`) is a documented stub
  (`ed25519:stub:n8n-nodes-reeflex`), matching reeflex-core's own current
  skeleton state (SPEC SS6 implementation-status note). Real signing is on
  core's roadmap (Vault-backed key management); see the code comment next
  to the stub for the upgrade path.
- Per-decision audit is provided by reeflex-core itself (every
  `/v1/decide` call is written to its JSONL audit log server-side) - this
  node does not duplicate that audit trail (Adapter Contract responsibility
  #4).

## Zero-code alternative

You do not need this node to use Reeflex from n8n. `POST /v1/decide` is a
plain HTTP endpoint - see
[`/docs/guides/n8n.md`](../docs/guides/n8n.md)
for a complete pattern using only n8n's built-in HTTP Request, Switch, and
Wait nodes. Install this package once you are tired of hand-building the
envelope JSON and the branching logic across multiple workflows.

## Resources

* [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
* [Reeflex Action Envelope & Adapter Contract (SPEC.md)](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md)
* [reeflex-core README](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/README.md)
* [reeflex.io](https://reeflex.io)
* [`examples/bulk-delete-guard.workflow.json`](./examples/bulk-delete-guard.workflow.json) - an importable end-to-end example workflow
* [`test/reeflexGate.test.ts`](./test/reeflexGate.test.ts) - the node's test suite, against a mocked core
* [`PUBLISH.md`](./PUBLISH.md) - exact, gated steps to publish this package to npm (not yet done)

## Version history

- **0.1.0** - Initial release. One node (Reeflex Gate, three outputs), one
  credential (Reeflex API). Targets reeflex-core v0.1.5+ (HIL Phase 1).
