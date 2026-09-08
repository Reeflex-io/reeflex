# reeflex-litellm — the Reeflex seat inside an LLM gateway

Govern agents you don't own — including the ones you never integrated with.

`reeflex-litellm` is a [LiteLLM](https://github.com/BerriAI/litellm) post-call
guardrail. For every response a model returns through the proxy, it builds one
Reeflex **Action Envelope per tool call**, asks `reeflex-core` `/v1/decide`, and
then allows the call, removes it, or withholds the whole response while a human
decides.

One integration at the gateway covers every agent behind it. You do not have to
instrument each application.

---

## What this seat guarantees, and what it does not

Read this section before the install instructions. The seat is genuinely useful
and it is also narrower than "the gateway stops the action", and a deployment
built on the wrong reading of it will be surprised.

### It sees a tool call PROPOSED. Not executed.

The only moment a gateway can see an action is when the model's answer comes
back — and at that moment nothing has run yet. So what this seat does is
**refuse an instruction before it is handed to the application**, by deleting it
from the response and putting a structured refusal in its place.

**What that gets you.** A client that executes the tool calls it is given has
nothing to execute. Measured on the wire: with a denied call, the response
carries `tool_calls: null`, `finish_reason: "stop"`, and the command string is
not in the response bytes at all.

**What it does not get you.** An application that has already kept its own copy
of the model's answer, or that reads the refusal and runs the tool anyway, is
**not stopped**. Nothing at the gateway can stop it — the gateway is not in the
execution path. If you need the action itself blocked at the moment it runs, you
need a seat at the execution point too: `reeflex-claude` (a Claude Code
`PreToolUse` hook), `reeflex-wordpress` (an Abilities gate), or your own adapter
in front of the tool.

### Attest must record "refused at gateway", never "prevented at execution"

Because of the above, this adapter's obligation under SPEC §5.1 is to record
what it actually did. **Every refusal this package emits carries
`"stage": "refused_at_gateway"`**, and that string is part of the payload
contract, not a debug field:

```json
{"reeflex": {"version": 1, "refused": [{
  "error": "reeflex_denied",
  "rule": "reeflex.policy/irreversible_systemic_prod",
  "reason": "Reeflex: irreversible systemic change in production [rule=…]",
  "tool_call_id": "call_0_88cba792",
  "tool": "run_shell",
  "stage": "refused_at_gateway"
}]}}
```

An evidence pipeline that collapses `refused_at_gateway` into the same bucket as
an execution-side prevention is claiming a guarantee this seat cannot deliver.
Keep them distinct.

Since 0.2.0 that distinction is also **machine-readable in the decision
ledger**, not only in the refusal the caller reads. Every record this package
writes carries three fields whose whole purpose is to stop a report
over-reading it:

```json
{"enforcement_stage": "refused_at_gateway",
 "observed": "proposal",
 "prevents_execution": false}
```

`prevented_at_execution` is defined in the same vocabulary — so this seat and
the execution-side seats share one — and this package **cannot emit it**:
`evidence.assert_never_claims_prevention()` raises, and the test suite pins
that it does.

#### These two fields cannot go on the evidence wire, and that is flagged, not fixed

`EVIDENCE-INGEST-SPEC-v1.md` §4 is a **closed** schema — "unknown top-level
keys → `422` (fail closed — never store un-vetted data)" — and the contract is
**FROZEN**. There is no §4 field for `enforcement_stage` and none for
`gateway_routing`. So this package does not send them: `evidence.wire_record()`
is a closed allowlist built by naming each §4 field, and
`assert_wire_is_spec_clean()` re-checks its own output before every request.

**The consequence, stated rather than papered over:** an Attest report built
from the §4 feed alone cannot distinguish a gateway refusal from an
execution-side prevention. The one adapter-controlled field that does reach a
report is `agent_id`, which this seat sets to
`agent:litellm-gateway/<org>/<model>` — so a report row can say *which
department, behind which gateway, on which model*, but not *what the refusal
achieved*. Closing that gap needs a spec change from the spec owner, which is
not a change an adapter may make. Full truth lives in the local ledger
(`REEFLEX_LITELLM_LEDGER_PATH`).

### No prompt reading. No PII masking. No LLM in the decision path.

This seat is **blind to prose by construction**. It reads `tool_calls` and
nothing else: not the system prompt, not the user's message, not the assistant's
text. A response with no tool calls is returned byte for byte unchanged and is
never even sent to core.

That is a **LIMIT, not a feature claim.** Text-layer guardrails — PII detection,
prompt-injection filtering, content policy — do a different job and this package
does not do it. Run them alongside; LiteLLM composes guardrails.

The decision is OPA/Rego plus classic logic inside `reeflex-core`. There is no
model in it, which means it cannot reason about intent, tone or novel phrasing —
it prices the action on three declared axes. Again: a limit, stated so a
deployment can plan around it.

### Streaming (`stream: true`) is governed too, and it is a different hook

`mode: post_call` fires for a **buffered** response. A streamed one is delivered
through `async_post_call_streaming_iterator_hook`, and this class implements
both. One `mode: post_call` line in the config governs both paths; there is no
second key to forget.

**What the seat does to a stream.** Frames that carry no tool call — the role
frame, prose deltas — are passed through **immediately and untouched**. From the
first frame carrying a `tool_calls` delta the tail of the stream is **buffered**:
`function.arguments` arrives split across frames, and the dangerous half of a
command is usually in the last one, so nothing is released until each call is
whole and decided. Then the tail goes out — verbatim if allowed, with the
refused call's fragments removed and the same structured refusal payload as the
buffered path if not, `finish_reason` flipping to `stop` when every call was
refused.

**Measured on the wire** (2026-09-08, litellm 1.100.0, real proxy, raw SSE bytes
— `proxy/stream_walk.py`):

| case | before this hook existed | now |
|---|---|---|
| denied `rm -rf /` | **in the bytes**, `finish_reason: tool_calls`, assembles into a runnable call | **absent from every byte**, one refusal frame, `finish_reason: stop` |
| allowed call | untouched | untouched — byte-identical to a proxy with no seat, once the model's own per-response `id`/`created`/`tool_call_id` are normalized |
| prose | untouched | untouched |
| hold | not applicable — nothing was withheld | withheld while a human decides, **released** when core accepts the approval |
| core unreachable | the call went out | refused, `reeflex_unavailable`; prose still flows |

**It also removes a defect nobody had filed.** Before this hook existed, LiteLLM
reassembled the finished stream and ran the *buffered* hook on it through
`_run_deferred_stream_guardrails` — which its own docstring calls *"audit-only —
content has already been delivered to the client"*. So a streamed `rm -rf /`
produced a **`deny` row in core's audit log and reached the caller anyway**: the
record contradicted the wire. LiteLLM skips that pass for any guardrail defining
the streaming hook, so the decision is now taken **once, before delivery**.
Measured both ways: 1 decision row per streamed request, and the refusal in the
bytes.

**The limit is unchanged.** This is still a tool call *proposed*, refused before
the client is handed it — not an action blocked at execution. See the section
above.

### One session per request unless you say otherwise

R5's cumulative session budget is charged against `agent.session_id`. This
adapter takes it, in order, from:

1. the `x-reeflex-session` request header (configurable via
   `reeflex_session_header`),
2. OpenAI's `user` field on the request body,
3. the per-request `litellm_call_id`.

If you supply neither 1 nor 2, **the budget is scoped to a single request** and
cannot accumulate across a conversation. It is not wrong, it is narrow. Mapping
a gateway virtual key or team to a Reeflex session/org is **not implemented** —
see "Not in this version" below.

### The verdict is only as good as the classification

`reeflex-core` observes none of the axes it decides on (SPEC §6): they are
computed in this process, by `reeflex_claude.classify` — the one classifier
shared with every other Reeflex adapter. This package adds no second classifier.

What it does add is a **normalization** step, because a gateway does not know its
tool names. See "Tool names" below: an unmapped tool is not allowed, it asks a
human.

---

## Install

```bash
pip install reeflex-litellm[proxy]     # the proxy extra pulls litellm
```

That line is true from **Reeflex v0.2.1** and was not true before it. This
package was written for v0.2.0 and published with v0.2.1 — until that tag it
was in this repository and on no package index, so the same line resolved
nothing. If `pip` cannot find it, you are ahead of the release: install from
source with
`pip install 'git+https://github.com/Reeflex-io/reeflex@main#subdirectory=reeflex-litellm'`.

> **Why the classifier's version matters here, and what the floor now does
> about it.** The classifier lives in `reeflex-claude`, and the wheel on PyPI
> was **0.1.7, uploaded 2026-07-06** — predating the RFX-144/145/146 fix.
> Measured against `reeflex-core:v0.2.0` with that wheel:
> `echo starting && rm -rf /var/lib/pgsql` is priced `reversible/single` and
> **core allows it**. With the classifier from the repository's `main`, the same
> command is denied `irreversible_systemic_prod`.
>
> This package requires `reeflex-claude>=0.2.0,<0.3` (RFX-224), and 0.2.0 is
> the first published wheel carrying that fix — so the stale classifier is
> excluded **by version** rather than by whichever copy happens to win a
> resolve. `tests/test_classifier_vintage.py` is still there as the tripwire:
> it fails loudly if a pre-fix classifier ever ends up in the venv anyway.

**Then write a tenancy map before you start the proxy.** There is no default
org, so without one every tool call is refused. An example ships at
[`examples/tenancy-map.example.json`](examples/tenancy-map.example.json), and
`reeflex-litellm tenancy` validates yours offline — it exits non-zero if the
map would not load, which is what you want at deploy time rather than as an
outage. See "Tenancy: two departments behind one gateway" below.

## Wire it in

`proxy/config.yaml` in this package is a working example:

```yaml
guardrails:
  - guardrail_name: "reeflex-action-gate"
    litellm_params:
      guardrail: reeflex_litellm.guardrail.ReeflexActionGuardrail
      mode: post_call
      default_on: true
      reeflex_hold_wait: 30            # seconds a response may be withheld
      reeflex_session_header: x-reeflex-session
```

```bash
export REEFLEX_CORE_URL=http://your-core:8080
export REEFLEX_CORE_TOKEN=…            # if your core sets REEFLEX_AUTH_TOKEN

# REQUIRED: which Reeflex org each gateway key/team belongs to. There is no
# default org, so without this every tool call is refused. See "Tenancy" below.
export REEFLEX_LITELLM_TENANCY_MAP_FILE=/etc/reeflex/tenancy.json

# Optional: the local decision ledger, and pushing its §4 projection to a gate.
export REEFLEX_LITELLM_LEDGER_PATH=/var/log/reeflex/decisions.jsonl
export REEFLEX_LITELLM_EVIDENCE_PUSH=true
export RFX_GATE_TOKEN_PAYMENTS=…       # referenced BY NAME from the map
export RFX_EVIDENCE_KEY_PAYMENTS=…     # the derived 32-byte signing key, hex

litellm --config proxy/config.yaml --host 127.0.0.1 --port 4000
```

Validate the map before you deploy it — every tenancy misconfiguration is a
total refusal at runtime, and you want it as a non-zero exit instead:

```bash
reeflex-litellm tenancy              # prints what it binds, or exits 1
reeflex-litellm key-hash sk-…        # the digest a `key_hash` binding needs
```

To try it with no model and no API key, this package ships a mock model that
returns the tool calls you name in the prompt:

```bash
python3 proxy/mock_model.py --port 18602 &
litellm --config proxy/config.yaml --host 127.0.0.1 --port 18600 &

curl -s localhost:18600/v1/chat/completions -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-anything' -d '{
    "model": "mock-tools",
    "messages": [{"role":"user","content":"TOOL run_shell {\"command\": \"rm -rf /\"}"}]}'
```

## Tenancy: two departments behind one gateway

One proxy fronts every agent in a company. Without a tenancy binding, two
departments' decisions carry the same `agent.id`, spend the same R5 budget and
land in one Reeflex org — where either department can read the other's holds.
That is not a reporting inconvenience: core's hold check 8 binds an approval to
an actor, so a shared `agent.id` means the payments team's approval can be
spent by the marketing team's agent.

**The binding is explicit, and there is deliberately no default org.**

```bash
export REEFLEX_LITELLM_TENANCY_MAP_FILE=/etc/reeflex/tenancy.json
```

```json
{
  "version": 1,
  "tenants": {
    "acme-payments": {
      "org": "acme-payments",
      "principal": "payments-oncall@acme.example",
      "environment": "production",
      "on_prem_hosts": ["llm.internal.acme.example"],
      "evidence": {
        "ingest_url": "https://app.reeflex.io/api/v1/evidence",
        "gate_token_env": "RFX_GATE_TOKEN_PAYMENTS",
        "signing_key_env": "RFX_EVIDENCE_KEY_PAYMENTS"
      }
    }
  },
  "bind": {
    "key_alias": {"payments-bot": "acme-payments"},
    "team_id":   {"team_9f2c": "acme-payments"},
    "key_hash":  {"<sha256 of the virtual key>": "acme-payments"}
  }
}
```

The identity comes from `user_api_key_dict` — LiteLLM's own authentication
result, which **the caller cannot set**. Resolution is most-specific-first:
`key_hash`, then `key_alias`, then `team_id`. Compute a `key_hash` with
`reeflex-litellm key-hash sk-…` (it is LiteLLM's `hash_token()`).

Credentials are **by reference only**: the map names environment variable
*names*. A map carrying a token or a signing key *value* is a load error, on
purpose — it is a file operators copy between hosts and paste into tickets.

**What refuses, and why there is no fallback:**

| situation | result |
|---|---|
| no map configured | every tool call refused — this is *not* "tenancy off" |
| key/team not in the map | refused, `reeflex_tenant_unmapped`, **core never called** |
| a `*` / `default` / `fallback` entry | **load error** — a catch-all is the defect this exists to prevent |
| map unreadable or not JSON | every tool call refused |
| a response with no tool calls | untouched; tenancy is not even resolved |

An unmapped caller gets a refusal naming the identity that arrived and the env
var to fix, so an operator sees something actionable instead of evidence
quietly filed under the wrong company. A single-tenant operator writes eight
lines of JSON and has *named* their org rather than defaulted into one.

Editing the map file takes effect on the next request — the cache is keyed on
the file's mtime and size, so adding a department needs no proxy restart.

### Where the isolation is actually enforced — two mechanisms, two codebases

1. **The actor identity — here.** `agent.id` becomes
   `agent:litellm-gateway/<org>/<model>` and `agent.session_id` becomes
   `litellm:<org>:<session>`. That is what makes one department's approval
   unspendable by another's agent (core's hold check 8) and one department's
   R5 budget unchargeable to another's session. Two teams that both call their
   nightly job `nightly` no longer share one budget.

2. **The evidence org — the server, not this adapter.** SPEC §3 resolves
   `(gate_id, org_id)` from the gate **token**, server-side, and §4 has no org
   field at all. So this adapter's whole obligation is to present the *right
   tenant's* gate token; Postgres row-level security on `org_id` in
   **reeflex-app** is what keeps two orgs' stored evidence and holds apart.

`tests/test_tenancy_isolation.py` measures both halves — two keys producing two
actor identities in the bodies core actually received, and two batches signed
with two different tenants' credentials. It does **not** exercise reeflex-app's
RLS or core's hold check 8; those live in those repos' suites.

### `gateway_routing`: which model answered, and where it ran

A hook sits in front of one system; a gateway does not. Every decision record
carries a routing block — the model requested and the model that answered, the
deployment id, the provider, the `api_base` host, the calling key/team, and
whether the caller asked for a stream.

`placement` is `on_prem` / `cloud` / `undeclared` and is **declared by the
operator** (`on_prem_hosts` / `cloud_hosts`, or the proxy-wide
`REEFLEX_LITELLM_ONPREM_HOSTS` / `REEFLEX_LITELLM_CLOUD_HOSTS`). It is never
inferred: a VPC endpoint in a public cloud is private too, and a reverse proxy
in the building can be public. A separate `api_base_is_private` field carries
the *measured* hint, and is `null` for a DNS name because this code did not
resolve it. An undeclared host stays `undeclared` rather than being guessed
into `cloud`.

No prompt, no completion, no tool arguments. The `api_base` is reduced to
`HOST[:PORT]`, dropping userinfo, path and query — a URL can carry a credential
and this value is written to a ledger.

## The outcomes

| core says | what the caller receives |
|---|---|
| `allow` | the tool call, untouched |
| `deny` | the tool call **removed**; a structured refusal in `message.content`; `finish_reason` flips to `stop` if nothing is left to call |
| `require_approval` | the response is **withheld** up to `reeflex_hold_wait` seconds while the hold is polled. Approved → the original envelope is resubmitted and released **only if core allows it**. Rejected → refused. Nobody decided in time → refused, naming the still-open hold so the caller can retry |
| unreachable / unparseable / unknown | **fail closed**: refused, `reeflex_unavailable`, rule `reeflex.core/fail_closed`, with the reason in the payload the model reads |
| *core is never asked* | the caller's key/team is not bound to a Reeflex org: refused, `reeflex_tenant_unmapped`, rule `reeflex.litellm/tenancy_unmapped`. This is decided **before** core, so no decision is recorded against the wrong tenant and no R5 budget is charged to a session that belongs to nobody |

A response with several tool calls is ruled on **per call**: one denied call
beside one allowed call removes exactly one.

`require_approval` never releases on the hold status alone. Core's eight
resubmission checks are the authority — one of them (RFX-138) exists because a
hold id by itself was once enough to spend somebody else's approval.

## Tool names

The classifier speaks the Claude Code tool vocabulary (`Bash`, `Write`, `Edit`,
`Read`, `WebFetch`, …). Your gateway's tools are called whatever your
applications called them. This package maps between them, and it will only do so
when the mapping is **faithful**:

* a tool whose name suggests shell execution **and** which carries a command
  string → `Bash`, and the classifier prices the **actual command**;
* an argument that IS a shell command (`command` / `cmd` / `shell_command`) →
  `Bash`, under any tool name;
* write / edit / read / fetch / search names with a matching argument shape →
  the corresponding tool;
* **everything else is unmapped.**

An unmapped tool call goes to the classifier under its own gateway name, which
is the classifier's unknown-tool path. Measured against
`reeflex-core:v0.2.0`: that is `require_approval` under
`reeflex.policy/irreversible_broad_prod` — **it asks a human. It is not allowed
and it is not silently denied.**

A tool called `delete_file(path=…)` is deliberately left unmapped rather than
rewritten into a synthetic `rm -- <path>`: fabricating a command the model never
proposed would put that command into `context.command_preview`, i.e. into the
line a human reads in the audit record. (RFX-144/145/146: price the action, not
a phrasing we invented for it.)

Declare your own names instead:

```bash
export REEFLEX_LITELLM_TOOL_MAP='{"acme_infra_runner": "Bash"}'
```

The map is re-read per call, so an edit needs no proxy restart. A malformed map
is ignored rather than fatal — a typo must not take the governance seat offline,
and an ignored map leaves calls unmapped, which asks a human.

Check a map before pointing the proxy at anything, with no network:

```bash
echo '[{"id":"c1","type":"function","function":{"name":"acme_infra_runner",
  "arguments":"{\"cmd\": \"rm -rf /\"}"}}]' | reeflex-litellm normalize
```

**The gateway tool name always reaches core**, mapped or not, as
`action.ability` = `litellm/<your tool name>`. Two reasons, both verified:
core's verb canon reads the ability's first token (so `litellm/delete_file`
becomes `verb: delete` inside core, and lands on R5's deletion budget), and
core's audit line carries `action.ability` — so your tool name is what a human
sees in the record.

## What it costs

Measured on one box on 2026-09-08: LiteLLM 1.100.0,
`ghcr.io/reeflex-io/reeflex-core:v0.2.0` (digest `sha256:58a0a531dfa1…`, 32
decision workers), a local mock model, one allowed tool call per response, a
unique session per request. Two identical proxies differing only in whether the
guardrail is in the config; requests fired **alternately** at both so they share
the box's state; 200-request warm-up; repeats per cell; **zero errors in every
cell of every table below**.

**`added p50` = the seat's cost per request.**

| concurrent requests | 1 proxy worker | 4 proxy workers | `POST /v1/decide` alone |
|---|---|---|---|
| 1 | **+79.5 … +81.0 ms** | +79.4 … +79.9 ms | 82 ms |
| 10 | **+167.2 … +176.7 ms** | **+81.4 … +88.1 ms** | 63 ms |
| 50 | **+832 … +874 ms** | **+565 … +578 ms** | 226 ms |

Read across the row, not down the column. Three things fall out of it:

* **At concurrency 1 the seat costs exactly one decision** — +80 ms against a
  measured 82 ms for `POST /v1/decide` on its own. This adapter's own overhead
  is in the noise. The cost driver is core forking `opa eval` per decision.
  (Connection reuse makes no difference: keep-alive against core measures 82.6
  ms p50 versus 82.0 ms for a fresh connection per call.)
* **At concurrency 10 the extra 90 ms on a single-worker proxy is the PROXY, not
  the seat.** Classification and JSON work happen in worker threads inside the
  proxy's own process, so they contend on the GIL with its event loop. Running
  the proxy with `--num_workers 4` brings the added cost back to ~85 ms, i.e.
  back to one decision. **If you take one operational note from this section:
  scale the proxy's workers.**
* **At concurrency 50 you are out of decision capacity, and more proxy workers
  only partly help.** Core sustained ~195 decisions/s at 50 concurrent with
  **zero shed requests** (`shed_total: 0`, 32 workers), and 50 in-flight
  requests each needing an 82 ms decision cannot go faster than that pipe.
  Scale `reeflex-core` — replicas, or `REEFLEX_MAX_WORKERS` — before scaling
  anything here, and keep `proxy workers × REEFLEX_LITELLM_MAX_INFLIGHT` in the
  same neighbourhood as core's capacity rather than well above it.

**A response with N tool calls costs about N decisions.** Calls within one
response are decided **in order, not concurrently**, on purpose: R5's cumulative
budget is charged per decision on a shared session, so deciding them
concurrently would make the verdict depend on which decision reached the ledger
first. Measured at 2 calls per response, concurrency 1: added p50 **+158.2 …
+159.5 ms** — twice the one-call number, as designed.

### Does tenancy change that? No — it is still one decision

Re-measured on 2026-09-08 with the tenancy lookup, the routing block and the
evidence ledger all on the request path. Three proxies against one core and one
mock model, requests **rotated** across the arms so no arm is systematically
last, keep-alive per thread, `TCP_NODELAY`, zero errors:

| concurrency | no guardrail | guardrail, pre-tenancy | guardrail, tenancy on |
|---|---|---|---|
| 1 | 12.0 ms | 88.3 ms | **89.0 ms** |
| 10 | 14.2 ms | 171.1 ms | **173.3 ms** |

The RFX-243 delta (tenancy on − pre-tenancy) has a **median of +1.9 ms at
concurrency 1**, but individual repeats ran from **−9.6 ms to +4.0 ms** — it
straddles zero, so this instrument cannot resolve it. What *can* be bounded is
the work itself, measured directly:

| on the request path, per tool call | cost |
|---|---|
| `tenancy.resolve()` (map from file, cached, includes the `stat`) | 11.8 µs |
| `routing.build()` (the `gateway_routing` block) | 12.7 µs |
| `evidence.ledger_record()` | 12.0 µs |
| **all RFX-243 CPU work together** | **68 µs** |
| `evidence.append_ledger()` — one `write` + `fsync` | 273 µs |

So ~0.34 ms of real work against a ~85 ms decision: **0.4%**. And the count that
"one decision" actually means is exact — 20 proxy requests carrying one tool
call each produced **exactly 20** `POST /v1/decide` in core's log. The tenancy
lookup adds **no** core round trip; it is a local map read.

Two caveats worth more than the numbers. **The bigger envelope is free:**
`context.gateway_routing` grows the body from 1119 to 1823 bytes (1.6×) and
costs core **−0.26 ms p50** over 300 interleaved requests — i.e. nothing. And
**a fixed arm order lies:** the first version of this table read +4.6 ms, all of
which turned out to be a position effect in the harness — the arm that ran last
in each interleaved triple paid a systematic penalty. Reversing the order
collapsed it to +0.3 ms and one repeat went negative. Rotating fixed it.

**Two measurement errors this table already survived**, both recorded in
`bench/latency.py`'s docstring because the corrected numbers are only worth
anything next to them:

* A first version reported `added p50 +28.0 ms` at concurrency 1. Re-running the
  identical cell gave +85.9 / +85.5 / +86.6. The harness's own client opened a
  fresh connection per request, which made the **baseline** bimodal (p50 ~9 ms
  or ~58 ms, a 49 ms step, each mode steady for hundreds of consecutive
  requests) while the model behind both proxies measured 1.3 ms flat. A
  sequential design subtracts a baseline measured in one mode from a hook-on
  cell measured in the other. Fixed by a per-thread keep-alive connection with
  `TCP_NODELAY`, and by interleaving the two sides.
* The streaming hole was first measured as "the destructive call did NOT reach
  the caller" — which was the mock model not implementing SSE, not the gateway
  governing anything. It implements SSE now, which is how the hole was confirmed
  and then closed.

Reproduce with `bench/latency.py` (`--help` and the module docstring document
every constant it holds fixed and why).

### What streaming costs, which is two numbers and not one

Same rig, same day, `--stream`, one uvicorn worker, 3 repeats per cell, zero
errors. Streaming has **two** latencies and quoting either one alone is
misleading:

| concurrency 1 | added p50 |
|---|---|
| **time to first token** (first SSE frame) | **−0.4 … +0.3 ms** |
| **time to first tool-call frame** | **+71.3 … +73.0 ms** |
| whole response | +71.4 … +73.1 ms |
| *same rig, buffered, for comparison* | *+67.7 … +68.6 ms* |

The first row is what a human watching text appear experiences: the seat does
not touch prose, so it is unchanged. The second is what an agent experiences:
the tool call cannot leave until `/v1/decide` answers, so it costs **one
decision** — the same one the buffered path costs, plus ~3 ms.

On a **prose** response the seat never calls core at all, and the whole added
cost is **+0.6 … +1.7 ms p50**. The pre-fix build measured **+40.4 … +40.9 ms**
on that same prompt, because LiteLLM was reassembling every stream after
delivery to run the buffered hook on it. Governing streaming made ungoverned
prose *faster*.

At concurrency 10 on one worker the proxy is saturated — baseline p95 swings
between 85 and 156 ms across repeats — and the added figures (+130 … +207 ms
TTFT, +315 … +345 ms to the tool frame) are dominated by queueing in the proxy,
not by the seat. The operational note from the buffered table applies unchanged
and is the one that matters: **scale the proxy's workers.**

**The mock emits its whole stream at once**, so these are upper bounds. A real
provider spends hundreds of milliseconds emitting tokens, and the decision
overlaps that.

## Not in this version

* **Pre-call blocking.** The seat cannot stop a request from reaching a model;
  it rules on what comes back.
* **`enforcement_stage` and `gateway_routing` on the evidence wire.** They are
  in the local ledger, not on the §4 feed, because §4 is a closed schema and
  frozen. An Attest report built from that feed cannot tell a gateway refusal
  from an execution-side prevention. Flagged for the spec owner; not an
  adapter's change to make.
* **A cumulative session budget without a session header.** Unchanged by
  tenancy — see "One session per request" above. Tenancy changed the
  *namespace*, not the value.
* **Counting unmapped callers.** An unmapped caller is refused and logged, but
  writes no ledger row: a governance row naming no org would be worse than an
  absent one, because a report could total it. Read the proxy log.
* **Authenticating the caller.** `user_api_key_dict` is LiteLLM's
  authentication result and this package trusts it exactly as far as LiteLLM's
  own code does. If the proxy's key auth is wrong, this is wrong with it.

## Development

```bash
pip install -e ../reeflex-claude -e '.[proxy]' pytest
pytest tests/ -q
```

`tests/test_litellm_contract.py` skips without `litellm` installed, and asserts
that the base class in play is litellm's real `CustomGuardrail` before testing
anything — so a green run cannot mean "the fallback shim passed". Everything
else runs with no proxy, no model and no Docker, against a scriptable stub core
(`tests/stubcore.py`, which documents what it is and is not evidence of).

**Neither suite reads a socket.** For the streaming path that matters, because
the defect it closes was a defect of what left the process. `proxy/stream_walk.py`
drives a real proxy and asserts on the raw `text/event-stream` bytes:

```bash
python3 proxy/mock_model.py --port 18612 &
litellm --config proxy/config.yaml --port 18620 &          # with the seat
litellm --config proxy/config-nohook.yaml --port 18630 &   # the control
python3 proxy/stream_walk.py \
    --hook-url http://127.0.0.1:18620 \
    --nohook-url http://127.0.0.1:18630 \
    --core-url http://127.0.0.1:18711 \
    --api-key-file /path/to/the/proxy/master.key
```

It exits non-zero on any failure and prints the measurement rather than a
verdict word on every row, so running it against a gateway *without* the seat
prints the destructive command sitting in the bytes.

## License

Apache-2.0.
