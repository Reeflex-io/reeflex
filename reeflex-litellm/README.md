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

### Streaming responses are NOT governed by this hook

`mode: post_call` fires for a buffered response. A request with `stream: true`
is delivered through a different hook (`async_post_call_streaming_iterator_hook`)
which this class does not implement.

**Measured, not assumed** (2026-09-08, litellm 1.100.0, this proxy config): the
same `rm -rf /` tool call that is refused on the buffered path **reaches the
caller intact** as `chat.completion.chunk` deltas when `stream: true` is set.

Until that hook is implemented, a deployment that must not have an ungoverned
path should **refuse `stream: true` at the gateway**.

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

> **Check your `reeflex-claude`.** The classifier lives in `reeflex-claude`, and
> the version on PyPI is **0.1.7, uploaded 2026-07-06** — which predates the
> RFX-144/145/146 fix. Measured against `reeflex-core:v0.2.0` with that wheel:
> `echo starting && rm -rf /var/lib/pgsql` is priced `reversible/single` and
> **core allows it**. With the classifier from the repository's `main`, the same
> command is denied `irreversible_systemic_prod`.
>
> `tests/test_classifier_vintage.py` fails loudly on the stale wheel. Run the
> suite after installing, or install `reeflex-claude` from source until a newer
> wheel is published.

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
litellm --config proxy/config.yaml --host 127.0.0.1 --port 4000
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

## The four outcomes

| core says | what the caller receives |
|---|---|
| `allow` | the tool call, untouched |
| `deny` | the tool call **removed**; a structured refusal in `message.content`; `finish_reason` flips to `stop` if nothing is left to call |
| `require_approval` | the response is **withheld** up to `reeflex_hold_wait` seconds while the hold is polled. Approved → the original envelope is resubmitted and released **only if core allows it**. Rejected → refused. Nobody decided in time → refused, naming the still-open hold so the caller can retry |
| unreachable / unparseable / unknown | **fail closed**: refused, `reeflex_unavailable`, rule `reeflex.core/fail_closed`, with the reason in the payload the model reads |

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
* The streaming limit above was first measured as "the destructive call did NOT
  reach the caller" — which was the mock model not implementing SSE, not the
  gateway governing anything. It does not implement SSE any more; the limit is
  real.

Reproduce with `bench/latency.py` (`--help` and the module docstring document
every constant it holds fixed and why).

## Not in this version

* **Tenancy.** A gateway virtual key or team is not mapped to a Reeflex org or
  session; see "One session per request" above. This is the next ticket.
* **Streaming.** See the limit above. Refuse `stream: true` meanwhile.
* **Pre-call blocking.** The seat cannot stop a request from reaching a model;
  it rules on what comes back.
* **Evidence push.** Refusals are in the response and in core's audit log. This
  package does not itself push to an Attest pipeline.

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

## License

Apache-2.0.
