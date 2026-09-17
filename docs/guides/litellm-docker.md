---
title: "Govern LiteLLM in Docker: AI governance for tool calls, without rebuilding your proxy"
description: >-
  Two measured ways to put Reeflex in front of a LiteLLM proxy running in
  Docker — an external connector container that needs nothing in your image,
  and a derived image with the guardrail installed in-process. Complete
  docker-compose for both, with the scoping matrix, the hold behaviour and the
  latency cost measured on the stock ghcr.io/berriai/litellm image.
---

# Govern LiteLLM in Docker

You run LiteLLM as a container. This page puts Reeflex in front of the tool
calls your models return, and it is written so that everything on it was run —
against the stock `ghcr.io/berriai/litellm:v1.101.0` image, on a clean host, on
**2026-09-17**. Where a thing did not work, or works only on LiteLLM's paid
tier, it says so.

There are two paths. **Read the first one.** The second exists for a deployment
that cannot accept a BETA API on LiteLLM's side.

| | **Nothing in your image** | **Inside your image** |
|---|---|---|
| what you run | one extra container (`reeflex-connector`) | your own image, `FROM ghcr.io/berriai/litellm` |
| your proxy container | **unchanged, stock** | rebuilt, and rebuilt again on every LiteLLM upgrade |
| LiteLLM feature used | Generic Guardrail API (**BETA**, see [Bounds](#what-this-path-depends-on-and-what-breaks-if-it-changes)) | `CustomGuardrail` dotted import path (stable 1.x) |
| a denied tool call | the whole response is refused, HTTP 400 | the call is removed, HTTP 200, the rest of the response survives |
| a denied call in a **streamed** response | **the bytes reach your client**, then an error frame | the call never reaches your client |
| added latency, 1 concurrent caller | **+95 ms** | +92 ms |
| added latency, 10 concurrent callers | no reliable figure — [see below](#what-it-costs) | no reliable figure |

Both paths take the same decision, from the same code, against the same
`reeflex-core`. The difference is where that code runs and what LiteLLM lets it
hand back.

!!! warning "What a gateway seat can and cannot claim"

    A gateway sees a tool call **proposed**, never executed. Both paths refuse
    an instruction before it is handed to your application; neither is in the
    execution path, so an application that keeps its own copy of the model's
    answer, or reads the refusal and runs the tool anyway, is not stopped.
    Every refusal Reeflex emits here is recorded `stage: refused_at_gateway`
    and is never reported as prevention at the point of execution. If you need
    the action blocked where it runs, add a seat there too —
    [`reeflex-claude`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-claude/README.md)
    for Claude Code, the WordPress gate for WooCommerce, or your own adapter in
    front of the tool.

---

## Path 1 — nothing in your image

### What it is

LiteLLM ships a **Generic Guardrail API**: instead of importing a Python class,
the proxy POSTs the model's answer to an HTTP server you run, and that server
answers `NONE` (let it through) or `BLOCKED` (refuse). Reeflex ships that
server as a container. Your LiteLLM stays the image you already pulled, in
whatever container or managed service you run it in.

```
your app ──► LiteLLM (stock image) ──► model
                  │  the answer, with its tool_calls
                  ▼
           reeflex-connector ──► reeflex-core  POST /v1/decide
                  │                    (allow / deny / require_approval)
                  ▼
           NONE | BLOCKED  ──► LiteLLM ──► your app
```

The connector classifies the tool call, binds the LiteLLM key or team to a
Reeflex org, builds the Action Envelope and asks core **once per tool call**.
Core never sees LiteLLM, and never sees the axes it decides on — it receives
them computed, in the envelope, from a process you run.

### 1. The compose file

```yaml title="docker-compose.yml"
services:
  litellm:
    # The STOCK image. Pin it: the guardrail API this depends on is BETA.
    image: ghcr.io/berriai/litellm:v1.101.0
    command: ["--config", "/app/config.yaml", "--port", "4000"]
    ports: ["4000:4000"]
    environment:
      LITELLM_MASTER_KEY: ${LITELLM_MASTER_KEY:?set me}
      # The shared secret LiteLLM presents to the connector. Same value as
      # REEFLEX_CONNECTOR_TOKEN below; referenced, never written here.
      REEFLEX_CONNECTOR_TOKEN: ${REEFLEX_CONNECTOR_TOKEN:?set me}
    volumes:
      - ./litellm-config.yaml:/app/config.yaml:ro
    depends_on: [reeflex-connector]

  reeflex-connector:
    image: ghcr.io/reeflex-io/reeflex-connector:latest
    environment:
      REEFLEX_CONNECTOR_TOKEN: ${REEFLEX_CONNECTOR_TOKEN:?set me}
      REEFLEX_CORE_URL: http://reeflex-core:8080
      REEFLEX_LITELLM_TENANCY_MAP_FILE: /etc/reeflex/tenancy.json
      # Seconds a response may be withheld while a human decides a hold.
      # 0 = never wait: refuse at once and name the hold. See "Holds" below.
      REEFLEX_LITELLM_HOLD_WAIT: "30"
    volumes:
      - ./tenancy.json:/etc/reeflex/tenancy.json:ro
      # The connector's own decision ledger. WITHOUT THIS VOLUME the ledger is
      # discarded when the container is recreated.
      - reeflex-ledger:/app/ledger
    # No `ports:` on purpose — only the proxy needs to reach it.

  reeflex-core:
    image: ghcr.io/reeflex-io/reeflex-core:v0.2.1
    environment:
      # Binds an approver's bearer token to the principal it IS, which is what
      # lets a hold be approved at all (core 0.2.0+ refuses an approver it
      # cannot verify). One entry per human who may approve.
      REEFLEX_RESOLVER_TOKENS: >-
        {"${APPROVER_TOKEN:?set me}":{"type":"human","id":"alice@example.com"}}
    volumes:
      - reeflex-state:/app/audit

volumes:
  reeflex-ledger:
  reeflex-state:
```

### 2. The LiteLLM config

```yaml title="litellm-config.yaml"
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  - guardrail_name: reeflex
    litellm_params:
      guardrail: generic_guardrail_api
      # post_call is the ONLY mode that can see an action. The pre-call hook
      # sees the prompt and which tools EXIST — not which one the model chose,
      # nor with what arguments. A proxy configured `mode: pre_call` looks
      # wired and governs nothing; the connector counts those requests and
      # says so on /healthz.
      mode: post_call
      api_base: http://reeflex-connector:8080
      api_key: os.environ/REEFLEX_CONNECTOR_TOKEN
      # The default. Named anyway: it is the difference between a connector
      # outage refusing actions and a connector outage releasing them.
      unreachable_fallback: fail_closed
      default_on: true
      # WITHOUT THIS the value of your session header does not arrive.
      # LiteLLM forwards the VALUE of an inbound header only for its own
      # allowlist (host, accept, content-type, user-agent, x-stainless-*,
      # x-litellm-*) and replaces every other value with the literal string
      # "[present]". `extra_headers` is the allowlist extension.
      extra_headers: ["x-reeflex-session"]
```

### 3. The tenancy map — without it, every tool call is refused

Reeflex has **no default org**. A gateway caller that no map binds is refused
before core is asked, so that one department's actions never land in another
department's evidence.

```json title="tenancy.json"
{
  "version": 1,
  "tenants": {
    "acme-payments": {
      "org": "acme-payments",
      "label": "ACME Payments",
      "principal": "payments-oncall@acme.example",
      "environment": "production"
    }
  },
  "bind": {
    "key_alias": {"payments-bot": "acme-payments"},
    "team_id":   {"6b4af483-312f-48d9-a028-290ac3c59e6d": "acme-payments"}
  }
}
```

`environment` is load-bearing and is the setting most easily got wrong.
Measured on this rig: the same `rm -rf /var/lib/pgsql`, from two keys bound to
two orgs, was **denied** (`irreversible_systemic_prod`) for the org declared
`production` and **allowed** (`default_allow`) for the org declared `staging`.
The policy is environment-sensitive by design; a production deployment mapped
to `staging` is governed by the weaker half of the pack.

### 4. Start it, and prove it

```console
$ docker compose up -d
$ curl -s localhost:4000/health/liveliness
$ docker compose exec litellm python -c "import reeflex_litellm"
ModuleNotFoundError: No module named 'reeflex_litellm'   # ← the point of this path
```

Now make the model propose something destructive and read what comes back:

```console
$ curl -s localhost:4000/v1/chat/completions \
    -H "Authorization: Bearer $YOUR_VIRTUAL_KEY" \
    -H 'Content-Type: application/json' \
    -H 'x-reeflex-session: nightly-batch' \
    -d '{"model":"gpt-4o","messages":[{"role":"user",
         "content":"delete the postgres data directory"}]}'
```

A refused response looks like this — HTTP **400**, with the structured refusal
inside `error.message`:

```json
{"error": {"message": "Reeflex: irreversible systemic change in production is not allowed even with approval [rule=reeflex.policy/irreversible_systemic_prod] {\"reeflex\": {\"refused\": [{\"error\": \"reeflex_denied\", \"rule\": \"reeflex.policy/irreversible_systemic_prod\", \"reason\": \"...\", \"tool_call_id\": \"call_0_4c3923ac\", \"tool\": \"run_shell\", \"stage\": \"refused_at_gateway\"}], \"version\": 1}}",
            "type": "invalid_request_error", "code": "400"}}
```

The connector's own counters are the second witness, and they need the token:

```console
$ curl -s -H "x-api-key: $REEFLEX_CONNECTOR_TOKEN" \
       http://reeflex-connector:8080/healthz
{"status":"ok","service":"reeflex-connector","version":"0.2.0",
 "endpoint":"/beta/litellm_basic_guardrail_api","auth_required":true,
 "tenancy":{"loaded":true,"orgs":2},"core_url":"http://reeflex-core:8080",
 "hold_wait_seconds":30.0,
 "counters":{"responses_seen":8,"tool_calls_decided":9,"allowed":3,
             "blocked":4,"pre_call_requests":0,"unmapped_tenant":1,
             "internal_errors":0,"unauthorised":0}}
```

Without the token `/healthz` still answers — liveness, version, whether a token
is required and whether a tenancy map loaded — so a container healthcheck needs
no secret and an operator can tell "no map" from "wrong token" without one.

### What your agent sees when a call is refused — and the one way this path is stricter

**A refusal on this path refuses the whole response.** If a response proposes
two tool calls and core denies one, the caller gets the refusal naming the
denied call and does not get the allowed one either.

That is not a choice we made freely. LiteLLM's guardrail response model
(`GenericGuardrailAPIResponse`, 1.101.0) carries exactly `action`,
`blocked_reason`, `texts`, `images`, `tools` and `stream_holdback_chars`.
**There is no `tool_calls` field on the response**, and
`_build_guardrail_return_inputs()` copies back only texts, images, tools and
holdback — so there is no way to say "keep call 1, drop call 2". Answering
`NONE` and describing the refusal in the text would *release* the denied call.
So the connector blocks, which is stricter than the in-process seat and never
weaker.

If your agents routinely batch an allowed call and a governed one in a single
response, path 2 loses less work.

### Holds: a human in the loop, over an HTTP request that waits

A hold on this path is a **slow HTTP response**. The connector does not answer
until the human has, or until `REEFLEX_LITELLM_HOLD_WAIT` runs out. Measured
end to end on this rig, with a real hold raised by core and approved by a human
credential:

| arm | what happened | elapsed |
|---|---|---|
| nobody approves, `hold_wait: 30` | HTTP 400, `reeflex_hold_timeout`, the hold id named so it can be retried after a decision | 31 s |
| a human approves while the request waits | **HTTP 200, the tool call delivered** | 1 s |
| connector holds 65 s, proxy at its default timeout | HTTP 400, `reeflex_hold_timeout` — **the proxy waited 67 s** | 67 s |
| proxy `REQUEST_TIMEOUT=10`, hold 65 s, `fail_closed` | **HTTP 500** from LiteLLM (`litellm.Timeout`), the action refused — but the caller sees LiteLLM's error, not Reeflex's reason | 11 s |
| proxy `REQUEST_TIMEOUT=10`, hold 65 s, `fail_open` | **HTTP 200, the tool call delivered** | 11 s |

The approved arm's ledger row is the evidence that this is a real Article-14
loop and not a timing coincidence:

```json
{"rule": "reeflex.policy/approved_resubmission",
 "enforcement_stage": "allowed_at_gateway", "released_after_approval": true,
 "hold_decision": {"decided_by": {"type": "human", "id": "alice@example.com"},
                   "resolution": "approved", "verified": true}}
```

**So holds are honoured on this path, and three things follow.**

1. **LiteLLM's timeout on the guardrail call is 600 s** — read off
   `get_async_httpx_client(GuardrailCallback)`, whose client is built with
   `httpx.Timeout(600 s, connect=5 s)` — and measured to exceed 65 s. Set
   `REEFLEX_LITELLM_HOLD_WAIT` below it.
2. **It is not configurable per guardrail.** The only lever is the
   `REQUEST_TIMEOUT` environment variable, which is proxy-wide and also
   governs your model calls. Measured: with `REQUEST_TIMEOUT=10` the guardrail
   call was abandoned at ~11 s.
3. **At expiry the default is fail-closed, and `fail_open` is a hole.** With
   `unreachable_fallback: fail_open` the same expiry **delivered the tool
   call**, and so did stopping the connector entirely. If you set `fail_open`,
   set `REEFLEX_LITELLM_HOLD_WAIT: 0` with it — refuse at once and name the
   hold — because a hold that outlives the timeout is otherwise an approval
   nobody gave.

A caller that gets `reeflex_hold_timeout` can read the `hold_id` out of the
refusal, wait for the human, and retry; core's single-use check means the
approval is spent once.

### Streaming: the refusal lands, but not before the bytes

Measured on the wire, with `stream: true` and a denied tool call:

| path | what the client received |
|---|---|
| **connector (this path)** | 5 SSE frames carrying the tool call and its complete arguments — `rm -rf /var/lib/pgsql` **is in the delivered bytes** — followed by an error frame carrying the Reeflex refusal, and no `finish_reason` |
| in-process (path 2) | 4 frames, **no tool call at all**, `finish_reason: "stop"` |

This follows from LiteLLM's streaming design rather than from ours: in the
default `block_only` mode the proxy yields each chunk to the client as it
arrives and scans every 5th chunk, so a block terminates what is left of the
stream instead of preventing what has already gone. The one setting that
withholds chunks until the whole response is moderated
(`streaming_buffer_until_moderated`) is read off an attribute the generic
guardrail class never sets, and there is no config key that reaches it.

**What to do about it, in order of preference:**

* **Send `stream: false` for agents that call tools.** Nothing is lost: a tool
  call is not read as it arrives — nothing happens until the whole call is
  there.
* **Use path 2 for streaming agents.** Its streaming hook buffers the tool-call
  frames, decides, and only then releases — measured above.
* **Treat the streamed path as audit-only** and know that you are: the decision
  is recorded and the refusal is delivered, but after the client has the bytes.

### What this path depends on, and what breaks if it changes

* The Generic Guardrail API is marked **BETA** by LiteLLM. Everything here was
  measured on **`ghcr.io/berriai/litellm:v1.101.0`**
  (digest `sha256:d295634e09c648dcdb72c4cc2dd226f5fb87823a73e88cbbed6f205e4deb044b`).
  **Pin that tag.**
* If the request shape changes, the connector sees fewer fields: the tenancy
  block is `request_data`, and a caller it cannot bind is refused, not guessed.
  You would see `unmapped_tenant` climbing on `/healthz`.
* If the response vocabulary changes — for example if a future release reads
  `tool_calls` back from a guardrail — the whole-response block above becomes
  unnecessary, and that is the first thing we would change.
* If the endpoint path moves, LiteLLM appends
  `/beta/litellm_basic_guardrail_api` to your `api_base`; the connector serves
  exactly that path and answers 404 on anything else.

### What the evidence record loses on this path

The connector records the same decision ledger as the in-process seat, with one
honest gap: the generic wire carries no `_hidden_params`, so **which deployment
answered** is not knowable here. `api_base_host`, `deployment_id` and
`provider` are `null`, and `placement` is `undeclared` rather than guessed at.
If "was this prompt answered on-premise or in someone else's cloud" has to be
in your evidence, path 2 carries it. Everything else — the org, the session,
the axes, the rule, the stage, the approver — is identical, and the ledger row
says `"transport": "generic_guardrail_api"` so the two are never confused.

---

## Path 2 — inside your image

Take this path when a BETA API on LiteLLM's side is unacceptable, when you
batch governed and ungoverned tool calls in one response, or when you stream
tool calls and need them withheld.

### The Dockerfile, and why it is not the two lines you have seen

Every write-up of this pattern, including ours until today, says:

```dockerfile
FROM ghcr.io/berriai/litellm:main-latest
RUN pip install 'reeflex-litellm[proxy]'      # ← this does not build
```

**Measured 2026-09-17: that fails with `exit code 127`.** The LiteLLM image is
a [Wolfi](https://github.com/wolfi-dev) image whose Python lives in a
virtualenv at `/app/.venv` (Python 3.13.15), and it ships **no `pip`, no
`pip3`, no `uv`**. `python -m pip` answers `No module named pip`.
`python -m ensurepip` does work. So:

```dockerfile title="Dockerfile"
FROM ghcr.io/berriai/litellm:v1.101.0
RUN python -m ensurepip \
 && python -m pip install --no-cache-dir "reeflex-litellm==0.1.0"
```

Two notes on that second line, both measured:

* **`reeflex-litellm`, not `reeflex-litellm[proxy]`.** The `[proxy]` extra
  exists to bring LiteLLM in; this image already has it, and asking for the
  extra invites pip to resolve LiteLLM again inside an image that was built
  with `uv`. Installing the base package pulled exactly two wheels —
  `reeflex_litellm-0.1.0` and its one dependency `reeflex_claude-0.2.0` — and
  left LiteLLM untouched.
* **Pin the version.** An unpinned install makes the image you ship today and
  the image you ship next month two different governance builds. `0.1.0` is
  what is on PyPI as of 2026-09-17 and it is the build measured here; the tree
  has since moved to `0.2.0`, so raise the pin once a release tag publishes it
  ([Availability](#availability)).

### The compose file

```yaml title="docker-compose.yml"
services:
  litellm:
    build: .                       # the Dockerfile above
    command: ["--config", "/app/config.yaml", "--port", "4000"]
    ports: ["4000:4000"]
    environment:
      LITELLM_MASTER_KEY: ${LITELLM_MASTER_KEY:?set me}
      REEFLEX_CORE_URL: http://reeflex-core:8080
      REEFLEX_LITELLM_TENANCY_MAP_FILE: /etc/reeflex/tenancy.json
      REEFLEX_LITELLM_HOLD_WAIT: "30"
    volumes:
      - ./litellm-config.yaml:/app/config.yaml:ro
      - ./tenancy.json:/etc/reeflex/tenancy.json:ro
    depends_on: [reeflex-core]

  reeflex-core:
    image: ghcr.io/reeflex-io/reeflex-core:v0.2.1
    environment:
      REEFLEX_RESOLVER_TOKENS: >-
        {"${APPROVER_TOKEN:?set me}":{"type":"human","id":"alice@example.com"}}
    volumes:
      - reeflex-state:/app/audit

volumes:
  reeflex-state:
```

Note what moved: on this path the Reeflex environment (`REEFLEX_CORE_URL`, the
tenancy map, the hold wait) belongs to the **proxy** container, because the
decision runs inside it.

### The config

```yaml title="litellm-config.yaml"
guardrails:
  - guardrail_name: reeflex
    litellm_params:
      # A dotted import path: this module must be importable INSIDE this
      # container, which is what the derived image above is for.
      guardrail: reeflex_litellm.guardrail.ReeflexActionGuardrail
      mode: post_call
      default_on: true
      reeflex_hold_wait: 30
      reeflex_session_header: x-reeflex-session
```

### What a refusal looks like here

HTTP **200**, with the denied call deleted from the response and the refusal
where the model will read it on the next turn:

```json
{"choices": [{"finish_reason": "stop",
              "message": {"role": "assistant", "tool_calls": null,
                          "content": "{\"reeflex\": {\"refused\": [{\"error\": \"reeflex_denied\", \"rule\": \"reeflex.policy/irreversible_systemic_prod\", \"stage\": \"refused_at_gateway\", ...}], \"version\": 1}}"}}]}
```

A client that simply executes the tool calls it is given has nothing to
execute, and `finish_reason` flips from `tool_calls` to `stop` so an
OpenAI-compliant client does not loop waiting for a call that is not there.

---

## Which requests does Reeflex run on?

This is the section to read before deciding whether the integration fits your
org. **Every row was measured on the stock OSS image, and three of the six
scopes in LiteLLM's documentation are paid-tier features** that answer 403 or
500 without a `LITELLM_LICENSE`.

| scope | where it is set | stock OSS image? |
|---|---|---|
| **everyone, always** | `default_on: true` on the guardrail | ✅ measured |
| **per model / provider** | `model_list[].litellm_params.guardrails: ["reeflex"]` | ✅ measured |
| **per request** | `{"guardrails": ["reeflex"]}` in the request body | ✅ measured |
| **per team, locked** | `POST /team/update {"metadata": {"guardrails": {"modify_guardrails": false}}}` | ✅ measured |
| **per API key** | `POST /key/generate\|/key/update {"guardrails": [...]}` | ❌ **403, Enterprise** |
| **per team, attached** | `POST /team/update {"guardrails": [...]}` | ❌ **403, Enterprise** |
| **by tag / header** | `mode: {tags: {"User-Agent: x": "post_call"}, default: ...}` | ❌ **Enterprise — and it fails at request time**: the config loads, then every request through that proxy answers HTTP 500 |

The measured rows, with the same denied action every time, and two witnesses
per row (what the caller got, and whether the connector was asked at all):

```
--- per REQUEST -------------------------------------------------------------
body names ["reeflex"]                     HTTP 400  reeflex ran   REFUSED
body names ["sink"] (another guardrail)    HTTP 200  reeflex idle  DELIVERED
body names nothing                         HTTP 200  reeflex idle  DELIVERED
--- per MODEL ---------------------------------------------------------------
model has reeflex attached, body silent    HTTP 400  reeflex ran   REFUSED
model ungoverned, body silent              HTTP 200  reeflex idle  DELIVERED
--- default_on: true --------------------------------------------------------
every row above, including "body names a DIFFERENT guardrail" and
"body names []"                            HTTP 400  reeflex ran   REFUSED
```

### The three things a buyer asks next

**1. Precedence, measured rather than inferred.** Attachments are **additive**,
and a caller cannot subtract one. A model with Reeflex attached, called with
`{"guardrails": ["something-else"]}` in the body, still ran Reeflex and refused
the action; so did `{"guardrails": []}`; so did `default_on: true` against both.
Two guardrails can and do run on one request (measured: both were called on an
allowed action) — but **the first one that blocks ends the request**, and the
rest are not called. That is why a Reeflex refusal shows `sink` at zero calls:
not precedence, ordering.

The one way a caller changes the set is by *adding* to it, and
`modify_guardrails: false` on their team closes even that: measured, a request
from a key in that team naming guardrails in its body is answered
**403 `Your team does not have permission to modify guardrails`** by the stock
image, before the model is called.

**2. Off means audited-nothing — not "audited as allowed".** A request that
reaches a provider Reeflex is not attached to produces **no decision record at
all**: no ledger row, no envelope, nothing in core. An Attest report for that
org will have a hole exactly the shape of the un-governed model, and it will
not look like a hole — it will look like a period in which that model proposed
nothing. If you roll out provider by provider, keep the list of un-attached
models with the report, because the report cannot derive it.

**3. LiteLLM's scoping and Reeflex's tenancy are two different questions.**
LiteLLM's scoping decides **whether** Reeflex runs. The tenancy map decides
**which org** the decision belongs to. They are configured in different files
and can disagree: a key can be perfectly in scope for the guardrail and bound
to no org, in which case every tool call from it is refused with
`reeflex_tenant_unmapped` and core is never asked.

```
   LiteLLM scoping                        Reeflex tenancy
   "does the guardrail run?"              "whose decision is it?"
   ├── default_on                         ├── key_hash   ┐
   ├── model_list[].guardrails            ├── key_alias  ├─► one Reeflex org
   ├── team / key (Enterprise)            └── team_id    ┘   (no default org:
   └── request body                                          unbound = refused)
```

### What we recommend, and why

* **Buying Reeflex for compliance:** `default_on: true` on the guardrail, plus
  `modify_guardrails: false` on every team. One line each, both work on the
  free image, and together they mean no caller and no team can opt out of
  being governed.
* **Rolling out provider by provider:** attach per model
  (`model_list[].litellm_params.guardrails: ["reeflex"]`) and leave
  `default_on: false`. Then write down which models are not on the list — see
  point 2.

---

## Tenancy: which fields actually arrive

Reeflex binds a gateway caller to an org on `key_hash`, then `key_alias`, then
`team_id` — most specific first. On the connector path those values arrive in
the request's `request_data` block, and this is one such block, captured off
the wire:

```json
"request_data": {
  "user_api_key_hash": "47094ea918cdee64246554ae2d468daf15071e0f84757decf3c7aea2d6180aeb",
  "user_api_key_alias": "payments-bot",
  "user_api_key_team_alias": "payments",
  "user_api_key_team_id": "6b4af483-312f-48d9-a028-290ac3c59e6d"
}
```

**All three binding dimensions arrive**, for a proxy-issued virtual key:
`user_api_key_hash` is the key's `token_id` — the sha256 of the key, never the
key — and it is what `/key/generate` returned when the key was minted.

Two things this block does **not** carry, and both change what you should bind
on:

* **`via_virtual_key` is not on this wire.** In-process, that field is
  LiteLLM's own unforgeable marker that the proxy authenticated the key, and
  the connector cannot see it. The shape test still applies — a raw `sk-…`
  credential that a `custom_auth` callback put in that field is neither bound
  nor recorded — but a deployment using `custom_auth` should bind on
  `key_alias` or `team_id`, where there is nothing to forge.
* **Fields the proxy did not set are simply absent** (`user_api_key_user_id`,
  `user_api_key_org_id`, `user_api_key_end_user_id` were absent for this key
  and present for others). Bind on a value you set deliberately.

**The catch-all stays a refusal.** A caller that no dimension binds is refused
with a reason naming what the proxy authenticated, and core is never called —
measured, with the master key, which no map bound.

### The session a cumulative budget is charged against

R5's cumulative budgets key on a session id. On this path the connector takes
it from, in order:

1. `additional_provider_specific_params.reeflex_session` — set once in
   `litellm_params`, or per request by the caller under
   `guardrails: [{"reeflex": {"extra_body": {"reeflex_session": "..."}}}]`;
2. the `x-reeflex-session` header — **only if you listed it in
   `extra_headers`**, otherwise its value arrives as the literal `[present]`
   and is discarded rather than used (using it would give every caller behind
   one proxy a single shared budget);
3. `user_api_key_end_user_id`, which is where LiteLLM puts the OpenAI `user`
   field;
4. the per-request `litellm_trace_id` / `litellm_call_id`.

Whatever it resolves to is namespaced by org (`litellm:<org>:<session>`), so
two departments that both call their session `nightly` do not share a budget —
measured.

---

## What it costs

Two proxies, identical but for the guardrail, same mock model, one uvicorn
worker each, 200 requests per cell after a 50-request warm-up, interleaved,
two repeats. `added` is the difference of two p50s, not an instrumented slice
of one.

Every cell was measured **twice, in two sessions hours apart**, and all four
numbers are given rather than the best one:

| concurrency | no guardrail p50 | connector **added** p50 | in-process **added** p50 |
|---|---|---|---|
| 1 | 20.7–22.4 ms | **+93.8 +94.0 +95.1 +96.6 ms** | **+89.3 +91.0 +92.1 +92.6 ms** |
| 10 | 31.4–73.4 ms | +181.5 +229.4 +327.8 +384.3 ms | +257.7 +312.8 +342.3 +373.3 ms |

**At one concurrent caller the cost is about +95 ms, and it is a real number:**
four measurements span 2.8 ms. **The network hop costs about 3 ms** — the
connector's four readings sit consistently ~3 ms above the in-process ones.
Nearly all of the governance cost is the decision itself; core forks an
`opa eval` per decision, and that is the same on both paths.

**At ten concurrent callers there is no reliable number and we will not print
one.** The four readings per path span 2.1×, the *baseline* itself moved
31→73 ms between runs, and the two paths' ranges overlap completely — so the
honest statement is "hundreds of milliseconds, dominated by queueing on a
saturated single worker", not a figure. If concurrency is your question, measure
it on your own hardware with `reeflex-litellm/bench/latency.py`; a number we
quote from one busy host would not survive contact with yours.

One round trip is paid **per tool call**, in order, so a response proposing two
calls costs about twice a response proposing one.

Numbers are per uvicorn worker, against a mock model, on one host. Take them as
the shape of the cost, not as a promise about your hardware.

---

## Failure posture, in one table

LiteLLM has **two** switches here and they are not the same size.
`unreachable_fallback` (default `fail_closed`) covers a connector it could not
reach — a network error, a timeout, or a 502/503/504. `fail_on_error` (default
`true`) covers **every** error, including a 401 and a malformed answer. Each
row below was measured on this rig.

| what fails | default (`fail_closed`, `fail_on_error: true`) | `unreachable_fallback: fail_open` | `fail_on_error: false` |
|---|---|---|---|
| connector stopped | HTTP 500, refused | **HTTP 200, delivered** | delivered |
| guardrail call times out | HTTP 500, refused | **HTTP 200, delivered** | delivered |
| wrong connector token (401) | HTTP 500, refused | HTTP 500, **still refused** | **HTTP 200, delivered** |
| core unreachable from the connector | HTTP 400, `reeflex.core/fail_closed`, with the reason | same | same |
| the connector's own code raises | HTTP 400, `reeflex.core/fail_closed` | same | same |

The last two rows are why the connector answers its own internal failure with
**200 + `action: BLOCKED`** rather than a 5xx: LiteLLM classifies 502/503/504
as "unreachable", and that is exactly the class `fail_open` releases. A
decision expressed in the body cannot be turned into a pass by a setting on the
proxy — which is the whole reason to express it there.

**`fail_on_error: false` releases governed actions on any connector error.** If
you set it, you have chosen availability over governance for that proxy; say so
where your auditors can read it, because the decision record will simply be
absent.

---

## Availability

| | today (2026-09-17) |
|---|---|
| `reeflex-litellm` on PyPI | **0.1.0**, published 2026-09-16 — the in-process guardrail of path 2. That is the version path 2's Dockerfile pins below, and it is the one measured here. The tree now declares **0.2.0** (the connector), which is **not yet on PyPI**; raise the pin to `0.2.0` once a release tag publishes it |
| `reeflex-connector` image | **built from source in this repo**; published to `ghcr.io/reeflex-io/reeflex-connector` from the next release tag. Until that tag lands, path 1 needs `docker build -t reeflex-connector:local reeflex-litellm/` from a checkout, and the compose file's `image:` line pointed at it |
| `reeflex-core` image | `ghcr.io/reeflex-io/reeflex-core:v0.2.1` |

## Also worth knowing

* **The connector refuses to start without `REEFLEX_CONNECTOR_TOKEN`** (exit 2,
  with the reason). Anything that can reach its port can propose actions in the
  name of any org in the tenancy map, so an accidental open port is a worse
  default than a container that will not start. Set
  `REEFLEX_CONNECTOR_ALLOW_ANONYMOUS=1` if you have decided otherwise.
* **Nothing in this path reads your prompts.** The connector receives the
  assistant's tool calls and the model name; it does not score, mask or store
  prose, and there is no LLM anywhere in the decision path.
* **The ledger is a volume.** Without the `reeflex-ledger` mount, the
  connector's decision records are discarded when the container is recreated.
* **Evidence push is optional and per-tenant.** Configure it in the tenancy map
  under each tenant's `evidence` block, with credentials **by reference** —
  every key ending `_env` is the NAME of an environment variable. A map
  carrying a token is refused at load.
