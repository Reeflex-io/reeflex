# A destructive tool call, held at the gateway, released by a human

A LiteLLM proxy in front of a model. An agent behind it asks for
`DROP TABLE customers` on production. The proxy hands back a refusal instead of
the tool call, a hold appears in an approval inbox, a person approves it, and
the agent's call is released — because a policy engine said `allow`, not
because the hold said `approved`.

Everything here runs on one machine. One prompt, six steps, two DENY variants,
about two minutes.

```bash
./bootstrap.sh     # once — installs a LiteLLM proxy and pulls one container
./run.sh           # the walk
```

The full transcript of the run we recorded is in
[`evidence/transcript.txt`](evidence/transcript.txt), with a screenshot per
step in [`evidence/shots/`](evidence/shots/). If your run disagrees with ours,
ours is wrong: tell us.

---

## Read this before you read the transcript

Three things about this demo are narrower than they look, and knowing which is
which is the difference between evaluating the product and evaluating a
screenshot.

### 1. The gateway sees a tool call PROPOSED. It does not prevent an execution.

The only moment a gateway can see an action is when the model's answer comes
back, and at that moment nothing has run. So what happens in step 2 is that the
instruction is **deleted from the response the caller receives** and a
structured refusal takes its place. On the wire: `tool_calls: null`,
`finish_reason: "stop"`, and the command string is not in the response bytes at
all — `run.sh` searches the whole document for it, not just the `tool_calls`
field.

An application that kept its own copy of the model's answer, or that reads the
refusal and runs the tool anyway, is **not stopped**. Nothing at a gateway can
stop it. If you need the action blocked at the moment it runs, you need a seat
at the execution point too.

Every record this seat writes says so, in fields rather than in prose:

```json
{"enforcement_stage": "refused_at_gateway",
 "observed": "proposal",
 "prevents_execution": false}
```

### 2. Two different things produce a hold, and only one is the gate reading the action

`run.sh` prints this table by making the calls:

| tool call | verdict | rule |
|---|---|---|
| `run_shell {"command": "ls -la"}` | **allow** | `read_only_internal` |
| `run_shell {"command": "psql -h prod-db -c \"SELECT count(*) FROM customers\""}` | **allow** | `read_only_internal` |
| `run_shell {"command": "psql -h prod-db -c \"DROP TABLE customers\""}` | **hold** | `irreversible_broad_prod` |
| `run_shell {"command": "rm -rf ./build"}` | **hold** | `irreversible_broad_prod` |
| `run_shell {"command": "rm -rf /var/lib/pgsql"}` | **deny** | `irreversible_systemic_prod` |
| `run_sql {"query": "DROP TABLE customers"}` | **hold** | `irreversible_broad_prod` |
| `drop_table {"table": "customers"}` | **hold** | `irreversible_broad_prod` |
| `ping {"host": "example.com"}` | **hold** | `irreversible_broad_prod` |
| `get_weather {"city": "Bucharest"}` | **hold** | `irreversible_broad_prod` |

Read the two halves separately.

**The first half is real discrimination.** Same tool, same host, same session:
`SELECT` is allowed and `DROP TABLE` is held. `run_shell` carries a command
string, so the gateway maps it to the classifier's `Bash` tool and the
classifier prices **the actual command** — `danger_signature:
sql_drop_table`, `classification_tier: destructive_broad` in the held
envelope. Widen the blast radius from one database to the filesystem and the
same seat *denies* instead of holding.

**The second half is fail-to-human, not comprehension.** `run_sql`,
`drop_table`, `ping` and `get_weather` are tools this gateway has no faithful
mapping for. An unmapped tool goes to the classifier under its own gateway
name, which is the unknown-tool path, and comes back `require_approval`. That
is a good default — it is not allowed and it is not silently denied — but
`ping` holds for exactly the same reason `run_sql` does, and `ping` is
harmless. The last two rows are in the demo **as controls**, so nobody reads
the `run_sql` row as "Reeflex understood the SQL". It didn't. It understood
that it didn't understand.

If your tools are called something else, declare them:
`REEFLEX_LITELLM_TOOL_MAP='{"acme_infra_runner": "Bash"}'`. Re-read per call,
no restart.

### 3. There is no LLM in the decision path, and that is a limit as well as a property

The verdict comes from OPA/Rego plus classic logic inside `reeflex-core`. It
cannot reason about intent, tone or novel phrasing; it prices an action on
three declared axes — reversibility, blast radius, externality. The seat is
also blind to prose by construction: it reads `tool_calls` and nothing else,
not the system prompt, not the user's message, not the assistant's text. A
response with no tool calls is returned byte for byte unchanged and is never
sent to the policy engine.

Text-layer guardrails — PII detection, prompt-injection filtering, content
policy — do a different job and this package does not do it. Run them
alongside; LiteLLM composes guardrails.

---

## What the walk does, step by step

### Step 0 — what it is running against

Printed, so nothing about the run is ambient:

* `reeflex-core` **v0.2.0**, pinned by digest
  `sha256:58a0a531dfa1aa9bdfaf82baf94c4a1388303520cae755ffbbe1a28d9e64845b`,
  not by tag. The same published image `api-dev.reeflex.io` runs (compared by
  `RepoDigests` on both hosts).
* **`REEFLEX_REQUIRE_VERIFIED_APPROVER` is deliberately not set**, so it takes
  its shipped default, `true`. A demo that turned that guard off would be
  demonstrating a configuration we do not ship.
* LiteLLM **1.100.0**, pinned. Every number below was recorded against it.
* The classifier from **this checkout**, and the walk *asserts* that: the
  `reeflex-claude` wheel on PyPI is 0.1.7 (uploaded 2026-07-06), which predates
  a classifier fix, and with it `echo starting && rm -rf /var/lib/pgsql` is
  priced reversible/single and core **allows** it.
* The tenancy map, validated by `reeflex-litellm tenancy` before any traffic. A
  misconfigured map is a total refusal at runtime, so the walk turns it into a
  non-zero exit first.

### Step 1 — one prompt

```
Clean up the old customer table on prod.
TOOL run_shell {"command": "psql -h prod-db -c \"DROP TABLE customers\""}
```

The model is a local mock that returns the tool calls you name in the prompt.
That is deliberate: the thing being demonstrated is the gateway, and a real
model makes the one variable that matters — which tool call comes back —
nondeterministic, so a red run could always be the model changing its mind.
Point the proxy at any OpenAI-compatible model and the seat behaves
identically; what a mock cannot prove is that every real provider's tool-call
shape normalizes correctly, which is what `reeflex-litellm normalize` is for.

### Step 2 — the gateway returns a HOLD instead of the tool call

```
tool_calls:    None        <- the model proposed one; the caller got none
finish_reason: 'stop'
error:   reeflex_hold_timeout
rule:    reeflex.policy/irreversible_broad_prod
stage:   refused_at_gateway
hold_id: e1ca09cc5f294cf88a6fabaa23963876
```

This arm of the demo runs a proxy configured `reeflex_hold_wait: 2`, so the
response is withheld for two seconds and then refused **naming the still-open
hold**. Nothing is consumed; the hold waits for a human.

The hold in `reeflex-core` carries the whole envelope, and two fields in it are
worth stopping on:

```
agent.id:    agent:litellm-gateway/acme-payments/mock-tools
session_id:  litellm:acme-payments:demo-step2-1788856606
```

The department (`acme-payments`) is in the **actor identity**, not in a label
beside it. That is what makes one department's approval unspendable by
another's agent — core binds an approval to the actor — and what stops two
teams that both call their nightly job `nightly` from sharing one cumulative
budget.

### Step 3 — the hold in the approval inbox

`evidence/shots/step3-holds-inbox.png` is `app.reeflex.io/app/holds` on a
tenant created for this walk. The card reads:

```
delete · litellm-gateway · 1 item · production
raised 2026-09-08 08:28 UTC        3 hours left to decide
gate litellm-gateway-demo · requested by agent agent:litellm-gateway/acme-payments/mock-tools
rule reeflex.policy/irreversible_broad_prod — irreversible broad change in production requires human approval
[ ✓ Approve ]   [ Deny… ]
```

**What is NOT on that card, and it is the honest answer to a question you may
have been about to ask.** The `gateway_routing` block — which model answered,
which deployment, the `api_base` host, whether the endpoint is declared on-prem
or cloud, which key or team called — is **not** in the inbox and **not** in an
Attest report. `EVIDENCE-INGEST-SPEC-v1` §4, the schema the evidence feed is
validated against, has no field for it and the contract is frozen; an adapter
may not change a wire contract with deployed gates. That block lives in the
adapter's own decision ledger (`REEFLEX_LITELLM_LEDGER_PATH`), which step 6
prints in full. The one adapter-controlled identity field that *does* reach the
report is `agent_id`, which is why the card can name the department, the
gateway and the model at all.

There is also a field on the ledger line that exists purely to stop a report
over-reading this step:

```
hold_announced: "sent"
```

`sent` means the hold reached an inbox. `failed` means we tried and the inbox
was unreachable. `not_configured` means no inbox is wired up at all — the hold
exists in the policy engine and nobody was told. A report that counted all
three as "human oversight was exercised" would be making the Article 14
overclaim in miniature, so the fact is recorded rather than assumed.

### Steps 4 and 5 — a person approves, and the call is released

One request, blocked at a proxy configured `reeflex_hold_wait: 180`. While it
is blocked:

1. a real browser loads `/app/holds`, finds **this hold's own card** (matched
   on `id="hold-<hold_id>"`, not on page text) and clicks Approve;
2. a relay carries the decision from the app to `reeflex-core`;
3. the gateway's poll sees `approved`, resubmits the **original** envelope with
   the approval attached, and core answers `allow`;
4. the still-open HTTP request returns — carrying the tool call.

```
tool_calls:    [{"function": {"arguments": "{\"command\": \"psql -h prod-db -c
                 \\\"DROP TABLE customers\\\"\"}", "name": "run_shell"}, ...}]
finish_reason: 'tool_calls'
```

The gateway does not release on the hold's status. Core's eight resubmission
checks are the authority — one of them exists because a hold id by itself was
once enough to spend somebody else's approval.

Three guards are proven in the transcript rather than asserted:

| probe | result |
|---|---|
| the approver's credential on `POST /v1/decide` | **401** — an approver credential is not a key to submitting actions |
| approving as `bob.somebody@…` on alice's credential | **403 `principal_mismatch`** — *"a caller may only approve as itself"* |
| the correct approval | **200**, `decided_by_verified: true`, `principal_source` from the credential |

#### 5b — the limit: an approval that arrives late cannot be spent

Measured by `lib/late_approval.py`, printed in the transcript:

1. the agent asks → refused, hold **H1**;
2. a human approves **H1**, after the wait window closed;
3. the agent retries → refused, hold **H2**, a *different* hold.

H1 stays `approved`, `consumed_ts: null` — a real human decision that nothing
will ever spend. The release only ever happens **inside one request**: there is
no way for a caller to hand an already-approved hold id back to the gateway,
and the policy engine raises a new hold on every `require_approval`.

Nothing is released by accident, which is the fail-closed half. But it means
"a human in an inbox" and the shipped 30-second default wait are not
compatible: either the operator raises the wait to something a person can
answer inside — holding an HTTP request open for minutes — or a held call is
refused and has to be re-asked after the approval, which starts a new hold.
This is a real trade and it is open work, not a detail.

### Step 6 — the record, and exactly what it may not claim

The walk prints the adapter's ledger table for the whole run, then the full
ledger line for the released call, then projects that same line onto the
evidence wire and shows what is missing. The negative result is the point, so
it is produced by **running** the projection:

* on the ledger: `enforcement_stage`, `observed`, `prevents_execution`,
  `gateway_routing`, `hold_id`, `hold_announced`;
* on the §4 wire: `decision_id`, `verdict`, `rule`, `envelope_hash`,
  `occurred_ts`, `action.{verb,target_system,target_environment}`,
  `magnitude.count`, `agent_id`, `hold.hold_id`, `sig_alg`. **And nothing
  else.**

So, stated plainly: **an Attest report built from the evidence feed alone
cannot distinguish a gateway refusal from an execution-side prevention.** It
does not claim `prevented_at_execution` — correctly, because nothing here
prevented an execution — and it cannot state `refused_at_gateway` either, so it
states neither. Closing that needs a spec change, which is filed and is not an
adapter's to make.

Two guards are exercised in front of you:

* adding `enforcement_stage` to the wire record raises before the request —
  the projection is a closed allowlist that re-checks its own output;
* `assert_never_claims_prevention("prevented_at_execution")` raises, so this
  package cannot emit that stage even by mistake.

#### The auditor's report, and the disagreement it surfaces

With a tenant configured, the walk generates the report on the web plane —
`/app/attest`, two dates, one button — downloads it as JSON into
`evidence/shots/step6-attest-report.json`, and prints what is and is not in it.

The row for this walk's decision now carries the human:

```
hold 36423764  resolution="approved"  decided_by=human:alice.approver@acme.example
```

That was `resolution: null, decided_by_id: null` until this round. The gateway
recorded that a hold existed and never that anyone resolved it, so the whole
Article 14 finding rested on Reeflex's *own* records — the audited party
attested nothing about its own oversight. The seat now sends the approver
`reeflex-core` verified against the approving credential.

**And the first thing that produced is a reported contradiction, which is the
correct outcome and worth understanding before you see it:**

```
ART14_APPROVER_CONTRADICTED (medium)
  Both sources agree this production hold was approved, but not on WHO decided
  it: the gate's evidence names human:alice.approver@acme.example, Reeflex's
  own record names human:eee6c19a-a783-4fc1-9205-400a1475f5a4. The Art.14
  allocation of oversight is to the principal Reeflex recorded.
```

The same person, named two ways. The gateway sends the identity the policy
engine verified against the credential; the application stores its internal
per-user id. The report does not pick a winner quietly — it reports the
disagreement and attributes oversight to its own record. That is the
application-side gap the relay section below describes, seen from the reporting
end, and it is open work. Until it closes, every approved gateway hold carries
that medium-severity gap.

Two numbers that this did **not** change, called out because they are easy to
misread:

* `human_resolved` was already correct — it is computed from Reeflex's own
  hold-resolution rows, not from the evidence feed;
* `of_those_a_human_decided` is 0 before and after, also correctly: it counts
  holds raised because the action was *unclassifiable*, and this seat declares
  every field that rule reads, so it raises none (see DENY variant B).

### DENY variant A — a hard deny the model can read

`rm -rf /var/lib/pgsql` is `deny reeflex.policy/irreversible_systemic_prod` —
not held; refused even with approval. The caller gets the tool call removed and
this in `message.content`:

```json
{"reeflex": {"version": 1, "refused": [{
  "error": "reeflex_denied",
  "rule": "reeflex.policy/irreversible_systemic_prod",
  "reason": "Reeflex: irreversible systemic change in production is not allowed even with approval [rule=…]",
  "tool_call_id": "call_0_…",
  "tool": "run_shell",
  "stage": "refused_at_gateway"}]}}
```

That is a **structured** result on purpose: the model reads it on its next turn
and can say so or propose something narrower, instead of retrying the same
refused call in a loop.

### DENY variant B — unclassifiable resolves to a HOLD, not a deny

The same action, decided twice, differing in one field:

| envelope | decision | rule |
|---|---|---|
| all three axes declared | **deny** | `irreversible_systemic_prod` |
| `axes.reversibility` omitted | **require_approval** | `unclassified_action` |

> *"this action could not be classified: axes.reversibility was not declared by
> the adapter and core used its conservative default, so the verdict rests on a
> guess — a human decides"*

The unclassified rule outranks the terminal deny, and unlike the deny it is
resolvable. A terminal refusal is the right answer for an action an adapter
declared and the wrong one for an action the engine guessed at.

**And this gateway seat cannot reach it.** It declares all three axes,
`action.verb`, `magnitude.count` and `target.environment` on every call, so
every envelope it sends reads `provenance.undeclared: []` — printed from the
walk's own holds. `provenance` is computed by core from what is absent and
overwritten unconditionally, so a caller cannot assert its way from the deny
into the hold either. The rule is a guard for adapters that omit a field; this
one does not.

### Control — the same envelopes against a core this walk did not configure

The three decisive envelopes are re-decided against `api-dev.reeflex.io`, the
shared Reeflex evaluation endpoint, with the published public eval token. All
three agree. So no verdict in the transcript is a property of the container the
walk started.

**Why the approval steps are not run there**, since it is the obvious question:
that deployment has `REEFLEX_REQUIRE_VERIFIED_APPROVER=true` and **no**
`REEFLEX_RESOLVER_TOKENS` and no config mount, so on core 0.2.0 every
`POST /v1/holds/{id}/resolve` there returns `403 principal_not_verified` — for
anyone. That is not a defect: a shared evaluation endpoint has no business
holding a credential bound to a named human. It does mean an approval can only
be walked against a core whose operator has bound one, which is what the walk
starts.

---

## What you need, and what you do not

**Nothing but Docker, Python 3.12 and network access** for steps 1, 2, 5, 6 and
both DENY variants. No Reeflex account, no API key, no real model.

**Steps 3 and 4 need a Reeflex tenant with a registered gate**, because they
write into a real approval inbox and click a real button in it. Two environment
variables switch them on:

```bash
export RFX_DEMO_GATE_TOKEN=…      # rfx_gate_… from gate registration
export RFX_DEMO_EVIDENCE_KEY=…    # the derived 32-byte signing key, hex
./run.sh
```

Without them **the walk still runs** and prints, in the transcript, that steps
3 and 4 were NOT RUN and why. It substitutes an approval through the policy
engine's own resolution route — with the approver's own bound credential, and
with both refusal controls above — so step 5 is still a real approval by a
verified principal; it just is not a person clicking a button. Nothing is
faked to cover the gap, and there are no staged screenshots in
`evidence/shots/`: every image is a headless Chromium render of the live
application at that moment in the run.

If you want a tenant to try it against, mail `hello@reeflex.io`.

---

## The pieces, and where each one lives

```
your agent ──► LiteLLM proxy ──► the model
                    │
                    │  post-call hook: one Action Envelope per tool call
                    ▼
              reeflex-core /v1/decide          ← the verdict. OPA/Rego, no LLM.
                    │  require_approval
                    ├──────────────► the hold lives here (the authority)
                    │
                    └──► POST /api/v1/holds ──► the approval inbox (a person)
                                                        │  Approve
                              the relay ◄───────────────┘
                                  │
                                  └──► POST /v1/holds/{id}/resolve
```

| file | what it is |
|---|---|
| `bootstrap.sh` | one-time: a venv with LiteLLM, the two Reeflex packages from this checkout, and the core image by digest |
| `stack.sh` | `up` / `down` / `status` for the four processes. Generates three separate credentials per run, mode 600, never echoed |
| `run.sh` | the walk |
| `config/tenancy.json` | which Reeflex org a gateway caller belongs to. Credentials **by reference** — env var *names*, never values |
| `config/litellm-impatient.yaml` | the seat with `reeflex_hold_wait: 2` — produces the readable HOLD |
| `config/litellm-patient.yaml` | the seat with `reeflex_hold_wait: 180` — releases after an approval |
| `lib/approve_in_ui.py` | the browser walk: enrolment through a CDP virtual authenticator, then the Approve click |
| `lib/relay.py` | app → core. Sixty lines of what the product connector does, with the two known blockers configured around (see below) |
| `lib/discrimination.py` | the allow/hold/deny table above, including the two controls |
| `lib/r0.py` · `lib/late_approval.py` · `lib/wire_truth.py` | the three measurements the demo would be dishonest without |
| `lib/apidev_control.py` | the shared-core control |
| `lib/attest.py` | generates the auditor's report on the web plane and reads what is and is not in it |

### About that relay

The hold lives in **two** places: the policy engine holds it (and is the
authority on releasing it), the application **shows** it (and is where a person
can decide). Something has to carry the decision from the second to the first.
In the product that is the holds connector.

**On core 0.2.0 the shipped connector cannot do it**, and this is measured, not
suspected: it authenticates with the engine's single shared token — which
cannot be bound to N approvers — and it relays the application's internal
per-user UUID rather than the identity a resolver credential is bound to. Both
produce `403`, the hold stays pending, and the agent's resubmission is
`deny reeflex_hold_not_approved`. The application then tells the truth about
it: the hold reads `resolution_failed` and a report raises
`ART14_RESOLUTION_REFUSED_BY_CORE` — *human oversight was exercised and did not
take effect*. That is open work.

So `lib/relay.py` is in `demo/` and not in a package, and it differs from the
connector in exactly two ways, both of them things a real deployment must also
do: it presents **the approver's own** credential, and it is configured with an
explicit `decided_by.id → principal` map. It **refuses to relay** a decision it
cannot map, rather than guessing an approver — inventing an approver is the
defect that verified approvers exist to close.

Also measured, and the reason that map cannot simply be dropped: a resolve with
no `principal` at all, with only `type`, or with only `id` is
`400 invalid_request`. A relay cannot decline to assert an identity and let the
credential speak for itself.

---

## Known gaps in what this demo shows

Kept in one list so none of them has to be inferred from a silence.

1. **This walk is buffered only; `stream: true` is governed, elsewhere.** When
   this demo was written the seat implemented the buffered post-call hook and
   nothing else, and the same `rm -rf /` that is refused on the buffered path
   reached the caller intact as stream deltas. RFX-242 closed that: the
   guardrail also implements `async_post_call_streaming_iterator_hook`, and the
   assembled calls are decided by the same `enforce.rule_one_call()`, in the
   same order, as the buffered path. **Every request in this walk is buffered**,
   so nothing in this transcript is evidence about the streamed path — that
   evidence is `reeflex-litellm/proxy/stream_walk.py`, which asserts on raw
   `text/event-stream` bytes.
2. **An approval that arrives after the wait window is unspendable** (step 5b).
3. **The evidence feed cannot carry the enforcement stage or the routing
   block**, so a report cannot distinguish a gateway refusal from an
   execution-side prevention (step 6).
4. **The app→core relay here is not the shipped connector** (above).
5. **An unmapped tool holds regardless of what it does** (point 2 at the top).
6. **The model is a mock.** It proves the seat; it does not prove that every
   real provider's tool-call shape normalizes correctly.
7. **Every approved gateway hold currently carries a medium-severity
   `ART14_APPROVER_CONTRADICTED` gap** in the report, because the two halves of
   the chain name the same human differently (step 6). Open work, on the
   application side.
8. **`gateway_routing.deployment_id` is derived from the deployment's API
   key.** LiteLLM computes it as a digest whose preimage includes `api_key`
   for a config-declared deployment with no explicit id (measured on 1.100.0).
   It is not a secret and no credential value is recorded — but it changes when
   you rotate the key, so do not join on it across a rotation, and give the
   deployment an explicit `model_info.id` in the proxy config if you would
   rather it were not key-derived at all.
9. **The walk creates state.** Holds in the policy engine's store under the run
   directory, and — with the app leg on — evidence rows and pending holds in
   your tenant. `./stack.sh down` stops the processes and removes the
   container; it deliberately leaves the run directory so you can read the
   ledger and the audit log afterwards.

## One operator trap worth knowing before you deploy anything

The published core image runs as uid `10001`. If its data volume is not
writable by that uid, the **audit log degrades with a warning and keeps
answering** — audit failure is not a denial — but the **hold store fails
closed**, so every `require_approval` comes back as
`deny reeflex.core/hold_store_unavailable`. A misconfigured volume silently
converts every human-approval action in your deployment into a refusal.
`stack.sh` sets the ownership; this paragraph exists because it did not, once,
and the symptom read like a policy problem.
