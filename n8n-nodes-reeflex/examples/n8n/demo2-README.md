# Demo 2 — Fragmentation Doesn't Work

**Teaches:** splitting one big delete into many small calls under the SAME
session does not evade governance — `reeflex-core` accumulates cumulative
state **per session**, not per call (SPEC §4.1, "fragmentation resistance").

File: [`demo2-fragmentation-doesnt-work.workflow.json`](./demo2-fragmentation-doesnt-work.workflow.json)

## Setup

See the top-level [README.md](./README.md) → "Credential setup" for the
exact 3 values (Core URL / API Token / Ignore SSL Issues) and the 2-minute
import steps.

> Disclaimer: Eval token for api-dev.reeflex.io — dev endpoint,
> rate-limited, may reset anytime; not for production.

## The story

A "Code" node generates a **session id ONCE**, at random (so importing this
demo does not collide with anyone else running it against the shared
api-dev endpoint), and bakes it identically into 10 items — each describing
a `delete count=5` call with axes that deliberately do NOT trip R2
(`recoverable` / `single` / `production`, not `irreversible`/`broad`), so
this demo isolates R5 alone.

A **Loop Over Items** node (n8n's standard `splitInBatches`, batch size 1)
feeds these 10 items one at a time into the same Reeflex Gate node, which
therefore calls `POST /v1/decide` 10 times, in order, all with the same
`agent.session_id`.

`reeflex-core`'s policy pack
(`reeflex-core/policy/reeflex.rego`) has a `delete_session_budget` of **20**.
Rule R5 fires when `prior_deletes + this_call's count > 20`. With 5 per
call:

| Call | Prior deletes (this session) | This call | Total | R5 fires? | Verdict |
|---|---|---|---|---|---|
| 1 | 0 | 5 | 5 | no | Allowed |
| 2 | 5 | 5 | 10 | no | Allowed |
| 3 | 10 | 5 | 15 | no | Allowed |
| 4 | 15 | 5 | 20 | no (20 is not > 20) | Allowed |
| 5 | 20 | 5 | 25 | **yes** | **Held** |
| 6–10 | 25, 30, ... | 5 | 30, 35, ... | yes | Held |

**The point:** `reeflex-core` appends every decided action to the session
ledger AFTER evaluation, regardless of whether the verdict was allow, deny,
or hold (`reeflex-core/app/decide.py`, "Step 10: Append to session ledger
AFTER eval" — unconditional). So even the calls that got held still count
toward the budget for the next call. An agent cannot "reset" the budget by
staying under a per-call threshold; the cost is tracked across the whole
session, exactly as designed to defeat this exact bypass attempt.

## Expected result when you run it

- Calls 1–4: route to **Allowed**.
- Calls 5–10: route to **Held for Approval**, rule
  `reeflex.policy/session_delete_budget`.
- **Denied**: empty (wired for robustness only).
- The "Loop finished" node fires once at the end.

## Honesty note

This demo is fully live and works exactly as described against the shared
api-dev endpoint. The random session-id suffix is not cosmetic — it is what
lets many people run this same demo concurrently against one shared core
without polluting each other's budget.

## GIF (filmed at T7)

*(placeholder — no GIF yet)*

**How to film:** import into a local n8n (Docker), attach the credential,
click "Execute workflow" once, and let the loop run to completion (it will
make 10 sequential HTTP calls — expect a couple of seconds).

**What you'll see:** the Loop Over Items node's iteration counter climbing
1→10; the Reeflex Gate node's output lighting up "Allowed" for the first 4
iterations, then visibly flipping to "Held for Approval" from iteration 5
onward and staying there — the flip, live, on one unbroken session.
