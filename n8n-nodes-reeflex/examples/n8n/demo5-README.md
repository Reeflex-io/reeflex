# Demo 5 — Watch Before You Enforce (observe posture)

**Teaches:** "observe" is a **workflow posture** — a deliberate wiring
choice in the n8n workflow, not a mode `reeflex-core` itself has. The gate
still returns a real verdict every time; what changes is what the workflow
does with it afterwards.

File: [`demo5-watch-before-you-enforce.workflow.json`](./demo5-watch-before-you-enforce.workflow.json)

## Setup

See the top-level [README.md](./README.md) → "Credential setup" for the
exact 3 values (Core URL / API Token / Ignore SSL Issues) and the 2-minute
import steps.

> Disclaimer: Eval token for api-dev.reeflex.io — dev endpoint, staging
> cert (set verify_ssl=false / Ignore SSL Issues on), may reset anytime; not
> for production.

## The story

Two sample actions, each built to trip a different high-risk rule if this
workflow were wired to enforce:

| Row | Table | Axes | Would-be verdict (enforce posture) |
|---|---|---|---|
| 1 | `customers` | irreversible / broad / production | `require_approval` (R2) — would **HOLD** |
| 2 | `core_schema` | irreversible / systemic / production | `deny` (R3) — would be a **terminal DENY** |

Both items go through the SAME Reeflex Gate node and get the SAME real
verdicts they would get in any other demo — `reeflex-core` has no idea this
workflow is "observing." What makes this "observe" is entirely downstream:

- The **Held for Approval** output routes to an "Audit: would-be HOLD
  logged" node instead of a Wait/notify node.
- The **Denied** output routes to an "Audit: would-be DENY logged" node
  instead of a terminal alert.
- **Both audit nodes, and the Allowed output directly, all converge on the
  same "Proceed" node** — the workflow runs the action regardless of what
  the verdict was.

This is the standard dry-run / shadow-mode pattern for safely rolling out a
new policy pack or a stricter axis assignment: you get the real signal
(what WOULD have been blocked, and why — `reeflex.reason` / `reeflex.rule`
are still fully populated on every item) logged for review, with zero risk
of the workflow itself stalling in production while you evaluate it.

## Relationship to reeflex-core / reeflex-wordpress "observe" concepts

`reeflex-core` itself does not have a server-side "observe" decision mode —
every `/v1/decide` call in this demo is a normal, real call, not a mock.
(The WordPress adapter has its own, separate `REEFLEX_MODE` constant that
toggles an observe/enforce posture at the adapter level — that is a
resource-side adapter concept, unrelated to this n8n workflow-level
pattern; see `reeflex-wordpress` for that.) This demo shows the same idea
implemented purely as n8n wiring: any source-side adapter (n8n included)
can build an observe posture just by choosing what its Held/Denied outputs
connect to.

## Expected result when you run it

- **Allowed**: empty for these two sample rows (both are deliberately
  high-risk).
- **Held for Approval**: 1 item (`customers`) → logged → proceeds.
- **Denied**: 1 item (`core_schema`) → logged → proceeds.
- **Both items reach the final "Proceed" node** regardless of branch.

## Honesty note

This demo is fully live and works exactly as described against the shared
api-dev endpoint — the verdicts are real, only the workflow's reaction to
them differs from an enforce-posture demo (contrast with
[demo1](./demo1-README.md), where the Held branch stops instead of
proceeding).

## GIF (filmed at T7)

*(placeholder — no GIF yet)*

**How to film:** import into a local n8n (Docker), attach the credential,
click "Execute workflow" once.

**What you'll see:** two items entering Reeflex Gate, one routing through
"Audit: would-be HOLD logged" and one through "Audit: would-be DENY
logged" — then BOTH arrows converging into the same "Proceed" node at the
end, visually making the point that the workflow never actually stopped for
either would-be-blocked action, only logged what would have happened.
