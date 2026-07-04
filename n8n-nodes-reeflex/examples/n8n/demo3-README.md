# Demo 3 — The Approval Loop

**Teaches:** the full human-in-the-loop cycle end to end — decide → HOLD
(`hold_id` returned) → resolve the hold → resubmit the SAME envelope with
approval → allow.

File: [`demo3-the-approval-loop.workflow.json`](./demo3-the-approval-loop.workflow.json)

## Setup

See the top-level [README.md](./README.md) → "Credential setup" for the
exact 3 values (Core URL / API Token / Ignore SSL Issues) and the 2-minute
import steps. **This demo also needs the credential attached to the two
HTTP Request nodes** ("Resolve hold" and "Resubmit to /v1/decide"), not just
the Reeflex Gate node — they use the same "Reeflex Core API" credential via
n8n's **Authentication: Predefined Credential Type → Reeflex API**, so
`{{$credentials.coreUrl}}` resolves inside those nodes too and no URL/token
is duplicated in the workflow.

> Disclaimer: Eval token for api-dev.reeflex.io — dev endpoint, staging
> cert (set verify_ssl=false / Ignore SSL Issues on), may reset anytime; not
> for production.

## The story

1. A sample action (`wordpress/bulk-delete-posts`, 25 posts, irreversible +
   broad + production) is deliberately built to trip R2 every time — this
   demo is about what happens AFTER a hold exists, not about whether one
   gets created (see [demo1](./demo1-README.md) for that).
2. **Reeflex Gate** returns `require_approval` with `hold_id` and
   `expires_ts`. The item on the "Held for Approval" output also carries
   `reeflex.envelope` — the exact envelope that was sent, unmodified.
3. **Resolve hold (automation principal)** — an HTTP Request node POSTs
   `/v1/holds/{hold_id}/resolve` with:
   ```json
   { "decision": "approve", "principal": { "type": "automation", "id": "n8n-demo3-approval-loop" }, "reason": "approved via n8n demo3 - the approval loop" }
   ```
   `automation` is one of three principal types core recognizes (human /
   agent / automation — see `reeflex-core/README.md`, "Approval
   principals"). This step records the approval; it does **not** re-run the
   guarded action.
4. **Resubmit to /v1/decide** — a second HTTP Request node reuses
   `reeflex.envelope` from the Reeflex Gate node verbatim (spreads it, then
   sets `approval.present = true` and `approval.hold_id`). `action`, `axes`,
   `magnitude`, and `target` stay byte-identical to the original, because
   core's hash binding is computed over exactly those fields
   (`reeflex-core/README.md`, "The hash binding") — a resubmission with a
   modified action would come back `deny` with
   `reeflex_hold_envelope_mismatch`.
5. **Resubmission approved?** (IF node) — checks `decision == "allow"`
   before treating the loop as successful. Never assume; always check.

## Expected result when you run it

- First `/v1/decide` call: `require_approval`, `hold_id` present.
- Resolve call: HTTP 200, hold `status: "approved"`.
- Second `/v1/decide` call: `allow`.
- Final branch: "Execute the delete now (ALLOWED after approval)".

## Honesty note — what's real vs. documented-only

This entire loop (steps 1–5 above) is **fully live and works exactly as
described against the shared api-dev endpoint** — nothing here is
simulated.

**Not implemented in this JSON, documented here instead:** the
**webhook-trigger variant**. `reeflex-core` can push a `hold.created`
webhook to `REEFLEX_WEBHOOK_URL` the moment a hold is created, so instead of
this workflow calling `/v1/holds/{id}/resolve` itself, a *separate*
n8n workflow with a **Webhook** trigger node could receive that event and
drive the approval UI (Slack button, ticketing system, etc. — see
[`../../docs/guides/n8n.md`](../../docs/guides/n8n.md), section 3, and
`reeflex-core/README.md`, "Outbound hold webhook"). This is **not** the
default here for one concrete reason: `REEFLEX_WEBHOOK_URL` is a single,
global setting on the core server, and it fires for **every** hold on that
instance, not scoped to one importer's execution. On a shared,
multi-tenant endpoint like api-dev, there is no way to route that one
global webhook to *your* n8n instance without an intermediate receiver that
looks up the right waiting execution by `hold_id` — exactly the situation
`docs/guides/n8n.md` calls out as "exactly why the dedicated
`n8n-nodes-reeflex` package exists as the next step up from this zero-code
guide." If you run your **own** `reeflex-core` instance, set
`REEFLEX_WEBHOOK_URL` to an n8n **Wait node's** webhook URL (Webhook mode)
and you get the fully event-driven variant — no polling, no manual "Resolve
hold" HTTP call needed on your side (a human resolving the hold externally,
e.g. via Slack, triggers the webhook directly). This variant is not filmed
in the T7 GIF plan for this repo (it needs a dedicated core instance to
demonstrate correctly); the automation-principal HTTP-based loop above is
what gets filmed, since it is what genuinely works against api-dev.

## GIF (filmed at T7)

*(placeholder — no GIF yet)*

**How to film:** import into a local n8n (Docker), attach the credential to
all 3 nodes that need it (Reeflex Gate + 2 HTTP Request nodes), click
"Execute workflow" once, and let it run end to end (4 sequential HTTP
calls: decide, resolve, resubmit, then the IF).

**What you'll see:** the item passing through Held → Resolve hold →
Resubmit → the IF node routing to "Execute the delete now (ALLOWED after
approval)" — open the "Resubmit to /v1/decide" node's output panel to show
`decision: "allow"` where the first call had returned
`decision: "require_approval"` for the exact same underlying action.
