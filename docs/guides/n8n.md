---
title: "Govern n8n agents with Reeflex: n8n AI governance, zero-code"
description: >-
  Add AI governance to an n8n agent node with built-in HTTP Request, Switch,
  and Wait nodes, or the dedicated n8n-nodes-reeflex node — no custom code
  required.
---

# Govern your n8n agents (zero-code)

You do not need to install anything to put Reeflex in front of an n8n
workflow. reeflex-core exposes one plain HTTP endpoint
(`POST /v1/decide`) and one outbound webhook (`hold.created` /
`hold.resolved`). Both compose with n8n's built-in **HTTP Request**,
**Switch**, and **Wait** nodes. This guide builds that flow with zero
custom code. If you would rather use a dedicated node, see the
[`n8n-nodes-reeflex`](https://github.com/Reeflex-io/reeflex/blob/main/n8n-nodes-reeflex/README.md) package - it wraps
exactly the same call.

This guide assumes reeflex-core is reachable from your n8n instance and,
for the human-in-the-loop leg, that n8n is reachable from reeflex-core (for
the `hold.created` webhook). See
[`../../reeflex-core/README.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/README.md) for how to
run reeflex-core and its environment variables.

## 1. Ask for a decision before the risky step

Before the node in your workflow that performs the actual action (deleting
a record, sending an email, issuing a refund, etc.), add an **HTTP Request**
node configured as follows:

- **Method:** `POST`
- **URL:** `{{$env.REEFLEX_CORE_URL}}/v1/decide` (or hardcode your Core URL)
- **Authentication:** Generic Credential Type -> Header Auth, with
  `Authorization: Bearer <your REEFLEX_AUTH_TOKEN>` (skip this if the
  server has auth disabled)
- **Send Body:** JSON, with a body matching the Action Envelope
  (`reeflex-spec/SPEC.md` SS2). A minimal example:

```json
{
  "reeflex_version": "0.1",
  "agent": {
    "id": "agent:n8n",
    "on_behalf_of": null,
    "session_id": "={{$execution.id}}"
  },
  "action": {
    "namespace": "crm",
    "verb": "delete",
    "ability": "crm/delete-contact"
  },
  "target": {
    "kind": "contact",
    "ref": "={{$json.contactId}}",
    "environment": "production"
  },
  "params": {},
  "magnitude": {
    "count": 1
  },
  "axes": {
    "reversibility": "recoverable",
    "blast_radius": "single",
    "externality": "internal"
  },
  "approval": {
    "present": false,
    "hold_id": null
  },
  "trajectory_ref": null,
  "context": {},
  "meta": {
    "timestamp": "={{$now.toISO()}}",
    "nonce": "={{$execution.id + '-' + $itemIndex}}",
    "signature": "ed25519:stub:n8n-http-request"
  }
}
```

Fill in `action`, `target`, and `axes` to describe your actual action
truthfully - see SPEC SS3 and SS4 for the verb and axis vocabularies. A
stable `agent.session_id` is required (SPEC SS4.1, fragmentation
resistance): reuse the same value across every decision call in one
workflow run, for example `={{$execution.id}}`.

The response is a Decision object (SPEC SS5):

```json
{
  "decision": "allow",
  "reason": "no high-risk axis matched",
  "rule": "reeflex.policy/default_allow",
  "obligations": [],
  "modulation": null
}
```

## 2. Branch on the verdict

Add a **Switch** node right after the HTTP Request node, routing on
`{{$json.decision}}`:

- `allow` -> continue to the node that performs the real action.
- `require_approval` -> go to step 3 (the human-in-the-loop branch).
- `deny` (or anything else / a request error) -> stop the workflow, notify
  someone, or route to a rejection path. **Never treat a failed HTTP
  Request node (core unreachable) as `allow`.** Reeflex's Adapter Contract
  (SPEC SS6) requires failing closed - configure the HTTP Request node's
  error output (or "Continue On Fail") to route to the same place as
  `deny`, not to the `allow` path.

## 3. The human-in-the-loop branch (Wait node + hold webhook)

When the verdict is `require_approval`, the `/v1/decide` response also
carries `hold_id` and `expires_ts` (reeflex-core README, "Holds and
human-in-the-loop"). Nobody has approved anything yet - the action must not
run.

1. Add a **Wait** node in **Webhook** mode. n8n gives you a resume URL for
   this specific execution.
2. Configure reeflex-core's outbound hold webhook to call that URL:
   set `REEFLEX_WEBHOOK_URL` on the reeflex-core server to your n8n Wait
   node's webhook URL (reeflex-core README, "Outbound hold webhook"). Note
   that this webhook is global to the reeflex-core instance and fires for
   every hold, not scoped to one execution - for a shared core instance, use
   an intermediate small webhook receiver that looks up the right waiting
   execution by `hold_id`, or run one Wait/webhook workflow per
   long-lived session. This is exactly why the dedicated
   `n8n-nodes-reeflex` package exists as the next step up from this
   zero-code guide.
3. A human (or your own resolution tooling) approves or rejects the hold by
   calling `POST /v1/holds/{hold_id}/resolve` on reeflex-core directly (see
   the reeflex-core README, "Holds API"). This can be a Slack action, a
   ticketing system webhook, or a second n8n workflow with its own HTTP
   Request node.
4. Once resolved, the `hold.resolved` webhook event (or your own polling
   with an HTTP Request node against `GET /v1/holds/{id}`) resumes the
   Wait node.
5. **Re-submit the exact same envelope** to `POST /v1/decide`, this time
   with `approval.present = true` and `approval.hold_id` set to the
   `hold_id` from step 1's response. Keep `action`, `axes`, `magnitude`,
   and `target` byte-identical to the original submission - core hashes
   exactly those fields and denies a resubmission whose action changed
   (SPEC SS5.1, "hash binding"). If approved, core returns `allow`; only
   then does your workflow perform the real action.
6. If the resolution was `rejected`, or the hold has since expired
   (`REEFLEX_HOLD_TTL_SECONDS`, default 4 hours), the resubmission returns
   `deny` with a machine-readable reason code (`reeflex_hold_not_approved`,
   `reeflex_hold_expired`, etc. - see the reeflex-core README's "Approval
   principals" / reason-code table). Route those to the same rejection path
   as a normal `deny`.

## Why this is "zero code"

Every step above is a built-in n8n node (HTTP Request, Switch, Wait) and
plain JSON. No custom package, no TypeScript, no npm install. The tradeoff
is that you build and maintain the envelope JSON and the resubmission logic
in your own workflow. If you find yourself copy-pasting this pattern across
many workflows, install `n8n-nodes-reeflex` instead - it is the same call,
packaged as one node with three outputs (Allowed / Held for Approval /
Denied) so you do not have to hand-build the envelope or the Switch node
every time. It does not, by itself, replace steps 3-5 above: resubmission
after a human approval is still your workflow's responsibility either way
(reeflex-core never executes actions - see SPEC SS5.1, "Adapter
responsibility on approval").
