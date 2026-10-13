---
title: "Use case: outbound communications and payments"
description: >-
  An agent that sends email, posts messages, issues refunds or pays invoices.
  How the external_sends and money budgets catch a run of individually small
  actions, and what they do not catch.
---

# Outbound communications and payments

## The situation

A support or finance team lets an agent act on customers' behalf: reply to
tickets by email, post in a shared channel, issue refunds, pay supplier
invoices. Every one of those effects leaves your systems — a sent email cannot
be recalled, a payout cannot be un-sent.

## What goes wrong without a gate

Each action is small and each one is plausible. The failure is the run: a
loop that replies to the same ticket queue twice emails every customer twice;
a refund policy misread as "refund anything under €2,000" is fine for one
ticket and is €40,000 by the end of the afternoon. Nothing per-call is over a
threshold, so a per-call check passes all of it. This is the structuring
pattern banks have watched for in payments for decades — split one large move
into many small ones.

## Three representative actions

**One customer reply.** Outbound, irreversible (sent is sent), single. Allowed
— and counted toward the session's `external_sends` budget.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:support", "session_id": "sess-support-5520" },
  "action":    { "namespace": "mail", "verb": "emit", "ability": "email/send" },
  "target":    { "kind": "mailbox", "ref": "customer:83311", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "outbound" },
  "approval":  { "present": false }
}
```

**The 51st send in one session.** `external_sends` defaults to 50 per session.
The 51st outbound action — of any kind: email, chat post, webhook — is held for
a person, who sees the session's history and decides whether the run is the job
or a loop.

**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget` · **call** 51 · **reason contains** `external_sends` — sends 1–50 are this same envelope, each allowed.

```json
{
  "agent":     { "id": "agent:support", "session_id": "sess-support-5521" },
  "action":    { "namespace": "mail", "verb": "emit", "ability": "email/send" },
  "target":    { "kind": "mailbox", "ref": "customer:83311", "environment": "production" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "outbound" },
  "approval":  { "present": false }
}
```

**The third €1,800 refund.** The `money` budget is per currency (EUR 5,000 by
default) and reads `params.amount` and `params.currency` from whatever verb
carries them. Two refunds of €1,800 are €3,600; the third would take the
session to €5,400, and is held.

**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget` · **call** 3 · **reason contains** `money` — refunds 1–2 are this same envelope, each allowed.

```json
{
  "agent":     { "id": "agent:support", "session_id": "sess-support-5522" },
  "action":    { "namespace": "payments", "verb": "transact", "ability": "refunds/create" },
  "target":    { "kind": "charge", "ref": "charge:ch_3Q0x", "environment": "production" },
  "params":    { "amount": 1800, "currency": "EUR" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "single", "externality": "outbound" },
  "approval":  { "present": false }
}
```

Mixed currencies do not escape it: the budget sums each currency's *share of its
own limit*, so €4,999 and $4,999 in one session is 1.9 budgets, not two
half-used ones. No exchange rate is involved. The per-currency limits in
`budgets.rego` are illustrative defaults an operator must review.

## How to deploy it

Whichever adapter carries the agent's tools — [reeflex-mcp](../mcp-gateway.md)
for MCP tools, the [n8n node](../guides/n8n.md) for workflow steps,
[the LiteLLM connector](../guides/litellm-docker.md) for a gateway fleet. The
lines that matter are two: the send/pay tools declared
`externality: outbound`, and the payment tools passing the amount as
`params.amount` with an ISO 4217 `params.currency`. The limits themselves are
in `budgets.rego`; see the [policy guide](../policy-guide.md#2-level-1-change-a-threshold).

## What Reeflex does NOT do here

- It does not read the email. Whether a reply is rude, wrong, or leaks a
  customer's data is content; Reeflex prices the act of sending, not what is
  sent.
- It does not know an amount the adapter did not pass. A payment tool whose
  amount is not mapped to `params.amount` is charged nothing against the money
  budget.
- It does not track across sessions. The ledger is per session over a rolling
  window (3,600 s by default); an agent that opens a new session per refund
  starts each one at zero.
- It does not hold the first refund of €4,000. One action under the limit, in
  a fresh session, is allowed; the budget is about the run, not the single
  payment. A per-action ceiling is a rule you add.
