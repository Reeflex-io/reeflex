# Demo 1 — Bulk Delete Guard (real risk, not row count)

**Teaches:** one **Reeflex Gate** node routes two bulk-delete requests to
two different verdicts because they carry two different **risk axes** —
not because one has more rows than the other.

File: [`demo1-bulk-delete-guard.workflow.json`](./demo1-bulk-delete-guard.workflow.json)

## Setup

See the top-level [README.md](./README.md) → "Credential setup" for the
exact 3 values (Core URL / API Token / Ignore SSL Issues) and the 2-minute
import steps. This demo needs only the one "Reeflex Core API" credential.

> Disclaimer: Eval token for api-dev.reeflex.io — dev endpoint, staging
> cert (set verify_ssl=false / Ignore SSL Issues on), may reset anytime; not
> for production.

## The story

A "Code" node produces two sample bulk-delete requests, standing in for two
real upstream queries:

| Row | Table | Count | Reversibility | Blast radius | Environment | Expected verdict |
|---|---|---|---|---|---|---|
| 1 | `stale_carts` | 3 | recoverable | single | production | **Allowed** |
| 2 | `customers` | 50 | irreversible | broad | production | **Held for Approval** |

Both items flow through the SAME Reeflex Gate node (one gate call per
item). Row 1 is a small, soft-deletable cleanup — low risk on every axis, so
`reeflex-core`'s default-allow rule (`reeflex.policy/default_allow`, or R1 if
you widen it to a read) applies. Row 2 is a large hard delete of a live
production table — `irreversible + broad + production` trips R2
(`reeflex.policy/irreversible_broad_prod`, `reeflex-core/policy/reeflex.rego`),
which holds it for a human regardless of how many rows are actually in the
table.

**The point:** `count` (the Action Envelope's `magnitude.count`) is not what
R2 keys on at all — only the three axes are. A 3-row hard delete of the same
production table with `irreversible`/`broad` axes would ALSO be held; a
50-row soft-deletable cleanup with `recoverable`/`single` axes would ALSO be
allowed. Describe the action honestly and the gate routes it correctly, no
matter the count.

## Expected result when you run it

- **Allowed** output: 1 item (`stale_carts`).
- **Held for Approval** output: 1 item (`customers`) — carries
  `reeflex.hold_id` and `reeflex.expires_ts`. This demo stops here; it does
  not resolve the hold. See [demo3-the-approval-loop](./demo3-README.md) for
  what happens next.
- **Denied** output: empty (wired for robustness only).

## Honesty note

This demo is fully live and works exactly as described against the shared
api-dev endpoint — no local core needed, nothing simulated.

## GIF (filmed at T7)

*(placeholder — no GIF yet)*

**How to film:** import this workflow into a local n8n (Docker), attach the
credential, click "Execute workflow" once, and capture the canvas showing
both output branches lighting up with their item counts (1 and 1).

**What you'll see:** a single click producing two pinned/highlighted
outputs — the top ("Allowed") branch lit for the `stale_carts` row, the
middle ("Held for Approval") branch lit for the `customers` row — with the
item data panel open on each to show the different axis values side by
side.
