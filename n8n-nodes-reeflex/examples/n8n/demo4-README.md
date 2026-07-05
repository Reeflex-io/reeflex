# Demo 4 — Nothing Gets Through (terminal deny)

**Teaches:** some actions are not "a bigger version of a holdable action" —
they are a different category entirely. `irreversible + systemic +
production` is a **terminal deny**: no hold, no `hold_id`, no principal that
can ever approve it.

File: [`demo4-nothing-gets-through.workflow.json`](./demo4-nothing-gets-through.workflow.json)

## Setup

See the top-level [README.md](./README.md) → "Credential setup" for the
exact 3 values (Core URL / API Token / Ignore SSL Issues) and the 2-minute
import steps.

> Disclaimer: Eval token for api-dev.reeflex.io — dev endpoint,
> rate-limited, may reset anytime; not for production.

## The story

A single sample action: `postgres/drop-schema`, `count = 1`,
`reversibility = irreversible`, `blastRadius = systemic`,
`environment = production`. `count` is deliberately 1 — R3
(`reeflex.policy/irreversible_systemic_prod`,
`reeflex-core/policy/reeflex.rego`) does not look at magnitude at all, only
the axes. A single `DROP SCHEMA` is exactly as systemic as a thousand-row
wipe of the same schema.

`reeflex-core` returns `decision: "deny"` directly — **no `hold_id`, no
`expires_ts` are ever attached to this response**, because core never
creates a hold for this rule in the first place (`reeflex-core/README.md`:
"`irreversible_systemic_prod` is resolvable by no principal — its deny is
terminal"). There is nothing downstream to resolve, by design: unlike R2
(demo 1/3) or R5 (demo 2), this rule has no approval path at all, for any
principal type (human, agent, or automation).

## Expected result when you run it

- **Denied** output: 1 item, `rule: "reeflex.policy/irreversible_systemic_prod"`,
  `reason: "irreversible systemic change in production is not allowed even
  with approval"`.
- **Allowed** / **Held for Approval**: empty (wired for robustness only).

## Honesty note — what's real vs. needs a local core

**The terminal-deny half of this demo is fully live and works exactly as
described against the shared api-dev endpoint** — nothing here is
simulated.

**Not demonstrated here, on purpose:** the **freeze / kill-switch** half of
the "nothing gets through" story. `reeflex-core` has an operator-side
environment variable, `REEFLEX_FREEZE`, which — when set to `true` — makes
*every* non-read verb deny immediately with reason `"frozen by operator"`
(`reeflex-core/README.md`, "Kill-switch / freeze"). This is genuinely a
different, stronger form of "nothing gets through" than R3 (it applies to
*all* actions, not just systemic ones), but it is set on the **core
server's environment**, re-read on every request, hot-reloadable without a
restart. An importer of this n8n workflow has no way to flip that variable
on the shared, operator-run api-dev endpoint — doing so would freeze the
endpoint for every other person currently trying these demos. **This is
deliberately NOT faked in the workflow JSON.** There is no node in this
demo pretending to simulate a freeze; the JSON only demonstrates the R3
terminal-deny path, which is real.

To see the freeze behavior for real: run your own `reeflex-core` instance
(see `../../reeflex-core/README.md`), set `REEFLEX_FREEZE=true`, and point
this same workflow's credential at your instance instead of api-dev — any
non-read action (including one that would otherwise be a plain `allow`)
will come back denied with `rule: "reeflex.policy/frozen"`. **This is what
gets filmed at T7 against a local core**, not against api-dev.

## GIF (filmed at T7)

*(placeholder — no GIF yet)*

**This demo needs a local core to fully film (see above).** Plan:

1. **Segment A (against api-dev, as imported):** click "Execute workflow"
   once, show the single item landing on "Denied", open its data panel to
   show `rule: "reeflex.policy/irreversible_systemic_prod"` and the absence
   of any `hold_id` field (contrast this against demo 3's Held item, which
   has one).
2. **Segment B (against a local core, `REEFLEX_FREEZE=true`):** re-run the
   SAME workflow (credential repointed at `http://127.0.0.1:8080` or
   similar) and show a DIFFERENT, less severe action (e.g. demo1's
   `stale_carts` row, which normally comes back Allowed) now also landing
   on Denied, with `rule: "reeflex.policy/frozen"` — the freeze applies to
   everything, not just the systemic case.
