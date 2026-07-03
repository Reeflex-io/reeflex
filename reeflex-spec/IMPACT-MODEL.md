# How Reeflex Computes Impact

> Companion to [SPEC.md](./SPEC.md). This document explains **how an action's
> impact is calculated** so that a deterministic policy can decide on it. If you
> have ever wondered whether "computed impact" is a real mechanism or just a
> slogan, this is the answer: it is a plain, reproducible classification — no LLM,
> no black-box score.

---

## The short version

Impact is not a single number a model dreams up. It is a **three-layer,
deterministic reading** of what an action *is* and how much it *touches*:

1. **Per-action classification** (in the adapter) — read the raw action, derive
   the three axes + a magnitude from explicit rules.
2. **Cumulative state** (in the core) — add up what the session has already done.
3. **The verdict** (in the policy) — read axes + cumulative, apply thresholds.

The same action, in the same session state, always reads the same way. That is
the whole point.

---

## Layer 1 — Per-action classification (the adapter)

This is where "impact" is first computed. The adapter looks at the raw action and
produces the [Action Envelope](./SPEC.md#2-the-action-envelope): a verb, a
magnitude (`count`), and the three axes (`reversibility`, `blast_radius`,
`externality`).

The rules are **explicit and read from the structure of the action** — not
inferred by a model. Two reference adapters implement this today:

### Claude Code adapter (`reeflex-claude/reeflex_claude/classify.py`, Python)

Classifies shell / SQL / file operations. A few of the real rules:

| Raw action | verb | reversibility | blast_radius |
|---|---|---|---|
| `ls`, `cat`, `git status` | read | reversible | single |
| `rm file.txt` | delete | irreversible | single |
| `rm -rf somedir` | delete | irreversible | broad |
| `rm -rf /` (or `$HOME`, system dirs) | delete | irreversible | **systemic** |
| `DROP TABLE orders` | delete | irreversible | broad |
| `DROP DATABASE` | delete | irreversible | **systemic** |
| `DELETE FROM t` (no `WHERE`) | delete | irreversible | broad |
| `git push --force` | emit | irreversible | broad (outbound) |
| `Write` to an existing file | create | irreversible (overwrite) | single |
| `Write` to `.env` / secrets / prod config | create | irreversible | broad |

The verb comes from **intent, not tool name**: the same `Bash` tool is `read`,
`delete`, `emit`, or `execute` depending on the leading command. Magnitude comes
from counting (e.g. the number of file arguments to `rm`).

### WordPress adapter (`reeflex-wordpress/reeflex-gate/class-reeflex-normalizer.php`, PHP)

Classifies WordPress ability calls. The verb is derived from the ability name
**most-dangerous-first** (so `fetch-and-delete-posts` resolves to `delete`, not
`read`), and the axes follow:

| Ability + input | verb | reversibility | blast_radius |
|---|---|---|---|
| `core/get-post` | read | reversible | single |
| `core/delete-post` `{ids:[42]}` (trash) | delete | recoverable | single |
| `core/delete-post` 25 ids | delete | irreversible (bulk ≥ 20) | broad |
| `core/delete-post` `{force_delete:true}` | delete | irreversible | broad |
| `core/delete-site-wide-data` | delete | irreversible | **systemic** |
| `core/publish-*`, `send-*`, `email-*` | emit | irreversible | outbound |

### The one rule that matters most

**Agent-supplied input may only raise risk, never lower it.** If an axis or count
is missing or non-canonical, it is coerced to the **most-restrictive** value —
never silently allowed. A forged approval flag in the input is stripped and
ignored. This is what makes the classification safe even when the agent is
adversarial: the worst an attacker can do by lying is make their own action look
*more* dangerous, never less.

---

## Layer 2 — Cumulative state (the core)

A per-action check is gameable: "require approval when `count > 5`" is defeated by
deleting 5 at a time, ten times. So before evaluating policy, `reeflex-core`
computes a **cumulative** object from the session's prior actions over a rolling
window (`reeflex-core/app/ledger.py`):

```jsonc
"cumulative": {
  "window_seconds": 3600,
  "count_by_verb":      { "delete": 47, "transact": 2 },
  "count_by_ability":   { "wordpress/delete-post": 47 },
  "amount_by_currency": { "EUR": 480.00 }
}
```

The core is the only component that sees every action in a session, so it — not
the adapter — computes this. The adapter's only extra duty is to supply a stable
`session_id`. This is how "delete 5, one hundred times" trips the same budget as
"delete 500": fragmentation buys nothing.

> **Deliberate strictness:** once a session has exceeded its
> delete budget, the base policy holds *every* subsequent action from that
> session — including reads — until it is approved or the rolling window
> (default 3600 s) expires. The posture is "a session that tried to fragment
> is a suspicious session." If you are testing repeatedly, use a fresh
> `session_id` per run (the `reeflex-verify` tool does this for you).
> Narrowing the post-budget hold to destructive verbs only is an open policy
> decision; either way, you can tune or replace R5 in your own Rego pack.

---

## Layer 3 — The verdict (the policy)

The policy does **not** re-measure impact. It reads the axes + cumulative that
layers 1–2 produced and applies thresholds (`reeflex-core/policy/reeflex.rego`):

```rego
# Irreversible + systemic + production → deny (even with approval).
r3_deny if {
    input.axes.reversibility == "irreversible"
    input.axes.blast_radius  == "systemic"
    input.target.environment == "production"
}

# Session delete budget → require approval (fragmentation guard).
r5_require_approval_budget if {
    prior := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
    prior + input.magnitude.count > 20
    not input.approval.present
}
```

Same envelope + same cumulative → same decision, every time. No LLM in this path.

---

## The honest part: structure vs. real magnitude

There are **two kinds of "compute"**, and they differ in reliability. We are
candid about both because it determines where Reeflex is strongest.

**1. From the structure of the action — solid today.**
Verb, whether a `WHERE` clause is present, an `-r` flag, the number of arguments,
the ability name. All of this is read directly and deterministically. Both
reference adapters do this and are conformance-tested.

**2. Real magnitude — reliable only at the resource.**
"How many rows will this `DELETE ... WHERE status='old'` actually hit?" is **not
in the command text.** Determining it requires asking the resource itself (e.g. a
plan estimate / `EXPLAIN` before executing). This is precisely why the resource
boundary matters:

- **At the resource** (e.g. the database wire-proxy), Reeflex can measure the true
  magnitude and the agent cannot lie about it.
- **At the source** (an SDK call), you depend on what the agent declares — and a
  compromised agent can under-declare `count` to dodge a threshold. Reeflex
  mitigates this with conservative defaults (missing `count` → 1, but bulk/`-all`
  signals in the action name force `broad` regardless of a declared count), but
  the guarantee is strongest where the impact is *measured*, not *declared*.

**This is the core argument for governing at the resource:** it is the only place
real impact can be computed rather than trusted.

---

## Summary

| Question | Answer |
|---|---|
| Is impact an AI guess? | No. Deterministic rules read from the action's structure. |
| Where is it computed? | Layer 1 in the adapter (axes + magnitude); layer 2 in the core (cumulative). |
| Can an agent game it? | Input can only raise risk, never lower it. Cumulative defeats fragmentation. |
| What's the hard part? | Real row-count magnitude — reliable only at the resource, which is why we govern there. |
| Is it built? | Yes, in two reference adapters (Claude Code, WordPress). Database/GraphQL magnitude is the next adapter surface. |

---

## Where these rules come from

No industry standard exists yet for governing agent *actions* — the category is too new. But none of these rules is invented from thin air: each is a decades-old safety principle applied to a new domain.

| Rule | Established principle | Where it comes from |
|---|---|---|
| R1 — high-risk changes require approval | Change-advisory board (CAB) at machine speed | Change management / ITIL |
| R2 — catastrophic actions are not approved, they are re-scoped | Actions beyond a severity threshold cannot be waved through | Safety engineering (aviation, nuclear) |
| R3 — what leaves the system gets checked; there is no unsend | Outbound data is inspected before egress | DLP / egress control |
| R4 — above a threshold, a second signature | Large transactions require a second authorisation | Transaction thresholds (finance) |
| R5 — split-up transactions are caught; agents fragment deletes the same way banks have watched for 50 years | Structuring / "smurfing" detection on velocity | Fraud-detection velocity checks |
| The axes (reversibility × blast radius × externality) | Severity × scope × reversibility | Classic risk assessment |

New rules for a new domain; old, proven principles underneath.

---

## What the base policy does not catch

Honesty over promises. The base policy governs structural, destructive impact — it is not a claim to catch every possible harm. Known limits:

- **Exfiltration through reads.** 10,000 customer-record reads classify as read / reversible / internal → allowed. A mass-read guard is a natural data-protection pack candidate, not part of the base policy.
- **Semantic damage.** One product set to the wrong price is single / reversible → allowed. Content *correctness* is not an impact axis.
- **Slow-burn abuse across sessions.** The cumulative ledger is per-session over a rolling window; rotating sessions dilutes it.

The axes are universal; the base rules are a strong start, not a ceiling. The policy is plain Rego — read it in a minute, extend it in an afternoon.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
