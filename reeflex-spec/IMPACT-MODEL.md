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
  "count_by_verb":        { "delete": 47, "transact": 2 },
  "count_by_ability":     { "wordpress/delete-post": 47 },
  "count_by_externality": { "outbound": 12 },
  "amount_by_currency":   { "EUR": 480.00 },
  "total_count": 61,
  "sum_physical_envelope": 0.42
}
```

The core is the only component that sees every action in a session, so it — not
the adapter — computes this. The adapter's only extra duty is to supply a stable
`session_id`. This is how "delete 5, one hundred times" trips the same budget as
"delete 500": fragmentation buys nothing. `count_by_externality` and
`total_count` aggregate regardless of verb/ability — the basis for R5's
configurable, cross-cutting budgets below.

**Physical impact (SPEC §4.5, RFX-427).** `sum_physical_envelope` is the summed
`magnitude.physical.envelope_fraction` of the session's prior actions — how far
the session has already moved the plant, in units of the declared safe ranges
(1.0 = one full-range sweep). It has the same window and the same
prior-actions-only semantics as every other aggregate here; it is summed with
`math.fsum`, so ten declared steps of 0.1 add up to exactly 1.0. Physical
*writes* need no new aggregate: the five physical verbs (`set`, `mode`,
`override`, `actuate`, `flash`) are canonical only on an envelope declared
`externality: physical`, so `count_by_verb` for those five already counts
physical writes and nothing else. This is how "40 setpoint steps of 3 %, each
inside its range, together a full sweep" trips a budget that no single step
does.

> **Deliberate strictness:** once a session has exceeded a cumulative
> budget, the base policy holds *every* subsequent action from that
> session — including reads — until it is approved or the rolling window
> (default 3600 s) expires (the excess alone already exceeds the limit,
> whatever the next action contributes). The posture is "a session that
> tried to fragment is a suspicious session." If you are testing
> repeatedly, use a fresh `session_id` per run (the `reeflex-verify` tool
> does this for you). Narrowing the post-budget hold to destructive verbs
> only is an open policy decision; either way, you can tune or replace
> R5 in your own Rego pack.

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

# Any configured cumulative dimension (money / deletions / external_sends /
# objects_touched / physical_writes / physical_envelope — budgets.rego)
# exceeded its budget → require approval.
budget_require_approval if {
    count(exceeded_dimensions) > 0
    not input.approval.present
}

# R8: a physical override of, or write to, a safety function, in production
# or staging → deny (even with approval).
r8_safety_function_override if {
    input.axes.externality == "physical"
    input.target.environment in {"production", "staging"}
    input.target.safety_function == true
    input.action.verb in {"set", "update", "delete", "flash", "mode"}
}
```

For physical impact the policy reads four more inputs, all declared by the
adapter: the verb (one of the five physical verbs), `target.safety_function`,
`magnitude.physical.envelope_fraction`, and `axes.externality == "physical"`,
which arms every one of R8–R11 and which core never guesses (its default for a
missing externality is `outbound`). R8 and R10a deny in production and staging
(staging, for a plant, is a HIL rig with real actuators); R9 and R11 hold in
production; none of them arms in `dev`, the digital twin. The full table and
the precedence are SPEC §4.5.

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

No industry standard exists yet for governing agent *actions* — the category is too new. But none of these rules is invented from thin air: each applies a decades-old safety principle to a new domain. Here is the base pack **exactly as it ships** (R1–R5 in [`reeflex.rego`](../reeflex-core/policy/reeflex.rego) + [`budgets.rego`](../reeflex-core/policy/budgets.rego)), and the discipline each rule descends from:

| Base rule (as it ships) | What it decides | Rooted in |
|---|---|---|
| **R1** · read-only → *allow* | reversible reads pass untouched | reversibility-first — a read is not a risk |
| **R2** · irreversible + broad, in production → *require approval* | a high-risk change waits for a human | change management / ITIL — a change-advisory board at machine speed |
| **R3** · irreversible + systemic, in production → *deny* | catastrophic actions are refused, not waved through | safety engineering (aviation, nuclear) — past a severity line you re-scope, you don't approve |
| **R4** · default → *allow* | govern by exception, not by blanket block | least astonishment / default-permit |
| **R5** · configurable cumulative budgets (deletions / money / external\_sends / objects\_touched) → *require approval* | split-up actions are caught together, the way banks have watched structured transactions for 50 years — generalized from one hardcoded verb (deletions) to budgets a policy author writes as data, aggregated across *heterogeneous* verbs/abilities, with `objects_touched` weighing every action so no small-tier action is exempt from accumulating | fraud-detection velocity checks (structuring / "smurfing") — extended past a payments-only, zero-weighted-small-tier cumulative check |
| **R8** · physical override of, or write to, a safety function, in production or staging → *deny* | an agent's override of, or write to, a target its adapter declared a safety function is refused, approved or not | functional safety (IEC 61508, ISO 13849) — a safety function is changed through the plant's own management-of-change procedure, not through the control channel it protects |
| **R10a** · physical request outside the declared safe range, in production or staging → *deny* | a setpoint past the operating envelope is refused | operating envelopes / safe operating limits in process safety |
| **R9** · irreversible physical actuation or firmware / logic load, in production → *require approval* | dosing, cutting, a PLC program download waits for a human | permit-to-work and management of change for control-system changes |
| **R11** · operating-mode change on a live plant → *require approval* | auto↔manual, bypass, arm/disarm, start/stop a unit waits for a human | mode-change procedures and shift handover in plant operations |
| **R10b** · physical budgets (`physical_writes`, `physical_envelope`) → *require approval* | many small in-range steps that add up to a full sweep reach a human | the same structuring logic as R5, measured in fractions of the safe range |
| **The three axes** · reversibility × blast radius × externality | severity × scope × reversibility, scored on every action | classic risk assessment — and the same axes make **egress control** (externality) and **transaction thresholds** (magnitude) expressible as ready extension packs |

New rules for a new domain; old, proven principles underneath.

---

## What the base policy does not catch

Honesty over promises. The base policy governs structural, destructive impact — it is not a claim to catch every possible harm. Known limits:

- **Exfiltration through reads.** A read is read / reversible / internal, so R1 alone would allow any volume of it — but every read still counts toward `objects_touched` (R5), so a mass-read run now hits a session budget rather than passing unbounded; a *dedicated* mass-read guard tuned to the actual sensitivity of reads is still a natural data-protection pack candidate, not part of the base policy.
- **Semantic damage.** One product set to the wrong price is single / reversible → allowed. Content *correctness* is not an impact axis.
- **Slow-burn abuse across sessions.** The cumulative ledger is per-session over a rolling window; rotating sessions dilutes it.

**Physical / human-safety impact (R8–R11, RFX-427).** What this does NOT claim:

- Reeflex is **not a safety system** and must never be described as one. Safety functions are SIL-rated hardware / safety-PLC logic (IEC 61508, ISO 13849). Reeflex is a defence-in-depth layer **above** the safety PLC, at the agent boundary: it decides whether the agent may **issue** the command. The SIS stays the last line.
- **Supervisory level only.** Setpoints, modes, recipes, firmware, missions — not the control loop (milliseconds).
- **Verdict ≠ outcome.** Reeflex records the decision and the *declared* magnitude; it does not read sensors. Attest says so, as it does for IT evidence (received vs occurred).
- `envelope_fraction` and `safety_function` are the **adapter's** declarations. A wrong safe range in a mapping is a wrong verdict — mapping files are controlled documents, and the docs say so.

The axes are universal; the base rules are a strong start, not a ceiling. The policy is plain Rego — read it in a minute, extend it in an afternoon.

---

*Reeflex — a seatbelt for the AI acting on your systems.*
