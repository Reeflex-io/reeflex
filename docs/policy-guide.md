# Adapt Reeflex to your use case

The entire decision policy that `reeflex-core` evaluates is **one Rego file**:
[`reeflex-core/policy/reeflex.rego`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/policy/reeflex.rego), backed by
one test file, [`reeflex-core/policy/reeflex_test.rego`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/policy/reeflex_test.rego).
There is no plugin API, no DSL, no hidden config layer — you read the rules,
you edit the rules, `opa test` tells you whether you broke anything. That file
IS the product's decision surface. This guide shows three levels of change,
from smallest to largest, **with every example verified against a real `opa
test` run** before it went into this document (see the raw output inline
below — this guide does not ask you to trust an unverified snippet).

Nothing in this guide requires touching `reeflex-core`'s Python. The engine
(`app/opa.py`) only ever asks OPA one question — `data.reeflex.policy.decision`
— and returns whatever comes back. Change the policy, not the engine.

---

## 1. How it works (short version)

Every request to `POST /v1/decide` carries an Action Envelope (3 risk axes +
verb + target + magnitude + cumulative state). The base policy evaluates five
rules (R1–R5) against those fields and returns exactly one `decision` object:
`allow`, `deny`, or `require_approval`. Precedence is explicit and total —
**deny > require_approval > allow** — so for any input exactly one Rego block
matches and no two rules can disagree.

> **Environment matters.** R2 and R3 are gated on `production`. In `dev`,
> `staging`, or any other environment, an irreversible / broad / systemic
> action is **not** held or denied by R2/R3 — only R1 (read allow), R5 (delete
> budget), and R4 (default allow) apply. Set `target.environment` accordingly;
> the stricter behavior is intentional for production only.
>
> You can also define your **own** environments: the policy matches
> `target.environment` as a plain string, so you can gate rules on any names
> you use (e.g. `prod-eu`, `critical`) by editing `reeflex.rego` — with zero
> core changes.

This guide does not re-derive the axis model or the five shipped rules — see:

- [`docs/why-reeflex.md`](why-reeflex.md) — why the model looks like this, HITL/HOTL/AIL.
- [`reeflex-spec/IMPACT-MODEL.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/IMPACT-MODEL.md) — how impact is computed, layer by layer, and what the base policy deliberately does not catch (its closing section already names the mass-read guard used as this document's LEVEL 2 example).
- [`reeflex-spec/SPEC.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md) §2–§5 — the full Action Envelope and Decision contracts.

What matters for this guide is just the shape of the file you're about to
edit: a handful of `<rule>_allow` / `<rule>_deny` / `<rule>_require_approval`
**predicates**, and a handful of `decision := {...} if { ... }` **complete-rule
blocks**, each guarded by `not <higher-precedence predicate>` so that exactly
one block's body is true for any given envelope.

---

## 2. LEVEL 1 — change a threshold

The smallest possible change: one constant.

**Work in a copy — never edit the checked-in policy in place.** So a mistake
can't dirty the shipped `reeflex-core/policy/` (which must stay
byte-identical), copy the directory once and run every command below against
the copy:

```bash
cp -r reeflex-core/policy my-policy
```

The constant you'll change lives in `my-policy/reeflex.rego`:

```rego
delete_session_budget := 20
```

This is R5's fragmentation-resistance budget (SPEC §4.1): the maximum
cumulative `delete` count allowed in a session before core requires human
approval. Say your risk tolerance is lower and you want that budget at 5,
not 20. Edit the one line:

```rego
delete_session_budget := 5
```

That's the entire code change. But changing a constant is a real behavior
change, and your test suite is the proof of what changed — including tests
you didn't intend to touch. Run the suite against your copy:

```bash
opa test my-policy/ -v
```

**What actually happened when I ran this against the copy** (the shipped
`reeflex-core/policy/` stays untouched): the shipped test
`test_r5_under_budget_allows` uses a fixture tuned to sit under the *old*
budget of 20 (prior deletes = 3, this batch = 5, total = 8 — under 20, over
5). At this point you have only the **nine shipped tests** — the two boundary
tests below aren't added yet — so the count is out of nine:

```
FAILURES
--------------------------------------------------------------------------------
data.reeflex.policy_test.test_r5_under_budget_allows: FAIL (1.0406ms)
  ...
  my-policy/reeflex_test.rego:108   | | Fail got.decision = "allow"
--------------------------------------------------------------------------------
PASS: 8/9
FAIL: 1/9
```

That failure is `opa test` doing its job: total = 8 is now *over* the new
budget of 5, so the fixture's old assumption ("8 is under budget") is no
longer true, and the test correctly says so. **Lowering a shared constant
means re-checking every fixture that was tuned against the old value** — this
is not a bug in `opa test`, it is the reason you run it before deploying.
Fix the fixture to match the new intent ("a small batch under the new budget
still allows"):

```diff
-# R5 UNDER BUDGET: prior deletes = 3, this batch = 5; total = 8 <= 20.
+# R5 UNDER BUDGET: prior deletes = 1, this batch = 2; total = 3 <= 5 (the
+# LOWERED budget).
 test_r5_under_budget_allows if {
 	envelope := {
 		"action": {"verb": "delete"},
 		"target": {"environment": "staging"},
 		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
-		"magnitude": {"count": 5},
-		"cumulative": {"count_by_verb": {"delete": 3}},
+		"magnitude": {"count": 2},
+		"cumulative": {"count_by_verb": {"delete": 1}},
 		"approval": {"present": false},
 	}
 	got := policy.decision with input as envelope
 	got.decision == "allow"
 }
```

Then add a test that proves the new boundary — a batch that trips **5** but
would not have tripped **20**:

```rego
# LEVEL 1 (docs/policy-guide.md): with delete_session_budget lowered to 5, a
# first-call batch of 6 (prior_deletes defaults to 0) now trips the budget —
# it would NOT have tripped the shipped default of 20.
test_lowered_budget_trips_at_six if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 6},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/session_delete_budget"
}

# Sanity: a batch of 5 stays AT the new budget, not over it (5 > 5 is false)
# -> allow. Proves the boundary is ">" not ">=", matching the rule body.
test_lowered_budget_five_is_still_allowed if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal"},
		"magnitude": {"count": 5},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
}
```

Re-run the same command. Raw output, verified against the copy:

```
$ opa test my-policy/ -v
...
data.reeflex.policy_test.test_r1_read_internal_allow: PASS (2.1634ms)
data.reeflex.policy_test.test_r2_irreversible_broad_prod_require_approval: PASS (2.1482ms)
data.reeflex.policy_test.test_r3_irreversible_systemic_prod_deny: PASS (1.5904ms)
data.reeflex.policy_test.test_r4_default_allow: PASS (2.0952ms)
data.reeflex.policy_test.test_precedence_deny_over_require_approval: PASS (1.6273ms)
data.reeflex.policy_test.test_r5_budget_exceeded_triggers_require_approval: PASS (2.1634ms)
data.reeflex.policy_test.test_r5_under_budget_allows: PASS (1.0939ms)
data.reeflex.policy_test.test_r5_budget_exceeded_but_approved_allows: PASS (2.0952ms)
data.reeflex.policy_test.test_r5_absent_cumulative_does_not_crash: PASS (1.0939ms)
data.reeflex.policy_test.test_lowered_budget_trips_at_six: PASS (1.109ms)
data.reeflex.policy_test.test_lowered_budget_five_is_still_allowed: PASS (1.5904ms)
--------------------------------------------------------------------------------
PASS: 11/11
```

Nine original tests plus two new ones, all green, one fixture corrected. That
is the whole workflow for a threshold change.

---

## 3. LEVEL 2 — add a rule end-to-end (the mass-read guard)

This is the crux of the guide: adding a genuinely new rule without breaking
precedence, proven with `opa test` rather than asserted.

### The honest problem this rule solves

`reeflex-spec/IMPACT-MODEL.md` names the mass-read guard as "a natural
extension" that "is not part of the base policy." That framing is slightly
out of date in one important, verifiable way. Look at R5's actual predicate:

```rego
r5_require_approval_budget if {
	prior_deletes := object.get(input, ["cumulative", "count_by_verb", "delete"], 0)
	prior_deletes + input.magnitude.count > delete_session_budget
	not input.approval.present
}
```

**There is no verb guard.** `input.magnitude.count` is added to the prior
delete count *regardless of what verb the current action is*. Verified
directly against the shipped policy:

```bash
$ echo '{"action":{"verb":"read"},"target":{"environment":"production"},
  "axes":{"reversibility":"reversible","blast_radius":"broad","externality":"internal"},
  "magnitude":{"count":5000},"approval":{"present":false}}' \
  | opa eval -d reeflex-core/policy -I --format=pretty "data.reeflex.policy.decision"
{
  "decision": "require_approval",
  "reason": "session delete budget exceeded (fragmentation guard)",
  "rule": "reeflex.policy/session_delete_budget"
}
```

A 5,000-record **read** already comes back `require_approval` — the base
policy is *not* silently allowing mass reads today. But the reason is a lie:
nothing was deleted. An operator reading the audit log sees "delete budget
exceeded" for an action that deleted nothing, which is confusing and will be
mis-triaged. The honest fix is not "add a mass-read guard where none existed"
— it's **give mass reads their own rule id and their own true reason**, and
make sure exactly one `decision` block fires so OPA doesn't choke on two
candidates being true at once.

### The rule

Add a constant, right after `delete_session_budget`:

```rego
# Maximum records a single `read` action may touch before it requires human
# approval — a mass-read / exfiltration guard. Deliberately separate from
# delete_session_budget: reads and deletes are different risks and should
# not share a threshold.
mass_read_budget := 1000
```

Add the predicate, right after `r5_require_approval_budget`:

```rego
# R6 (custom): mass-read guard. R5 has NO verb guard — it adds
# input.magnitude.count for ANY verb, so a large-count `read` already trips
# r5_require_approval_budget under the misleading reason "session delete
# budget exceeded". R6 gives mass reads their own honest rule id and reason;
# precedence below makes R6 win over R5 for reads.
r6_mass_read_guard if {
	input.action.verb == "read"
	input.magnitude.count > mass_read_budget
	not input.approval.present
}
```

### The decision block, and the precedence fix

Add a new `require_approval` block for R6, placed **between R2 and R5** in
file order (R3 deny > R2 > R6 > R5 > R1 > R4):

```rego
# require_approval (R6) — mass-read guard; fires when R3 and R2 do not, and
# takes precedence over R5 for reads (see r6_mass_read_guard comment above).
decision := {
	"decision": "require_approval",
	"reason": "mass read exceeds session read budget (exfiltration guard)",
	"rule": "reeflex.policy/mass_read_guard",
} if {
	r6_mass_read_guard
	not r3_deny
	not r2_require_approval
}
```

Now the part that is easy to get wrong. R5's existing block did **not** know
about R6, so a read with `count = 5000` satisfied *both* the new R6 block
above *and* the existing R5 block below — two candidate values for the same
complete rule. I proved this is a real failure, not a hypothetical, by
running the *unguarded* version through `opa test`:

```
data.reeflex.policy_test.test_r6_mass_read_gets_its_own_rule_not_session_delete_budget: ERROR (1ms)
  reeflex.rego:113: eval_conflict_error: complete rules must not produce multiple outputs
data.reeflex.policy_test.test_r6_boundary_one_over_triggers_mass_read_guard: ERROR (0s)
  reeflex.rego:113: eval_conflict_error: complete rules must not produce multiple outputs
--------------------------------------------------------------------------------
PASS: 14/16
ERROR: 2/16
```

`eval_conflict_error` is OPA refusing to pick a winner between two `decision`
values that are simultaneously true — exactly the "second `decision` value ...
CONFLICT" failure mode this task called out. (Operationally this is not a
silent widen: `reeflex-core`'s `app/opa.py` treats any non-zero OPA exit or
malformed result as `OpaEvalError` and the caller denies — fail-closed holds
even here. But a hard deny on every mass read, with no clear reason, is not
the outcome you want either.) The fix is the one-line precedence guard the
brief specified — add `not r6_mass_read_guard` to the R5 block:

```diff
 decision := {
 	"decision": "require_approval",
 	"reason": "session delete budget exceeded (fragmentation guard)",
 	"rule": "reeflex.policy/session_delete_budget",
 } if {
 	r5_require_approval_budget
 	not r3_deny
 	not r2_require_approval
+	not r6_mass_read_guard
 }
```

And, for full correctness regardless of how the two constants are tuned
relative to each other, the same guard on **both allow blocks** (R1 and R4).
Without it, a deployment that (mis)configures `mass_read_budget` *below*
`delete_session_budget` could hit a read that trips R6 but not R5, which
would otherwise fall through to an allow block that has no idea R6 exists —
the same kind of two-candidate conflict, just reachable from a different
angle:

```diff
 decision := {
 	"decision": "allow",
 	"reason": "read-only internal action",
 	"rule": "reeflex.policy/read_only_internal",
 } if {
 	r1_allow
 	not r2_require_approval
 	not r3_deny
 	not r5_require_approval_budget
+	not r6_mass_read_guard
 }
```

```diff
 decision := {
 	"decision": "allow",
 	"reason": "no high-risk axis matched",
 	"rule": "reeflex.policy/default_allow",
 } if {
 	not r1_allow
 	not r2_require_approval
 	not r3_deny
 	not r5_require_approval_budget
+	not r6_mass_read_guard
 }
```

Total precedence is now `R3 (deny) > R2 > R6 > R5 > R1 > R4`, still total —
every predicate combination lands in exactly one block.

### Tests — precedence proven, not asserted

```rego
# THE CRUX: a mass read (count=5000, internal, no prior deletes) used to
# surface as "session delete budget exceeded" — an honest decision, a
# misleading reason. R6 now gives it its own rule id.
test_r6_mass_read_gets_its_own_rule_not_session_delete_budget if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "reversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 5000},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/mass_read_guard"
}

# BOUNDARY at mass_read_budget itself (1000): not strictly greater, so R6
# does NOT fire — but 1000 is still > delete_session_budget (20), so R5's
# verb-agnostic count check still fires. Honest limit of the fix: reads
# between the two thresholds still carry the older, less precise reason.
test_r6_boundary_at_budget_falls_back_to_r5 if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "reversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 1000},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/session_delete_budget"
}

# One count over the boundary (1001) DOES fire R6.
test_r6_boundary_one_over_triggers_mass_read_guard if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "reversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 1001},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/mass_read_guard"
}

# Approval clears BOTH r5 and r6 -> falls through to R1 (read-only) -> allow.
test_r6_mass_read_with_approval_allows if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "reversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 5000},
		"approval": {"present": true},
	}
	got := policy.decision with input as envelope
	got.decision == "allow"
	got.rule == "reeflex.policy/read_only_internal"
}

# PRECEDENCE: R2 still outranks R6 for a read that also matches R2's axes.
test_r2_outranks_r6_for_qualifying_read if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 5000},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/irreversible_broad_prod"
}

# PRECEDENCE: R3 (deny) still outranks R6.
test_r3_outranks_r6_for_qualifying_read if {
	envelope := {
		"action": {"verb": "read"},
		"target": {"environment": "production"},
		"axes": {"reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal"},
		"magnitude": {"count": 5000},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "deny"
	got.rule == "reeflex.policy/irreversible_systemic_prod"
}

# NON-READ verbs are unaffected: R6 checks verb == "read" explicitly.
test_r6_does_not_fire_for_non_read_verbs if {
	envelope := {
		"action": {"verb": "delete"},
		"target": {"environment": "staging"},
		"axes": {"reversibility": "recoverable", "blast_radius": "broad", "externality": "internal"},
		"magnitude": {"count": 5000},
		"approval": {"present": false},
	}
	got := policy.decision with input as envelope
	got.decision == "require_approval"
	got.rule == "reeflex.policy/session_delete_budget"
}
```

Raw `opa test -v` output, verified in a scratch copy, all 9 original tests
plus 7 new R6 tests, no conflicts:

```
data.reeflex.policy_test.test_r3_irreversible_systemic_prod_deny: PASS (1.1707ms)
data.reeflex.policy_test.test_r5_budget_exceeded_but_approved_allows: PASS (526.7µs)
data.reeflex.policy_test.test_r5_under_budget_allows: PASS (526.7µs)
data.reeflex.policy_test.test_r5_budget_exceeded_triggers_require_approval: PASS (1.6895ms)
data.reeflex.policy_test.test_r6_does_not_fire_for_non_read_verbs: PASS (1.6895ms)
data.reeflex.policy_test.test_r2_irreversible_broad_prod_require_approval: PASS (1.6451ms)
data.reeflex.policy_test.test_r2_outranks_r6_for_qualifying_read: PASS (2.1718ms)
data.reeflex.policy_test.test_r1_read_internal_allow: PASS (2.1501ms)
data.reeflex.policy_test.test_r5_absent_cumulative_does_not_crash: PASS (1.6313ms)
data.reeflex.policy_test.test_r6_mass_read_with_approval_allows: PASS (2.6768ms)
data.reeflex.policy_test.test_r6_boundary_at_budget_falls_back_to_r5: PASS (2.814ms)
data.reeflex.policy_test.test_r4_default_allow: PASS (1.1729ms)
data.reeflex.policy_test.test_r6_boundary_one_over_triggers_mass_read_guard: PASS (1.7685ms)
data.reeflex.policy_test.test_precedence_deny_over_require_approval: PASS (1.1462ms)
data.reeflex.policy_test.test_r6_mass_read_gets_its_own_rule_not_session_delete_budget: PASS (1.1462ms)
data.reeflex.policy_test.test_r3_outranks_r6_for_qualifying_read: PASS (711.2µs)
--------------------------------------------------------------------------------
PASS: 16/16
```

**What this example does NOT claim**: mass reads between `delete_session_budget`
(20) and `mass_read_budget` (1000) still surface under the older
`session_delete_budget` rule id — `test_r6_boundary_at_budget_falls_back_to_r5`
proves that boundary rather than hiding it. Pick your own `mass_read_budget`
deliberately; this guide's `1000` is illustrative, not a recommendation.

---

## 4. LEVEL 3 — replace the whole policy

You are not restricted to editing the shipped file in place. `reeflex-core`
loads the policy directory from an environment variable, read in
[`reeflex-core/app/opa.py`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/app/opa.py):

```python
def _policy_dir() -> str:
    env_dir = os.environ.get("REEFLEX_POLICY_DIR", "")
    if env_dir:
        return env_dir
    # Default: <repo root>/reeflex-core/policy (two levels up from this file)
    here = pathlib.Path(__file__).resolve()
    return str(here.parent.parent / "policy")
```

Every `/v1/decide` call runs `opa eval -d <policy_dir> -I --format=json
data.reeflex.policy.decision` against that directory (same file, same
function). There is exactly one knob: **`REEFLEX_POLICY_DIR`**. Point it at
your own directory containing your own `.rego` files and core will evaluate
those instead — no core code change, no rebuild required if you're bind-
mounting.

Two ways to use it:

**Running from source** (see [`reeflex-core/README.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/README.md) env var table):

```bash
export REEFLEX_OPA_BIN=opa
export REEFLEX_POLICY_DIR=/path/to/your-policy
python reeflex-core/main.py
```

**Running the container** — the [`Dockerfile`](https://github.com/Reeflex-io/reeflex/blob/main/Dockerfile) bakes the
default in (`ENV REEFLEX_POLICY_DIR=/app/policy`); override it and bind-mount
your directory over it in [`docker-compose.yml`](https://github.com/Reeflex-io/reeflex/blob/main/docker-compose.yml):

```yaml
services:
  core:
    # ...existing config (image/build, ports, healthcheck)...
    environment:
      REEFLEX_POLICY_DIR: /policy   # overrides the Dockerfile default (/app/policy)
    volumes:
      - ./my-policy:/policy:ro
```

Whatever package you write MUST still expose `data.reeflex.policy.decision`
as the query root — that is the one contract `app/opa.py` depends on
(`query = "data.reeflex.policy.decision"`). Everything else — how many rules,
what they're called, how you organize files inside the directory — is yours.

### The input contract

Your policy reads fields off `input`, the Action Envelope. The fields the
*shipped* rules actually touch (there is no reason your own policy is
limited to these — this is the minimum a Reeflex-aware policy typically
needs):

| Field | Type | Used by |
|---|---|---|
| `input.action.verb` | string (`read`/`create`/`update`/`delete`/`execute`/`transact`/`emit`) | R1, R6 |
| `input.axes.reversibility` | `reversible`/`recoverable`/`irreversible` | R2, R3 |
| `input.axes.blast_radius` | `single`/`scoped`/`broad`/`systemic` | R2, R3 |
| `input.axes.externality` | `internal`/`outbound`/`physical` | R1 |
| `input.target.environment` | `production`/`staging`/`dev` | R2, R3 |
| `input.magnitude.count` | integer | R5, R6 |
| `input.cumulative.count_by_verb.*` | object, injected by core before eval (SPEC §4.1) | R5 (`.delete`) |
| `input.approval.present` | boolean | R5, R6 |

Full envelope shape, including `agent`, `target.kind`, `params`, `context`,
and `meta`: [`reeflex-spec/SPEC.md`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-spec/SPEC.md) §2. The
`cumulative` object and why fragmentation resistance needs it: SPEC §4.1.
**Any field your policy reads and finds missing should resolve conservatively
— never toward `allow`** (the shipped R5 predicate does this explicitly with
`object.get(..., 0)` for `cumulative`, defaulting absent prior activity to
zero rather than erroring or unblocking).

### The output contract

Your policy's `decision` rule must produce an object shaped like this
(SPEC §5):

```jsonc
{
  "decision": "require_approval",   // allow | deny | require_approval — required
  "reason": "...",                   // human-readable, for audit — required
  "rule": "your.policy/rule_id",     // fired rule id, for audit — required
  "obligations": ["audit:full"]      // optional; passed through verbatim by app/opa.py if present
}
```

`app/opa.py` reads exactly these keys off the returned value
(`value.get("decision")`, `value.get("reason", "")`, `value.get("rule", "")`,
`value.get("obligations", [])`) — add an `"obligations"` key to any decision
block and core forwards it to the adapter without any code change on the
core side.

---

## 5. Testing + safety

**Always run `opa test` before deploying a policy change** — against
whichever directory you're about to point `REEFLEX_POLICY_DIR` at:

```bash
opa test reeflex-core/policy/ -v
```

or, for a custom policy directory:

```bash
opa test /path/to/your-policy -v
```

Two structural guarantees hold regardless of what you write:

- **Fail-closed is not a policy responsibility — it's the engine's.**
  `app/opa.py`'s `evaluate()` raises `OpaEvalError` on the OPA binary being
  missing, a non-zero exit, a timeout, malformed JSON, or an
  undefined/empty result (including the `eval_conflict_error` case shown in
  LEVEL 2 above, before it was fixed) — the caller converts that into a
  `deny`, never an `allow`. A broken or ambiguous policy denies traffic; it
  does not open it.
- **No LLM, no network, no wall-clock time in the decision path.** The
  policy reads only `input` and its own constants. Do not call out to an
  external data source, do not branch on `time.now_ns()`, do not read
  free-text/markdown/OKF content as a decision input — any of those would
  break "same envelope in, same decision out," which is the actual
  determinism guarantee this product sells (see
  [`docs/adr/0002-no-llm-in-decision-path.md`](adr/0002-no-llm-in-decision-path.md)).

Every example in this guide was verified with these exact commands, in a
scratch copy of `reeflex-core/policy/`, never against the checked-in files —
see the raw `opa test` output inline in sections 2 and 3 above.
