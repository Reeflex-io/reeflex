# Contributing to Reeflex

Reeflex is a deterministic governance layer for AI-agent actions. The open
core (engine, spec, adapters) is Apache 2.0. Contributions target the open
core only; the commercial compliance tier is out of scope for community PRs.

---

## Table of contents

1. [Project layout](#1-project-layout)
2. [Prerequisites](#2-prerequisites)
3. [Running the tests](#3-running-the-tests)
4. [Running the demo](#4-running-the-demo)
5. [Code standards](#5-code-standards)
6. [How to write a new adapter](#6-how-to-write-a-new-adapter)
7. [PR process](#7-pr-process)
8. [Contribution scope](#8-contribution-scope)

---

## 1. Project layout

```
reeflex-core/         # decision engine: POST /v1/decide (Python + OPA/Rego)
  app/                # server, pipeline, envelope validation, ledger, audit
  policy/             # reeflex.rego (rules R1-R5) + reeflex_test.rego (OPA tests)
  tests/              # Python unit tests (test_decide.py)
reeflex-spec/         # SPEC.md (Action Envelope + Adapter Contract) + JSON schemas
  ADAPTER-EXAMPLES.md # worked adapter implementations (WordPress reference, Postgres)
reeflex-mock/         # mock adapter + end-to-end demo (worked example for adapter authors)
reeflex-claude/       # Claude Code adapter (reference, conformance-tested)
reeflex-wordpress/    # WordPress adapter (reference, conformance-tested)
docs/adr/             # Architecture Decision Records
QUICKSTART.md         # 10-minute walkthrough from zero to watching core stop a bulk delete
INSTALL.md            # OPA installation instructions (per OS)
CHANGELOG.md
```

---

## 2. Prerequisites

- **Python 3.12** (stdlib only — no pip dependencies for reeflex-core itself).
- **OPA 1.18** (single static binary). See [INSTALL.md](INSTALL.md).
  The OPA binary must be on your `PATH`, or the path must be set via
  `REEFLEX_OPA_BIN`.

Verify:

```bash
python --version   # expect Python 3.12.x
opa version        # expect Version: 1.18.x
```

Set the minimal environment from the repo root:

```bash
# Linux / macOS
export REEFLEX_OPA_BIN=opa
export REEFLEX_POLICY_DIR=reeflex-core/policy
```

```powershell
# Windows (PowerShell)
$env:REEFLEX_OPA_BIN = "opa"
$env:REEFLEX_POLICY_DIR = "reeflex-core\policy"
```

---

## 3. Running the tests

### Python unit tests

Run from the `reeflex-core/` directory:

```bash
cd reeflex-core
python -m unittest tests.test_decide -v
```

This drives the full `decide.process()` pipeline end-to-end. OPA is invoked
as a real subprocess — no mocking. `REEFLEX_OPA_BIN` must resolve to a
working OPA binary. The fail-closed test intentionally points at a
nonexistent OPA path and asserts `deny`.

### OPA policy tests

Run from the repo root:

```bash
opa test reeflex-core/policy/ -v
```

This runs `reeflex_test.rego` against `reeflex.rego`. It covers all five
policy rules: R1 allow, R2 require_approval, R3 deny, R4 default allow,
R5 session delete budget (fragmentation resistance), plus approval-present
bypass and absent-cumulative defensive defaults.

Note: `REEFLEX_OPA_BIN` is used by the Python tests; the `opa test` command
above uses whatever `opa` binary is on your `PATH`. If OPA is not on `PATH`,
run `<path-to-opa> test reeflex-core/policy/ -v` directly.

---

## 4. Running the demo

From the repo root:

```bash
python reeflex-mock/demo.py
```

The demo starts the engine as a subprocess, runs 5 end-to-end scenarios
(read, single delete, bulk delete requiring approval, fragmentation
resistance, fail-closed on broken OPA path), prints before/after store
state with read-back assertions, and exits with `STATUS: PASS` or
`STATUS: FAIL`.

See [QUICKSTART.md](QUICKSTART.md) for a full walkthrough of all 5 scenarios
and how to read the output.

---

## 5. Code standards

- **Language:** Python (stdlib only — no new pip dependencies without
  explicit discussion in the PR). PHP for the WordPress adapter.
- **Identifiers and filenames:** ASCII only. No Unicode in identifiers.
- **Docs and comments:** English only.
- **Deterministic decision path — zero LLM.** The path through
  `POST /v1/decide` is OPA/Rego plus classical logic. No LLM may be
  introduced anywhere in this path. This is a hard limit, not a preference
  (see ADR-0002). A PR that adds an LLM call, any
  stochastic model, or any free-text interpretation to the decision path
  will be rejected.
- **Fail-closed is structural.** Any OPA error, missing binary, or
  unexpected exception must produce `deny`, never `allow`. Do not add code
  paths that silently allow on error.
- **Conservative defaults.** An unknown axis value must coerce to the most
  restrictive option (`irreversible`, `systemic`, `physical`), never be
  omitted or defaulted to permissive.
- **No secrets or PII.** Hardcoded credentials and real client data are
  forbidden. Use synthetic examples only.

---

## 6. How to write a new adapter

An adapter connects a backend (a database, an API, a CMS) to Reeflex. To be
Reeflex-compliant it must implement four responsibilities defined in
[SPEC §6](reeflex-spec/SPEC.md#6-the-adapter-contract). The worked reference
implementation is `reeflex-mock/adapter.py`.

### 6.1 Overview

```
backend action --[ adapter ]--> Action Envelope --> POST /v1/decide --> Decision --[ adapter ]--> proceed / block / hold
```

The engine knows nothing about your backend. Your adapter's job is to
translate every backend action into the universal Action Envelope, ask core
for a decision, and enforce it faithfully.

### 6.2 The four responsibilities

**INTERCEPT** — Capture the backend action before it executes.

Your interception point is adapter-specific: an MCP gateway, an API proxy,
a WordPress hook, a database driver wrapper. The constraint is that the
backend must not be touched until a decision is received and applied. In
`adapter.py`, the interception seam is `MockAdapter.apply(intent)`.

**NORMALIZE** — Produce a valid Action Envelope (SPEC §2).

This is the hard, valuable part. Every field in the envelope must be derived
from what you know about the action. Map your backend operations to:

- A normalized `verb` from the fixed set: `read`, `create`, `update`,
  `delete`, `execute`, `transact`, `emit` (SPEC §3).
- The backend-specific operation in `action.ability`
  (e.g. `wordpress/delete-post`).
- All three axes (SPEC §4):

  | Axis | Values (least to most restrictive) |
  |---|---|
  | `reversibility` | `reversible` → `recoverable` → `irreversible` |
  | `blast_radius` | `single` → `scoped` → `broad` → `systemic` |
  | `externality` | `internal` → `outbound` → `physical` |

  When uncertain, default to the most restrictive value — never omit an
  axis or guess permissive.

- A stable `agent.session_id` (**required**). Core uses this key to track
  cumulative action budgets for fragmentation resistance (SPEC §4.1). A
  missing or empty `session_id` returns HTTP 400.

- `target.environment` — `production`, `staging`, or `dev`.

See `reeflex-spec/ADAPTER-EXAMPLES.md` for worked axis-mapping decisions for
WordPress and Postgres backends.

**ENFORCE** — POST the envelope to core and apply the decision faithfully.

```
POST /v1/decide   Content-Type: application/json
{ ActionEnvelope }
->
{ "decision": "allow" | "deny" | "require_approval",
  "reason": "...",
  "rule": "reeflex.policy/...",
  "obligations": [...] }
```

Apply the decision:

- `allow` — execute the action on the backend.
- `deny` — block it. Surface `reason` to the caller. Backend untouched.
- `require_approval` — hold it. Queue for a human reviewer. Re-submit the
  envelope with `approval.present = true` when the human approves.

**Fail-closed is mandatory.** If core is unreachable, returns non-200, or
returns a response without a `decision` field, the adapter must deny or
hold. It must never silently allow on error. Any returned `obligations`
must be honored; ignoring an obligation is a conformance failure.

**AUDIT** — Emit one append-only audit record per decision.

The record must include at minimum: envelope summary, decision, rule that
fired, and applied outcome. An audit write failure must never affect the
decision — wrap the audit path in a try/except.

### 6.3 Reference functions (reeflex-mock/adapter.py)

| Responsibility | Function |
|---|---|
| INTERCEPT | `MockAdapter.apply()` |
| NORMALIZE | `MockAdapter._normalize()` |
| ENFORCE | `MockAdapter._call_core()` + `MockAdapter._enforce()` |
| AUDIT | `MockAdapter._audit()` |

Read `reeflex-mock/adapter.py` end-to-end before writing your adapter. The
module docstring explains every axis-mapping decision.

### 6.4 Conformance suite

An adapter claiming Reeflex compliance must pass the conformance suite
(SPEC §7). Minimum conformance for v0.1:

- Produces a schema-valid envelope for every intercepted action.
- Sets all three axes (conservative defaults when unknown).
- Applies `allow` / `deny` / `require_approval` correctly.
- Fails closed on core error (never silently allows).
- Honors every returned obligation.
- Emits an audit record per decision.
- Supplies a stable `session_id`.

---

## 7. PR process

1. Open an issue or discuss in a comment before starting a large change.
2. Fork the repo and create a branch from `main`.
3. Make your changes. Add or update tests as needed.
4. Run the full test suite locally before opening a PR:
   ```bash
   cd reeflex-core && python -m unittest tests.test_decide -v
   opa test reeflex-core/policy/ -v
   ```
   Paste the raw output in the PR description.
5. Open a pull request using the PR template. Fill in every section,
   including the determinism check (no LLM added to the decision path).
6. A maintainer will review. Reviews focus on correctness, the
   determinism invariant, fail-closed behavior, and the open-core boundary.

### Developer Certificate of Origin (DCO)

All commits must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Signing off certifies that you
wrote the contribution (or have the right to submit it) under the project's Apache-2.0 license. Add the
sign-off automatically with the `-s` flag:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <your@email>` trailer to the commit. PRs whose commits are not
signed off will be asked to amend (`git commit --amend -s`, or `git rebase --signoff` for multiple commits).

---

## 8. Contribution scope

Contributions are welcome for:

- `reeflex-core` — engine behavior, policy rules, test coverage.
- `reeflex-spec` — spec clarifications, schema definitions, conformance cases.
- Community adapters (`reeflex-postgres`, `reeflex-s3`, etc.) that implement
  the SPEC §6 adapter contract.
- `reeflex-mock` — improvements to the demo and mock adapter.
- Documentation and QUICKSTART improvements.

Out of scope for community PRs:

- The commercial compliance tier (NIS2/DORA/GDPR reporting, ANAF/SmartBill
  integrations). This code does not live in the open repos.
- Any change that introduces an LLM, stochastic model, or free-text
  interpretation into the `/v1/decide` decision path.

If you are unsure whether a proposed change is in scope, open an issue
first.

---

*Reeflex — governance that isn't another AI.*
