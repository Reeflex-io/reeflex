# Gate policy — what blocks merge, what's report-only, and the allow-skips register

`gate.py` (repo root) is the single command that must be green before trusting
the tree — see its module docstring for the full mechanics (anchored parsing,
built-artifact invocation, the full test suite). This document answers the
question `gate.py --help` does not: **which of its components actually stop a
merge, and which are informational** — plus the register that makes every
allowed skip accountable to a name and a date instead of an oral tradition.

Without this written twice, the failure mode is concrete: `--allow-skips`
quietly grows a new entry, nobody records why, six months pass, and the gate
reports GREEN while a real suite has been silently excluded the whole time —
"lying green" returning through the one door built to be an honest exception.

---

## 1. Blocking vs report-only

CI runs `gate.py` from two jobs in `.github/workflows/gate.yml`:

- **`preflight-gate`** — runs `gate.py --pypi delegated --allow-skips
  wp-conformance` inline, against the PR's own tree.
- **`smoke-pypi`** — a sibling job that runs `smoke-pypi.yml` via
  `workflow_call`; `gate.py` itself only prints `COMPONENT pypi-smoke:
  DELEGATED` for this leg (see `run_pypi_smoke()`).

**Rule:** only `preflight-gate` may be a *required* status check on branch
protection. `smoke-pypi` answers "are the already-published PyPI packages
healthy right now", not "is this PR correct" — nothing in a PR's diff can fix
a broken published release, so treating that job as merge-blocking would stop
all work on an unrelated axis (the exact tension the ticket that produced this
document was opened to resolve). `smoke-pypi` stays **report-only**: its
result is read at release time and by whoever is chasing a PyPI incident, not
enforced on every PR.

Inside `preflight-gate` itself, every `COMPONENT` line gate.py emits is
blocking by default:

| Component | What it runs | Blocking? |
|---|---|---|
| `rego-core` | `opa test reeflex-core/policy/` | yes |
| `rego-claude` | `opa test reeflex-claude/policy/` | yes |
| `unittest-core` | full `unittest discover` over `reeflex-core/tests` | yes |
| `pytest-mcp` / `pytest-holds` / `pytest-claude` | `pytest tests/ -q` per package | yes |
| `npm-n8n` | `npm ci && npm test` in `n8n-nodes-reeflex/` | yes |
| `entrypoints` | build wheels from the tree + invoke every published console script | yes |
| `drift` | fails if a test file exists outside every enumerated suite root | yes |
| `pypi-smoke` | fresh install from PyPI of the published packages | **report-only** — always `DELEGATED` in CI (see above); only `run`/`skip` locally |
| `wp-conformance` | 4 PHP live-core harnesses against a real `reeflex-core` | yes, **when it runs** — allowed to `SKIP` only via the register in §3 |
| `wp-spec-conformance` | the SPEC conformance vectors (`reeflex-spec/conformance/`) driven through the WordPress normalizer — **no live core, no network** | yes — skips only where there is no `php` at all |

A component that **FAILs** turns the gate `RED` (exit 1) — always blocking,
no exception. A component that **SKIPs** without a matching `--allow-skips`
entry turns the gate `INCOMPLETE` (exit 3) — also blocking, by design (§14.6
of the WoW standard: a suite that quietly stops running is not a green gate).
Only a skip that is BOTH printed AND listed in `--allow-skips` lets the gate
report `GREEN` despite it — which is exactly why §2 exists.

---

## 2. The allow-skips discipline

**Every `--allow-skips <key>` entry that ships in `gate.yml` (or in a release
preflight command) must have a matching row in the register below, carrying a
reason and a date.** A PR that adds or changes an `--allow-skips` flag and
does not add/update the matching row is incomplete review bait, not a valid
change.

The register is re-read, not just written once:

- **At every PR that touches `--allow-skips`, `gate.yml`, or `gate.py`'s skip
  logic** — the reviewer checks the reason is still real, not rubber-stamped.
- **At every release preflight** — a release is exactly the moment a
  structurally-unrunnable-here component (like `wp-conformance` in CI) most
  needs its live-environment counterpart actually exercised somewhere before
  publishing.
- **At the next checkpoint that touches the owning suite** — if the suite
  behind an entry changes materially, the entry's reason is re-verified, not
  assumed to still hold.

A reason must state what makes the component **structurally** unrunnable in
that context (missing live dependency, delegated by design) — never "it was
failing and we didn't have time," which is a FAIL waiting to be reclassified
as a skip.

---

## 3. Allow-skips register (current)

| Component | Reason | Added | Re-confirmed | Upgrade path |
|---|---|---|---|---|
| `wp-conformance` | Needs a **live** `reeflex-core` instance — the 4 PHP harnesses (`conformance-demo.php`, `admin-holds-demo.php`, `fanout-regression-demo.php`, `hold-dedup-regression-demo.php`) POST real `/v1/decide` / `/v1/holds` calls against a running engine; CI does not provision one today. See `reeflex-wordpress/tests/README.md`. | 2026-08-11 (PR #73) | 2026-08-20 (PR #77 / RFX-27 — scope widened from 1 harness to all 4 under the same key; all 4 measured PASS against a real local `reeflex-core`) | Stand up an ephemeral `reeflex-core` service in `gate.yml` (a background process or service container) and pass `--core-url`, turning this from an allowed skip into a real `PASS`. Not scheduled; flag if picked up. |
| `pypi-smoke` | Delegated by design to `smoke-pypi.yml` via `workflow_call` — one copy of the fresh-install smoke, not two (DoD 4). It also structurally answers a different question than a PR review: the health of the **last published release**, not the tree under review — see §1 for why this also keeps it out of the required-status-check set. | 2026-08-11 (PR #73) | 2026-08-20 (PR #77 / RFX-27) | No upgrade path — this is a permanent-by-design delegation, not a placeholder gap. |

No other component is currently registered. A `SKIPPED` line for anything not
in this table is, by construction, **not** allowed and forces `INCOMPLETE`.

---

## 4. Adding a new allow-skips entry

1. Add the row to §3 **in the same PR** that adds or widens the
   `--allow-skips` flag.
2. State the reason in terms of what is structurally unrunnable here (a
   missing live dependency, a delegated-by-design duplicate) — not
   convenience.
3. State an upgrade path, or explicitly "no upgrade path — permanent by
   design" (as `pypi-smoke` is).
4. Get it reviewed like any other gate change. The reviewer's job is to
   confirm the reason is real, not to rubber-stamp a red suite into a quiet
   skip.

---

## 5. `.mcpb` distribution — open, owner decision

Whether Reeflex ships a `.mcpb` bundle build across a CI matrix (Windows /
macOS / Linux) is a **product decision**, not a mechanical one: zero `.mcpb`
assets have shipped across 15 releases to date, and the would-be matrix job
is deliberately not wired into CI, gated on that decision. This document
covers gate mechanics only (§1-§4) and does not resolve it — it remains open,
tracked on RFX-13, for the owner. If the answer becomes YES, the follow-up
ticket should also decide, under §1's framework, whether the `.mcpb` build is
blocking or report-only. If NO, the dormant scaffolding and the `.mcpb`
mention in the launch narrative should be removed together.
