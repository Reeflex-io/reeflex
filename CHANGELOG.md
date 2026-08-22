# Changelog

All notable changes to Reeflex are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project is pre-release.

## [Unreleased]

### Changed

- **An action the canon cannot CLASSIFY now resolves to a hold, under its own rule id, instead of a terminal deny (RFX-132).** After #89 and #90 the three conservative defaults compose: `reversibility → irreversible`, `blast_radius → systemic`, `environment → production` is exactly R3 — the one rule a human is not allowed to clear. So the envelope an adapter emits when it *cannot price an action* (`{"action":{"verb":"frobnicate"},"target":{"environment":"qa-eu"},"axes":{}}`) was getting a hard refusal with no human anywhere in it, on a product whose value proposition is the human in the loop. Each default that produced it was individually right; the composition was never designed.

  **The decision, and the argument you can attack.** DENY makes the product brittle at the moment it is least certain, and a gate that refuses the unfamiliar gets switched off — which is a fail-open with extra steps. ALLOW is the defect class the last six tickets were spent killing. HOLD is the third state Reeflex exists to have, and "I do not know what this is, ask a human" is the most honest thing the product can say about an input it cannot verify.

  **New R0**, `reeflex.policy/unclassified_action`, highest precedence. `envelope.py` now records, per field, whether the caller **declared** a value core recognises or core **guessed** one — a core-computed `provenance.undeclared` list — and R0 fires when a verdict R2 or R3 would have produced rests on at least one of those guesses. The reason names the fields, so the hold says *what* could not be classified rather than only that something could not.

  **Four bounds, each one measured rather than asserted.** (1) **R0 only ever converts a refusal.** It fires when R2 or R3 would, never on an allow, so the long tail of unaliased verbs on reversible non-production actions stays `default_allow` — which is the volume objection, and RFX-145's lesson from the other side. (2) **Only the three inputs R2/R3 actually read can trigger it** (`axes.reversibility`, `axes.blast_radius`, `target.environment`); guessing `axes.externality` or `action.verb` is recorded but softens nothing. (3) **"Declared" is judged on the FOLDED token**, so `Systemic` is a declaration of systemic — judged on the raw exact match a caller would downgrade a terminal deny to a resolvable hold by capitalising one letter, which is RFX-86's evasion one tier up. (4) **`provenance` is core-computed and overwritten unconditionally**, so a caller cannot assert its way from R3's deny into R0's hold; that is the whole security of the rule and it has its own test.

  **The coercion itself is deliberately unchanged.** `_AXIS_ALLOWED` is still matched exactly, so `Broad` still coerces to `systemic` as it always did. Folding the *value* too would turn `blast_radius: "SINGLE"` on an irreversible production action from a DENY into an ALLOW, and a case fix that relaxes a refusal is not this ticket's to make. The residual wrong-DENY is stated in `envelope.py` and left as its own ticket.

  **Measured volume, because "HOLD not DENY" is only defensible if the holds land somewhere an operator can keep up with.** Over a 31-action corpus of what a coding agent actually issues, driven through the *shipped* `reeflex-claude` classifier and envelope builder: **0 of 31 envelopes carry a guessed classification**, so R0 adds **zero** holds to a realistic workload — both reference adapters always emit all three axes and a declared environment. Over the exhaustive 6,048-input grid (756 axis/verb/env combinations × 8 provenance shapes), **294 decisions move (4.9%), in exactly two directions**: 147 `deny/irreversible_systemic_prod → require_approval/unclassified_action` (the ticket's target) and 147 `require_approval/irreversible_broad_prod → require_approval/unclassified_action` (a relabel; same verdict, same obligations). **No allow becomes a hold, no refusal becomes an allow, and 0 of the 756 grid points a CONFORMANT adapter can produce move at all.** Harness and transcripts: `code-reports/dev-3--028-evidence/`.

  **R0 is resolvable, which is the entire difference from the R3 it replaces.** `irreversible_systemic_prod` stays in core's `NON_RESOLVABLE_RULES`; `unclassified_action` is not in it, and the default resolution policy makes it human-only. `reeflex-spec/SPEC.md` §4.0 states the rule normatively, including the adapter SHOULD that keeps R0 rare.

### Added
- **R5, generalized — configurable cumulative budgets over heterogeneous action types (RFX-11).** `reeflex-core/policy/budgets.rego` generalizes R5's cumulative-delete guard into policy-authored budgets over four dimensions — `money`, `deletions`, `external_sends`, `objects_touched` — definable per session/principal as Rego data, not a hardcoded Python or Rego constant. `objects_touched` gives every action non-zero weight regardless of verb/ability, closing the gap where a session amplifier that assigns 0 to small-tier actions never accumulates a long tail of individually-harmless calls into a hold (the exact gap left open by the closest thesis rival's hardcoded, payments-only cumulative check). `ledger.py` gains `count_by_externality` + `total_count` (additive fields on the existing `cumulative` object, SPEC §4.1) so the new dimensions aggregate across whatever verb/ability produced each action. The original R5 rule id/reason/default (20) are unchanged for backward compatibility. `decide.py` gains `resolve_session_identity()` — a single seam for the identity that keys the ledger and that budgets.rego reads as `input.agent.session_id`, so RFX-9's still-open question of WHERE that identity comes from is a one-function change later, not a re-key. See `reeflex-core/tests/test_budgets_rfx11.py` for the end-to-end smurfing-scenario demo, including one that edits `budgets.rego` alone (zero Python changes) to prove the budget is genuinely policy-controlled.
- **WP.org auto-deploy CI (RFX-22)** — `.github/workflows/wporg-deploy.yml` deploys `reeflex-gate`
  (trunk + version tag + listing assets) to the WordPress.org plugin SVN via
  `10up/action-wordpress-plugin-deploy` on every published GitHub Release. Inert until
  `WPORG_SVN_USERNAME`/`WPORG_SVN_PASSWORD` GitHub Secrets exist (the plugin is still in the
  wordpress.org review queue) — see `docs/RELEASING.md` §2.5.
- **WooCommerce use-case docs page** (`docs/adapters/woocommerce.md`) — the marketing story over
  coverage the WordPress adapter already has (`woocommerce/*` abilities pass through the same
  `WP_Ability::execute()` seam); no new adapter code.

### Fixed
- **A human's approval now names the party it was granted to, not just the action (RFX-138, RFX-139).** Checks 1–7 of the hold-resubmission chain answered *"is this the action a human approved"*; nothing answered *"is this the requester they approved it for"*. `agent` is outside `canonical_hash()`'s `{action, axes, magnitude, target}` projection and outside check 7's `params` comparison, so an approval was spendable by any caller holding the `hold_id`: agent ALPHA raised an irreversible production delete, a human approved it, agent BETA resubmitted the identical action with ALPHA's `hold_id` and got `allow` — and because that resubmission consumed the single-use hold, ALPHA, the agent the human actually approved, was then refused `reeflex_hold_consumed`. Quieter and worse: the same bot, the same session, the same action, with only `agent.on_behalf_of` changed from alice to bob, produced an audit line byte-identical to a legitimate resubmission. Both were reproduced over HTTP against the container built from `44c6f85` — the commit *after* check 7 landed. **Check 8** compares the resubmission's actor key (`agent.id` + `agent.on_behalf_of`, falling back to `agent.session_id` only when the envelope names no agent, so a SPEC-minimal envelope is not a vacuous key) against the approved envelope's, and denies `reeflex_hold_actor_mismatch` **before** `mark_consumed()` — so a refused substitution no longer destroys the human's decision. Identities are compared folded, the same normalization the four-eyes guard uses, so an agent that restarts (new `session_id`) or is spelled in a different case does not lose an approval it was granted: over-blocking here would be a wrong DENY on the one path where a human explicitly said yes, and the release gate now fails on that too. **RFX-139 is why RFX-138 existed:** `DECIDE_ENVELOPE_PATHS` omitted `agent.id` and `agent.on_behalf_of`, which `decide.py` has always read through `principal.is_self_approval()` — so the "decide.py reads nothing undeclared" test passed by under-reporting, and a field that is never declared can never be bound by an approval binding derived from `field_treatments.TREATMENTS`. Both fields are now declared, every caller-supplied field states what an approval binds about it (`BIND_HASH` / `BIND_VALUE` / `BIND_ACTOR` / `BIND_NONE` with a written reason — an exclusion has to be argued, not implied by a block list nobody re-reads), and the decide.py side is swept **dynamically**: the approval chain runs against an envelope that records every field anything dereferences, so a reader in another module cannot hide from it the way this one did. `reeflex-core/tests/test_approval_actor_binding_rfx138.py` (17 tests) and A6 in `scripts/attack-probe-rfx97-release-gate.py`.
  - **The adapter obligation, written down normatively (RFX-138 follow-up).** Check 8 creates a deployment hazard for third-party adapters that nothing in the codebase stated: a resolution surface — an admin screen, a CLI, a chat approval — runs in the *operator's* context, so an adapter that derives identity from "the live request" when it resubmits substitutes the resolver for the actor and core will refuse it. That refusal is indistinguishable from the attack it exists for. `reeflex-spec/SPEC.md` §5.1 now states what an approval authorises as four normative conditions (hash, `params` values, actor identity, unconsumed-and-in-TTL), requires that a condition-3 refusal not consume the hold, requires adapters to capture `{id, on_behalf_of, session_id}` at hold creation and replay them verbatim, and states the residual rather than implying it: all three identity fields stay caller-asserted, so an approval is now non-transferable *between* declared identities without any declared identity becoming true. Carried from the closed PR #95, which was the only place either RFX-138 branch said this (dev-1--022 §5).
  - **Two more paths the module reads and did not declare (RFX-139 follow-up).** `DECIDE_ENVELOPE_PATHS` still omitted `params.amount` and `params.currency`, which check 7 has dereferenced since #92. The dynamic sweep did not require them — it subtracts `policy_input_paths | LEDGER_ENVELOPE_PATHS` as "explained elsewhere", and the ledger declares both — which is self-consistent but not what the tuple's own stated purpose says it is ("the envelope fields THIS MODULE reads to reach a verdict"). Declared, and the sweep now carries an anti-vacuity pin: the two RFX-139 assertions are SUBSET assertions, so a refactor that moved the four-eyes compare or the actor key out of `_validate_approval()` would shrink the recorded set and leave both green as tautologies. The six paths a hold-approval check was written to compare are asserted to be read.
- **The envelope boundary gets one discipline instead of a sixth patch — every caller-supplied field the decision path reads is now enumerated, treated, and tested (RFX-127, RFX-133).** Five ways to beat the deterministic decision path had been found and fixed one field at a time (RFX-86 environment, RFX-85 verb, RFX-84 approver, and the two here). They are one defect: *a caller-supplied value that the policy reads without canonicalising or verifying it.* `reeflex-core/app/field_treatments.py` now declares every such field with its treatment — canonicalise (closed enum, unknown coerces to the most-guarded member), validate (type/range), verify (checked against state the caller does not control), or core-computed — and `tests/test_field_treatments.py` DERIVES the set of fields actually read, from `policy/*.rego`, from `ledger.py` and from `decide.py`, failing if any of them lacks a declared treatment. A new field cannot reach a rule untreated. Scanning the Rego alone is not enough and both open tickets prove it: `params.currency` reached the money budget only through the ledger, and `approval.hold_id` appears in no rule at all.
  - **RFX-127 — `approval:{present:true}` with no `hold_id` switched off EVERY cumulative budget.** R5 reads `not input.approval.present`, and `decide.py` entered the six-check hold-validation chain only when `present` AND `hold_id` were both set, so a bare `present:true` skipped validation entirely and reached OPA still asserting an approval that no hold had ever backed — verdict `default_allow`, deletions/money/external_sends/objects_touched all disabled, and no trace in the audit line. Not one condition evaded: a whole rule disabled by an unverified boolean, the same shape as RFX-84's self-asserted approving human. `_validate_approval()` was already written to refuse a missing `hold_id`; that guard was the only reason the branch was unreachable. An approval assertion is now always validated and a refusal is audited, and the OPA input's `approval.present` is set from what core verified rather than from what the caller wrote. **Reproduced live on api-dev with the published eval token** (control `require_approval` → attack `allow`) and re-run clean after; see `scripts/attack-probe-envelope-boundary.py`.
  - **RFX-133 — the money budget was evaded by omitting `params.currency`, and the number it compared was not a quantity of money.** `ledger.py` recorded an amount only when a currency was also present, so leaving one optional field out kept the spend out of `cumulative.amount_by_currency` entirely: 8,000 spent against a budget of 5,000, never held. `params.currency` is now canonicalised at the envelope boundary to an ISO 4217 alpha-3 code or `XXX` ("no currency involved"), which is a real accumulating bucket, so omission buys nothing. Underneath it was a unit error no canonicalisation fixes: `sum(amount_by_currency)` added EUR to JPY to IDR and compared the result to one scalar limit. **Budgets are now per currency and aggregate as dimensionless UTILISATION** (`used_c / limit_c`) — you cannot add EUR to JPY, but you can add the fraction of each budget consumed, which needs no exchange rate and stays deterministic. That closes fragmentation across currencies (4900 EUR + 4900 USD = 1.87 utilisation → held) while removing the wrong-DENY the old sum produced (4000 EUR + 2000 JPY ≈ EUR 4012 → allowed, not "6000 > 5000"). Negative amounts are counted as exposure (`abs`), so alternating +N/-N no longer unwinds the budget.
  - **A sixth and a seventh, found BY the enumeration during the sweep and fixed here.** `params.amount` accepted `NaN`/`Infinity` (Python's `json.loads` takes the bare tokens), and one NaN in the ledger made every later comparison against that currency false — a single call permanently disabled the session's money budget; a non-finite amount is now a structural refusal. And `params` sits outside the `envelope_hash` projection (`{action, axes, magnitude, target}`), so an approval bound *nothing* about the amount: a hold raised for EUR 6,000 was resubmitted as EUR 6,000,000 with a byte-identical hash and allowed — the human approved one number and the agent executed another. `_validate_approval()` gains a seventh check comparing the decision inputs the hash does not cover, with the path list derived from the treatment table rather than hardcoded, so the `envelope_hash` preimage (which audit/SIEM/evidence join on) is left untouched.
  - All five attacks live in one re-runnable file, `reeflex-core/tests/test_envelope_boundary_attacks.py` (37 tests), so any future build can be asked the single question "do all five still fail?" — 19 of them fail on the pre-fix tree and all pass after. **Note for release: api-dev runs a pre-RFX-11 build with no money dimension and no environment canon, so RFX-133 is not reproducible there and RFX-127 is still live there; the probe fingerprints the target build and says which it is rather than assuming.**

- **A hold nobody answers can finally be seen as timed out — three core-side links (RFX-64, RFX-65).** Core knew every hold's deadline and told nobody: `decide.py` put `expires_ts` on the `/v1/decide` RESPONSE, but `audit.record()` never wrote it, so the audited stream a connector/SIEM tails carried no deadline and anything downstream had to either guess a TTL (which drifts from this core's `REEFLEX_HOLD_TTL_SECONDS`) or show a held action as pending forever. It is now on the `require_approval` audit line, additively, exactly the way `hold_id` and `traceparent` already were. Second: the denial that refuses an action BECAUSE ITS HOLD TIMED OUT (`reeflex_hold_expired`) carried no `hold_id` — `decide.py`'s `fail_resp` branch called `_try_audit(...)` without one — so the one record naming the timeout could not be attached to the hold it was about; the whole hold-validation refusal family now names the hold it was decided against (and its creating decision as `parent_decision_id`), conditioned on the hold actually existing so a fabricated id in an envelope never invents a phantom hold. Third: `holds.py::_append_expired_event()` stamped `expired_ts`/`resolved_ts` with the OBSERVATION time. Expiry is lazy by design ("evaluated on read/validate … no background thread"), so on a deployment where nothing reads a pending hold that observation can be weeks late — three real production holds raised in July 2026 were recorded as having timed out on 2026-08-20, the instant something first happened to list them. The appended record and the Art.14 `hold_resolution` event now carry the hold's OWN `expires_ts` as the expiry time, with the detection time kept separately as an additive `observed_ts`: both facts, neither invented, and an append-only evidence stream that no longer states the wrong date for the event it exists to evidence. Verified end to end against a live app + connector with a real 75-second TTL, no faked clock (`reeflex-core/tests/test_hold_expiry_visibility_rfx64_65.py`, 10 tests).

- **`reeflex-holds` gets real `list`/`approve`/`reject` terminal subcommands, and the silent-lie defect they fix (RFX-42).** Before this change, `reeflex-holds list` (or `approve`, or `--help` — any argv at all) fell straight into `server.py`'s `mcp.run(transport="stdio")`, which ignores argv entirely; run from a terminal (stdin not a live MCP client) it just exited 0 with zero output the moment stdin hit EOF — an operator reasonably reads silence as "no pending holds", which is worse than the tool not existing. `reeflex_holds/cli.py` adds real argparse subcommands calling the same `client.py` functions the MCP tools call (`GET /v1/holds`, `GET /v1/holds/{id}`, `POST /v1/holds/{id}/resolve`); `server.main()` now dispatches to the CLI on any argv and only falls into the stdio transport with none, so Claude Desktop / the MCPB bundle (which launch with no args) are unaffected. Same `REEFLEX_PRINCIPAL`-only resolving-identity rule as the MCP tool — no `--principal` flag exists, so a resolution made from this CLI is indistinguishable in reeflex-core's evidence from one made through the dashboard or an MCP client. `gate.py`'s `PUBLISHED` entrypoint smoke updates `reeflex-holds` from "no argparse, exit 0 only" to "anchored usage banner", proving the fix at the same gate that used to encode the defect as an accepted fact.

### Changed
- **`reeflex-holds` 0.2.0 (not yet published) — ports from `mcp.server.fastmcp.FastMCP` to `mcp.server.mcpserver.MCPServer`, the post-2026-07-28-spec successor (RFX-26).** The `mcp` dependency floor moves to `mcp>=2`; this package no longer supports `mcp<2` (the two APIs are not simultaneously importable from one `mcp` install). Mechanical port validated by the RFX-9 spike (dev-1--003): tool registration, forwarding, and error propagation are unchanged — only the import path and the `Tool.inputSchema` -> `Tool.input_schema` attribute rename in tests. `reeflex-mcp` is unaffected and stays pinned at `mcp>=1.2,<2` on its own dependency contract; `gate.py`'s pytest/entrypoint suites now use one venv per package instead of one shared venv, since the two packages' `mcp` constraints can no longer resolve together.

## [0.1.15] - reeflex-mcp 0.1.3 + reeflex-holds 0.1.2 (mcp<2 dependency pin)

Both PyPI packages have been broken on FRESH install since 2026-07-28: `mcp` 2.0.0 (released that day) removed the `mcp.server.fastmcp` module, which both `reeflex-mcp` and `reeflex-holds` import at startup, and both packages declared `mcp>=1.2.0` with no upper bound — so a fresh `pip install` resolved `mcp` 2.0.0 and the installed tool died immediately with `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`. Existing environments that already had `mcp` 1.x installed were unaffected.

### Fixed
- **`reeflex-mcp` 0.1.3 — fresh installs from PyPI work again.** The `mcp` dependency is now capped at `mcp>=1.2,<2`, so pip resolves a 1.x SDK that still ships `mcp.server.fastmcp`. No code change over 0.1.2; if your install already works, this changes nothing. The pin landed on `main` in #71; this version exists to carry it to PyPI, because PyPI versions are immutable and 0.1.2 is already published without the pin.
- **`reeflex-holds` 0.1.2 — same fix, same cause.** `mcp` capped at `mcp>=1.2,<2`; no code change over 0.1.1, which is already published without the pin and fails on fresh install for the same reason.

## [0.1.14] - reeflex-mcp 0.1.2 (dogfooding fixes)

reeflex-mcp gateway: three first-run / reliability fixes found by dogfooding (installing the gateway in Claude Desktop). No decision-path change; deterministic behavior unchanged.

### Fixed
- **A failed or closing stdio upstream no longer crashes the whole gateway** (an anyio cancel-scope teardown error). `required: false` now degrades gracefully — the dead upstream is skipped and the healthy ones boot. Also fixes an orphaned-subprocess leak when a stdio upstream connect times out.
- **Enforce mode no longer denies harmless reads on an unmapped server.** The read-name heuristic is widened (`count_`/`fetch_`/`query_`/`describe_`/`find_`/`select_`, camelCase `get*`/`list*`) and the upstream's own MCP tool annotations (`readOnlyHint`/`destructiveHint`) are honored as an authoritative tier ahead of the heuristic. Genuine unknowns still fail closed.
- **`reeflex-mcp setup` writes an absolute `--config` path** (fixes "Server disconnected" when the launched gateway's cwd differs from the setup dir) and scaffolds `REEFLEX_CORE_URL` + `REEFLEX_MODE=observe` into the client entry's env — never `enforce` by default; `REEFLEX_CORE_TOKEN` is never auto-written.


## [0.1.13] - audit enrichment (Attest evidence fields)

Core: audit trail enrichment for the compliance-evidence surface (Attest / AI Act Art.14 human-oversight trail). No decision verdict or decision-logic change; additive only.

### Added
- **`agent_id` + `action.target_system` on every decision audit record.** The JSONL audit record (`audit.record()`) now carries `agent_id` (`envelope.agent.id` — the same source `decide.py`'s actor-identity check already uses) and `action.target_system` (`envelope.target.system`, sitting alongside the pre-existing `action.environment` key) so an evidence consumer can attribute a decision to an acting identity and a target system without re-deriving them from the raw envelope. Both are non-load-bearing metadata: empty string on absence, fail-open, never affecting the decision.
- **`hold_resolution` audit events — the AI Act Art.14 human-oversight evidence trail.** A new event shape (`"event": "hold_resolution"`) on the SAME append-only `decisions.jsonl` stream (same lock, same fsync, same read-back-after-write discipline) captures `hold_id`, `resolution` (`approved`\|`rejected`\|`expired`), `decided_by`, `decision_id`, and `resolved_ts` whenever a hold is resolved. All three fire at the RESOLUTION/DECISION moment, so every hold outcome is evidenced regardless of any later consumption: `approved` and `rejected` fire in `holds.resolve_hold()` immediately after the human's decision is durably written (symmetric — the audited fact is the Art.14 human-oversight *decision*, which stands even if an approved hold is never resubmitted/consumed); `expired` fires in `holds._append_expired_event()` when the lazy expiry transition is durably written (`decided_by="system:reeflex-core"`, a documented sentinel — an expiry has no deciding principal). `decision_id` is `""` on these events (no `/v1/decide` transit exists at the decision moment); for an approved hold, the eventual resubmission's decision record carries the same `hold_id`, correlating the executed action back to the approval. The discriminator field (`"event"` — absent on legacy decision records) lets a connector/SIEM distinguish the two record shapes on one ordered stream without breaking any existing decision-record consumer.
- **`integrations/wazuh/reeflex-decoder.xml`** doc-comment updated (no decoder logic change — `JSON_Decoder` auto-decodes any additive field) to document the audit-log field vocabulary (`agent_id`, `action.target_system`, `hold_resolution` event fields) alongside the pre-existing live-SIEM-syslog field list.

## [0.1.12] - 2026-07-13

Core: the freeze kill-switch now surfaces on the SIEM (#45). Gateway: `reeflex-mcp` 0.1.1 observe-mode traceability parity (GAP-1, #46). No decision verdict or decision-logic change; additive only.

### Fixed
- **SIEM `kill_switch` event now emitted on a freeze (`REEFLEX_FREEZE`) flip.** `emit_kill_switch()` was fully implemented but had no production call site — `docs/siem.md` advertised a `kill_switch` event that never fired (a facade). `decide._try_fire_freeze_flipped()` now emits it on a freeze state CHANGE (engage → `flipped`, clear → `cleared`), alongside the existing `freeze.flipped` audit record + webhook, so the SIEM (a SOC's primary surface) is no longer the one surface blind to the operator kill-switch. Fire-and-forget, best-effort, only on a state change (no per-request noise); no decision verdict or decision-logic change.
- **`reeflex-mcp` 0.1.1 — observe mode now tags `decision_id` (GAP-1).** In `observe` mode, `_handle_call_tool()` called `_decide()` for the audit trail but forwarded the result without tagging its `_meta` with core's `decision_id`/`parent_decision_id` and without logging the verdict — unlike `enforce`'s allow path, which does both. The forwarded result's `_meta` now carries `decision_id` (+ `parent_decision_id` when core returns one), at parity with enforce, and a stderr line logs the observed verdict/`decision_id`/`rule` (`would-<verdict> ... -- forwarding (observe never blocks)`) so an operator can correlate an observed call to core's audit/SIEM record. Additive/observability-only: observe still always forwards and fails open regardless of verdict — no change to verdict handling in either mode.

## [0.1.11] - 2026-07-11

Core decision traceability + concurrency-safe hold consumption — the dependency baseline for the `reeflex-mcp` gateway, which ships in this same tag (0.1.0, its first release). No core decision verdict or decision-logic change; additive only. (Core version realigns to the release tag here: 0.1.9 and 0.1.10 were adapter/channel releases where `reeflex-core` was unchanged, so core skipped them.)

### Added
- **Hold consumption CAS (compare-and-set) guard.** `holds.mark_consumed()` now checks the hold's current status (`== "approved"`) INSIDE the same lock acquisition it uses to append the `consumed` event, instead of appending unconditionally once the hold is found. This closes a latent double-consume race: two concurrent resubmissions of the same approved single-use hold could previously both pass `_validate_approval()` and both reach `mark_consumed()`, and both would be marked consumed and both would be allowed to execute — double-executing an approved-once irreversible action. With the CAS guard, exactly one concurrent caller observes `status == "approved"` and wins the consume; every other caller (racing or merely late) observes a non-`"approved"` status and gets `None` back. `decide.py`'s resubmission path now treats a `None` return from `mark_consumed()` as a hard deny (`reeflex_hold_already_consumed`, rule `reeflex.core/hold_validation`) rather than proceeding to allow, and audits it with both `decision_id` (this refused transit) and `parent_decision_id` (the hold's creating decision). This was previously masked because `server.py` runs a single-threaded `http.server.HTTPServer`; hardened now, ahead of the upcoming threaded `reeflex-mcp` gateway. No API surface change, no new endpoints, no server threading change.
- **`reeflex-mcp` 0.1.0 — MCP gateway adapter (new component).** A transparent MCP proxy that governs any MCP upstream, stdio or streamable-HTTP: aggregates and namespaces every configured upstream's tools (`<upstream>__<tool>`) with zero hardcoded tool knowledge, intercepts `tools/call`, normalizes it into the Action Envelope via a 3-tier resolution (declarative per-server mapping > name-heuristic > conservative default — starters ship for `filesystem`/`github`/`postgres`), asks `reeflex-core`'s `POST /v1/decide`, and enforces the verdict. `allow` forwards and tags core's `decision_id`; `deny` blocks with `rule`/`reason`/`decision_id`; `require_approval` surfaces `hold_id`/`expires_ts` and tracks the pending hold (keyed by session + the canonical action hash) so a client retry is recognized as a resubmission (`approval.parent_decision_id`) — core never executes, the gateway executes after the allow. `observe` mode (default) always forwards and fails open; `enforce` + core unreachable fails closed, proven by the `reeflex-mcp check` self-probe (mirrors `reeflex-claude check`). Obligations (SPEC §5/§7 minimum #5) are read on every decision in both modes — enforce blocks on an unknown obligation (fail closed), observe records it. Lifecycle subcommands `setup`/`restore`/`add`/`import`/`doctor` migrate a client's MCP config (Claude Desktop, `.mcp.json`, `.claude/settings.json`) onto a single governed gateway entry, with backup/restore, and detect configs that bypass the gateway (single-path drift). 287 unit tests pass; conformance-tested per SPEC §7 (all minimums). Zero LLM anywhere near the decision path. See [docs/mcp-gateway.md](docs/mcp-gateway.md). **Not yet published to PyPI** — publication is a gate (human GO), same as every other Reeflex package.
- **Decision traceability: `decision_id` primary key.** Every `/v1/decide` transit (allow / deny / require_approval) now generates a `decision_id` (uuid4 hex), added to the Decision response, the audit record, and the SIEM decision event, so those three surfaces join on an exact key instead of a ts+session heuristic. `envelope_hash` (reusing `holds.canonical_hash()` — the `{action, axes, magnitude, target}` projection already used to bind a hold to its approval) is likewise carried into the audit record and SIEM event. Holds now store the `decision_id` of the decision that created them (`create_hold(..., decision_id=...)`), and a resolved approval resubmission carries `parent_decision_id` — either adapter-supplied via `approval.parent_decision_id` or, as a fallback, resolved from the consumed hold's `decision_id` — so `decision -> hold -> approval -> re-decision` is fully navigable. An opaque W3C trace-context string at `envelope.context.traceparent`, if present, is echoed verbatim into the audit record and SIEM event (no OpenTelemetry SDK, no spans — pure passthrough). All additions are additive/keyword-only with safe defaults; no decision verdict, decision logic, or existing field is changed. SPEC.md and ADAPTER-EXAMPLES.md gain a SHOULD: adapters propagate `decision_id` onto the executed effect (their own log / audit note) so the final link of the chain stitches too.

## [0.1.10] - 2026-07-06

PyPI publish path: `reeflex-claude` and `reeflex-holds` now ship through CI with SLSA provenance via PyPI Trusted Publishing. No runtime behaviour change to either package.

### Changed
- **`reeflex-claude` 0.1.7** — docs: README now states the **Python 3.8+** prerequisite and clarifies that R2/R3 are production-gated and that custom policy environments are supported (from #30). This is the first `reeflex-claude` release published to PyPI **through CI with provenance** (0.1.6 was published manually, without provenance).
- **`reeflex-holds` 0.1.1** — no functional change; the bump exists solely to cut the **first `reeflex-holds` release published to PyPI through CI with provenance** (0.1.0 was published manually, without provenance). Version bumped honestly to carry the provenance publish, since PyPI rejects re-publishing an existing version.

## [0.1.9] - 2026-07-06

n8n community node release-path fix. No change to any component's runtime behaviour.

### Fixed
- **`n8n-nodes-reeflex` now publishes with provenance (0.1.1).** The release workflow's n8n build failed because `npm ci` compiled `isolated-vm` (native, pulled transitively by `@n8n/node-cli`), which is not needed to build/lint/pack the node — so `npm ci --ignore-scripts` is used, and the npm publish job runs npm ≥ 11.5.1 and authenticates via npm OIDC Trusted Publishing (tokenless), which signs the `--provenance` attestation. The node keeps **zero runtime dependencies**. (The previously published `n8n-nodes-reeflex@0.1.0` had no provenance because it was published manually.)

## [0.1.8] - 2026-07-06

Core telemetry hardening for SIEM consumption (Wazuh integration + launch readiness). No decision-path behaviour change; the GHCR core image is rebuilt so `api-dev` runs a baked image rather than a container hotpatch.

### Added
- **Decision telemetry enrichment for SIEM.** The syslog decision event now carries `srcip` (caller IP from `X-Forwarded-For` / peer, named `srcip` so Wazuh GeoIP can enrich it), `namespace` + `agent_id` (the originating module/adapter — e.g. wordpress / claude / n8n), and `target_ref` + `params` (the executed command that produced the decision). The fire-and-forget, non-blocking decision-path invariant is unchanged.

### Fixed
- **Syslog TCP keepalive.** Enable `SO_KEEPALIVE` (plus Linux `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`, ~30s detection) on the syslog connection so a restarted collector (e.g. `wazuh-remoted`) is detected and delivery resumes, instead of silently dropping events on a half-open connection until the core container is restarted.

## [0.1.7] - 2026-07-05

Patch release for the **WordPress adapter** (`reeflex-gate` → 0.1.7). Other components unchanged from 0.1.6 (`reeflex-core` v0.1.5 on GHCR; PyPI/npm unchanged).

### Fixed
- **WordPress adapter — hold fan-out.** A single gated action triggered one `/v1/decide` call — and, when held, one hold — per *registered ability* instead of once, producing duplicate "Pending approvals" rows (the "Reeflex N" badge). A request-scoped decision memo collapses the permission-callback fan-out across all registered abilities to exactly one decision (one hold) per action. The guarantees are unchanged (actor ≠ approver, single-use holds, double-execution dedup).

## [0.1.6] - 2026-07-05

First multi-channel release: the Claude adapter, the holds MCP server, and the n8n community node ship to PyPI / npm alongside the GitHub release and the GHCR core image.

### Added
- **`reeflex-holds` MCP server (first release).** A FastMCP server exposing `list_holds` / `get_hold` / `resolve_hold` / `get_freeze_status` over reeflex-core's Holds API, so an MCP client (e.g. Claude Desktop) can be the approval surface. Env-configured (`REEFLEX_CORE_URL` / `REEFLEX_TOKEN` / `REEFLEX_PRINCIPAL` / `REEFLEX_VERIFY_SSL`); TLS-verify opt-out at parity with the adapters.
- **`n8n-nodes-reeflex` community node (first release).** The "Reeflex Gate" node (allow / hold / deny outputs) + "Reeflex API" credential, plus five importable, story-driven demo workflows preconfigured against the public api-dev eval endpoint — each with an embedded GIF of a real run.
- **reeflex-claude: `REEFLEX_VERIFY_SSL` + `REEFLEX_CORE_TOKEN`.** TLS-verify opt-out (user's risk, default on) and bearer auth, at parity with the WordPress adapter; enables dev/self-signed + authenticated core endpoints (e.g. `api-dev.reeflex.io`).

### Fixed
- **WordPress adapter — double-gating dedup (reeflex-gate 0.1.5).** An MCP-originated action gated twice (the ability's own gate + the MCP adapter layer) created two holds for one call; approving both re-ran the action twice. The adapter now deduplicates by canonical envelope hash + session within a tight creation-time window, so a double-gated action executes **at most once** — the second approval closes its record without re-executing. Corrected the wp-admin docblock/notice that wrongly claimed the companion approval never executes. Regression test (`hold-dedup-regression-demo.php`, D1–D8) added.
- **n8n demo 3 (approval loop).** Resolves holds with a `human` principal (api-dev's default resolution policy is human-only) with an id distinct from the actor (avoids `actor_is_approver`), and regenerates `meta.nonce` on resubmit (core rejects a reused nonce as a replay) — so the decide → hold → resolve → resubmit → allow loop runs end-to-end out of the box in a real n8n.

## [0.1.5] - 2026-07-04

### Added

- **HIL Phase 1: holds queue and resolution API.** `reeflex-core` now materializes `require_approval` verdicts as persistent holds (`app/holds.py`): event-sourced, append-only JSONL store (`audit/holds.jsonl`), in-memory index rebuilt at boot, lazy expiry. Three new HTTP endpoints share the same bearer auth as `/v1/decide`: `GET /v1/holds` (paged list, expiry sweep on list), `GET /v1/holds/{id}` (full detail including envelope), `POST /v1/holds/{id}/resolve` (approve or reject, four-step validation chain).
- **Approval principals: human, agent, automation.** All three types resolve holds via the same API. Shipped default: human-only for all rules (`REEFLEX_RESOLUTION_POLICY` absent). Operators configure allowed types per rule short-name via `REEFLEX_RESOLUTION_POLICY` (JSON string or file path). The `decided_by` field records `type:identity` verbatim (e.g. `human:leo`, `agent:triage-bot`, `automation:camunda-proc-123`) and is the EU AI Act Art. 14 oversight-allocation evidence.
- **Actor != approver, enforced in core.** The agent whose action raised the hold cannot resolve it on any surface via any principal type. Enforced both at resolve time (`POST /v1/holds/{id}/resolve` returns 403 `actor_is_approver`) and at resubmission time (`/v1/decide` returns deny `reeflex_hold_actor_is_approver`).
- **Systemic deny stays terminal.** `irreversible_systemic_prod` is always a terminal `deny`; it never creates a hold and is rejected at resolve time with 403 `rule_not_resolvable`.
- **Single-use, TTL-bound, action-hash binding.** Each hold stores the `sha256` of the action-defining projection (`action`, `axes`, `magnitude`, `target`). A modified action cannot ride an old approval. Holds expire after `REEFLEX_HOLD_TTL_SECONDS` (default 14400 s / 4 h). A consumed hold cannot be reused.
- **Kill-switch / freeze.** `REEFLEX_FREEZE=true` (or `1` / `yes`) denies all non-read verbs immediately with reason `"frozen by operator"`, rule `reeflex.policy/frozen`. Hot-reloadable — no restart required. Read verbs pass through. Freeze flips are audited and fire a webhook event.
- **Outbound hold webhook.** `REEFLEX_WEBHOOK_URL` (optional). Events: `hold.created`, `hold.resolved`, `hold.expired`, `freeze.flipped`. Fire-and-forget, bounded queue (default 1000 slots), drop-on-overflow, 3 s timeout, no retries, at-most-once. Never blocks `/v1/decide`. Enables BPMN/SOAR/n8n automation without vendor connectors — core builds the socket, not the engines.
- **`app/holds.py`**, **`app/webhook.py`** — new modules (Python stdlib only, no new dependencies).
- **`tests/test_hil.py`** — HIL Phase 1 test suite: T1 (hold store), T2a (freeze), T2b/T2c (approval decision path, OPA-dependent), T3 (holds HTTP API), T4 (webhook). OPA-dependent tests are skipped when OPA is absent, consistent with the existing pattern.

### Notes

- Core only. Adapters are unchanged in Phase 1. Phase 2 = adapter re-submission surfaces (WordPress admin, Slack notifier, CLI subcommands).
- Zero LLM in the decision path is unchanged. The `agent` principal type in the resolution policy is AIL: an AI judge the operator explicitly designates, recorded in the audit trail — the first decision (OPA/Rego) remains fully deterministic and LLM-free.
- The `/v1/decide` response gains `hold_id` and `expires_ts` only when the verdict is `require_approval` and hold creation succeeds.

## [0.1.4] - 2026-07-03

### Added
- **SIEM / syslog telemetry.** `reeflex-core` can stream every decision to a configured syslog endpoint — RFC 5424 over UDP (default), TCP (RFC 6587 octet-counted framing), or TLS (RFC 5425) — as structured JSON (default) or CEF. Consumed by Splunk, QRadar, Wazuh, FortiSIEM, Graylog, Grafana Loki, Datadog and friends with zero vendor connectors. Also emits engine lifecycle events; a kill-switch event type is designed for Phase 1. Disabled by default (`REEFLEX_SYSLOG_ENABLED=false`); configured entirely by env (`REEFLEX_SYSLOG_ADDRESS`/`_PROTOCOL`/`_FORMAT`/`_FACILITY`/`_TLS_VERIFY`). Python stdlib only — no new dependencies.
- **The telemetry invariant:** emission is fire-and-forget — a bounded in-memory queue, drop-on-overflow with a dropped-events counter, all socket I/O on a background daemon thread. It can never block or fail `/v1/decide`. "Fail-closed for decisions, fail-open for telemetry." The append-only audit JSONL stays authoritative. Verified: a dead / slow / unreachable endpoint adds zero decision latency.
- `docs/siem.md` — quickstart, the decision-event JSON schema, the CEF mapping + severity tables, and short consuming guides for 11 platforms (Splunk, QRadar, Wazuh, FortiSIEM, Graylog, Loki/promtail, Datadog, Logstash, Filebeat, Fluentd, and a Fluentd/Logstash/Vector → Kafka bridge). Guides only — no vendor code.

### Notes
- Adapters unchanged: the core emits, and observe-mode decisions flow through the same channel (observe + SIEM = "monitor mode").

## [0.1.3] - 2026-07-03

### Added
- **Observe mode (HIL-DESIGN §8, Phase 0)** in both adapters. WordPress: `REEFLEX_MODE` constant (`enforce`|`observe`, default `enforce`) + a Settings "Enforcement mode" dropdown (same locked-field precedence). Claude adapter: `REEFLEX_MODE=observe` env var. In observe, the adapter requests the decision and writes an audit record annotated `mode=observe` with the would-be verdict, but never enforces (the action always proceeds); a core outage **fails open** (never blocks). Enforce behaviour is unchanged. Zero core changes.
- Conformance harness gains observe scenarios (all actions proceed; core-down proceeds + outage audited); Claude adapter gains observe unit tests.

## [0.1.2] - 2026-07-02

### Changed
- **`reeflex-verify` — fresh agent session per run.** The CLI now sends a unique `Mcp-Session-Id`
  header on every run (override with `--session-id` to pin one). The core binds cumulative
  anti-fragmentation policy state to `session_id` (SPEC §4.1); without a fresh session, repeated
  runs against the same site accumulate into one per-session delete budget and eventually the gate
  holds even read-only actions (rule `reeflex.policy/session_delete_budget`), producing false
  mismatches. Validated 5/5 on a live WordPress site in both the standard and mu install forms.

### Docs
- `reeflex-verify/README.md` now shows a real clean-run screenshot (`docs/img/reeflex-verify-output.png`).
- `ROADMAP.md` records the open policy decision on R5 scope (all-verbs vs destructive-verbs-only).

## [0.1.1] - 2026-07-02

API hardening ahead of network exposure. The decision path is unchanged.

### Added
- **Optional bearer-token auth on `POST /v1/decide`** — set `REEFLEX_AUTH_TOKEN` to require
  `Authorization: Bearer <token>` (constant-time comparison). Unset/empty = disabled (backward
  compatible — identical behavior to 0.1.0). Missing or invalid token → HTTP 401, fail-closed.
  `GET /healthz` is always unauthenticated so liveness probes work without credentials.
- **Request body size cap** — `REEFLEX_MAX_BODY_BYTES` (default 256 KiB); oversized request → HTTP 413.
- **WordPress adapter — admin Settings page** — Settings > Reeflex Gate (API URL, Token, Verify TLS),
  with wp-config constants taking precedence over and locking the fields; bearer core token
  (`REEFLEX_CORE_TOKEN`) and an optional TLS-verify toggle (`REEFLEX_VERIFY_SSL`, default on; disable
  only for dev/staging certs such as api-dev.reeflex.io).
- **`reeflex-verify` CLI** — operator tool that fires real actions at a live install and prints the
  allow / hold / deny verdict per scenario. Transports over the system `curl` (browser UA + retry) so it
  works against WAF-protected sites, with UTF-8 output. Cross-platform (Windows / Linux / macOS).
- **Release packages** — the WordPress gate as `reeflex-gate-wordpress-standard.zip` and `-mu.zip`, plus
  `reeflex-verify.zip` (the CLI) and `reeflex-test-abilities.zip` (safe test abilities to exercise the gate).

### Security
- Suppressed the HTTP server version banner (no stack / Python-version disclosure).
- Added `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` to every response.
- Sanitized the `invalid_json` error response (no JSON-parser detail leaked to the client).
- Unsupported methods (PUT / DELETE / PATCH) → clean `405` JSON instead of the default HTML page.
- The container now runs as an unprivileged non-root user (uid 10001).

### Notes
- Decision path unchanged: determinism, fail-closed on OPA error, the five reference behaviors, and the
  55/55 engine + 9/9 policy tests all hold. Auth is off by default, so adapters and demos are unaffected.
- TLS termination, rate limiting, and DNS are handled at the deployment edge (reverse proxy), not in-engine.

## [0.1.0] - 2026-07-02

First public preview: the deterministic decision engine, its contract, a reference adapter, and onboarding.

### Added
- **Action Envelope & Adapter Contract** (`reeflex-spec/`) — the universal action shape (three axes:
  reversibility, blast_radius, externality), the four adapter responsibilities (intercept → normalize →
  enforce → audit), the Decision object, and the v0.1 conformance minimums.
- **`reeflex-core` decision engine** — `POST /v1/decide` (Python + OPA/Rego): envelope validation with
  fail-closed conservative defaults (non-canonical axis values coerce to most-restrictive), strict
  `magnitude.count`, required `agent.session_id`, a per-session cumulative ledger with a fragmentation
  guard (SPEC §4.1), and an append-only JSONL audit. Fail-closed on any OPA error — never `allow`.
  Zero LLM in the decision path. 55/55 engine tests; 9/9 policy tests.
- **Base policy pack (R1–R5)** — read-only-internal → allow; irreversible + broad + production →
  require_approval; irreversible + systemic + production → deny; default allow; session delete-budget
  fragmentation guard.
- **`reeflex-mock` reference adapter + demo** — a contract-conformant adapter over an in-memory store, and
  a five-scenario end-to-end demo (allow; single delete; bulk-delete requiring approval; fragmentation
  resistance; fail-closed on broken OPA) with store before→after read-back assertions.
- **Onboarding** — `INSTALL.md`, `QUICKSTART.md` (clone → "watch it stop a delete"), and per-component READMEs.
- **Architecture & decisions** — `docs/adr/0001-deployment-model.md` (engine-as-service, open-core,
  on-prem-first; hosted = roadmap), `docs/adr/0002-no-llm-in-decision-path.md`, `docs/open-core.md`,
  and `docs/architecture.md` (Mermaid diagrams).
- **Community health** — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md`,
  issue / pull-request templates, and a (not-yet-activated) CI workflow that runs `opa test` + the engine tests.

### Notes
- v0.1 is an early preview. Cryptographic signing of envelopes and audit records, a Postgres-backed
  audit/ledger, a live WordPress install on a real instance, the hosted tier, and an approval workflow are on the
  roadmap (see [ROADMAP.md](ROADMAP.md)) — not yet built. The Claude Code and WordPress reference adapters
  are included and conformance-tested.
- `reeflex-spec/` is the maintained source of truth for the Action Envelope, Adapter Contract, and conformance requirements.
