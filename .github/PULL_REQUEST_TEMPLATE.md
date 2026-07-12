## What and why

<!-- Describe what this PR changes and why.
     Link the issue it closes if applicable: Closes #NNN -->

## Tests run

<!--
Paste the raw output of both test commands.
Do not summarize — paste the actual terminal output.
-->

**Python unit tests** (`cd reeflex-core && python -m unittest tests.test_decide -v`):

```
(paste output here)
```

**OPA policy tests** (`opa test reeflex-core/policy/ -v`):

```
(paste output here)
```

## Determinism check

- [ ] No LLM, stochastic model, or free-text interpretation has been added to
      the `/v1/decide` decision path (engine, policy evaluation, envelope
      normalization).
- [ ] The fail-closed invariant is preserved: every error path in the decision
      pipeline produces `deny`, never `allow`.
- [ ] Conservative-default behavior is preserved: unknown axis values coerce to
      the most restrictive option and are never omitted.

## Docs updated

- [ ] CHANGELOG.md entry added (or N/A for trivial changes).
- [ ] Relevant docs (SPEC.md, QUICKSTART.md, README, CONTRIBUTING) updated if
      the change affects public-facing behavior.

## Boundary check

- [ ] No closed-tier content (Attest / Fleet / Cloud — compliance-evidence,
      multi-site-management, or hosted-operations code, or internal
      commercial-tier endpoints) is included.
- [ ] No secrets, credentials, API keys, or real PII are included. All examples
      use synthetic data.
- [ ] License headers and the root LICENSE file are unchanged (Apache 2.0 —
      never relicensed).
