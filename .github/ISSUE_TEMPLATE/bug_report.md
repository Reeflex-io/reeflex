---
name: Bug report
about: Report incorrect behavior in the engine, an adapter, or the conformance suite
labels: bug
---

## What happened

<!-- Describe what the engine or adapter did. Be specific. -->

## Expected behavior

<!-- Describe what you expected to happen instead. -->

## Steps to reproduce

<!--
Provide the minimum steps to reproduce the issue.
If the issue is in the decision pipeline, include the exact envelope you sent.
-->

1.
2.
3.

## Envelope and decision (if relevant)

<!--
If the bug involves an incorrect allow/deny/require_approval decision,
paste the Action Envelope you submitted and the Decision you received.
Omit any real PII or credentials — use synthetic values.
-->

**Envelope sent:**
```json

```

**Decision received:**
```json

```

**Decision expected:**
```json

```

## Environment

| Item | Version |
|---|---|
| OPA version (`opa version`) | |
| Python version (`python --version`) | |
| OS | |
| reeflex-core commit or tag | |
| Adapter (if applicable) | |

## Additional context

<!-- Anything else relevant: log output, audit JSONL entries, error messages. -->
