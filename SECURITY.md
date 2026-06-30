# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue to report a security vulnerability.**
Public disclosure of an unpatched vulnerability puts all users at risk.

Report privately by emailing **security@reeflex.io**. If you prefer
end-to-end encryption, request a PGP key in your first email and we will
provide one.

### What to include

- A clear description of the vulnerability and its potential impact.
- Affected component(s) and version(s) (see the supported versions table
  below).
- Steps to reproduce, or a minimal proof-of-concept. The more specific the
  better; vague reports are harder to triage.
- Your assessment of severity and exploitability, if you have one.
- Whether you intend to publish and, if so, your preferred disclosure
  timeline.

### What to expect

We will acknowledge receipt within **5 business days** and aim to provide
an initial assessment within **14 calendar days**. We will keep you
informed as we work toward a fix. We will coordinate disclosure timing with
you before publishing any advisory.

---

## Supported versions

| Version | Status | Security fixes |
|---|---|---|
| 0.1.x | Early / active development | Best-effort — no SLA at this stage |

Reeflex 0.1.x is pre-release software under active development. We will
apply security fixes on a best-effort basis. We are not yet in a position
to commit to a defined remediation SLA. We will state that explicitly here
and update this table as the project matures.

---

## Scope

The following are in scope for responsible disclosure:

**Engine — reeflex-core**

- Behavior of `POST /v1/decide` that would cause it to return `allow` when
  the correct decision is `deny` or `require_approval` (fail-open
  vulnerabilities are the highest priority).
- Bypass of the fail-closed invariant — any path by which core returns
  `allow` when OPA evaluation fails or is unavailable.
- Injection or manipulation of the Action Envelope in ways that cause a
  policy to be evaluated against attacker-controlled data.
- Replay of a previously-decided envelope that bypasses the nonce
  (`meta.nonce`) check.

**Adapters — normalize / enforce**

- An adapter that fails to enforce a `deny` or `require_approval` decision
  (i.e., proceeds with the action anyway).
- Normalization logic that maps a high-risk action to a lower-risk axis
  value, causing an action to bypass a rule it should trigger.
- Fail-closed bypass in the adapter — any code path where the adapter
  silently allows an action when core is unreachable or returns an error.

**Conformance contract**

- A conformance test case that passes for an adapter that is actually
  non-conformant (false positive in the suite).

Out of scope: denial-of-service via resource exhaustion, the OPA binary
itself (report those upstream to the OPA project), or any component in the
commercial closed tier (which is not hosted in this repository).

---

## Audit trail signing

The current implementation writes append-only JSONL audit records per
decision. Tamper-evident signing of audit records (ed25519, with
Vault-backed key management) is on the roadmap but is not implemented yet.
We do not claim cryptographic integrity for audit records in v0.1.x. This
is noted in the spec (SPEC §6) and the ROADMAP.

---

*Reeflex — governance that isn't another AI.*
