---
title: "Evidence for auditors — Reeflex attests, your auditor certifies"
description: >-
  What a Reeflex evidence report proves about your AI-agent governance control,
  which frameworks it maps to, the three words we refuse to use loosely, and
  exactly what lands in an auditor's hands.
---

# Evidence for auditors

**Reeflex attests. Your auditor certifies.**

That sentence is the whole design, so it is worth being blunt about what it
rules out. Reeflex does not make you compliant with NIS2, DORA, the EU AI Act,
or anything else. It does not keep you compliant. It has no opinion on whether
you pass your audit, and nothing it produces is legal advice.

What it does is narrower and more useful: it produces **the evidence that your
governance control over AI-agent actions was operating** — an append-only
record of every action an agent attempted, what the gate decided, which rule
decided it, and who, if anyone, approved it — **plus the gaps we detect in that
evidence, and a written statement of what we do not cover.**

Your auditor takes it from there. That is their job, and it is not one we can
do for you.

## Why the honest version is the stronger one

Every vendor in this category says "compliance". Nobody in a procurement
meeting believes it, because the claim is unfalsifiable — there is no test a
buyer can run that would come back negative.

So we do the opposite, and it is a commercial argument, not a hedge:

**We publish our seams.** This page tells you which of the three adjectives
usually attached to audit records survives an outside check, which one is half
true, and which one is not true in the way you would assume. It tells you which
frameworks the engine assesses today and which are a draft mapping we have not
shipped. The report itself carries the same limits, in the same words, in a
section the auditor reads before the evidence.

**Because we say what we cannot show, what we do show is checkable.** A
security architect who reads a document with no limits in it learns nothing
about the product. A document that names its limits precisely is one where the
remaining claims can be tested — and those are the claims we want tested.

**The decisions underneath are deterministic, so they can be replayed.** The
gate is OPA/Rego and classic logic with no language model anywhere in the
decision path ([ADR-0002](../adr/0002-no-llm-in-decision-path.md)). Same action
envelope in, same verdict out. An auditor does not have to accept the log's
account of why an action was denied; they can put the same envelope through the
same policy and watch it deny again. That is a property very few AI-governance
records have, and it is why the evidence is worth producing at all.

---

## Mapped is not shipped

!!! warning "Read this before the table below"

    Two different things are described on this page and they must not be
    confused.

    **The mapping** is a draft specification covering **seven frameworks**. It
    is a working document. It is not a product you can generate a report from.

    **The engine** — the thing that reads your evidence and produces an
    auditor's report today — assesses **three controls**: NIS2 Article 21(2),
    EU AI Act Article 12, and EU AI Act Article 14. That is the list. It is
    short on purpose.

    If you buy Reeflex Attest today, you get reports over those three. The
    other frameworks in the table are mapped, not shipped, and the table says
    so on every row.

## Framework coverage

### Legend

| Label | Meaning |
|---|---|
| **Evidences** | Reeflex records directly attest that this control operated. |
| **Partial** | Reeflex attests one aspect; other evidence is needed for the whole control. |
| **Not evidenced** | Outside Reeflex's scope. Listed so the map is honest, not padded. |

### The map

| Framework · obligation | In the engine today | Coverage | Not evidenced |
|---|---|---|---|
| **NIS2 Article 21(2)** — cybersecurity risk-management measures | **Assessed today** | **Partial** | Business continuity and backup (c) · supply-chain security (d) · security in acquisition and development, vulnerability handling (e) · cyber hygiene and training (g) · MFA and secured communications (j) |
| **DORA Article 9** — protection and prevention | Mapped — not in the engine | **Partial** | Cryptographic key management · secure data transfer · resilience and continuity |
| **EU AI Act Article 12** — record-keeping (logging) | **Assessed today** | **Evidences** — for agent-action events | The AI system's own internal telemetry. This is a record of what actions were attempted and how each was decided, not a model trace. |
| **EU AI Act Article 14** — human oversight | **Assessed today** | **Evidences** — the oversight allocation trail | Oversight exercised somewhere Reeflex cannot see. A decision taken outside the holds inbox is reported as resting on the audited party's word. |
| **EU AI Act — the rest of it** (Art. 9 risk management, Art. 15 accuracy and robustness, Art. 50 transparency, conformity assessment) | — | **Not evidenced** | All of it. Reeflex evidences two articles of this regulation and makes no claim about the others. |
| **SOC 2** — CC6.1 logical access, CC8.1 change management | Mapped — not in the engine | **Partial** | User and identity provisioning · physical access · the full design → test → deploy change lifecycle |
| **HIPAA Security Rule** — 45 CFR §164.312 / §164.308 | Mapped — not in the engine | **Partial** | Physical safeguards (§164.310) · workforce security · contingency planning · the application's own ePHI-access telemetry |
| **NIST SP 800-53 Rev. 5** (with a CSF 2.0 note) | Mapped — not in the engine | **Partial** | Contingency planning (CP) · physical (PE) · personnel (PS) · broad SC / RA · **AU-10 non-repudiation**, which the records do not support today — see [the three adjectives](#the-three-adjectives-taken-apart) |
| **CIS Controls v8** | Mapped — not in the engine | **Partial** | Asset and software inventory (1, 2) · vulnerability management (7) · malware defences (10) · data recovery (11) · network infrastructure (12) · awareness training (14) |
| **Backups · physical and personnel security · the SDLC · patch management · network security · security-awareness training** | — | **Not evidenced** | In every framework above. Reeflex governs what an agent does to your systems at run time. It is one control point, and it sits beside your others rather than replacing any of them. |

**The right-hand column is the point of the table.** Reeflex is an
action-governance control. It evidences the slice of each framework that is
about *what an automated actor was allowed to do, who approved it, and what
stopped it* — and it is silent about the rest of the framework, by design. A
map with no empty cells in it would be a map nobody should trust.

The per-article mapping behind each row — which specific field of the decision
record backs which specific obligation, the scope note attached to each
control, and the reasoning for each coverage label — is part of the commercial
[Attest](../open-core.md#attest-audit-ready-control-evidence) tier and is not
published here.

### Why NIS2 and DORA lead, and the AI Act follows

**NIS2 Article 21(2) is a present obligation, not a future one.** It is
transposed into national law across the EU, essential and important entities
are being audited against it now, and a documented record of risk-management
measures operating is the kind of thing those audits ask for. That is where the
evidence is needed this quarter.

**DORA has applied to EU financial entities since January 2025**, and Article
9's protection-and-prevention duties — continuous control of ICT operations,
preventing unauthorised or high-impact actions, authorising changes before they
execute — describe an agent gate almost line for line. It is mapped and it is
the next control we intend to ship; it is not in the engine today.

**The EU AI Act's Articles 12 and 14 are the one we are ready early for.** The
Digital Omnibus (Regulation (EU) 2026/1744, in force 27 July 2026) moved the
Chapter III high-risk obligations for Annex III systems — including
record-keeping and human oversight — from 2 August 2026 to **2 December 2027**.
Article 50 transparency is unaffected and applies now. So the Art.12/14
evidence Reeflex produces is preparation ahead of a deadline rather than a
response to an audit happening today, and we would rather say that than let you
discover it later.

---

## The three adjectives, taken apart

Audit records get described as "signed, timestamped and append-only" so
routinely that the phrase has stopped carrying information. We took the three
words one at a time and checked each against what the system actually does. One
survives, one is half true, and one is true of something other than what you
would assume.

### Append-only — true, and enforced below the application

The evidence store is append-only, and that is enforced at the **database grant
level**: the runtime role holds `INSERT` and `SELECT` and holds neither
`UPDATE` nor `DELETE`. There is no HTTP surface that removes a record. This is
not application code that could be bypassed by a bug in application code — it
is a property of the database role the application connects as, and it is
verifiable on the production database.

**The limit, stated:** this is a claim about the runtime, not about the
database as a whole. An operator's admin plane can delete a whole tenant's
records; that action is itself audited, and no grant described here prevents
it.

### Signed — one signature per delivery, and nobody can re-check it afterwards

Records arrive over a signed wire. What that signature is, precisely: **one
HMAC computed over an entire delivery of records**, stored on every record in
that delivery, keyed with the evidence key the app hands you when you register
a gate.

Three consequences, all of which we would rather you hear from us:

- It authenticates **who sent a delivery**. It says nothing about whether the
  contents of any individual record are true.
- It is symmetric — you hold the same key we verify with — so it cannot carry
  non-repudiation. It could not settle a dispute about who did what.
- Its signed input is not persisted, so **after ingest nobody can re-verify it,
  including us**. It was checked once, at the door.

We do not write "each record is signed", and the report does not print a
per-record signature column, because a value shared across every record of a
delivery is not a property of a record and rendering it as one teaches the
reader something false.

**On the roadmap, not shipped:** per-record **Ed25519** signing, which is what
a control like NIST AU-10 actually asks for — a holder of the public key could
then verify a record without trusting us at all. The `sig_alg` field on every
record is already versioned so that older rows stay readable under the scheme
they were signed with when this lands.

### Timestamped — half true, and the true half is ours

Every record carries two times, and the difference between them matters.

`occurred_ts` is **the time the gate declared** the decision was taken. It is
validated for shape and nothing else. It is your system's account of its own
clock.

`received_ts` is **the time our server observed the record arriving** — a
database default that no gate token can set. That one is ours.

Both are carried, and both are printed side by side, labelled, in every export
format. So the honest sentence is: *Reeflex can tell an auditor when a record
arrived; it cannot tell them when the decision was taken.* Most of the time the
two are seconds apart and the comparison is uninteresting, which is exactly why
it is worth printing — the interesting case is the one where it is not.

### And a fourth, while we are here

Each record also carries an `envelope_hash`, a fingerprint of the action
computed inside the gate. The algorithm is public and open-source. The
pre-image is not transmitted, so **no party — us included — can recompute that
hash from a report.** It is checked for well-formedness and treated as a label
for an action, not as proof about a record. Making it recomputable is a
separate roadmap item from the Ed25519 work above, and neither has shipped.

---

## What an auditor actually receives

A report is generated for one organisation over one period, and it comes out in
**four formats — Markdown, JSON, CSV and PDF**. All four are renderings of the
same assembled object; none of them re-queries anything, so they cannot
disagree about the facts.

### The six sections

1. **Header and disclaimer.** Organisation, period, generation time, engine
   version, and the attests-not-certifies statement in full. It is carried by
   every one of the four formats and tested per format.
2. **Scope and completeness.** Which registered gates were in scope, and a
   plain statement that Reeflex reports what it received and cannot see what a
   gate never sent. The auditor reads the limits of the population before they
   read the population.
3. **Per control.** Framework, article, coverage label, the scope note, the
   count, the evidence chain as a navigable table of records, the metrics, and
   the gaps detected for that control. Each control also states its
   **attestation basis** input by input — which values are your own account and
   which ones we hold an independent record of.
4. **Gap summary — the auditor's worklist.** Every gap across every control,
   most severe first.
5. **Verifiability, and its limits.** What each anchor on a record does and
   does not establish, written under a heading that names the limit rather than
   promising more than the anchors deliver.
6. **Auditor certification.** A blank block — name, organisation, the reviewed
   report hash, date, signature — for the reviewing auditor to complete and
   retain. Reeflex neither pre-fills nor validates it.

### The cap, and why it is honest

A control emits one gap per offending record, so a busy month can produce tens
of thousands of findings. Rendering all of them produced a PDF that took over
two minutes and 1.5 GB of memory to build, behind a 90-second proxy timeout —
that is to say, a report the auditor never received.

So the two prose formats cap the worklist at the most severe 50 (Markdown) and
40 (PDF). Three properties keep that cap from becoming a second overclaim, and
all three are asserted by tests:

- **The list is sorted by severity before it is cut**, so a high-severity
  finding a control happened to emit last is still in the document that gets
  emailed.
- **The withheld count is stated per severity.** "+33,300 further findings"
  can never quietly stand in for 33,300 high ones.
- **The JSON download carries every gap, uncapped** — and the JSON is the
  pre-image of the report hash, so what the hash attests to is the complete
  set, not the abridged one. The CSV is uncapped too; it carries the evidence
  chain and being the full-fidelity export is its job.

### The report hash

The package carries a **`report_hash`**: a SHA-256 over the canonical JSON of
the whole assembled report. It is identical across all four formats, and anyone
holding the JSON download can recompute it with no Reeflex account and no API
call — drop the `report_hash` field, canonicalise what remains, hash it,
compare.

**What it establishes:** that the four downloads describe the same package, and
that a reader who wrote the hash down can detect a later change to the file
they were given.

**What it does not:** it is not a signature. There is no key. Nothing in it
binds the package to Reeflex, and someone who edits a copy of the JSON can
recompute a hash that passes the same check. Treat it as an identifier for the
package, not as proof of where it came from.

---

## What we detect: the gap vocabulary

The gaps are the part of the report a serious auditor reads first, because a
report with no gaps in it is either a very quiet month or an instrument that
cannot see. Today the engine emits **seventeen gap codes** across the three
controls, six of them at high severity.

The ones that tend to matter most:

- **A production action was approved with no human approver recorded.** It was
  gated, it was approved, and the approval is not attributed to a person.
- **Two sources disagree about who decided a hold, and how.** Your gate's
  evidence says one thing; our own append-only record of what a human clicked
  in the holds inbox — a table no gate token can write — says another. The
  report prints both, quotes the human's written reason, and states which one
  Reeflex believes.
- **A human exercised oversight and it did not take effect.** We hold a
  recorded human decision, and the gate reports that the engine refused to
  apply it. The action stays blocked and the hold still needs a decision — this
  is oversight that happened and did not land, which looks like success from
  every other angle.
- **An approval was granted for one agent and spent by another.** An approval
  that binds an action but not an actor is spendable by any agent sharing the
  deployment.
- **A resolution Reeflex cannot corroborate.** A production hold reported
  resolved on the gate's word alone, with no record of it in our holds inbox.
  This is not an accusation. It is the honest statement that we cannot
  corroborate that a human exercised oversight there — and without it, an
  attacker would need exactly one step: fabricate against a hold nobody
  resolved here, and there is nothing to contradict.

??? note "The full vocabulary — all seventeen codes"

    **EU AI Act Art.12 — record-keeping**

    | Code | Severity | What it means |
    |---|---|---|
    | `ART12_NO_RECORDS` | medium | No evidence in the period. Reeflex cannot distinguish "no agent action was decided" from "no gate delivered anything" — read it against the gate roster in the scope section. |
    | `ART12_INTEGRITY` | high | A record's integrity anchor is not the shape the report claims it is. |
    | `ART12_UNKNOWN_SIG_ALG` | medium | A record declares a signing scheme this engine cannot shape-check. Reported as unverifiable rather than as passed or failed. |

    **EU AI Act Art.14 — human oversight**

    | Code | Severity | What it means |
    |---|---|---|
    | `ART14_PROD_NO_HUMAN_APPROVER` | high | A production action was gated and approved, and no human approver is recorded. |
    | `ART14_RESOLUTION_CONTRADICTED` | high | The gate's evidence and Reeflex's own record disagree about who resolved a hold and how. Both are printed; Reeflex reports its own. |
    | `ART14_EXPIRED_HOLD_REPORTED_RESOLVED` | high | The gate reports a resolution for a hold whose deadline had already passed with no decision recorded here. |
    | `ART14_RESOLUTION_REFUSED_BY_CORE` | high | A recorded human decision that the engine refused to apply. Oversight exercised, and not effective. |
    | `ART14_APPROVAL_SPENT_BY_ANOTHER_AGENT` | high | The approval was raised for one agent and consumed by another. |
    | `ART14_APPROVER_CONTRADICTED` | medium | Both sources agree on the outcome and name a different human. |
    | `ART14_UNCORROBORATED_RESOLUTION` | medium | A production hold reported resolved on the gate's word alone. |
    | `ART14_UNRESOLVED_PROD_HOLD` | medium | A production hold raised and never resolved — oversight interposed, not exercised. |
    | `ART14_EXPIRED_PROD_HOLD` | medium | A production hold that timed out with no human decision before its deadline. |
    | `ART14_UNCLASSIFIED_ACTION_HELD` | medium | Held because the gate could not classify the action, not because a rule identified a risk. Counted separately so it cannot read as evidence that the control caught something. |
    | `ART14_RESOLUTION_MISSING_FROM_EVIDENCE` | medium | Reeflex holds a human decision for a hold whose evidence is absent from the period entirely. |
    | `ART14_RESOLUTION_NOT_ACKED` | info | Reeflex recorded a human decision and the gate's evidence carries no resolution for it. Expected briefly; worth investigating otherwise. |

    **NIS2 Art.21(2) — risk-management measures**

    | Code | Severity | What it means |
    |---|---|---|
    | `NIS2_ESCALATION_NOT_IN_THE_PORTAL` | medium | Records report an action escalated to a human, and the holds inbox never received the hold. Either the push failed or no human was ever given the decision. |
    | `NIS2_NO_DENY_COVERAGE` | info | No denials or approvals required in the period — either nothing risky occurred or the policy did not gate. For the auditor to interpret, not for us to assert. |

---

## The one thing no arrangement of this can do

**Reeflex cannot detect a fabricated record.** A record describing an action
that never happened, pushed over the real signed wire with a real gate token,
is indistinguishable from a true one by construction: we receive an account of
an event we did not witness.

We are not going to pretend otherwise, and we are not going to ship a detector
that would also fire on honest data. What we do instead is shrink every claim
to what its inputs support, per input, where the auditor can see it. Where a
count rests on your own gate's account and nothing else, the report labels it
**self-attested** rather than dressing it as evidence. Where we hold an
independent record — what a human actually clicked in the holds inbox, when our
server observed a delivery, which registered gate sent it, the append-only
grant itself — the report says so and reconciles against it.

That distinction is printed in every format, on every control, and it is the
reason an auditor can use the document at all.

---

## Where to go next

- **[Compliance & open core](index.md)** — why NIS2 is the current driver and
  how the licensing boundary is drawn.
- **[Open-core boundary](../open-core.md)** — what is Apache 2.0 and free
  forever, and what the commercial Attest tier adds. Everything that keeps you
  safe is open; what you pay for is help proving it.
- **[No LLM in the decision path](../adr/0002-no-llm-in-decision-path.md)** —
  the architectural decision that makes a decision replayable.
- **[SIEM export](../siem.md)** — getting the same decision stream into the
  tooling your SOC already runs.

*Reeflex produces evidence. Your auditor decides what it is worth. We would
rather you find the limits on this page than in the meeting.*
