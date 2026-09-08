# The recorded run

One `./run.sh`, 2026-09-08, 11:50–11:52 EEST, on the Reeflex devbox. Live
against `app.reeflex.io` (`reeflex-app:main-dbfe954`) on a tenant created for
this walk, and against a `reeflex-core` container pinned by digest
`sha256:58a0a531dfa1…845b` — the same published image `api-dev.reeflex.io`
runs, with `REEFLEX_REQUIRE_VERIFIED_APPROVER` left at its shipped default.

| file | what it is |
|---|---|
| `transcript.txt` | the terminal, verbatim, 450 lines. **It carries ANSI colour codes** — `cat` it or `less -R` it; an editor will show the escapes. |
| `shots/step3-holds-inbox.png` | `/app/holds` with the gateway's hold pending: verb, gateway, item count, environment, deadline, gate name, the requesting agent identity, the rule and its sentence, and the Approve / Deny controls. |
| `shots/step4c-approve-control.png` | the same render, taken immediately before the click. It is byte-identical to the shot above because the control was already in view — kept as a separate file only so the step numbering in the transcript maps to a file, not to imply a second moment. |
| `shots/step4d-approved.png` | after the click. The card has lost its Approve/Deny controls and reads `ALLOW resolved by alice.approver@acme.example at 2026-09-08 08:52 UTC`. |
| `shots/step4-wire.json` | every request the browser made to a Reeflex route during step 4, off Playwright's `page.on("response")` — including `POST /app/holds/<id>/resolve 200`, which is the approval. |
| `shots/step6-attest-report.png` | the Attest report page after generating over the walk's period. |
| `shots/step6-attest-report.json` | that report, downloaded through `GET /app/attest/download?report_id=&format=json`. |

## What is in here that is worth reading first

**The step-4 wire log**, because it is the shortest proof that a person's click
is what resolved the hold rather than a script calling an API:

```json
[{"method": "GET",  "url": "/app/holds", "status": 200},
 {"method": "GET",  "url": "/app/holds/badge", "status": 200},
 {"method": "POST", "url": "/app/holds/<hold_id>/resolve", "status": 200}]
```

**The Article 14 rows in the report**, because one of them is a contradiction
the report is right to raise — the gate names the approver by the email
`reeflex-core` verified against their credential, the portal names the same
person by its internal id, and the report says so instead of quietly picking
one. `README.md` in the parent directory explains it under step 6.

## What is NOT in here

* **No secrets.** Scanned before committing: none of the run's five generated
  credentials (core's auth token, the approver's resolver token, the proxy's
  master key, the tenant's gate token, the tenant's evidence signing key)
  appears in any file here. The long hex strings in the transcript are an
  envelope hash, the core image digest, and LiteLLM's deployment id.
* **No staged image.** Every screenshot is a headless Chromium render of the
  live application at that moment in the run. If a step could not be walked,
  the transcript says NOT RUN; it never shows a picture instead.
* **No latency table.** That measurement belongs to `reeflex-litellm` and is in
  that package's README, taken with a harness built for it.

## Two things in the transcript are negative results, on purpose

* **`5b`** — an approval granted after the gateway's wait window closes cannot
  be spent. The retry raises a second hold and the human's real decision sits
  `approved, consumed_ts: null` forever.
* **The `ping` and `get_weather` rows** in the discrimination table — harmless
  calls, held under the same rule as `run_sql {"query": "DROP TABLE
  customers"}`, which is what stops that row being read as the gate having
  understood the SQL.

A run that only printed the rows we liked could not be audited.
