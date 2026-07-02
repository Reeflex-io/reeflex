# reeflex-mock

The worked example for adapter authors. A complete, runnable Reeflex adapter
against an in-memory store — small enough to read in one sitting, real enough
to demonstrate every contract responsibility from
[SPEC §6](../reeflex-spec/SPEC.md): **intercept → normalize → enforce → audit**.

If you are writing your own adapter, start by reading these three files in
order:

| File | What it shows |
|---|---|
| `store.py` | The "backend" being protected — an in-memory record store |
| `agent.py` | A scripted agent that attempts reads, deletes, and bulk deletes |
| `adapter.py` | The adapter itself: builds the Action Envelope, calls `POST /v1/decide`, enforces the decision, writes the audit JSONL |

## Run the demo

From the repo root (no server needed — the demo starts `reeflex-core` itself):

```bash
python reeflex-mock/demo.py
```

The demo runs five scenarios and prints the decision for each: a read (allow),
a single delete (allow), a bulk force-delete (require_approval), a systemic
delete (deny), and a fail-closed check against a dead core (everything
blocked). It verifies the store contents before and after each action, so you
can see that held and denied actions genuinely never executed.

A full walkthrough of the output is in [../QUICKSTART.md](../QUICKSTART.md).

## Files generated at runtime

`adapter-audit.jsonl` and the `demo-*-audit.jsonl` files are append-only audit
logs written by demo runs — one JSON record per decision. They are artifacts,
not source.
