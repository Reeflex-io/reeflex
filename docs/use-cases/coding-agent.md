---
title: "Use case: a coding agent on a production repo and infrastructure"
description: >-
  Claude Code (or any coding agent) with a shell on machines that reach
  production. The impact actions of a documented agentic attack, priced by the
  reeflex-claude classifier, and what the base pack decides for each.
---

# A coding agent on a production repo and infrastructure

## The situation

A team runs Claude Code with a shell on a box that can reach production — the
deploy host, a bastion, a developer laptop with production credentials. The
agent runs `git`, `kubectl`, `terraform`, `psql`, `mysql` as the human would,
and [reeflex-claude](../adapters/index.md), installed as Claude Code's
PreToolUse hook, prices each tool call before it runs.

## What goes wrong without a gate

A shell is the widest tool there is, and an agent uses it at machine tempo.
The impact phase of an incident is a handful of commands seconds apart, each
of which looks like ordinary database work on its own. The clearest public
record of that phase is **JADEPUFFER**, documented by the Sysdig Threat
Research Team on 1 July 2026 ([source](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)):
an LLM-driven agent that, against a Nacos configuration database, copied all
1,342 configuration items into an AES-encrypted table, dropped the original
`config_info` and `his_config_info` tables, and created a `README_RANSOM`
table with the demand.

!!! warning "JADEPUFFER was an attacker's agent"

    It ran on infrastructure the attacker had taken over through an
    unauthenticated code-execution flaw in Langflow (CVE-2025-3248). It
    called nobody's gate, and **nothing on this page would have been in its
    path**: Reeflex governs the agents you route through it, not an intruder
    with code execution on your host. The statements are used here because
    they are a documented, real sequence of impact actions by an LLM-driven
    agent — the same shape an agent *you* run can produce by mistake, or under
    prompt injection, through a shell that is gated.

## Three representative actions

The three JADEPUFFER impact statements, issued as a coding agent would issue
them — `mysql -e` through the Bash tool — and priced by reeflex-claude's own
classifier. Each envelope is what `reeflex_claude.envelope.build_envelope`
emits, trimmed of transport fields (`meta`, `context`).

**The encrypting copy.** `CREATE TABLE … AS SELECT` creates a new table and
changes no existing row. The classifier prices it recoverable/scoped and the
pack allows it. It is the step that makes the data unreadable *once the
original is gone* — and on its own, it is not destructive.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:claude-code/sess-7f3a", "session_id": "claude:sess-7f3a" },
  "action":    { "namespace": "claude-code", "verb": "execute", "ability": "claude-code/Bash" },
  "target":    { "kind": "command", "ref": null, "environment": "production" },
  "params":    { "tool_name": "Bash",
                 "verb_source": "bash_intent_parse:mysql -h 10.0.4.12 nacos -e \"CREATE TABL" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal" },
  "approval":  { "present": false }
}
```

**Dropping the original table.** `DROP TABLE` is recognised by the classifier
(`sql_drop_table`) and priced irreversible/broad. In production that is R2: the
command waits for a person.

**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`

```json
{
  "agent":     { "id": "agent:claude-code/sess-7f3a", "session_id": "claude:sess-7f3a" },
  "action":    { "namespace": "claude-code", "verb": "delete", "ability": "claude-code/Bash" },
  "target":    { "kind": "resource", "ref": null, "environment": "production" },
  "params":    { "tool_name": "Bash",
                 "verb_source": "bash_intent_parse:mysql -h 10.0.4.12 nacos -e \"DROP TABLE " },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "broad", "externality": "internal" },
  "approval":  { "present": false }
}
```

**Creating the ransom-note table.** A new, empty table. Allowed.

**Verdict:** `allow` · **rule** `reeflex.policy/default_allow`

```json
{
  "agent":     { "id": "agent:claude-code/sess-7f3a", "session_id": "claude:sess-7f3a" },
  "action":    { "namespace": "claude-code", "verb": "execute", "ability": "claude-code/Bash" },
  "target":    { "kind": "command", "ref": null, "environment": "production" },
  "params":    { "tool_name": "Bash",
                 "verb_source": "bash_intent_parse:mysql -h 10.0.4.12 nacos -e \"CREATE TABL" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "recoverable", "blast_radius": "scoped", "externality": "internal" },
  "approval":  { "present": false }
}
```

Read the three together: **one of the three steps is held, and it is the one
that cannot be undone.** That is the design — the gate prices the destruction,
not the intent — and it is also the limit: an agent that only ever copied data
out and never dropped anything would not have met this rule at all.

For contrast, a command that would take the database's data directory with it
is refused outright, with no approval path:

**Verdict:** `deny` · **rule** `reeflex.policy/irreversible_systemic_prod`

```json
{
  "agent":     { "id": "agent:claude-code/sess-7f3a", "session_id": "claude:sess-7f3a" },
  "action":    { "namespace": "claude-code", "verb": "delete", "ability": "claude-code/Bash" },
  "target":    { "kind": "command", "ref": "/var/lib/pgsql", "environment": "production" },
  "params":    { "tool_name": "Bash", "verb_source": "bash_intent_parse:rm -rf /var/lib/pgsql" },
  "magnitude": { "count": 1 },
  "axes":      { "reversibility": "irreversible", "blast_radius": "systemic", "externality": "internal" },
  "approval":  { "present": false }
}
```

## How to deploy it

```bash
pip install reeflex-claude
reeflex-claude setup     # writes the fail-closed PreToolUse hook into .claude/settings.json
reeflex-claude check
```

`setup` writes `REEFLEX_CORE_URL` and `REEFLEX_MODE=enforce` into the hook's
environment. The line that matters after that is **`REEFLEX_CLAUDE_ENVIRONMENT`**:
it defaults to `production`, which is the safe default and the reason the
envelopes above arm R2 and R3. On a box that genuinely only reaches staging,
setting it to `staging` turns those two rules off for that box — set it
deliberately, not to make a hold go away. Full adapter guide:
[Adapters](../adapters/index.md).

## What Reeflex does NOT do here

- It does not stop an intruder. An attacker with code execution on the host
  runs their own agent and calls no gate (see the JADEPUFFER note above).
- It does not read data flows. The encrypting copy and any exfiltration by
  `SELECT` are reads and creates; they count toward session budgets and are
  not held on their own.
- It does not parse every SQL statement or script. The classifier reads the
  command line; a destructive statement inside a `.sql` file passed with
  `-f`, or inside a script the agent wrote a minute earlier, is priced by what
  the command line shows.
- It does not see actions that do not go through the Claude Code tool call —
  a cron job the agent installed, a CI pipeline it pushed to.
- It is no more fail-closed than Claude Code's hook runner. The runner lets a
  tool run if the hook crashes, prints something other than a well-formed
  verdict, or overruns the `settings.json` timeout. reeflex-claude answers
  inside its own deadline to stay clear of that, but the runner's behaviour is
  Claude Code's, not ours. The measured table is in the reeflex-claude README,
  under "The gate is no more fail-closed than the hook runner".
