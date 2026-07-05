# Your AI agent has the same database access you do. That's the problem.

> Canonical version on dev.to (link pending)

Give an AI agent access to your systems and it inherits your permissions —
all of them. It can read every customer record, delete every product,
send every email, issue every refund. Not because it's malicious. Because
it's authenticated, it's authorized, and nothing between the agent and your
database asks the one question that matters:

**"Is this specific action safe to run, right now?"**

Your identity provider already checked *who* the agent is. Your guardrails
already checked whether the *prompt* was toxic. But a perfectly
authenticated agent, with legitimate permissions and a clean prompt, can
still run `DELETE FROM products` — and every layer you have says "looks
fine."

That gap is what we built Reeflex to close. It's open source (Apache-2.0),
it runs in front of your resources, and its entire decision policy is five
rules you can read in about a minute.

## The five rules

An agent wants to do something. Reeflex turns that action into a small,
boring description — what verb, how many things, reversible or not, does it
leave the system — and runs it past five rules:

- **R1 — reads pass.** Looking at data is allowed. The gate stays out of
  the way for the 95% of actions that are harmless.
- **R2 — big irreversible changes wait for a human.** Force-deleting a
  batch of products in production doesn't get blocked forever; it gets
  *held* until a person says yes.
- **R3 — system-wide destruction is refused outright.** "Delete
  everything" isn't a thing you approve. It's a thing you re-scope.
- **R4 — actions leaving your system wait for a human.** An outbound
  email, a payout, a refund — there's no undo button on the outside world,
  so those pause for a look.
- **R5 — the session has a budget.** More on this one below, because it's
  the rule that catches the clever attack.

Everything else is allowed. That's the whole policy. No machine-learning
risk score, no thousand hidden signatures — five rules, in plain readable
code, that you can audit in the time it takes to make coffee.

## The clever attack: death by a thousand small cuts

Here's the rule we're proudest of. Say your policy holds any bulk delete
over 20 items. An agent — misaligned, hijacked, or just confused by a bad
instruction — figures out it can delete 500 products by asking a hundred
times for 5 each. Every single request looks innocent. Under most systems,
all hundred go through.

Banks have caught this trick for fifty years. It's called *structuring*, or
*smurfing*: breaking one suspicious transaction into many small ones to
slip under the reporting threshold. Reeflex borrows the countermeasure
directly — R5 keeps a **cumulative budget per session**. The hundredth
batch of five trips the same limit the single batch of 500 would have.
Fragmenting a dangerous action buys the attacker exactly nothing.

None of these rules are invented. Each one is a decades-old safety
principle pointed at a new target: change management (R2), safety
engineering (R3), egress control (R4), transaction thresholds and fraud
velocity checks (R5). New rules for a new domain; old, proven ideas
underneath.

## What it deliberately does NOT catch

This is the part most security tools won't tell you, so here it is first:
**the base policy does not catch everything, and any tool that claims it
does is lying.**

- An agent reading 10,000 customer records is just a read. R1 allows it.
  That's exfiltration, and the base rules don't see it. (A mass-read guard
  is a natural extension — but it's not on by default, and we won't pretend
  it is.)
- Publishing one product at the wrong price is a single, reversible edit.
  Allowed. Correctness of content isn't something impact rules can judge.
- A patient attacker rotating across sessions dilutes the per-session
  budget.

The five rules govern *structural, destructive impact*, and they do it
well. They are a strong floor, not a ceiling. The policy is plain code —
read it in a minute, extend it in an afternoon.

We think saying this out loud is the whole point. A gate you can't inspect
isn't a gate you can trust.

## The other half: nothing happens in the dark

Two things make the rules usable in real life instead of just correct on
paper.

**Observe mode.** Turn Reeflex on and it changes nothing — it watches. Every
action gets a verdict written to the audit log, but everything still runs.
You get a report of what *would* have been held or denied, on your real
traffic, before you enforce a single thing. Install it on a Monday, read
what your agents actually did all week, then flip enforcement on with
thresholds you've already tuned. Zero risk to try.

**The decision is yours.** When a rule says "wait for a human," Reeflex
doesn't make the second call — it hands you the decision, with the context
to make it in five seconds. A human approves it, or an agent you designate ([AIL — agent-in-the-loop](../why-reeflex.md#ail))
does, or your existing approval workflow does. We flag; you rule. And every
handover is recorded: who approved what, when, under which rule. That record
happens to be exactly the evidence an auditor asks for.

The decision path itself has **zero LLM in it.** Same action in, same
verdict out, every time. We're not using AI to police AI — the whole point
is a layer that's boring, deterministic, and explainable.

## Try it in two minutes

The gate is free forever. Everything that keeps you safe — the engine, the
five rules, human approval, observe mode, the kill switch, audit, SIEM
export — is open source and always will be.

```
pip install reeflex-claude      # governs a Claude Code agent
npm i n8n-nodes-reeflex         # a gate node for your n8n workflows
```

Point it at the public evaluation endpoint, watch it decide, then run your
own engine when you're ready. The WordPress plugin governs WooCommerce
stores through the same five rules.

It's on GitHub at github.com/Reeflex-io/reeflex. Break it, fork it, tell us
where the rules are wrong. The clone that improves the rules is a clone
that improves the standard — and that's a trade we'll take every time.

*Reeflex — a seatbelt for the AI acting on your systems.*
