# Why Reeflex — and how it fits next to what you already run

Three different questions get asked before an AI agent touches your systems.
Most of the stack answers the first two. Reeflex exists for the third.

1. **"Who is this agent, and what may it access?"** — identity and
   authorization. Answered at the source by agent-identity platforms and
   policy engines (Microsoft Entra Agent ID, AWS Bedrock Guardrails, Cerbos,
   Permit.io, OPA-based authorization).
2. **"Is this prompt or output harmful?"** — content safety. Answered by
   LLM guardrails, probabilistically, on text.
3. **"Is this specific action safe to run, right now?"** — impact. A
   perfectly authenticated agent, with legitimate permissions and a clean
   prompt, deleting 500 products. Every layer above says "OK". This is the
   question Reeflex answers — and holds the action for a human when the
   answer is "not without you looking at it".

## The honest comparison

| | Identity & authz platforms | LLM guardrails | MCP gateways | **Reeflex** |
|---|---|---|---|---|
| Judges | the **actor** (role, permission) | the **text** (prompt/output) | the **traffic** (auth, rate, routing) | the **act** (impact of the action) |
| Where it sits | at the source (IdP, agent platform) | around the model | in front of MCP servers | **at the resource, before execution** |
| Decision engine | rules on identity | ML classifiers (probabilistic) | authn/z + limits | **deterministic OPA/Rego — zero LLM in the decision path** |
| Sees action scale? | no (delete 1 = delete 5,000) | no | rarely, per-call at best | **yes — count, reversibility, blast radius, externality** |
| Split-batch evasion | not addressed | not addressed | not addressed | **cumulative per-session ledger — fragmentation buys nothing** |
| Human approval | ticket systems, out of band | n/a | mostly absent | **built in: hold → your designated principal decides → action runs (shipped in core, v0.1.5)** |
| Evidence | logs after the fact | flags after the fact | access logs | **pre-execution record of what the agent *attempted*** — streamed to your SIEM in real time |
| If the engine is down | varies | fails open as a rule | varies | **fails closed — nothing goes through** |

*("MCP gateways" above is the commodity, identity-first category — Permit.io,
agent.security, and similar: auth, rate limits, routing. Reeflex's own
component at that same seam, `reeflex-mcp`, is not that category — it renders
the impact judgment instead. See
[below](#reeflex-mcp--governance-judgment-at-the-mcp-seam).)*

## What Reeflex deliberately does not do

- It does not replace identity, SSO, or permissions. Keep them.
- It does not scan prompts or outputs. Content safety stays where it is.
- It does not do identity, consent, or routing for MCP traffic — that is the
  commodity MCP-gateway job, and your gateway keeps it. `reeflex-mcp` is
  Reeflex's own component at that seam, and it renders a different
  judgment — see below.
- It does not use AI to police AI. The decision path is boring on purpose:
  the same envelope in produces the same verdict out, every time.

<a id="reeflex-mcp--governance-judgment-at-the-mcp-seam"></a>

## reeflex-mcp — governance judgment at the MCP seam

**MCP gateways govern who may call; Reeflex governs whether the call is
safe. reeflex-mcp puts that impact judgment at the same seam.**

The commodity "MCP gateway" category — Permit.io's MCP Gateway,
agent.security, and others — does identity-first authorization: who the
caller is, what token it holds, which tools it may reach, routed and rate-
limited at the MCP boundary. That is a real, useful job, and `reeflex-mcp`
does not replace it — run both, the same way you'd run an identity platform
alongside Reeflex generally (see the comparison above).

`reeflex-mcp` occupies the same seam with a different question. It
intercepts `tools/call` on any MCP upstream, normalizes it into the same
Action Envelope every other Reeflex adapter produces, and asks
`reeflex-core`'s `/v1/decide`: given this specific call's impact axes,
magnitude, environment, and this session's cumulative history, is it safe to
run — not just permitted? A fully-authorized, correctly-routed call can still
be about to delete 500 rows; that is the case `reeflex-mcp` is built for.

Some products in this category shipped the MCP-gateway seam before we did —
no claim of being first or only here. What `reeflex-mcp` brings to that seam
is **fully self-hosted, zero-account operation**: no control plane, no
hosted account, no traffic leaving the operator's own network. The gateway
calls the operator's own `reeflex-core`, nothing else. Full guide:
[docs/mcp-gateway.md](mcp-gateway.md).

## So do I still need my existing stack?

Yes — all of it. Reeflex is a layer the stack is missing, not a replacement
for the layers it has. Identity decides who gets in. Guardrails decide what
may be said. Reeflex decides what may be *done*.

*A seatbelt for the AI acting on your systems.*

---

<a id="ail"></a>

## HITL, HOTL, and now AIL — naming the third kind of oversight

> **AIL** /eɪl/ — agent-in-the-loop: the resolution of a governance hold
> by an AI principal you designate, under your resolution policy, recorded
> in the audit trail — never the agent whose action raised the hold.

When Reeflex holds an action, it has already made one decision: this is
the gray zone, it should not run unsupervised. That first decision is
deterministic — pure OPA/Rego, zero LLM, the same verdict every time.

Then it stops. Because the *second* decision — should this specific held
action actually proceed — is not ours to make. It belongs to you, judged
under your rules, by the judge you choose. We flag; you rule.

The industry already has names for two of the ways you can rule:

- **HITL — human-in-the-loop.** A person approves the action before it
  runs. Maximum control. The catch is that it does not scale: a noisy
  approval queue gets rubber-stamped or ignored, and a rubber-stamped
  checkpoint is worse than none.
- **HOTL — human-on-the-loop.** A person monitors and can intervene, but
  the action does not wait on them. Faster, looser, for the reversible
  middle ground.

There is a third way that is increasingly practiced and not yet named.
Sometimes the judge you trust for the routine holds is not a person — it
is an AI you designate: a private model fine-tuned on your procedures, a
supervisor agent that already knows your systems, a classifier you run in
your own infrastructure. You trust it. That is your call, not ours.

We call that **AIL — agent-in-the-loop.** (Pronounced like *ale* — because
the point is you get to step away while an agent you trust takes the shift
a human shouldn't have to stay awake for.)

We don't claim to have discovered anything. People already wire agents up
to approve other agents' actions. What's missing is a name for the
pattern and a safe, neutral place to plug it in — so it stops being an
accident and starts being a governed choice.

### Why AIL matters

The industry treats agent-delegated approval as a *risk to warn about*:
"delegation chains obscure accountability," "the agentic blame loop,"
every action authorized and yet no one accountable. We think that framing
is a failure of design, not a law of nature. Agent-delegated approval is
only a blame loop if it's unstructured. Give it a name, boundaries, and an
audit trail, and it becomes a mechanism you can govern.

That is the whole contribution: not the idea, the discipline around it.

AIL earns its place for three concrete reasons:

1. **It fixes what HITL can't: scale.** Human approval has a hard ceiling.
   One operator can meaningfully review a few holds a day; a fleet
   generates hundreds. Past that ceiling, humans approve blindly — the
   exact alert fatigue that makes HITL collapse in practice. AIL absorbs
   the routine volume so the human is left only with the genuinely hard
   calls. The autopilot flies; the pilot takes the controls when it
   matters.

2. **The trust is yours, and so is the boundary.** We do not certify that
   any AI is fit to approve. Whether your model is trustworthy enough to
   resolve a hold is your governance decision — your model, your infra,
   your risk. What we provide is the neutral socket and the guarantees
   that make that choice *safe whatever you plug in*:
   - **actor ≠ approver** — the agent whose action raised the hold can
     never resolve its own hold. Enforced on identity, in the core.
   - **per-rule resolution policy** — you decide which rules AIL may
     resolve. The session-budget hold, perhaps; a systemic-blast-radius
     deny, never. Default ships human-only; AIL is opt-in, explicitly.
   - **the terminal deny stays terminal** — systemic destruction is
     resolvable by no principal, human or agent. Re-scoped, not approved.
   - **every handover is recorded** — `decided_by: agent:triage-bot`,
     verbatim, append-only. The blame loop becomes an accountability
     trail.

3. **It resolves the "zero LLM" paradox instead of breaking it.** Our
   first decision has zero LLM in it and always will. AIL lives in the
   *second* decision — which was never ours. If you put an AI there, that
   is your documented governance choice, and documenting exactly that
   choice is what the EU AI Act's Article 14 asks you to prove. The gate
   stays deterministic. Who answers the flag is pluggable.

The whole posture, in one line: **the industry treats agent-delegated
approval as a risk to warn about. We treat it as a mechanism to govern —
named, bounded, and audited.**

We flag. You rule — with a human (HITL), on the loop (HOTL), or with an
agent you trust (AIL).
