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
| Human approval | ticket systems, out of band | n/a | mostly absent | **designed in: hold → human decides → action runs (approval API shipping next)** |
| Evidence | logs after the fact | flags after the fact | access logs | **pre-execution record of what the agent *attempted*** |
| If the engine is down | varies | fails open as a rule | varies | **fails closed — nothing goes through** |

## What Reeflex deliberately does not do

- It does not replace identity, SSO, or permissions. Keep them.
- It does not scan prompts or outputs. Content safety stays where it is.
- It does not route or catalog MCP traffic. Your gateway keeps its job —
  and can call Reeflex's `/v1/decide` as its judgment layer.
- It does not use AI to police AI. The decision path is boring on purpose:
  the same envelope in produces the same verdict out, every time.

## So do I still need my existing stack?

Yes — all of it. Reeflex is a layer the stack is missing, not a replacement
for the layers it has. Identity decides who gets in. Guardrails decide what
may be said. Reeflex decides what may be *done*.

*A seatbelt for the AI acting on your systems.*
