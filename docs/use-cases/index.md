---
title: "Use cases"
description: >-
  The scenarios Reeflex helps in, IT and OT — each with real Action Envelopes,
  the verdict the base pack gives them, how to deploy it, and what Reeflex does
  not do there.
---

# Use cases

Each page below is one scenario: who runs what agent against what, what goes
wrong without a gate, three representative actions as real Action Envelopes
with the verdict and rule the base pack gives them, the adapter and the one
setting that matters, and — on every page — what Reeflex does **not** do
there. The verdicts are not illustrations. `scripts/docs_envelopes_check.py`
runs every envelope on these pages through `reeflex-core`'s own decision path
and fails if a printed verdict or rule id differs from what the engine
returns. Where an envelope was built by an adapter, the page names the adapter
function that built it. The adapter's transport fields (`meta`, nonce,
signature, `context`) are left out because no rule reads them.

| scenario | adapter | the rule that matters most |
|---|---|---|
| [A coding agent on production](coding-agent.md) | reeflex-claude | R2 `irreversible_broad_prod` — the irreversible step of a sequence waits for a person |
| [A database agent on Postgres](database-agent.md) | reeflex-mcp (Postgres mapping) | R2 — `execute_sql` is priced as its worst case |
| [A CMS / ops agent on WordPress](cms-agent.md) | reeflex-gate (WordPress plugin) | R7 `authority_change_prod` — installing code is a change of authority |
| [An automation agent in n8n](automation-agent.md) | n8n Reeflex Gate node | R5 money budget — a refund loop is one run, not many small refunds |
| [Any MCP tool-using agent](mcp-tool-agent.md) | reeflex-mcp | R3 on the unmapped-tool floor — an unknown tool is refused in production |
| [An LLM-gateway fleet](llm-gateway-fleet.md) | reeflex-litellm | R2 — the proposed tool call is decided before the client sees it |
| [Outbound communications & payments](outbound-and-payments.md) | any | R5 `external_sends` and `money` budgets |
| [Evidence for an auditor](evidence-for-an-auditor.md) | any | R0 `unclassified_action` — a coverage gap is reported as one, not as a control |
| [Industrial setpoints (OPC-UA / Modbus)](industrial-setpoints.md) | reeflex-mcp | R10b `physical_envelope` / `physical_writes` — forty small steps are one move |
| [Building management](building-management.md) | reeflex-mcp | R11 `mode_change_live` — a mode change on a live unit waits for a person |
| [Lab automation & robotics](lab-automation.md) | reeflex-mcp | R9 `physical_irreversible` — a dose cannot be un-dispensed |
| [Mobile robots & drones](mobile-robots-and-drones.md) | reeflex-mcp | R11 — arming a vehicle waits for the pilot |

The four OT pages depend on the physical-impact rules (R8–R11 and two budgets,
RFX-427), which are not in reeflex-core v0.2.3. Before you read them, read
**[Reeflex above the safety PLC](above-the-safety-plc.md)**: where Reeflex sits
relative to the safety system, what it does not claim, and the regulatory
context, with sources.
