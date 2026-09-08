#!/usr/bin/env python3
"""
wire_truth.py -- what an Attest report over this feed can and cannot say.

Step 6 of the walk. The interesting part is the negative result, so it is
printed by RUNNING the projection rather than by describing it.

THE SHORT VERSION
  * The adapter's own ledger line carries `enforcement_stage`,
    `observed: proposal`, `prevents_execution: false` and the whole
    `gateway_routing` block.
  * EVIDENCE-INGEST-SPEC-v1 §4 -- the schema of the feed a Reeflex Attest
    report is built from -- has no field for any of them, and it is a CLOSED
    schema (unknown top-level key -> 422) on a FROZEN contract.
  * So a report built from the §4 feed alone CANNOT distinguish a gateway
    refusal from an execution-side prevention. The one adapter-controlled
    field that does reach a report is `agent_id`, which this seat sets to
    `agent:litellm-gateway/<org>/<model>` -- which department, behind which
    gateway, on which model, but not what the refusal achieved.

That gap is a spec change (RFX-247), and an adapter may not make a change to a
wire contract with deployed gates. It is stated here, in the demo a customer
reads, rather than left for them to discover in a report.

The seat's own guard against the overclaim is also exercised below:
`assert_never_claims_prevention()` raises on `prevented_at_execution`, so this
package cannot emit it even by mistake.
"""

from __future__ import annotations

import json
import sys

from reeflex_litellm import evidence

path = sys.argv[1]
rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
held = [r for r in rows if r.get("hold_id")] or rows
line = held[-1]

print("   the ledger line (the adapter's own record) carries:")
for k in ("enforcement_stage", "observed", "prevents_execution", "hold_id",
          "hold_announced"):
    print("     %-20s %s" % (k, json.dumps(line.get(k))))
print("     %-20s %s" % ("gateway_routing", "{%s}" % ", ".join(
    sorted((line.get("gateway_routing") or {}).keys()))))

wire = evidence.wire_record(line)
print()
print("   the SAME line projected onto the §4 evidence wire:")
for k in sorted(wire):
    print("     %-20s %s" % (k, json.dumps(wire[k])))

missing = [k for k in ("enforcement_stage", "observed", "prevents_execution",
                       "gateway_routing") if k in wire]
if missing:
    raise SystemExit("   these reached the frozen wire and must not have: %s"
                     % missing)
print()
print("   NOT on the wire: enforcement_stage, observed, prevents_execution,")
print("   gateway_routing. Not omitted by oversight -- `wire_record()` is a")
print("   closed allowlist and `assert_wire_is_spec_clean()` re-checks its own")
print("   output before every request. Try it:")
bad = dict(wire)
bad["enforcement_stage"] = line["enforcement_stage"]
try:
    evidence.assert_wire_is_spec_clean(bad)
    raise SystemExit("   the guard did NOT fire -- that is a defect")
except evidence.EvidenceConfigError as exc:
    print("     %s" % str(exc)[:230])

print()
print("   and the overclaim guard, on the stage this seat must never emit:")
try:
    evidence.assert_never_claims_prevention(
        evidence.STAGE_PREVENTED_AT_EXECUTION)
    raise SystemExit("   the guard did NOT fire -- that is a defect")
except Exception as exc:
    print("     %s: %s" % (type(exc).__name__, str(exc)[:220]))

print()
print("   What a report CAN therefore say about this walk: a production")
print("   `delete` on `litellm-gateway`, rule irreversible_broad_prod, held,")
print("   then allowed under approved_resubmission, by")
print("     agent_id = %s" % wire.get("agent_id"))
print("   What it CANNOT say: that the action was prevented at execution. It")
print("   was not. It was refused at a gateway, which is a different and")
print("   weaker fact, and the two must not be counted together.")
