#!/usr/bin/env python3
"""
attest.py -- generate the report an auditor would read, and read it honestly.

Runs on the WEB plane with the session the enrolment ceremony minted, because
that is the plane a customer uses: `/app/attest`, two date fields, one
`Generate report` button (htmx `POST /app/attest/reports`), then
`GET /app/attest/download?report_id=&format=json`.

TWO TRAPS THIS SCRIPT IS WRITTEN AROUND, both previously measured on this app:
  * the period fields are `required`, and a click with either one empty is
    silently eaten by the browser's own validation -- the request is never
    made and the page looks unchanged, which reads as "the report failed";
  * there is no `/app/api/v1/attest/reports/{id}/download`; the download is
    the web route above, and its 404 nearly became a false defect report.

WHAT IT PRINTS, AND WHY THE NEGATIVE PART MATTERS MOST
The report row for this walk's decision is shown, and then what the row does
NOT contain: no `enforcement_stage`, no `prevents_execution`, no
`gateway_routing`. §4 has no field for them and it is frozen, so this is the
report an auditor gets today. `agent_id` naming the gateway and the department
is the whole of what this seat can carry into it (RFX-247).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import date, timedelta

APP = os.environ.get("RFX_DEMO_APP_BASE", "https://app.reeflex.io")
STATE = os.environ.get("RFX_DEMO_BROWSER_STATE",
                       "/tmp/reeflex-gateway-hold-run/browser-state.json")
SHOTS = os.environ.get("RFX_DEMO_SHOTS", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "shots"))


def log(m):
    print("   %s" % m, flush=True)


def main():
    if not os.path.exists(STATE):
        log("no browser session (%s) -- the attest step needs the signed-in "
            "state the enrolment produced. NOT RUN." % STATE)
        return 0
    from playwright.sync_api import sync_playwright
    today = date.today()
    frm = (today - timedelta(days=1)).isoformat()
    to = (today + timedelta(days=1)).isoformat()
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(storage_state=STATE,
                            viewport={"width": 1440, "height": 1200})
        pg = ctx.new_page()
        posts = []
        pg.on("response", lambda r: posts.append(
            (r.request.method, r.url.replace(APP, ""), r.status))
            if "/app/attest" in r.url else None)
        pg.goto(APP + "/app/attest", wait_until="networkidle")
        pg.fill("input[name='period_from']", frm)
        pg.fill("input[name='period_to']", to)
        # The fields are `required`; a click with either empty is eaten by the
        # browser and never reaches the server. Assert they took the value.
        for name, want in (("period_from", frm), ("period_to", to)):
            got = pg.input_value("input[name='%s']" % name)
            assert got == want, ("%s did not take the value (%r != %r); the "
                                 "Generate click would have been silently "
                                 "dropped" % (name, got, want))
        log("period %s .. %s" % (frm, to))
        pg.get_by_role("button", name="Generate report").click()
        pg.wait_for_timeout(6000)
        pg.screenshot(path=os.path.join(SHOTS, "step6-attest-report.png"),
                      full_page=True)
        for m, u, s in posts:
            log("%-5s %-46s %s" % (m, u, s))
        body = pg.inner_text("body")
        if "No reports generated yet" in body:
            log("the page still says no reports exist -- the generate did not "
                "take. Screenshot: step6-attest-report.png")
            b.close()
            return 1

        # The report id, off the download link the page rendered.
        import re
        ids = re.findall(r"report_id=([0-9a-f-]{36})", pg.content())
        if not ids:
            log("no report_id on the page after generating; see the screenshot")
            b.close()
            return 1
        rid = ids[0]
        log("report_id %s" % rid)
        resp = ctx.request.get(
            "%s/app/attest/download?report_id=%s&format=json" % (APP, rid))
        assert resp.status == 200, "download -> HTTP %d" % resp.status
        report = resp.json()
        out = os.path.join(SHOTS, "step6-attest-report.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        log("downloaded -> %s" % out)

        blob = json.dumps(report)

        # THE DECISIVE NUMBERS. `of_those_a_human_decided` is the Article 14
        # count, and it is computed from THIS FEED -- not from the app's own
        # hold tables. Before the adapter filled §4's `hold.resolution` /
        # `hold.decided_by`, it read 0 over a period containing two real UI
        # approvals: a report that was right about its inputs and wrong about
        # the world.
        log("")
        log("the Article 14 basis the report computed:")
        for ctrl in report.get("controls") or []:
            basis = ctrl.get("attestation_basis") or {}
            if not basis:
                continue
            for k in sorted(basis):
                log("  %-52s %s" % (k, json.dumps(basis[k])))
            break
        log("")
        log("the evidence-chain rows' approver fields:")
        seen = 0
        for ctrl in report.get("controls") or []:
            for row in (ctrl.get("evidence_chain") or []):
                if not row.get("hold_id"):
                    continue
                log("  hold %s  resolution=%-9s decided_by=%s:%s"
                    % (str(row.get("hold_id"))[:8],
                       json.dumps(row.get("resolution")),
                       row.get("decided_by_type"), row.get("decided_by_id")))
                seen += 1
                if seen >= 6:
                    break
            if seen:
                break
        log("")
        log("what the report contains about this walk:")
        for needle in ("litellm-gateway", "acme-payments",
                       "irreversible_broad_prod", "approved_resubmission",
                       "alice.approver@acme.example"):
            log("  %-34s %s" % (needle, "present" if needle in blob else "ABSENT"))
        log("")
        log("and what it does NOT contain -- §4 has no field for these and the")
        log("contract is frozen, so this is the report an auditor gets today:")
        for needle in ("enforcement_stage", "prevents_execution",
                       "gateway_routing", "refused_at_gateway",
                       "prevented_at_execution"):
            log("  %-34s %s" % (needle, "PRESENT" if needle in blob else "absent"))
        log("")
        log("`prevented_at_execution` being absent is correct and is the point:")
        log("nothing in this chain prevented an execution. `refused_at_gateway`")
        log("being absent too is the GAP (RFX-247) -- the report cannot state")
        log("the weaker, true fact either, so it states neither.")
        b.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
