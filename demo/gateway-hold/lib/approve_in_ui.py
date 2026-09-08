#!/usr/bin/env python3
"""
approve_in_ui.py -- a REAL human approval, in a real browser, on the live app.

    python3 lib/approve_in_ui.py enrol   --invite-url URL --shots DIR
    python3 lib/approve_in_ui.py approve --hold-id HEX     --shots DIR

WHY A BROWSER AND NOT AN HTTP CALL
==================================
`POST /app/api/v1/holds/{id}/resolve` is one request and it would be easy to
script. It is also the wrong instrument for step 4 of this walk, because the
claim being demonstrated is "a person looked at this and decided", and the only
way to know the person could HAVE looked is to render the page they would look
at and click the control they would click. A resolve driven over HTTP proves
the route works; it proves nothing about whether the hold was visible.

So this drives Chromium, over TLS, against app.reeflex.io, and writes a
screenshot of every step into the evidence directory. It also asserts the
Approve control is the element actually PAINTED at its own centre --
`is_visible()` is true for an element sitting entirely behind a sticky header,
which has produced a false pass on this codebase before.

THE PASSKEY IS REAL, AND IT IS A VIRTUAL AUTHENTICATOR
======================================================
`enrol` completes the app's own WebAuthn ceremony through a CDP virtual
authenticator (`ctap2` / `internal` / resident key / UV), so the
`webauthn_credentials` and `sessions` rows are the ones the deployed build's
own code wrote. The control that makes it meaningful: the context's cookie jar
is asserted EMPTY before the ceremony, so the session that exists afterwards
cannot be one that was already there.

The invite TOKEN is the one thing that does not come over the wire -- the app
mails it and stores only a hash -- so it is read from the `create_org` return
value and passed in. Everything after the token is TLS to the public host.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

APP = os.environ.get("RFX_DEMO_APP_BASE", "https://app.reeflex.io")
STATE = os.environ.get("RFX_DEMO_BROWSER_STATE",
                       "/tmp/reeflex-gateway-hold-run/browser-state.json")


def log(msg):
    print("[ui] %s" % msg, flush=True)


def _authenticator(ctx, page):
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    res = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal",
        "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp, res["authenticatorId"]


def _painted(el) -> bool:
    """Is this element the thing actually drawn at its own centre?

    `is_visible()` checks display/visibility/box and says NOTHING about
    occlusion. A fixed banner behind a sticky header passed `is_visible()` on
    this app while being invisible on screen.
    """
    return bool(el.evaluate("""el => {
        const b = el.getBoundingClientRect();
        if (!b.width || !b.height) return false;
        const hit = document.elementFromPoint(b.left + b.width/2,
                                              b.top + b.height/2);
        return !!hit && (el.contains(hit) || hit.contains(el));
    }"""))


def enrol(args):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = ctx.new_page()
        page.goto(APP + "/signin", wait_until="domcontentloaded")
        cookies_before = ctx.cookies()
        assert cookies_before == [], (
            "the cookie jar was NOT empty before the ceremony (%d cookies) -- "
            "a session that already existed would make this proof vacuous: %r"
            % (len(cookies_before), [c["name"] for c in cookies_before]))
        log("control: cookie jar empty before the ceremony")

        _authenticator(ctx, page)
        page.goto(args.invite_url, wait_until="domcontentloaded")
        page.screenshot(path=os.path.join(args.shots, "step4a-invite-page.png"),
                        full_page=True)
        # The enrolment control's label has moved between builds; match on the
        # accessible role and any of the words it has used, and FAIL LOUDLY
        # rather than clicking something else.
        clicked = False
        # Measured against the deployed build 2026-09-08: the label is
        # "Register a passkey". The others are kept because this page's label
        # has moved between builds and a demo that breaks on a caption is a
        # bad demo -- but an UNMATCHED page raises with the buttons it saw,
        # rather than clicking whatever is first.
        for pattern in ("Register a passkey", "Create passkey",
                        "Create your passkey", "Enrol", "Enroll",
                        "Accept invitation", "Continue"):
            btn = page.get_by_role("button", name=pattern)
            if btn.count() and btn.first.is_visible():
                log("clicking %r" % pattern)
                btn.first.click()
                clicked = True
                break
        if not clicked:
            page.screenshot(path=os.path.join(args.shots,
                                              "step4a-invite-NO-BUTTON.png"))
            raise SystemExit(
                "no enrolment control found on the invite page. Buttons seen: %r"
                % [page.get_by_role("button").nth(i).inner_text()
                   for i in range(page.get_by_role("button").count())])
        page.wait_for_timeout(4000)
        cookies = ctx.cookies()
        names = sorted(c["name"] for c in cookies)
        log("cookies after the ceremony: %s" % names)
        assert any(c["name"] == "rfx_session" for c in cookies), (
            "the ceremony did not produce a session cookie; got %r at %s"
            % (names, page.url))
        ctx.storage_state(path=STATE)
        page.goto(APP + "/app", wait_until="domcontentloaded")
        page.screenshot(path=os.path.join(args.shots, "step4b-signed-in.png"),
                        full_page=True)
        log("enrolled; storage state -> %s" % STATE)
        browser.close()


def approve(args):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(storage_state=STATE,
                                  viewport={"width": 1440, "height": 1000})
        page = ctx.new_page()
        wire = []
        # Every request the page makes to a Reeflex route, not only `/api/`:
        # the resolve is a plain htmx `POST /app/holds/{id}/resolve` on the WEB
        # plane, and a filter on `/api/` recorded an empty wire log on the
        # first live run while the approval had in fact gone through.
        page.on("response", lambda r: wire.append(
            (r.request.method, r.url, r.status))
            if ("/app/" in r.url or "/api/" in r.url) else None)

        page.goto(APP + "/app/holds", wait_until="networkidle")
        page.screenshot(path=os.path.join(args.shots, "step3-holds-inbox.png"),
                        full_page=True)

        # THE ANCHOR IS THE CARD'S OWN id, NOT THE PAGE TEXT.
        # The hold id is NOT rendered as visible text on this page -- it lives
        # in `id="hold-<hold_id>"` and in the resolve form's `hx-post`. The
        # first version of this script matched on the page's inner_text and
        # would have silently approved whatever hold happened to be first.
        card = page.locator("#hold-%s" % args.hold_id)
        assert card.count() == 1, (
            "hold %s has no card on the inbox page (found %d). Cards present: "
            "%r\nPage text was:\n%s"
            % (args.hold_id, card.count(),
               page.locator(".rfx-hold-card").evaluate_all(
                   "els => els.map(e => e.id)"),
               page.inner_text("body")[:1200]))
        text = card.first.inner_text()
        log("the hold's own card is on the page (#hold-%s)" % args.hold_id[:8])
        log("what the human reads on it:")
        for line in [l for l in text.splitlines() if l.strip()]:
            log("    | %s" % line)
        for expected in ("delete", "production", "litellm-gateway",
                         "irreversible_broad_prod", "acme-payments"):
            assert expected in text, (
                "the card does not mention %r, so a human could not tell what "
                "they are approving. Card text:\n%s" % (expected, text))
        log("the card names the verb, the environment, the gateway, the rule "
            "and the department")

        # The Approve control, scoped to THIS card's own resolve form, so a
        # many-hold inbox and a one-hold inbox behave identically and the walk
        # cannot approve somebody else's action.
        form = card.locator(
            "form[hx-post='/app/holds/%s/resolve']"
            ":has(input[name='decision'][value='approve'])" % args.hold_id)
        assert form.count() == 1, (
            "expected exactly one approve form on card %s, found %d"
            % (args.hold_id, form.count()))
        el = form.first.locator("button[type='submit']")
        el.scroll_into_view_if_needed()
        assert _painted(el), (
            "the Approve control is in the DOM and `is_visible()`, but it is "
            "NOT the element painted at its own centre -- a human could not "
            "click it")
        log("the Approve control is painted where it says it is: %r"
            % el.inner_text().strip())
        page.screenshot(path=os.path.join(args.shots,
                                          "step4c-approve-control.png"),
                        full_page=True)
        el.click()
        page.wait_for_timeout(4000)
        page.screenshot(path=os.path.join(args.shots, "step4d-approved.png"),
                        full_page=True)
        after = page.locator("#hold-%s" % args.hold_id)
        log("the card after the click: %r"
            % (after.first.inner_text().replace("\n", " · ")[:220]
               if after.count() else "<removed from the pending list>"))
        log("requests the browser actually made:")
        for m, u, s in wire:
            log("   %-5s %-70s %s" % (m, u.replace(APP, ""), s))
        with open(os.path.join(args.shots, "step4-wire.json"), "w") as fh:
            json.dump([{"method": m, "url": u.replace(APP, ""), "status": s}
                       for m, u, s in wire], fh, indent=2)
        browser.close()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enrol")
    e.add_argument("--invite-url", required=True)
    e.add_argument("--shots", required=True)
    e.set_defaults(fn=enrol)
    a = sub.add_parser("approve")
    a.add_argument("--hold-id", required=True)
    a.add_argument("--shots", required=True)
    a.set_defaults(fn=approve)
    args = ap.parse_args()
    # AN EMPTY hold id made the "the hold is on the page" assertion VACUOUS
    # once, on the first live run of this script: `""[:8]` is `""`, `"" in
    # body` is True, and it went on to click the first Approve control on the
    # page -- a DIFFERENT org member's hold would have been approved by a
    # walk that then reported success. Refuse the shape, not just the empty
    # string.
    hold_id = getattr(args, "hold_id", None)
    if hold_id is not None:
        if len(hold_id) != 32 or any(c not in "0123456789abcdef" for c in hold_id):
            raise SystemExit(
                "--hold-id must be a 32-char lowercase hex uuid4 (core's hold "
                "id shape); got %r. An empty or partial id would make the "
                "on-the-page assertion below vacuous." % hold_id)
    os.makedirs(args.shots, exist_ok=True)
    args.fn(args)


if __name__ == "__main__":
    main()
