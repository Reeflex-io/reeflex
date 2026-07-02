#!/usr/bin/env python3
"""
reeflex-verify — operator tool to check a live Reeflex integration.

You point it at a system where you have installed the Reeflex gate, it fires a
set of real actions, and it shows you what Reeflex decided for each one:
ALLOW, HOLD (require_approval), or DENY. No developer setup, no test framework
— one command, a table of verdicts.

Design: one script, one subcommand per integration. Today: `wp` (WordPress).
As new integrations ship, they get their own subcommand (postgres, shell, ...).

Stdlib only — no pip install. Works with Python 3.8+.

    reeflex-verify wp --url https://your-site.tld \\
                      --user admin \\
                      --app-password "xxxx xxxx xxxx xxxx xxxx xxxx"

Environment fallbacks (so you don't put secrets on the command line):
    REEFLEX_WP_URL, REEFLEX_WP_USER, REEFLEX_WP_APP_PASSWORD
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# Browser-like User-Agent. Some hosts (cPanel mod_security / anti-bot WAFs) reset or
# cancel connections from non-browser clients like "Python-urllib"; presenting a browser
# UA — and preferring the system `curl` transport below — lets an operator run this
# against their own WAF-protected site.
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36")

# --------------------------------------------------------------------------
# Terminal colors (enabled on Windows 10+ too).
# --------------------------------------------------------------------------
def _enable_ansi():
    if os.name == "nt":
        os.system("")  # turns on VT processing in modern Windows terminals
    # Ensure Unicode output (check marks, box-drawing) does not crash on a legacy
    # Windows code page (e.g. cp1252): force UTF-8 with a safe replacement fallback.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001  (older Pythons / non-reconfigurable streams)
            pass


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


def color(text, c):
    return f"{c}{text}{C.RESET}"


# --------------------------------------------------------------------------
# Verdict labels + how expected/actual are shown.
# --------------------------------------------------------------------------
ALLOW = "ALLOW"
HOLD = "HOLD"
DENY = "DENY"
FAIL_CLOSED = "FAIL-CLOSED"

VERDICT_COLOR = {
    ALLOW: C.GREEN,
    HOLD: C.YELLOW,
    DENY: C.RED,
    FAIL_CLOSED: C.RED,
}


# --------------------------------------------------------------------------
# WordPress client (Abilities API over REST).
# --------------------------------------------------------------------------
class WPClient:
    """Minimal WordPress Abilities API client using Basic auth (App Password)."""

    def __init__(self, base_url, user, app_password, insecure=False, timeout=15):
        self.base = base_url.rstrip("/")
        token = base64.b64encode(f"{user}:{app_password}".encode()).decode()
        self.auth_header = f"Basic {token}"
        self.timeout = timeout
        self.insecure = insecure
        # Prefer the system curl: its TLS handshake traverses WAF/anti-bot layers
        # that reset Python's urllib. Fall back to urllib when curl is absent.
        self._curl = shutil.which("curl")

    def _request(self, method, path, body=None):
        """Return (http_status, parsed_body). Never raises on transport/HTTP errors —
        error bodies are captured so Reeflex verdicts (which may arrive as 403/503 or a
        2xx with an error-shaped body) are all read uniformly. status == 0 means the
        request could not be delivered at all (transport failure)."""
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        status, raw = (self._via_curl(method, url, data) if self._curl
                       else self._via_urllib(method, url, data))
        if status == 0:
            detail = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
            return 0, {"__neterror__": detail or "request failed"}
        try:
            parsed = json.loads(raw.decode() or "null")
        except (ValueError, UnicodeDecodeError):
            parsed = {"__rawbody__": raw[:400].decode(errors="replace")}
        return status, parsed

    def _via_curl(self, method, url, data):
        """Transport via system curl (browser UA, Basic auth, retries). -> (status, raw bytes)."""
        fd, tmp = tempfile.mkstemp(prefix="reeflex-verify-")
        os.close(fd)
        cmd = [self._curl, "-sS", "-o", tmp, "-w", "%{http_code}", "-X", method,
               "-A", _BROWSER_UA, "-H", "Authorization: " + self.auth_header,
               "-H", "Accept: application/json", "--max-time", str(self.timeout)]
        if self.insecure:
            cmd.append("-k")
        if data is not None:
            cmd += ["-H", "Content-Type: application/json", "--data-binary", data.decode()]
        cmd.append(url)
        last = ""
        try:
            for attempt in range(3):
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 15)
                code = (p.stdout or "").strip()
                if code.isdigit() and code != "000":
                    with open(tmp, "rb") as fh:
                        return int(code), fh.read()
                last = (p.stderr or "").strip() or ("curl exit %d (http=%s)" % (p.returncode, code or "?"))
                if attempt < 2:
                    time.sleep(2)
        except Exception as e:  # noqa: BLE001
            last = str(e)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return 0, last.encode()

    def _via_urllib(self, method, url, data):
        """Fallback transport via urllib (browser UA, retries). -> (status, raw bytes)."""
        headers = {"Authorization": self.auth_header, "Accept": "application/json",
                   "User-Agent": _BROWSER_UA}
        if data is not None:
            headers["Content-Type"] = "application/json"
        ctx = None
        if self.insecure:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        last = ""
        for attempt in range(3):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
                return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
            except Exception as e:  # noqa: BLE001  (URLError / RemoteDisconnected / reset / timeout)
                last = str(getattr(e, "reason", e))
                if attempt < 2:
                    time.sleep(2)
        return 0, last.encode()

    def list_abilities(self):
        return self._request("GET", "/wp-json/wp-abilities/v1/abilities")

    def run_ability(self, namespace, ability, input_dict):
        # No readonly/destructive annotation on the test abilities => POST + body.
        path = f"/wp-json/wp-abilities/v1/abilities/{namespace}/{ability}/run"
        return self._request("POST", path, {"input": input_dict})


# --------------------------------------------------------------------------
# Turn an HTTP (status, body) pair into a Reeflex verdict.
# We key on the WP_Error `code` first (unambiguous), status second.
# --------------------------------------------------------------------------
def classify(status, body):
    if not isinstance(body, dict):
        return (ALLOW if 200 <= status < 300 else f"HTTP {status}"), None

    if "__neterror__" in body:
        return "NET-ERROR", body["__neterror__"]

    code = body.get("code", "") or ""
    data = body.get("data", {}) if isinstance(body.get("data"), dict) else {}

    if code == "reeflex_unavailable":
        return FAIL_CLOSED, "core unreachable / fail-closed"
    if code == "reeflex_denied":
        return DENY, "policy rule fired"
    if code == "reeflex_hold":
        return HOLD, "held for human approval"

    # Non-Reeflex WordPress errors (auth, missing ability, etc.)
    if code.startswith("rest_") or code in ("incorrect_password", "invalid_username"):
        return f"WP-ERROR:{code}", body.get("message", "")

    # No error code and a 2xx => the ability executed. Reeflex allowed it.
    if 200 <= status < 300:
        return ALLOW, "ability executed"

    return f"HTTP {status}", body.get("message", "")


# --------------------------------------------------------------------------
# The WordPress test scenarios.
# --------------------------------------------------------------------------
def wp_scenarios():
    ids_50 = list(range(1, 51))
    ids_25 = list(range(1, 26))
    return [
        ("read a test item",
         "get-item", {"id": 1}, ALLOW,
         "read-only — should always pass"),
        ("delete 1 item (soft / trash)",
         "delete-item", {"ids": [1]}, ALLOW,
         "single recoverable delete — passes"),
        ("bulk delete 50 items (force)",
         "delete-item", {"ids": ids_50, "force_delete": True}, HOLD,
         "irreversible + broad in production — held"),
        ("bulk delete 25 items (soft, >=20)",
         "delete-item", {"ids": ids_25}, HOLD,
         ">=20 items counts as irreversible — held"),
        ("delete ALL site data (force)",
         "delete-site-wide-data", {"force_delete": True}, DENY,
         "systemic blast radius — denied outright"),
    ]


# --------------------------------------------------------------------------
# Pretty output.
# --------------------------------------------------------------------------
def print_header(title):
    line = "=" * 74
    print(color(line, C.DIM))
    print(color(f" {title}", C.BOLD))
    print(color(line, C.DIM))


def fmt_verdict(v):
    c = VERDICT_COLOR.get(v, C.CYAN)
    return color(f"{v:<12}", c)


# --------------------------------------------------------------------------
# `wp` subcommand.
# --------------------------------------------------------------------------
def cmd_wp(args):
    url = args.url or os.environ.get("REEFLEX_WP_URL", "")
    user = args.user or os.environ.get("REEFLEX_WP_USER", "")
    app_pw = args.app_password or os.environ.get("REEFLEX_WP_APP_PASSWORD", "")

    missing = [n for n, v in (("--url", url), ("--user", user),
                              ("--app-password", app_pw)) if not v]
    if missing:
        print(color(f"Missing required: {', '.join(missing)}", C.RED))
        print("Provide them as flags or via REEFLEX_WP_URL / REEFLEX_WP_USER / "
              "REEFLEX_WP_APP_PASSWORD.")
        return 2

    client = WPClient(url, user, app_pw, insecure=args.insecure)
    ns = args.namespace

    print_header(f"Reeflex verify · WordPress · {url}")
    expect_fc = args.expect_fail_closed
    if expect_fc:
        print(color(" Mode: --expect-fail-closed — every action should be BLOCKED.", C.YELLOW))
        print(color(" (Point the plugin at a dead core URL first, then run this.)\n", C.DIM))

    # --- Precheck: can we reach the site, auth, and see the test abilities? --
    status, body = client.list_abilities()
    if status == 0:
        print(color(f"Cannot reach the site: {body.get('__neterror__')}", C.RED))
        return 2
    if status == 401:
        print(color("Authentication failed (401).", C.RED))
        print("Check the username and Application Password. Generate one in "
              "wp-admin → Users → Profile → Application Passwords.")
        return 2
    if status == 404:
        print(color("Abilities API endpoint not found (404).", C.RED))
        print("This site may be below WordPress 6.9, or the Abilities API is "
              "not active. Reeflex needs the Abilities API to gate.")
        return 2

    names = []
    if isinstance(body, list):
        names = [a.get("name", "") for a in body if isinstance(a, dict)]
    elif isinstance(body, dict) and isinstance(body.get("abilities"), list):
        names = [a.get("name", "") for a in body["abilities"] if isinstance(a, dict)]

    want = f"{ns}/delete-item"
    if want not in names:
        print(color(f"Test abilities not found (looked for '{want}').", C.YELLOW))
        print("Install and activate the 'Reeflex Test Abilities' plugin on this "
              "site first (it registers safe test abilities to fire at).")
        print(color(f"Abilities visible to this user: {len(names)}", C.DIM))
        return 2

    print(color(f"✓ Reached site, authenticated, test abilities present.\n", C.GREEN))

    # --- Run scenarios ------------------------------------------------------
    rows = []
    passed = 0
    for title, ability, payload, expected_normal, why in wp_scenarios():
        expected = FAIL_CLOSED if expect_fc else expected_normal
        status, resp = client.run_ability(ns, ability, payload)
        verdict, detail = classify(status, resp)

        ok = (verdict == expected)
        if ok:
            passed += 1
        rows.append((title, verdict, expected, ok, why, detail, status))

    # --- Table --------------------------------------------------------------
    for title, verdict, expected, ok, why, detail, status in rows:
        mark = color("✓", C.GREEN) if ok else color("✗", C.RED)
        print(f" {mark}  {title}")
        print(f"      Reeflex said : {fmt_verdict(verdict)}  "
              f"{color('(expected ' + expected + ')', C.DIM)}")
        if args.verbose:
            print(color(f"      why          : {why}", C.DIM))
            print(color(f"      http/detail  : {status} · {detail}", C.DIM))
        print()

    # --- Summary ------------------------------------------------------------
    total = len(rows)
    allok = (passed == total)
    print(color("-" * 74, C.DIM))
    summary = f" {passed}/{total} actions decided as expected."
    print(color(summary, C.GREEN if allok else C.RED))
    if allok:
        print(color(" Reeflex is intercepting and deciding correctly on this site.",
                    C.GREEN))
    else:
        print(color(" Some verdicts did not match. Re-run with --verbose for detail,",
                    C.YELLOW))
        print(color(" and check the audit log (wp-content/reeflex-audit.jsonl).",
                    C.YELLOW))
    print(color("-" * 74, C.DIM))
    return 0 if allok else 1


# --------------------------------------------------------------------------
# Argument parsing.
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="reeflex-verify",
        description="Verify a live Reeflex integration by firing real actions "
                    "and showing the allow/hold/deny verdict for each.",
    )
    sub = p.add_subparsers(dest="integration", required=True)

    wp = sub.add_parser("wp", help="Verify a WordPress site with the Reeflex gate installed.")
    wp.add_argument("--url", help="Site URL, e.g. https://your-site.tld "
                                  "(or env REEFLEX_WP_URL)")
    wp.add_argument("--user", help="WordPress username (or env REEFLEX_WP_USER)")
    wp.add_argument("--app-password", help="Application Password "
                                           "(or env REEFLEX_WP_APP_PASSWORD)")
    wp.add_argument("--namespace", default="reeflex-test",
                    help="Ability namespace to test (default: reeflex-test)")
    wp.add_argument("--expect-fail-closed", action="store_true",
                    help="Assert that EVERY action is blocked (use after pointing "
                         "the plugin at a dead core URL to test fail-closed).")
    wp.add_argument("--insecure", action="store_true",
                    help="Skip TLS certificate verification (self-signed dev sites).")
    wp.add_argument("--verbose", action="store_true", help="Show why + HTTP detail.")
    wp.set_defaults(func=cmd_wp)

    return p


def main():
    _enable_ansi()
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
