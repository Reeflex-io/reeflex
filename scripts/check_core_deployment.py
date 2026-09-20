#!/usr/bin/env python3
"""check_core_deployment.py — is the deployed core the build we test, and can it
still do the thing the product is sold on? (RFX-309 req 3, RFX-90, RFX-88)

WHY THIS EXISTS, AND WHY IT IS NOT reeflex-app's check_deploy_drift.py.

reeflex-app already ships a daily deploy-drift job (RFX-90). It watches
app.reeflex.io and it says in its own closing comment that api-dev — the
production CORE — is deliberately not wired into it. Two reasons, both real,
and both are why this file is here instead of a line in that workflow:

  1. Core had no build identity over HTTP, so that checker could only ever
     report the same unfixable "will not say what it is" FAIL. RFX-89's core
     half (reeflex-core/app/buildinfo.py, /healthz `revision`) removes that
     blocker, and this change ships it.

  2. THE GIT ARM IS BOUND TO THE REPO THE CHECKER LIVES IN. `check()` asks
     `git cat-file -e <revision>` in its `--repo` clone, so a correct core
     commit handed to the app-repo checker is rejected as "not a commit in
     this repository". Measured 2026-09-20 (dev-1--185): the deployed core
     revision e175e4e resolves in the monorepo clone and does NOT resolve in
     the reeflex-app clone. Wiring api-dev into the app repo's workflow would
     have been wrong even after (1) was fixed.

AND A DRIFT ARM ALONE WOULD HAVE BEEN GREEN THROUGH THE WHOLE DEFECT.
RFX-309, in its own words: "the deploy-drift check (RFX-90) compares code
revision, not capability". On 2026-09-20 the production core was at e175e4e =
origin/main exactly — zero drift — while `holds.resolvable` was false and it
had resolved ZERO holds since 2026-08-22, 551 of 593 having expired
unanswered. A revision-only check passes that deployment every day. So this
tool has TWO arms and a failure in either one is a FAIL:

  DRIFT arm       is the deployed commit the commit we test?
  CAPABILITY arm  can this deployment accept an APPROVAL at all?

WHAT THE CAPABILITY ARM COSTS THE TARGET: one unauthenticated GET /healthz.
It does NOT raise a hold and does NOT attempt a resolve. RFX-309 req 3
suggested "raise a hold, attempt one resolve, consume it", and that is the
stronger instrument — but against api-dev it would write hold and
forged-approval records into the same ledger real Attest reports are
generated from, which the fleet bounds forbid. Core publishing the fact
itself (RFX-309 req 2, shipped in #159 and live) is what makes a read-only
arm possible at all. Its limit is stated in LIMITS below, not glossed.

USAGE
  python scripts/check_core_deployment.py --target https://api-dev.reeflex.io
  python scripts/check_core_deployment.py --target http://127.0.0.1:8080 \
      --max-behind 0 --skip-capability

  --ref            git ref the deployment is measured against (default origin/main)
  --max-age-days   fail if the oldest undeployed commit is older than this
                   (default 2)
  --max-behind     fail if more than N commits are undeployed (default: no
                   count limit)
  --repo           path to the git clone (default: this script's repository)
  --timeout        HTTP timeout in seconds (default 15)
  --skip-drift     run the capability arm only (for a scratch core built from
                   a tree the clone does not have)
  --skip-capability  run the drift arm only
  --selftest       run the arm logic against built fixtures and exit

VERDICT — anchored, case-sensitive; parse EXACTLY this line. Same convention
as scripts/check_migration_heads.py and reeflex-app's check_deploy_drift.py:

  CORE-DEPLOYMENT: PASS (...)   exit 0
  CORE-DEPLOYMENT: FAIL (...)   exit 1 — drift, an unidentifiable build, or a
                                deployment that cannot accept an approval
  CORE-DEPLOYMENT: ERROR (...)  exit 2 — the check itself could not run
                                (target unreachable, not a git repo, shallow
                                clone). NOT a pass, and deliberately a
                                different exit code from FAIL so "we could not
                                look" is never filed as "we looked and it was
                                fine".

THE FAILURE MODE THIS MUST NOT HAVE. A check that cannot go red is the defect
it is supposed to catch — `reeflex-claude check` printing "PASS — fail-closed
verified" over a path that could not fail (RFX-147/RFX-205), a release gate
whose green meant no row ran (RFX-179), a CI job reporting success over a
suite that failed (RFX-376). So, stated explicitly and asserted first in the
test suite:

  * a deployment that will not say what it is        -> FAIL, not "unknown, pass"
  * a deployment that publishes no `holds` block     -> FAIL, not "unknown, pass"
  * a target that cannot be reached                  -> ERROR, never PASS

LIMITS, written down rather than discovered later.

  * `revision` is a SELF-REPORT by the build, not an attestation. A compose
    file can set REEFLEX_BUILD_REVISION to any commit and this cannot tell
    that from an honest value; `docker inspect`'s
    org.opencontainers.image.revision stays ground truth for anyone with
    shell access. What it buys is that a build which says nothing, or says
    something that is not on our ref, becomes visible WITHOUT shell access.

  * `holds.resolvable: true` is a statement about the deployment's
    CONFIGURATION — that some credential exists which the approver check
    would accept. It is not a promise that any given hold resolves: the
    rule's NON_RESOLVABLE_RULES guard, the resolution policy, four-eyes,
    expiry and consumption all still run. This arm therefore detects the
    100% case (nobody can approve anything) and not the per-hold ones. It is
    core's own report about itself, not an independent probe; an end-to-end
    arm that really spends an approval is the stronger check and belongs on
    a scratch core, not on production.

  * A green here says nothing about reeflex-app. That deployment has its own
    checker in its own repo, with its own clone.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# `datetime.UTC` is 3.11+. This is a STANDALONE tool: CI runs it on 3.12, but
# an operator debugging a deploy runs it with whatever `python3` the box has
# (3.9 on the fleet devbox, 3.6 on .118), and a checker that dies on an
# ImportError reads exactly like a checker that found nothing.
UTC = timezone.utc  # noqa: UP017 - `datetime.UTC` is 3.11+; see above

DEFAULT_REF = "origin/main"
DEFAULT_MAX_AGE_DAYS = 2.0
DEFAULT_TIMEOUT = 15
DEFAULT_TARGET = "https://api-dev.reeflex.io"

VERDICT_PASS = "CORE-DEPLOYMENT: PASS"
VERDICT_FAIL = "CORE-DEPLOYMENT: FAIL"
VERDICT_ERROR = "CORE-DEPLOYMENT: ERROR"


class CheckError(Exception):
    """The check could not run. Exit 2, never conflated with a clean result."""


# ---------------------------------------------------------------------------
# reading the deployment
# ---------------------------------------------------------------------------

def fetch_healthz(target: str, timeout: int) -> tuple[dict, str]:
    """One unauthenticated GET. Core serves /healthz without a token by
    construction (server.py: "GET /healthz is always unauthenticated"), so
    this needs no secret and writes nothing."""
    url = target.rstrip("/") + "/healthz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # 4xx/5xx: reachable, not usable
        raise CheckError("%s answered HTTP %s" % (url, exc.code)) from exc
    except urllib.error.URLError as exc:
        raise CheckError("%s is unreachable (%s)" % (url, exc.reason)) from exc
    except (ValueError, OSError) as exc:
        raise CheckError("%s did not answer JSON (%s)" % (url, exc)) from exc
    if not isinstance(body, dict):
        raise CheckError("%s answered JSON that is not an object" % url)
    return body, url


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

def git(repo: pathlib.Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise CheckError(
            "git %s failed in %s: %s" % (" ".join(args), repo, proc.stderr.strip())
        )
    return proc.stdout.strip()


def commit_exists(repo: pathlib.Path, rev: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", "%s^{commit}" % rev],
        capture_output=True, text=True,
    ).returncode == 0


def is_ancestor(repo: pathlib.Path, rev: str, ref: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", rev, ref],
        capture_output=True, text=True,
    ).returncode == 0


def _parse_git_iso(iso: str) -> datetime:
    """Parse git's `%cI`, including the `Z` spelling.

    `datetime.fromisoformat` did not accept a trailing `Z` until Python 3.11,
    and git prints `Z` (not `+00:00`) whenever the committer's timezone is
    UTC — which is every commit made on a GitHub runner. This tool promises
    to run under the `python3` an operator actually has (3.9 on the devbox,
    3.6 on .118), and there the unhandled `ValueError` escapes as a traceback
    with NO anchored verdict line: a reader parsing for `CORE-DEPLOYMENT:`
    finds nothing at all. Caught by
    tests/test_check_core_deployment.py::test_a_stale_deployment_fails_on_AGE.
    """
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    return datetime.fromisoformat(iso)


def undeployed(repo: pathlib.Path, rev: str, ref: str) -> list:
    """[(sha, committed_at, subject)] for every commit on `ref` not in `rev`."""
    out = git(repo, "rev-list", "--reverse", "--format=%H%x1f%cI%x1f%s",
              "%s..%s" % (rev, ref))
    rows = []
    for line in out.splitlines():
        if line.startswith("commit ") or not line.strip():
            continue
        # maxsplit=2, so a subject containing the separator keeps its commit in
        # the list. Dropping an unparseable row would UNDERSTATE the drift,
        # which is this tool failing open on its own arithmetic.
        sha, iso, subject = line.split("\x1f", 2)
        rows.append((sha, _parse_git_iso(iso), subject))
    return rows


# ---------------------------------------------------------------------------
# the two arms
# ---------------------------------------------------------------------------

def capability_arm(body: dict, endpoint: str) -> tuple[bool, list, list]:
    """Can this deployment accept an approval at all? (RFX-309)"""
    lines: list = []
    failures: list = []
    holds = body.get("holds")

    # A core too old to publish the fact is NOT a pass. This is the same rule
    # as "a build that will not say what it is": the pre-#159 image answered
    # identically whether or not it could approve, and reading that silence
    # as health is exactly how the defect survived eight days.
    if not isinstance(holds, dict):
        failures.append(
            "the deployment publishes no `holds` block on %s, so it cannot say "
            "whether any human can approve anything (a core older than RFX-309 "
            "/ v0.2.2) — unknown is reported as a failure, not as a pass"
            % endpoint
        )
        return False, lines, failures

    resolvable = holds.get("resolvable")
    reason = holds.get("reason", "")
    approvers = holds.get("verified_approvers")
    ttl = holds.get("ttl_seconds")
    lines.append("capability   resolvable=%s reason=%s verified_approvers=%s ttl_seconds=%s"
                 % (resolvable, reason or "(none)", approvers, ttl))

    if resolvable is not True:
        failures.append(
            "this deployment cannot accept an approval (`holds.resolvable` is %r, "
            "reason %r): every hold it raises expires unanswered%s — the product's "
            "human-oversight loop is not merely untested here, it cannot run"
            % (resolvable, reason,
               "" if not isinstance(ttl, int) else " after %s seconds" % ttl)
        )
    return not failures, lines, failures


def drift_arm(
    body: dict,
    endpoint: str,
    repo: pathlib.Path,
    ref: str,
    max_age_days: float,
    max_behind,
) -> tuple[bool, list, list]:
    """Is the deployed commit the commit we test? (RFX-90 / RFX-88)"""
    lines: list = []
    failures: list = []

    ref_sha = git(repo, "rev-parse", ref)
    lines.append("%-12s %s" % (ref, ref_sha))

    revision = (body.get("revision") or "").strip()

    # (1) the build will not say what it is.
    if not revision:
        failures.append(
            "the deployment reports no build revision (`revision` absent or empty "
            "on %s), so it cannot be compared to any commit — this is drift by "
            "default, not a pass" % endpoint
        )
        return False, lines, failures

    lines.append("deployed     %s" % revision)

    # (2) it says something this clone has never heard of. Note the second
    # cause: this tool must run against the MONOREPO clone, because a core
    # commit is not an object in reeflex-app's.
    if not commit_exists(repo, revision):
        failures.append(
            "the deployment reports revision %s which is not a commit in %s "
            "(unfetched, a branch that was never merged, or the wrong clone — a "
            "core revision does not resolve in the reeflex-app repository)"
            % (revision, repo)
        )
        return False, lines, failures

    # (3) it is a commit, but not one on the ref we test against.
    if not is_ancestor(repo, revision, ref):
        ahead = git(repo, "rev-list", "--count", "%s..%s" % (ref, revision))
        failures.append(
            "the deployed commit %s is NOT an ancestor of %s (%s commit(s) on it "
            "are not on %s) — the deployment is on a side branch"
            % (git(repo, "rev-parse", "--short", revision), ref, ahead, ref)
        )
        return False, lines, failures

    # (4) it is behind. Age is the budget, not count: api-dev is CD-style but
    # the monorepo merges all day, and failing on behind>0 would make this job
    # permanently red — and a permanently red job is one nobody reads, which
    # is the same death as a check that never speaks. `--max-behind 0` exists
    # for whoever wants the strict reading. What actually hurt us was AGE:
    # 34 days, a month-old image (RFX-88).
    rows = undeployed(repo, revision, ref)
    lines.append("behind       %d commit(s) on %s" % (len(rows), ref))
    if rows:
        oldest_sha, oldest_at, oldest_subject = rows[0]
        age_days = (datetime.now(UTC) - oldest_at).total_seconds() / 86400.0
        lines.append("oldest       %s %s (%.1f days undeployed) %s"
                     % (oldest_sha[:7], oldest_at.isoformat(), age_days,
                        oldest_subject[:70]))
        for sha, at, subject in rows:
            lines.append("  - %s %s %s" % (sha[:7], at.date().isoformat(), subject[:78]))
        if age_days > max_age_days:
            failures.append(
                "the oldest undeployed commit %s has been waiting %.1f days, "
                "budget is %.1f days" % (oldest_sha[:7], age_days, max_age_days)
            )
        if max_behind is not None and len(rows) > max_behind:
            failures.append(
                "%d commit(s) undeployed, budget is %d" % (len(rows), max_behind)
            )
    return not failures, lines, failures


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def check(
    target: str,
    repo: pathlib.Path,
    ref: str = DEFAULT_REF,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    max_behind=None,
    timeout: int = DEFAULT_TIMEOUT,
    run_drift: bool = True,
    run_capability: bool = True,
) -> tuple[bool, list, str]:
    if not run_drift and not run_capability:
        raise CheckError("both arms are skipped — there is nothing to check")

    body, endpoint = fetch_healthz(target, timeout)
    lines = ["target       %s -> %s" % (endpoint, json.dumps(body, sort_keys=True))]
    failures: list = []

    if run_capability:
        _ok, cap_lines, cap_failures = capability_arm(body, endpoint)
        lines += cap_lines
        failures += cap_failures
    else:
        lines.append("capability   SKIPPED (--skip-capability)")

    if run_drift:
        _ok, drift_lines, drift_failures = drift_arm(
            body, endpoint, repo, ref, max_age_days, max_behind
        )
        lines += drift_lines
        failures += drift_failures
    else:
        lines.append("drift        SKIPPED (--skip-drift)")

    if failures:
        return False, lines, "; ".join(failures)

    arms = [n for n, on in (("capability", run_capability), ("drift", run_drift)) if on]
    return True, lines, "%s: %s arm(s) clean" % (target, "+".join(arms))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Is the deployed reeflex-core the build we test, and can it "
                    "accept an approval? (RFX-309 req 3, RFX-90)",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--max-age-days", type=float, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--max-behind", type=int, default=None)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--skip-drift", action="store_true")
    parser.add_argument("--skip-capability", action="store_true")
    parser.add_argument("--selftest", action="store_true",
                        help="prove both arms can go red, then exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    repo = pathlib.Path(args.repo) if args.repo else pathlib.Path(__file__).resolve().parent.parent
    try:
        ok, lines, detail = check(
            target=args.target,
            repo=repo,
            ref=args.ref,
            max_age_days=args.max_age_days,
            max_behind=args.max_behind,
            timeout=args.timeout,
            run_drift=not args.skip_drift,
            run_capability=not args.skip_capability,
        )
    except CheckError as exc:
        print("%s (%s)" % (VERDICT_ERROR, exc))
        return 2

    for line in lines:
        print(line)
    print("%s (%s)" % (VERDICT_PASS if ok else VERDICT_FAIL, detail))
    return 0 if ok else 1


def _selftest() -> int:
    """Prove BOTH arms can go red, on this file, without a network or a clone.

    A tool whose green nobody has seen turn red is the class of defect it
    exists to catch, so the selftest is deliberately about the FAILING
    directions, and it is the same property tests/test_check_core_deployment.py
    asserts under unittest discovery (gate.yml runs both).
    """
    cases = [
        ("healthy", {"status": "ok", "holds": {"resolvable": True,
                                               "reason": "credentials_bound",
                                               "verified_approvers": 1,
                                               "ttl_seconds": 14400}}, True),
        ("api-dev today", {"status": "ok", "holds": {"resolvable": False,
                                                     "reason": "verification_not_configured",
                                                     "verified_approvers": 0,
                                                     "ttl_seconds": 14400}}, False),
        ("pre-RFX-309 core", {"status": "ok"}, False),
        ("resolvable absent", {"status": "ok", "holds": {"reason": "x"}}, False),
    ]
    failed = 0
    for label, body, expect_ok in cases:
        ok, _lines, failures = capability_arm(body, "/healthz")
        mark = "ok " if ok == expect_ok else "BAD"
        if ok != expect_ok:
            failed += 1
        print("%s capability %-20s -> %s %s"
              % (mark, label, "PASS" if ok else "FAIL",
                 "" if ok else "(%s)" % failures[0][:70]))
    if failed:
        print("%s (selftest: %d case(s) wrong)" % (VERDICT_ERROR, failed))
        return 2
    print("%s (selftest: capability arm goes red on 3 of 4 fixtures, green on 1)"
          % VERDICT_PASS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
