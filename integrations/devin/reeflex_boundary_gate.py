#!/usr/bin/env python3
"""reeflex_boundary_gate.py -- ask reeflex-core before a CI job takes the
irreversible step a Devin (Cognition) change leads to: merging into a protected
branch, or deploying (RFX-450).

Devin has no pre-action hook, so Reeflex cannot see or stop what Devin does
inside its own sandbox. What it can gate is the boundary Devin's work has to
cross to reach your systems -- the pull request into `main`, the deploy job --
because those run in YOUR CI. This script is that gate. It is stdlib-only
Python 3.9+, so a GitHub Actions runner can run it with no install step.

    merge   For a pull_request event: if the PR author is one of
            REEFLEX_GATE_AUTHORS (default: Devin's GitHub app) AND the diff
            touches a path matching REEFLEX_GATE_PATHS (default: migrations/,
            infra/, *.tf, Dockerfile, CI config), ask core. Otherwise exit 0
            and say why nothing was asked.
    deploy  Ask core before a deploy step, every time it runs.

What core answers decides the exit code:

    allow             -> 0
    deny              -> 1
    require_approval  -> print the hold id, poll GET /v1/holds/{id} until a
                         human resolves it in the Reeflex portal (or the hold
                         expires, or REEFLEX_WAIT_SECONDS passes); on approval,
                         resubmit the same envelope with the approval attached
                         and exit by THAT answer. Rejected / expired / timeout
                         -> 1.
    anything else (core unreachable, a 5xx, an answer it cannot parse) -> 1.
    The gate fails closed: a CI job that cannot get an answer does not merge.

For the step to stop a merge Devin performs itself, the job running this script
must be a REQUIRED status check on the protected branch. Without that, GitHub
lets the merge through whatever this script says.

Environment:
  REEFLEX_CORE_URL       required, e.g. https://core.example.com
  REEFLEX_CORE_TOKEN     bearer for /v1/decide and /v1/holds (if core has auth on)
  REEFLEX_GATE_AUTHORS   comma-separated PR author logins to gate
                         (default "devin-ai-integration[bot]")
  REEFLEX_GATE_PATHS     comma-separated fnmatch patterns (default below)
  REEFLEX_ENVIRONMENT    target environment for the envelope (default production)
  REEFLEX_WAIT_SECONDS   how long to wait for a human (default 1800)
  REEFLEX_POLL_SECONDS   poll interval (default 15)
  REEFLEX_PORTAL_URL     optional; printed so the approver knows where to go
  GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT,
  GITHUB_ACTOR, GITHUB_SHA, GITHUB_STEP_SUMMARY -- set by GitHub Actions.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_AUTHORS = "devin-ai-integration[bot]"
DEFAULT_PATHS = ",".join([
    "migrations/*", "*/migrations/*", "infra/*", "*/infra/*",
    "*.tf", "*.tfvars", "Dockerfile", "*/Dockerfile", "Dockerfile.*", "*/Dockerfile.*",
    ".github/workflows/*", ".github/reeflex/*", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/*", "azure-pipelines.yml",
])

# (method, url, body or None) -> (status, parsed JSON or None)
Http = Callable[[str, str, Optional[dict]], Tuple[int, Optional[dict]]]


class GateError(Exception):
    """Anything that stops the gate from getting an answer. Exit 1."""


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def make_http(core_url: str, token: Optional[str], timeout: float = 20.0) -> Http:
    base = core_url.rstrip("/")

    def http(method: str, path: str, body: Optional[dict]) -> Tuple[int, Optional[dict]]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 -- operator-set URL
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except (urllib.error.URLError, OSError) as exc:
            raise GateError("reeflex-core unreachable at %s: %s" % (base, exc.__class__.__name__)) from exc
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    return http


# --- what is gated -------------------------------------------------------------


def split_list(value: str) -> List[str]:
    return [p.strip() for p in value.replace("\n", ",").split(",") if p.strip()]


def risky_files(files: List[str], patterns: List[str]) -> List[str]:
    """The changed paths that match any pattern, by full path or by basename."""

    out = []
    for f in files:
        f = f.strip()
        if not f:
            continue
        base = f.rsplit("/", 1)[-1]
        if any(fnmatch.fnmatchcase(f, p) or fnmatch.fnmatchcase(base, p) for p in patterns):
            out.append(f)
    return out


def merge_envelope(*, repo: str, pr: dict, files: List[str], environment: str, session_id: str) -> dict:
    """The action a merge of this PR is: an update to the protected branch that
    downstream automation turns into migrations run, infrastructure changed, a
    pipeline rewritten. Declared irreversible + broad on purpose -- a revert
    commit does not un-run a migration -- which is R2 in core's pack."""

    base = (pr.get("base") or {}).get("ref") or "main"
    return {
        "reeflex_version": "0.2",
        "agent": {
            "id": "agent:devin",
            "on_behalf_of": (pr.get("user") or {}).get("login"),
            "session_id": session_id,
        },
        "action": {"namespace": "github", "verb": "update", "ability": "github/merge-pull-request"},
        "target": {"kind": "branch", "ref": "%s:%s" % (repo, base), "environment": environment},
        "params": {
            "pull_request": pr.get("number"),
            "head_sha": (pr.get("head") or {}).get("sha"),
            "gated_paths": sorted(files)[:50],
        },
        "magnitude": {"count": len(files)},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
    }


def deploy_envelope(*, repo: str, target: str, environment: str, sha: Optional[str], actor: Optional[str],
                    session_id: str) -> dict:
    return {
        "reeflex_version": "0.2",
        "agent": {"id": "agent:ci-deploy", "on_behalf_of": actor, "session_id": session_id},
        "action": {"namespace": "deploy", "verb": "execute", "ability": "deploy/release-to-environment"},
        "target": {"kind": "service", "ref": "%s:%s" % (repo, target), "environment": environment},
        "params": {"sha": sha},
        "magnitude": {"count": 1},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"},
    }


# --- asking core ---------------------------------------------------------------


def decide(http: Http, envelope: dict, approval_hold: Optional[str] = None) -> dict:
    body = dict(envelope)
    body["meta"] = {"nonce": uuid.uuid4().hex}
    body["approval"] = {"present": True, "hold_id": approval_hold} if approval_hold else {"present": False}
    status, doc = http("POST", "/v1/decide", body)
    if status != 200 or not isinstance(doc, dict) or doc.get("decision") not in ("allow", "deny", "require_approval"):
        # core puts the specific refusal in `reason` (a portal credential sent
        # without X-Reeflex-Gate is 403 {"error": "forbidden", "reason":
        # "gate_not_declared"}); print it, or every 403 reads the same.
        doc = doc if isinstance(doc, dict) else {}
        raise GateError("reeflex-core answered HTTP %s without a decision: %s" % (
            status, doc.get("reason") or doc.get("error")))
    return doc


def wait_for_hold(http: Http, hold_id: str, *, wait_s: float, poll_s: float,
                  sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                  log: Callable[[str], None] = print) -> str:
    """Poll until the hold is no longer pending. Returns its status, or
    'timeout'."""

    deadline = clock() + wait_s
    last = None
    while True:
        status, doc = http("GET", "/v1/holds/%s" % hold_id, None)
        if status in (401, 403):
            # core reads holds with its operator token; a portal-issued gate
            # credential is accepted on /v1/decide and refused here.
            raise GateError("this token could ask for the decision but may not read hold %s (HTTP %s); "
                            "REEFLEX_CORE_TOKEN must be core's operator token (REEFLEX_AUTH_TOKEN), "
                            "not a portal-issued gate credential" % (hold_id, status))
        if status != 200 or not isinstance(doc, dict):
            raise GateError("reading hold %s answered HTTP %s" % (hold_id, status))
        state = doc.get("status")
        if state != last:
            log("reeflex: hold %s is %s" % (hold_id, state))
            last = state
        if state != "pending":
            return str(state)
        if clock() >= deadline:
            return "timeout"
        sleep(poll_s)


def gate(http: Http, envelope: dict, *, wait_s: float, poll_s: float, portal: Optional[str],
         log: Callable[[str], None] = print, **wait_kw: Any) -> Tuple[int, Dict[str, Any]]:
    """Ask, wait if held, resubmit if approved. (exit code, record)."""

    first = decide(http, envelope)
    rec: Dict[str, Any] = {"decision": first["decision"], "rule": first.get("rule"),
                           "decision_id": first.get("decision_id")}
    log("reeflex: %s (%s) -- %s" % (first["decision"], first.get("rule"), first.get("reason")))
    if first["decision"] == "allow":
        return 0, rec
    if first["decision"] == "deny":
        return 1, rec

    hold_id = first.get("hold_id")
    if not hold_id:
        raise GateError("require_approval without a hold_id")
    rec["hold_id"] = hold_id
    log("reeflex: HELD -- hold_id %s, expires %s" % (hold_id, first.get("expires_ts")))
    if portal:
        log("reeflex: approve or reject it at %s" % portal)
    outcome = wait_for_hold(http, hold_id, wait_s=wait_s, poll_s=poll_s, log=log, **wait_kw)
    rec["hold_status"] = outcome
    if outcome != "approved":
        log("reeflex: not approved (%s) -- this step does not run" % outcome)
        return 1, rec

    again = decide(http, envelope, approval_hold=hold_id)
    rec.update({"resubmission": again["decision"], "resubmission_rule": again.get("rule"),
                "resubmission_decision_id": again.get("decision_id")})
    log("reeflex: resubmitted with the approval -> %s (%s)" % (again["decision"], again.get("rule")))
    return (0 if again["decision"] == "allow" else 1), rec


# --- entry point ---------------------------------------------------------------


def _session_id(mode: str) -> str:
    return "gh:%s:%s:%s:%s" % (_env("GITHUB_REPOSITORY", "local"), _env("GITHUB_RUN_ID", uuid.uuid4().hex[:8]),
                               _env("GITHUB_RUN_ATTEMPT", "1"), mode)


def _summary(lines: List[str]) -> None:
    path = _env("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def main(argv: Optional[List[str]] = None, http: Optional[Http] = None) -> int:
    ap = argparse.ArgumentParser(prog="reeflex_boundary_gate")
    sub = ap.add_subparsers(dest="mode", required=True)
    m = sub.add_parser("merge", help="gate a pull request merge")
    m.add_argument("--changed-files", required=True, help="file with one changed path per line")
    m.add_argument("--event", default=_env("GITHUB_EVENT_PATH"), help="GitHub event JSON (pull_request)")
    d = sub.add_parser("deploy", help="gate a deploy step")
    d.add_argument("--target", required=True, help="what is being deployed, e.g. payments-api")
    for p in (m, d):
        p.add_argument("--dry-run", action="store_true", help="print the envelope, ask nothing")
    args = ap.parse_args(argv)

    environment = _env("REEFLEX_ENVIRONMENT", "production")
    repo = _env("GITHUB_REPOSITORY", "local/repo")
    session_id = _session_id(args.mode)

    if args.mode == "merge":
        if not args.event:
            print("reeflex: no --event / GITHUB_EVENT_PATH -- cannot tell who authored this change", file=sys.stderr)
            return 1
        with open(args.event, encoding="utf-8") as fh:
            pr = (json.load(fh) or {}).get("pull_request") or {}
        author = (pr.get("user") or {}).get("login") or ""
        authors = split_list(_env("REEFLEX_GATE_AUTHORS", DEFAULT_AUTHORS))
        with open(args.changed_files, encoding="utf-8") as fh:
            files = [line.strip() for line in fh if line.strip()]
        hits = risky_files(files, split_list(_env("REEFLEX_GATE_PATHS", DEFAULT_PATHS)))
        if author not in authors:
            print("reeflex: PR author %r is not in REEFLEX_GATE_AUTHORS -- not gated" % author)
            _summary(["### Reeflex boundary gate", "Not gated: author `%s` is not a gated agent." % author])
            return 0
        if not hits:
            print("reeflex: %d changed file(s), none under a gated path -- not gated" % len(files))
            _summary(["### Reeflex boundary gate", "Not gated: no changed file matches a gated path."])
            return 0
        print("reeflex: %s changed %d gated path(s): %s" % (author, len(hits), ", ".join(hits[:10])))
        envelope = merge_envelope(repo=repo, pr=pr, files=hits, environment=environment, session_id=session_id)
    else:
        envelope = deploy_envelope(repo=repo, target=args.target, environment=environment,
                                   sha=_env("GITHUB_SHA"), actor=_env("GITHUB_ACTOR"), session_id=session_id)

    if args.dry_run:
        print(json.dumps(envelope, indent=2, sort_keys=True))
        return 0

    core = _env("REEFLEX_CORE_URL")
    if http is None:
        if not core:
            print("reeflex: REEFLEX_CORE_URL is not set -- failing closed", file=sys.stderr)
            return 1
        http = make_http(core, _env("REEFLEX_CORE_TOKEN"))
    try:
        code, rec = gate(http, envelope, wait_s=float(_env("REEFLEX_WAIT_SECONDS", "1800")),
                         poll_s=float(_env("REEFLEX_POLL_SECONDS", "15")), portal=_env("REEFLEX_PORTAL_URL"))
    except GateError as exc:
        print("reeflex: %s -- failing closed" % exc, file=sys.stderr)
        _summary(["### Reeflex boundary gate", "**Failed closed:** %s" % exc])
        return 1
    _summary(["### Reeflex boundary gate", "", "| field | value |", "|---|---|"]
             + ["| %s | `%s` |" % (k, v) for k, v in rec.items()]
             + ["", "**%s**" % ("Allowed" if code == 0 else "Blocked")])
    return code


if __name__ == "__main__":
    sys.exit(main())
