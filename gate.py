#!/usr/bin/env python3
"""gate.py — the uniform repo-level preflight gate (WoW §18.5 / §14.6).

WHY THIS EXISTS: on 2026-07-28 the `mcp` SDK released 2.0.0 and both published
PyPI packages died on fresh install, while every CI job stayed green for five
days — each workflow tested its own slice with `pip install -e .` and nothing
ever invoked a BUILT artifact. This gate is the single command that must be
green before trusting the tree:

  1. checks the environment FIRST and stops on a wrong one (never a lying green)
  2. builds every published package from the tree and INVOKES each entry point
     ("the file exists" is not proof — the P0 failure mode died at invocation)
  3. runs the COMPLETE test suite, not the touched slice
  4. includes the fresh-install-from-PyPI smoke (in CI this leg is DELEGATED to
     .github/workflows/smoke-pypi.yml via workflow_call — one copy, not two)
  5. parses its own output with anchored, case-sensitive regexes; a log line
     merely containing the word "pass" cannot flip the gate green
     (prove it: python gate.py --selftest)

USAGE
  python gate.py                        # full local preflight (the release preflight)
  python gate.py --pypi delegated       # CI: smoke-pypi.yml runs the PyPI leg as a sibling job
  python gate.py --pypi skip            # tree-health only; prints a flagged skip
  python gate.py --allow-skips wp-conformance
  python gate.py --core-url http://127.0.0.1:8099   # also run the WP live-core harness
  python gate.py --selftest             # prove the anchored parsing (DoD 5)

VERDICT — anchored, case-sensitive; parse EXACTLY these lines:
  GATE: GREEN        exit 0 — every component ran and passed (skips only via --allow-skips)
  GATE: RED          exit 1 — at least one component FAILED
  GATE: ENV-STOP     exit 2 — environment unfit; NOTHING was gated
  GATE: INCOMPLETE   exit 3 — no failures, but a component was SKIPPED; not green (§22.8)

A suite that cannot run in this context prints `COMPONENT <key>: SKIPPED (<reason>)`
— never silently absent. The `drift` component fails the gate when it finds test
files that no enumerated component covers, so a new suite cannot appear without
either being wired in here or turning the gate red.

SILENT SKIPS (RFX-87; sweep RFX-105..RFX-115). `drift` proved insufficient: it
checks that a test file SITS in an enumerated root, never that it YIELDS TESTS. PR #89's
regression guard for a live fail-open security hole sat in the right directory
and collected ZERO tests for its entire life — green every run, never one
assertion. Location is not execution. Three components now close that class:

  test-census   scripts/check_test_census.py — every enumerated test file must
                yield tests under the runner its root is ACTUALLY run with, no
                test body may be empty, and no test may be skipped
                unconditionally without a ticketed, printed waiver.
  skip-ledger   prints every SKIPPED/DELEGATED component with its reason, and
                REFUSES an `--allow-skips` key that carries no registered
                justification (SKIP_REGISTRY) — you cannot silence a skip here
                without writing down why.
  pypi-smoke    `--pypi delegated` now VERIFIES that a sibling job actually
                invokes smoke-pypi.yml. Delegation you cannot point at is not
                delegation, it is an unrun component printing a reassuring word.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Markers that prove gate.py sits at a Reeflex repo root (wrong dir => ENV-STOP).
ROOT_MARKERS = [
    "reeflex-core/policy",
    "reeflex-core/tests",
    "reeflex-mcp/pyproject.toml",
    "reeflex-holds/pyproject.toml",
    "reeflex-claude/pyproject.toml",
    ".github/workflows",
]

# The packages this repo publishes to PyPI, with their console entry points.
# reeflex-core ships as a GHCR image, not a PyPI package — it is gated by its
# test suites below, not by a wheel build.
PUBLISHED = [
    # (pypi/dist name, entry point, has argparse usage banner)
    ("reeflex-mcp", "reeflex-mcp", True),
    # RFX-42: reeflex-holds now has real argparse subcommands (list/approve/
    # reject) for any argv; `--help` prints a real anchored usage banner
    # exactly like the other two. With NO argv it still starts the stdio MCP
    # server unchanged (see server.main()) -- not exercised by this smoke.
    ("reeflex-holds", "reeflex-holds", True),
    ("reeflex-claude", "reeflex-claude", True),
]

# Every test-suite root in the repo. The drift check fails the gate if a
# test-looking file exists OUTSIDE these roots (a suite nobody wired in).
SUITE_ROOTS = [
    "reeflex-core/policy",
    "reeflex-core/tests",
    "reeflex-claude/policy",
    "reeflex-claude/tests",
    "reeflex-mcp/tests",
    "reeflex-holds/tests",
    "n8n-nodes-reeflex/test",
    "reeflex-wordpress/tests",
    "scripts/tests",
]

# RFX-49: candidate locations for a checked-out reeflex-app (private repo,
# never vendored into this tree) whose migrations/versions this gate can
# additionally validate. First existing match wins; none found -> SKIPPED
# (this repo itself has no alembic migrations of its own).
APP_MIGRATIONS_CANDIDATES = [
    "/root/reeflex/reeflex-app/migrations/versions",  # canonical devbox clone (WoW R.5)
    os.path.join(os.path.dirname(REPO_ROOT), "reeflex-app", "migrations", "versions"),  # sibling checkout
]

TEST_FILE_PATTERNS = ["test_*.py", "*_test.py", "*_test.rego", "*.test.ts", "*.test.js"]

# RFX-108: the ONLY component keys whose SKIP may be silenced via --allow-skips,
# each with the reason it can be structurally unrunnable. An --allow-skips key
# that is not registered here is REFUSED by the skip-ledger component: a skip
# that nobody wrote a reason for is precisely the class this gate exists to
# kill, and "--allow-skips <anything>" was a blank cheque.
SKIP_REGISTRY = {
    "wp-conformance":
        "needs a live reeflex-core and a php CLI. NOTE (RFX-105): CI now STARTS a "
        "core and passes --core-url, so this allowance is no longer used there — "
        "it remains for local runs on a box with no php.",
    "migration-heads":
        "validates the PRIVATE reeflex-app repo's alembic graph, which is never "
        "checked out on this public repo's runner. reeflex-app's own ci.yml runs "
        "the ENFORCING copy of the same check against its own migrations on every "
        "PR — this leg is the free bonus when both repos sit side by side.",
    "pypi-smoke":
        "--pypi skip is a deliberate tree-health-only run; the published-artifact "
        "smoke is owned by smoke-pypi.yml, which also runs daily on a schedule.",
    "unittest-core":
        "the core suite silently drops its ~40 opa-dependent tests without the opa "
        "binary, so without opa the whole component is a loud SKIP rather than a "
        "partial green. Allowed only on a box that genuinely cannot install opa.",
    "rego-core": "no opa binary available in this context.",
    "rego-claude": "no opa binary available in this context.",
    "npm-n8n": "no npm/node >=20.15 available in this context.",
}

DRIFT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "dist-test",
    "build", "site", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist-artifacts", "pypi-dist",
}

SUBPROCESS_TIMEOUT = 1800  # seconds; generous — npm ci / pip resolve are the slow legs

# --------------------------------------------------------------------------
# Anchored, case-sensitive parsers (DoD 5). ^/$ with re.M; NO re.I anywhere.
# --------------------------------------------------------------------------

OPA_PASS_RE = re.compile(r"^PASS: (\d+)/(\d+)$", re.M)
PYTEST_PASS_RE = re.compile(r"^(\d+) passed\b[^\n]* in [0-9.]+s(?: \([^)]*\))?$", re.M)
PYTEST_SKIP_RE = re.compile(r"^\d+ passed, (\d+) skipped\b", re.M)
UNITTEST_RAN_RE = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$", re.M)
UNITTEST_OK_RE = re.compile(r"^OK(?: \((?P<detail>[^)]*)\))?$", re.M)
N8N_PASS_RE = re.compile(r"^(\d+) passed, (\d+) failed, (\d+) total$", re.M)
MIGRATION_HEADS_RE = re.compile(r"^MIGRATION-HEADS: (PASS|FAIL) \((.*)\)$", re.M)
TEST_CENSUS_RE = re.compile(r"^TEST-CENSUS: (PASS|FAIL) \((.*)\)$", re.M)
USAGE_RE_TMPL = r"^usage: %s\b"
COMPONENT_RE = re.compile(r"^COMPONENT ([a-z0-9-]+): (PASS|FAIL|SKIPPED|DELEGATED)\b(?: \((.*)\))?$")


def parse_opa(exit_code: int, text: str):
    """PASS iff exit 0 AND the summary line `PASS: n/n` matches with n == n."""
    m = OPA_PASS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == m.group(2):
        return True, "%s/%s rego tests" % (m.group(1), m.group(2))
    if exit_code == 0:
        return False, "exit 0 but no anchored 'PASS: n/n' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_pytest(exit_code: int, text: str):
    """PASS iff exit 0 AND an anchored `N passed ... in X.XXs` summary matches."""
    m = PYTEST_PASS_RE.search(text)
    if exit_code == 0 and m:
        s = PYTEST_SKIP_RE.search(text)
        skipped = int(s.group(1)) if s else 0
        detail = "%s tests" % m.group(1)
        if skipped:
            detail += ", %d skipped in-suite" % skipped
        return True, detail
    if exit_code == 0:
        return False, "exit 0 but no anchored pytest pass summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_unittest(exit_code: int, text: str):
    """PASS iff exit 0 AND `Ran N tests in Xs` AND an anchored `OK` line."""
    ran = UNITTEST_RAN_RE.search(text)
    ok = UNITTEST_OK_RE.search(text)
    if exit_code == 0 and ran and ok:
        detail = "%s tests" % ran.group(1)
        if ok.group("detail"):
            detail += ", %s in-suite" % ok.group("detail")
        return True, detail
    if exit_code == 0:
        return False, "exit 0 but no anchored 'Ran N tests' + 'OK' — cannot confirm"
    return False, "exit %d" % exit_code


def parse_n8n(exit_code: int, text: str):
    """PASS iff exit 0 AND the runner's own `N passed, 0 failed, N total` line."""
    m = N8N_PASS_RE.search(text)
    if exit_code == 0 and m and m.group(2) == "0" and m.group(1) == m.group(3):
        return True, "%s tests" % m.group(1)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'N passed, 0 failed, N total' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_migration_heads(exit_code, text):
    """PASS iff exit 0 AND the checker's own anchored 'MIGRATION-HEADS: PASS
    (...)' line — mirrors the other parse_* functions (DoD 5): an exit 0
    with no matching line, or a matching FAIL line, cannot flip this green."""
    m = MIGRATION_HEADS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'MIGRATION-HEADS: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def parse_test_census(exit_code, text):
    """PASS iff exit 0 AND the census's own anchored 'TEST-CENSUS: PASS (...)'
    line — same shape as parse_migration_heads (DoD 5). A census that cannot
    say PASS in its own words cannot flip this component green."""
    m = TEST_CENSUS_RE.search(text)
    if exit_code == 0 and m and m.group(1) == "PASS":
        return True, m.group(2)
    if m and m.group(1) == "FAIL":
        return False, m.group(2)
    if exit_code == 0:
        return False, "exit 0 but no anchored 'TEST-CENSUS: PASS' summary — cannot confirm"
    return False, "exit %d" % exit_code


def audit_skips(statuses, allow_skips, registry=None):
    """RFX-108: account for every skip in this run.

    Returns (ok, lines). NOT green when an --allow-skips key carries no
    registered justification — silencing a skip must cost you a written
    reason. A STALE allowance (the key is allowed but the component actually
    ran) is reported as a WARN rather than a failure: it is a cleanup, not a
    lying green, and failing on it would break every local invocation the
    moment a suite starts working again."""
    registry = SKIP_REGISTRY if registry is None else registry
    lines = []
    skipped = sorted(k for k, s in statuses.items() if s == "SKIPPED")
    delegated = sorted(k for k, s in statuses.items() if s == "DELEGATED")

    for k in skipped:
        allowed = k in allow_skips
        lines.append("  SKIPPED    %s%s" % (k, "  [allowed]" if allowed else "  [NOT ALLOWED -> INCOMPLETE]"))
        lines.append("             why: %s" % registry.get(k, "(no registered justification)"))
    for k in delegated:
        lines.append("  DELEGATED  %s  (ran elsewhere — verified, see the component)" % k)
    if not skipped and not delegated:
        lines.append("  nothing was skipped or delegated in this run")

    unregistered = sorted(k for k in allow_skips if k not in registry)
    stale = sorted(k for k in allow_skips if k in statuses and statuses[k] != "SKIPPED")
    for k in stale:
        lines.append("  WARN       --allow-skips %s is STALE: that component reported %s, not "
                     "SKIPPED. Drop it from --allow-skips." % (k, statuses[k]))
    for k in unregistered:
        lines.append("  REFUSED    --allow-skips %s is not in SKIP_REGISTRY — a skip with no "
                     "written justification cannot be silenced here." % k)
    return not unregistered, lines


def derive_verdict(lines, allow_skips):
    """Compute the final verdict EXCLUSIVELY by re-parsing the gate's own
    emitted COMPONENT lines (anchored, case-sensitive) — DoD(5) taken
    literally: if the transcript cannot be parsed back, nothing turns green."""
    statuses = {}
    for line in lines:
        m = COMPONENT_RE.match(line)
        if m:
            statuses[m.group(1)] = m.group(2)
    if not statuses:
        return "RED", statuses  # a gate that gated nothing is not green
    if any(s == "FAIL" for s in statuses.values()):
        return "RED", statuses
    hard_skips = [k for k, s in statuses.items() if s == "SKIPPED" and k not in allow_skips]
    if hard_skips:
        return "INCOMPLETE", statuses
    return "GREEN", statuses


# --------------------------------------------------------------------------
# Gate machinery
# --------------------------------------------------------------------------

class Gate:
    def __init__(self, args):
        self.args = args
        self.lines = []          # the transcript the verdict is parsed from
        self.tmp = tempfile.mkdtemp(prefix="reeflex-gate-")

    def emit(self, line=""):
        self.lines.append(line)
        print(line, flush=True)

    def run_cmd(self, cmd, cwd=None, env_extra=None, env_drop=(), stdin_devnull=False):
        env = dict(os.environ)
        for k in env_drop:
            env.pop(k, None)
        if env_extra:
            env.update(env_extra)
        try:
            proc = subprocess.run(
                cmd, cwd=cwd or REPO_ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=(subprocess.DEVNULL if stdin_devnull else None),
                text=True, errors="replace", timeout=SUBPROCESS_TIMEOUT,
            )
            return proc.returncode, proc.stdout.replace("\r\n", "\n")
        except subprocess.TimeoutExpired:
            return 124, "TIMEOUT after %ds: %s" % (SUBPROCESS_TIMEOUT, cmd)
        except FileNotFoundError as exc:
            return 127, "NOT RUNNABLE: %s" % exc

    def show(self, text, full=False, tail=15):
        body = text.rstrip("\n").split("\n")
        if not full and len(body) > tail:
            self.emit("  ... (%d lines suppressed; full output printed on failure)" % (len(body) - tail))
            body = body[-tail:]
        for line in body:
            self.emit("  | " + line)

    def component(self, key, status, detail=""):
        self.emit("COMPONENT %s: %s (%s)" % (key, status, detail) if detail
                  else "COMPONENT %s: %s" % (key, status))

    # -- venv helpers -------------------------------------------------------

    def make_venv(self, name):
        path = os.path.join(self.tmp, name)
        code, out = self.run_cmd([sys.executable, "-m", "venv", path])
        if code != 0:
            return None, out
        return path, ""

    @staticmethod
    def venv_bin(venv_path, exe):
        sub = "Scripts" if os.name == "nt" else "bin"
        return os.path.join(venv_path, sub, exe)

    def venv_python(self, venv_path):
        return self.venv_bin(venv_path, "python.exe" if os.name == "nt" else "python")

    # -- phase 0: environment ----------------------------------------------

    def env_check(self):
        ok = True
        if sys.version_info < (3, 10):
            self.emit("ENV: STOP python %s < 3.10 (all published packages require >=3.10)"
                      % sys.version.split()[0])
            ok = False
        else:
            self.emit("ENV: OK python %s" % sys.version.split()[0])
        missing = [m for m in ROOT_MARKERS
                   if not os.path.exists(os.path.join(REPO_ROOT, m))]
        if missing:
            self.emit("ENV: STOP not a Reeflex repo root (%s) — missing: %s"
                      % (REPO_ROOT, ", ".join(missing)))
            ok = False
        else:
            self.emit("ENV: OK repo root %s" % REPO_ROOT)
        code, out = self.run_cmd([sys.executable, "-m", "pip", "--version"])
        if code != 0:
            self.emit("ENV: STOP pip is not available (%s)" % out.strip())
            ok = False
        else:
            self.emit("ENV: OK %s" % out.strip())
        # Soft tools: their absence SKIPs the dependent suite (printed), it does
        # not stop the gate — but it is stated here so the skip is no surprise.
        self.opa = os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa")
        self.npm = shutil.which("npm")
        self.php = shutil.which("php")
        for label, path in (("opa", self.opa), ("npm", self.npm), ("php", self.php)):
            self.emit("ENV: NOTE %s = %s" % (label, path or "NOT FOUND"))
        if os.environ.get("NODE_ENV"):
            # NODE_ENV=production makes npm omit devDependencies and the n8n
            # suite would fail for the WRONG reason — neutralized per-suite.
            self.emit("ENV: NOTE NODE_ENV=%s is set; the n8n suite runs with it cleared"
                      % os.environ["NODE_ENV"])
        if os.getcwd() != REPO_ROOT:
            self.emit("ENV: NOTE cwd differs from repo root; gating %s" % REPO_ROOT)
        return ok

    # -- suites -------------------------------------------------------------

    def run_rego(self, key, rel):
        if not self.opa:
            self.component(key, "SKIPPED", "opa binary not found (install OPA or set REEFLEX_OPA_BIN)")
            return
        code, out = self.run_cmd([self.opa, "test", os.path.join(REPO_ROOT, rel), "-v"])
        ok, detail = parse_opa(code, out)
        self.show(out, full=not ok)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_core_unittest(self):
        key = "unittest-core"
        if not self.opa:
            # The suite RUNS without opa but silently drops ~40 opa-dependent
            # tests via skipUnless — that is the silent-skip class this gate
            # exists to kill, so without opa the component is a loud SKIP.
            self.component(key, "SKIPPED", "opa binary not found — the suite would silently skip its opa-dependent tests")
            return
        code, out = self.run_cmd(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
            cwd=os.path.join(REPO_ROOT, "reeflex-core"),
            env_extra={"REEFLEX_OPA_BIN": self.opa, "REEFLEX_POLICY_DIR": "policy"},
        )
        ok, detail = parse_unittest(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_pytest_suites(self):
        keys = [("pytest-mcp", "reeflex-mcp"), ("pytest-holds", "reeflex-holds"),
                ("pytest-claude", "reeflex-claude")]
        # One venv PER package, not one shared venv (RFX-26): reeflex-mcp pins
        # mcp>=1.2,<2 while reeflex-holds (ported to MCPServer) now requires
        # mcp>=2 -- installing both editable into a single venv is an
        # unsatisfiable pip resolve, not a real conflict in the tree (each
        # package's own dependency contract is internally consistent).
        for key, pkg in keys:
            venv_path, err = self.make_venv("venv-suite-%s" % pkg)
            if not venv_path:
                self.component(key, "FAIL", "suite venv creation failed: %s" % err)
                continue
            py = self.venv_python(venv_path)
            code, out = self.run_cmd(
                [py, "-m", "pip", "install", "-q", "pytest", "-e", os.path.join(REPO_ROOT, pkg)])
            if code != 0:
                self.show(out, full=True)
                self.component(key, "FAIL", "suite venv install failed")
                continue
            code, out = self.run_cmd([py, "-m", "pytest", "tests/", "-q"],
                                     cwd=os.path.join(REPO_ROOT, pkg))
            ok, detail = parse_pytest(code, out)
            self.show(out, full=not ok, tail=6)
            self.component(key, "PASS" if ok else "FAIL", detail)

    def run_n8n(self):
        key = "npm-n8n"
        if not self.npm:
            self.component(key, "SKIPPED", "npm not found (node >=20.15 required by n8n-nodes-reeflex)")
            return
        cwd = os.path.join(REPO_ROOT, "n8n-nodes-reeflex")
        # NODE_ENV dropped: production mode omits devDependencies (tsc) and
        # fails the suite for a reason that is the ENVIRONMENT's, not the tree's.
        code, out = self.run_cmd([self.npm, "ci", "--include=dev", "--no-audit", "--no-fund"],
                                 cwd=cwd, env_drop=("NODE_ENV",))
        if code != 0:
            self.show(out, full=True)
            self.component(key, "FAIL", "npm ci exit %d" % code)
            return
        code, out = self.run_cmd([self.npm, "test"], cwd=cwd, env_drop=("NODE_ENV",))
        ok, detail = parse_n8n(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- built artifacts + entry points (DoD 2) ------------------------------

    def run_entrypoints(self):
        key = "entrypoints"
        wheels = os.path.join(self.tmp, "wheels")
        os.makedirs(wheels, exist_ok=True)
        # Build real artifacts (wheels) from the tree — NOT `pip install -e .`,
        # which is exactly how CI stayed green over a dead published package.
        wheel_for = {}
        for pkg, _, _ in PUBLISHED:
            before = set(os.listdir(wheels))
            code, out = self.run_cmd([sys.executable, "-m", "pip", "wheel", "--no-deps",
                                      "-q", "-w", wheels, os.path.join(REPO_ROOT, pkg)])
            if code != 0:
                self.show(out, full=True)
                self.component(key, "FAIL", "wheel build failed for %s" % pkg)
                return
            wheel_for[pkg] = sorted(os.path.join(wheels, f) for f in set(os.listdir(wheels)) - before)
        # One venv PER package, not one shared venv (RFX-26): reeflex-mcp pins
        # mcp>=1.2,<2 while reeflex-holds (ported to MCPServer) now requires
        # mcp>=2 -- resolving both wheels' dependencies from PyPI into a single
        # venv is an unsatisfiable pip resolve, not a real conflict in the tree.
        failures = []
        details = []
        resolved = []
        for pkg, entry, has_usage in PUBLISHED:
            venv_path, err = self.make_venv("venv-entry-%s" % pkg)
            if not venv_path:
                failures.append("%s: venv creation failed" % pkg)
                continue
            py = self.venv_python(venv_path)
            # Install the wheel WITH dependency resolution from PyPI: this is
            # the leg that catches a missing/wrong dependency pin (2026-07-28 class).
            code, out = self.run_cmd([py, "-m", "pip", "install", "-q"] + wheel_for[pkg])
            if code != 0:
                self.show(out, full=True)
                failures.append("%s: installing built wheel failed" % pkg)
                continue
            code, ver_out = self.run_cmd([py, "-m", "pip", "show", "mcp"])
            ver = next((l for l in ver_out.split("\n") if l.startswith("Version:")), "Version: ?")
            resolved.append("%s: %s" % (pkg, ver.split(":", 1)[1].strip()))
            exe = self.venv_bin(venv_path, entry + (".exe" if os.name == "nt" else ""))
            code, out = self.run_cmd([exe, "--help"], stdin_devnull=True)
            self.emit("  | invoke: %s --help -> exit %d" % (entry, code))
            if code != 0:
                self.show(out, full=True)
                failures.append("%s --help exit %d" % (entry, code))
                continue
            if has_usage:
                if re.search(USAGE_RE_TMPL % re.escape(entry), out, re.M):
                    details.append("%s: exit 0 + anchored usage banner" % entry)
                else:
                    failures.append("%s: exit 0 but no anchored 'usage: %s' banner" % (entry, entry))
            else:
                details.append("%s: exit 0 (no argparse — proves the script resolves and imports, nothing more)" % entry)
        self.emit("  | resolved mcp %s" % "; ".join(resolved))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "; ".join(details))

    # -- fresh-install-from-PyPI smoke (DoD 4) -------------------------------

    # RFX-107: "DELEGATED" is the one status that asserts a component ran
    # SOMEWHERE ELSE. That was taken on trust: delete the smoke-pypi job from
    # gate.yml and this gate would print DELEGATED and stay GREEN forever,
    # while the fresh-install smoke — the leg that exists because five days of
    # green CI hid two dead published packages on 2026-07-28 — ran nowhere.
    # So the delegation is now VERIFIED against the workflow that must carry it.
    DELEGATE_WORKFLOW = os.path.join(".github", "workflows", "gate.yml")
    DELEGATE_RE = re.compile(r"^\s*uses:\s*\./\.github/workflows/smoke-pypi\.yml\s*$", re.M)

    def verify_delegation(self):
        """Returns (ok, detail): does a sibling job actually invoke the smoke?"""
        path = os.path.join(REPO_ROOT, self.DELEGATE_WORKFLOW)
        if not os.path.exists(path):
            return False, "claims delegation but %s does not exist" % self.DELEGATE_WORKFLOW
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        if not self.DELEGATE_RE.search(body):
            return False, ("claims delegation but no job in %s invokes "
                           "./.github/workflows/smoke-pypi.yml" % self.DELEGATE_WORKFLOW)
        return True, "smoke-pypi.yml via workflow_call in the same workflow run (verified wired in %s)" \
                     % self.DELEGATE_WORKFLOW

    def run_pypi_smoke(self):
        key = "pypi-smoke"
        if self.args.pypi == "delegated":
            ok, detail = self.verify_delegation()
            self.component(key, "DELEGATED" if ok else "FAIL", detail)
            return
        if self.args.pypi == "skip":
            self.component(key, "SKIPPED", "explicitly disabled via --pypi skip (tree-health run)")
            return
        failures, details = [], []
        for pkg, entry, _ in PUBLISHED:
            venv_path, err = self.make_venv("venv-pypi-" + pkg)
            if not venv_path:
                failures.append("%s: venv failed" % pkg)
                continue
            py = self.venv_python(venv_path)
            code, out = self.run_cmd([py, "-m", "pip", "install", "-q", "--no-cache-dir", pkg])
            if code != 0:
                self.show(out, full=True)
                failures.append("%s: pip install from PyPI failed" % pkg)
                continue
            code, ver_out = self.run_cmd([py, "-m", "pip", "show", pkg])
            ver = next((l.split(":", 1)[1].strip() for l in ver_out.split("\n")
                        if l.startswith("Version:")), "?")
            exe = self.venv_bin(venv_path, entry + (".exe" if os.name == "nt" else ""))
            code, out = self.run_cmd([exe, "--help"], stdin_devnull=True)
            self.emit("  | pypi %s==%s: %s --help -> exit %d" % (pkg, ver, entry, code))
            if code != 0:
                self.show(out, full=True)
                failures.append("%s==%s: published entry point died (exit %d)" % (pkg, ver, code))
            else:
                details.append("%s==%s ok" % (pkg, ver))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "; ".join(details))

    # -- WordPress live-core harness -----------------------------------------

    # RFX-27: the WordPress adapter has FOUR live-core PHP harnesses, not one —
    # conformance-demo.php was the only one gate.py ever invoked; the other three
    # (added for real fixed bugs, see their own docblocks + CHANGELOG) were run by
    # nobody in any automation. One of them (fanout-regression-demo.php, and
    # transitively hold-dedup-regression-demo.php) was silently BROKEN — a fatal
    # "undefined function wp_upload_dir()" — since audit_log_path() started calling
    # it; measured + fixed 2026-08-20 (see wp-stubs.php). All four share the same
    # live-core prerequisite, so they run (or SKIP) together under one component.
    WP_HARNESSES = [
        "conformance-demo.php",
        "admin-holds-demo.php",
        "fanout-regression-demo.php",
        "hold-dedup-regression-demo.php",
    ]

    def run_wp(self):
        key = "wp-conformance"
        if not self.args.core_url:
            self.component(key, "SKIPPED",
                           "needs a LIVE reeflex-core (pass --core-url); the harnesses POST real /v1/decide calls "
                           "AND resolve real holds, so since core 0.2.0 that core must also be started with "
                           "REEFLEX_RESOLVER_TOKENS=reeflex-wordpress/tests/harness-resolver-tokens.json "
                           "(or REEFLEX_REQUIRE_VERIFIED_APPROVER=false) — see reeflex-wordpress/tests/README.md")
            return
        if not self.php:
            self.component(key, "SKIPPED", "php CLI not found")
            return
        failures, details = [], []
        for script in self.WP_HARNESSES:
            code, out = self.run_cmd([self.php, "tests/%s" % script, self.args.core_url],
                                     cwd=os.path.join(REPO_ROOT, "reeflex-wordpress"))
            self.emit("  -- %s" % script)
            self.show(out, full=code != 0, tail=12)
            if code == 0:
                details.append("%s: exit 0" % script)
            else:
                failures.append("%s: exit %d" % (script, code))
        if failures:
            self.component(key, "FAIL", "; ".join(failures))
        else:
            self.component(key, "PASS", "%d harnesses vs %s (%s)"
                           % (len(self.WP_HARNESSES), self.args.core_url, "; ".join(details)))

    # -- drift check ----------------------------------------------------------

    def run_drift(self):
        key = "drift"
        covered = [os.path.normpath(os.path.join(REPO_ROOT, r)) for r in SUITE_ROOTS]
        strays = []
        for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in DRIFT_EXCLUDE_DIRS and not d.startswith("reeflex-gate-")]
            for f in filenames:
                if any(fnmatch.fnmatch(f, p) for p in TEST_FILE_PATTERNS):
                    full = os.path.normpath(os.path.join(dirpath, f))
                    if not any(full.startswith(c + os.sep) or os.path.dirname(full) == c
                               for c in covered):
                        strays.append(os.path.relpath(full, REPO_ROOT))
        if strays:
            for s in strays:
                self.emit("  | unenumerated test file: %s" % s)
            self.component(key, "FAIL",
                           "%d test file(s) outside the enumerated suite roots — wire them into gate.py or they run NOWHERE" % len(strays))
        else:
            self.component(key, "PASS",
                           "no test files outside the %d enumerated suite roots" % len(SUITE_ROOTS))

    # -- test census (RFX-87) -------------------------------------------------

    def run_test_census(self):
        # Unconditional and static (ast only, no imports, no deps): every
        # enumerated test file must YIELD TESTS under the runner its root is
        # actually run with. `drift` proves a test file is in a directory some
        # component names; this proves the file is not inert. #89's guard
        # satisfied drift and collected zero tests.
        key = "test-census"
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "check_test_census.py"), REPO_ROOT]
        )
        ok, detail = parse_test_census(code, out)
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- migration graph (RFX-49) --------------------------------------------

    def run_migration_heads_selftest(self):
        # Unconditional: proves the CHECKER TOOL itself is correct (single
        # head passes, a shared-parent collision fails, re-parenting fixes
        # it, merge migrations/dangling parents/duplicate ids are handled).
        # This runs regardless of whether reeflex-app is checked out here.
        key = "migration-heads-selftest"
        code, out = self.run_cmd(
            [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-t", "scripts"],
        )
        ok, detail = parse_unittest(code, out)
        self.show(out, full=not ok, tail=8)
        self.component(key, "PASS" if ok else "FAIL", detail)

    def run_migration_heads(self):
        # Optional: this repo has no alembic migrations of its own (reeflex-core
        # is OPA/Rego, not a DB-backed service) — the graph that actually broke
        # in RFX-49 lives in the private reeflex-app repo, cloned separately
        # (never vendored into this tree). When that checkout is present
        # (canonical devbox layout, WoW R.5, or a REEFLEX_APP_MIGRATIONS_DIR
        # override) this gate ALSO validates its migration graph, for free,
        # in the same command a developer already runs on that machine.
        key = "migration-heads"
        app_dir = os.environ.get("REEFLEX_APP_MIGRATIONS_DIR")
        if app_dir and not os.path.isdir(app_dir):
            app_dir = None
        if not app_dir:
            app_dir = next((c for c in APP_MIGRATIONS_CANDIDATES if os.path.isdir(c)), None)
        if not app_dir:
            self.component(key, "SKIPPED",
                           "no reeflex-app checkout found (set REEFLEX_APP_MIGRATIONS_DIR, "
                           "or check out reeflex-app as a sibling of this repo) — this repo "
                           "itself has no alembic migrations")
            return
        code, out = self.run_cmd(
            [sys.executable, os.path.join(REPO_ROOT, "scripts", "check_migration_heads.py"), app_dir]
        )
        ok, detail = parse_migration_heads(code, out)
        self.show(out, full=True)
        self.component(key, "PASS" if ok else "FAIL", detail)

    # -- main -----------------------------------------------------------------

    def main(self):
        self.emit("REEFLEX PREFLIGHT GATE (gate.py) — repo root: %s" % REPO_ROOT)
        self.emit("")
        if not self.env_check():
            self.emit("")
            self.emit("GATE: ENV-STOP")
            return 2
        self.emit("")
        for header, fn in [
            ("rego-core       opa test reeflex-core/policy/", lambda: self.run_rego("rego-core", "reeflex-core/policy")),
            ("rego-claude     opa test reeflex-claude/policy/", lambda: self.run_rego("rego-claude", "reeflex-claude/policy")),
            ("unittest-core   full discovery over reeflex-core/tests", self.run_core_unittest),
            ("pytest suites   reeflex-mcp + reeflex-holds + reeflex-claude", self.run_pytest_suites),
            ("npm-n8n         n8n-nodes-reeflex npm ci + npm test", self.run_n8n),
            ("entrypoints     build wheels from tree + invoke every entry point", self.run_entrypoints),
            ("pypi-smoke      fresh install of the PUBLISHED packages", self.run_pypi_smoke),
            ("wp-conformance  WordPress live-core harness", self.run_wp),
            ("migration-heads-selftest  scripts/tests: check_migration_heads correctness", self.run_migration_heads_selftest),
            ("migration-heads  static alembic graph (reeflex-app, if checked out) — single head, no DB", self.run_migration_heads),
            ("test-census     every enumerated test file must YIELD TESTS (RFX-87)", self.run_test_census),
            ("drift           test files outside every enumerated suite", self.run_drift),
        ]:
            self.emit("--- %s" % header)
            fn()
            self.emit("")

        # skip-ledger runs LAST: it is the only component that reads the other
        # components' statuses, so it cannot be ordered anywhere else.
        allow = set(filter(None, (self.args.allow_skips or "").split(",")))
        _, statuses_so_far = derive_verdict(self.lines, allow)
        self.emit("--- skip-ledger     what was skipped in THIS run, and why (RFX-108)")
        ledger_ok, ledger_lines = audit_skips(statuses_so_far, allow)
        for line in ledger_lines:
            self.emit(line)
        self.component("skip-ledger", "PASS" if ledger_ok else "FAIL",
                       "every skip in this run is accounted for" if ledger_ok
                       else "an --allow-skips key has no registered justification")
        self.emit("")

        verdict, statuses = derive_verdict(self.lines, allow)
        self.emit("GATE SUMMARY")
        for k, s in statuses.items():
            note = " [skip allowed via --allow-skips]" if s == "SKIPPED" and k in allow else ""
            self.emit("  %s: %s%s" % (k, s, note))
        self.emit("")
        self.emit("GATE: %s" % verdict)
        return {"GREEN": 0, "RED": 1, "INCOMPLETE": 3}[verdict]


# --------------------------------------------------------------------------
# Selftest (DoD 5): prove the parsing is anchored and case-sensitive.
# --------------------------------------------------------------------------

def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # opa: only a full, exact, case-sensitive `PASS: n/n` line with n == n passes
    check("opa accepts real summary", parse_opa(0, "data.x: PASS (1ms)\nPASS: 9/9\n")[0])
    check("opa rejects lowercase", not parse_opa(0, "pass: 9/9\n")[0])
    check("opa rejects indented line", not parse_opa(0, "  PASS: 9/9\n")[0])
    check("opa rejects partial pass", not parse_opa(0, "PASS: 8/9\n")[0])
    check("opa rejects embedded word", not parse_opa(0, "all tests PASS: 9/9 today\n")[0])
    check("opa rejects nonzero exit", not parse_opa(1, "PASS: 9/9\n")[0])

    # pytest: a line merely containing "passed" must not flip the gate
    check("pytest accepts real summary", parse_pytest(0, "....\n56 passed in 1.02s\n")[0])
    check("pytest accepts warnings variant", parse_pytest(0, "56 passed, 2 warnings in 3.21s\n")[0])
    ok, detail = parse_pytest(0, "55 passed, 1 skipped in 2.20s\n")
    check("pytest reports in-suite skips", ok and "1 skipped in-suite" in detail)
    check("pytest rejects prose mention", not parse_pytest(0, "the run passed in style\n")[0])
    check("pytest rejects PASSED uppercase", not parse_pytest(0, "56 PASSED in 1.02s\n")[0])
    check("pytest rejects failed-prefix line", not parse_pytest(0, "5 failed, 56 passed in 1.02s\n")[0])
    check("pytest rejects indented summary", not parse_pytest(0, "  56 passed in 1.02s\n")[0])
    check("pytest rejects nonzero exit", not parse_pytest(1, "56 passed in 1.02s\n")[0])

    # n8n: only the runner's own exact summary with 0 failed passes
    check("n8n accepts real summary", parse_n8n(0, "ok - x\n14 passed, 0 failed, 14 total\n")[0])
    check("n8n rejects failures", not parse_n8n(0, "13 passed, 1 failed, 14 total\n")[0])
    check("n8n rejects count mismatch", not parse_n8n(0, "13 passed, 0 failed, 14 total\n")[0])
    check("n8n rejects prose mention", not parse_n8n(0, "all 14 passed, 0 failed, 14 total tests\n")[0])
    check("n8n rejects nonzero exit", not parse_n8n(1, "14 passed, 0 failed, 14 total\n")[0])

    # unittest: needs BOTH `Ran N tests in Xs` AND an anchored OK line
    check("unittest accepts real summary", parse_unittest(0, "Ran 255 tests in 60.953s\n\nOK\n")[0])
    ok, detail = parse_unittest(0, "Ran 255 tests in 60.953s\n\nOK (skipped=1)\n")
    check("unittest reports in-suite skips", ok and "skipped=1 in-suite" in detail)
    check("unittest rejects lowercase ok", not parse_unittest(0, "Ran 5 tests in 1.0s\n\nok\n")[0])
    check("unittest rejects OK-in-prose", not parse_unittest(0, "Ran 5 tests in 1.0s\neverything OK here\n")[0])
    check("unittest rejects FAILED", not parse_unittest(1, "Ran 5 tests in 1.0s\n\nFAILED (failures=2)\n")[0])
    check("unittest rejects missing Ran line", not parse_unittest(0, "\nOK\n")[0])

    # migration-heads: only the checker's own anchored PASS/FAIL line counts
    check("migration-heads accepts real PASS", parse_migration_heads(0, "MIGRATION-HEADS: PASS (1 head: 0011_x)\n")[0])
    check("migration-heads rejects real FAIL even at exit 0",
          not parse_migration_heads(0, "MIGRATION-HEADS: FAIL (2 heads)\n")[0])
    check("migration-heads rejects nonzero exit despite PASS line",
          not parse_migration_heads(1, "MIGRATION-HEADS: PASS (1 head: x)\n")[0])
    check("migration-heads rejects prose mention",
          not parse_migration_heads(0, "well, MIGRATION-HEADS: PASS (1 head: x) I guess\n")[0])
    check("migration-heads rejects exit 0 with no anchored line",
          not parse_migration_heads(0, "some other output\n")[0])

    # test-census: only the census's own anchored PASS/FAIL line counts (RFX-108)
    check("test-census accepts real PASS",
          parse_test_census(0, "TEST-CENSUS: PASS (44 files, 943 tests collected, 2 waived)\n")[0])
    check("test-census rejects real FAIL even at exit 0",
          not parse_test_census(0, "TEST-CENSUS: FAIL (1 finding(s) [zero-collection])\n")[0])
    check("test-census rejects nonzero exit despite PASS line",
          not parse_test_census(1, "TEST-CENSUS: PASS (44 files)\n")[0])
    check("test-census rejects prose mention",
          not parse_test_census(0, "note: TEST-CENSUS: PASS (all good) probably\n")[0])
    check("test-census rejects exit 0 with no anchored line",
          not parse_test_census(0, "collected some tests\n")[0])

    # skip-ledger: an allowance without a written justification is refused (RFX-108)
    reg = {"known": "a registered reason"}
    ok, lines = audit_skips({"a": "PASS", "known": "SKIPPED"}, {"known"}, reg)
    check("skip-ledger passes a registered, used allowance", ok)
    check("skip-ledger prints the reason for every skip",
          any("why: a registered reason" in l for l in lines))
    ok, lines = audit_skips({"a": "PASS", "mystery": "SKIPPED"}, {"mystery"}, reg)
    check("skip-ledger REFUSES an unregistered --allow-skips key", not ok)
    check("...and says so", any("not in SKIP_REGISTRY" in l for l in lines))
    ok, lines = audit_skips({"known": "PASS"}, {"known"}, reg)
    check("skip-ledger WARNs on a stale allowance without failing", ok)
    check("...and names it", any("is STALE" in l for l in lines))
    ok, lines = audit_skips({"a": "PASS"}, set(), reg)
    check("skip-ledger says plainly when nothing was skipped",
          ok and any("nothing was skipped" in l for l in lines))
    ok, lines = audit_skips({"a": "SKIPPED"}, set(), reg)
    check("skip-ledger flags a NOT-ALLOWED skip in the ledger text",
          any("NOT ALLOWED" in l for l in lines))
    check("...and reports the missing justification honestly",
          any("no registered justification" in l for l in lines))
    check("every key in the real SKIP_REGISTRY carries a non-empty reason",
          all(isinstance(v, str) and len(v) > 20 for v in SKIP_REGISTRY.values()))

    # transcript re-parse: only exact COMPONENT lines count
    v, _ = derive_verdict(["COMPONENT a: PASS (x)", "COMPONENT b: PASS"], set())
    check("verdict GREEN on all pass", v == "GREEN")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: FAIL (boom)"], set())
    check("verdict RED on any fail", v == "RED")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: SKIPPED (no tool)"], set())
    check("verdict INCOMPLETE on skip", v == "INCOMPLETE")
    v, _ = derive_verdict(["COMPONENT a: PASS", "COMPONENT b: SKIPPED (no tool)"], {"b"})
    check("verdict GREEN when skip allowed", v == "GREEN")
    v, _ = derive_verdict(["component a: pass", "This line mentions PASS"], set())
    check("verdict RED when transcript unparseable", v == "RED")
    v, _ = derive_verdict(["  COMPONENT a: PASS"], set())
    check("verdict ignores indented component line", v == "RED")

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  selftest %s: %s" % ("PASS" if ok else "FAIL", n))
    if failed:
        print("SELFTEST: FAIL (%d/%d checks failed)" % (len(failed), len(checks)))
        return 1
    print("SELFTEST: PASS (%d checks)" % len(checks))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="gate.py", description="Reeflex uniform preflight gate")
    p.add_argument("--pypi", choices=["run", "delegated", "skip"], default="run",
                   help="PyPI smoke: run inline (default), delegated (CI runs smoke-pypi.yml "
                        "as a sibling workflow_call job), or skip (flagged, forces INCOMPLETE)")
    p.add_argument("--allow-skips", default="",
                   help="comma-separated component keys whose SKIP does not force INCOMPLETE "
                        "(printed in the summary; use for structurally unrunnable suites)")
    p.add_argument("--core-url", default="",
                   help="live reeflex-core URL for the WordPress conformance harness")
    p.add_argument("--selftest", action="store_true",
                   help="run the anchored-parsing selftest and exit")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.selftest:
        sys.exit(selftest())
    gate = Gate(args)
    try:
        sys.exit(gate.main())
    finally:
        shutil.rmtree(gate.tmp, ignore_errors=True)
