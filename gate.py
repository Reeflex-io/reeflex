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
    ("reeflex-holds", "reeflex-holds", False),  # server main(), no argparse:
    # exit 0 proves the console script resolves and the package imports —
    # exactly where the 2026-07-28 breakage died — NOT that a usage banner
    # was shown.
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
]

TEST_FILE_PATTERNS = ["test_*.py", "*_test.py", "*_test.rego", "*.test.ts", "*.test.js"]

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

    def run_pypi_smoke(self):
        key = "pypi-smoke"
        if self.args.pypi == "delegated":
            # In CI the sibling workflow_call job runs smoke-pypi.yml (one copy
            # of the smoke, owned there). DELEGATED counts as ran-elsewhere and
            # is only honest when that sibling actually runs — the gate.yml
            # workflow wires both.
            self.component(key, "DELEGATED", "smoke-pypi.yml via workflow_call in the same workflow run")
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
                           "needs a LIVE reeflex-core (pass --core-url); the harnesses POST real /v1/decide calls — see reeflex-wordpress/tests/README.md")
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
            ("drift           test files outside every enumerated suite", self.run_drift),
        ]:
            self.emit("--- %s" % header)
            fn()
            self.emit("")
        allow = set(filter(None, (self.args.allow_skips or "").split(",")))
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
