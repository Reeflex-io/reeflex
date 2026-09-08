#!/usr/bin/env python3
"""verify_release_artifacts.py — INVOKE what a release is about to ship, or has
just shipped, in a venv that holds nothing but the artefact.

WHY THIS EXISTS (RFX-246, and the shape it keeps coming back in)
---------------------------------------------------------------
Three instruments in this repo have reported green over an artefact nobody
could use:

  * `release.yml`'s `pypi` job goes green over a version PyPI already has
    (`skip-existing: true`), so "the release published three packages" was read
    off a job that published one.
  * `smoke-pypi.yml` asserts `<entry point> --help` exits 0. That catches
    import-time death and nothing else — a gate that fails to REFUSE exits 0 on
    `--help`.
  * `gate.py`'s `entrypoints` component does the same `--help` assertion over a
    wheel built from the tree.

So this script does the one thing none of them do: it runs a REAL subcommand,
with real inputs, and it runs the NEGATIVE control beside it. A build whose
validator was deleted would still print JSON for a valid map; only the invalid
map distinguishes it. Every check below is a pair or names why it is not.

WHAT IT IS POINTED AT
---------------------
`--python` is the interpreter of a venv somebody else populated. This script
does not install anything and does not care WHERE the artefact came from —
`release.yml` runs it twice per release, once against the wheels that run built
(before publishing) and once against `pip install` from PyPI (after), and the
same command runs by hand on a devbox. That symmetry is deliberate: a check
that only exists inside a workflow is a check nobody re-runs when they doubt
the answer.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
No network to `reeflex-core` and no proxy is started. `reeflex-litellm tenancy`
and `reeflex-claude connect --dry-run` are the two operator commands that are
meaningful with no engine reachable; the live end-to-end walks (a real
`/v1/decide`, a real proxy, a real portal) belong to the round reports that
measured them, not to a release workflow that must be able to run unattended.

It also does not claim a release PUBLISHED anything. Pointed at PyPI it proves
"the version this tag names is installable from the index and runs"; on a tag
where a package's version did not move, that same PASS is about the PREVIOUS
upload, and release.yml's summary says so.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

REPO_ROOT_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VALID_MAP = "reeflex-litellm/examples/tenancy-map.example.json"
CATCH_ALL_MAP = "reeflex-litellm/examples/tenancy-map.catch-all-is-refused.json"
SETUP_DOC = "docs/setup/v1/agent-setup.md"

# The two tenants the shipped example map binds. Asserted by NAME rather than
# by count: "two tenants" would also pass on a map that loaded one tenant twice.
EXPECT_TENANTS = {"acme-payments", "acme-marketing"}


class Checks:
    """A PASS/FAIL ledger that prints as it goes and never hides a failure in a
    return value nobody reads."""

    def __init__(self) -> None:
        self.failures = []
        self.passes = 0

    def ok(self, label: str, detail: str = "") -> None:
        self.passes += 1
        print("  PASS  %s%s" % (label, ("  — " + detail) if detail else ""))

    def fail(self, label: str, detail: str) -> None:
        self.failures.append((label, detail))
        print("  FAIL  %s\n        %s" % (label, detail))

    def expect(self, cond: bool, label: str, detail_ok: str, detail_bad: str) -> bool:
        if cond:
            self.ok(label, detail_ok)
            return True
        self.fail(label, detail_bad)
        return False


def run(argv, *, env=None, cwd=None, stdin_devnull=True):
    """One subprocess, captured. `env` REPLACES the environment rather than
    extending it: a `REEFLEX_*` variable inherited from the runner would make
    the tenancy checks measure the runner's configuration instead of the map
    the check names."""

    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    }
    if env:
        base.update(env)
    proc = subprocess.run(
        argv,
        env=base,
        cwd=cwd,
        stdin=subprocess.DEVNULL if stdin_devnull else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def venv_bin(python: str, name: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(python)), name)


def installed_version(python: str, dist: str):
    """The version pip actually resolved, read from the installed metadata
    rather than from the package's own `__version__` — the two disagree exactly
    when it matters (an editable install of a tree whose version was bumped, or
    a `0.0.0+unknown` because nothing is installed at all)."""

    code, out, _ = run([
        python, "-c",
        "import importlib.metadata as m,sys;"
        "sys.stdout.write(m.version(%r))" % dist,
    ])
    return out.strip() if code == 0 else None


# ---------------------------------------------------------------------------
# reeflex-litellm
# ---------------------------------------------------------------------------

def check_litellm(c: Checks, python: str, root: str, expect_version, want_proxy: bool) -> None:
    print("\nreeflex-litellm")
    exe = venv_bin(python, "reeflex-litellm")

    got = installed_version(python, "reeflex-litellm")
    if got is None:
        c.fail("reeflex-litellm is installed", "importlib.metadata could not find it")
        return
    if expect_version:
        c.expect(got == expect_version, "installed version is the one this tag names",
                 "%s" % got, "expected %s, installed %s" % (expect_version, got))
    else:
        c.ok("installed version", got)

    # The entry point exists AND prints its own name in an anchored usage
    # banner. Same assertion gate.py's `entrypoints` makes, kept because a
    # console script that resolves to the wrong module still exits 0.
    code, out, err = run([exe, "--help"])
    banner = re.search(r"^usage:\s+reeflex-litellm", out, re.M) is not None
    c.expect(code == 0 and banner, "reeflex-litellm --help",
             "exit 0 + anchored usage banner",
             "exit %d, banner=%s\n%s" % (code, banner, (out + err)[:400]))

    # --- the real subcommand, on the example map this repo ships ------------
    valid = os.path.join(root, VALID_MAP)
    code, out, err = run([exe, "tenancy"],
                         env={"REEFLEX_LITELLM_TENANCY_MAP_FILE": valid})
    if code != 0:
        c.fail("tenancy accepts the shipped example map",
               "exit %d\n%s" % (code, (out + err)[:600]))
    else:
        try:
            parsed = json.loads(out)
        except Exception as exc:  # noqa: BLE001
            c.fail("tenancy prints parseable JSON", "%s\n%s" % (exc, out[:400]))
            parsed = None
        if parsed is not None:
            names = set(parsed.get("tenants", {}))
            c.expect(names == EXPECT_TENANTS,
                     "tenancy binds the two tenants the example map declares",
                     ", ".join(sorted(names)),
                     "expected %s, got %s" % (sorted(EXPECT_TENANTS), sorted(names)))
            orgs = {t.get("org") for t in parsed.get("tenants", {}).values()}
            c.expect(orgs == EXPECT_TENANTS, "each tenant resolves to its own org",
                     ", ".join(sorted(o for o in orgs if o)),
                     "orgs were %s" % sorted(orgs))
            alias = parsed.get("bind", {}).get("key_alias", {})
            c.expect(set(alias.values()) == EXPECT_TENANTS,
                     "both departments are bound by key_alias",
                     json.dumps(alias, sort_keys=True),
                     "key_alias bound %s" % json.dumps(alias, sort_keys=True))
            # A credential must never be in this output. The map names env
            # VARIABLES; the check is that the output carries names and not
            # anything shaped like a value.
            leaked = [tok for tok in ("sk-", "rfx_gate_", "rfx_ek_") if tok in out]
            c.expect(not leaked, "no credential-shaped value in the tenancy output",
                     "none of sk- / rfx_gate_ / rfx_ek_", "found %s" % leaked)

    # --- THE NEGATIVE CONTROL. Without this, every assertion above also
    # passes on a build whose validator does nothing at all. ----------------
    catch_all = os.path.join(root, CATCH_ALL_MAP)
    code, out, err = run([exe, "tenancy"],
                         env={"REEFLEX_LITELLM_TENANCY_MAP_FILE": catch_all})
    c.expect(code == 1 and "catch-all" in (out + err),
             "CONTROL: a `default` catch-all entry is REFUSED",
             "exit 1, and the message names the catch-all",
             "exit %d; message was %r" % (code, (out + err)[:400]))

    # No map at all is a refusal too, and it is a different code path (the
    # loader never gets a document). "Tenancy off" is not a state this package
    # has, and a release that grew one would pass every check above.
    code, out, err = run([exe, "tenancy"])
    c.expect(code == 1 and "REEFLEX_LITELLM_TENANCY_MAP" in (out + err),
             "CONTROL: no map configured is a refusal, naming the env var",
             "exit 1",
             "exit %d; message was %r" % (code, (out + err)[:400]))

    # --- the proxy extra ---------------------------------------------------
    # `reeflex_litellm.guardrail` is the ONLY module that imports litellm, so
    # importing it is what distinguishes `pip install reeflex-litellm` from
    # `pip install reeflex-litellm[proxy]`. Nothing above would have noticed a
    # broken extra: the decision logic is tested without litellm on purpose.
    #
    # `litellm.__version__` does NOT exist (litellm 1.100.0 raises
    # AttributeError from its module `__getattr__`), which this check asserted
    # on its first run and had to be told. The installed metadata is the right
    # source anyway — it is what pip resolved.
    code, out, err = run([
        python, "-c",
        "import importlib.metadata as m, reeflex_litellm.guardrail as g;"
        "print('litellm', m.version('litellm'), g.ReeflexActionGuardrail.__name__)",
    ])
    if want_proxy:
        if c.expect(code == 0, "the [proxy] extra resolves and the guardrail imports",
                    out.strip(), "exit %d\n%s" % (code, err[-600:])):
            _check_python_floor_against_litellm(c, python)
    else:
        c.ok("skipped: --no-proxy-extra", "guardrail import not attempted")


def _floor(spec):
    """The lowest `(major, minor)` a `Requires-Python` spec admits, or None.

    Deliberately crude: it reads the `>=`/`>` clause and ignores the rest. The
    one question asked is "does OUR floor sit at or above THEIRS", and a
    version-specifier library is not worth adding to a release check for it."""

    if not spec:
        return None
    for part in spec.split(","):
        part = part.strip()
        m = re.match(r">=?\s*(\d+)\.(\d+)", part)
        if m:
            return (int(m.group(1)), int(m.group(2)))
    return None


def _check_python_floor_against_litellm(c: Checks, python: str) -> None:
    """RFX-248: reeflex-litellm said `>=3.9` with a `3.9` classifier while its
    `proxy` extra required `litellm>=1.100`, whose own metadata says
    `>=3.10,<3.15`. So `pip install 'reeflex-litellm[proxy]'` was unsatisfiable
    on the interpreter the package advertised — and the repo gate could not see
    it, because it deliberately never installs the extra.

    This is the check that closes it, and it belongs here rather than in a
    suite: it needs BOTH distributions' installed metadata, which only a venv
    that resolved the extra has."""

    code, out, _ = run([
        python, "-c",
        "import importlib.metadata as m;"
        "print(m.metadata('reeflex-litellm').get('Requires-Python',''));"
        "print(m.metadata('litellm').get('Requires-Python',''))",
    ])
    lines = out.strip().splitlines()
    if code != 0 or len(lines) < 2:
        c.fail("both Requires-Python values are readable", out.strip() or "no output")
        return
    ours, theirs = _floor(lines[0]), _floor(lines[1])
    if ours is None or theirs is None:
        c.fail("both Requires-Python floors parse",
               "reeflex-litellm=%r litellm=%r" % (lines[0], lines[1]))
        return
    c.expect(ours >= theirs,
             "our Requires-Python floor is not below litellm's (RFX-248)",
             "reeflex-litellm %s vs litellm %s" % (lines[0], lines[1]),
             "reeflex-litellm says %s but litellm requires %s — the [proxy] "
             "extra is unsatisfiable on an interpreter we advertise"
             % (lines[0], lines[1]))


# ---------------------------------------------------------------------------
# reeflex-claude
# ---------------------------------------------------------------------------

def check_claude(c: Checks, python: str, root: str, expect_version) -> None:
    print("\nreeflex-claude")
    exe = venv_bin(python, "reeflex-claude")

    got = installed_version(python, "reeflex-claude")
    if got is None:
        c.fail("reeflex-claude is installed", "importlib.metadata could not find it")
        return
    if expect_version:
        c.expect(got == expect_version, "installed version is the one this tag names",
                 "%s" % got, "expected %s, installed %s" % (expect_version, got))
    else:
        c.ok("installed version", got)

    # `connect` is the subcommand the portal's /app/onboard line invokes. Its
    # presence in the PUBLISHED wheel is the whole of what makes that line
    # true, and until 0.2.0 no published wheel had it.
    code, out, err = run([exe, "connect", "--help"])
    c.expect(code == 0 and "--dry-run" in out,
             "the published wheel HAS `connect` (the /app/onboard line)",
             "exit 0",
             "exit %d\n%s" % (code, (out + err)[:400]))

    # --dry-run exchanges nothing, writes nothing and needs no portal, so it
    # is the one leg of that line a release workflow can assert. It also
    # prints the setup-document digest, which is checked below.
    workdir = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "rfx-connect-dryrun")
    os.makedirs(workdir, exist_ok=True)
    code, out, err = run(
        [exe, "connect", "--dry-run", "--agent", "claude", "--project",
         "--token", "rfx_reg_dryrun", "--portal", "http://127.0.0.1:9"],
        env={"HOME": workdir}, cwd=workdir)
    c.expect(code == 0 and "NOT exchanging" in out,
             "connect --dry-run exits 0 and writes nothing",
             "exit 0", "exit %d\n%s" % (code, (out + err)[:600]))

    # THE CROSS-REPO PIN, CHECKED AT RELEASE TIME. The wheel carries
    # `SETUP_DOC_SHA256` and the portal prints the same constant beside the
    # copy button; both are asserted against their own copy of the document by
    # their own suite, and neither repo's CI can see the other. Here the
    # PUBLISHED wheel's constant is compared against the document AT THIS TAG,
    # which is the one comparison neither suite can make.
    printed = re.search(r"sha256:\s*([0-9a-f]{64})", out)
    doc = os.path.join(root, SETUP_DOC)
    if not printed:
        c.fail("connect prints the setup-document digest", "no sha256 line in its output")
    elif not os.path.exists(doc):
        c.fail("the setup document is in this tree", doc + " does not exist")
    else:
        with open(doc, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        c.expect(printed.group(1) == actual,
                 "the wheel's SETUP_DOC_SHA256 matches %s at this tag" % SETUP_DOC,
                 actual,
                 "wheel says %s, the document hashes to %s"
                 % (printed.group(1), actual))

    # CONTROL, and it is about a credential rather than about a feature: a
    # long-lived gate token pasted where the single-use registration token
    # goes must be refused BEFORE anything is sent. The portal here is a dead
    # port, so a build that sent first would fail with a connection error
    # (exit 1) instead of the refusal (exit 2) — the exit code is what
    # distinguishes them.
    code, out, err = run(
        [exe, "connect", "--agent", "claude", "--token", "rfx_gate_notreal",
         "--portal", "http://127.0.0.1:9"],
        env={"HOME": workdir}, cwd=workdir)
    c.expect(code == 2 and "rfx_reg_" in (out + err),
             "CONTROL: a `rfx_gate_` token is refused before any request",
             "exit 2, naming the credential it wanted",
             "exit %d (1 would mean it tried to send it first)\n%s"
             % (code, (out + err)[:400]))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Invoke the release artefacts installed in a venv and "
                    "assert what they do, with the negative controls.")
    p.add_argument("--python", required=True,
                   help="python of the venv holding the installed artefacts")
    p.add_argument("--repo-root", default=REPO_ROOT_DEFAULT,
                   help="checkout the example maps and the setup document are read from")
    p.add_argument("--expect-litellm", default=None,
                   help="the reeflex-litellm version this release names (e.g. 0.1.0)")
    p.add_argument("--expect-claude", default=None,
                   help="the reeflex-claude version this release names (e.g. 0.2.0)")
    p.add_argument("--no-proxy-extra", action="store_true",
                   help="the venv was installed WITHOUT [proxy]; skip the litellm import")
    p.add_argument("--skip-litellm", action="store_true")
    p.add_argument("--skip-claude", action="store_true")
    args = p.parse_args(argv)

    root = os.path.abspath(args.repo_root)
    python = os.path.abspath(args.python)
    if not os.path.exists(python):
        print("no such interpreter: %s" % python, file=sys.stderr)
        return 2
    for rel in (VALID_MAP, CATCH_ALL_MAP):
        if not os.path.exists(os.path.join(root, rel)):
            print("missing %s under --repo-root %s" % (rel, root), file=sys.stderr)
            return 2

    print("verify_release_artifacts: %s" % python)
    print("  repo root: %s" % root)
    c = Checks()
    if not args.skip_litellm:
        check_litellm(c, python, root, args.expect_litellm, not args.no_proxy_extra)
    if not args.skip_claude:
        check_claude(c, python, root, args.expect_claude)

    print("\n%d passed, %d failed" % (c.passes, len(c.failures)))
    if c.failures:
        # A FLOOR UNDER THE WALK is not needed here (every check is named and
        # counted above), but a zero-check run must never read as success.
        for label, detail in c.failures:
            print("FAILED: %s — %s" % (label, detail))
        return 1
    if c.passes == 0:
        print("FAILED: nothing was checked — every package was skipped")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
