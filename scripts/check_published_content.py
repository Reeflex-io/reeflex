#!/usr/bin/env python3
"""check_published_content.py — the tree and the index disagree under ONE version number.

WHY THIS EXISTS (RFX-300 requirement 3).  On 2026-09-16 qa-211 measured that the
published `reeflex-mcp` 0.1.3 lets the governed upstream classify itself: an MCP
server that declares `readOnlyHint: true` on an unmapped destructive tool turns
core's DENY into ALLOW.  That hole is FIXED on main.  It reaches no customer,
because `reeflex-mcp/pyproject.toml` on main also declares `version = "0.1.3"`,
so `pip install -U reeflex-mcp` resolves 0.1.3 == 0.1.3 and reports "already
satisfied".  317 source lines of merged security fixes, invisible to the index.

The ticket states the requirement in its own words, and states why the
instrument that already exists does not meet it:

    "a release-gate component that FAILS when a published artefact's SOURCES
     differ from the checkout's while the VERSION STRING matches.  The
     version-lag check RFX-241 asks for would not have caught this one, because
     there is no version lag -- there is a version COLLISION.  Compare content,
     not numbers."

WHAT THIS IS NOT.  `scripts/check_published_classifier.py` (RFX-241 step 3)
compares BEHAVIOUR: it drives the published reeflex-claude wheel through this
tree's conformance corpus.  It is the better instrument for the defect it was
built for and it is NOT made redundant here.  It cannot catch RFX-300 for two
reasons, both measured rather than argued:

  * it scopes to reeflex-claude, and the RFX-300 hole is in reeflex-mcp; and
  * qa-211 measured that a hole present in BOTH trees scores zero divergences.
    A behavioural corpus is blind to a defect the checkout shares with the
    artefact.  Content is the orthogonal instrument: it does not care whether
    either side is correct, only whether they are the same thing.

So the two components answer different questions and both are worth running.
This one asks only: does the artefact a customer installs contain the code this
repository believes it published?

THE THREE OUTCOMES, and why the middle one is the whole design
==============================================================

  MATCH        the version in pyproject.toml is on the index and every file in
               the distributed package is byte-identical to the tree.  PASS.

  UNPUBLISHED  the version in pyproject.toml is NOT on the index.  PASS, and
               this is deliberate.  The normal state of a healthy repo between
               a version bump and its release is "the tree is ahead of the
               index", and a gate that goes red on that is a gate that goes red
               on the fix for RFX-300 itself.  A check that reddens on the
               remedy gets switched off within a day, and a switched-off gate
               protects nobody -- the same argument RFX-145 makes about strict
               mode.  The version being absent is reported on its own line so
               the state is visible rather than merely tolerated.

  COLLISION    the version is on the index AND the contents differ.  FAIL.
               This is the only failing outcome and it is the RFX-300 shape
               exactly.

WHAT COUNTS AS A DIFFERENCE.  Every file the wheel ships under its top-level
package directory, not only `*.py`.  reeflex-mcp ships three `mappings/*.yaml`
files inside the package, and those files are what decide how a tool name is
classified -- a `.py`-only comparison would have been blind to a mapping change,
which is the same class of defect this check exists for.  (Measured this round:
those three YAML files happen to be identical between wheel and tree, so
widening the comparison did not move today's verdict.  It is in scope because of
what it could hide tomorrow, and this sentence is here so a reader does not read
the widening as a finding.)  A file present on only ONE side counts too: adding
a module without moving the version is the same collision.

FAIL-CLOSED ON NO NETWORK.  If the index cannot be reached, this exits non-zero
and says so.  It does not pass, and it does not print INCONCLUSIVE: a verdict
word that does not move the exit status is how a check quietly stops checking
(see RFX-97's `closed: none` with exit 0).  gate.py runs this component only on
a run that is already reaching PyPI; `--pypi skip` skips it with the rest.

WHAT THIS INSTRUMENT CANNOT SEE, stated because the claims canon requires it:

  * It compares the SDIST/wheel payload to the tree.  It does not verify that
    the wheel on the index was BUILT from any particular commit -- there is no
    provenance attestation here, and two different commits can produce identical
    sources.  It answers "same content", not "same origin".
  * It reads the top-level package directory only.  Entry-point metadata,
    dependency pins in METADATA, and the `dist-info` are NOT compared, so a
    wheel whose declared dependencies drifted while its sources did not is a
    MATCH here.  That is RFX-241/dep-floors territory.
  * It compares against the version pyproject.toml declares.  It says nothing
    about whether that version SHOULD have moved, and it cannot: deciding to cut
    0.1.4 is a release-sequencing call, not a measurement.
  * A package with no `pyproject.toml` is not discovered.  reeflex-core is the
    deliberate case -- its release artefact is the Docker image, not a wheel.
"""

from __future__ import annotations

import argparse
import difflib
import io
import json
import os
import posixpath
import sys
import urllib.error
import urllib.request
import zipfile

PYPI_JSON = "https://pypi.org/pypi/{dist}/{version}/json"
HTTP_TIMEOUT = 60

# Files that exist in a working tree as a build by-product and are never part of
# the distribution.  Anything NOT listed here is compared; the list is small and
# explicit on purpose, because "the comparison quietly ignored that directory"
# is the failure mode this whole file is about.
TREE_IGNORE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
TREE_IGNORE_SUFFIXES = (".pyc", ".pyo", ".pyd", ".so")


class IndexUnreachable(Exception):
    """The index could not be consulted — distinct from 'the version is absent'."""


# ---------------------------------------------------------------------------
# WAIVERS — the collisions that already exist, each naming the ticket that
# tracks it, and each of which EXPIRES BY ITSELF.
#
# Wiring this component in with no waivers would turn main red on every PR from
# the moment it lands, because both collisions below are real right now and the
# remedy for both is a version bump, which is a release-sequencing decision this
# check is not entitled to take (qa-210 declined it on RFX-299 for the same
# reason).  gate.py already names this trap in its own words, about adding
# reeflex-litellm to PUBLISHED before the wheel existed: "Adding it before the
# wheel exists makes this gate red on every PR, including the one that adds it."
#
# So a waiver here means one thing only: "this collision is known, a ticket owns
# it, and a NEW one must still fail."  Three properties make it a waiver rather
# than a hole, and the third is the one that matters:
#
#   1. it is pinned to an exact version — the collision on some OTHER version of
#      the same package is not waived;
#   2. it must name a ticket, like conformance.py's `residual` field, because
#      "an unexplained exclusion is how a gate quietly stops gating";
#   3. a waiver whose collision has GONE AWAY is itself a FAILURE.  When
#      reeflex-mcp is republished at 0.1.4, or the tree moves off 0.1.3, this
#      entry stops describing reality and the component goes red until it is
#      deleted.  A waiver list that does not self-expire is how a gate rots into
#      a checkbox; this one cannot outlive the defect it excuses.
# ---------------------------------------------------------------------------

WAIVED_COLLISIONS = {
    "reeflex-mcp": {
        "version": "0.1.3",
        "ticket": "RFX-300",
        "why": "317 lines of merged security fixes (RFX-173 trust_annotations, "
               "RFX-174/175, RFX-138, RFX-129/214) are on main under the version "
               "string already on the index, so no customer can pip-upgrade into "
               "them. Closing it means publishing a HIGHER version, which is a "
               "release decision.",
    },
    "reeflex-claude": {
        "version": "0.2.0",
        "ticket": "RFX-299",
        "why": "#147 moved SETUP_DOC_SHA256 without moving the version, so the "
               "published 0.2.0 prints a digest the tree no longer has. Tracked "
               "with its own remedy (bump to 0.2.1) as a release-sequencing call.",
    },
}


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _toml_scalar(text: str, key: str):
    """First top-level `key = "value"` in a pyproject's [project] table.

    Deliberately not a TOML parser: python 3.9 has no tomllib, this repo's gate
    runs on the system interpreter, and adding a dependency to a release-gate
    component to read two strings is the wrong trade.  It reads only the
    [project] table so a `[tool.x] version = ...` cannot answer for it.
    """
    in_project = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_project = line in ("[project]",)
            continue
        if not in_project or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip().strip('"').strip("'")
    return None


def discover_packages(repo_root: str) -> list:
    """Every directory with a pyproject.toml that declares a name and version.

    Discovered, never listed.  gate.py's own `PUBLISHED` constant is a hand-kept
    list and it omits reeflex-litellm (documented there, and true when it was
    written); a hardcoded roster of packages goes stale in exactly the way the
    version numbers this check exists for went stale.
    """
    found = []
    for entry in sorted(os.listdir(repo_root)):
        pyproject = os.path.join(repo_root, entry, "pyproject.toml")
        if not os.path.isfile(pyproject):
            continue
        with open(pyproject, encoding="utf-8") as fh:
            text = fh.read()
        dist = _toml_scalar(text, "name")
        version = _toml_scalar(text, "version")
        if not dist or not version:
            continue
        module = dist.replace("-", "_")
        pkg_dir = os.path.join(repo_root, entry, module)
        if not os.path.isdir(pkg_dir):
            continue
        found.append({"dist": dist, "version": version,
                      "module": module, "pkg_dir": pkg_dir, "dir": entry})
    return found


# ---------------------------------------------------------------------------
# fetching
# ---------------------------------------------------------------------------

def fetch_wheel(dist: str, version: str):
    """Return (wheel_bytes, upload_time) for this exact version, or None if absent.

    Uses the JSON API and urllib rather than `pip download`, and the reason is
    measured: the devbox's default interpreter is 3.9, reeflex-mcp requires
    >=3.10, and `pip download reeflex-mcp==0.1.3` answers

        ERROR: Ignored the following versions that require a different python
        version ... No matching distribution found

    which is indistinguishable from "not published" unless you read the stderr.
    A gate component that reports NOT PUBLISHED for the one package whose
    collision it exists to catch is worse than no component.  The JSON API has
    no interpreter constraint.
    """
    url = PYPI_JSON.format(dist=dist, version=version)
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            meta = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # the version is genuinely not on the index
        raise IndexUnreachable("%s -> HTTP %s" % (url, exc.code))
    except Exception as exc:  # noqa: BLE001 - urllib raises a wide family here
        raise IndexUnreachable("%s -> %s" % (url, exc))

    for u in meta.get("urls", []):
        if u.get("packagetype") == "bdist_wheel":
            try:
                with urllib.request.urlopen(u["url"], timeout=HTTP_TIMEOUT) as resp:
                    return resp.read(), u.get("upload_time_iso_8601", "?")
            except Exception as exc:  # noqa: BLE001
                raise IndexUnreachable("%s -> %s" % (u["url"], exc))
    raise IndexUnreachable("%s==%s is on the index but ships no wheel" % (dist, version))


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------

def _wheel_payload(wheel_bytes: bytes, module: str) -> dict:
    """{relative path: bytes} for every file the wheel ships under `module/`."""
    out = {}
    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            head = name.split("/", 1)[0]
            if head != module:
                continue  # dist-info and any other top-level are out of scope
            out[posixpath.relpath(name, module)] = zf.read(name)
    return out


def _tree_payload(pkg_dir: str) -> dict:
    out = {}
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in TREE_IGNORE_DIRS]
        for fn in files:
            if fn.endswith(TREE_IGNORE_SUFFIXES):
                continue
            abs_path = os.path.join(root, fn)
            rel = os.path.relpath(abs_path, pkg_dir).replace(os.sep, "/")
            with open(abs_path, "rb") as fh:
                out[rel] = fh.read()
    return out


def _line_delta(a: bytes, b: bytes) -> int:
    left = a.decode("utf-8", "replace").splitlines()
    right = b.decode("utf-8", "replace").splitlines()
    return sum(1 for line in difflib.unified_diff(left, right, lineterm="", n=0)
               if line[:1] in "+-" and not line.startswith(("---", "+++")))


def compare(wheel_bytes: bytes, pkg_dir: str, module: str) -> dict:
    """Content comparison of a published wheel against the checkout."""
    published = _wheel_payload(wheel_bytes, module)
    tree = _tree_payload(pkg_dir)

    changed, only_wheel, only_tree, lines = [], [], [], 0
    for rel in sorted(set(published) | set(tree)):
        if rel not in tree:
            only_wheel.append(rel)
            lines += _line_delta(published[rel], b"")
        elif rel not in published:
            only_tree.append(rel)
            lines += _line_delta(b"", tree[rel])
        elif published[rel] != tree[rel]:
            delta = _line_delta(published[rel], tree[rel])
            changed.append((rel, delta))
            lines += delta
    return {
        "compared": len(set(published) | set(tree)),
        "changed": changed,
        "only_wheel": only_wheel,
        "only_tree": only_tree,
        "lines": lines,
        "identical": not (changed or only_wheel or only_tree),
    }


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------

def check(repo_root: str, fetch=fetch_wheel, only=None, waivers=None):
    """Return (ok, lines). `fetch` is injectable so the selftest needs no network."""
    if waivers is None:
        waivers = WAIVED_COLLISIONS
    packages = discover_packages(repo_root)
    if only:
        packages = [p for p in packages if p["dist"] in only]

    out, collisions, unreachable, matched, unpublished = [], [], [], [], []
    waived, used_waivers = [], set()

    if not packages:
        out.append("  no directory with a [project] name+version was found")
        out.append("PUBLISHED-CONTENT: FAIL (discovered zero packages — a content "
                   "check over nothing passes trivially)")
        return False, out

    for pkg in packages:
        dist, version = pkg["dist"], pkg["version"]
        try:
            fetched = fetch(dist, version)
        except IndexUnreachable as exc:
            unreachable.append(dist)
            out.append("  %s==%s: INDEX-UNREACHABLE (%s)" % (dist, version, exc))
            continue

        if fetched is None:
            unpublished.append("%s==%s" % (dist, version))
            out.append("  %s==%s: UNPUBLISHED — the tree is ahead of the index, "
                       "which is not a collision" % (dist, version))
            continue

        wheel_bytes, uploaded = fetched
        result = compare(wheel_bytes, pkg["pkg_dir"], pkg["module"])
        if result["identical"]:
            matched.append("%s==%s" % (dist, version))
            out.append("  %s==%s: MATCH (%d files, uploaded %s)"
                       % (dist, version, result["compared"], uploaded))
            continue

        waiver = waivers.get(dist)
        is_waived = bool(waiver) and waiver["version"] == version
        if is_waived:
            used_waivers.add(dist)
            waived.append("%s==%s (%s)" % (dist, version, waiver["ticket"]))
            label = "COLLISION (WAIVED, %s)" % waiver["ticket"]
        else:
            collisions.append("%s==%s" % (dist, version))
            label = "COLLISION"
        out.append("  %s==%s: %s — same version string, %d differing lines "
                   "across %d files (wheel uploaded %s)"
                   % (dist, version, label, result["lines"],
                      len(result["changed"]) + len(result["only_wheel"])
                      + len(result["only_tree"]), uploaded))
        for rel, delta in result["changed"]:
            out.append("      %s: %d lines differ" % (rel, delta))
        for rel in result["only_wheel"]:
            out.append("      %s: in the PUBLISHED wheel, not in the tree" % rel)
        for rel in result["only_tree"]:
            out.append("      %s: in the TREE, not in the published wheel" % rel)

    if unreachable:
        out.append("PUBLISHED-CONTENT: FAIL (the index could not be consulted for "
                   "%s — this check fails closed, because a content comparison "
                   "that did not run is not a green one)" % ", ".join(unreachable))
        return False, out

    # A waiver that no longer describes a real collision is itself a failure.
    # This is what stops the list above from becoming permanent: the entry dies
    # with the defect, not whenever someone remembers to prune it.  Only
    # evaluated when the index WAS reachable and the package was actually
    # examined, so an outage cannot fake an expiry.
    examined = {p["dist"] for p in packages}
    stale = []
    for dist, waiver in sorted(waivers.items()):
        if dist not in examined or dist in used_waivers:
            continue
        stale.append("%s (waived at %s for %s)" % (dist, waiver["version"], waiver["ticket"]))
    if stale:
        out.append("PUBLISHED-CONTENT: FAIL (stale waiver: %s — the collision it "
                   "excuses is gone, so the entry now hides nothing and excuses "
                   "nothing. Delete it from WAIVED_COLLISIONS)" % "; ".join(stale))
        return False, out

    if collisions:
        out.append("PUBLISHED-CONTENT: FAIL (%s published under a version string the "
                   "tree still declares, with different content — a customer running "
                   "`pip install -U` gets the OLD code and pip reports success; "
                   "cut a higher version. See RFX-300)" % ", ".join(collisions))
        return False, out

    detail = "%d matched" % len(matched)
    if unpublished:
        detail += ", %d not yet on the index (%s)" % (len(unpublished),
                                                      ", ".join(unpublished))
    if waived:
        detail += ", %d KNOWN collision(s) waived against a ticket (%s)" % (
            len(waived), ", ".join(waived))
    out.append("PUBLISHED-CONTENT: PASS (%s)" % detail)
    return True, out


# ---------------------------------------------------------------------------
# selftest — every arm proven on a synthetic wheel, no network
# ---------------------------------------------------------------------------

def _fake_wheel(module: str, files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, body in files.items():
            zf.writestr("%s/%s" % (module, rel), body)
        zf.writestr("%s-9.9.9.dist-info/METADATA" % module, "Name: x\n")
    return buf.getvalue()


def selftest() -> int:
    import shutil
    import tempfile

    checks = []

    def record(name, ok):
        checks.append((name, ok))

    root = tempfile.mkdtemp(prefix="rfx300-selftest-")
    try:
        pkg_dir = os.path.join(root, "reeflex-demo", "reeflex_demo")
        os.makedirs(os.path.join(pkg_dir, "mappings"))
        with open(os.path.join(root, "reeflex-demo", "pyproject.toml"), "w") as fh:
            fh.write('[project]\nname = "reeflex-demo"\nversion = "1.2.3"\n')
        with open(os.path.join(pkg_dir, "__init__.py"), "w") as fh:
            fh.write("VERSION = 1\n")
        with open(os.path.join(pkg_dir, "mappings", "m.yaml"), "w") as fh:
            fh.write("tool: safe\n")

        tree_files = {"__init__.py": "VERSION = 1\n", "mappings/m.yaml": "tool: safe\n"}

        # 1. identical content -> PASS
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"))
        record("identical wheel and tree -> PASS", ok and any("MATCH" in l for l in lines))

        # 2. a .py that differs -> FAIL (the RFX-300 shape)
        drifted = dict(tree_files, **{"__init__.py": "VERSION = 2\n"})
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", drifted), "t"))
        record("differing .py under one version -> FAIL",
               not ok and any("COLLISION" in l for l in lines))

        # 3. a NON-.py that differs -> FAIL. This is the arm a `*.py`-only
        #    comparison fails, and reeflex-mcp's classification mappings are
        #    exactly this file type.
        yaml_drift = dict(tree_files, **{"mappings/m.yaml": "tool: destructive\n"})
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", yaml_drift), "t"))
        record("differing .yaml under one version -> FAIL",
               not ok and any("m.yaml" in l for l in lines))

        # 4. a module only in the tree -> FAIL (a new file, version not bumped)
        fewer = {"__init__.py": "VERSION = 1\n"}
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", fewer), "t"))
        record("file present only in the tree -> FAIL",
               not ok and any("not in the published wheel" in l for l in lines))

        # 5. version absent from the index -> PASS, and NOT silently
        ok, lines = check(root, fetch=lambda d, v: None)
        record("version not on the index -> PASS and reported",
               ok and any("UNPUBLISHED" in l for l in lines))

        # 6. index unreachable -> FAIL. The arm that stops this being a check
        #    that passes without running.
        def boom(d, v):
            raise IndexUnreachable("simulated outage")

        ok, lines = check(root, fetch=boom)
        record("index unreachable -> FAIL, not PASS",
               not ok and any("fails closed" in l for l in lines))

        # 7. __pycache__ in the tree must not be read as a collision
        os.makedirs(os.path.join(pkg_dir, "__pycache__"))
        with open(os.path.join(pkg_dir, "__pycache__", "x.cpython-39.pyc"), "wb") as fh:
            fh.write(b"\x00\x01")
        ok, _ = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"))
        record("__pycache__ is not a collision", ok)

        # --- the waiver arms ------------------------------------------------
        w = {"reeflex-demo": {"version": "1.2.3", "ticket": "RFX-DEMO", "why": "x"}}

        # 7a. a waived collision at the waived version -> PASS, still printed
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", drifted), "t"),
                          waivers=w)
        record("waived collision -> PASS and still visible",
               ok and any("WAIVED" in l for l in lines))

        # 7b. the SAME package colliding at a DIFFERENT version is NOT waived.
        #     The waiver is pinned, so the next release's collision still fails.
        w_other = {"reeflex-demo": {"version": "9.9.9", "ticket": "RFX-DEMO", "why": "x"}}
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", drifted), "t"),
                          waivers=w_other)
        record("waiver pinned to a version does not cover another version",
               not ok and any("COLLISION" in l and "WAIVED" not in l for l in lines))

        # 7c. THE ONE THAT MATTERS: the collision is fixed, the waiver remains
        #     -> FAIL. A waiver that outlives its defect is a checkbox.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          waivers=w)
        record("waiver whose collision is gone -> FAIL (self-expiring)",
               not ok and any("stale waiver" in l for l in lines))

        # 7d. an index outage must not be read as a waiver expiring
        ok, lines = check(root, fetch=boom, waivers=w)
        record("outage is not read as a stale waiver",
               not ok and any("fails closed" in l for l in lines)
               and not any("stale waiver" in l for l in lines))

        # 8. discovery finds the package by walking, not by a hardcoded list
        record("discovery finds the package",
               [p["dist"] for p in discover_packages(root)] == ["reeflex-demo"])

        # 9. a [tool.x] version must not answer for [project]
        with open(os.path.join(root, "reeflex-demo", "pyproject.toml"), "w") as fh:
            fh.write('[project]\nname = "reeflex-demo"\nversion = "1.2.3"\n'
                     '[tool.poetry]\nversion = "9.9.9"\n')
        record("only the [project] table answers",
               discover_packages(root)[0]["version"] == "1.2.3")
    finally:
        shutil.rmtree(root, ignore_errors=True)

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  selftest %s: %s" % ("PASS" if ok else "FAIL", n))
    if failed:
        print("SELFTEST: FAIL (%d/%d checks failed)" % (len(failed), len(checks)))
        return 1
    print("SELFTEST: PASS (%d checks)" % len(checks))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="check_published_content.py",
        description="FAIL when a published artefact's sources differ from the "
                    "checkout's under the SAME version string (RFX-300)")
    p.add_argument("repo_root", nargs="?", default=None,
                   help="repo root to check (default: the parent of this script's directory)")
    p.add_argument("--only", action="append", default=None,
                   help="restrict to this dist name (repeatable)")
    p.add_argument("--selftest", action="store_true",
                   help="prove every arm on synthetic wheels, no network, and exit")
    args = p.parse_args(sys.argv[1:] if argv is None else argv)

    if args.selftest:
        return selftest()

    repo_root = args.repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok, lines = check(repo_root, only=args.only)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
