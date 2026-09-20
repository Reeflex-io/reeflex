#!/usr/bin/env python3
"""check_published_content.py — the tree and the index disagree under ONE version number.

WHY THIS EXISTS (RFX-300 requirement 3).  On 2026-09-16 qa-211 measured that the
published `reeflex-mcp` 0.1.3 lets the governed upstream classify itself: an MCP
server that declares `readOnlyHint: true` on an unmapped destructive tool turns
core's DENY into ALLOW.  That hole is FIXED on main.  It reached no customer,
because `reeflex-mcp/pyproject.toml` on main ALSO declared `version = "0.1.3"`,
so `pip install -U reeflex-mcp` resolved 0.1.3 == 0.1.3 and reported "already
satisfied".  317 source lines of merged security fixes, invisible to the index.

UPDATE 2026-09-18 (qa--247).  The tree is at 0.1.4, so the COLLISION this
component was written to catch is over and its waiver is gone.  The INDEX is
unchanged -- `pip install reeflex-mcp` still serves the 0.1.3 wheel, re-measured
that day answering `allow` on a `readOnlyHint: true` where the same call with no
annotation answers `deny` -- and it stays that way until a tag is cut.  That
half now lives in `UNPUBLISHED_WITH_A_TICKET`, below.

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

               NOT EVERY LAG IS ROUTINE, though, and the difference is not
               visible in this outcome on its own: while reeflex-mcp sat at a
               COLLISION every gate run printed RFX-300 next to it, and moving
               the version -- the remedy -- turned that into an UNPUBLISHED
               line indistinguishable from the two packages merely waiting for
               a tag.  `UNPUBLISHED_WITH_A_TICKET` below is what keeps the
               ticket on the line until the release actually happens, and
               reports the entry as EXPIRED once it has (RFX-377: it used to
               FAIL, which reddened `main` for whoever merged after a release).

  COLLISION    the version is on the index AND the contents differ.  FAIL.
               This is the only failing outcome of the comparison itself, and
               it is the RFX-300 shape exactly.  The one other way this
               component fails is a declaration that is STALE -- an entry
               naming the artefact still under test that no longer describes
               anything.  An entry naming an artefact NO LONGER under test is
               EXPIRED: printed, counted on the anchored line, and not a
               failure, because the event that expired it is the remedy.

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
    # reeflex-mcp / RFX-300 was waived here at 0.1.3, with its own remedy
    # written into the waiver: "publishing a HIGHER version".  qa--247 moved
    # reeflex-mcp to 0.1.4, so the collision the waiver excused no longer
    # exists and this component fails on the stale entry by design (watched
    # failing: exit 1, "stale waiver: reeflex-mcp (waived at 0.1.3 for
    # RFX-300)").  Removed rather than left to rot.  The half of RFX-300 the
    # bump does NOT close -- the index still serving the old wheel until a tag
    # is cut -- moved to UNPUBLISHED_WITH_A_TICKET below, because that is the
    # state a version bump puts it in and an unannotated UNPUBLISHED line is
    # indistinguishable from a routine lag.
    # reeflex-claude / RFX-299 was waived here at 0.2.0 ("#147 moved
    # SETUP_DOC_SHA256 without moving the version, so the published 0.2.0
    # prints a digest the tree no longer has"), with its own remedy written
    # into the waiver: bump to 0.2.1. RFX-325 did that bump, so the collision
    # the waiver excused no longer exists and the entry now hides nothing --
    # which this component detects and fails on by design. Removed rather
    # than left to rot into a waiver nobody can attribute.
}


# ---------------------------------------------------------------------------
# UNPUBLISHED entries that are NOT a routine lag.
#
# WHY THIS TABLE EXISTS, and it is a consequence of moving a version rather
# than a new idea.  UNPUBLISHED is "the tree is ahead of the index", which for
# reeflex-claude and reeflex-litellm today means a normal wait for the next
# tag.  For reeflex-mcp it means something a customer can be hurt by: the wheel
# `pip install reeflex-mcp` serves is the one qa--211 measured letting the
# governed upstream classify itself, and qa--247 re-measured it answering
# `allow` where the same call with no annotation answers `deny` (RFX-300).
# Before the bump that fact was printed on every gate run as "COLLISION
# (WAIVED, RFX-300)".  After the bump the same fact renders as one more
# UNPUBLISHED line, identical in appearance to the two routine ones -- so the
# bump, on its own, is a change that makes this component QUIETER about a
# defect that has not moved.  This table is what stops that.
#
# It follows the waiver's three properties, for the same reasons:
#
#   1. it names the version the INDEX is serving, so it cannot silently cover a
#      different artefact;
#   2. it must name a ticket -- an unexplained annotation is how a gate's
#      output rots into noise;
#   3. IT SELF-EXPIRES.  The entry applies only while the package is
#      UNPUBLISHED.  The moment the tree's version IS on the index -- i.e. the
#      release happened, which is the remedy -- the entry stops describing
#      reality and this component says so, in full, on every run, until it is
#      deleted.
#
# It does NOT fail the gate while the lag is real, for the reason the module
# docstring already gives about UNPUBLISHED: a check that reddens on the state
# the remedy passes through gets switched off, and the remedy here (cut a tag)
# is an owner decision this component is not entitled to force.  What it is
# entitled to do is refuse to be quiet.
#
# AND IT DOES NOT FAIL THE GATE WHEN IT EXPIRES EITHER, WHICH IS A REVERSAL OF
# THE ORIGINAL DESIGN (RFX-377).  Expiry is caused by the release -- the very
# remedy the paragraph above declines to force -- so failing on it reddens the
# gate on the state the remedy passes through, one step later.  It does not
# even redden the release round: that round's gate runs before the upload, so
# it goes green, and the red lands on `main` afterwards and on whoever merges
# next.  Measured on 2026-09-20: publishing v0.2.2 at 00:40Z expired the
# `reeflex-mcp` entry that used to live here, this component went red on an
# unchanged `main` (run 35478969213, green on the same sha at 00:31Z), and six
# open pull requests were blocked behind it under the main-CI-green-between-
# merges rule.  The entry excused nothing in either state, so nothing was
# hidden by letting it pass -- it is now printed as EXPIRED and counted on the
# anchored line instead.
# ---------------------------------------------------------------------------

UNPUBLISHED_WITH_A_TICKET = {
    # reeflex-mcp / RFX-300 lived here, flagged at `index_serves: 0.1.3`: the
    # wheel `pip install reeflex-mcp` served classified an unmapped production
    # tool from the upstream server's own `readOnlyHint`, so the governed
    # component moved core's verdict, and the tree's fix (RFX-173
    # trust_annotations, RFX-174/175, RFX-138, RFX-129/214) reached no customer.
    # The v0.2.2 tag published reeflex-mcp 0.1.4 on 2026-09-20T00:40:40Z; the
    # wheel now MATCHes the tree, so the lag this entry warned about is over and
    # the entry is deleted rather than left to report EXPIRED forever.
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

def check(repo_root: str, fetch=fetch_wheel, only=None, waivers=None, flagged=None):
    """Return (ok, lines). `fetch` is injectable so the selftest needs no network."""
    if waivers is None:
        waivers = WAIVED_COLLISIONS
    if flagged is None:
        flagged = UNPUBLISHED_WITH_A_TICKET
    packages = discover_packages(repo_root)
    if only:
        packages = [p for p in packages if p["dist"] in only]

    out, collisions, unreachable, matched, unpublished = [], [], [], [], []
    waived, used_waivers = [], set()
    flagged_lags, used_flags = [], set()

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
            flag = flagged.get(dist)
            if flag:
                used_flags.add(dist)
                flagged_lags.append("%s==%s (%s)" % (dist, version, flag["ticket"]))
                out.append("  %s==%s: UNPUBLISHED — the tree is ahead of the index, "
                           "which is not a collision, BUT the index still serves "
                           "%s==%s and %s: %s"
                           % (dist, version, dist, flag["index_serves"],
                              flag["ticket"], flag["why"]))
                out.append("      `pip install %s` keeps serving %s until this "
                           "version is published; the tree moving is not the "
                           "customer getting the fix." % (dist, flag["index_serves"]))
            else:
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

    # A declaration that no longer describes anything splits two ways, and
    # RFX-377 is the measurement that made the split necessary.  Both branches
    # are only evaluated when the index WAS reachable and the package was
    # actually examined, so an outage cannot fake either one.
    #
    #   STALE    the version the entry names is STILL the version under
    #            examination, and there is no collision.  The entry is a lie
    #            about an artefact that is still out there -> FAIL.
    #
    #   EXPIRED  the version the entry names is not the one under examination
    #            any more -- the tree was bumped, or the release happened.  The
    #            entry's subject is gone.  It excuses nothing (the pin already
    #            guarantees that: `is_waived` requires an exact version match),
    #            so it cannot hide a collision, and it does not fail -> it is
    #            reported, loudly, on every run until someone deletes it.
    #
    # The reversal is paid for.  Until 2026-09-20 both branches failed, by
    # design -- "a waiver list that does not self-expire is how a gate rots
    # into a checkbox".  Publishing v0.2.2 at 00:40Z expired the one live entry
    # in `UNPUBLISHED_WITH_A_TICKET` and this component went red on `main`,
    # AFTER the release round had finished green, blocking six open pull
    # requests behind a tree nobody had changed.  The pressure to delete is
    # kept and moved onto the PASS line, where it is visible every run instead
    # of being a surprise that blocks a merge queue.
    examined = {p["dist"] for p in packages}
    tree_version = {p["dist"]: p["version"] for p in packages}
    stale, expired = [], []
    for dist, waiver in sorted(waivers.items()):
        if dist not in examined or dist in used_waivers:
            continue
        where = ("%s (waived at %s for %s; the tree now declares %s)"
                 % (dist, waiver["version"], waiver["ticket"], tree_version.get(dist)))
        if waiver["version"] == tree_version.get(dist):
            stale.append("%s (waived at %s for %s)"
                         % (dist, waiver["version"], waiver["ticket"]))
        else:
            expired.append(where)
    if stale:
        out.append("PUBLISHED-CONTENT: FAIL (stale waiver: %s — the version it names "
                   "is the version the tree still declares, and the collision it "
                   "excuses is gone, so the entry now hides nothing and excuses "
                   "nothing. Delete it from WAIVED_COLLISIONS)" % "; ".join(stale))
        return False, out
    for line in expired:
        out.append("  EXPIRED WAIVER: %s — the tree moved off the version this "
                   "waiver pins, so it excuses nothing on any artefact under test. "
                   "Delete it from WAIVED_COLLISIONS" % line)

    # Same rule, one state over: an UNPUBLISHED_WITH_A_TICKET entry for a
    # package that is no longer UNPUBLISHED means the release happened, which
    # is the whole remedy.  The entry is then a warning about a lag that ended
    # -- EXPIRED, not stale, and it is the exact case RFX-377 measured.
    expired_flags = []
    for dist, flag in sorted(flagged.items()):
        if dist not in examined or dist in used_flags:
            continue
        expired_flags.append("%s (flagged at %s for %s)" % (dist, flag["index_serves"],
                                                            flag["ticket"]))
    for line in expired_flags:
        out.append("  EXPIRED LAG FLAG: %s — the package is no longer ahead of the "
                   "index, so the lag this entry warns about is over and it warns "
                   "about nothing. Delete it from UNPUBLISHED_WITH_A_TICKET" % line)

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
    if flagged_lags:
        detail += (", %d of those lag(s) NOT routine — the index still serves a "
                   "wheel a ticket is open on (%s)"
                   % (len(flagged_lags), ", ".join(flagged_lags)))
    # The expiry debt rides on the anchored line, not only in the body: this is
    # the sentence gate.py shows as the component detail, and an expired entry
    # only visible to someone scrolling the log is the quiet rot these tables'
    # rules exist to prevent.
    if expired or expired_flags:
        detail += (", %d EXPIRED declaration(s) describing an artefact no longer "
                   "under test — delete them" % (len(expired) + len(expired_flags)))
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

        # 7c. THE ONE THAT MATTERS: the collision is fixed at the version the
        #     waiver names, and the waiver remains -> FAIL. A waiver that
        #     outlives its defect on the artefact still under test is a checkbox.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          waivers=w)
        record("waiver whose collision is gone at the version it names -> FAIL",
               not ok and any("stale waiver" in l for l in lines))

        # 7c-ii. RFX-377, the other half: the waiver names a version the tree
        #     has moved OFF. Its subject is gone, it excuses nothing (7b proves
        #     the pin), so it EXPIRES -- reported, counted, and NOT a failure.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          waivers=w_other)
        record("waiver pinned to a version the tree left -> EXPIRED, not FAIL",
               ok and any("EXPIRED WAIVER" in l for l in lines)
               and not any("stale waiver" in l for l in lines))
        record("...and the expiry is counted on the anchored PASS line",
               any("PUBLISHED-CONTENT: PASS" in l and "EXPIRED declaration" in l
                   for l in lines))

        # 7c-iii. and it still excuses NOTHING: the same expired waiver over a
        #     REAL collision fails, undeclared, by name. This is the fail-closed
        #     corner -- without it, "expired is not a failure" would be a way to
        #     make the component quieter rather than more correct.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", drifted), "t"),
                          waivers=w_other)
        record("an EXPIRED waiver excuses no collision",
               not ok and any("COLLISION" in l and "WAIVED" not in l for l in lines))

        # 7d. an index outage must not be read as a waiver expiring.
        #     WHAT ACTUALLY PROTECTS THIS IS THE EARLY RETURN on `unreachable`,
        #     not the `dist not in examined` clause below it -- measured by
        #     removing that clause and watching this arm stay green at 23/23.
        #     Both arms are kept, and 7d-ii is the one that covers the clause.
        ok, lines = check(root, fetch=boom, waivers=w)
        record("outage is not read as a stale waiver",
               not ok and any("fails closed" in l for l in lines)
               and not any("stale waiver" in l or "EXPIRED WAIVER" in l for l in lines))

        # 7d-ii. a declaration naming a package THIS RUN DID NOT EXAMINE -- a
        #     `--only` filter, or a dist that has left the repo -- must not be
        #     judged at all. Judging it would report an expiry for an artefact
        #     nobody compared, and under `--only` that is a verdict about a
        #     package the run deliberately skipped.
        w_absent = {"reeflex-absent": {"version": "1.2.3", "ticket": "RFX-DEMO", "why": "x"}}
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          waivers=w_absent)
        record("a waiver for a package this run did not examine is not judged",
               ok and not any("EXPIRED WAIVER" in l or "stale waiver" in l for l in lines))

        # --- the flagged-lag arms -------------------------------------------
        # An UNPUBLISHED line that a ticket is open on must not read like the
        # two routine ones next to it.  Note the SAME `fetch=lambda: None` as
        # arm 5: the only variable between 7e and 5 is the table.
        f = {"reeflex-demo": {"index_serves": "1.0.0", "ticket": "RFX-DEMO",
                              "why": "the old wheel does the bad thing"}}

        # 7e. flagged + still unpublished -> PASS, and the ticket is ON the line
        ok, lines = check(root, fetch=lambda d, v: None, flagged=f)
        record("flagged lag -> PASS, names the ticket and the served version",
               ok and any("UNPUBLISHED" in l and "RFX-DEMO" in l and "1.0.0" in l
                          for l in lines)
               and any("NOT routine" in l for l in lines))

        # 7f. the control for 7e: an UNPUBLISHED package with NO entry must
        #     stay plain.  Without this, 7e could pass because every
        #     UNPUBLISHED line had grown a ticket.
        ok, lines = check(root, fetch=lambda d, v: None, flagged={})
        record("an unflagged lag stays a plain UNPUBLISHED line",
               ok and any("UNPUBLISHED" in l for l in lines)
               and not any("RFX-DEMO" in l or "NOT routine" in l for l in lines))

        # 7g. THE ONE RFX-377 IS ABOUT: the package is on the index again --
        #     the release happened, which is the entry's own remedy -- and the
        #     entry remains. A warning about a lag that ended is a warning
        #     nobody can act on, but it is also not a reason to redden a gate
        #     that blocks every open PR. EXPIRED: reported, counted, not a FAIL.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          flagged=f)
        record("flag whose lag is over -> EXPIRED, not FAIL",
               ok and any("EXPIRED LAG FLAG" in l for l in lines))
        record("...and it names both the ticket and the version it flagged",
               any("EXPIRED LAG FLAG" in l and "RFX-DEMO" in l and "1.0.0" in l
                   for l in lines))
        record("...and the expiry is counted on the anchored PASS line",
               any("PUBLISHED-CONTENT: PASS" in l and "EXPIRED declaration" in l
                   for l in lines))

        # 7g-ii. the fail-closed corner for the flag table: an expired entry
        #     must not soften a REAL collision on the republished wheel. The
        #     flag table never excused a collision in the first place, and this
        #     arm is what stops a future edit from making it do so quietly.
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", drifted), "t"),
                          flagged=f)
        record("an EXPIRED lag flag does not soften a collision on the new wheel",
               not ok and any("COLLISION" in l for l in lines))

        # 7h. and an outage must not be read as the lag having ended, for the
        #     same reason 7d exists for waivers -- and with the same caveat:
        #     the early return on `unreachable` is what carries this one.
        ok, lines = check(root, fetch=boom, flagged=f)
        record("outage is not read as an expired lag flag",
               not ok and any("fails closed" in l for l in lines)
               and not any("EXPIRED LAG FLAG" in l for l in lines))

        # 7h-ii. the mirror of 7d-ii, for the flag table.
        f_absent = {"reeflex-absent": {"index_serves": "1.0.0", "ticket": "RFX-DEMO",
                                       "why": "x"}}
        ok, lines = check(root, fetch=lambda d, v: (_fake_wheel("reeflex_demo", tree_files), "t"),
                          flagged=f_absent)
        record("a lag flag for a package this run did not examine is not judged",
               ok and not any("EXPIRED LAG FLAG" in l for l in lines))

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
