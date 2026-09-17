"""Unit tests for scripts/check_published_content.py (RFX-300).

WHY THIS FILE EXISTS, GIVEN THE SCRIPT ALREADY HAS `--selftest`.  `--selftest`
is the script self-attesting, and gate.py runs it as its own step.  This root is
run by `unittest discover -s scripts/tests -t scripts`, i.e. the same runner the
suites are measured with, so these assertions EXECUTE in the suite too — a
detector whose only proof is the tool's own opinion of itself is the shape RFX-87
was filed about.

What these add over `--selftest`, rather than repeating it:

  * the WAIVER LIST is checked against the real repository.  A waiver keyed on a
    dist name that no package declares would sit there looking like an
    accounted-for exception while excusing nothing and, worse, while never
    expiring — the stale-waiver rule only fires for packages that were actually
    examined.  A typo is therefore silent, and that is precisely the class this
    component exists to kill.
  * the anchored verdict line is asserted in the exact shape gate.py's regex
    parses.  The two live in different files and nothing else ties them
    together; RFX-97 is the ticket about a verdict word that did not move an
    exit status.

Written as unittest TestCases because bare pytest-style functions here would
collect zero tests and pass forever (RFX-87).

No test in this file touches the network: every one injects `fetch`.
"""

import io
import os
import re
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import check_published_content as cpc  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The line gate.py parses. Kept here as a literal, deliberately NOT imported
# from gate.py: a contract asserted against its own definition asserts nothing.
VERDICT_RE = re.compile(r"^PUBLISHED-CONTENT: (PASS|FAIL) \((.*)\)$", re.M)


def _wheel(module, files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for rel, body in files.items():
            zf.writestr("%s/%s" % (module, rel), body)
        zf.writestr("%s-0.0.0.dist-info/METADATA" % module, "Name: x\n")
    return buf.getvalue()


class TempPackage:
    """A throwaway repo root holding one package, so no test reads the real tree."""

    def __init__(self, files, version="1.2.3"):
        self.root = tempfile.mkdtemp(prefix="rfx300-test-")
        pkg = os.path.join(self.root, "reeflex-demo", "reeflex_demo")
        os.makedirs(pkg)
        with open(os.path.join(self.root, "reeflex-demo", "pyproject.toml"), "w") as fh:
            fh.write('[project]\nname = "reeflex-demo"\nversion = "%s"\n' % version)
        for rel, body in files.items():
            path = os.path.join(pkg, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(body)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


TREE = {"__init__.py": "VERSION = 1\n", "mappings/m.yaml": "tool: safe\n"}


class VerdictLineContract(unittest.TestCase):
    """gate.py parses a line this script prints. Nothing else couples them."""

    def setUp(self):
        self.pkg = TempPackage(TREE)
        self.addCleanup(self.pkg.close)

    def test_pass_line_matches_the_regex_gate_parses(self):
        ok, lines = cpc.check(self.pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertTrue(ok)
        m = VERDICT_RE.search("\n".join(lines))
        self.assertIsNotNone(m, "no anchored PUBLISHED-CONTENT line in:\n%s" % "\n".join(lines))
        self.assertEqual(m.group(1), "PASS")

    def test_fail_line_matches_the_regex_gate_parses(self):
        drifted = dict(TREE, **{"__init__.py": "VERSION = 2\n"})
        ok, lines = cpc.check(self.pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", drifted), "t"))
        self.assertFalse(ok)
        m = VERDICT_RE.search("\n".join(lines))
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "FAIL")

    def test_exactly_one_verdict_line_is_printed(self):
        """Two verdict lines and the parser reads whichever it meets first."""
        ok, lines = cpc.check(self.pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertEqual(len(VERDICT_RE.findall("\n".join(lines))), 1)


class OutcomeArms(unittest.TestCase):

    def setUp(self):
        self.pkg = TempPackage(TREE)
        self.addCleanup(self.pkg.close)

    def test_identical_content_passes(self):
        ok, _ = cpc.check(self.pkg.root, waivers={},
                          fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertTrue(ok)

    def test_non_python_file_drift_fails(self):
        """reeflex-mcp ships mappings/*.yaml, and those files decide a
        classification. A `*.py`-only comparison is blind to exactly the change
        that matters most."""
        drifted = dict(TREE, **{"mappings/m.yaml": "tool: destructive\n"})
        ok, lines = cpc.check(self.pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", drifted), "t"))
        self.assertFalse(ok)
        self.assertTrue(any("m.yaml" in l for l in lines))

    def test_version_absent_from_index_is_not_a_failure(self):
        """The normal state between a version bump and its release. A gate that
        reddens here reddens on the remedy for RFX-300 itself."""
        ok, lines = cpc.check(self.pkg.root, waivers={}, fetch=lambda d, v: None)
        self.assertTrue(ok)
        self.assertTrue(any("UNPUBLISHED" in l for l in lines))

    def test_unreachable_index_fails_closed(self):
        def boom(d, v):
            raise cpc.IndexUnreachable("simulated outage")

        ok, lines = cpc.check(self.pkg.root, waivers={}, fetch=boom)
        self.assertFalse(ok, "a comparison that did not run must not be green")
        self.assertTrue(any("fails closed" in l for l in lines))

    def test_zero_discovered_packages_is_a_failure(self):
        """A content check over nothing passes trivially, so it must not pass."""
        empty = tempfile.mkdtemp(prefix="rfx300-empty-")
        self.addCleanup(shutil.rmtree, empty, True)
        ok, lines = cpc.check(empty, waivers={}, fetch=lambda d, v: None)
        self.assertFalse(ok)
        self.assertTrue(any("zero packages" in l for l in lines))


class WaiverSemantics(unittest.TestCase):

    def setUp(self):
        self.pkg = TempPackage(TREE)
        self.addCleanup(self.pkg.close)
        self.drifted = dict(TREE, **{"__init__.py": "VERSION = 2\n"})
        self.w = {"reeflex-demo": {"version": "1.2.3", "ticket": "RFX-DEMO", "why": "x"}}

    def test_waived_collision_passes_but_stays_visible(self):
        ok, lines = cpc.check(self.pkg.root, waivers=self.w,
                              fetch=lambda d, v: (_wheel("reeflex_demo", self.drifted), "t"))
        self.assertTrue(ok)
        body = "\n".join(lines)
        self.assertIn("WAIVED", body)
        self.assertIn("RFX-DEMO", body, "a waiver must name its ticket in the transcript")

    def test_waiver_is_pinned_to_one_version(self):
        other = {"reeflex-demo": {"version": "9.9.9", "ticket": "RFX-DEMO", "why": "x"}}
        ok, _ = cpc.check(self.pkg.root, waivers=other,
                          fetch=lambda d, v: (_wheel("reeflex_demo", self.drifted), "t"))
        self.assertFalse(ok, "a waiver for 9.9.9 must not cover the collision at 1.2.3")

    def test_waiver_that_outlives_its_collision_fails(self):
        """The property that stops the list becoming a checkbox."""
        ok, lines = cpc.check(self.pkg.root, waivers=self.w,
                              fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertFalse(ok)
        self.assertTrue(any("stale waiver" in l for l in lines))

    def test_outage_does_not_masquerade_as_an_expired_waiver(self):
        """Otherwise an index outage would tell a reader to delete the waiver
        for a collision that is still there."""
        def boom(d, v):
            raise cpc.IndexUnreachable("simulated outage")

        ok, lines = cpc.check(self.pkg.root, waivers=self.w, fetch=boom)
        self.assertFalse(ok)
        self.assertFalse(any("stale waiver" in l for l in lines))

    def test_waiver_for_a_version_not_on_the_index_is_also_stale(self):
        """A collision requires a PUBLISHED version to collide with.

        This arm was written expecting the opposite — that an unpublished
        version leaves its waiver merely unexercised rather than stale — and the
        implementation disagreed.  The implementation is right: if the version
        is not on the index there is no artefact, so the waiver is excusing
        nothing, exactly as when the collision has been fixed.  Recorded here
        with its reasoning because the two readings are easy to swap, and
        because the state cannot arise from the real workflow: the remedy for
        RFX-300 moves the TREE's version, which trips the pinned-version rule
        instead (see test_waiver_is_pinned_to_one_version).
        """
        ok, lines = cpc.check(self.pkg.root, waivers=self.w, fetch=lambda d, v: None)
        self.assertFalse(ok)
        self.assertTrue(any("stale waiver" in l for l in lines), "\n".join(lines))


class WaiverListMatchesTheRealRepo(unittest.TestCase):
    """The waiver list is data, and wrong data here is silent.

    A waiver keyed on a dist name no package declares excuses nothing and never
    expires, because the stale rule only fires for packages that were examined.
    It would read, forever, as an accounted-for exception.
    """

    def setUp(self):
        self.declared = {p["dist"]: p for p in cpc.discover_packages(REPO_ROOT)}

    def test_discovery_finds_the_repo_packages(self):
        self.assertTrue(self.declared, "no packages discovered in %s" % REPO_ROOT)

    def test_every_waiver_names_a_package_that_exists(self):
        for dist in cpc.WAIVED_COLLISIONS:
            self.assertIn(dist, self.declared,
                          "waiver for %r names no package in this repo" % dist)

    def test_every_waiver_pins_the_version_the_tree_declares(self):
        """A waiver pinned to a version the tree has moved off is dead weight:
        it can never match, so it can never be exercised and never expire."""
        for dist, waiver in cpc.WAIVED_COLLISIONS.items():
            if dist not in self.declared:
                continue
            self.assertEqual(
                waiver["version"], self.declared[dist]["version"],
                "waiver for %s pins %s but the tree declares %s — bump or delete it"
                % (dist, waiver["version"], self.declared[dist]["version"]))

    def test_every_waiver_names_a_ticket(self):
        for dist, waiver in cpc.WAIVED_COLLISIONS.items():
            self.assertRegex(waiver.get("ticket", ""), r"^RFX-\d+$",
                             "waiver for %s must name the ticket that owns it" % dist)
            self.assertTrue(waiver.get("why", "").strip(),
                            "waiver for %s must say why" % dist)


class TomlReading(unittest.TestCase):

    def test_only_the_project_table_answers(self):
        root = tempfile.mkdtemp(prefix="rfx300-toml-")
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "reeflex-demo", "reeflex_demo"))
        with open(os.path.join(root, "reeflex-demo", "pyproject.toml"), "w") as fh:
            fh.write('[project]\nname = "reeflex-demo"\nversion = "1.2.3"\n'
                     '[tool.poetry]\nversion = "9.9.9"\n')
        self.assertEqual(cpc.discover_packages(root)[0]["version"], "1.2.3")

    def test_a_directory_without_pyproject_is_not_discovered(self):
        """reeflex-core is the deliberate case: its artefact is the Docker
        image, not a wheel, so it has no pyproject and must not be reported."""
        self.assertNotIn("reeflex-core",
                         {p["dist"] for p in cpc.discover_packages(REPO_ROOT)})


class ComparisonMechanics(unittest.TestCase):

    def test_pycache_in_the_tree_is_not_a_collision(self):
        pkg = TempPackage(TREE)
        self.addCleanup(pkg.close)
        cache = os.path.join(pkg.root, "reeflex-demo", "reeflex_demo", "__pycache__")
        os.makedirs(cache)
        with open(os.path.join(cache, "x.cpython-39.pyc"), "wb") as fh:
            fh.write(b"\x00\x01")
        ok, lines = cpc.check(pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertTrue(ok, "\n".join(lines))

    def test_dist_info_is_out_of_scope(self):
        """Only the package directory is compared; the wheel's own metadata
        directory is not, and must not create a phantom difference."""
        pkg = TempPackage(TREE)
        self.addCleanup(pkg.close)
        ok, _ = cpc.check(pkg.root, waivers={},
                          fetch=lambda d, v: (_wheel("reeflex_demo", TREE), "t"))
        self.assertTrue(ok)

    def test_file_only_in_the_tree_is_a_collision(self):
        pkg = TempPackage(TREE)
        self.addCleanup(pkg.close)
        ok, lines = cpc.check(
            pkg.root, waivers={},
            fetch=lambda d, v: (_wheel("reeflex_demo", {"__init__.py": "VERSION = 1\n"}), "t"))
        self.assertFalse(ok)
        self.assertTrue(any("not in the published wheel" in l for l in lines))

    def test_file_only_in_the_wheel_is_a_collision(self):
        pkg = TempPackage(TREE)
        self.addCleanup(pkg.close)
        extra = dict(TREE, **{"extra.py": "x = 1\n"})
        ok, lines = cpc.check(pkg.root, waivers={},
                              fetch=lambda d, v: (_wheel("reeflex_demo", extra), "t"))
        self.assertFalse(ok)
        self.assertTrue(any("not in the tree" in l for l in lines))


if __name__ == "__main__":
    unittest.main()
