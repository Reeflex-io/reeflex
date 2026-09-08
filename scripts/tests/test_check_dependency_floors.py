"""Unit tests for scripts/check_dependency_floors.py (the PR #123 sweep).

The script carries its own `--selftest` (53 properties), which is what
`gate.yml` and the `dep-floors-selftest` gate component run. This file is the
*second* pair of eyes on the properties that would matter most if the checker
were quietly wrong, expressed as unittest TestCases so they also run under
`unittest discover -s scripts/tests -t scripts` — the runner `gate.py` actually
uses for this root, and the mismatch that let PR #89's regression guard collect
zero tests for its whole life (RFX-87).

The one property everything else rests on: THE CHECKER MUST FAIL ON THE TREE AS
IT WAS BEFORE THIS SWEEP. A floor check that has never been observed to refuse
anything is not evidence about the tree.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_dependency_floors as cdf  # noqa: E402


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class PythonSpecifierTests(unittest.TestCase):
    def test_the_exact_123_defect_is_unbounded(self):
        # reeflex-holds/pyproject.toml said this, and mcp 2.1.1 arrived.
        name, spec = cdf.parse_py_requirement("mcp>=2")
        self.assertEqual(name, "mcp")
        self.assertFalse(cdf.py_requirement_is_bounded(spec))

    def test_the_exact_123_fix_is_bounded(self):
        _, spec = cdf.parse_py_requirement("mcp>=2,<2.2")
        self.assertTrue(cdf.py_requirement_is_bounded(spec))

    def test_a_bare_name_is_unbounded(self):
        # reeflex-mcp shipped `pyyaml` — no floor and no ceiling — and
        # reeflex-mcp 0.1.3 on PyPI still declares exactly that.
        name, spec = cdf.parse_py_requirement("pyyaml")
        self.assertEqual(name, "pyyaml")
        self.assertEqual(spec, "")
        self.assertFalse(cdf.py_requirement_is_bounded(spec))

    def test_not_equal_does_not_bound(self):
        # `!=` excludes one point release. It is not a ceiling, and reading it
        # as one is the plausible way this checker could have been wrong.
        _, spec = cdf.parse_py_requirement("urllib3>=1,!=2.0.1")
        self.assertFalse(cdf.py_requirement_is_bounded(spec))

    def test_compatible_release_bounds(self):
        self.assertTrue(cdf.py_requirement_is_bounded("~=6.0"))

    def test_ceiling_without_floor_is_still_a_ceiling(self):
        # reeflex-holds/mcpb/constraints.txt is exactly this shape.
        _, spec = cdf.parse_py_requirement("mcp<2")
        self.assertTrue(cdf.py_requirement_is_bounded(spec))

    def test_extras_and_markers_do_not_hide_the_specifier(self):
        name, spec = cdf.parse_py_requirement(
            'mkdocs-material[imaging]>=9.5,<10 ; python_version >= "3.9"')
        self.assertEqual(name, "mkdocs-material")
        self.assertTrue(cdf.py_requirement_is_bounded(spec))


class NpmRangeTests(unittest.TestCase):
    def test_star_is_unbounded(self):
        # n8n-nodes-reeflex declared `n8n-workflow: "*"`, and all three
        # PUBLISHED versions on npm still do.
        self.assertFalse(cdf.npm_range_is_bounded("*"))

    def test_the_replacement_range_is_bounded(self):
        self.assertTrue(cdf.npm_range_is_bounded(">=1.83 <3"))

    def test_caret_and_tilde_are_bounded(self):
        self.assertTrue(cdf.npm_range_is_bounded("^9.39.4"))
        self.assertTrue(cdf.npm_range_is_bounded("~3.8.3"))

    def test_open_floor_is_unbounded(self):
        self.assertFalse(cdf.npm_range_is_bounded(">=20.15"))

    def test_a_union_is_as_loose_as_its_loosest_branch(self):
        self.assertTrue(cdf.npm_range_is_bounded("^1 || ^2"))
        self.assertFalse(cdf.npm_range_is_bounded("^1 || *"))


class ExtractionTests(unittest.TestCase):
    def test_a_dependency_only_in_a_comment_is_not_collected(self):
        # The way a line-based reader over-collects, which would produce a
        # finding against a file that declares nothing of the kind.
        text = ('[project]\n'
                '# mcp>=2 used to be here\n'
                'dependencies = ["mcp>=2,<2.2"]\n')
        got = [s for _, s in cdf.extract_pyproject_requirements(text, "fx")]
        self.assertEqual(got, ["mcp>=2,<2.2"])

    def test_a_hash_inside_a_string_is_not_a_comment(self):
        self.assertEqual(cdf.strip_toml_comment('a = "x#y"'), 'a = "x#y"')

    def test_tool_tables_are_not_read_as_dependencies(self):
        text = ('[project]\n'
                'dependencies = ["mcp>=2,<2.2"]\n'
                '[tool.setuptools.packages.find]\n'
                'include = ["reeflex_mcp*"]\n')
        got = [s for _, s in cdf.extract_pyproject_requirements(text, "fx")]
        self.assertEqual(got, ["mcp>=2,<2.2"])

    def test_an_unreadable_shape_raises_instead_of_returning_empty(self):
        # An instrument that cannot read a manifest must not report PASS over
        # it. Returning [] here is how a checker goes green on a file it never
        # understood.
        with self.assertRaises(cdf.Unreadable):
            cdf.extract_pyproject_requirements(
                '[tool.poetry.dependencies]\npython = "^3.10"\n', "fx")

    def test_the_anchored_extractor_agrees_with_tomllib_on_every_real_manifest(self):
        # The real guarantee, on the real files, when the stdlib parser exists.
        if cdf.extract_pyproject_requirements_tomllib('[project]\n', "fx") is None:
            self.skipTest("no tomllib/tomli on this interpreter (%s)"
                          % ".".join(str(x) for x in sys.version_info[:3]))
        checked = 0
        for rel, full in cdf.iter_manifests(REPO_ROOT):
            if os.path.basename(rel) != cdf.PYPROJECT:
                continue
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
            mine = cdf.extract_pyproject_requirements(text, rel)
            theirs = cdf.extract_pyproject_requirements_tomllib(text, rel)
            self.assertEqual(sorted(mine), sorted(theirs), rel)
            checked += 1
        self.assertGreaterEqual(checked, 3, "expected at least 3 pyproject.toml files")


class AllowanceTests(unittest.TestCase):
    def test_todays_allowances_are_traceable_and_live(self):
        # Every allowance must (a) cite a ticket/PR and (b) still name a
        # requirement that exists in THIS tree — checked against the real walk,
        # not against the allowance table talking to itself.
        seen = set()
        for rel, full in cdf.iter_manifests(REPO_ROOT):
            try:
                for section, name, _spec, _eco in cdf.requirements_in(rel, full):
                    seen.add((rel, section, name))
            except cdf.Unreadable as exc:
                self.fail("unreadable manifest in the real tree: %s" % exc)
        ok, lines = cdf.check_allowances(seen)
        self.assertTrue(ok, "\n".join(lines))

    def test_an_allowance_with_no_ticket_is_refused(self):
        ok, _ = cdf.check_allowances(
            {("a/package.json", "engines", "node")},
            allowed={("a/package.json", "engines", "node"): "because I said so"})
        self.assertFalse(ok)

    def test_a_stale_allowance_is_refused(self):
        ok, _ = cdf.check_allowances(
            set(), allowed={("gone/package.json", "engines", "node"): "fine (RFX-1)"})
        self.assertFalse(ok)


class EndToEndTests(unittest.TestCase):
    def _tree(self, files):
        td = tempfile.mkdtemp(prefix="dep-floors-test-")
        self.addCleanup(__import__("shutil").rmtree, td, True)
        for rel, content in files.items():
            full = os.path.join(td, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(content)
        return td

    def test_the_pre_sweep_tree_FAILS(self):
        # THE control. These are the six requirements this repo actually
        # declared on main 373a5ec, verbatim. If the checker cannot refuse
        # THIS, its PASS on the fixed tree means nothing.
        pinned = ", ".join('"dep%d>=1,<2"' % i for i in range(cdf.MIN_REQUIREMENTS))
        td = self._tree({
            "reeflex-mcp/pyproject.toml":
                '[build-system]\nrequires = ["setuptools>=68"]\n'
                '[project]\ndependencies = ["mcp>=1.2,<2", "pyyaml", "anyio>=4.5"]\n',
            "reeflex-holds/pyproject.toml":
                '[build-system]\nrequires = ["setuptools>=68"]\n'
                '[project]\ndependencies = ["mcp>=2,<2.2"]\n',
            "reeflex-claude/pyproject.toml":
                '[build-system]\nrequires = ["setuptools>=68.0"]\n'
                '[project]\ndependencies = [%s]\n' % pinned,
            "n8n-nodes-reeflex/package.json":
                json.dumps({"peerDependencies": {"n8n-workflow": "*"}}),
        })
        ok, lines, verdict = cdf.run(td, allowed={})
        self.assertFalse(ok, verdict)
        blob = "\n".join(lines)
        for needle in ("setuptools >=68", "pyyaml", "anyio >=4.5", "n8n-workflow *"):
            self.assertIn(needle, blob, needle)
        self.assertIn("6 unbounded", verdict)

    def test_the_post_sweep_shape_PASSES(self):
        pinned = ", ".join('"dep%d>=1,<2"' % i for i in range(cdf.MIN_REQUIREMENTS))
        td = self._tree({
            "reeflex-mcp/pyproject.toml":
                '[build-system]\nrequires = ["setuptools>=68,<85"]\n'
                '[project]\ndependencies = ["mcp>=1.2,<2", "pyyaml>=6,<7", '
                '"anyio>=4.5,<5", %s]\n' % pinned,
            "n8n-nodes-reeflex/package.json":
                json.dumps({"peerDependencies": {"n8n-workflow": ">=1.83 <3"}}),
        })
        ok, lines, verdict = cdf.run(td, allowed={})
        self.assertTrue(ok, verdict + "\n" + "\n".join(lines))
        self.assertIn("; 0 unbounded;", verdict)

    def test_an_empty_walk_cannot_pass(self):
        # RFX-217's lesson, applied here: "nothing unbounded was found" is a
        # claim an empty walk satisfies.
        ok, lines, verdict = cdf.run(self._tree({}), allowed={})
        self.assertFalse(ok)
        self.assertIn("WALK FLOOR", "\n".join(lines))

    def test_installed_and_scratch_trees_are_not_our_declarations(self):
        td = self._tree({
            "node_modules/left-pad/package.json":
                json.dumps({"dependencies": {"anything": "*"}}),
            ".scratch-dev1-099/pyproject.toml":
                '[project]\ndependencies = ["mcp>=2"]\n',
        })
        ok, lines, verdict = cdf.run(td, allowed={})
        self.assertIn("over 0 manifests", verdict)

    def test_the_real_repo_root_is_clean_and_non_empty(self):
        # The claim this whole change makes about THIS tree, measured on it,
        # with the real ALLOWED table.
        ok, lines, verdict = cdf.run(REPO_ROOT)
        self.assertTrue(ok, verdict + "\n" + "\n".join(lines))
        self.assertIn("; 0 unbounded;", verdict)
        self.assertNotIn("over 0 manifests", verdict)


if __name__ == "__main__":
    unittest.main()
