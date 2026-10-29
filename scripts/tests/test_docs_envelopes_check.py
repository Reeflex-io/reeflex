"""docs_envelopes_check.py: the parser and the exit code, without core.

The check's verdicts come from reeflex-core's own decision path and need opa;
these tests do not. They pin the two ways the instrument could lie without a
single wrong verdict: a marker it fails to parse (the block silently leaves
the check), and a PENDING-CORE block that reads as green.
"""
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import docs_envelopes_check as dec  # noqa: E402

ENV = """{
  "agent": {"id": "a", "session_id": "s"},
  "action": {"verb": "delete"},
  "target": {"environment": "production"},
  "axes": {"reversibility": "irreversible", "blast_radius": "broad", "externality": "internal"}
}"""

PAGE = (
    "# Page\n\n"
    "**Verdict:** `require_approval` · **rule** `reeflex.policy/irreversible_broad_prod`\n\n"
    "```json\n" + ENV + "\n```\n\n"
    "**Verdict:** `require_approval` · **rule** `reeflex.policy/cumulative_budget`"
    " · **call** 11 · **reason contains** `physical_writes` — steps 1–10 allowed.\n\n"
    "```json\n" + ENV.replace('"internal"', '"physical"') + "\n```\n"
)


def _row(decision, rule, reason="r", call=1):
    return {"call": call, "status": 200, "decision": decision, "rule": rule, "reason": reason}


class Parse(unittest.TestCase):
    def _extract(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "p.md"
            p.write_text(text)
            return dec.extract(p)

    def test_both_markers_parse_with_call_and_reason(self):
        blocks, problems = self._extract(PAGE)
        self.assertEqual(problems, [])
        self.assertEqual([b["call"] for b in blocks], [1, 11])
        self.assertEqual(blocks[1]["reason"], "physical_writes")
        self.assertEqual(blocks[0]["rule"], "reeflex.policy/irreversible_broad_prod")

    def test_a_marker_that_does_not_parse_is_a_problem_not_a_skip(self):
        blocks, problems = self._extract(PAGE.replace("`require_approval` ·", "require_approval ·", 1))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("unparseable verdict marker", problems[0])

    def test_a_marker_with_no_json_block_is_a_problem(self):
        _, problems = self._extract("**Verdict:** `allow` · **rule** `x`\n\n## Next\n")
        self.assertIn("no ```json block", problems[0])

    def test_invalid_json_is_a_problem(self):
        _, problems = self._extract("**Verdict:** `allow` · **rule** `x`\n\n```json\n{,}\n```\n")
        self.assertIn("not valid JSON", problems[0])

    def test_physical_detection(self):
        self.assertFalse(dec.needs_physical_core({"axes": {"externality": "outbound"}}))
        self.assertTrue(dec.needs_physical_core({"axes": {"externality": "physical"}}))
        self.assertTrue(dec.needs_physical_core({"action": {"verb": "override"}}))
        self.assertTrue(dec.needs_physical_core({"target": {"safety_function": False}}))
        self.assertTrue(dec.needs_physical_core({"magnitude": {"physical": {}}}))


class ExitCode(unittest.TestCase):
    """main() is run on a real page with core replaced by a stub."""

    def _main(self, page, rows_for, physical):
        repo = pathlib.Path(dec.REPO)
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "p.md").write_text(page)
            with mock.patch.object(dec, "decide", side_effect=rows_for), \
                 mock.patch.object(dec, "core_has_physical", return_value=physical):
                return dec.main(["--core-tree", str(repo), "--pages", os.path.join(d, "*.md")])

    @staticmethod
    def _rows(core_tree, env, calls, python, opa):
        last = (_row("require_approval", "reeflex.policy/cumulative_budget", "cumulative physical_writes budget")
                if env["axes"]["externality"] == "physical"
                else _row("require_approval", "reeflex.policy/irreversible_broad_prod"))
        return [_row("allow", "reeflex.policy/default_allow")] * (calls - 1) + [last]

    def test_everything_matches_is_0(self):
        self.assertEqual(self._main(PAGE, self._rows, physical=True), 0)

    def test_pending_core_is_3_not_0(self):
        self.assertEqual(self._main(PAGE, self._rows, physical=False), 3)

    def test_a_mismatch_is_1_even_with_pending_blocks(self):
        bad = PAGE.replace("irreversible_broad_prod`", "default_allow`", 1)
        self.assertEqual(self._main(bad, self._rows, physical=False), 1)

    def test_an_earlier_call_that_was_not_allowed_is_1(self):
        def rows(core_tree, env, calls, python, opa):
            r = self._rows(core_tree, env, calls, python, opa)
            if calls > 1:
                r[3] = _row("require_approval", "reeflex.policy/cumulative_budget")
            return r
        self.assertEqual(self._main(PAGE, rows, physical=True), 1)

    def test_the_instrument_failing_is_1(self):
        def boom(*a):
            raise RuntimeError("core child failed")
        self.assertEqual(self._main(PAGE, boom, physical=True), 1)

    def test_no_markers_is_2(self):
        self.assertEqual(self._main("# nothing here\n", self._rows, physical=True), 2)


if __name__ == "__main__":
    unittest.main()
