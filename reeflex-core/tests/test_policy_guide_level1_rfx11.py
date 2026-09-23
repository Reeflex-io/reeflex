"""LEVEL 1 of the policy guide must name things the shipped pack actually has
(RFX-11).

WHY THIS FILE EXISTS. RFX-11 generalised R5: the delete budget stopped being a
bare `delete_session_budget := 20` constant in `reeflex.rego` and became the
`default_budgets` table in `budgets.rego`. RFX-11's own landing note flagged
that `docs/policy-guide.md` still taught the old name and recommended a
follow-up ticket; no such ticket was ever filed, and for 33 days LEVEL 1 - the
first thing a policy author reads, and the section RFX-11's closing criterion
("the budget policy written by a user, not hardcoded") rests on - opened with

    The constant you'll change lives in `my-policy/reeflex.rego`:
    delete_session_budget := 20

against a pack where that identifier exists in no file at all. The mechanism
was correct the whole time; the only route a user had to it was not. Nothing
failed, because no test has ever read an instruction.

WHAT IT ASSERTS, and deliberately nothing more:

  1. Every `my-policy/<f>.rego` LEVEL 1 tells the reader to open corresponds to
     a file that exists in the shipped `reeflex-core/policy/`.
  2. The rego fence LEVEL 1 presents as "the threshold you'll change" is
     present VERBATIM in the pack file the same sentence names. This is the
     assertion that was false for 33 days.
  3. Every `reeflex.policy/*` id LEVEL 1 mentions is an id the pack emits.
  4. The identifier LEVEL 1's note calls gone - `delete_session_budget` - is
     in fact absent from the pack, so the note cannot quietly become a lie if
     someone reintroduces the constant.

WHAT IT DOES NOT ASSERT, so nobody reads more into a green run. It does not
check the arithmetic, the test COUNTS or the `opa test` transcripts quoted in
the section: those are a dated snapshot and the section says so. It does not
run OPA. It reads only the LEVEL 1 section, so drift in LEVEL 2/3 (owned by
RFX-255) is invisible to it by design. And it asserts that the instructions
point at something real, not that following them produces any particular
verdict - the end-to-end proof of that is `test_budgets_rfx11.py`.
"""

from __future__ import annotations

import pathlib
import re
import unittest

# reeflex-core/tests/<this file> -> repo root is two parents up.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "reeflex-core" / "policy"
GUIDE = REPO_ROOT / "docs" / "policy-guide.md"

# Anchored on the heading so that renaming or moving the section fails loudly
# here rather than silently emptying the fixture.
_LEVEL1_START = re.compile(r"^## 2\. LEVEL 1\b", re.M)
_NEXT_SECTION = re.compile(r"^## 2b\.", re.M)

# "The threshold you'll change lives in `my-policy/budgets.rego`" -> the file,
# and the fence that follows it is what the reader is told to go and edit.
_THRESHOLD_SENTENCE = re.compile(
    r"threshold you'll change lives in `my-policy/(?P<file>[A-Za-z0-9_.-]+\.rego)`"
)
_MY_POLICY_FILE = re.compile(r"`my-policy/(?P<file>[A-Za-z0-9_.-]+\.rego)`")
_REGO_FENCE = re.compile(r"```rego\n(?P<body>.*?)```", re.S)
_RULE_ID = re.compile(r"reeflex\.policy/[a-z0-9_]+")

# The name RFX-11 retired. LEVEL 1's note states it is gone from the pack;
# assertion 4 keeps that statement honest in both directions.
_RETIRED_IDENTIFIER = "delete_session_budget"


def _level1_section() -> str:
    text = GUIDE.read_text(encoding="utf-8")
    start = _LEVEL1_START.search(text)
    assert start, f"LEVEL 1 heading not found in {GUIDE} - fixture is empty"
    rest = text[start.end():]
    end = _NEXT_SECTION.search(rest)
    assert end, "section 2b heading not found - LEVEL 1's end is unbounded"
    return rest[: end.start()]


def _pack_text() -> str:
    parts = [p.read_text(encoding="utf-8") for p in sorted(POLICY_DIR.glob("*.rego"))]
    assert parts, f"no .rego files under {POLICY_DIR} - fixture is empty"
    return "\n".join(parts)


def _emitted_rule_ids() -> set[str]:
    """Rule ids the shipped pack actually produces, read from the non-test
    modules only - a `_test.rego` may name an id it merely asserts on."""
    ids: set[str] = set()
    for p in sorted(POLICY_DIR.glob("*.rego")):
        if p.name.endswith("_test.rego"):
            continue
        ids |= set(_RULE_ID.findall(p.read_text(encoding="utf-8")))
    return ids


class TestLevel1PointsAtTheShippedPack(unittest.TestCase):

    def setUp(self) -> None:
        self.section = _level1_section()
        # Anti-vacuity: every assertion below is a search over this string, so
        # a section that silently shrank to nothing would pass all of them.
        self.assertGreater(
            len(self.section), 2000,
            "LEVEL 1 section is implausibly short - the anchors probably stopped matching",
        )

    def test_every_file_level1_names_exists_in_the_pack(self) -> None:
        named = sorted({m.group("file") for m in _MY_POLICY_FILE.finditer(self.section)})
        self.assertTrue(named, "LEVEL 1 names no `my-policy/*.rego` file at all")
        missing = [f for f in named if not (POLICY_DIR / f).is_file()]
        self.assertEqual(
            [], missing,
            f"LEVEL 1 sends the reader to {missing}, which the shipped pack does not contain; "
            f"pack has {sorted(p.name for p in POLICY_DIR.glob('*.rego'))}",
        )

    def test_the_threshold_it_tells_you_to_edit_is_in_the_file_it_names(self) -> None:
        """Assertion 2 - the one that was false for 33 days.

        Before this fix the sentence named `reeflex.rego` and the fence under it
        read `delete_session_budget := 20`, which was in no file in the pack.
        """
        m = _THRESHOLD_SENTENCE.search(self.section)
        self.assertIsNotNone(
            m, "LEVEL 1 no longer says where the threshold lives - reword the regex or the doc"
        )
        target = POLICY_DIR / m.group("file")
        self.assertTrue(target.is_file(), f"LEVEL 1 names {target.name}, which is not in the pack")

        fence = _REGO_FENCE.search(self.section[m.end():])
        self.assertIsNotNone(fence, "no ```rego fence follows the 'threshold lives in' sentence")
        lines = [
            ln.strip() for ln in fence.group("body").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        self.assertTrue(lines, "the threshold fence has no code in it - fixture is empty")

        haystack = target.read_text(encoding="utf-8")
        for ln in lines:
            self.assertIn(
                ln, haystack,
                f"LEVEL 1 tells the reader to edit `{ln}` in {target.name}, "
                f"and that line is not in {target.name}",
            )

    def test_every_rule_id_level1_mentions_is_one_the_pack_emits(self) -> None:
        mentioned = set(_RULE_ID.findall(self.section))
        self.assertTrue(mentioned, "LEVEL 1 mentions no rule id at all")
        emitted = _emitted_rule_ids()
        self.assertTrue(emitted, "read no rule ids out of the pack - fixture is empty")
        self.assertEqual(
            set(), mentioned - emitted,
            f"LEVEL 1 names rule ids the pack does not emit: {sorted(mentioned - emitted)}",
        )

    def test_the_identifier_level1_calls_retired_really_is_absent(self) -> None:
        """LEVEL 1 states `delete_session_budget` is in no pack file. If someone
        reintroduces it, that sentence becomes false and this goes red."""
        self.assertIn(
            _RETIRED_IDENTIFIER, self.section,
            "LEVEL 1 no longer mentions the retired identifier - if the note was "
            "removed deliberately, remove this assertion with it",
        )
        self.assertNotIn(
            _RETIRED_IDENTIFIER, _pack_text(),
            f"LEVEL 1 tells the reader `{_RETIRED_IDENTIFIER}` is gone from the pack, "
            f"but it is back in {POLICY_DIR}",
        )


if __name__ == "__main__":
    unittest.main()
