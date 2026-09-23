"""RFX-153 -- every corpus COUNT the module docstring states must be the count
the corpus actually has.

WHY THIS TEST EXISTS, AND WHY test_residual_docstring_rfx153.py DOES NOT COVER IT.

That test owns the `<command> -> <radius>` claim rows, and it deliberately
scopes itself to one docstring section, ending its regex at `^WHAT REMAINS\\.`.
Every corpus count in the same docstring lives at or after that line, so the
counts are outside it BY CONSTRUCTION -- not by oversight.

The counts have now gone stale twice in two days, both times in the docstring
of the function whose stale docstring is the whole subject of RFX-153:

  * `#213` as first pushed said the `default_protected := true` cost was
    measured "across the corpus' 73 everyday rows". Nothing in the repo's
    history ever equalled 73; qa--314 measured 96 and corrected it by hand.
  * Seven hours later `#219` (RFX-405) added 13 conformance rows -- 9 destroy,
    4 everyday. The corrected `252` and `96` became `265` and `100`, and the
    suite stayed green. dev-1--223 measured it, and arm D of
    `arm-the-rfx153-guard.py` shows the escape directly: rewriting
    `252-case corpus` to `99999-case corpus` leaves every test passing.

Correcting the number by hand is what does not scale. The corpus is a growing
artefact -- 82 -> 84 -> 252 -> 265 rows since 2026-08-22 -- so any denominator
written beside it is wrong by default and right only by accident.

WHAT THIS TEST DOES NOT COVER, DECLARED RATHER THAN LEFT QUIET.

It guards the DENOMINATORS only -- the corpus totals, which are pure data and
cost nothing to read. It does NOT guard the two NUMERATORS in the same prose:

    "emptying `protected_assets` turns 6 of the corpus' rows from ask to allow"
    "`default_protected := true` costs 5 false positives"

Both were re-measured true at 265 rows by dev-1--223 (`measure-corpus-postures.py`,
OPA 1.18 against reeflex-core's real pack, three postures, 0 opa errors). Pinning
them here would need OPA and the core policy pack inside this suite, which it does
not have. They remain unguarded and the prose beside them says so.
"""

import json
import pathlib
import re
import unittest

from reeflex_claude import classify as classify_mod

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _REPO_ROOT / "reeflex-spec" / "conformance" / "claude-adapter-bash.json"

# Every shape in which the docstring states a corpus TOTAL.
_TOTAL_PATTERNS = (
    r"(\d+)-case corpus",           # "no everyday row in the 265-case corpus"
    r"corpus'\s+(\d+)\s+rows",      # "6 of the corpus' 265 rows"
)
# ...and the one shape in which it states the EVERYDAY subtotal.
_EVERYDAY_PATTERN = r"corpus'\s+(\d+)\s+everyday\s+rows"
# ...and the growth history, whose LAST element is a claim about today.
_HISTORY_PATTERN = r"corpus has gone\s+((?:\d+\s*->\s*)*\d+)\s+rows"


class DocstringCorpusCountsMatchTheCorpus(unittest.TestCase):
    """The counts are read from the docstring, never pinned as literals here.

    Pinning `265` in this file would make it one more unchecked mirror of the
    claim -- the exact failure mode RFX-153 is about. The invariant is
    "what the prose says == what the corpus is", so this test stays correct
    when the corpus grows and the prose is updated with it.
    """

    @classmethod
    def setUpClass(cls):
        cls.doc = classify_mod.__doc__ or ""
        cases = json.loads(_CORPUS.read_text(encoding="utf-8"))["cases"]
        cls.total = len(cases)
        cls.everyday = sum(1 for c in cases if c.get("family") == "everyday")

    def test_every_stated_corpus_total_is_the_corpus_total(self):
        found = []
        for pattern in _TOTAL_PATTERNS:
            for stated in re.findall(pattern, self.doc, re.DOTALL):
                found.append((pattern, int(stated)))
        # VACUITY GUARD: a reflow that breaks these patterns must fail loudly
        # rather than quietly leave this test asserting over an empty list.
        self.assertTrue(
            found,
            "no corpus total found in the classify.py module docstring -- either "
            "the prose was reworded or this test's patterns rotted. Either way "
            "this test is no longer reading anything; fix it rather than delete it.",
        )
        wrong = [f"{pattern!r} states {stated}, corpus has {self.total}"
                 for pattern, stated in found if stated != self.total]
        self.assertEqual([], wrong, "\n".join(wrong))

    def test_the_stated_everyday_subtotal_is_the_everyday_subtotal(self):
        stated = re.findall(_EVERYDAY_PATTERN, self.doc, re.DOTALL)
        self.assertTrue(
            stated,
            "no everyday-row count found in the classify.py module docstring -- "
            "see the vacuity note above.",
        )
        wrong = [f"docstring states {s} everyday rows, corpus has {self.everyday}"
                 for s in stated if int(s) != self.everyday]
        self.assertEqual([], wrong, "\n".join(wrong))

    def test_the_growth_history_ends_at_todays_row_count(self):
        """`82 -> 84 -> 252 rows` is a claim about today in its last element."""
        histories = re.findall(_HISTORY_PATTERN, self.doc, re.DOTALL)
        self.assertTrue(
            histories,
            "no corpus growth history found in the classify.py module docstring -- "
            "see the vacuity note above.",
        )
        wrong = []
        for h in histories:
            last = int(re.findall(r"\d+", h)[-1])
            if last != self.total:
                wrong.append(f"history {h!r} ends at {last}, corpus has {self.total}")
        self.assertEqual([], wrong, "\n".join(wrong))


if __name__ == "__main__":
    unittest.main()
