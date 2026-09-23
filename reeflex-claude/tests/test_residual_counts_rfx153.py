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

Nor does it read a total stated in a unit these patterns do not carry -- "265
conformance entries", "265 cases". Four totals are stated today and all four are
read; a fifth in a new unit would not be, and the vacuity guard cannot see that
because the other four still match. See the _TOTAL_PATTERNS comment for the one
direction in which this test is deliberately over-wide.
"""

import json
import pathlib
import re
import unittest

from reeflex_claude import classify as classify_mod

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _REPO_ROOT / "reeflex-spec" / "conformance" / "claude-adapter-bash.json"

# Every shape in which the docstring states a corpus TOTAL.
#
# THESE ARE DISCOVERING, NOT AN ENUMERATION, AND THAT IS THE POINT (dev-3--172).
# As first pushed these read `(\d+)-case corpus` and `corpus'\s+(\d+)\s+rows` --
# an allowlist of the two phrasings that happened to exist. The same commit that
# added them also added a THIRD statement of the total, in a shape neither one
# reads:
#
#     "...measurements dated to this commit (dev-1--225, re-measured at 265 rows)"
#
# Measured on the shipped tree: rewriting that 265 to 999 left all 763 tests
# green. A guard against a stale denominator that is itself keyed to the exact
# words beside the denominator has the defect it was written to catch, so these
# patterns now anchor on the UNIT (`rows`, `-case`) and not on the sentence.
#
# THE TRADE, DECLARED: this is deliberately over-wide in one direction. Any
# `<N> rows` anywhere in this docstring is now asserted to be the corpus total,
# so a future sentence stating some OTHER row count in that exact shape fails
# this test. That failure is loud and self-describing (see the message below)
# and is the direction we want to fail in. Censused at this commit: `<N> rows`
# matches 3 times and `<N>-case` once, all four the corpus total, no false
# positive -- and `<N> everyday rows` does not collide, because `everyday` sits
# between the number and `rows`.
#
# STILL NOT READ, so it is a limit and not a claim of coverage: a total written
# in a third unit -- "265 conformance entries", "265 cases" -- is invisible to
# both patterns. The vacuity guard does not catch that either, because the other
# statements still match. Add the unit here if the prose grows one.
_TOTAL_PATTERNS = (
    r"(\d+)-case",      # "no everyday row in the 265-case corpus"
    r"(\d+)\s+rows",    # "the corpus' 265 rows", "...re-measured at 265 rows"
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
            for match in re.finditer(pattern, self.doc, re.DOTALL):
                # Quote the sentence, not just the number: with discovering
                # patterns the reader's first question is always WHICH sentence.
                start = max(0, match.start() - 60)
                snippet = " ".join(self.doc[start:match.end() + 20].split())
                found.append((int(match.group(1)), snippet))
        # VACUITY GUARD: a reflow that breaks these patterns must fail loudly
        # rather than quietly leave this test asserting over an empty list.
        self.assertTrue(
            found,
            "no corpus total found in the classify.py module docstring -- either "
            "the prose was reworded or this test's patterns rotted. Either way "
            "this test is no longer reading anything; fix it rather than delete it.",
        )
        wrong = [f"states {stated}, corpus has {self.total}:  ...{snippet}..."
                 for stated, snippet in found if stated != self.total]
        self.assertEqual(
            [], wrong,
            "\n".join(wrong) + (
                "\n\nEvery `<N> rows` and `<N>-case` in the classify.py module "
                "docstring is read as a claim about the corpus total. If one of "
                "these is a stale denominator, correct it. If it was never meant "
                "to BE the total, phrase it so it does not read as one -- do not "
                "narrow these patterns back to the sentences that exist today, "
                "which is the hole dev-3--172 measured."
            ),
        )

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
