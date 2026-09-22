"""RFX-153 -- the blast_radius the module docstring claims for each command it
names must be the one classify() actually emits for that command.

WHY THIS TEST EXISTS, AND WHY THE EXISTING SUITES DID NOT CATCH IT.

test_classify_rfx144_ported.py already pins the BEHAVIOUR: it asserts the
data-container raise prices `/srv/prod/db.sqlite` as `broad`.  That guard was
green for the fifteen days in which classify.py carried TWO blocks of prose
saying the opposite -- a module-docstring section headed "KNOWN RESIDUAL AFTER
RFX-144 (tracked as RFX-153)" listing those same four commands as priced
`single` and therefore allowed in production, and a `_radius_for_paths`
docstring repeating it seventeen lines above the branch that does the raise.

The raise landed in 568ce2c (2026-09-07), a commit whose own subject names
RFX-153.  The prose was last touched in 68911f3 (2026-08-22) and shipped
unchanged in the published reeflex-claude 0.2.0 and 0.2.1 wheels, where it is
the answer a reader gets when they ask what a single-file production
destruction is priced as.  RFX-153's Jira description quotes it as the
adapter's stated rationale for the ticket being open.

So the sentence is not decoration: it is the artefact a reader consults, and it
said the pre-fix value while the code beside it said the fixed one.

This test states the INVARIANT rather than a constant.  It does not pin
"broad"; it reads whatever commands the docstring lists, reads whatever radius
the docstring claims beside each, and asserts classify() agrees.  Pinning the
literal here would be one more unchecked mirror of the same claim.
"""

import re
import unittest

from reeflex_claude import classify as classify_mod
from reeflex_claude.classify import classify

# The docstring section this test owns, delimited by its own heading so that
# reflowing or adding unrelated `->` tables elsewhere in the ~20 KB module
# docstring cannot silently attach rows to it or detach rows from it.
_SECTION_RE = re.compile(
    r"^WHAT RFX-153 STILL TRACKS, AND WHAT IT NO LONGER DOES$"
    r"(.*?)"
    r"^WHAT REMAINS\.",
    re.MULTILINE | re.DOTALL,
)

# One claim row: four-space indent, the command, `->`, the radius claimed.
_CLAIM_RE = re.compile(r"^ {4}(\S.*?)\s+->\s+([a-z_]+)\s*$", re.MULTILINE)

# The sentences that argued for the pre-fix reading. Kept as separate checks
# from the table above because they failed independently: correcting the table
# and leaving the argument standing would leave the reader with the same wrong
# answer in prose.
_PRE_FIX_MODULE_SENTENCE = "the adapter cannot\nclose it without lying"
_PRE_FIX_FUNCTION_SENTENCE = "is priced `single` here and therefore cannot reach"


class ResidualDocstringMatchesBehaviour(unittest.TestCase):
    def _claims(self):
        doc = classify_mod.__doc__ or ""
        section = _SECTION_RE.search(doc)
        self.assertIsNotNone(
            section,
            "classify.py's module docstring no longer carries the RFX-153 "
            "section this test scores. If the section was renamed, rename the "
            "anchor here -- do not delete the check: the claim it guards is "
            "what shipped wrong in two published wheels.")
        claims = _CLAIM_RE.findall(section.group(1))
        self.assertTrue(
            claims,
            "the RFX-153 docstring section names no `<command> -> <radius>` "
            "rows, so nothing in it is checked against the classifier")
        return claims

    def test_every_radius_the_docstring_claims_is_the_one_classify_emits(self):
        for command, declared in self._claims():
            with self.subTest(command=command):
                emitted = classify("Bash", {"command": command})["blast_radius"]
                self.assertEqual(
                    declared, emitted,
                    "classify.py's module docstring says %r is priced "
                    "blast_radius=%r; classify() emits %r. RFX-153: these "
                    "disagreed for fifteen days and in two published wheels. "
                    "Update the docstring row, not this test."
                    % (command, declared, emitted))

    def test_the_commands_the_docstring_names_are_the_ones_the_ticket_names(self):
        """The section must still speak about RFX-153's own four commands.

        Without this, a later edit could satisfy the check above by deleting
        every row it could not justify -- a green test over an empty claim.
        """
        commands = [c for c, _ in self._claims()]
        self.assertEqual(
            len(commands), 4,
            "expected the four commands RFX-153's summary names, found %d: %r"
            % (len(commands), commands))
        for fragment in ("rm ", "> ", "truncate -s 0 ", "dd "):
            self.assertTrue(
                any(c.startswith(fragment) for c in commands),
                "no row in the RFX-153 section names the %r form; the ticket's "
                "summary names all four and the section is what a reader "
                "consults" % fragment.strip())

    def test_the_pre_fix_rationale_sentences_are_gone(self):
        module_doc = classify_mod.__doc__ or ""
        function_doc = classify_mod._radius_for_paths.__doc__ or ""
        # assertNotIn would print the whole ~20 KB docstring into the CI log on
        # failure; assertFalse on the membership test says the same in one line.
        self.assertFalse(
            _PRE_FIX_MODULE_SENTENCE in module_doc,
            "classify.py's module docstring has regained the sentence arguing "
            "the adapter cannot close RFX-153's four commands -- it closed "
            "them in 568ce2c and the test above measures that it did")
        self.assertFalse(
            _PRE_FIX_FUNCTION_SENTENCE in function_doc,
            "_radius_for_paths' docstring has regained the claim that a single "
            "production file is priced `single` there; the data-container "
            "raise in the same function's body returns `broad` for it")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
