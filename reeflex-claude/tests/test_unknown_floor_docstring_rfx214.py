"""RFX-214 -- the module docstring's unknown-tool externality must be the value
classify() actually emits.

WHY THIS TEST EXISTS, AND WHY IT IS NOT REDUNDANT WITH test_classify.py.

test_classify.py already pins the BEHAVIOUR: it reads the member R5's
external_sends budget charges out of reeflex-core/policy/budgets.rego and
asserts the unknown-tool fallback declares that member.  That guard was green
for the whole fifteen days in which classify.py's own "AXIS MAPPING RATIONALE"
block told the reader the opposite -- `unknown externality -> internal`, plus a
paragraph arguing for it.  The stale prose shipped: it is in the published
reeflex-claude 0.2.0 (2026-09-16) and 0.2.1 (2026-09-20) wheels.

RFX-214's own description quotes that paragraph as the adapter's stated
rationale.  So the docstring is not decoration here -- it is the artefact a
reader consults to learn what an unidentifiable tool is priced as, and it said
the pre-fix value.  A guard that scores the code and not the sentence beside it
leaves the reader with a wrong answer and no red test anywhere.

This test states the invariant rather than a constant: whatever classify()
emits for a tool it cannot identify, that is what the docstring line must say.
Pinning "outbound" as a literal in this file would be one more unchecked mirror.
"""

import re
import unittest

from reeflex_claude import classify as classify_mod
from reeflex_claude.classify import classify

# The docstring line this test owns. Anchored on "unknown externality" followed
# by an arrow, so reflowing the surrounding table cannot silently detach it.
_DOCSTRING_LINE_RE = re.compile(r"^\s*unknown externality\b[^\n]*?->\s*([a-z_]+)", re.MULTILINE)

# A tool name no branch of the classifier recognises -- the admitted-ignorance
# path RFX-214 is about.
_UNIDENTIFIABLE_TOOL = "SomeCustomTool"


class UnknownFloorDocstringMatchesBehaviour(unittest.TestCase):
    def _declared_in_docstring(self) -> str:
        doc = classify_mod.__doc__ or ""
        matches = _DOCSTRING_LINE_RE.findall(doc)
        # Uniqueness is asserted, not assumed: if a second "unknown externality
        # -> x" line is ever added, this test must fail rather than silently
        # score whichever one happens to come first.
        self.assertEqual(
            len(matches), 1,
            "expected exactly one 'unknown externality -> <value>' line in "
            "classify.py's module docstring, found %d: %r" % (len(matches), matches))
        return matches[0]

    def test_docstring_declares_the_externality_classify_actually_emits(self):
        emitted = classify(_UNIDENTIFIABLE_TOOL, {"param": "value"})["externality"]
        declared = self._declared_in_docstring()
        self.assertEqual(
            declared, emitted,
            "classify.py's module docstring says an unidentifiable tool is priced "
            "externality=%r, but classify(%r) emits %r. RFX-214: these disagreed in "
            "two published wheels. Update the docstring line, not this test."
            % (declared, _UNIDENTIFIABLE_TOOL, emitted))

    def test_the_pre_fix_rationale_paragraph_is_gone(self):
        """The paragraph that argued FOR the defective value must not come back.

        Separate from the line check above because the two failed independently:
        the table line and the prose paragraph below it were both wrong, and a
        fix that corrected only the line would leave the argument standing.
        """
        doc = classify_mod.__doc__ or ""
        needle = 'the unknown-tool fallback uses "internal"'
        # assertNotIn would print the whole ~20 KB module docstring into the CI
        # log on failure. assertFalse on the membership test says the same
        # thing in one line.
        self.assertFalse(
            needle in doc,
            "the pre-RFX-214 rationale paragraph is back in classify.py's module "
            "docstring (found %r); it argues for the one externality "
            "external_sends does not charge" % needle)

    def test_a_tool_the_adapter_does_know_is_unaffected(self):
        """Scope guard. RFX-214 moved ONLY the admitted-ignorance path.

        If this ever fails, the fix has widened past its ticket: `internal` is
        correct for a tool the adapter genuinely knows is local, and moving it
        would charge every file read to the operator's external-send budget.
        """
        self.assertEqual(classify("Read", {"file_path": "/tmp/x"})["externality"], "internal")
        self.assertEqual(classify("Write", {"file_path": "/tmp/x"})["externality"], "internal")
        # ...and a tool that genuinely does leave the machine keeps saying so.
        self.assertEqual(classify("WebFetch", {"url": "https://example.invalid"})["externality"],
                         "outbound")


if __name__ == "__main__":
    unittest.main()
