"""
test_prefixed_group_rfx405.py -- RFX-405, at the HOOK plane.

THE DEFECT, in one line: RFX-329 closed the subshell group only when it is the
FIRST thing in its segment, so putting any prefix word in front of it restored
the escape in full.

    { (rm -rf /var/lib/pgsql); }              was execute/recoverable/scoped
    time (rm -rf /var/lib/pgsql)              was execute/recoverable/scoped
    if (rm -rf /var/lib/pgsql); then :; fi    was execute/recoverable/scoped

WHY IT ESCAPED.  `_shell_segments` calls `_peel_group` on the raw segment and
`_peel_wrappers` on its tokens AFTERWARDS.  `_peel_group` strips a `(` only at
position 0, so a group behind a prefix is never peeled; `_peel_wrappers` then
drops the prefix, and the surviving command word is the literal `(rm`, which
matches no branch of `_infra_destructive` or `_classify_bash_delete`.  The line
falls to the default Bash EXECUTE arm and the target ref is mangled, so R6
cannot rescue it either -- the same failure RFX-329 described, one construct
out.

WHY THE PAIRING IS THE INSTRUMENT, and not "is a delete refused".  Each
destructive row below is paired with the SAME PREFIX carrying the BARE command
(`{ rm -rf V; }`, `time rm -rf V`, `if rm -rf V; then :; fi`).  All nine bare
rows were ALREADY refused on the broken tree.  A test that asserted only "this
is refused" would pass on the broken tree via the bare row; what discriminates
is that the two halves of a pair must AGREE.  `test_a_group_and_its_bare_twin_
agree` is that assertion, and it is the one to keep if any other is deleted.

GROUND TRUTH IS REAL BASH, not an opinion about bash.  Every destructive form
here was executed by /bin/bash against a freshly seeded synthetic victim
directory and the destruction read off the filesystem afterwards, on the tree
this fix was cut from: 9 of 9 destroy, and the four prefixes bash REJECTS in
front of a group (`nice`, `nohup`, `env FOO=1`, `FOO=1` -- an external command
takes no subshell as an argument) were checked with `bash -n` and excluded
rather than counted.  Rig and raw output:
code-reports/dev-1--218--20260922-evidence/80-prefix-family.{txt,json}.

WHAT THIS DOES NOT COVER, stated rather than left to be inferred:
  * The stub core is R1-R4 of the shipped pack for a first call in a session --
    the same limit test_substitution_rfx301 documents.  A real core has further
    asking rules and they can only make a verdict stricter.  The round that
    wrote this file also decided every row through core's REAL pack under
    `opa eval`, proved byte-identical to the deployed v0.2.2 core's.
  * RFX-328 (the `depth < 3` ceiling) and the `gap-` family (a subshell whose
    body only exists at runtime, `(eval "$CMD")`) are untouched.
  * A group behind a prefix this module does NOT drop is still unread; that is
    not reachable in bash for the prefixes measured, but it is not asserted.
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from reeflex_claude import classify as classify_mod
from reeflex_claude.classify import classify
from test_substitution_rfx301 import _HookPlaneCase

_V = "/var/lib/pgsql"

# (label, the group form, the SAME prefix with the bare command).
# Every left-column form really destroys the victim under /bin/bash; every
# right-column form was already refused before this fix.
PREFIXED_PAIRS = [
    ("brace",  "{ (rm -rf %s); }" % _V,
               "{ rm -rf %s; }" % _V),
    ("time",   "time (rm -rf %s)" % _V,
               "time rm -rf %s" % _V),
    ("bang",   "! (rm -rf %s)" % _V,
               "! rm -rf %s" % _V),
    ("if",     "if (rm -rf %s); then :; fi" % _V,
               "if rm -rf %s; then :; fi" % _V),
    ("while",  "while (rm -rf %s); do break; done" % _V,
               "while rm -rf %s; do break; done" % _V),
    ("until",  "until (rm -rf %s); do break; done" % _V,
               "until rm -rf %s; do break; done" % _V),
    ("for_do", "for i in 1; do (rm -rf %s); done" % _V,
               "for i in 1; do rm -rf %s; done" % _V),
    ("then",   "if true; then (rm -rf %s); fi" % _V,
               "if true; then rm -rf %s; fi" % _V),
    ("else",   "if false; then :; else (rm -rf %s); fi" % _V,
               "if false; then :; else rm -rf %s; fi" % _V),
]

# The same syntax with a harmless body.  A fix that refuses the left column by
# refusing PREFIXES, or by refusing PARENTHESES, fails every row here -- and a
# gate that asks on `time (ls -la /tmp)` gets switched off, which is the
# argument RFX-145 makes about strict mode.
BENIGN_PREFIXED = [
    ("brace",  "{ (echo hi); }"),
    ("time",   "time (ls -la /tmp)"),
    ("bang",   "! (grep -q foo /tmp/x)"),
    ("if",     "if (ls /tmp); then :; fi"),
    ("while",  "while (true); do break; done"),
    ("for_do", "for i in 1; do (echo $i); done"),
    ("then",   "if true; then (cat /etc/hosts); fi"),
]

# Parentheses behind a prefix that are NOT a subshell group.  Peeling these
# would be the false positive that makes the fix worse than the defect.
NOT_GROUPS_BEHIND_A_PREFIX = [
    ("arithmetic_after_keyword", "if ((RETRIES + 1)); then :; fi"),
    ("arithmetic_bare",          "((RETRIES + 1))"),
    ("case_pattern",             "case $x in (a) echo hi;; esac"),
    ("quoted_text",              "time echo '(rm -rf %s)'" % _V),
    # A FUNCTION DEFINITION: a bare word followed by an unquoted `(`, valid
    # bash, and defining it runs nothing -- so it must stay allowed.
    #
    # RECORDED HONESTLY, BECAUSE THE ROUND THAT ADDED THESE TWO ROWS ADDED THEM
    # ON A HYPOTHESIS THAT TURNED OUT TO BE FALSE.  Widening
    # `_peel_prefixed_group` to step over ANY leading word (sabotage arm C)
    # breaks only `test_the_peel_only_steps_over_words_this_module_already_
    # drops` -- an assertion about a frozenset.  These rows were expected to
    # make that arm break BEHAVIOUR as well.  They do not: measured under the
    # arm, `deploy () { rm -rf V; }` segments to `) { rm -rf V` and still
    # prices execute/recoverable/scoped, because the `)` survives as the
    # command word and matches nothing either.
    #
    # So the standing reading is that arm C has NO reachable behavioural
    # consequence that could be constructed here -- a bare word before an
    # unquoted `(` is a bash syntax error nearly everywhere, and the one place
    # it is not, the peel does not reach a destructive command word.  The
    # narrowness of `_PREFIX_WORDS` is cheap insurance, not a load-bearing
    # guard, and the frozenset assertion is the only instrument that sees it.
    # These two rows stay because they pin a real shape that must stay allowed,
    # not because they discriminate that arm.
    ("function_definition_spaced",  "deploy () { rm -rf %s; }" % _V),
    ("function_definition_tight",   "cleanup() { rm -rf %s; }" % _V),
]


class TestAGroupBehindAPrefixReachesAHuman(_HookPlaneCase):
    """The RFX-405 headline, as a verdict from the real entry point."""

    def test_every_prefixed_group_destruction_is_refused(self):
        for label, group, _bare in PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                decision, _ = self.hook(group)
                self.assertNotEqual(
                    "allow", decision,
                    "%s: bash DESTROYS %s here, and the gate allowed it "
                    "-- RFX-405" % (label, _V))

    def test_a_group_and_its_bare_twin_agree(self):
        """THE discriminating assertion -- see this file's docstring.

        The bare twin was refused on the broken tree too, so a pair that
        DISAGREES is exactly the RFX-405 signature and nothing else.
        """
        for label, group, bare in PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                group_decision, _ = self.hook(group)
                bare_decision, _ = self.hook(bare)
                self.assertEqual(
                    bare_decision, group_decision,
                    "%s: the bare command is %r but the same prefix with a "
                    "subshell group is %r -- the group is unread"
                    % (label, bare_decision, group_decision))

    def test_the_axes_on_the_wire_name_the_delete(self):
        """Not just 'refused': refused because the wire said delete."""
        for label, group, _bare in PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                _, envelope = self.hook(group)
                axes = (envelope or {}).get("axes") or {}
                action = (envelope or {}).get("action") or {}
                self.assertEqual("delete", action.get("verb"), label)
                self.assertEqual("irreversible", axes.get("reversibility"), label)


class TestTheFalsePositiveFloor(_HookPlaneCase):
    """A subshell behind a keyword is ordinary shell and must stay allowed."""

    def test_every_benign_prefixed_group_is_allowed(self):
        for label, command in BENIGN_PREFIXED:
            with self.subTest(prefix=label):
                decision, _ = self.hook(command)
                self.assertEqual("allow", decision,
                                 "%s: %r must stay allowed" % (label, command))

    def test_parens_behind_a_prefix_that_are_not_a_group(self):
        for label, command in NOT_GROUPS_BEHIND_A_PREFIX:
            with self.subTest(form=label):
                decision, _ = self.hook(command)
                self.assertEqual("allow", decision,
                                 "%s: %r is not a subshell group" % (label, command))


class TestClassifyPlaneInvariants(unittest.TestCase):
    """Cheaper assertions that pin the mechanism rather than the verdict."""

    def test_the_command_word_is_the_command_not_the_paren(self):
        """The literal `(rm` is what the broken tree read as the command."""
        for label, group, _bare in PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                cls = classify("Bash", {"command": group})
                ref = cls.get("target_ref")
                self.assertEqual("delete", cls.get("verb"), label)
                self.assertIsNotNone(
                    ref, "%s: the EXECUTE arm sets target_ref=None, so a "
                         "None ref here means the group was never read" % label)
                self.assertNotIn("(", str(ref), label)
                self.assertNotIn(")", str(ref), label)

    def test_arithmetic_behind_a_keyword_is_not_peeled(self):
        """`((...))` is arithmetic: bash reads `rm` there as a variable name."""
        cls = classify("Bash", {"command": "if ((rm + 1)); then :; fi"})
        self.assertNotEqual("delete", cls.get("verb"))

    def test_the_peel_only_steps_over_words_this_module_already_drops(self):
        """The narrowness IS the false-positive floor, so pin it.

        A word outside `_PREFIX_WORDS` must leave the segment untouched --
        otherwise the helper would start eating arbitrary command words.
        """
        self.assertEqual(
            "notakeyword (rm -rf /tmp/x)",
            classify_mod._peel_prefixed_group("notakeyword (rm -rf /tmp/x)"))
        self.assertEqual(
            "rm -rf /tmp/x",
            classify_mod._peel_prefixed_group("time (rm -rf /tmp/x)"))

    def test_unbounded_wrappers_are_not_in_the_prefix_set(self):
        """`xargs`/`parallel` carry a meaning `_peel_wrappers` reports.

        Consuming them here would drop `unbounded`, which is how a command
        whose affected set only exists at runtime stops being marked as such.
        """
        for word in classify_mod._UNBOUNDED_WRAPPERS:
            self.assertNotIn(word, classify_mod._PREFIX_WORDS)

    def test_rfx329_is_not_undone(self):
        """The bare group this fix builds on must still be read."""
        cls = classify("Bash", {"command": "(rm -rf %s)" % _V})
        self.assertEqual("delete", cls.get("verb"))

    def test_rfx301_substitution_is_not_undone(self):
        cls = classify("Bash", {"command": "echo $(rm -rf %s)" % _V})
        self.assertEqual("delete", cls.get("verb"))


# ---------------------------------------------------------------------------
# RFX-405 residual, measured by qa--315 while landing this branch.
#
# The first version of `_peel_prefixed_group` stepped over exactly ONE prefix
# word: it returned the moment the word after a prefix was not `(`.  Every
# bash-valid PAIR of prefix words therefore still left `(rm` as the command
# word -- and `_shell_segments` manufactures such pairs out of ordinary code,
# because it splits on `;` and leaves the keyword attached to the segment, so
# `if true; then time (rm -rf V); fi` arrives here as `then time (rm -rf V)`.
#
# HOW THIS WAS FOUND, and why the rows below are a matrix and not a list: the
# nine rows above are nine STRINGS, and one string is not a class.  The
# complement was enumerated instead -- eight shell contexts x twelve wrapper
# words, filtered to the sixteen combinations `bash -n` accepts.  TWELVE of
# those sixteen escaped, each one verified to destroy a freshly seeded
# synthetic directory under real /bin/bash before it was written down.  Only
# `bare` and `subshell`, the two contexts with no keyword in front of the
# wrapper, were read correctly.
#
# Only `!` and `time` can be the inner word.  An external command takes no
# subshell as an argument, so `sudo`, `nice`, `env`, `command` and the rest are
# syntax errors here (checked with `bash -n`, excluded rather than counted) --
# which is also why the wider walk drops no wrapper meaning that the
# single-word step did not already drop.
DOUBLE_PREFIXED_PAIRS = [
    ("time_bang",   "time ! (rm -rf %s)" % _V,
                    "time ! rm -rf %s" % _V),
    ("bang_time",   "! time (rm -rf %s)" % _V,
                    "! time rm -rf %s" % _V),
    ("then_time",   "if true; then time (rm -rf %s); fi" % _V,
                    "if true; then time rm -rf %s; fi" % _V),
    ("then_bang",   "if true; then ! (rm -rf %s); fi" % _V,
                    "if true; then ! rm -rf %s; fi" % _V),
    ("else_time",   "if false; then :; else time (rm -rf %s); fi" % _V,
                    "if false; then :; else time rm -rf %s; fi" % _V),
    ("do_time",     "while true; do time (rm -rf %s); break; done" % _V,
                    "while true; do time rm -rf %s; break; done" % _V),
    ("do_bang",     "until false; do ! (rm -rf %s); break; done" % _V,
                    "until false; do ! rm -rf %s; break; done" % _V),
    ("for_do_time", "for i in 1; do time (rm -rf %s); done" % _V,
                    "for i in 1; do time rm -rf %s; done" % _V),
    ("brace_time",  "{ time (rm -rf %s); }" % _V,
                    "{ time rm -rf %s; }" % _V),
    ("brace_bang",  "{ ! (rm -rf %s); }" % _V,
                    "{ ! rm -rf %s; }" % _V),
]

# The same shapes with a harmless body.  A walk that steps over consecutive
# words and then peels whatever it lands on would refuse these too.
BENIGN_DOUBLE_PREFIXED = [
    ("time_bang",  "time ! (grep -q foo /tmp/x)"),
    ("then_time",  "if true; then time (ls -la /tmp); fi"),
    ("do_time",    "while true; do time (echo hi); break; done"),
    ("brace_time", "{ time (cat /etc/hosts); }"),
    # Arithmetic still has to survive TWO prefix words, not just one.
    ("then_time_arith", "if true; then time ((RETRIES + 1)); fi"),
]


class TestTwoPrefixWordsAreAlsoRead(_HookPlaneCase):
    """The residual: one prefix word was stepped over, two were not."""

    def test_every_double_prefixed_group_destruction_is_refused(self):
        for label, group, _bare in DOUBLE_PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                decision, _ = self.hook(group)
                self.assertNotEqual(
                    "allow", decision,
                    "%s: bash DESTROYS %s here, and the gate allowed it "
                    "-- RFX-405 residual" % (label, _V))

    def test_a_double_prefixed_group_and_its_bare_twin_agree(self):
        """The discriminating assertion, for the same reason as above.

        The bare twin was refused both before and after the one-word step, so
        a pair that DISAGREES is the residual signature and nothing else.
        """
        for label, group, bare in DOUBLE_PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                group_decision, _ = self.hook(group)
                bare_decision, _ = self.hook(bare)
                self.assertEqual(
                    bare_decision, group_decision,
                    "%s: the bare command is %r but the same two prefix words "
                    "with a subshell group is %r -- the group is unread"
                    % (label, bare_decision, group_decision))

    def test_the_axes_on_the_wire_name_the_delete(self):
        for label, group, _bare in DOUBLE_PREFIXED_PAIRS:
            with self.subTest(prefix=label):
                _, envelope = self.hook(group)
                axes = (envelope or {}).get("axes") or {}
                action = (envelope or {}).get("action") or {}
                self.assertEqual("delete", action.get("verb"), label)
                self.assertEqual("irreversible", axes.get("reversibility"), label)

    def test_the_benign_double_prefixed_forms_stay_allowed(self):
        for label, command in BENIGN_DOUBLE_PREFIXED:
            with self.subTest(form=label):
                decision, _ = self.hook(command)
                self.assertEqual("allow", decision,
                                 "%s: %r must stay allowed" % (label, command))


class TestTheWalkCommitsOnlyWhenItReachesAGroup(unittest.TestCase):
    """The mechanism, so the behavioural rows above have an attribution.

    A walk that consumed prefix words unconditionally would change how every
    keyword-led segment WITHOUT a group is read, which is most of the corpus.
    """

    def test_a_segment_with_no_group_is_returned_untouched(self):
        for segment in ("then time rm -rf %s" % _V,
                        "time ! rm -rf %s" % _V,
                        "then echo hi",
                        "do break",
                        "time",
                        ""):
            with self.subTest(segment=segment):
                self.assertEqual(
                    segment, classify_mod._peel_prefixed_group(segment),
                    "a segment with no group behind its prefix words must be "
                    "handed to `_peel_wrappers` exactly as it arrived")

    def test_consecutive_prefix_words_are_stepped_over(self):
        self.assertEqual(
            "rm -rf %s" % _V,
            classify_mod._peel_prefixed_group("then time (rm -rf %s)" % _V))
        self.assertEqual(
            "rm -rf %s" % _V,
            classify_mod._peel_prefixed_group("time ! (rm -rf %s)" % _V))

    def test_a_non_prefix_word_still_stops_the_walk(self):
        """The narrowness the first version bought is not spent by the walk."""
        self.assertEqual(
            "deploy () { rm -rf %s; }" % _V,
            classify_mod._peel_prefixed_group("deploy () { rm -rf %s; }" % _V))
        self.assertEqual(
            "time echo '(rm -rf %s)'" % _V,
            classify_mod._peel_prefixed_group("time echo '(rm -rf %s)'" % _V))


if __name__ == "__main__":
    unittest.main()
