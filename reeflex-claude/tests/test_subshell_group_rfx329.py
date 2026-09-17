"""
test_subshell_group_rfx329.py -- RFX-329, at the HOOK plane.

THE DEFECT, in one line: one pair of parentheses was the shortest string that
escaped the classifier entirely.  `(rm -rf /srv/prod/data)` was priced
execute/recoverable/scoped and ALLOWED, while bash really deletes the
directory.

WHY IT ESCAPED.  `_split_on_operators` is quote-aware but was not group-aware,
so the whole group survived as one segment, and `shlex` tokenised it as
`['(rm', '-rf', 'V)']`.  The command word was the literal string `(rm`, which
matches no branch of `_infra_destructive` or `_classify_bash_delete`, so the
line fell through to the default Bash EXECUTE arm.  The target ref was mangled
to `V))` as well, so R6 could not rescue it either.

WHY THE TESTS LIVE AT THIS PLANE.  The brace group `{ rm -rf V; }` -- the same
shell semantics -- was already priced delete/irreversible/systemic, so a
classify-plane test that only asserted "a delete is refused" would have passed
on the broken tree via the wrong row.  These drive the REAL entry point,
`python -m reeflex_claude.cli hook`, against a stub core that decides from the
axes it actually received; the assertion is on a DECISION off the wire.

The harness and the oracle are IMPORTED from test_substitution_rfx301, not
copied.  That file makes the argument already: two transcriptions of the same
policy drift apart, and the one that drifts is the copy nobody is reading.

WHAT THIS DOES NOT COVER, stated rather than left to be inferred:
  * The stub core is R1-R4 of the shipped pack for a first call in a session,
    inheriting exactly the limit test_substitution_rfx301 documents.  A real
    core v0.2.1 has at least one further asking rule, and it can only make a
    verdict stricter.
  * `((...))` arithmetic is asserted NOT to be peeled, but a subshell whose
    body only exists at runtime (`(eval "$CMD")`) is still unread -- that is
    the `gap-` family, not this fix.
  * RFX-328 (the `depth < 3` ceiling in `_shell_segments`, and the nested
    `sh -c` sharing that budget) is a DIFFERENT cause in the same file and is
    deliberately not addressed here; `test_the_depth_ceiling_is_still_open`
    below pins it so the gap stays declared rather than silently assumed.
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

from reeflex_claude.classify import classify
from test_substitution_rfx301 import _HookPlaneCase


# Every command here really does delete the target when bash runs it.  That was
# measured, not argued: the rig in code-reports/dev-1--153-evidence/rfx329_rig.py
# runs each form against a synthetic victim directory and checks the directory
# on disk afterwards.  On origin/main 242c8814 six of these forms destroyed the
# victim while the classifier called them reads or executes.
DESTRUCTIVE_GROUPS = [
    ("bare_group",          "(rm -rf /var/lib/pgsql)"),
    ("spaced_group",        "( rm -rf /var/lib/pgsql )"),
    ("group_in_substitution", "echo $( (rm -rf /var/lib/pgsql) )"),
    ("nested_groups",       "( (rm -rf /var/lib/pgsql) )"),
    ("group_piped",         "(rm -rf /var/lib/pgsql) | cat"),
    ("group_then_benign",   "(rm -rf /var/lib/pgsql); echo done"),
    ("group_with_operator", "(cd /srv && rm -rf /var/lib/pgsql)"),
]

# The same syntax with a harmless body.  A fix that refuses the left column by
# refusing PARENTHESES fails every row here -- and a gate that asks on a
# subshell gets switched off, which is the argument RFX-145 makes about strict
# mode and RFX-301 re-applies to its own scanner.
BENIGN_GROUPS = [
    ("bare_group",          "(ls -la /tmp)"),
    ("spaced_group",        "( ls -la /tmp )"),
    ("group_with_operator", "(cd /tmp && ls)"),
    ("group_echo",          "(echo hello)"),
    ("nested_groups",       "( (ls /tmp) )"),
    ("group_piped",         "(ls /tmp) | wc -l"),
]

# Parentheses that are NOT a subshell group.  Peeling these would be the false
# positive that makes the fix worse than the defect.
NOT_GROUPS = [
    ("arithmetic",        "((RETRIES + 1))"),
    ("single_quoted",     "echo '(rm -rf /var/lib/pgsql)'"),
    ("double_quoted",     'echo "(rm -rf /var/lib/pgsql)"'),
    ("grep_for_the_text", "grep -rn '(rm' src/"),
]


class TestASubshellGroupReachesAHuman(_HookPlaneCase):
    """The RFX-329 headline, as a verdict from the real entry point."""

    def test_every_subshell_destruction_is_refused(self):
        for label, command in DESTRUCTIVE_GROUPS:
            with self.subTest(form=label):
                decision, _ = self.hook(command)
                self.assertNotEqual(
                    "allow", decision,
                    "%s: bash DESTROYS /var/lib/pgsql here, and the gate "
                    "allowed it -- RFX-329" % label)

    def test_the_axes_on_the_wire_name_the_delete(self):
        """Not just 'refused': refused because the wire said delete."""
        for label, command in DESTRUCTIVE_GROUPS:
            with self.subTest(form=label):
                _, envelope = self.hook(command)
                axes = envelope.get("axes") or {}
                self.assertEqual(
                    "delete", (envelope.get("action") or {}).get("verb"),
                    "%s: the verb on the wire must be the delete" % label)
                self.assertEqual("irreversible", axes.get("reversibility"),
                                 "%s: reversibility on the wire" % label)

    def test_the_command_word_is_the_command_not_the_paren(self):
        """
        The precise defect, asserted POSITIVELY.

        The first version of this test asserted `")" not in ref`, on the
        ticket's description of a mangled ref.  It passed on the broken tree:
        the default Bash EXECUTE arm sets `target_kind="command"` and
        `target_ref=None`, so there was no ref for a paren to leak into and
        the assertion was vacuous.  Asserting the ref IS the path is what
        makes this fail on origin/main -- measured, W1 in the break rig.
        """
        _, envelope = self.hook("(rm -rf /var/lib/pgsql)")
        target = envelope.get("target") or {}
        self.assertEqual(
            "/var/lib/pgsql", target.get("ref"),
            "the group's target never reached the wire: %r" % (target,))

    def test_the_brace_group_control_still_refuses(self):
        """
        The control that fired on the broken tree too.  It is here so that a
        future regression cannot make the whole class pass for the wrong
        reason -- if this row is the only one green, the fix is gone.
        """
        decision, _ = self.hook("{ rm -rf /var/lib/pgsql; }")
        self.assertNotEqual("allow", decision)


class TestTheFalsePositiveFloor(_HookPlaneCase):
    """A subshell is an ordinary thing to write."""

    def test_every_benign_group_is_allowed(self):
        for label, command in BENIGN_GROUPS:
            with self.subTest(form=label):
                decision, _ = self.hook(command)
                self.assertEqual(
                    "allow", decision,
                    "%s: this deletes nothing and must not reach a human" % label)

    def test_parens_that_are_not_a_group_are_not_peeled(self):
        for label, command in NOT_GROUPS:
            with self.subTest(form=label):
                decision, _ = self.hook(command)
                self.assertEqual(
                    "allow", decision,
                    "%s: peeled something that is not a subshell" % label)


class TestClassifyPlaneInvariants(unittest.TestCase):
    """Cheap assertions that do not need the hook subprocess."""

    def test_arithmetic_is_not_read_as_its_contents(self):
        """
        `((rm -rf V))` is arithmetic evaluation: bash reads `rm` as a variable
        name and deletes nothing.  Pricing it as the inner command would be a
        false positive, so `_peel_group` refuses a doubled paren.
        """
        result = classify("Bash", {"command": "((rm -rf /var/lib/pgsql))"})
        self.assertNotEqual("delete", result.get("verb"))

    def test_rfx301_substitution_is_not_undone(self):
        """
        A regression guard on the neighbouring fix: whatever `_peel_group`
        does, `echo $(rm -rf V)` must still be read as a delete.

        Honest note on its strength.  Removing the balance check -- letting a
        trailing `)` be stripped unconditionally -- does NOT make this fail
        (break W3, measured: 10/10 still green).  `_balanced_paren` returns
        the remainder on an unterminated substitution, so losing the final
        `)` costs nothing today.  The balance check is therefore defensive
        rather than load-bearing, and this test is falsified only by a peel
        that removes parens it does not own (break W5).
        """
        result = classify("Bash", {"command": "echo $(rm -rf /var/lib/pgsql)"})
        self.assertEqual("delete", result.get("verb"))
        self.assertEqual("irreversible", result.get("reversibility"))

    def test_a_database_client_inside_a_group_is_reachable(self):
        """
        `_sql_reachable` reads the same segments, so it could not see the
        client in `(psql -c '...')` either.
        """
        result = classify("Bash", {"command": "(psql -c \"DROP TABLE t\")"})
        self.assertEqual("delete", result.get("verb"))

    def test_the_depth_ceiling_is_still_open(self):
        """
        RFX-328, pinned rather than fixed.  This asserts the CURRENT state so
        that closing RFX-328 makes this test fail loudly and the declaration
        gets updated, instead of the gap quietly outliving its own comment.
        """
        escaping = "echo $(echo $(echo $(echo $(rm -rf /var/lib/pgsql))))"
        result = classify("Bash", {"command": escaping})
        self.assertNotEqual(
            "delete", result.get("verb"),
            "RFX-328 appears to be fixed -- update this test and the "
            "declaration in _shell_segments rather than deleting it")


if __name__ == "__main__":
    unittest.main()
