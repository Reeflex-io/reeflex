"""
RFX-328 / RFX-336 / RFX-337 -- the substitution walk spends a work budget, not
a depth counter, and says so when it runs out.

WHAT WAS WRONG.  `_shell_segments` guarded its recursion with `depth < 3`, and
`sh -c` unwrapping spent the SAME counter, so wrappers and nestings were
fungible.  Five destructive lines were priced `read / reversible / single /
benign` -- ALLOW -- and a real bash really runs every one of them:

    echo $(echo $(echo $(echo $(rm -rf V))))        depth ceiling
    echo `echo \\`rm -rf V\\``                        nested backticks
    sh -c 'sh -c "echo \\$(rm -rf V)"'               `sh -c` inside `sh -c`
    echo $(>/dev/null rm -rf V)                     redirection before the verb

GROUND TRUTH IS OFF THE FILESYSTEM, NOT OFF AN ARGUMENT.  Every "destructive"
line below was run by dev-2 round 071 in a real bash against a synthetic victim
directory with a canary file in it, and the canary was read back afterwards:
28 destroyed, 18 survived.  On main `ba3ccb4` the classifier disagreed with
bash on 15 of the 46; on this tree it disagrees on none.  The transcript is in
`code-reports/dev-2--071-evidence/`.

WHY THE BENIGN HALF IS HALF THE FILE.  A classifier that answers "irreversible
delete" to everything passes every test above and is strictly worse than the
defect being fixed, because it is a gate an operator switches off.  The
`must_not` cases are the ones that make the `must` cases mean anything -- in
particular the four places where a backslash means the shell does NOT run the
substitution, which is what separates this fix from "unescape everything".
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

from reeflex_claude.classify import (  # noqa: E402
    _WALK_MAX_DEPTH,
    _WalkBudget,
    _shell_segments,
    classify,
)

V = "/var/lib/pgsql"


def _verdict(command):
    return classify("Bash", {"command": command})


def _is_destructive(result):
    return (result.get("verb") == "delete"
            or result.get("classification_tier") in ("destructive_systemic",
                                                     "destructive_broad"))


class SubstitutionDepthTests(unittest.TestCase):
    """RFX-336: the walk no longer stops at three levels."""

    def test_nesting_past_the_old_ceiling_is_read(self):
        for levels in (4, 5, 8, 20):
            command = "echo $(" * levels + "rm -rf %s" % V + ")" * levels
            with self.subTest(levels=levels):
                result = _verdict(command)
                self.assertEqual("delete", result.get("verb"))
                self.assertEqual("irreversible", result.get("reversibility"))

    def test_the_three_levels_that_already_worked_still_work(self):
        """A fix that closes 4 and breaks 3 would net out at zero."""
        for levels in (1, 2, 3):
            command = "echo $(" * levels + "rm -rf %s" % V + ")" * levels
            with self.subTest(levels=levels):
                self.assertEqual("delete", _verdict(command).get("verb"))

    def test_nested_backticks_are_walked(self):
        """
        RFX-336: `_to_backtick` found the body, but the body still carried the
        backslashes the shell had already consumed, so the nested backtick was
        invisible.  Both of these delete for real.
        """
        for command in ("echo `echo \\`rm -rf %s\\``" % V,
                        "echo `echo \\$(rm -rf %s)`" % V):
            with self.subTest(command=command):
                self.assertEqual("delete", _verdict(command).get("verb"))


class ShellCNestingTests(unittest.TestCase):
    """RFX-337 case 2: `sh -c` inside `sh -c`."""

    def test_sh_c_inside_sh_c_is_unwrapped(self):
        command = 'sh -c \'sh -c "echo \\$(rm -rf %s)"\'' % V
        self.assertEqual("delete", _verdict(command).get("verb"))

    def test_three_levels_of_sh_c(self):
        command = 'sh -c \'sh -c "sh -c \\"echo \\$(rm -rf %s)\\""\'' % V
        self.assertEqual("delete", _verdict(command).get("verb"))

    def test_a_single_quoted_payload_keeps_its_backslash(self):
        """
        THE CONTROL THAT STOPS THE FIX FROM BEING "UNESCAPE EVERYTHING".

        Measured, because the two spellings look identical after `shlex` has
        removed the quotes and they do NOT mean the same thing:

            sh -c "echo \\$(rm -rf V)"   -> DESTROYED  (backslash consumed)
            sh -c 'echo \\$(rm -rf V)'   -> SURVIVED   (backslash preserved)

        If this test goes red, `_c_payload_quote` has stopped distinguishing
        them and the gate has started refusing a line the shell does not run.
        """
        command = "sh -c 'echo \\$(rm -rf %s)'" % V
        self.assertNotEqual("delete", _verdict(command).get("verb"))

    def test_the_wrapper_forms_that_already_worked_still_work(self):
        for command in ("sh -c 'echo $(rm -rf %s)'" % V,
                        "bash -c 'echo $(echo $(rm -rf %s))'" % V):
            with self.subTest(command=command):
                self.assertEqual("delete", _verdict(command).get("verb"))


class RedirectionPrefixTests(unittest.TestCase):
    """RFX-337 case 1: a redirection written before the command word."""

    def test_a_redirection_before_the_verb_is_peeled(self):
        for prefix in (">/dev/null", "> /dev/null", "2>/dev/null",
                       ">>/dev/null", "</dev/null", ">/dev/null 2>&1"):
            command = "echo $(%s rm -rf %s)" % (prefix, V)
            with self.subTest(prefix=prefix):
                self.assertEqual("delete", _verdict(command).get("verb"),
                                 "redirection prefix %r hid the verb" % prefix)

    def test_a_redirection_at_the_top_level_is_peeled_too(self):
        self.assertEqual("delete", _verdict(">/dev/null rm -rf %s" % V).get("verb"))

    def test_a_redirection_does_not_swallow_a_benign_command(self):
        """Peeling must expose the real verb, not eat it."""
        result = _verdict(">/dev/null cat /etc/hostname")
        self.assertEqual("read", result.get("verb"))

    def test_a_trailing_redirection_is_not_a_prefix(self):
        """`echo hi > file` must still be an echo, not a peel."""
        self.assertNotEqual("delete", _verdict("echo hi > /tmp/out").get("verb"))


class RedirectionPrefixTruncationTests(unittest.TestCase):
    """
    PEELING A REDIRECTION MUST NOT LOSE WHAT IT TRUNCATES.

    Found by qa--237 reviewing this PR and confirmed by dev-2--072 on a separate
    rig.  The first version of the RFX-337 arm peeled a redirection prefix
    whenever anything followed it -- but bash applies the redirection AND runs
    the command, so `> f cmd` truncates `f` and runs `cmd`.  Reading the line as
    `cmd` alone priced a production database truncation `benign`, which is worse
    than the escape the arm closes.

    THE GUARD THAT LET IT THROUGH WAS A SPELLING, NOT A BEHAVIOUR.  The arm
    guarded only the TERMINAL form (`if nxt >= n: break`), and every test above
    aims its redirection at `/dev/null` -- which destroys nothing, so peeling it
    loses nothing.  The hole was invisible to a suite that never pointed a
    redirection at a real file.

    GROUND TRUTH IS OFF THE FILESYSTEM (dev-2--072, synthetic canary in a temp
    dir; the production-looking path below is classifier INPUT only and is never
    executed).  All four spellings here destroy the canary's contents.  `>>` and
    `<` leave it intact, which is why they are controls rather than more cases.

    WHY EVERY ASSERTION IS ABOUT CONTENT AND NONE IS ABOUT SIZE.  `> f echo hi`
    truncates `f` and then `echo` writes `hi` into it, so the file ends at three
    bytes.  An "is the file empty" check calls three of these four shapes SAFE,
    on a tree where they are broken.  Two agents and I all hit that instrument
    before it was caught; it is written down here so the next one does not.
    """

    CONTAINER = "/srv/prod/db.sqlite"

    # SIX spellings, not four.  qa--237's table listed four; qa--238's ground
    # truth found that `>|` (clobber override) and `&>` (both streams) destroy
    # the contents too, and a test that covers four leaves two live.  Every one
    # of these was run against a real bash with a canary read back afterwards.
    # Only the first prices destructive on main -- the other five are holes this
    # closes rather than a regression it restores.
    SPELLINGS = ("> %s echo hi", ">%s echo hi", "1> %s echo hi",
                 "2> %s echo hi", ">| %s echo hi", "&> %s echo hi")

    def test_a_truncating_prefix_over_a_data_container_is_still_a_delete(self):
        for form in self.SPELLINGS:
            command = form % self.CONTAINER
            with self.subTest(command=command):
                result = _verdict(command)
                self.assertEqual("delete", result.get("verb"),
                                 "the peel dropped the truncation of %r"
                                 % self.CONTAINER)
                self.assertEqual("broad", result.get("blast_radius"))
                self.assertEqual("overwrite_container",
                                 result.get("danger_signature"))

    def test_the_prefix_form_prices_no_lower_than_the_terminal_form(self):
        """
        The rule in one line: `> P cmd` truncates P exactly as `> P` does, so it
        cannot be priced below it whatever `cmd` is.  Asserted as a relation
        rather than a constant so it keeps holding if the pricing of P moves.
        """
        terminal = _verdict("> %s" % self.CONTAINER)
        for form in self.SPELLINGS:
            with self.subTest(command=form % self.CONTAINER):
                prefixed = _verdict(form % self.CONTAINER)
                self.assertEqual(terminal.get("classification_tier"),
                                 prefixed.get("classification_tier"))

    def test_an_ordinary_path_is_priced_like_its_own_terminal_form_too(self):
        """Not only the sensitive path -- the relation is not a path lookup."""
        self.assertEqual(_verdict("> /tmp/out.log").get("classification_tier"),
                         _verdict("> /tmp/out.log echo hi").get("classification_tier"))

    # -- the controls: these must NOT tighten -------------------------------

    def test_a_clobber_override_is_not_cut_in_half_by_the_pipe_split(self):
        """
        `>|` reached none of this until the splitter stopped treating its `|`
        as a pipe: the line came apart into `>` and `P cmd`, so the truncation
        was invisible however carefully the peel was written.  The same
        exception `2>&1` and `&>log` already had.
        """
        line = ">| %s echo hi" % self.CONTAINER
        self.assertEqual([line], _shell_segments(line))

    def test_an_ordinary_pipe_still_splits(self):
        """The control for the line above: `|` is still a pipe everywhere else."""
        self.assertEqual(["echo a", "grep b"], _shell_segments("echo a | grep b"))
        self.assertEqual(["ls > out", "head"], _shell_segments("ls > out | head"))

    def test_an_appending_prefix_is_not_a_truncation(self):
        """`>> f cmd` leaves the canary intact on a real shell."""
        self.assertNotEqual("delete",
                            _verdict(">> %s echo hi" % self.CONTAINER).get("verb"))

    def test_an_input_redirection_is_not_a_truncation(self):
        """`< f cat` reads it.  Nothing is destroyed."""
        self.assertNotEqual("delete",
                            _verdict("< %s cat" % self.CONTAINER).get("verb"))

    def test_a_discard_sink_is_not_a_destruction(self):
        """
        `>/dev/null cmd` is the single most common redirection there is and it
        destroys nothing.  Without this exclusion the fix would price it off the
        terminal form of `> /dev/null`, which this tree already reads as
        `rm_recursive_root` -- a systemic destruction, on a line that discards
        output.  (That terminal over-classification predates this ticket and is
        left alone: it is conservative, not fail-open.)
        """
        for sink in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            with self.subTest(sink=sink):
                result = _verdict("> %s echo hi" % sink)
                self.assertNotEqual("delete", result.get("verb"))
                self.assertEqual("benign", result.get("classification_tier"))

    def test_the_escape_this_arm_was_written_for_is_still_closed(self):
        """RFX-337's original case.  A fix that gives it back nets out at zero."""
        self.assertEqual("delete", _verdict(">/dev/null rm -rf %s" % V).get("verb"))
        self.assertEqual("delete",
                         _verdict("echo $(>/dev/null rm -rf %s)" % V).get("verb"))

    def test_both_halves_of_a_doubly_destructive_line_are_seen(self):
        """The truncation and the delete: the worse of the two wins, not the first."""
        result = _verdict("> %s rm -rf %s" % (self.CONTAINER, V))
        self.assertEqual("delete", result.get("verb"))
        self.assertEqual("irreversible", result.get("reversibility"))


class BenignLinesStayBenignTests(unittest.TestCase):
    """
    The half of the fix that keeps the gate usable.  Every line here SURVIVED
    in a real bash -- the shell does not run the substitution -- so pricing any
    of them a delete would be a false refusal.
    """

    CASES = [
        ("top-level escape", "echo \\$(rm -rf %s)" % V),
        ("single quoted", "echo '$(rm -rf %s)'" % V),
        ("escaped inside double quotes", 'echo "a \\$(rm -rf %s)"' % V),
        ("escaped dollar in a $() body", "echo $(echo \\$(rm -rf %s))" % V),
        ("escaped backtick in a $() body", "echo $(echo \\`rm -rf %s\\`)" % V),
        ("single quotes inside a substitution", "echo $(echo '$(rm -rf %s)')" % V),
        ("a deep READ is not a delete", "echo $(echo $(echo $(echo $(ls -la /tmp))))"),
        ("a nested backtick READ", "echo `echo \\`ls /tmp\\``"),
        ("arithmetic is not a command", "echo $((1 + 1))"),
        ("grep for the literal text", "grep -r 'rm -rf' /tmp"),
    ]

    def test_benign_lines_are_not_priced_as_deletes(self):
        for name, command in self.CASES:
            with self.subTest(case=name):
                self.assertFalse(
                    _is_destructive(_verdict(command)),
                    "%s: the shell does not run this, but the gate refused "
                    "it -- %r" % (name, command))


class WalkBudgetTests(unittest.TestCase):
    """
    What the walk bounds, and what it does when it runs out.

    The old ceiling failed OPEN at the bound: it stopped reading and priced
    the line from the `echo` it had managed to read.  The budget fails CLOSED,
    under its own signature, which is the RFX-322 treatment of a command the
    classifier did not read.
    """

    def test_a_walk_that_finishes_reports_it_finished(self):
        budget = _WalkBudget()
        _shell_segments("echo $(rm -rf %s)" % V, budget=budget)
        self.assertFalse(budget.exhausted)

    def test_past_the_depth_ceiling_the_walk_says_it_did_not_finish(self):
        command = "echo $(" * (_WALK_MAX_DEPTH + 40) + "rm -rf %s" % V \
            + ")" * (_WALK_MAX_DEPTH + 40)
        budget = _WalkBudget()
        _shell_segments(command, budget=budget)
        self.assertTrue(budget.exhausted,
                        "the walk stopped early and did not record it -- that "
                        "silence is the fail-open this budget replaces")

    def test_an_unfinished_walk_is_refused_not_priced_benign(self):
        """
        THE LOAD-BEARING ONE.  A `rm -rf` hidden below the ceiling must not
        come back benign just because the walk could not reach it.
        """
        command = "echo $(" * 200 + "rm -rf %s" % V + ")" * 200
        result = _verdict(command)
        self.assertEqual("unwalkable_command", result.get("danger_signature"))
        self.assertEqual("destructive_systemic", result.get("classification_tier"))
        self.assertEqual("irreversible", result.get("reversibility"))

    def test_a_long_benign_chain_is_not_refused(self):
        """
        The budget was 512 segments first, and this line -- which is nothing
        but `echo hello` repeated -- tripped it and was refused.  A gate that
        refuses this is one an operator turns off, so the bound was raised
        above anything the 64 KiB command cap can chain.
        """
        command = " && ".join(["echo hello"] * 4000)[:60000]
        result = _verdict(command)
        self.assertNotEqual("unwalkable_command", result.get("danger_signature"))
        self.assertFalse(_is_destructive(result))

    def test_deep_nesting_does_not_crash_the_hook(self):
        """
        Removing the ceiling outright raises RecursionError at ~1000 levels,
        and RFX-323 measured Claude Code's PreToolUse runner FAILING OPEN when
        the hook crashes -- so a crash here is not a lesser bug than the
        escape, it is the same bug with a longer command.
        """
        command = "echo $(" * 8000 + "rm -rf /v" + ")" * 8000
        try:
            result = _verdict(command)
        except RecursionError:  # pragma: no cover - the thing being prevented
            self.fail("the walk exhausted the stack; the hook would crash and "
                      "the runner fails open on a crashed hook (RFX-323)")
        self.assertTrue(_is_destructive(result))


class DeclaredResidualsTests(unittest.TestCase):
    """
    The gaps this change does NOT close, asserted so the declaration cannot
    quietly go stale -- the rule `_substitution_bodies` already states and the
    reason `test_the_depth_ceiling_is_closed` exists at all.
    """

    def test_a_substitution_that_produces_the_command_word_is_still_unread(self):
        """RFX-158 / `gap-command-substitution`.  Still open, still declared."""
        result = _verdict('eval "$(echo rm -rf %s)"' % V)
        self.assertNotEqual(
            "delete", result.get("verb"),
            "RFX-158 appears to be closed -- move it out of the residual "
            "lists in conformance.py and reeflex-litellm's STILL_OPEN table "
            "rather than deleting this test")


if __name__ == "__main__":
    unittest.main()
