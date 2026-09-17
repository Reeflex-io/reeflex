"""
test_peel_group_rfx335.py -- RFX-335: `_peel_group` was quadratic on a run of
unmatched closing parentheses.

THE DEFECT, in one line: `_peel_group` stripped one character per iteration and
re-balanced the WHOLE remaining string each time, so a run of `n` unmatched
closers cost O(n^2).  Measured on `7f19d374`: 8000 closers took 6.19s, and each
doubling of the input multiplied the time by ~4.

WHAT IT IS AND IS NOT, stated at measured strength, because the tempting
stronger claim is wrong:

  * It is NOT a bypass.  `echo hi)))` is a bash SYNTAX ERROR -- nothing can
    execute -- so this is CPU burn on input that can never run.
  * It fails CLOSED today.  RFX-321 (`#163`, merged three hours before the
    subshell fix that exposed this) answers `deny` under
    `reeflex.core/deadline_exceeded` when classify overruns, and qa--232
    watched that happen with a discriminating control.
  * What it really costs is a core-minute of CPU per bomb and a
    `deadline_exceeded` answer where a working classifier would have given a
    real verdict.

So this file guards a COST property, not a decision property.  That framing
matters: had the fix been written to make the bomb "safe", it would have been
solving a problem that RFX-321 already solved.

WHY THE PRIMARY GUARD COUNTS WORK RATHER THAN SECONDS.  A wall-clock assertion
is the obvious way to test "it got faster" and it is the one that goes flaky on
a loaded CI box.  `test_one_scan_per_peel_not_one_per_character` instead counts
the characters the balance helpers are asked to scan, which is deterministic on
any machine: the pre-fix implementation scans ~n^2/2 of them and the fixed one
scans n.  The wall-clock test is kept as a second, deliberately loose check,
because the property anyone actually cares about is "the hook answers inside its
budget" and that is measured in seconds, not in scans.

WHAT THIS DOES NOT COVER:
  * Other quadratic paths in `classify`.  This file pins `_peel_group` only.
    `_split_on_operators` and `_shell_segments` were not profiled here.
  * The hook-plane deadline behaviour itself, which is RFX-321's
    `test_deadline_rfx321.py`, not this file.
  * Any claim that the bomb was ever exploitable.  It was not, and the tests
    below deliberately assert nothing of the sort.
"""

from __future__ import annotations

import os
import sys
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from reeflex_claude import classify as _classify_mod
from reeflex_claude.classify import _peel_group, classify, MAX_BASH_COMMAND_CHARS


class _ScanCounter:
    """
    Count the characters the paren-balance helpers are asked to scan during one
    `_peel_group` call.

    Both helper names are wrapped, not just the one the fixed tree uses: the
    pre-fix implementation reaches for `_paren_balance` and the fixed one for
    `_paren_prefix_balance`, and a guard that only knew about the latter would
    score the broken tree as ZERO scanned characters and pass it.  That is the
    shape of a control that cannot fail.
    """

    NAMES = ("_paren_balance", "_paren_prefix_balance")

    def __init__(self):
        self.chars = 0
        self.calls = 0
        self._saved = {}

    def __enter__(self):
        for name in self.NAMES:
            original = getattr(_classify_mod, name, None)
            if original is None:
                continue
            self._saved[name] = original
            setattr(_classify_mod, name, self._wrap(original))
        if not self._saved:
            raise AssertionError(
                "neither %s exists -- this counter would measure nothing"
                % (" nor ".join(self.NAMES),)
            )
        return self

    def __exit__(self, *exc):
        for name, original in self._saved.items():
            setattr(_classify_mod, name, original)
        return False

    def _wrap(self, fn):
        def wrapper(text, *a, **kw):
            self.chars += len(text)
            self.calls += 1
            return fn(text, *a, **kw)

        return wrapper


class TestRFX335PeelGroupIsLinear(unittest.TestCase):

    def test_one_scan_per_peel_not_one_per_character(self):
        """
        The deterministic guard. Peeling a run of n unmatched closers must scan
        O(n) characters, not O(n^2).

        Pre-fix arithmetic, for the record: the strip loop ran n times and
        called the whole-string `_paren_balance` each time, scanning
        n + (n-1) + ... = ~n^2/2 characters. For n = 4000 that is ~8,000,000
        against the 4,007 the fixed tree scans -- three orders of magnitude, so
        the 4x budget below is not a knife-edge.
        """
        n = 4000
        command = "echo hi" + ")" * n

        with _ScanCounter() as counter:
            _peel_group(command)

        self.assertGreater(
            counter.calls, 0,
            "no balance helper was called at all -- the counter is not wired to "
            "the code under test, so this assertion proves nothing",
        )
        self.assertLessEqual(
            counter.chars, 4 * len(command),
            "peeling %d closers scanned %d characters (%.1fx the input). The "
            "balance of the remaining text is being recomputed per stripped "
            "character again -- that is RFX-335."
            % (n, counter.chars, counter.chars / float(len(command))),
        )

    def test_scanning_grows_linearly_when_the_input_doubles(self):
        """
        The same property expressed as a ratio, which is what actually tells
        linear from quadratic: doubling the closers must not quadruple the work.
        """
        def scanned(n):
            with _ScanCounter() as counter:
                _peel_group("echo hi" + ")" * n)
            return counter.chars

        small, large = scanned(2000), scanned(4000)
        self.assertGreater(small, 0, "counter not wired -- ratio is meaningless")
        ratio = large / float(small)
        self.assertLess(
            ratio, 3.0,
            "work grew %.2fx when the input doubled; linear is ~2x and "
            "quadratic is ~4x, so this is the quadratic strip loop." % ratio,
        )

    def test_the_whole_command_cap_peels_well_inside_the_hook_budget(self):
        """
        The property an operator cares about, in the units they care about.

        Budget is deliberately loose. The shipped hook timeout is 30s; the fixed
        tree peels the full 65536-character cap in ~0.03s; the pre-fix tree
        needed minutes. Anything under 5s distinguishes those three numbers
        without turning CI load into a test failure.
        """
        command = "echo hi" + ")" * MAX_BASH_COMMAND_CHARS

        start = time.perf_counter()
        _peel_group(command)
        elapsed = time.perf_counter() - start

        self.assertLess(
            elapsed, 5.0,
            "peeling a full-cap closer run took %.2fs. The shipped hook timeout "
            "is 30s, so this is the RFX-335 burn." % elapsed,
        )


class TestRFX335TheVerdictsDidNotMove(unittest.TestCase):
    """
    A performance fix that changed a verdict would be a far worse defect than
    the one it fixed. These pin the behaviour RFX-329 shipped.
    """

    def test_the_subshell_catch_still_holds(self):
        verdict = classify("Bash", {"command": "(rm -rf /srv/prod/data)"})
        self.assertEqual(verdict["verb"], "delete")
        self.assertEqual(verdict["reversibility"], "irreversible")
        self.assertEqual(verdict["target_ref"], "/srv/prod/data")

    def test_arithmetic_is_still_not_peeled(self):
        """
        The false-positive floor. `((rm = 1))` is arithmetic evaluation: bash
        reads `rm` as a variable name and deletes nothing, so pricing it as a
        delete would be a false positive.
        """
        self.assertEqual(_peel_group("((rm -rf /srv/prod/data))"),
                         "((rm -rf /srv/prod/data))")
        self.assertNotEqual(classify("Bash", {"command": "((rm = 1))"})["verb"],
                            "delete")

    def test_an_ordinary_subshell_is_still_allowed(self):
        self.assertEqual(_peel_group("(cd /tmp && ls)"), "cd /tmp && ls")

    def test_a_quoted_closer_is_not_stripped_as_grammar(self):
        """
        The trailing `)` here is inside an unterminated double quote, so it is
        not the close of a group and the balance check must leave it alone.
        This is the case the window arithmetic in the fix could most easily get
        wrong.
        """
        self.assertEqual(_peel_group('echo "abc)'), 'echo "abc)')

    def test_stranded_closers_are_still_peeled_off(self):
        self.assertEqual(_peel_group("echo hi)"), "echo hi")
        self.assertEqual(_peel_group("(rm -rf /srv/prod/data" + ")" * 4),
                         "rm -rf /srv/prod/data")


if __name__ == "__main__":
    unittest.main()
