"""RFX-353 -- the three flag checks read an ARGV, not the whole line.

Until this ticket `classify.py` asked three questions of a command string with a
regex that scanned the WHOLE line after a command word:

    _FORCE_PUSH_RE   \\bgit\\s+push\\b.*--force\\b|\\bgit\\s+push\\b.*-f\\b
    _GIT_CLEAN_RE    \\bgit\\s+clean\\b.*-[a-zA-Z]*f[a-zA-Z]*
    _RM_RECURSIVE_RE \\brm\\b.*-[a-zA-Z]*r[a-zA-Z]*

"Is there a dash-LETTER somewhere after the command word" is not the question
any of them meant to ask, and the giveaway is that each was wrong in BOTH
directions at once -- a destruction spelled with the wrong case walked through,
and a benign line whose own OPERAND contained the letter was held. A check that
can be wrong both ways from one token has never read an argv.

GROUND TRUTH. Every verdict pinned below was executed first, against synthetic
canaries under /tmp and a local bare git repo (no remote, no network, nothing
outside the sandbox), and read off the filesystem or off the repo's refs:

    rm -R / -fR / -Rf victim/       -> tree DESTROYED (POSIX synonym of -r)
    rm b/my-report.txt              -> one file gone, sibling tree SURVIVED
    git clean -n src/my-fixtures    -> "Would remove", canary SURVIVED
    git clean {-n -f,-f -n,-nfd,-fnd} -> SURVIVED in all four: -n dominates -f
    git push origin main            -> ! [rejected] (non-fast-forward)
    git push origin +main:main      -> "+ 243161a...8a8743a (forced update)"
    git push --mirror origin        -> "- [deleted] doomed"
    git push --delete origin b      -> "- [deleted] doomed2"
    git push origin :probe          -> "- [deleted] probe"
    git push --dry-run --force      -> remote ref did NOT move
    git push --force-if-includes    -> still rejected; it never forces alone
    git clean -Fdx                  -> error: unknown switch `F'; nothing removed

Pure: no network, no I/O, no side effects. The production-looking paths are
CLASSIFIER INPUT ONLY -- this module creates, opens and executes nothing.
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import classify


def _cls(command):
    return classify("Bash", {"command": command})


class TestRmRecursionIsReadFromRmsOwnFlags(unittest.TestCase):
    """`rm -R` destroyed the canary tree and was priced single/none/moderate."""

    RECURSIVE = [
        "rm -r /srv/prod/data",
        "rm -R /srv/prod/data",           # <- allowed before RFX-353
        "rm -fR /srv/prod/data",          # <- allowed before RFX-353
        "rm -Rf /srv/prod/data",          # <- allowed before RFX-353
        "rm -rf /srv/prod/data",
        "rm --recursive /srv/prod/data",
    ]

    def test_every_recursive_spelling_is_priced_recursive(self):
        for command in self.RECURSIVE:
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("broad", got["blast_radius"])
                self.assertEqual("rm_recursive", got["danger_signature"])
                self.assertEqual("destructive_broad", got["classification_tier"])

    def test_a_filename_does_not_make_a_delete_recursive(self):
        """The complement: the caller's own FILENAME was flipping the verdict.

        These two differ by the file's name and nothing else. Before RFX-353
        the second was `broad` / `rm_recursive` -- a single-file delete priced
        as a recursive tree delete because `-report` contains a dash and an r.
        """
        for command in ("rm /tmp/scratch.txt", "rm /tmp/quarterly-report.txt"):
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("single", got["blast_radius"])
                self.assertEqual("none", got["danger_signature"])

    def test_a_path_after_the_end_of_options_is_not_a_flag(self):
        got = _cls("rm -- -weird-r-file.txt")
        self.assertEqual("single", got["blast_radius"])
        self.assertEqual("none", got["danger_signature"])

    def test_a_non_recursive_flag_is_not_recursion(self):
        got = _cls("rm -d /srv/prod/emptydir")
        self.assertEqual("none", got["danger_signature"])


class TestGitCleanReadsItsOwnFlags(unittest.TestCase):

    def test_force_still_deletes(self):
        got = _cls("git clean -fd src/fixtures")
        self.assertEqual("delete", got["verb"])
        self.assertEqual("irreversible", got["reversibility"])
        self.assertEqual("broad", got["blast_radius"])

    def test_a_pathspec_containing_dash_f_does_not_make_a_dry_run_a_delete(self):
        """Measured: this printed "Would remove" and removed nothing.

        It was priced delete / irreversible / broad and held for approval --
        `src/my-fixtures` supplied the `f` the whole-line regex wanted.
        """
        for command in ("git clean -n src/my-fixtures",
                        "git clean --dry-run src/my-fixtures"):
            with self.subTest(command=command):
                got = _cls(command)
                self.assertNotEqual("delete", got["verb"])
                self.assertEqual("recoverable", got["reversibility"])

    def test_dry_run_dominates_force_in_every_order(self):
        """All four orders left the canary in place on a real git."""
        for command in ("git clean -n -f -d probe", "git clean -f -n -d probe",
                        "git clean -nfd probe", "git clean -fnd probe"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _cls(command)["verb"])

    def test_a_config_override_that_removes_the_refusal_is_a_delete(self):
        """`git -c clean.requireForce=false clean -d` deletes with no `-f`.

        Measured: with the default config `git clean -d` answers *"clean.
        requireForce is true and -f not given: refusing to clean"* and removes
        nothing; with the override it printed "Removing probe/" and the canary
        was gone. Found by dev-1--167's measurement handover.
        """
        for command in ("git -c clean.requireForce=false clean -d /srv/prod",
                        "git -c clean.requireForce=0 clean /srv/prod"):
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("delete", got["verb"])
                self.assertEqual("irreversible", got["reversibility"])

    def test_the_config_override_complement(self):
        """Its complement, three ways: the refusal still standing, an unrelated
        `-c`, and the dry run, which dominates the override too (measured)."""
        for command in ("git -c clean.requireForce=true clean -d build/",
                        "git -c user.name=x clean -d build/",
                        "git -c clean.requireForce=false clean -n -d build/"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _cls(command)["verb"])

    def test_the_uppercase_F_position_is_carried_over_deliberately(self):
        """`git clean -Fdx` is NOT a git command -- git answers "unknown switch
        `F'" and removes nothing, measured. Two tests in test_classify.py pin it
        as delete/broad on purpose, so RFX-353 preserves that rather than
        flipping another round's tested call inside an unrelated fix. If that
        position is ever revisited, this test and those two move together.
        """
        self.assertEqual("delete", _cls("git clean -Fdx")["verb"])


class TestGitPushForceIsReadFromPushesOwnArgv(unittest.TestCase):

    FORCES = [
        "git push --force origin main",
        "git push -f origin main",
        "git push --force-with-lease origin main",
        "git push origin +main:main",            # <- allowed before RFX-353
        "git push --mirror origin",              # <- allowed before RFX-353
        "git push --delete origin release-2026-09",   # <- allowed before
        "git push -d origin release-2026-09",         # <- allowed before
        "git push origin :release-2026-09",           # <- allowed before
    ]

    def test_every_spelling_that_rewrites_a_remote_ref_is_priced_force(self):
        for command in self.FORCES:
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("emit", got["verb"])
                self.assertEqual("broad", got["blast_radius"])
                self.assertEqual("git_force_push", got["danger_signature"])

    def test_a_push_that_moves_no_ref_is_not_a_force_push(self):
        """The complement. None of these moved a remote ref when measured."""
        for command in ("git push origin main",
                        "git push --dry-run --force origin main",
                        "git push -n --force origin main",
                        "git push --force-if-includes origin main"):
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("scoped", got["blast_radius"])
                self.assertEqual("none", got["danger_signature"])


class TestAGlobalOptionDoesNotHideTheSubcommand(unittest.TestCase):
    """`\\bgit\\s+push\\b` required the subcommand to be the very next word.

    `git -C /srv/app push --force origin main` matched no check at all and was
    not even routed to EMIT: it came out execute / recoverable / scoped, i.e. a
    literal force push scoring BELOW a plain `git push`.
    """

    def test_force_push_behind_a_global_option(self):
        for command in ("git -C /srv/app push --force origin main",
                        "git -c user.name=x push --force origin main",
                        "git --no-pager push --force origin main"):
            with self.subTest(command=command):
                got = _cls(command)
                self.assertEqual("emit", got["verb"])
                self.assertEqual("git_force_push", got["danger_signature"])

    def test_git_clean_behind_a_global_option(self):
        got = _cls("git --no-pager clean -fdx /srv/prod")
        self.assertEqual("delete", got["verb"])
        self.assertEqual("broad", got["blast_radius"])

    def test_a_wrapper_still_peels(self):
        """`sudo git push --force` was a force push before and stays one."""
        got = _cls("sudo git push --force origin main")
        self.assertEqual("git_force_push", got["danger_signature"])

    def test_a_different_subcommand_is_not_a_push(self):
        self.assertNotEqual("emit", _cls("git -C /srv/app status")["verb"])


if __name__ == "__main__":
    unittest.main()
