"""RFX-358 -- `_READ_GIT_SUBCOMMANDS` priced a git subcommand from the
subcommand WORD ALONE, so the flags that turn it into a state change were never
read.

    classify.py:1047     if cmd0 == "git" and low and low[0] in _READ_GIT_SUBCOMMANDS:
                             return _read_result(preview)
    classify.py:480      {"status", "log", "diff", "show", "branch"}

Four of those five have a destructive invocation.  Before the fix every one of
them returned verb=read / tier=benign / danger_signature=none /
reversibility=reversible -- the cheapest verdict this classifier has -- and
through `build_envelope` into core's real pack that decided
`allow / reeflex.policy/read_only_internal`.

GROUND TRUTH IS OFF DISK, NOT OFF THE MANUAL.  Every semantic this file relies
on was executed against a real git (2.52.0) in a scratch repo under
/tmp/rfx-qa253-canary and recorded in the RFX-358 report:

    git branch -d <unmerged>        rc=1    "not fully merged", branch survives
    git branch -D <unmerged>        rc=0    "Deleted branch (was c3a61fe)"
    git branch -m <src> <existing>  rc=128  "already exists", both survive
    git branch -M <src> <existing>  rc=0    the overwritten ref is gone
    git diff|log|show --output=P    rc=0    P held "PRECIOUS DATA"; it did not
                                            afterwards -- replaced by diff text
    git diff -oP / -o P             rc=129 / rc=128, nothing written

That last line is why `_git_output_target` exists instead of reusing
`_flag_value(args, "-o", "--output")` the way `sort` does: that helper also
matches a bare `-o` and the letter `o` inside any short bundle, and pricing a
destruction off a spelling git REFUSES TO RUN states something untrue.  A
previous round pinned two tests to exactly that kind of command.

WHAT THIS DOES NOT CLAIM.  `git branch -D` still reaches `allow` at a single
call on an empty ledger -- identically to `userdel alice`, `docker rm c1` and
`aws s3 rm s3://b/k`, which the tree already prices delete/irreversible/scoped.
The corpus records that with residual=RFX-153.  What the honest verb DOES change
is asserted below as a budget turnover, because it is the half no
single-decision probe can see.

THE OVER-CALL HALF IS ASSERTED TOO.  A classifier fix measured only on the
shapes it was built for measures nothing, so the ordinary-work cases are here
with the arms and carry the same weight.
"""

import unittest

from reeflex_claude.classify import classify


def _cls(command):
    return classify("Bash", {"command": command})


class TestGitBranchRefMutationIsNotARead(unittest.TestCase):
    """The reproduction, replayed: these must no longer price benign."""

    FORCING = [
        "git branch -D main",
        "git branch -D feature/x",
        "git branch --delete --force release/1",
        "git branch -d --force release/1",
        "git branch -M main legacy",
        "git branch -C a b",
    ]

    NON_FORCING_MUTATIONS = [
        "git branch -d feature/x",
        "git branch --delete feature/x",
        "git branch -m old new",
        "git branch -c a b",
        "git branch -u origin/main",
        "git branch --set-upstream-to=origin/main",
        "git branch --unset-upstream",
        "git branch --edit-description",
    ]

    def test_no_ref_mutation_is_priced_as_a_read(self):
        """The RFX-358 fail-open, both tiers at once."""
        for command in self.FORCING + self.NON_FORCING_MUTATIONS:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertNotEqual(
                    "read", cls["verb"],
                    f"{command} changes a ref and is priced as a read")
                self.assertNotEqual(
                    "benign", cls["classification_tier"],
                    f"{command} changes a ref and is priced benign")

    def test_the_forcing_spellings_are_priced_as_ref_destructions(self):
        """`-D`/`-M`/`-C` are what git runs when it refuses the lowercase pair."""
        for command in self.FORCING:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertEqual("delete", cls["verb"], command)
                self.assertEqual("git_ref_delete", cls["danger_signature"], command)
                self.assertEqual("irreversible", cls["reversibility"], command)
                self.assertEqual("scoped", cls["blast_radius"], command)

    def test_the_non_forcing_mutations_are_not_charged_as_destructions(self):
        """
        git refuses to lose commits for these on its own (rc=1 / rc=128,
        measured).  Charging them to R5's cumulative delete budget would price
        ordinary branch hygiene as destruction -- the RFX-249 over-blocking cost
        `_infra_destructive`'s account branch already weighs.
        """
        for command in self.NON_FORCING_MUTATIONS:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertEqual("execute", cls["verb"], command)
                self.assertEqual("none", cls["danger_signature"], command)

    def test_the_force_delete_names_the_branch_it_destroys(self):
        """RFX-206/RFX-341: "a delete was held" is not something an auditor can
        check unless the record says WHICH ref."""
        self.assertEqual("main", _cls("git branch -D main")["target_ref"])
        self.assertEqual("release/1",
                         _cls("git branch --delete --force release/1")["target_ref"])


class TestGitOutputFlagIsAWholeFileDestruction(unittest.TestCase):
    """`git diff|log|show --output=P` destroys P.  Canary-verified."""

    WEIGHTY = [
        "git diff --output=/srv/prod/db.sqlite",
        "git log --output=/srv/prod/db.sqlite",
        "git show HEAD --output=/srv/prod/db.sqlite",
        "git diff --output /srv/prod/db.sqlite",
    ]

    def test_output_over_a_weighty_path_is_a_destruction(self):
        for command in self.WEIGHTY:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertEqual("delete", cls["verb"], command)
                self.assertEqual("irreversible", cls["reversibility"], command)
                self.assertNotEqual("benign", cls["classification_tier"], command)

    def test_the_destruction_names_the_file(self):
        self.assertEqual(
            "/srv/prod/db.sqlite",
            _cls("git diff --output=/srv/prod/db.sqlite")["target_ref"])

    def test_the_o_spelling_git_refuses_is_not_priced(self):
        """
        `git diff -o P` exits 128 and writes nothing; `-oP` exits 129.  If this
        ever starts pricing a destruction, the fix has been rewired onto
        `_flag_value` and is asserting a command that cannot run.
        """
        for command in ("git diff -o /srv/prod/db.sqlite",
                        "git diff -o/srv/prod/db.sqlite"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _cls(command)["verb"], command)


class TestOrdinaryGitIsUntouched(unittest.TestCase):
    """
    The over-call half.  Every one of these was read/benign before the fix and
    must still be -- a classifier change that quiets the fail-open by pricing
    routine work as destruction has replaced one defect with another.
    """

    READS = [
        "git status", "git status -s", "git status --porcelain",
        "git log", "git log --oneline -20", "git log -p", "git log --graph --all",
        "git diff", "git diff HEAD~1", "git diff --stat", "git diff --cached",
        "git show HEAD", "git show HEAD --stat", "git show v1.0:README.md",
        # `git branch` the LISTING -- the reason `branch` is in the read table
        "git branch", "git branch -a", "git branch -r", "git branch -v",
        "git branch --list", "git branch --show-current",
        "git branch --contains HEAD", "git branch --merged",
        "git branch --sort=-committerdate",
        # creating a branch names a new ref; it destroys nothing
        "git branch newfeature", "git branch newfeature origin/main",
    ]

    ORDINARY_OUTPUT = [
        "git diff --output=/tmp/build.diff",
        "git log --output=out.log",
        "git diff --output=build/changes.txt",
    ]

    def test_read_only_git_is_still_a_read(self):
        for command in self.READS:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertEqual("read", cls["verb"], command)
                self.assertEqual("benign", cls["classification_tier"], command)

    def test_output_to_ordinary_paths_is_not_a_destruction(self):
        """
        The weighty gate, reused rather than re-implemented.  Charging every
        `git diff --output=build.diff` in every CI script to R5's cumulative
        delete budget is a cost no single-decision probe can see.
        """
        for command in self.ORDINARY_OUTPUT:
            with self.subTest(command=command):
                cls = _cls(command)
                self.assertEqual("read", cls["verb"], command)
                self.assertEqual("benign", cls["classification_tier"], command)


class TestTheAdjacencyDirectionIsUnchangedAndFailsClosed(unittest.TestCase):
    """
    qa--248 flagged the other half of this table as unmeasured.  It is measured
    now and it is NOT a fail-open: a global option before the subcommand loses
    the read arm and falls to EXECUTE, which is noisier rather than weaker.
    Pinned so nobody re-measures it, and so a later "fix" that makes these reads
    again has to argue with a test.
    """

    def test_a_global_option_before_the_subcommand_does_not_read(self):
        for command in ("git -c core.pager=cat status",
                        "git --no-pager log",
                        "git -C /tmp status"):
            with self.subTest(command=command):
                self.assertEqual("execute", _cls(command)["verb"], command)


class TestTheBudgetIsWhereTheRefDeleteHalfShowsUp(unittest.TestCase):
    """
    The `git branch -D` half does not flip a single decision: core allows a
    scoped irreversible delete at call 1, exactly as it allows `userdel alice`.
    Asserting a verdict flip here would be asserting something false.

    What changed is that the action now reaches R5's cumulative delete budget
    at all.  Measured through the real pack in the RFX-358 report: on main the
    same command ran 40 times untouched; with the fix the session turns over at
    call 21 under `reeflex.policy/session_delete_budget`.  This test pins the
    classifier-side precondition for that -- the verb core counts.
    """

    def test_the_force_delete_is_counted_as_a_delete(self):
        self.assertEqual("delete", _cls("git branch -D main")["verb"])

    def test_the_listing_is_not_counted_as_a_delete(self):
        self.assertNotEqual("delete", _cls("git branch -a")["verb"])
        self.assertNotEqual("delete", _cls("git branch")["verb"])


if __name__ == "__main__":
    unittest.main()
