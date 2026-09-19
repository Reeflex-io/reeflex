"""RFX-366 + RFX-361 -- the caller chose the verdict by how far they spelled a flag.

Every flag test in `classify.py` compared an argv token to one LITERAL long-option
spelling.  Both argv parsers the module reads -- GNU getopt_long and git's
parse-options -- resolve an unambiguous ABBREVIATION of a long option.  So the
same destruction, written two ways, scored two different verdicts, and the
cheaper one was the caller's to pick:

    sort --output /srv/prod/db.sqlite in.txt   -> irreversible/broad  require_approval
    sort --out    /srv/prod/db.sqlite in.txt   -> recoverable/scoped  ALLOW
    sort --o      /srv/prod/db.sqlite in.txt   -> recoverable/scoped  ALLOW

Those two decisions are core's, not a transcription: taken through
`reeflex-core/app/opa.py` over `reeflex-core/policy/*.rego` on the real `opa`
binary, with `decide.py` Step 6's `cumulative`/`approval.present` overwrites
reproduced.  Six shapes moved allow -> require_approval and two moved
require_approval -> allow when the resolver landed.

GROUND TRUTH.  Every verdict pinned in this module was EXECUTED first, on this
box, against synthetic five-line canary victims under /tmp and a LOCAL bare git
repo -- no network, no remote, nothing outside the sandbox -- and read off the
filesystem, or off the bare repo's own refs with `for-each-ref`.  coreutils 8.32,
git 2.52.0:

    sort --output/--outpu/--outp/--out/--ou/--o VICTIM  -> canary 0/5, all six
    tee  --append/--appen/--appe/--app/--ap/--a VICTIM  -> canary 5/5, all six
    tee  --output-error VICTIM                          -> canary 0/5
    cp   --target-directory/--target-dir/--targ/--tar/--ta/--t DIR SRC
                                                        -> SRC 5/5, all six
    cp   --no-target-directory/--no-target/--no-targ/--no-t SRC VICTIM
                                                        -> canary 0/5, all four
    cp   --no SRC VICTIM      -> rc=1 "option '--no' is ambiguous", canary 5/5
    truncate --size/--siz/--si/--s 0 VICTIM             -> canary 0/5, all four
    git push --delete/--dele/--del/--de origin doomed   -> upstream refs
                                        [doomed main] -> [main], all four
    git push --mirror/--mirro/--mir/--mi/--m origin     -> same, all five
    git push --prune/--pru origin 'refs/heads/*'        -> same, both
    git push --d / --pr / --p                           -> rc=129 ambiguous
    git push --force origin main                        -> "(forced update)"
    git push --forc / --for / --fo / --f                -> rc=129 ambiguous
    git push --force-with origin main                   -> "(forced update)"
    git clean --force/--forc/--fo/--f untracked.txt     -> REMOVED, all four
    git clean -f --dry-run/--dry/--dr/--d untracked.txt -> SURVIVES, all four
    git branch --delete/--dele/--del/--de/--d doomed    -> "Deleted branch"
    git branch --fo                                     -> rc=129 ambiguous
    git diff|log|show --outpu/--outp/--out/--ou/--o P   -> rc=128, canary 5/5

THE TWO RESULTS THAT KILL THE OBVIOUS FIX, and both are pinned below:

1.  A blanket `startswith` is wrong.  `cp --targ DIR SRC` and `cp --no-t SRC
    FILE` are three characters apart and mean OPPOSITE things -- the first
    destroys nothing, the second destroys FILE.
2.  "Tools resolve any unique prefix" is not true of git.  `git diff --out` is
    NOT `--output`: exit 128, canary intact, because those options are read by
    the revision parser rather than by parse-options.  `_git_output_target` is
    therefore deliberately unchanged, and `TestGitDiffOutputDoesNotAbbreviate`
    exists to keep a later round from "finishing the job".

And the discriminating pair that forces the table to be keyed PER SUBCOMMAND:
`--f` is unambiguously `--force` for `git clean` and is AMBIGUOUS for `git push`
(--follow-tags/--force/--force-if-includes/--force-with-lease).  One shared
table would be wrong for exactly one of them.

Pure: no network, no I/O, no side effects.  The production-looking paths are
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

from reeflex_claude.classify import (            # noqa: E402
    _canonical_long_flags,
    _resolve_long_flag,
    classify,
)

DB = "/srv/prod/db.sqlite"


def _cls(command):
    return classify("Bash", {"command": command})


def _prices_destruction(c):
    """Did this classification price a whole-file / ref destruction?"""
    return (c.get("danger_signature") not in (None, "none")
            or c.get("blast_radius") in ("broad", "systemic"))


class TestResolverMirrorsTheMeasuredParsers(unittest.TestCase):
    """The resolver's answer must equal what the binary actually did.

    Each row is `(command_key, token, expected)` where `expected` is the option
    the real parser resolved the token to, or None where the real parser exited
    non-zero.  Every one of these was executed; see the module docstring.
    """

    RESOLVES = [
        # unique prefixes, all the way down to one letter
        ("sort", "--output", "--output"), ("sort", "--outpu", "--output"),
        ("sort", "--outp", "--output"), ("sort", "--out", "--output"),
        ("sort", "--ou", "--output"), ("sort", "--o", "--output"),
        ("tee", "--append", "--append"), ("tee", "--appen", "--append"),
        ("tee", "--app", "--append"), ("tee", "--ap", "--append"),
        ("tee", "--a", "--append"),
        ("tee", "--o", "--output-error"),
        ("cp", "--targ", "--target-directory"), ("cp", "--t", "--target-directory"),
        ("cp", "--no-t", "--no-target-directory"),
        ("cp", "--suf", "--suffix"), ("cp", "--f", "--force"),
        ("install", "--mod", "--mode"), ("install", "--dir", "--directory"),
        ("truncate", "--siz", "--size"), ("truncate", "--s", "--size"),
        ("truncate", "--r", "--reference"),
        ("git push", "--dele", "--delete"), ("git push", "--del", "--delete"),
        ("git push", "--de", "--delete"),
        ("git push", "--mir", "--mirror"), ("git push", "--m", "--mirror"),
        ("git push", "--pru", "--prune"),
        ("git push", "--force-with", "--force-with-lease"),
        ("git clean", "--forc", "--force"), ("git clean", "--f", "--force"),
        ("git clean", "--dry", "--dry-run"), ("git clean", "--d", "--dry-run"),
        ("git branch", "--del", "--delete"), ("git branch", "--d", "--delete"),
        ("git branch", "--forc", "--force"),
        # EXACT MATCH WINS over the longer options it prefixes.
        # `git push --force` forced the update; `--forc` did not.
        ("git push", "--force", "--force"),
        ("cp", "--backup", "--backup"),
        # AMBIGUOUS -> the tool exits 129/1 and nothing happens, so None.
        ("git push", "--d", None),      # --delete or --dry-run
        ("git push", "--pr", None),     # --progress or --prune
        ("git push", "--p", None),      # --prune or --push-option
        ("git push", "--forc", None),   # --force-with-lease or --force-if-includes
        ("git push", "--for", None), ("git push", "--fo", None),
        ("git push", "--f", None),
        ("git branch", "--fo", None),   # --force or --format
        ("cp", "--no", None),           # --no-clobber/--no-dereference/...
        ("cp", "--c", None),            # --copy-contents or --context
        # NOT AN OPTION OF THIS COMMAND AT ALL
        ("sort", "--nonesuch", None),
        ("tee", "--target-directory", None),
        # NO TABLE -> never resolved.  `git diff --out` is measured NOT to
        # abbreviate, and `dd` has no entry either.
        ("git diff", "--out", None),
        ("dd", "--of", None),
        ("", "--output", None),
    ]

    def test_every_resolution_matches_the_binary(self):
        for key, token, expected in self.RESOLVES:
            with self.subTest(command=key, token=token):
                self.assertEqual(_resolve_long_flag(key, token), expected)

    def test_resolution_is_case_sensitive(self):
        """`sort --OUT` is "unrecognized option", measured rc=2, canary 5/5."""
        self.assertIsNone(_resolve_long_flag("sort", "--OUT"))
        self.assertIsNone(_resolve_long_flag("git push", "--DELETE"))

    def test_a_short_flag_is_never_resolved(self):
        """Neither parser abbreviates short flags; the bundle tests rely on it."""
        for token in ("-o", "-output", "-", "--"):
            with self.subTest(token=token):
                self.assertIsNone(_resolve_long_flag("sort", token))


class TestCanonicalisationKeepsArgvAligned(unittest.TestCase):
    """Rewriting is TOKEN FOR TOKEN, or every index downstream shifts."""

    def test_value_and_operand_positions_are_unchanged(self):
        self.assertEqual(
            _canonical_long_flags("sort", ["--out", DB, "in.txt"]),
            ["--output", DB, "in.txt"])

    def test_attached_value_keeps_its_value(self):
        """`sort --o=P` truncated P, measured: the `=` spelling abbreviates too."""
        self.assertEqual(_canonical_long_flags("sort", ["--o=" + DB]),
                         ["--output=" + DB])
        self.assertEqual(_canonical_long_flags("cp", ["--suf=.bak"]),
                         ["--suffix=.bak"])

    def test_an_unresolvable_token_is_left_exactly_as_written(self):
        """A token the tool refuses must not silently become a different flag."""
        self.assertEqual(_canonical_long_flags("git push", ["--forc", "origin"]),
                         ["--forc", "origin"])

    def test_a_bare_double_dash_ends_option_parsing(self):
        """`sort -- --out P` reads `--out` as a FILE NAME; P survived 5/5."""
        self.assertEqual(_canonical_long_flags("sort", ["--", "--out", DB]),
                         ["--", "--out", DB])

    def test_a_command_with_no_table_is_returned_unchanged(self):
        args = ["--out", DB, "HEAD"]
        self.assertIs(_canonical_long_flags("git diff", args), args)


class TestSortOutputPrefixesAreTheSameDestruction(unittest.TestCase):
    """RFX-366's headline: five spellings truncated the file, one was priced."""

    DESTROYS = [
        "sort --output %s in.txt" % DB,
        "sort --outpu %s in.txt" % DB,
        "sort --outp %s in.txt" % DB,          # <- allowed before RFX-366
        "sort --out %s in.txt" % DB,           # <- allowed before RFX-366
        "sort --ou %s in.txt" % DB,            # <- allowed before RFX-366
        "sort --o %s in.txt" % DB,             # <- allowed before RFX-366
        "sort --out=%s in.txt" % DB,           # <- allowed before RFX-366
        "sort --o=%s in.txt" % DB,             # <- allowed before RFX-366
        "sort -o %s in.txt" % DB,
    ]

    def test_every_spelling_prices_the_destruction(self):
        for command in self.DESTROYS:
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["reversibility"], "irreversible")
                self.assertEqual(c["blast_radius"], "broad")
                self.assertEqual(c["danger_signature"], "overwrite_container")

    def test_the_audit_line_names_the_file_that_dies(self):
        """A record that does not name the resource is not auditable (RFX-206)."""
        for command in self.DESTROYS:
            with self.subTest(command=command):
                self.assertEqual(_cls(command)["target_ref"], DB)

    def test_sort_without_the_flag_still_writes_to_stdout(self):
        self.assertFalse(_prices_destruction(_cls("sort %s" % DB)))

    def test_a_case_folded_spelling_is_not_an_option_at_all(self):
        """`sort --OUT` is rejected by sort; pricing it would be untrue."""
        self.assertFalse(_prices_destruction(_cls("sort --OUT %s in.txt" % DB)))

    def test_after_a_bare_double_dash_the_token_is_a_filename(self):
        self.assertFalse(_prices_destruction(_cls("sort -- --out %s" % DB)))


class TestTeeAppendPrefixesAreNotDestructions(unittest.TestCase):
    """The fail-NOISY half, and it matters on its own.

    All five canary lines survived every one of these, and each was priced an
    irreversible broad destruction of the file it had just left intact.  A gate
    that asks on an append is a gate that gets switched off (RFX-131, RFX-145).
    """

    SURVIVES = [
        "echo x | tee --append %s" % DB,
        "echo x | tee --appen %s" % DB,        # <- held before RFX-366
        "echo x | tee --app %s" % DB,          # <- held before RFX-366
        "echo x | tee --ap %s" % DB,           # <- held before RFX-366
        "echo x | tee --a %s" % DB,            # <- held before RFX-366
    ]

    def test_no_append_spelling_prices_a_destruction(self):
        for command in self.SURVIVES:
            with self.subTest(command=command):
                self.assertFalse(_prices_destruction(_cls(command)))

    def test_tee_without_append_still_truncates(self):
        c = _cls("echo x | tee %s" % DB)
        self.assertEqual(c["danger_signature"], "overwrite_container")
        self.assertEqual(c["target_ref"], DB)

    def test_output_error_does_not_eat_the_operand(self):
        """A fail-open found beside the abbreviation one, not caused by it.

        `--output-error` carries an OPTIONAL value, which getopt_long accepts
        only ATTACHED.  `tee --output-error VICTIM` truncated VICTIM (0/5), but
        the flag was listed as consuming the next word, so the operand that
        died was dropped before anything was priced.
        """
        for command in ("echo x | tee --output-error %s" % DB,
                        "echo x | tee --output-error=warn %s" % DB):
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["danger_signature"], "overwrite_container")
                self.assertEqual(c["target_ref"], DB)


class TestTargetDirectoryAndItsOppositeAreNotFolded(unittest.TestCase):
    """The pair that proves a blanket `startswith` would be wrong.

    `--targ` and `--no-t` are three characters apart and mean opposite things.
    """

    def test_target_directory_prefixes_destroy_nothing(self):
        for command in ("cp --target-directory /srv/prod/ %s" % DB,
                        "cp --targ /srv/prod/ %s" % DB,
                        "cp --ta /srv/prod/ %s" % DB,
                        "cp --t /srv/prod/ %s" % DB,
                        "mv --targ /srv/prod/ %s" % DB):
            with self.subTest(command=command):
                self.assertFalse(_prices_destruction(_cls(command)))

    def test_no_target_directory_prefixes_still_destroy_the_destination(self):
        for command in ("cp --no-target-directory /tmp/src %s" % DB,
                        "cp --no-target /tmp/src %s" % DB,
                        "cp --no-targ /tmp/src %s" % DB,
                        "cp --no-t /tmp/src %s" % DB):
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["danger_signature"], "overwrite_container")
                self.assertEqual(c["target_ref"], DB)

    def test_an_abbreviated_value_flag_does_not_move_the_destination(self):
        """`--suf` unresolved made `.bak` the last positional, so the audit
        line named `.bak` while the database was the file overwritten."""
        c = _cls("cp /tmp/src %s --suf .bak" % DB)
        self.assertEqual(c["target_ref"], DB)
        c = _cls("install --mod 644 /tmp/src %s" % DB)
        self.assertEqual(c["target_ref"], DB)

    def test_truncate_size_prefixes_name_the_file_and_not_the_size(self):
        """Unresolved, the SIZE counted as a second path and target_ref went null."""
        for command in ("truncate --size 0 %s" % DB,
                        "truncate --siz 0 %s" % DB,
                        "truncate --s 0 %s" % DB):
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["target_ref"], DB)
                self.assertEqual(c["magnitude_count"], 1)


class TestGitPushPrefixesThatRemoveARemoteRef(unittest.TestCase):
    """RFX-361.  Read off the bare repo's refs, not off git's stdout."""

    FORCES = [
        "git push --delete origin doomed",
        "git push --dele origin doomed",       # <- allowed before RFX-361
        "git push --del origin doomed",        # <- allowed before RFX-361
        "git push --de origin doomed",         # <- allowed before RFX-361
        "git push --mirror origin",
        "git push --mir origin",               # <- allowed before RFX-361
        "git push --mi origin",                # <- allowed before RFX-361
        "git push --m origin",                 # <- allowed before RFX-361
        "git push --prune origin refs/heads/*",   # <- absent from the table
        "git push --pru origin refs/heads/*",     # <- absent from the table
        "git push --force origin main",
        "git push --force-with-lease origin main",
        "git push --force-with origin main",   # <- allowed before RFX-361
    ]

    def test_every_measured_ref_destruction_reaches_the_emit_arm(self):
        for command in self.FORCES:
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["danger_signature"], "git_force_push")
                self.assertEqual(c["blast_radius"], "broad")


class TestGitPushAmbiguousPrefixesAreNotForcePushes(unittest.TestCase):
    """git exits 129 and no ref moves, so pricing a force push would be untrue.

    This is the arm both tickets proposed getting WRONG: RFX-361 filed `--forc`
    as a force-push escape, and it is not one.
    """

    REFUSED = [
        "git push --d origin doomed",
        "git push --pr origin refs/heads/*",
        "git push --p origin refs/heads/*",
        "git push --forc origin main",
        "git push --for origin main",
        "git push --fo origin main",
        "git push --f origin main",
    ]

    def test_an_ambiguous_prefix_is_not_priced_as_a_force_push(self):
        for command in self.REFUSED:
            with self.subTest(command=command):
                self.assertNotEqual(_cls(command)["danger_signature"],
                                    "git_force_push")

    def test_force_if_includes_still_never_forces_on_its_own(self):
        """A SAFETY modifier; measured rc=1, refs unchanged."""
        for command in ("git push --force-if-includes origin main",
                        "git push --force-if origin main"):
            with self.subTest(command=command):
                self.assertNotEqual(_cls(command)["danger_signature"],
                                    "git_force_push")

    def test_dry_run_stays_dominant_when_abbreviated(self):
        for command in ("git push --dry-run --force origin main",
                        "git push --dry --force origin main"):
            with self.subTest(command=command):
                self.assertNotEqual(_cls(command)["danger_signature"],
                                    "git_force_push")


class TestGitCleanPrefixesInBothDirections(unittest.TestCase):
    """`--f` is `--force` HERE and ambiguous for `git push`: hence per-subcommand."""

    def test_force_prefixes_remove(self):
        for command in ("git clean --force /srv/prod/data",
                        "git clean --forc /srv/prod/data",
                        "git clean --fo /srv/prod/data",
                        "git clean --f /srv/prod/data"):
            with self.subTest(command=command):
                c = _cls(command)
                self.assertEqual(c["danger_signature"], "rm_recursive")
                self.assertEqual(c["blast_radius"], "broad")

    def test_dry_run_prefixes_remove_nothing(self):
        for command in ("git clean -f --dry-run /srv/prod/data",
                        "git clean -f --dry /srv/prod/data",
                        "git clean -f --dr /srv/prod/data",
                        "git clean -f --d /srv/prod/data"):
            with self.subTest(command=command):
                self.assertFalse(_prices_destruction(_cls(command)))

    def test_the_same_token_answers_differently_for_push_and_clean(self):
        """The discriminating pair.  One shared table would be wrong for one."""
        self.assertEqual(_resolve_long_flag("git clean", "--f"), "--force")
        self.assertIsNone(_resolve_long_flag("git push", "--f"))


class TestGitBranchDeletePrefixesLeaveTheReadArm(unittest.TestCase):
    """`git branch --del` deleted the branch and priced BELOW `--delete`.

    Unresolved it left `mutates` False, so the line took the READ arm at
    `_READ_GIT_SUBCOMMANDS` and came out reversible/single -- a lower tier than
    the spelled-out flag's recoverable/scoped.
    """

    def test_every_delete_spelling_leaves_the_read_arm(self):
        full = _cls("git branch --delete doomed")
        for command in ("git branch --delete doomed",
                        "git branch --dele doomed",
                        "git branch --del doomed",
                        "git branch --de doomed",
                        "git branch --d doomed"):
            with self.subTest(command=command):
                c = _cls(command)
                self.assertNotEqual((c["reversibility"], c["blast_radius"]),
                                    ("reversible", "single"))
                self.assertEqual(c["reversibility"], full["reversibility"])
                self.assertEqual(c["blast_radius"], full["blast_radius"])

    def test_listing_branches_is_still_a_read(self):
        c = _cls("git branch --list")
        self.assertEqual((c["reversibility"], c["blast_radius"]),
                         ("reversible", "single"))


class TestGitDiffOutputDoesNotAbbreviate(unittest.TestCase):
    """The exclusion that keeps a later round from "finishing the job".

    `git diff|log|show --output` is read by the revision parser, not by
    parse-options.  `--outpu`, `--outp`, `--out`, `--ou` and `--o` all exited
    128 with the canary intact 5/5.  Resolving them would price a destruction
    the binary refuses to perform.
    """

    def test_the_full_spelling_still_destroys(self):
        for sub in ("diff", "log", "show"):
            with self.subTest(sub=sub):
                c = _cls("git %s --output %s HEAD" % (sub, DB))
                self.assertEqual(c["danger_signature"], "overwrite_container")
                self.assertEqual(c["target_ref"], DB)

    def test_no_abbreviation_is_priced_as_a_destruction(self):
        for sub in ("diff", "log", "show"):
            for flag in ("--outpu", "--outp", "--out", "--ou", "--o"):
                with self.subTest(sub=sub, flag=flag):
                    self.assertFalse(
                        _prices_destruction(_cls("git %s %s %s HEAD" % (sub, flag, DB))))

    def test_those_subcommands_have_no_table(self):
        for sub in ("git diff", "git log", "git show"):
            with self.subTest(sub=sub):
                self.assertIsNone(_resolve_long_flag(sub, "--out"))


class TestTheTablesAreNotSilentlyEmpty(unittest.TestCase):
    """Anti-vacuity.  A resolver over an empty table resolves nothing and every
    assertion above that expects None would still pass."""

    EXPECTED_KEYS = {"sort", "tee", "cp", "mv", "install", "truncate",
                     "git push", "git clean", "git branch"}

    def test_every_command_this_module_prices_has_a_table(self):
        from reeflex_claude.classify import _LONG_OPTIONS_BY_COMMAND
        self.assertEqual(set(_LONG_OPTIONS_BY_COMMAND), self.EXPECTED_KEYS)

    def test_each_table_is_a_plausible_whole_option_list(self):
        """Ambiguity is a property of the WHOLE list.  A table trimmed to the
        flags this module cares about would call `git push --f` unique."""
        from reeflex_claude.classify import _LONG_OPTIONS_BY_COMMAND
        floors = {"sort": 25, "tee": 5, "cp": 25, "mv": 12, "install": 15,
                  "truncate": 6, "git push": 25, "git clean": 5,
                  "git branch": 25}
        for key, floor in floors.items():
            with self.subTest(command=key):
                self.assertGreaterEqual(len(_LONG_OPTIONS_BY_COMMAND[key]), floor)

    def test_the_options_this_module_prices_are_present_by_name(self):
        from reeflex_claude.classify import _LONG_OPTIONS_BY_COMMAND as T
        self.assertIn("--output", T["sort"])
        self.assertIn("--append", T["tee"])
        self.assertIn("--target-directory", T["cp"])
        self.assertIn("--no-target-directory", T["cp"])
        self.assertIn("--size", T["truncate"])
        for flag in ("--delete", "--mirror", "--prune", "--force",
                     "--force-with-lease", "--force-if-includes", "--dry-run"):
            self.assertIn(flag, T["git push"])
        self.assertIn("--force", T["git clean"])
        self.assertIn("--dry-run", T["git clean"])
        self.assertIn("--delete", T["git branch"])


if __name__ == "__main__":
    unittest.main()
