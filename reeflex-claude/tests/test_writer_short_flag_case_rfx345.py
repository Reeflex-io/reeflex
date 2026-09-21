"""RFX-345 -- the writer family's directory-destination bail failed open three
ways, and the case-fold the ticket names is only the first of them.

`_writer_overwrite_targets` refuses to price a destruction when the invocation
says its destination is a DIRECTORY, because which file inside a directory gets
overwritten cannot be resolved without touching the filesystem.  That bail is
RIGHT.  What was wrong was the test for it: ONE shared flag set
(`-t --target-directory -d --directory`), matched against `low` -- the
LOWERCASED argument list -- for all five writer commands.

  1. CASE.  `-T` is `--no-target-directory`: it asserts the destination is a
     FILE, the exact opposite of `-t`.  It folded to `-t` and switched the
     destruction pricing off.  `install -D` folded to `install -d` the same
     way.  So the LONG spelling `cp --no-target-directory /dev/null P` was
     priced delete/irreversible/broad and the SHORT `cp -T /dev/null P` was
     priced execute/recoverable/scoped -- same command, same effect, opposite
     answers.
  2. COMMAND.  `-d` is not a directory destination in `cp`; it is
     `--no-dereference --preserve=links`.  A shared set cannot know which
     command word it is answering for.
  3. COMMAND, with its own discriminator.  In `sort`, `-t` is the FIELD
     SEPARATOR and `-d` is `--dictionary-order`.  The SPACED `sort -t : -o P`
     bailed while the ATTACHED `sort -t: -o P` was priced correctly -- one
     command, one effect, two answers, which is the tell that the bail was
     matching a token and never reading a fact about the command.

GROUND TRUTH WAS EXECUTED, NOT ASSERTED.  Every DESTROYS line below emptied a
synthetic canary carrying five lines in a real /bin/bash, and every SURVIVES
line left its canary at five of five.

  INSTRUMENT, because it REVERSES the result: `cp` and `mv` are aliased to `-i`
  on this devbox.  The aliased run prompts, gets no answer, declines the
  overwrite and EXITS 0 with the canary intact -- so a real destroyer reads as
  safe.  The rig's own control caught it: `cp /dev/null P`, which RFX-343's
  executed ground truth already says destroys, read SURVIVED under the alias
  and DESTROYED under /usr/bin/cp.  Evidence:
  code-reports/dev-2--080--20260918-evidence/02-ground-truth.txt.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv, /etc or /var is created, opened, written or executed by this module.
"""

import unittest

from reeflex_claude.classify import classify


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"

# Each line below emptied the canary in a real bash.  Evidence:
# dev-2--080--20260918-evidence/{02,03,05}-ground-truth*.txt
DESTROYING = (
    "cp -T /dev/null %s" % PROD,
    "mv -T /tmp/replacement.dat %s" % PROD,
    "install -T /dev/null %s" % PROD,
    "install -D /dev/null %s" % PROD,
    "cp -d /dev/null %s" % PROD,
    "cp -aT /dev/null %s" % PROD,
    "sort -t : -k1 -o %s /tmp/in.txt" % PROD,
    "sort -d -o %s /tmp/in.txt" % PROD,
)

# Each line below left its canary at five of five, and the directory it wrote
# into kept every entry it started with.
NOT_DESTROYING = (
    "cp -t /srv/prod/ ./a.sql",
    "mv -t /srv/prod/ ./a.sql",
    "cp --target-directory=/srv/prod/ ./a.sql",
    "cp -at /srv/prod/ ./a.sql",
    "install -d /srv/prod/newdir",
    "install --directory /srv/prod/newdir",
    "cp ./a.sql ./b.sql /var/lib/pgsql/data/",
    "cp ./a.sql ./b.sql %s" % PROD,
    # THE SPACED LONG SPELLING, and it is here because a sabotage arm found it
    # missing.  Disabling the exact-token branch moved NO verdict across the
    # whole corpus and every assertion above -- the one-letter bundle test
    # covers a bare `-t`, and `--target-directory=DIR` leaves too few
    # positionals to price.  `--target-directory DIR` with TWO positionals is
    # the shape where that branch is the only thing standing, and nothing
    # asserted it.  Evidence: 11-exact-branch-loadbearing.txt.
    "mv --target-directory /srv/backup/ %s" % PROD,
    "cp --target-directory /srv/prod/ %s" % PROD,
    "install --target-directory /srv/prod/ %s" % PROD,
)


class TestTheShortFlagIsNotTheLongFlagLowercased(unittest.TestCase):
    """A destruction is priced the same however its flag is spelled."""

    def test_every_bailed_shape_that_destroys_is_now_a_delete(self):
        for command in DESTROYING:
            with self.subTest(command=command):
                self.assertEqual("delete", _c(command)["verb"])

    def test_and_it_names_the_file_it_destroyed(self):
        """target_ref is the half R6 matches on and the audit line prints.

        Pricing the destruction while reporting `target_ref=null` closes only
        half of this: the protected-path rule has no path to match, and "a
        delete was held in production" is not something an auditor can check
        against a record that does not say WHICH file.
        """
        for command in DESTROYING:
            with self.subTest(command=command):
                self.assertEqual(PROD, _c(command)["target_ref"])

    def test_the_short_and_long_spellings_of_one_flag_agree(self):
        """The defect stated as the comparison that exposes it.

        Compared to EACH OTHER rather than each to a constant: if the pricing
        of whole-file destruction ever moves, this moves with it instead of
        pinning a stale answer -- and it still fails the moment the two
        spellings diverge again.
        """
        pairs = (
            ("cp -T /dev/null %s" % PROD,
             "cp --no-target-directory /dev/null %s" % PROD),
            ("mv -T /tmp/replacement.dat %s" % PROD,
             "mv --no-target-directory /tmp/replacement.dat %s" % PROD),
            ("install -T /dev/null %s" % PROD,
             "install --no-target-directory /dev/null %s" % PROD),
        )
        for short, long_ in pairs:
            with self.subTest(short=short):
                s, l = _c(short), _c(long_)
                for axis in ("verb", "reversibility", "blast_radius",
                             "classification_tier", "target_ref"):
                    self.assertEqual(
                        l[axis], s[axis],
                        "%s differs between the short and long spelling of "
                        "one flag" % axis)

    def test_the_spaced_and_attached_spellings_of_sort_t_agree(self):
        """`sort -t :` and `sort -t:` are one invocation written two ways.

        This pair is what proved the bail was a token match rather than a fact
        about the command: on main the attached form was priced correctly and
        the spaced form was not.
        """
        spaced = _c("sort -t : -k1 -o %s /tmp/in.txt" % PROD)
        attached = _c("sort -t: -k1 -o %s /tmp/in.txt" % PROD)
        for axis in ("verb", "reversibility", "blast_radius",
                     "classification_tier", "target_ref"):
            self.assertEqual(attached[axis], spaced[axis], axis)

    def test_it_prices_like_the_shapes_already_caught(self):
        """These land where `truncate -s 0` and the RFX-343 family already do.

        Against the shipped reference shape, not hardcoded strings.
        """
        reference = _c("truncate -s 0 %s" % PROD)
        for command in DESTROYING:
            with self.subTest(command=command):
                cls = _c(command)
                for axis in ("verb", "reversibility", "blast_radius",
                             "classification_tier"):
                    self.assertEqual(reference[axis], cls[axis], axis)


class TestTheBailOnARealDirectoryStays(unittest.TestCase):
    """The half a careless fix breaks.

    Reading `args` instead of `low` while dropping the `-t` handling would turn
    every line here into a claimed destruction of a directory that measurably
    survives.  These are therefore the rows that fail first, and they are
    asserted on the RECORD as well as the verdict: a destruction of
    `/srv/prod/` is not made acceptable by being answered `allow`.
    """

    def test_a_genuine_directory_destination_is_not_priced(self):
        for command in NOT_DESTROYING:
            with self.subTest(command=command):
                self.assertEqual("execute", _c(command)["verb"])

    def test_and_names_no_destroyed_resource(self):
        for command in NOT_DESTROYING:
            with self.subTest(command=command):
                self.assertIsNone(_c(command)["target_ref"])

    def test_the_bundled_target_directory_does_not_name_the_source(self):
        """`cp -at DIR src` priced a destruction of SRC, which it reads.

        Fail-CLOSED, so never exposure -- but a record naming a resource
        nothing touched is not a record an auditor can check, and it is the
        same defect as naming the directory.
        """
        cls = _c("cp -at /tmp/ %s" % PROD)
        self.assertEqual("execute", cls["verb"])
        self.assertIsNone(cls["target_ref"])

    def test_three_positionals_name_no_destroyed_file(self):
        """EXECUTED both ways, and neither destroys the last positional.

        `cp a b DIR/` exits 0 with DIR and its contents intact; `cp a b FILE`
        exits 1 with "target is not a directory" and FILE intact.  Before this
        fix the last positional was taken as the destroyed file, so
        `cp ./a.sql ./b.sql /var/lib/pgsql/data/` was reported
        delete/irreversible/systemic against a directory that survived.
        """
        for command in ("cp ./a.sql ./b.sql /var/lib/pgsql/data/",
                        "cp ./a.sql ./b.sql %s" % PROD,
                        "mv ./a.sql ./b.sql /var/lib/pgsql/data/"):
            with self.subTest(command=command):
                cls = _c(command)
                self.assertEqual("execute", cls["verb"])
                self.assertIsNone(cls["target_ref"])

    def test_the_spaced_long_flag_is_the_exact_branch_standing_alone(self):
        """`mv --target-directory DIR FILE` -- the case a sabotage arm found.

        Bundles cannot match a `--` flag and the `=` spelling is caught by the
        positional count, so this is the only shape where matching the flag
        token itself decides the answer.  EXECUTED: the original path is gone
        and all five canary lines are recoverable at the new one -- which is
        the `gzip` exclusion this function's own docstring names, "P is gone,
        but its bytes are not".  Pricing it delete/irreversible would state
        something measurably untrue, so `execute` is the truthful answer and
        not merely the conservative one.
        """
        for command in ("mv --target-directory /srv/backup/ %s" % PROD,
                        "cp --target-directory /srv/prod/ %s" % PROD,
                        "install --target-directory /srv/prod/ %s" % PROD):
            with self.subTest(command=command):
                cls = _c(command)
                self.assertEqual("execute", cls["verb"])
                self.assertIsNone(cls["target_ref"])

    def test_two_positionals_are_still_priced(self):
        """The non-vacuity control for the test above.

        If `> 2` were ever written `>= 2` the whole writer family would stop
        being priced and every assertion in the class above would still pass,
        because they all assert on shapes that are supposed to bail.
        """
        cls = _c("cp /tmp/replacement.dat %s" % PROD)
        self.assertEqual("delete", cls["verb"])
        self.assertEqual(PROD, cls["target_ref"])


class TestTheFlagSetIsKeyedByCommand(unittest.TestCase):
    """`-t` and `-d` do not mean the same thing in every writer command.

    Asserted against the table rather than through `classify()` alone, because
    a future writer command added to `_WRITER_COMMANDS` with no entry here
    inherits an empty set -- which is the fail-CLOSED direction, and is the
    behaviour this pins.
    """

    def test_tee_and_sort_have_no_directory_destination_flag(self):
        from reeflex_claude.classify import _WRITER_DIR_DEST_FLAGS
        for cmd in ("tee", "sort"):
            exact, letters = _WRITER_DIR_DEST_FLAGS[cmd]
            self.assertEqual(frozenset(), exact, cmd)
            self.assertEqual("", letters, cmd)

    def test_no_uppercase_flag_is_in_any_entry(self):
        """`-T` and `-D` assert the destination is a FILE.

        Stated over the whole table rather than as four separate cases, so a
        flag added later cannot reintroduce the fold in a command nobody
        thought to write a case for.
        """
        from reeflex_claude.classify import _WRITER_DIR_DEST_FLAGS
        for cmd, (exact, letters) in _WRITER_DIR_DEST_FLAGS.items():
            for flag in exact:
                self.assertEqual(flag, flag.lower(),
                                 "%s: %s is not lowercase" % (cmd, flag))
            self.assertEqual(letters, letters.lower(), cmd)

    def test_cp_and_mv_do_not_treat_minus_d_as_a_directory(self):
        from reeflex_claude.classify import _WRITER_DIR_DEST_FLAGS
        for cmd in ("cp", "mv"):
            exact, letters = _WRITER_DIR_DEST_FLAGS[cmd]
            self.assertNotIn("-d", exact, cmd)
            self.assertNotIn("d", letters, cmd)

    def test_every_writer_command_has_an_entry(self):
        """A command in the family with no entry here is a silent empty set.

        Empty is the safe default, but it should be a DECISION -- `install`
        genuinely needs `-d` and `cp` genuinely must not have it.
        """
        from reeflex_claude.classify import (_WRITER_COMMANDS,
                                             _WRITER_DIR_DEST_FLAGS)
        self.assertEqual(set(_WRITER_COMMANDS), set(_WRITER_DIR_DEST_FLAGS))

    def test_every_writer_command_has_a_value_letter_entry(self):
        """The SIBLING table, for the reason the test above already exists.

        `_WRITER_VALUE_LETTERS` is read with `.get(cmd0, "")`, so a command
        missing from it also gets a silent empty set -- and the empty set is
        the FAIL-OPEN direction here: with no value letters, a bundle scan
        reads an option's VALUE as a flag letter, which is the exact defect
        RFX-345's second commit closed.

        Added by qa--257 because this guard's twin caught `git` missing from
        the other table after RFX-358 added it to the family, and nothing
        would have caught the same omission here.
        """
        from reeflex_claude.classify import (_WRITER_COMMANDS,
                                             _WRITER_VALUE_LETTERS)
        self.assertEqual(set(_WRITER_COMMANDS), set(_WRITER_VALUE_LETTERS))


if __name__ == "__main__":
    unittest.main()
