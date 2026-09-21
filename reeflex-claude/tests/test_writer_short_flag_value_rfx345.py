"""RFX-345, the review round: the fix for a token match introduced a token match.

PR #178 replaced one shared, lowercased flag set with a per-command one compared
against `args`.  That closes the case fold.  What it added in its place was
`_short_bundle_has(a, c)` -- `letter in arg[1:]`, a SUBSTRING test over the whole
rest of the token -- and a bail on three or more positionals.  Both read a short
option's VALUE as if it were a flag letter, which is the same class the ticket
was filed for: matching a token instead of reading a fact about the command.

getopt reads a bundle left to right and the FIRST letter that takes an argument
swallows the rest of the token as its value.  So:

  * `cp -St /dev/null P`      -- the `t` is the backup SUFFIX of `-S`.  Read as
    `--target-directory`, so the destruction was not priced at all.
  * `install -oroot /dev/null P` -- the `t` of the owner name `root`.  An
    ordinary provisioning line.
  * `install -Dm 755 /dev/null P` -- `-m` never appears as its own token, so
    `_positional_args` counted `755` as a positional, which made three, which
    tripped the new three-operand bail.

THESE ARE REGRESSIONS, NOT RESIDUALS.  Every shape below was priced
`delete/irreversible` on `main` (caf2cd6) and `execute/recoverable` with
`target_ref=None` on #178's head (28936ee), measured over a 578-shape
cross-product of the writer family under both trees -- so the merge condition
"no new escapes" failed and this is what it caught.

GROUND TRUTH WAS EXECUTED.  Every DESTROYS shape emptied a synthetic canary in a
real /bin/bash and every SURVIVES shape left its canary byte-identical.
Evidence: code-reports/dev-1--170--20260918-evidence/.

  INSTRUMENT, twice.  (1) `cp`/`mv` are aliased to `-i` here, so the aliased run
  declines and exits 0 with the canary intact and a real destroyer reads as
  SAFE; every executed line uses an absolute path, and the control
  `cp /dev/null P` reads DESTROYS.  (2) The first revision of the rig compared
  LINE COUNTS, and the source canary also had five lines, so `mv -St src P` --
  which replaces the file -- read SURVIVES.  The check is the victim's exact
  bytes for that reason.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv, /etc or /var is created, opened, written or executed by this module.
"""
import unittest

from reeflex_claude.classify import classify


def verdict(command):
    d = classify("Bash", {"command": command})
    return d.get("verb"), d.get("reversibility"), d.get("target_ref")


class ShortOptionValueIsNotAFlagLetter(unittest.TestCase):
    """EXECUTED: each of these emptied a canary. Each must be priced."""

    def assert_priced(self, command):
        verb, rev, ref = verdict(command)
        self.assertEqual(
            ("delete", "irreversible", "/srv/prod/db.sqlite"), (verb, rev, ref),
            "%r destroys its target and must be priced as a destruction that "
            "NAMES it; got %s/%s ref=%s" % (command, verb, rev, ref))

    def test_cp_suffix_value_beginning_with_t(self):
        # `-S t`: the backup suffix is "t", not --target-directory.
        self.assert_priced("cp -St /dev/null /srv/prod/db.sqlite")

    def test_cp_suffix_value_containing_t(self):
        # It is not only the bare letter -- any suffix with a t in it did this.
        self.assert_priced("cp -S.tmp /dev/null /srv/prod/db.sqlite")

    def test_mv_suffix_value(self):
        self.assert_priced("mv -St /tmp/replacement.dat /srv/prod/db.sqlite")
        self.assert_priced("mv -S.tmp /tmp/replacement.dat /srv/prod/db.sqlite")

    def test_install_owner_and_group_names_containing_t_or_d(self):
        # `-oroot` is `-o root`.  The t belongs to the owner's name.
        self.assert_priced("install -oroot /dev/null /srv/prod/db.sqlite")
        self.assert_priced("install -groot /dev/null /srv/prod/db.sqlite")

    def test_cp_bundle_whose_last_letter_takes_the_next_word(self):
        # `-fS .bak`: the .bak is -S's value, not a third operand.
        self.assert_priced("cp -fS .bak /dev/null /srv/prod/db.sqlite")
        self.assert_priced("cp -aS .bak /dev/null /srv/prod/db.sqlite")

    def test_install_bundled_mode_leaves_two_operands_not_three(self):
        self.assert_priced("install -Dm 755 /dev/null /srv/prod/db.sqlite")
        self.assert_priced("install -cm 644 /dev/null /srv/prod/db.sqlite")


class TheBailsThatMustSurvive(unittest.TestCase):
    """The complement. A fix that reads the bundle carelessly in the OTHER
    direction reports a destruction of a directory that measurably survives, so
    these are the half that fails first."""

    def assert_unpriced(self, command):
        verb, rev, ref = verdict(command)
        self.assertNotEqual(
            "delete", verb,
            "%r destroys nothing -- EXECUTED -- and must not be priced as a "
            "destruction; got %s/%s ref=%s" % (command, verb, rev, ref))
        self.assertIsNone(ref, "%r must name no destroyed file" % command)

    def test_genuine_directory_destinations_still_bail(self):
        self.assert_unpriced("cp -t /srv/prod/ ./a.sql")
        self.assert_unpriced("cp -at /srv/prod/ ./a.sql")
        self.assert_unpriced("cp -t/srv/prod/ ./a.sql")       # attached value
        self.assert_unpriced("mv -ft /srv/backup/ /srv/prod/db.sqlite")
        self.assert_unpriced("install -dt /srv/prod/ ./a.sql")

    def test_a_weighty_LAST_operand_under_t_is_still_a_source(self):
        # The shape where the bundle scan is the ONLY thing standing: every
        # other -t row leaves one positional, so the "fewer than two operands"
        # rule answers it and the scan could be broken silently. A sabotage arm
        # that reordered the scan went GREEN across the whole corpus until
        # these were added. EXECUTED: both operands land inside the directory
        # and db.sqlite comes through byte-identical.
        self.assert_unpriced("cp -at /srv/backup/ /tmp/a.sql /srv/prod/db.sqlite")
        self.assert_unpriced("cp -t/srv/backup/ /tmp/a.sql /srv/prod/db.sqlite")

    def test_install_d_creates_a_directory_even_when_bundled_before_a_value(self):
        # `-dm 755`: the d is a flag, the m takes 755.  Stopping the scan at
        # the first value-taking letter must not stop it BEFORE the d.
        self.assert_unpriced("install -d /srv/prod/newdir")
        self.assert_unpriced("install -dm 755 /srv/prod/newdir")

    def test_one_operand_once_the_bundled_value_is_taken(self):
        # EXECUTED: exits 1, "missing destination file operand", file intact.
        # main priced this one -- a destruction that cannot happen.
        self.assert_unpriced("install -Dm 755 /srv/prod/db.sqlite")

    def test_three_real_operands_still_bail(self):
        # EXECUTED: exits 1 against a file, 0 into a directory; either way the
        # last operand survives.  PR #178's second finding, unchanged by this.
        self.assert_unpriced("cp ./a.sql ./b.sql /var/lib/pgsql/data/")
        self.assert_unpriced("cp ./a.sql ./b.sql /srv/prod/db.sqlite")


class TheFixItselfIsNotWidenedByAccident(unittest.TestCase):
    """Case-sensitivity is what RFX-345 bought; a value-aware scan must not
    hand it back."""

    def test_uppercase_still_prices(self):
        for c in ("cp -T /dev/null /srv/prod/db.sqlite",
                  "cp -aT /dev/null /srv/prod/db.sqlite",
                  "install -D /dev/null /srv/prod/db.sqlite",
                  "install -T /dev/null /srv/prod/db.sqlite"):
            verb, _, ref = verdict(c)
            self.assertEqual("delete", verb, "%r lost its pricing" % c)
            self.assertEqual("/srv/prod/db.sqlite", ref)

    def test_tee_append_bundle_is_untouched(self):
        # tee has no short option that takes a value, so its bundle test is
        # left alone; this pins that the change did not reach it.
        self.assertNotEqual("delete", verdict("echo hi | tee -a /srv/prod/db.sqlite")[0])
        self.assertEqual("delete", verdict("echo hi | tee /srv/prod/db.sqlite")[0])
        self.assertNotEqual("delete", verdict("echo hi | tee -ai /srv/prod/db.sqlite")[0])


class PositionalArgsCallersAreUnaffected(unittest.TestCase):
    """`_positional_args` grew an optional argument. Callers that pass nothing
    must behave exactly as before."""

    def test_default_is_the_old_behaviour(self):
        from reeflex_claude.classify import _positional_args
        args = ["-Dm", "755", "/dev/null", "/srv/prod/db.sqlite"]
        self.assertEqual(["755", "/dev/null", "/srv/prod/db.sqlite"],
                         _positional_args(args))
        self.assertEqual(["/dev/null", "/srv/prod/db.sqlite"],
                         _positional_args(args, value_letters="tSmog"))

    def test_attached_value_consumes_nothing_further(self):
        from reeflex_claude.classify import _positional_args
        self.assertEqual(["/dev/null", "/srv/prod/db.sqlite"],
                         _positional_args(["-Dm755", "/dev/null", "/srv/prod/db.sqlite"],
                                          value_letters="tSmog"))


if __name__ == "__main__":
    unittest.main()
