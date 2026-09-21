"""RFX-384 -- the writer family's `sed` exclusion was measured on a PARTIAL
edit and applied to the whole command word.

`_writer_overwrite_targets` excludes `sed` because `sed -i 1d P` leaves 4 of 5
canary lines alive and that function is contracted to WHOLE-FILE destruction.
The measurement is right about `sed -i 1d`.  The exclusion was applied to the
command word, which is wider: `sed -i 's/.*//' P`, `sed -i 'd' P`,
`sed -i '1,$d' P` and `sed --in-place 's/.*//' P` lose ALL FIVE, and so do
`perl -pi -e 's/.*//' P`, `perl -i -pe 's/.*//' P` and
`perl -ni -e 'print if 0' P`.  `perl` is not named in that docstring at all,
and `_INLINE_DESTRUCTIVE_RE` models UNLINKING (`os.remove`, `shutil.rmtree`,
`.unlink(`) rather than content truncation, so no arm fired for either.

WHAT IS PRICED, AND ON WHICH AXIS.  Not whole-file loss -- reversibility.  An
UNBACKED in-place edit makes the prior contents unrecoverable at that path,
which is the axis R2 and R3 read.  Whole-versus-partial changes how much was
lost, not whether it can be got back.

THE CONTROL IS THE BACKUP SUFFIX, and it is a measurement rather than a
caution: after `sed -i.bak 's/.*//' P` all five canaries are on disk in P.bak,
so `recoverable` is TRUE there and the line must NOT be priced destructive.  A
fix that is too wide fails these rows.

GROUND TRUTH was executed, not asserted -- five canary lines per shape against
a real /bin/bash, read back off the filesystem.  Evidence:
code-reports/dev-1--186-evidence/70-inplace.py and inplace-main.json.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv or /etc is created, opened, written or executed by this module.
"""

import unittest

from reeflex_claude.classify import classify


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"
ORDINARY = "src/app.py"

# Lost all five canary lines in a real bash, with NO backup left on disk.
DESTROYING_UNBACKED = (
    "sed -i 's/.*//' %s" % PROD,
    "sed -i 'd' %s" % PROD,
    "sed -i '1,$d' %s" % PROD,
    "sed --in-place 's/.*//' %s" % PROD,
    "perl -pi -e 's/.*//' %s" % PROD,
    "perl -i -pe 's/.*//' %s" % PROD,
    "perl -ni -e 'print if 0' %s" % PROD,
)

# Lost all five AT THE PATH, and all five were found in the backup file.
BACKED_UP = (
    "sed -i.bak 's/.*//' %s" % PROD,
    "sed -i'.orig' 's/.*//' %s" % PROD,
    "sed --in-place=.bak 's/.*//' %s" % PROD,
    "perl -pi.bak -e 's/.*//' %s" % PROD,
)


class UnbackedInPlaceEditTests(unittest.TestCase):
    """The rows that were priced execute/recoverable/scoped on e175e4e."""

    def test_unbacked_in_place_edit_of_a_data_container_is_a_destruction(self):
        for command in DESTROYING_UNBACKED:
            with self.subTest(command=command):
                result = _c(command)
                self.assertEqual(result["verb"], "delete", command)
                self.assertEqual(result["reversibility"], "irreversible", command)
                self.assertEqual(result["danger_signature"], "overwrite_container",
                                 command)
                self.assertTrue(
                    result["classification_tier"].startswith("destructive"),
                    "%s priced %s" % (command, result["classification_tier"]))

    def test_the_destroyed_path_is_named(self):
        """target_ref=None is what left R6 with no path to match and the audit
        line unable to say which file was emptied."""
        for command in DESTROYING_UNBACKED:
            with self.subTest(command=command):
                self.assertEqual(_c(command)["target_ref"], PROD, command)

    def test_a_partial_in_place_edit_is_still_irreversible_at_that_path(self):
        """`sed -i 1d` keeps 4 of 5 lines -- and the line it removed is gone
        for good.  The magnitude differs from a whole-file wipe; the
        reversibility does not."""
        for command in ("sed -i 1d %s" % PROD,
                        "perl -pi -e 's/CANARY1/x/' %s" % PROD):
            with self.subTest(command=command):
                self.assertEqual(_c(command)["reversibility"], "irreversible",
                                 command)


class BackupSuffixTests(unittest.TestCase):
    """If the prior bytes are still on disk, `recoverable` is true and this
    must stay out of the destruction pricing."""

    def test_a_backup_suffix_is_not_a_destruction(self):
        for command in BACKED_UP:
            with self.subTest(command=command):
                result = _c(command)
                self.assertNotEqual(result["verb"], "delete", command)
                self.assertEqual(result["danger_signature"], "none", command)
                self.assertFalse(
                    result["classification_tier"].startswith("destructive"),
                    "%s priced %s" % (command, result["classification_tier"]))


class MustNotTightenTests(unittest.TestCase):
    """Ordinary development work, and the near-misses a bundle test invites."""

    def test_ordinary_source_edit_stays_benign(self):
        """The weightiness gate is what keeps `sed -i` on a source file out of
        R5's cumulative delete budget."""
        for command in ("sed -i 's/DEBUG/INFO/' %s" % ORDINARY,
                        "perl -pi -e 's/a/b/' %s" % ORDINARY,
                        "sed -i 's/.*//' build.log"):
            with self.subTest(command=command):
                result = _c(command)
                self.assertNotEqual(result["verb"], "delete", command)
                self.assertFalse(
                    result["classification_tier"].startswith("destructive"),
                    "%s priced %s" % (command, result["classification_tier"]))

    def test_a_module_name_containing_i_is_not_an_in_place_flag(self):
        """`-Mstrict` carries an `i`.  A naive `"i" in bundle` test reads it as
        in-place with backup suffix `ct` -- the same shape as the `tar -C` /
        `tar -c` fold RFX-343 recorded.  The bundle scan must stop at the first
        letter that takes a value."""
        result = _c("perl -Mstrict -e 'print' %s" % PROD)
        self.assertNotEqual(result["verb"], "delete")
        self.assertFalse(result["classification_tier"].startswith("destructive"))

    def test_sed_without_in_place_writes_nothing(self):
        for command in ("sed 's/.*//' %s" % PROD,
                        "sed -n '1p' %s" % PROD,
                        "sed -e 's/a/b/' %s" % PROD):
            with self.subTest(command=command):
                self.assertFalse(
                    _c(command)["classification_tier"].startswith("destructive"),
                    command)

    def test_perl_without_an_inline_program_is_not_an_edit(self):
        """`perl -i script.pl DATA` runs a program file; the first operand is
        not a file being edited."""
        result = _c("perl -i script.pl %s" % PROD)
        self.assertNotEqual(result["verb"], "delete")


class OperandExtractionTests(unittest.TestCase):
    """The script must not be read as a path, and a path must not be missed."""

    def test_the_sed_script_is_not_treated_as_an_operand(self):
        """With no -e/-f the FIRST operand is the script.  Reading it as a file
        would name the wrong thing as destroyed."""
        self.assertEqual(_c("sed -i 's/.*//' %s" % PROD)["target_ref"], PROD)

    def test_an_explicit_script_flag_leaves_every_operand_a_file(self):
        for command in ("sed -i -e 's/.*//' %s" % PROD,
                        "sed -i --expression='s/.*//' %s" % PROD):
            with self.subTest(command=command):
                self.assertEqual(_c(command)["target_ref"], PROD, command)

    def test_a_bundled_program_flag_consumes_its_value(self):
        """`perl -i -pe 'PROG' FILE` -- `PROG` is the value of the bundle's
        trailing `e`, not a path."""
        self.assertEqual(_c("perl -i -pe 's/.*//' %s" % PROD)["target_ref"], PROD)


if __name__ == "__main__":
    unittest.main()
