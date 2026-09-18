"""RFX-343 -- the whole-file destruction table had three entries and the
family has more.

`_overwrite_targets` priced exactly `dd of=`, `truncate` and a redirection used
as a command.  Everything else fell through to execute/recoverable/scoped, so a
production database emptied by `tee`, `cp`, `install`, `sort -o` or `mv` was
answered `allow` by the real policy pack on a FIRST call in a fresh session --
and came back with `target_ref=null`, so R6 had no path to match and the audit
line could not name the file that was destroyed.

THIS FAMILY CARRIES NO REDIRECTION OPERATOR ANYWHERE.  The destruction is in
the command's own semantics -- `tee P` truncates P because tee truncates -- so
neither the RFX-340 trailing-redirect fix nor the RFX-328 substitution budget
can reach it: there is nothing to peel.

GROUND TRUTH was executed, not asserted.  Every shape below ran against a real
/bin/bash over a synthetic victim carrying FIVE canary lines, and is declared
destructive only if ALL FIVE were gone from EVERY asserted operand.  Five and
not one, because a single canary cannot tell a WHOLE-FILE destruction from a
PARTIAL edit and its PLACEMENT silently decides the answer:

  * a canary at offset 0 is clipped by `dd conv=notrunc bs=1 count=1`, which
    truncates nothing -- the control then reads as a destruction;
  * a canary on line 2 survives `sed -i 1d`, which does destroy line 1 -- the
    row then reads as safe.

Both readings are artefacts of the layout, not facts about the command.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv, /etc or /var is created, opened, written or executed by this module.
"""

import unittest

from reeflex_claude.classify import classify


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"
WAL = "/srv/prod/wal.sqlite"

# Each shape lost all five canary lines in a real bash. Evidence:
# code-reports/dev-2--076--20260918-evidence/00-ground-truth.json
DESTROYING = (
    "tee %s" % PROD,
    "echo hi | tee %s" % PROD,
    "cp /dev/null %s" % PROD,
    "cp /tmp/replacement.dat %s" % PROD,
    "install /dev/null %s" % PROD,
    "sort -o %s /dev/null" % PROD,
    "mv /tmp/replacement.dat %s" % PROD,
)


class TestTheWriterFamilyIsADestruction(unittest.TestCase):
    """A command that empties a production database is priced like one."""

    def test_every_writer_shape_is_a_delete(self):
        for command in DESTROYING:
            with self.subTest(command=command):
                self.assertEqual("delete", _c(command)["verb"])

    def test_every_writer_shape_is_irreversible_and_broad(self):
        for command in DESTROYING:
            with self.subTest(command=command):
                cls = _c(command)
                self.assertEqual("irreversible", cls["reversibility"])
                self.assertEqual("broad", cls["blast_radius"])

    def test_the_record_names_the_file_that_was_destroyed(self):
        """target_ref is the half R6 needs and the audit line prints.

        Pricing the destruction correctly while reporting `target_ref=null`
        would close only half of RFX-343: the protected-path rule has no path
        to match on, and "a delete was held in production" is not something an
        auditor can check against a record that does not say WHICH file.
        """
        for command in DESTROYING:
            with self.subTest(command=command):
                self.assertEqual(PROD, _c(command)["target_ref"])

    def test_two_spellings_of_one_operation_price_alike(self):
        """`cp /dev/null P` and `install /dev/null P` are the same operation.

        A vocabulary table that holds one spelling and not the other is
        exactly the defect RFX-343 names, so the two are compared to each
        other rather than each to a constant.
        """
        cp = _c("cp /dev/null %s" % PROD)
        install = _c("install /dev/null %s" % PROD)
        for axis in ("verb", "reversibility", "blast_radius",
                     "classification_tier", "target_ref"):
            self.assertEqual(cp[axis], install[axis],
                             "%s differs between two spellings of one "
                             "operation" % axis)

    def test_the_writer_family_prices_like_the_shapes_already_caught(self):
        """The new rows must land where `truncate -s 0` already lands.

        Compared against the shipped reference shape rather than against
        hardcoded strings, so that if the pricing of whole-file destruction
        ever moves, this test moves with it instead of pinning a stale answer.
        """
        reference = _c("truncate -s 0 %s" % PROD)
        for command in DESTROYING:
            with self.subTest(command=command):
                cls = _c(command)
                for axis in ("verb", "reversibility", "blast_radius",
                             "classification_tier"):
                    self.assertEqual(reference[axis], cls[axis], axis)

    def test_every_operand_of_tee_is_truncated(self):
        """`tee A B` destroys BOTH, and the count has to say so.

        target_ref is null on a multi-path destruction by the SAME convention
        `rm a b` and `truncate a b` already use -- the identity moves into
        magnitude_count -- so this asserts the count rather than the ref.
        """
        cls = _c("echo hi | tee %s %s" % (PROD, WAL))
        self.assertEqual("delete", cls["verb"])
        self.assertEqual(2, cls["magnitude_count"])


class TestOrdinaryWorkStaysAllowed(unittest.TestCase):
    """The complement, which is the merge bar.

    `cp`, `mv` and `tee` are overwhelmingly ROUTINE.  Pricing all of them as
    deletes would charge every build to R5's cumulative delete budget and
    exhaust it on log files -- a cost no single-decision probe can see,
    because every such probe starts from an empty ledger.  These are the rows
    that fail if the path-weight gate is ever dropped.
    """

    ORDINARY = (
        "echo hi | tee ./build.log",
        "cp ./a.txt ./b.txt",
        "mv ./draft.md ./notes.md",
        "install ./a.bin ./b.bin",
        "sort -o ./sorted.txt ./input.txt",
    )

    def test_ordinary_writes_are_not_deletes(self):
        for command in self.ORDINARY:
            with self.subTest(command=command):
                cls = _c(command)
                self.assertNotEqual("delete", cls["verb"])
                self.assertEqual("recoverable", cls["reversibility"])

    def test_append_is_not_a_destruction(self):
        """-a leaves the prior contents intact: five of five canary lines."""
        for command in ("echo hi | tee -a %s" % PROD,
                        "echo hi | tee --append %s" % PROD):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_the_append_test_is_case_sensitive(self):
        """An uppercase bundle must NOT read as --append.

        Short flags are case-sensitive.  Folding case when testing for `-a`
        fails OPEN -- any bundle carrying an uppercase `A` would switch the
        destruction pricing off -- and the same fold read `tar -C` as
        `tar -c` while tar was still in the writer set.  `tee -A` is not a
        real flag, which is the point: an unrecognised flag must not be able
        to disarm the classifier.
        """
        self.assertEqual("delete", _c("tee -A %s" % PROD)["verb"])

    def test_the_production_path_as_a_source_is_not_a_destruction(self):
        """Reading a database is not emptying it."""
        for command in ("cp %s ./copy.out" % PROD,
                        "mv %s /tmp/backup.dat" % PROD,
                        "sort %s" % PROD):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_building_an_archive_is_not_a_destruction(self):
        """`tar -cf` is deliberately OUT of the writer family.

        `.tar` is itself a data-container extension, so gating tar on path
        weight prices every `tar -cf dist.tar src` in every build script as an
        irreversible destruction.  This row is what measured that, and it
        fails if tar is ever added without a gate that can tell the two apart.
        """
        self.assertNotEqual("delete", _c("tar -cf ./dist.tar ./src")["verb"])

    def test_a_directory_destination_names_no_file(self):
        """`-t DIR` cannot be resolved without touching the filesystem.

        Naming the DIRECTORY as the destroyed resource would report a
        destruction of the wrong thing, which is worse than reporting none.
        """
        for command in ("cp -t /srv/prod /tmp/a.dat",
                        "install -d /srv/prod/newdir"):
            with self.subTest(command=command):
                self.assertIsNone(_c(command)["target_ref"])


class TestTheExclusionsAreMeasuredNotForgotten(unittest.TestCase):
    """Three shapes RFX-343 lists that this change deliberately does NOT price.

    Each is a measurement rather than an oversight, and each is pinned here so
    that a later round changing one has to change a test that says why.
    """

    def test_sed_in_place_is_a_partial_edit_not_a_whole_file_destruction(self):
        """`sed -i 1d P` left 4 of 5 canary lines readable.

        `_overwrite_targets` is contracted to WHOLE-FILE destruction; pricing
        a partial edit through it would make that contract false.
        """
        self.assertNotEqual("delete", _c("sed -i 1d %s" % PROD)["verb"])

    def test_gzip_is_not_priced_irreversible(self):
        """`gzip P` removes P, but `gunzip` returns its bytes.

        `_classify_path_delete` hardcodes reversibility="irreversible", so
        routing gzip through it would state something measurably untrue. It
        needs a "recoverable but disruptive" pricing that does not exist yet.
        """
        self.assertNotEqual("irreversible", _c("gzip %s" % PROD)["reversibility"])

    def test_an_inline_interpreter_truncation_is_still_open(self):
        """`python3 -c "open('P','w')"` truncates and is NOT caught.

        It is the inline-interpreter mechanism, which extracts no path -- and
        without a path the weighty gate cannot be applied, so catching it here
        would price every `open('/tmp/out','w')` one-liner as an irreversible
        broad destruction. Pinned as a KNOWN GAP: this test documents what is
        NOT covered, and fails if someone closes it without revisiting the
        reasoning above.
        """
        cls = _c("python3 -c \"open('%s','w')\"" % PROD)
        self.assertNotEqual("delete", cls["verb"])


if __name__ == "__main__":
    unittest.main()
