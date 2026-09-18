"""RFX-343 -- a command can destroy a file with no redirection operator at all.

`dd of=` and `truncate` were the whole of the command-word overwrite table,
and RFX-340 added the redirection operators.  Between them they miss the
family where the destruction is in the COMMAND'S OWN semantics: `tee P`,
`sort -o P`, `sed -i P`, `gzip P`, `tar -cf P` and `install SRC P` each open a
named path for writing with no `>` anywhere on the line.  Every one of them
was priced `execute / recoverable / scoped`, carried `target_ref = None`, and
core's real policy pack answered `allow` on a first call in a fresh session
with no approval present -- so a customer's agent could empty a production
database and no human was asked.  The audit record did not name the file.

GROUND TRUTH FOR EVERY SHAPE BELOW was taken from a real /bin/bash against a
synthetic canary in a temp dir, with the predicate "is the CANARY STRING still
readable at that path" -- deliberately not `size == 0`, which reports SURVIVAL
for any shape that truncates and then writes (the trap RFX-340 recorded).  The
nine destroying shapes all destroyed; the fourteen control shapes all left the
canary intact.

WHY THESE ARE WEIGHTY-GATED.  `sed -i` over `build/out.txt` is an edit, not a
destruction, in exactly the way `pytest > out.log` is -- so these inherit
`_redirect_target_is_weighty` from the redirection scan rather than inventing
a second answer.  A 16170-row before/after sweep is what this rests on: 3968
rows raised, ZERO lowered, ZERO movement on any command word the fix does not
touch, ZERO raised on a non-weighty path.

WHAT IS DELIBERATELY NOT HERE.  `cp SRC DST` and `mv SRC DST` destroy DST only
if DST already exists; pricing them is a false-positive-tolerance call, not a
measurement, and it is flagged on RFX-343 rather than decided.  So is
`python3 -c "open(P,'w')"`, where the destruction is inside an interpreter
payload.  `TestTheFamilyThisDoesNotClose` pins those as still open so the
ticket cannot be closed by a green suite that never asked.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv, /etc or /var is created, written, opened or executed by this module.
"""

import unittest

from reeflex_claude.classify import classify


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"
DEV = "build/out.txt"


# Every spelling here was PROVED to destroy the canary by execution.
DESTROYING = [
    ("tee, bare",              "tee %s" % PROD),
    ("tee, piped into",        "echo hi | tee %s" % PROD),
    ("tee, second operand",    "echo hi | tee /tmp/other.log %s" % PROD),
    ("tee -i",                 "echo hi | tee -i %s" % PROD),
    ("sort -o, separate",      "sort -o %s /tmp/in.txt" % PROD),
    ("sort -o, attached",      "sort -o%s /tmp/in.txt" % PROD),
    ("sort --output=",         "sort --output=%s /tmp/in.txt" % PROD),
    ("sed -i with script",     "sed -i 1d %s" % PROD),
    ("sed -i with suffix",     "sed -i.bak 1d %s" % PROD),
    ("sed --in-place",         "sed --in-place 1d %s" % PROD),
    ("sed -i -e",              "sed -i -e 1d %s" % PROD),
    ("sed -ni cluster",        "sed -ni 1d %s" % PROD),
    ("gzip",                   "gzip %s" % PROD),
    ("gzip -f",                "gzip -f %s" % PROD),
    ("gunzip",                 "gunzip %s" % PROD),
    ("tar -cf",                "tar -cf %s /tmp/src" % PROD),
    ("tar -czf",               "tar -czf %s /tmp/src" % PROD),
    ("tar, legacy bundled",    "tar cf %s /tmp/src" % PROD),
    ("tar --create --file=",   "tar --create --file=%s /tmp/src" % PROD),
    ("install SRC DST",        "install /tmp/src %s" % PROD),
    ("install -m SRC DST",     "install -m 644 /tmp/src %s" % PROD),
]

# Every spelling here was PROVED to leave the canary intact by execution.
NON_DESTROYING = [
    ("tee -a appends",         "echo hi | tee -a %s" % PROD),
    ("tee --append appends",   "echo hi | tee --append %s" % PROD),
    ("tee -ai cluster",        "echo hi | tee -ai %s" % PROD),
    ("sort without -o reads",  "sort %s" % PROD),
    ("sed without -i reads",   "sed 1d %s" % PROD),
    ("sed -n reads",           "sed -n 1p %s" % PROD),
    ("gzip -c writes stdout",  "gzip -c %s" % PROD),
    ("gzip --stdout",          "gzip --stdout %s" % PROD),
    ("gzip -l lists",          "gzip -l %s" % PROD),
    ("gzip -t tests",          "gzip -t %s" % PROD),
    ("tar -xf extracts",       "tar -xf %s" % PROD),
    ("tar -tf lists",          "tar -tf %s" % PROD),
    ("tar -rf appends",        "tar -rf %s /tmp/src" % PROD),
    ("install -d makes dirs",  "install -d %s" % PROD),
    ("install -t target dir",  "install -t %s /tmp/src" % PROD),
]


class TestTheWriterFamilyIsADestruction(unittest.TestCase):
    """A command that empties a production database must not price as execute."""

    def test_every_destroying_spelling_is_a_delete(self):
        for label, command in DESTROYING:
            with self.subTest(label):
                self.assertEqual("delete", _c(command)["verb"],
                                 "%s: %s" % (label, command))

    def test_every_destroying_spelling_is_irreversible(self):
        # R6 reads `irreversible` BEFORE it reads the ref (dev-2--074, RFX-342),
        # so a correct ref on a `recoverable` action still cannot raise a hold.
        # Both legs, or neither is worth asserting.
        for label, command in DESTROYING:
            with self.subTest(label):
                self.assertEqual("irreversible", _c(command)["reversibility"],
                                 "%s: %s" % (label, command))

    def test_every_destroying_spelling_names_the_file_it_destroys(self):
        # The audit line keeps `ability` and `target.ref` and drops params, so
        # a destruction with ref=None is unattributable after the fact.
        for label, command in DESTROYING:
            with self.subTest(label):
                self.assertEqual(PROD, _c(command)["target_ref"],
                                 "%s: %s" % (label, command))

    def test_the_sed_script_word_is_not_counted_as_a_victim(self):
        """
        `sed -i SCRIPT FILE` -- the first positional is a PROGRAM, not a path.

        This guard exists because a sabotage run found the obvious version of
        it VACUOUS: with `sed -i 1d /srv/prod/db.sqlite`, disabling the
        script-drop changes nothing, because `1d` is not a weighty path and
        the weighty gate discards it anyway.  A guard that passes whether or
        not the code under it works is not a guard.

        The shape that CAN see it is a script word that looks like a path.
        Counting it as a second victim pushes `magnitude_count` to 2 and
        collapses `target_ref` to None -- so the audit record stops naming the
        file that was destroyed, which is the failure mode of the whole
        ticket.
        """
        r = _c("sed -i /srv/prod/nightly.sql %s" % PROD)
        self.assertEqual(PROD, r["target_ref"],
                         "the script word was counted as a destroyed file, "
                         "so the record no longer names the real victim")
        self.assertEqual(1, r["magnitude_count"])

    def test_the_tier_reaches_the_rule_that_holds_it(self):
        for label, command in DESTROYING:
            with self.subTest(label):
                self.assertEqual("destructive_broad",
                                 _c(command)["classification_tier"],
                                 "%s: %s" % (label, command))

    def test_it_prices_like_the_shapes_already_in_the_table(self):
        """`tee P` and `truncate P` are the same event and must price alike."""
        reference = _c("truncate -s 0 %s" % PROD)
        for label, command in DESTROYING:
            with self.subTest(label):
                got = _c(command)
                for axis in ("verb", "reversibility", "blast_radius",
                             "classification_tier", "target_ref"):
                    self.assertEqual(reference[axis], got[axis],
                                     "%s differs on %s: %s" % (label, axis, command))


class TestWhatIsNotADestruction(unittest.TestCase):
    """Appending, reading and listing leave the prior contents alone."""

    def test_no_non_destroying_spelling_became_a_delete(self):
        for label, command in NON_DESTROYING:
            with self.subTest(label):
                self.assertNotEqual("delete", _c(command)["verb"],
                                    "%s wrongly priced destructive: %s"
                                    % (label, command))

    def test_a_null_sink_is_not_a_destination(self):
        for command in ("echo hi | tee /dev/null",
                        "sort -o /dev/null /tmp/in.txt",
                        "install /tmp/src /dev/null"):
            with self.subTest(command):
                self.assertNotEqual("delete", _c(command)["verb"], command)


class TestOrdinaryFilesAreNotDestructions(unittest.TestCase):
    """
    The scoping the widening is affordable BECAUSE of.

    Charging `sed -i build/out.txt` to R5's cumulative delete budget buys
    nothing, and it is the same call `_redirect_target_is_weighty` already
    makes for `pytest > out.log`.  If this class goes red the fix has stopped
    being scoped and has become a widening of every `cmd file` on the box.
    """

    def test_a_dev_path_is_untouched_by_every_destroying_spelling(self):
        for label, command in DESTROYING:
            dev_command = command.replace(PROD, DEV)
            if dev_command == command:
                continue
            with self.subTest(label):
                self.assertNotEqual("delete", _c(dev_command)["verb"],
                                    "%s: %s" % (label, dev_command))

    def test_an_archive_tool_writing_an_archive_is_routine(self):
        """
        `.tar`/`.zip` are data containers, so without this every backup needs
        an approval -- including the backup you WANT the agent to take.
        """
        for command in (
                "tar -czf /srv/backups/db-2026-09-18.tar.gz %s" % PROD,
                "tar -cf /srv/backups/db.tar %s" % PROD,
                "gzip /srv/backups/db.tar",
                "gzip dist/bundle.tar"):
            with self.subTest(command):
                self.assertNotEqual("delete", _c(command)["verb"], command)

    def test_but_an_archive_written_over_a_database_is_not(self):
        """The excuse is for archive DESTINATIONS, not for archive TOOLS."""
        self.assertEqual("delete", _c("tar -cf %s /tmp/src" % PROD)["verb"])
        self.assertEqual("delete", _c("gzip %s" % PROD)["verb"])

    def test_the_excuse_is_withdrawn_on_a_system_path_or_a_secret(self):
        for command in ("tar -cf /etc/backup.tar /tmp/src",
                        "gzip /srv/prod/.env.tar"):
            with self.subTest(command):
                self.assertEqual("delete", _c(command)["verb"], command)


class TestTheDestructionSurvivesTheWayItIsWritten(unittest.TestCase):
    """A destruction does not stop being one inside a pipeline or a subshell."""

    def test_structural_wrappers_do_not_hide_it(self):
        inner = "echo hi | tee %s" % PROD
        for command in (inner,
                        "( %s )" % inner,
                        "%s && echo done" % inner,
                        "echo start; %s" % inner,
                        "LC_ALL=C tee %s" % PROD,
                        "sudo tee %s" % PROD,
                        "timeout 5 tee %s" % PROD):
            with self.subTest(command):
                self.assertEqual("delete", _c(command)["verb"], command)


class TestTheFamilyThisDoesNotClose(unittest.TestCase):
    """
    The part of RFX-343 that is FLAGGED AND NOT DECIDED, pinned as still open.

    `cp SRC DST` and `mv SRC DST` destroy DST only when DST already exists, and
    a static classifier cannot stat the filesystem; pricing them is a
    false-positive-tolerance call for the owner, not a measurement.  The
    interpreter payload (`python3 -c "open(P,'w')"`) is a third mechanism.

    These assertions record TODAY'S behaviour so nobody reads a green suite as
    "the writer family is closed".  When the owner decides, this class is the
    thing that goes red and has to be rewritten -- which is the point.
    """

    def test_cp_and_mv_onto_a_production_database_are_still_allowed_through(self):
        for command in ("cp /dev/null %s" % PROD,
                        "cp /tmp/replacement.dat %s" % PROD,
                        "mv /tmp/replacement.dat %s" % PROD):
            with self.subTest(command):
                self.assertEqual("execute", _c(command)["verb"],
                                 "RFX-343's conditional half moved without a "
                                 "decision being recorded: %s" % command)

    def test_an_interpreter_payload_is_still_not_read(self):
        self.assertEqual(
            "execute",
            _c("python3 -c \"open('%s','w')\"" % PROD)["verb"],
            "the interpreter half of RFX-343 moved without a decision")


if __name__ == "__main__":
    unittest.main()
