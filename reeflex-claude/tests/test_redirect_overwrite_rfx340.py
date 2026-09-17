"""RFX-340 -- a redirection truncates its target wherever it is written.

Until this round the redirect target was read off the COMMAND WORD, so
`> /srv/prod/db.sqlite` was priced a destruction and `echo hi >
/srv/prod/db.sqlite` -- the same destruction, the spelling people actually
write -- was priced benign/read and the real policy pack ALLOWED it.

GROUND TRUTH FOR EVERY SHAPE BELOW was taken from a real /bin/bash against a
synthetic canary in a temp dir, with the predicate "are the ORIGINAL CONTENTS
gone".  Two weaker predicates give wrong answers on this class and both were
actually shipped by agents on this codebase in one night:

  * `size == 0` reports SURVIVAL for `> P echo hi`, which truncates P and then
    writes three bytes into it;
  * survival ORed across several victim files reports SURVIVAL for every shape
    that only touches the first one.

The protected-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv, /etc or /var is created, written or executed by this module.
"""

import unittest

from reeflex_claude.classify import classify


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"


class TestTrailingRedirectIsADestruction(unittest.TestCase):
    """The spelling everyone writes must price like the one nobody writes."""

    def test_trailing_redirect_on_a_database_is_a_delete(self):
        self.assertEqual("delete", _c("echo hi > %s" % PROD)["verb"])

    def test_trailing_and_leading_price_the_same_destruction_alike(self):
        lead = _c("> %s echo hi" % PROD)
        trail = _c("echo hi > %s" % PROD)
        for axis in ("verb", "reversibility", "blast_radius",
                     "classification_tier", "danger_signature"):
            self.assertEqual(lead[axis], trail[axis],
                             "%s differs by where the > is written" % axis)

    def test_every_truncating_spelling_reaches_the_same_verdict(self):
        for command in (
                "echo hi > %s" % PROD,
                "echo hi >%s" % PROD,
                "echo hi 1> %s" % PROD,
                "echo hi 2> %s" % PROD,
                "echo hi &> %s" % PROD,
                "echo hi >& %s" % PROD,
                "echo hi {fd}> %s" % PROD,
                "echo > %s hi" % PROD,
                ">%s echo hi" % PROD,
                "true > %s" % PROD,
                "printf x > %s" % PROD,
                "cat /dev/null > %s" % PROD,
        ):
            with self.subTest(command=command):
                self.assertEqual("delete", _c(command)["verb"])
                self.assertEqual("irreversible", _c(command)["reversibility"])

    def test_every_target_on_the_line_is_counted_not_just_the_last(self):
        # Only the LAST redirection receives the output, but both files are
        # opened, and opening for truncation is what destroys the contents.
        got = _c("echo hi > /srv/prod/wal.sqlite > %s" % PROD)
        self.assertEqual("delete", got["verb"])

    def test_a_redirect_inside_a_substitution_still_truncates(self):
        for command in (
                "echo $(echo hi > %s)" % PROD,
                "echo $(echo $(echo hi > %s))" % PROD,
                "echo `echo hi > %s`" % PROD,
        ):
            with self.subTest(command=command):
                self.assertEqual("delete", _c(command)["verb"])

    def test_a_system_path_is_systemic(self):
        self.assertEqual("systemic", _c("echo hi > /etc/passwd")["blast_radius"])


class TestWhatIsNotATruncation(unittest.TestCase):
    """The complement. Each of these SURVIVES a real bash, so none is a delete.

    This class is the half that keeps the fix honest: a rule that prices every
    `>` as a destruction would pass every test in the class above.
    """

    def test_append_is_not_a_truncation(self):
        for command in ("echo hi >> %s" % PROD,
                        "echo hi &>> %s" % PROD,
                        "echo hi 2>> %s" % PROD):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_read_write_open_does_not_truncate(self):
        # `<>` opens for reading AND writing WITHOUT truncating. Confirmed
        # against a real bash: the canary survives.
        self.assertNotEqual("delete", _c("echo hi <> %s" % PROD)["verb"])

    def test_fd_duplication_is_not_a_file(self):
        for command in ("echo hi 2>&1", "echo hi >&2", "pytest -q 2>&1"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_discard_sinks_are_not_destructions(self):
        for command in ("echo hi > /dev/null",
                        "echo hi > /dev/stderr",
                        "echo hi 2> /dev/null"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_an_ordinary_file_stays_with_the_command_that_wrote_it(self):
        """The RFX-144 rule this fix had to preserve, not overturn.

        Pricing routine build output as a delete charges R5's cumulative
        budget for no gain.  That cost is invisible to any probe that decides
        ONE envelope from an empty ledger, so it is asserted here instead.
        """
        for command in ("pytest -q > out.log",
                        "make build > build/out.txt",
                        "echo hi > ./notes.md",
                        "cargo test > /tmp/scratch.log"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])


class TestTheGuardCanFail(unittest.TestCase):
    """A check I have only ever seen go green has not been tested.

    `_redirect_overwrite_targets` is the new instrument; these assertions are
    about the instrument itself, so that a future refactor which quietly stops
    finding targets fails here instead of silently reopening RFX-340.
    """

    def test_the_extractor_finds_the_target_in_every_position(self):
        from reeflex_claude.classify import _redirect_overwrite_targets as f
        self.assertEqual([PROD], f(["echo", "hi", ">", PROD]))
        self.assertEqual([PROD], f([">", PROD, "echo", "hi"]))
        self.assertEqual([PROD], f(["echo", "hi", ">" + PROD]))
        self.assertEqual([PROD], f(["echo", "hi", "2>", PROD]))

    def test_the_extractor_refuses_what_does_not_truncate(self):
        from reeflex_claude.classify import _redirect_overwrite_targets as f
        self.assertIsNone(f(["echo", "hi", ">>", PROD]))
        self.assertIsNone(f(["echo", "hi", "&>>", PROD]))
        self.assertIsNone(f(["echo", "hi", "<>", PROD]))
        self.assertIsNone(f(["echo", "hi", "<", PROD]))
        self.assertIsNone(f(["echo", "hi", "2>&1"]))
        self.assertIsNone(f(["echo", "hi", ">", "/dev/null"]))
        # An ordinary file is not a destruction -- the scoping half.
        self.assertIsNone(f(["pytest", "-q", ">", "out.log"]))

    def test_a_trailing_operator_with_no_target_does_not_crash(self):
        from reeflex_claude.classify import _redirect_overwrite_targets as f
        self.assertIsNone(f(["echo", "hi", ">"]))
        self.assertIsNone(f([">"]))
        self.assertIsNone(f([]))


if __name__ == "__main__":
    unittest.main()
