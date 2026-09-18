"""RFX-344 -- `>& PATH cmd` was priced as a benign read.

`>&word` with a NON-NUMERIC operand is bash's both-streams redirection: it is
`&>word` spelled the other way round, and it truncates `word`.  Written BEFORE
the command word it was reaching no classifier at all:

    >& /srv/prod/db.sqlite echo hi
        -> verb=read  reversibility=reversible  tier=benign  target_ref=None

which is the cheapest verdict this classifier can produce, on a destruction
that a real shell performs.  `target_ref=None` is the second half: even if
something else had held the action, the audit line could not have named the
file.

WHY IT WAS ONLY `>&`, WHICH IS NOT HOW THE TICKET WAS FILED.  RFX-344 was
filed as "the wrapper peel discards the redirection and its target".  Measured
on main 3347665, the leading spellings `>`, `>|`, `&>`, `1>`, `2>` and `3>`
were all priced delete/irreversible with the path in `target_ref`; `>&` alone
escaped.  `_truncates()` folds a leading fd number or `&` off the operator
with `lstrip("0123456789&")`, and `str.lstrip` strips from the LEFT only --
so `&>` normalises to `>` and matches `_TRUNCATING_OPERATORS`, while `>&`
keeps its trailing `&` and does not.  `_peel_wrappers` then consumed the
operator and its target without recording a truncation.

WHY THE FIX IS NOT "ADD `>&` TO `_TRUNCATING_OPERATORS`".  The peel records
what it emptied without consulting `_redirect_target_is_weighty`, while
`_redirect_overwrite_targets` does.  Measured on main, that asymmetry is
already live:

    > build.log echo hi   ->  delete/irreversible/moderate  ref=build.log
    echo hi > build.log   ->  read/reversible/benign        ref=None

Widening the operator tuple would have extended that over-call to a new
spelling and started charging routine output to R5's cumulative delete budget
-- a cost no single-decision probe can see, because every such probe starts
from an empty ledger.  So `_classify_segment` scans the RAW tokens instead,
which puts the leading spelling behind the same weight gate as the trailing
one.  `TestLeadingAndTrailingAgree` is what pins that.

WHY THE EXISTING GUARD STAYED GREEN, which is a coverage fact and not a bug in
the guard: `test_redirect_overwrite_rfx340.py` already asserts
`echo hi >& /srv/prod/db.sqlite` -- the operator was covered, in the TRAILING
position only.  Every leading spelling in that file is `>`.  So the family was
tested, the operator was tested, and the intersection was not.

GROUND TRUTH for every shape below is a real /bin/bash 5.1.8 against a
synthetic canary under /tmp, predicate "is the ORIGINAL content still there".
Two weaker predicates grade these wrong:

  * `size == 0` reports SURVIVAL for `>& P echo hi`, which truncates P and
    then writes three bytes into it;
  * "the file still exists" reports SURVIVAL for every truncating shape here,
    since none of them unlinks anything.

Measured destroying:  `>& P cmd`  `>&P cmd`  `cmd >& P`  `cmd >&P`
Measured surviving:   `>&1 cmd`  `>&2 cmd`  `>&- cmd`  `2>&1 cmd`
                      `>> P cmd`  `&>> P cmd`  `< P cmd`  `<> P cmd`

The protected-looking paths here are CLASSIFIER INPUT ONLY -- strings handed
to `classify()`.  Nothing under /srv, /etc or /var is created, written,
stat'd or executed by this module.
"""

import unittest

from reeflex_claude.classify import (
    classify,
    _TRUNCATING_REDIRECT_RE,
    _redirect_overwrite_targets,
    _safe_split,
)


def _c(command):
    return classify("Bash", {"command": command})


PROD = "/srv/prod/db.sqlite"
SYSTEMIC = "/var/lib/pgsql/data/base"
ORDINARY = "build.log"


class TestTheFiledInput(unittest.TestCase):
    """The exact string on the ticket, replayed."""

    def test_the_filed_input_is_a_delete(self):
        got = _c(">& %s echo hi" % PROD)
        self.assertEqual("delete", got["verb"])
        self.assertEqual("irreversible", got["reversibility"])

    def test_the_filed_input_names_the_file_it_destroys(self):
        # Half of the defect: without a ref, R6 has nothing to match and the
        # audit line cannot say WHICH resource was touched.
        self.assertEqual(PROD, _c(">& %s echo hi" % PROD)["target_ref"])

    def test_the_filed_input_is_not_benign(self):
        self.assertNotEqual("benign",
                            _c(">& %s echo hi" % PROD)["classification_tier"])

    def test_the_no_space_twin_is_the_same_destruction(self):
        # `>&/srv/prod/db.sqlite` is ONE token, not two, and it destroys the
        # same file.  It escaped for the same reason and by a different route.
        got = _c(">&%s echo hi" % PROD)
        self.assertEqual("delete", got["verb"])
        self.assertEqual(PROD, got["target_ref"])


class TestLeadingAndTrailingAgree(unittest.TestCase):
    """Where the operator is written must not change the verdict.

    This is the property the fix is built on, rather than a list of spellings:
    a classifier that answers differently depending on which side of the
    command word the redirection sits on is wrong in one of the two answers,
    and which one it is depends on the spelling the caller happened to pick.
    """

    def test_every_axis_agrees_across_position_for_both_streams(self):
        lead = _c(">& %s echo hi" % PROD)
        trail = _c("echo hi >& %s" % PROD)
        for axis in ("verb", "reversibility", "blast_radius", "externality",
                     "classification_tier", "danger_signature", "target_ref"):
            self.assertEqual(lead[axis], trail[axis],
                             "%s differs by where the >& is written" % axis)

    def test_agreement_holds_with_the_space_removed_on_both_sides(self):
        lead = _c(">&%s echo hi" % PROD)
        trail = _c("echo hi >&%s" % PROD)
        for axis in ("verb", "reversibility", "classification_tier",
                     "target_ref"):
            self.assertEqual(lead[axis], trail[axis])

    def test_agreement_holds_for_an_ORDINARY_file_too(self):
        # The gate is the TARGET, not the position and not the operator, so
        # the two spellings must agree on `allow` just as firmly as they agree
        # on `ask`.  Before this fix they did -- both benign -- for the wrong
        # reason: the leading one was invisible rather than judged.
        lead = _c(">& %s echo hi" % ORDINARY)
        trail = _c("echo hi >& %s" % ORDINARY)
        self.assertEqual(lead["verb"], trail["verb"])
        self.assertNotEqual("delete", lead["verb"])

    def test_a_systemic_path_is_systemic_in_the_leading_position(self):
        self.assertEqual(
            "destructive_systemic",
            _c(">& %s echo hi" % SYSTEMIC)["classification_tier"])


class TestWhatIsNotATruncation(unittest.TestCase):
    """The half that keeps the fix honest.

    A rule that priced every `>&` as a truncation would pass every test in
    the two classes above.  Ground truth: the canary SURVIVES on all of these,
    so a `delete` here would be a false positive on the most common
    redirection idioms there are.
    """

    def test_fd_duplication_in_the_leading_position_is_not_a_file(self):
        for command in (">&1 echo hi", ">&2 echo hi", "2>&1 echo hi",
                        "1>&2 echo hi"):
            with self.subTest(command=command):
                got = _c(command)
                self.assertNotEqual("delete", got["verb"])
                self.assertIsNone(got["target_ref"])

    def test_fd_CLOSE_is_not_a_file(self):
        # `>&-` closes the descriptor.  `-` is bash's third and last fd
        # operand; it is never a path.
        for command in (">&- echo hi", "2>&- echo hi", "echo hi >&-"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_an_ordinary_file_stays_with_the_command_that_wrote_it(self):
        # `pytest -q >& out.log` must not become a destruction: see
        # `everyday-redirect-build-log` in the corpus for the same requirement
        # on `>`.
        for command in (">& out.log pytest -q", ">& build.log echo hi",
                        ">&./notes.md echo hi"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_a_discard_sink_is_not_a_destruction(self):
        for command in (">& /dev/null echo hi", ">&/dev/null echo hi",
                        ">& /dev/stderr echo hi"):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_appending_does_not_destroy_the_prior_contents(self):
        # Ground truth: canary SURVIVES.  `&>>` is the both-streams append and
        # is the operator most easily swept up by a careless `>&`/`&>` rule.
        for command in (">> %s echo hi" % PROD, "&>> %s echo hi" % PROD,
                        "echo hi >> %s" % PROD, "echo hi &>> %s" % PROD):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])

    def test_reading_and_read_write_open_do_not_truncate(self):
        for command in ("< %s cat" % PROD, "<> %s true" % PROD):
            with self.subTest(command=command):
                self.assertNotEqual("delete", _c(command)["verb"])


class TestTheClobberOverrideTargetIsClean(unittest.TestCase):
    """`&>|` must not leave its `|` glued to the front of the path.

    `_TRUNCATING_REDIRECT_RE`'s alternation is tried left to right, and with
    `&>` ahead of `&>|` the longer operator never got a chance: the target
    came back as `|/srv/prod/db.sqlite`, a file that does not exist.  The
    VERDICT was right and the `target_ref` named the wrong thing, so nothing
    went red -- it was found by a before/after sweep, not by reading the
    pattern.  Pre-existing on main for the trailing spelling; this fix would
    have widened it to the leading one.

    Note `&>|` is a bash SYNTAX ERROR in every position (measured: rc=2, the
    canary survives, nothing is written), so pricing it a destruction at all
    is a conservative over-call rather than a fail-open.  That over-call is
    also pre-existing and is deliberately NOT changed here: removing it would
    LOWER rows, which is the one thing this change is not allowed to do.
    Flagged for its own ticket.
    """

    def test_the_operator_is_split_off_whole(self):
        m = _TRUNCATING_REDIRECT_RE.match("&>|%s" % PROD)
        self.assertIsNotNone(m)
        self.assertEqual("&>|", m.group(1))
        self.assertEqual(PROD, m.group(2))

    def test_the_target_carries_no_operator_character(self):
        for command in ("&>|%s" % PROD, "echo hi &>|%s" % PROD,
                        "&>|%s echo hi" % PROD):
            with self.subTest(command=command):
                ref = _c(command)["target_ref"]
                self.assertEqual(PROD, ref)
                self.assertFalse(ref.startswith("|"))

    def test_the_append_form_is_still_refused(self):
        # `&>>` appends.  The new `&>|` branch must not make it match.
        self.assertIsNone(_TRUNCATING_REDIRECT_RE.match("&>>%s" % PROD))


class TestTheGuardCanFail(unittest.TestCase):
    """Exercise the extractor directly, so a green suite means something.

    A guard only ever seen passing has not been tested.  These call the
    extractor rather than the classifier, so they fail on a changed mechanism
    even when some other rule happens to reach the same verdict.
    """

    def test_the_extractor_finds_a_leading_both_streams_target(self):
        self.assertEqual(
            [PROD],
            _redirect_overwrite_targets(_safe_split(">& %s echo hi" % PROD)))

    def test_the_extractor_refuses_every_fd_operand(self):
        for command in (">&1 echo hi", ">&2 echo hi", ">&- echo hi",
                        "2>&1 echo hi", "echo hi 2>&1"):
            with self.subTest(command=command):
                self.assertIsNone(
                    _redirect_overwrite_targets(_safe_split(command)))

    def test_the_extractor_refuses_an_ordinary_file(self):
        self.assertIsNone(
            _redirect_overwrite_targets(_safe_split(">& build.log echo hi")))

    def test_the_scan_sees_the_prefix_position_at_all(self):
        # The regression this fix exists to prevent: `_classify_segment` used
        # to hand `_redirect_overwrite_targets` the PEELED tokens, from which
        # a leading redirection had already been removed.  Asserted on the
        # extractor's own input so it fails if that wiring is reverted.
        peeled_away = _safe_split("echo hi")
        self.assertIsNone(_redirect_overwrite_targets(peeled_away))
        self.assertEqual(
            [PROD],
            _redirect_overwrite_targets(_safe_split(">& %s echo hi" % PROD)),
            "the leading redirection must still be in the token list the "
            "scan is given")

    def test_a_leading_operator_with_no_target_does_not_crash(self):
        for command in (">&", ">& ", "2>&", ">&|"):
            with self.subTest(command=command):
                self.assertIsInstance(_c(command), dict)


if __name__ == "__main__":
    unittest.main()
