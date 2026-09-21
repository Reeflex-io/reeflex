"""RFX-356 -- the order of two commands must not decide the verdict.

`_classify_bash` reports the most severe candidate on the line.  When two
candidates score an IDENTICAL severity key, `max()` keeps the FIRST one, so
POSITION ON THE LINE chose which `target_ref` reached core -- and position is
supplied by the agent being audited.  Measured against the real pack before the
fix: 144 of 225 pairs over a 5x5x3x3 grid answered `allow` in one order and
`require_approval` in the other.

These tests pin the PROPERTY (reordering changes nothing) rather than a list of
spellings, because the defect is structural and a spelling list would go stale
the next time a destroyer is added to the vocabulary.
"""

import itertools
import unittest

from reeflex_claude import classify as C


# Destroyers whose refs the FHS designates temporary.
EPHEMERAL = [
    "dd if=/dev/zero of=/tmp/x",
    "rm /tmp/scratch.txt",
    "truncate -s 0 /tmp/y",
    "shred -u /tmp/z",
    "> /tmp/w echo hi",
]

# Destroyers naming paths under core's DEFAULT `protected_assets` prefixes.
# Deliberately NOT all secrets: /srv/prod/config.json and /data/customers.csv
# are invisible to `_SENSITIVE_PATH_RE`, which is exactly why the tie-break
# cannot be built from the adapter's own sensitive-path knowledge.
PROTECTED = [
    "rm /srv/prod/secrets.env",
    "rm /srv/prod/config.json",
    "truncate -s 0 /var/lib/app/state.bin",
    "shred -u /data/customers.csv",
    "dd if=/dev/zero of=/srv/prod/ledger.dat",
]

SEPARATORS = [" ; ", " && ", " || "]
WRAPPERS = [("", ""), ("{ ", " ; }"), ("( ", " )")]


def _ref(command):
    return C.classify("Bash", {"command": command}).get("target_ref")


class TestSegmentOrderDoesNotDecide(unittest.TestCase):
    def test_the_headline_pair_from_the_ticket(self):
        """The two lines RFX-356 was filed on, in both orders."""
        protected_first = "{ rm /srv/prod/secrets.env ; dd if=/dev/zero of=/tmp/x ; }"
        ephemeral_first = "{ dd if=/dev/zero of=/tmp/x ; rm /srv/prod/secrets.env ; }"
        self.assertEqual(_ref(protected_first), "/srv/prod/secrets.env")
        self.assertEqual(
            _ref(ephemeral_first), "/srv/prod/secrets.env",
            "the ephemeral destruction was placed first and carried the line: "
            "the agent chose the verdict by choosing the order",
        )

    def test_reordering_never_changes_the_named_ref(self):
        """The property, over the whole grid: 225 pairs, both orders."""
        flipped = []
        for eph, prot, sep, (open_w, close_w) in itertools.product(
                EPHEMERAL, PROTECTED, SEPARATORS, WRAPPERS):
            a = open_w + eph + sep + prot + close_w
            b = open_w + prot + sep + eph + close_w
            if _ref(a) != _ref(b):
                flipped.append((a, _ref(a), b, _ref(b)))
        self.assertEqual(
            flipped, [],
            "%d of %d pairs name a different target_ref when reordered"
            % (len(flipped), len(EPHEMERAL) * len(PROTECTED)
               * len(SEPARATORS) * len(WRAPPERS)),
        )

    def test_the_non_temporary_ref_is_the_one_named(self):
        """Not merely stable under reordering -- stable on the SAFE side.

        A tie-break that consistently named the temporary ref would also make
        the property above pass, and would be the fail-open.
        """
        for eph, prot in itertools.product(EPHEMERAL, PROTECTED):
            for line in (eph + " ; " + prot, prot + " ; " + eph):
                ref = _ref(line)
                self.assertFalse(
                    C._is_fhs_temporary(ref),
                    "%r named the temporary ref %r while also destroying a "
                    "declared production asset" % (line, ref),
                )


class TestTheTieBreakOnlyBreaksTIES(unittest.TestCase):
    """The tie-break must not become a second severity axis."""

    def test_a_more_severe_temporary_candidate_still_wins(self):
        """Severity is compared FIRST; the tie-break never overrides it.

        `rm -rf /tmp/build` is unbounded -> `broad`, which outranks a single
        named file on tier.  It must keep winning even though its ref is
        temporary and the other candidate's is not -- otherwise this fix would
        have quietly downgraded every line that pairs a wide scratch deletion
        with a narrow named one.

        (`broad` and not `systemic`: `_SYSTEM_DIR_RE` does not match /tmp, so
        the unbounded deletion is priced broad.  Asserted as measured.)
        """
        line = "rm /home/app/notes.txt ; rm -rf /tmp/build"
        cls = C.classify("Bash", {"command": line})
        self.assertEqual(cls.get("blast_radius"), "broad")
        self.assertEqual(cls.get("target_ref"), "/tmp/build")
        # and the tie-break genuinely was not consulted: the two candidates do
        # NOT tie, so severity alone decided.
        narrow = C.classify("Bash", {"command": "rm /home/app/notes.txt"})
        self.assertNotEqual(C._severity(cls), C._severity(narrow))

    def test_an_all_ephemeral_line_is_unchanged(self):
        """No escalation on a line that destroys only scratch."""
        cls = C.classify("Bash", {"command": "rm /tmp/a ; rm /tmp/b"})
        self.assertTrue(C._is_fhs_temporary(cls.get("target_ref")))
        self.assertEqual(cls.get("reversibility"), "irreversible")

    def test_a_single_candidate_line_is_untouched(self):
        for line, expected in (("rm /tmp/a", "/tmp/a"),
                               ("rm /srv/prod/db.sqlite", "/srv/prod/db.sqlite")):
            self.assertEqual(_ref(line), expected)


class TestIsFhsTemporary(unittest.TestCase):
    def test_prefix_and_exact_forms(self):
        for ref in ("/tmp/x", "/tmp", "/var/tmp/y", "/var/cache/z",
                    "/dev/shm/a", "/run/b", "/TMP/UPPER"):
            self.assertTrue(C._is_fhs_temporary(ref), ref)

    def test_production_paths_are_not_temporary(self):
        for ref in ("/srv/prod/db", "/var/lib/app/state", "/data/x",
                    "/home/app/data/y", "/tmpfoo/notatemp"):
            self.assertFalse(C._is_fhs_temporary(ref), ref)

    def test_an_unnamed_ref_is_not_temporary(self):
        """An adapter that cannot name what it destroys has not established
        that the thing is scratch."""
        for ref in (None, "", 17, ["/tmp/x"]):
            self.assertFalse(C._is_fhs_temporary(ref), repr(ref))


if __name__ == "__main__":
    unittest.main()
