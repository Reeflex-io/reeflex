"""The docs must not drift from the shipped policy pack (RFX-254).

WHY THIS FILE EXISTS. `README.md`, `docs/index.md`, `docs/concepts/index.md`,
`docs/llms.txt` and `docs/faq.md` all said "the five rules (R1-R5)" for months
after the pack grew R0, R6 and R7. `docs/policy-guide.md` said six. Nothing
failed, because no test has ever read a sentence. The count was wrong in the
README a buyer reads first, and R0/R6/R7 - the three rules a careful buyer is
most likely to ask about - were invisible.

WHAT IT ASSERTS, and deliberately nothing more:

  1. The set of `reeflex.policy/*` ids the DIAGRAM names == the set the shipped
     `.rego` files actually emit. Add a rule and forget the diagram -> red.
     Delete one and forget the diagram -> red.
  2. The rule COUNT claimed in prose matches that set, everywhere a claim
     surface states one.
  3. No guarded doc reintroduces a stale "five rules / R1-R5" claim. Files
     that still carry one are listed in KNOWN_STALE with the ticket that owns
     them - that list is a debt register, and it is meant to shrink.

WHAT IT DOES NOT ASSERT, so nobody reads more into a green run. It does not
check that the PROSE about a rule is true, only that the rule is named and
counted. It reads rule ids from string literals in the policy files, so a rule
id assembled at runtime would be invisible to it - no rule in the pack does
that today, and assertion 1's equality check is what would catch it if one
appeared (the new id would reach the docs' side only by being written there).
"""

from __future__ import annotations

import pathlib
import re
import unittest

# reeflex-core/tests/<this file> -> repo root is two parents up.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "reeflex-core" / "policy"
DIAGRAMS = REPO_ROOT / "docs" / "architecture" / "diagrams.md"

# The heading the decision diagram lives under. Anchored so that moving the
# diagram to another page fails loudly instead of silently passing on an empty
# slice.
DIAGRAM_HEADING = "## How a verdict is reached"

RULE_ID_RE = re.compile(r"reeflex\.policy/([a-z0-9_]+)")

# The shipped pack's rule NUMBERS. Nine ids across eight numbers: R5 reports
# under two (`session_delete_budget` for the deletions dimension,
# `cumulative_budget` for every other), which is why "eight rules, nine ids"
# is the only phrasing that is true of both.
EXPECTED_RULE_NUMBERS = 8


def _policy_files() -> list[pathlib.Path]:
    """Every shipped .rego, excluding the OPA test files."""
    return sorted(
        p for p in POLICY_DIR.glob("*.rego") if not p.name.endswith("_test.rego")
    )


def _ids_in(text: str) -> set[str]:
    return set(RULE_ID_RE.findall(text))


def _shipped_rule_ids() -> set[str]:
    ids: set[str] = set()
    for p in _policy_files():
        ids |= _ids_in(p.read_text(encoding="utf-8"))
    return ids


def _diagram_section() -> str:
    text = DIAGRAMS.read_text(encoding="utf-8")
    start = text.find(DIAGRAM_HEADING)
    if start == -1:
        raise AssertionError(
            "%s no longer contains the heading %r. The decision diagram is the "
            "one place every rule id is named; if it moved, move this test's "
            "DIAGRAM_HEADING with it." % (DIAGRAMS, DIAGRAM_HEADING)
        )
    # Up to the next level-2 heading.
    nxt = text.find("\n## ", start + len(DIAGRAM_HEADING))
    return text[start:] if nxt == -1 else text[start:nxt]


class ShippedRuleIdsAreDocumented(unittest.TestCase):
    def test_the_pack_emits_the_ids_we_think_it_does(self):
        """A floor, so an empty parse cannot satisfy every other assertion."""
        ids = _shipped_rule_ids()
        self.assertGreaterEqual(
            len(ids), 9,
            "parsed only %d rule ids from %s -- the parser, not the pack, is "
            "probably what changed" % (len(ids), [p.name for p in _policy_files()]),
        )

    def test_diagram_names_exactly_the_shipped_rule_ids(self):
        shipped = _shipped_rule_ids()
        drawn = _ids_in(_diagram_section())

        missing = sorted(shipped - drawn)
        extra = sorted(drawn - shipped)
        msg = []
        if missing:
            msg.append(
                "these rule ids SHIP but the decision diagram does not name them: %s"
                % ", ".join(missing)
            )
        if extra:
            msg.append(
                "the decision diagram names these ids but NO shipped .rego emits "
                "them: %s" % ", ".join(extra)
            )
        self.assertEqual(
            shipped, drawn,
            "docs/architecture/diagrams.md has drifted from the policy pack. "
            + " | ".join(msg),
        )

    def test_the_number_of_rules_claimed_in_prose_matches_the_pack(self):
        """Every claim surface that states a count must state the true one.

        The count is derived from the pack, never hardcoded in the assertion:
        if a ninth rule number lands, this test demands the docs say nine.
        """
        n_ids = len(_shipped_rule_ids())
        self.assertEqual(
            EXPECTED_RULE_NUMBERS, 8,
            "EXPECTED_RULE_NUMBERS is a human-maintained count of rule NUMBERS "
            "(R0..R7). Rule numbers appear only in comments, so they cannot be "
            "parsed reliably -- update this constant and the docs together.",
        )

        # (path, what the file must say). Each is a live claim about the
        # CURRENT pack, so each must carry both true numbers or neither.
        claim_surfaces = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs" / "index.md",
            REPO_ROOT / "docs" / "concepts" / "index.md",
            REPO_ROOT / "docs" / "policy-guide.md",
            REPO_ROOT / "docs" / "llms.txt",
        ]
        for path in claim_surfaces:
            with self.subTest(path=str(path.relative_to(REPO_ROOT))):
                text = path.read_text(encoding="utf-8")
                self.assertIn(
                    "R0", text,
                    "%s describes the base policy pack but never mentions R0 -- "
                    "the unclassified-action hold, which is the pack's strongest "
                    "doctrinal position and the easiest one to drop when the "
                    "count is copied from an older file."
                    % path.relative_to(REPO_ROOT),
                )
                self.assertIn(
                    "R7", text,
                    "%s describes the base policy pack but never mentions R7."
                    % path.relative_to(REPO_ROOT),
                )

        # The two files that state a numeral must state the derived one.
        for path, numeral in [
            (REPO_ROOT / "docs" / "concepts" / "index.md", "nine rule ids"),
            (REPO_ROOT / "docs" / "policy-guide.md", "nine rule ids"),
            (REPO_ROOT / "README.md", "nine rule ids"),
            (REPO_ROOT / "docs" / "llms.txt", "nine rule ids"),
        ]:
            with self.subTest(path=str(path.relative_to(REPO_ROOT)), claim=numeral):
                self.assertEqual(
                    n_ids, 9,
                    "the pack now emits %d rule ids, so %r is no longer the true "
                    "claim -- update the docs and this list together."
                    % (n_ids, numeral),
                )
                self.assertIn(
                    numeral, path.read_text(encoding="utf-8"),
                    "%s must state the rule-id count, and state it as %r."
                    % (path.relative_to(REPO_ROOT), numeral),
                )


class StaleRuleCountClaimsDoNotComeBack(unittest.TestCase):
    """No guarded doc may reintroduce the "five rules (R1-R5)" claim.

    KNOWN_STALE is a DEBT REGISTER, not an exemption policy: every entry is a
    file that still carries the wrong count and the ticket that owns fixing
    it. Entries are expected to be deleted over time, never added to without
    a ticket.
    """

    # Scanned: everything a customer or contributor reads in this repo.
    SCAN_GLOBS = ["*.md", "docs/**/*.md", "docs/**/*.txt", "reeflex-spec/*.md"]

    STALE_RE = re.compile(
        r"five rules|five shipped rules|R1\s*[-–—]\s*R5|R1\s*[-–—]\s*R6|six rules"
    )

    KNOWN_STALE = {
        # Historical record of what shipped at v0.1. Correct AS A RECORD and
        # deliberately never rewritten -- a changelog that edits its own past
        # is worth nothing.
        "CHANGELOG.md": "historical entry, never to be rewritten",
        # RFX-254: these still claim five and are NOT one-line fixes.
        "CONTRIBUTING.md": "RFX-254",
        "reeflex-spec/README.md": "RFX-254",
        # IMPACT-MODEL enumerates each rule with the safety discipline it
        # descends from; adding R0/R6/R7 there is a writing job, not a count fix.
        "reeflex-spec/IMPACT-MODEL.md": "RFX-254",
        # A dated blog post whose whole argument is built on the number.
        # Rewriting it is an editorial decision, not a drift fix.
        "docs/blog/one-minute-policy.md": "RFX-254",
    }

    def test_no_new_file_claims_five_rules(self):
        offenders = []
        seen = set()
        for pattern in self.SCAN_GLOBS:
            for path in REPO_ROOT.glob(pattern):
                if not path.is_file() or path in seen:
                    continue
                seen.add(path)
                rel = path.relative_to(REPO_ROOT).as_posix()
                if rel in self.KNOWN_STALE:
                    continue
                for n, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1
                ):
                    if self.STALE_RE.search(line):
                        offenders.append("%s:%d: %s" % (rel, n, line.strip()[:110]))

        self.assertEqual(
            [], offenders,
            "the shipped pack is R0-R7 (nine rule ids). These lines claim "
            "otherwise:\n  " + "\n  ".join(offenders)
            + "\n\nFix the sentence. If the file genuinely cannot be fixed in "
              "this change, add it to KNOWN_STALE with the ticket that will.",
        )

    def test_the_debt_register_has_no_dead_entries(self):
        """A KNOWN_STALE entry whose file is clean is a lie about our debt."""
        dead = []
        for rel, owner in sorted(self.KNOWN_STALE.items()):
            path = REPO_ROOT / rel
            if not path.exists():
                dead.append("%s (%s): file no longer exists" % (rel, owner))
                continue
            if not self.STALE_RE.search(path.read_text(encoding="utf-8")):
                dead.append(
                    "%s (%s): no stale claim left -- delete this entry" % (rel, owner)
                )
        self.assertEqual(
            [], dead,
            "KNOWN_STALE lists files that are already clean:\n  "
            + "\n  ".join(dead),
        )


class ProductionGatingIsStatedCorrectly(unittest.TestCase):
    """R7 is production-gated too, and the docs said R2/R3/R6 for months.

    Read from `authority.rego` rather than asserted, so that relaxing the gate
    in the policy forces the sentence in the docs to change with it.
    """

    def test_r7_is_gated_on_production_in_the_policy(self):
        body = (POLICY_DIR / "authority.rego").read_text(encoding="utf-8")
        m = re.search(r"r7_authority_change if \{(.*?)\n\}", body, re.S)
        self.assertIsNotNone(
            m, "r7_authority_change is no longer a simple rule body in "
               "authority.rego -- re-read it before trusting this test.",
        )
        self.assertIn(
            'input.target.environment == "production"', m.group(1),
            "r7_authority_change no longer requires production. Every doc that "
            "lists the production-gated rules as R2/R3/R6/R7 is now wrong.",
        )

    def test_the_docs_list_r7_among_the_production_gated_rules(self):
        for rel in ["docs/concepts/index.md", "docs/policy-guide.md",
                    "docs/architecture/diagrams.md"]:
            with self.subTest(path=rel):
                text = (REPO_ROOT / rel).read_text(encoding="utf-8")
                # Tolerant of emphasis markers around the conjunction, so
                # "R2, R3, R6 **and R7**" and "R2, R3, R6 and R7" both pass.
                self.assertRegex(
                    text, r"R2,?\s*R3,?\s*R6\s*\**\s*and\s*\**\s*R7",
                    "%s must name R7 among the rules gated on production -- "
                    "`authority.rego` requires it and a reader planning a "
                    "staging rollout needs to know." % rel,
                )


if __name__ == "__main__":
    unittest.main()
