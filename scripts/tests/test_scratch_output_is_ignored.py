"""RFX-212 (monorepo leg): per-round agent scratch output must not be stageable.

RFX-212 was filed and fixed in reeflex-app in August 2026. Its own claim file
recorded the part that was never done -- "the MONOREPO (/root/reeflex) was not
checked for the same gap" -- and nobody checked it for 32 days. It has the gap.

Measured 2026-09-23 across all 245 worktrees of this repo, before the fix: a
`git add -A` would stage 5905 untracked files, 1414 of them under `.scratch*`
alone. Excluding throwaway virtualenvs as instrument noise, 525 of the rest
carried a credential-shaped string by the same `token|secret|password|api[_-]key`
regex RFX-212 used; one worktree accounted for 328.

WHAT THIS GUARD DOES AND DOES NOT PROMISE.
It asserts that the directory-name prefixes the fleet demonstrably writes are
ignored, and -- just as importantly -- that ordinary source paths are NOT, so a
future "ignore everything" edit reddens here rather than silently hiding a real
file. It CANNOT see a scratch directory named outside these prefixes: the rule
is a list and is only as wide as the names on it. `qa294-probe/` is a real,
measured example that this rule does not cover and this guard does not claim to.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(__file__).resolve().parent,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
)

# Directory names read off the 2026-09-23 census of this repo's worktrees, plus
# one synthetic name per prefix so the guard pins the PATTERN and not the sample.
#
# EVERY SAMPLE HERE MUST BE REACHABLE ONLY BY THE RULE IT IS MEANT TO PIN.
# Measured qa--329, 2026-09-23, by deleting each added rule alone and re-running
# this file: `.walk*/` and `.cache/` came out GREEN under that arm, i.e. nothing
# here reached them. `.walk-rfx64/run-a.log` is a `.log`, so with `.walk*/` gone
# the long-standing `*.log` rule still ignores it and the sample cannot tell the
# two rules apart; `.cache/` had no sample at all. Either rule could have been
# deleted later with this guard still green. The two entries marked below close
# that, and `test_each_scratch_rule_is_load_bearing` asserts the property
# directly rather than leaving it to whoever picks the next sample.
MUST_BE_IGNORED = [
    ".scratch/decisions.jsonl",
    ".scratch-dev1-217/capture.txt",
    ".scratch-dev3-170/probe.json",
    ".rfx-qa218/holds.jsonl",
    ".rfx-qa219/core-state.json",
    ".rfx170/anything.txt",
    ".venv-241/lib/python3.12/site-packages/x.py",
    ".venv-before/pyvenv.cfg",
    ".walk-rfx64/run-a.log",
    ".walk-rfx100/probe.json",   # non-`.log`: the only sample `.walk*/` alone reaches
    ".rig/arm.sh",
    ".probe-rfx342/out.json",
    ".cache/http/body.bin",      # `.cache/` had no sample at all
]

# The over-wideness arm. These are ordinary tracked-source paths and repo
# infrastructure; if a widening of the rule ever swallows one of them, a real
# change would stop being stageable and nobody would be told. Kept deliberately
# adjacent to the dot-directory rules, including a dotfile directory.
MUST_NOT_BE_IGNORED = [
    "reeflex-core/policy/pack.rego",
    "reeflex-core/tests/test_decide.py",
    "scripts/check_migration_heads.py",
    "scripts/tests/test_scratch_output_is_ignored.py",
    ".github/workflows/gate.yml",
    ".dockerignore",
    "README.md",
]


# The rules RFX-212 added, in the order they appear in `.gitignore`. Listed here
# rather than parsed so that renaming or dropping one reddens this file by name.
SCRATCH_RULES = [
    ".scratch*/",
    ".rfx*/",
    ".walk*/",
    ".venv-*/",
    ".rig/",
    ".probe*/",
    ".cache/",
]


def _ignored_under(gitignore_text: str, path: str) -> bool:
    """True iff `path` is ignored by `gitignore_text` alone, evaluated in a
    throwaway repo so the real tree is never mutated to answer the question.

    `--no-index` because the question is "do these RULES hide this path", not
    "what does this checkout's index say" -- the distinction `_is_ignored`
    documents. Gated on exit STATUS, never on output.
    """
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "init", "-q", tmp], check=True,
                       capture_output=True, text=True)
        Path(tmp, ".gitignore").write_text(gitignore_text)
        r = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", "--", path],
            cwd=tmp, capture_output=True, text=True,
        )
        if r.returncode not in (0, 1):
            raise AssertionError(
                "git check-ignore failed on %r: rc=%s stderr=%s"
                % (path, r.returncode, r.stderr.strip())
            )
        return r.returncode == 0


def _is_ignored(path: str, no_index: bool = False) -> bool:
    """True iff git would ignore `path`. Gated on exit STATUS, never on output:
    0 = ignored, 1 = not ignored, anything else is the instrument failing.

    `no_index=True` is required for any path that is TRACKED. `git check-ignore`
    consults the index and never reports a tracked file as ignored, whatever the
    rules say -- so an over-wideness arm written without it passes on every input
    and tests nothing. Measured while building this guard: with `.g*/` appended
    to `.gitignore`, `check-ignore .github/workflows/ci.yml` says "not ignored"
    by default and "ignored" under `--no-index`. The default answers "would git
    ignore this file today"; `--no-index` answers "do the RULES hide this path",
    which is the question the over-wideness arm is asking.
    """
    cmd = ["git", "check-ignore", "-q"]
    if no_index:
        cmd.append("--no-index")
    r = subprocess.run(
        cmd + ["--", path],
        cwd=REPO, capture_output=True, text=True,
    )
    if r.returncode not in (0, 1):
        raise AssertionError(
            "git check-ignore failed on %r: rc=%s stderr=%s"
            % (path, r.returncode, r.stderr.strip())
        )
    return r.returncode == 0


class TestScratchOutputIsIgnored(unittest.TestCase):
    def test_every_measured_scratch_class_is_ignored(self):
        stageable = [p for p in MUST_BE_IGNORED if not _is_ignored(p)]
        self.assertEqual(
            [], stageable,
            "RFX-212: a `git add -A` would stage per-round agent scratch output. "
            "These paths are not ignored: %s" % stageable,
        )

    def test_the_rule_does_not_swallow_real_files(self):
        """Over-wideness arm: the fix must not buy its green by ignoring source.

        `no_index=True` is load-bearing here -- every path below is tracked, and
        without it this assertion passes unconditionally. See `_is_ignored`."""
        swallowed = [p for p in MUST_NOT_BE_IGNORED if _is_ignored(p, no_index=True)]
        self.assertEqual(
            [], swallowed,
            "The scratch rule has grown wide enough to hide real files, so a "
            "genuine change to them would silently not be staged: %s" % swallowed,
        )

    def test_the_guard_can_tell_the_two_apart(self):
        """Vacuity arm. If `git check-ignore` were broken or the cwd wrong, both
        lists above could pass by returning a constant. Assert the instrument
        actually discriminates on this tree."""
        self.assertTrue(_is_ignored(".scratch/x"), "instrument reports nothing ignored")
        self.assertFalse(_is_ignored("README.md"), "instrument reports everything ignored")
        # and the same discrimination on the --no-index plane the arm above uses,
        # so a change that breaks only that plane cannot go unnoticed.
        self.assertTrue(_is_ignored(".scratch/x", no_index=True), "no-index: nothing ignored")
        self.assertFalse(_is_ignored("README.md", no_index=True), "no-index: all ignored")

    def test_each_scratch_rule_is_load_bearing(self):
        """Every rule above must have a sample that ONLY that rule reaches.

        Without this, a sample can be redundantly covered by an older, narrower
        rule and the new one is pinned by nothing -- deletable later with this
        file still green. Measured qa--329: that was true of `.walk*/` (its only
        sample was a `.log`, already caught by the long-standing `*.log`) and of
        `.cache/` (no sample at all). This asserts the property instead of
        trusting whoever picks the next sample.

        Instrument limit, stated: the throwaway repo carries only the ROOT
        `.gitignore`, so a sample a nested `.gitignore` also covered would read
        as load-bearing here. Every sample above is a root dot-directory, where
        no nested file applies.
        """
        text = (REPO / ".gitignore").read_text()
        unpinned = []
        for rule in SCRATCH_RULES:
            self.assertEqual(
                1, text.count("\n%s\n" % rule),
                "anchor: %r is not present exactly once in .gitignore" % rule,
            )
            without = text.replace("\n%s\n" % rule, "\n")
            # A sample pins `rule` iff the full ruleset ignores it and the
            # ruleset minus `rule` does not.
            if not any(
                _ignored_under(text, p) and not _ignored_under(without, p)
                for p in MUST_BE_IGNORED
            ):
                unpinned.append(rule)
        self.assertEqual(
            [], unpinned,
            "These rules are reached by no sample in MUST_BE_IGNORED, so deleting "
            "them leaves this guard green: %s" % unpinned,
        )


if __name__ == "__main__":
    unittest.main()
