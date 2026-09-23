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
    ".rig/arm.sh",
    ".probe-rfx342/out.json",
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


if __name__ == "__main__":
    unittest.main()
