"""Unit tests for scripts/check_published_connector.py (RFX-360).

WHY THIS FILE EXISTS AT ALL. The script had no suite. It is the only instrument
that says whether the n8n connector a customer installs still lags this tree,
and a check with no test is graded by whether it stays green.

Nothing here touches the network: every channel is a fixture built in memory.

Written as unittest TestCases because bare pytest-style functions in this root
would collect zero tests and pass forever — this root is run by
`unittest discover -s scripts/tests -t scripts` (gate.py), and RFX-87 is the
ticket about a guard that had never executed an assertion.
"""

import io
import os
import re
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import check_published_connector as cpc  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _norm(text):
    """Collapse whitespace before asserting on a rendered line.

    An assertion on a printed line otherwise measures where the text happened to
    wrap rather than what it says.
    """
    return re.sub(r"\s+", " ", text).strip()


def _tree_channel():
    """The tree arm, read from THIS checkout — the real files, not a fixture.

    REPO_ROOT is asserted rather than assumed: a probe that reads another
    worktree's scripts/ silently measures somebody else's tree.
    """
    assert cpc.REPO_ROOT == __import__("pathlib").Path(REPO_ROOT), (
        "module REPO_ROOT %s is not this checkout %s" % (cpc.REPO_ROOT, REPO_ROOT))
    return cpc.load_tree()


def _published(tree, delivered_artefacts, channel="github", version="FIXTURE"):
    """A published channel carrying the tree's bytes for `delivered_artefacts`.

    Every other artefact gets bytes with the fix taken back OUT — the probe that
    targets it is substituted away — so "not delivered" here is a file that is
    present and serving the old behaviour, which is the real lag. A fixture that
    omitted the file would exercise the NO-SUCH-FILE path and prove something
    else. The substitution is asserted to have changed the bytes: a revert that
    is a no-op scores as a pass and the arm proves nothing.
    """
    ch = cpc.Channel(channel, version=version)
    for name, paths in cpc.ARTEFACTS.items():
        rel_pub = paths.get(channel)
        rel_tree = paths.get("tree")
        if rel_pub is None or rel_tree is None:
            continue
        text = tree.text(rel_tree)
        if text is None:
            continue
        if name not in delivered_artefacts:
            for prop in cpc.PROPERTIES:
                if prop.artefact != name:
                    continue
                reverted = prop.probe.sub("<<NOT-IN-THIS-RELEASE>>", text)
                assert reverted != text, (
                    "taking %s out of %s was a no-op — the fixture is not the "
                    "arm it claims to be" % (prop.id, rel_tree))
                text = reverted
        ch.files[rel_pub] = text
    return ch


class ChannelFlag(unittest.TestCase):
    """RFX-360: `--channel X` must score X, not crash on the one not fetched."""

    def setUp(self):
        self.tree = _tree_channel()

    def test_scoring_one_channel_does_not_raise(self):
        published = {"github": _published(self.tree, set())}
        try:
            findings, _ = cpc.evaluate(self.tree, published)
        except KeyError as exc:  # pragma: no cover - this is the regression
            self.fail("evaluate() raised KeyError(%s) when only the github "
                      "channel was fetched — RFX-360" % exc)
        self.assertNotIn("PROBE-STALE", sorted({f.kind for f in findings}))

    def test_rows_on_an_unfetched_channel_are_not_reported_as_orphans(self):
        published = {"github": _published(self.tree, set())}
        findings, _ = cpc.evaluate(self.tree, published)
        orphans = [f for f in findings if f.kind == "ORPHAN-DECLARATION"]
        self.assertEqual(
            [], orphans,
            "every npm row was reported as an orphan because npm was not "
            "fetched, and an orphan's remedy is 'remove it' — a row whose "
            "channel nobody READ this run is not a row nobody scores",
        )

    def test_an_orphan_row_on_a_FETCHED_channel_is_still_reported(self):
        """The control for the test above: the orphan rule must still work."""
        published = {"github": _published(self.tree, set())}
        bogus = cpc.Lag("no-such-property", "github", "RFX-000", "2026-09-19", "never")
        with mock.patch.object(cpc, "LAG", list(cpc.LAG) + [bogus]):
            findings, _ = cpc.evaluate(self.tree, published)
        self.assertEqual(
            1, len([f for f in findings if f.kind == "ORPHAN-DECLARATION"]),
            "a declared row naming a property nothing scores, on a channel that "
            "WAS read, must still be reported",
        )


class ChannelFlagEndToEnd(unittest.TestCase):
    """The flag as an operator runs it, through main(), with no network."""

    def _run_main(self, argv):
        tree = _tree_channel()
        gh = _published(tree, set(), channel="github", version="FIXTURE gh")
        npm = _published(tree, set(), channel="npm", version="FIXTURE npm")
        buf = io.StringIO()
        with mock.patch.object(cpc, "load_github", lambda: gh), \
             mock.patch.object(cpc, "load_npm", lambda: npm), \
             mock.patch.object(sys, "argv", argv):
            with redirect_stdout(buf):
                code = cpc.main()
        return code, buf.getvalue()

    def test_channel_github_exits_0_rather_than_1(self):
        code, out = self._run_main(["check_published_connector.py",
                                    "--channel", "github"])
        self.assertEqual(
            0, code,
            "--channel github exited %s — the exit code that means 'a fix is "
            "missing' (RFX-360)\n%s" % (code, out))
        self.assertNotIn("Traceback", out)

    def test_channel_npm_exits_0_rather_than_1(self):
        code, out = self._run_main(["check_published_connector.py",
                                    "--channel", "npm"])
        self.assertEqual(0, code, out)
        self.assertNotIn("Traceback", out)

    def test_both_channels_still_score_every_declared_row(self):
        """Control: the single-channel runs must not be green by scoring less."""
        code, out = self._run_main(["check_published_connector.py"])
        self.assertEqual(0, code, out)
        text = _norm(out)
        for prop_id in ("agent-id-per-execution", "session-id-per-workflow",
                        "money-verb-needs-amount"):
            self.assertIn("%s npm" % prop_id, text, text)
            self.assertIn("%s github" % prop_id, text, text)


if __name__ == "__main__":
    unittest.main()
