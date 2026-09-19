"""Unit tests for scripts/check_published_connector.py (RFX-359, RFX-360).

WHY THIS FILE EXISTS AT ALL. The script had no suite. It is the only instrument
that says whether the connector a customer installs still lags this tree, and
until RFX-359 the answer it gave was wrong in the safe-looking direction: it
scored ONE of the five files the declared commit landed in, printed PASS, and —
on a republish of that one file — would have told the reader to DELETE the row
that was the last record of the other four. A check with no test is graded by
whether it stays green, which is exactly what it did.

Nothing here touches the network. Every channel is a fixture built in memory,
because the real event these tests are about (a PARTIAL republish, owner-gated)
is one we must never perform to measure.

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

SUBJECT = "session-id-per-workflow"


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

    Every other artefact gets bytes with the fix taken back OUT — each subject
    probe that targets it is substituted away — so "not delivered" in these
    fixtures is a file that is present and serving the old behaviour, which is
    the real lag. A fixture that simply omitted the file would exercise the
    NO-SUCH-FILE path instead and prove something else.

    The substitution is asserted to have changed the bytes: a revert that is a
    no-op scores as a pass and the arm proves nothing.
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
                for subject in prop.subjects:
                    if subject.artefact != name:
                        continue
                    reverted = subject.probe.sub("<<NOT-IN-THIS-RELEASE>>", text)
                    assert reverted != text, (
                        "taking %s out of %s was a no-op — the fixture is not "
                        "the arm it claims to be" % (prop.id, rel_tree))
                    text = reverted
        ch.files[rel_pub] = text
    return ch


def _kinds(findings):
    return sorted({f.kind for f in findings})


def _for(findings, kind, prop_id):
    return [f for f in findings if f.kind == kind and f.text.startswith(prop_id)]


class NodeOnlyRepublish(unittest.TestCase):
    """RFX-359: the row must not retire while four of its subjects still lag."""

    def setUp(self):
        self.tree = _tree_channel()

    def test_a_node_only_republish_does_not_retire_the_session_id_row(self):
        published = {"github": _published(self.tree, {"node"})}
        findings, lines = cpc.evaluate(self.tree, published)

        self.assertEqual(
            [], _for(findings, "STALE-DECLARATION", SUBJECT),
            "a republish of the node alone told the reader to delete the row "
            "that is the only record of the four demo workflows still serving "
            "the old session id — that is RFX-359",
        )

    def test_a_node_only_republish_names_the_four_files_that_still_lag(self):
        published = {"github": _published(self.tree, {"node"})}
        _, lines = cpc.evaluate(self.tree, published)
        line = _norm(next(l for l in lines if l.strip().startswith(SUBJECT)
                          and " github " in l))
        self.assertIn("GAP 1/5", line, line)
        for demo in ("demo1-bulk-delete-guard", "demo3-the-approval-loop",
                     "demo4-nothing-gets-through", "demo5-watch-before-you-enforce"):
            self.assertIn(demo, line,
                          "a partial delivery must name the files that lag, not "
                          "just count them: %s" % line)

    def test_a_full_republish_DOES_retire_the_row(self):
        """The control. Without it, test 1 passes just as well on a dead rig."""
        every_subject = {s.artefact for p in cpc.PROPERTIES for s in p.subjects}
        published = {"github": _published(self.tree, every_subject)}
        findings, _ = cpc.evaluate(self.tree, published)
        self.assertEqual(
            1, len(_for(findings, "STALE-DECLARATION", SUBJECT)),
            "with all five subjects delivered the declaration IS stale and must "
            "say so — the RFX-359 fix must not work by never retiring a row",
        )

    def test_one_lagging_demo_is_enough_to_hold_the_row_open(self):
        every_subject = {s.artefact for p in cpc.PROPERTIES for s in p.subjects}
        every_subject.discard("demo4-workflow")
        published = {"github": _published(self.tree, every_subject)}
        findings, lines = cpc.evaluate(self.tree, published)
        self.assertEqual([], _for(findings, "STALE-DECLARATION", SUBJECT))
        line = _norm(next(l for l in lines if l.strip().startswith(SUBJECT)
                          and " github " in l))
        self.assertIn("GAP 4/5", line, line)
        self.assertIn("demo4-nothing-gets-through", line, line)


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
        self.assertNotIn("PROBE-STALE", _kinds(findings))

    def test_rows_on_an_unfetched_channel_are_not_reported_as_orphans(self):
        published = {"github": _published(self.tree, set())}
        findings, _ = cpc.evaluate(self.tree, published)
        orphans = [f for f in findings if f.kind == "ORPHAN-DECLARATION"]
        self.assertEqual(
            [], orphans,
            "every npm row was called an orphan because npm was not fetched; a "
            "row whose channel nobody read this run is not a row nobody scores",
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

    def test_a_demo_subject_is_not_scored_on_npm(self):
        """examples/ is not in the tarball; absence there is not a gap."""
        for name in ("demo1-workflow", "demo3-workflow", "demo4-workflow",
                     "demo5-workflow", "demo3-readme"):
            self.assertNotIn("npm", cpc.ARTEFACTS[name],
                             "%s has an npm path but the tarball ships no "
                             "examples/ directory" % name)
        prop = next(p for p in cpc.PROPERTIES if p.id == SUBJECT)
        self.assertEqual(1, len(cpc.subjects_on(prop, "npm")))
        self.assertEqual(5, len(cpc.subjects_on(prop, "github")))


class TableGrounding(unittest.TestCase):
    """The tables are checked against the repository, not against each other."""

    def setUp(self):
        self.tree = _tree_channel()

    def test_every_subject_probe_matches_its_file_in_this_tree(self):
        for prop in cpc.PROPERTIES:
            for subject in prop.subjects:
                rel = cpc.ARTEFACTS[subject.artefact]["tree"]
                text = self.tree.text(rel)
                self.assertIsNotNone(text, "%s: %s is not in this checkout"
                                     % (prop.id, rel))
                self.assertRegex(
                    text, subject.probe,
                    "%s: /%s/ does not match %s — the probe has no subject, so "
                    "any published verdict from it is about the probe"
                    % (prop.id, subject.probe.pattern, rel))

    def test_every_lag_row_names_a_property_scored_on_that_channel(self):
        scored = {(p.id, c) for p in cpc.PROPERTIES for c in p.channels
                  if cpc.subjects_on(p, c)}
        for lag in cpc.LAG:
            self.assertIn((lag.property_id, lag.channel), scored,
                          "LAG row %s/%s is scored by nothing"
                          % (lag.property_id, lag.channel))

    def test_every_demo_workflow_on_disk_is_a_subject_or_declared_unscored(self):
        """Enumerate from the DIRECTORY, not from the table.

        RFX-359 is what happens when the table is the authority: four files the
        fix landed in were simply not in it, and nothing could notice. A demo
        added tomorrow must land in PROPERTIES or in UNSCORED_WORKFLOWS with a
        reason; it must not be able to arrive scored by nothing.
        """
        examples = os.path.join(REPO_ROOT, "n8n-nodes-reeflex", "examples", "n8n")
        on_disk = sorted(f for f in os.listdir(examples)
                         if f.endswith(".workflow.json"))
        self.assertTrue(on_disk, "no demo workflows found under %s" % examples)
        subject_files = {os.path.basename(cpc.ARTEFACTS[s.artefact]["tree"])
                         for p in cpc.PROPERTIES for s in p.subjects}
        for name in on_disk:
            with self.subTest(workflow=name):
                self.assertTrue(
                    name in subject_files or name in cpc.UNSCORED_WORKFLOWS,
                    "%s is scored by no property and is not declared in "
                    "UNSCORED_WORKFLOWS — a demo a customer can import, that "
                    "nothing compares against the published copy" % name)

    def test_every_unscored_declaration_has_a_file_and_a_reason(self):
        examples = os.path.join(REPO_ROOT, "n8n-nodes-reeflex", "examples", "n8n")
        for name, reason in cpc.UNSCORED_WORKFLOWS.items():
            self.assertTrue(os.path.exists(os.path.join(examples, name)),
                            "UNSCORED_WORKFLOWS names %s, which does not exist — "
                            "an exclusion that outlives its file excuses nothing "
                            "and never expires" % name)
            self.assertGreater(len(reason), 40,
                               "%s is excluded with no stated reason" % name)


class ProbesAreNotSatisfiedByProse(unittest.TestCase):
    """A probe a comment can satisfy measures the comment.

    Both spellings of the session id appear in PROSE in the very files they are
    checked in: the node's docstring explains the default, and demo1's `notes`
    field describes the session id in words. A single loose regex over the whole
    file text would be green on a file whose actual parameter had been changed
    back.
    """

    def _subject(self, artefact):
        prop = next(p for p in cpc.PROPERTIES if p.id == SUBJECT)
        return next(s for s in prop.subjects if s.artefact == artefact)

    def test_the_node_probe_ignores_the_docstring_that_explains_the_default(self):
        prose = (" * `agent.session_id`. The Session ID default is "
                 "`={{$workflow.id}}`, not\n * `={{$execution.id}}`: an "
                 "execution-scoped id resets every budget.\n"
                 "                default: '={{$execution.id}}',\n")
        self.assertIsNone(
            self._subject("node").probe.search(prose),
            "the node probe matched a file whose PARAMETER DEFAULT is the old "
            "value and whose only workflow-scoped mention is prose",
        )

    def test_the_workflow_probe_ignores_a_notes_field_that_mentions_it(self):
        prose = ('"notes": "each call gets its own session id ={{$workflow.id}} '
                 'so budgets accumulate",\n        "sessionId": '
                 '"={{$execution.id}}",\n')
        self.assertIsNone(
            self._subject("demo1-workflow").probe.search(prose),
            "the workflow probe matched a workflow whose sessionId parameter is "
            "the old value and whose only mention is in prose",
        )

    def test_the_probes_do_match_the_real_declaration(self):
        """Control: the two negatives above must not be vacuous."""
        self.assertIsNotNone(
            self._subject("node").probe.search("default: '={{$workflow.id}}',"))
        self.assertIsNotNone(
            self._subject("demo1-workflow").probe.search(
                '"sessionId": "={{$workflow.id}}",'))


class VerdictLine(unittest.TestCase):
    """What the PASS line claims, asserted in the shape a reader sees it."""

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

    def test_the_pass_line_states_what_was_scored_and_what_was_not(self):
        code, out = self._run_main(["check_published_connector.py"])
        self.assertEqual(0, code, out)
        text = _norm(out)
        self.assertIn("PASS — of the 12 (subject, channel) probe(s)", text, text)
        self.assertIn("A difference in a file no Property names is NOT scored", text)
        self.assertNotIn(
            "every gap between this tree and the published connector is declared",
            text,
            "the PASS line claims the whole diff again; it reads a named set of "
            "probes and 17 of 34 common files differed when that was last "
            "measured (RFX-359)",
        )

    def test_channel_github_exits_0_rather_than_1(self):
        code, out = self._run_main(["check_published_connector.py",
                                    "--channel", "github"])
        self.assertEqual(
            0, code,
            "--channel github exited %s — the exit code that means 'a fix is "
            "missing' (RFX-360)\n%s" % (code, out))
        self.assertIn("scoring 5 properties as 9 (subject, channel) probes on "
                      "github", _norm(out))
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
