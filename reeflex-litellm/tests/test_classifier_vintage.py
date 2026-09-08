"""
The instrument check: WHICH reeflex_claude is this suite pricing actions with.

WHY THIS FILE EXISTS
====================
`reeflex-litellm` depends on `reeflex-claude` for the ONE classifier.  The
version published on PyPI is **0.1.7, uploaded 2026-07-06** -- which PREDATES
the RFX-144/145/146 fix that landed on main on 2026-08-22 and grew
`classify.py` from 753 lines to 1911.  `reeflex-claude>=0.1.7` in this
package's pyproject is satisfied by that stale wheel, because 0.1.7 is still
the newest version on the index.

So `pip install reeflex-litellm` in a fresh venv can resolve a classifier that
prices `ls -la && rm -rf /var/lib/pgsql` as a READ, and every test in this
suite would still pass while the gateway seat mispriced the one thing the
RFX-144 round was about.

These two tests make that failure loud instead of silent.  They are assertions
about the INSTRUMENT, not about this package.
"""

from __future__ import annotations

import os

import reeflex_claude
from reeflex_claude import classify


def test_the_classifier_in_use_reads_every_command_on_the_line():
    """RFX-144/145/146: price the action, not the phrasing.

    A benign leading command followed by a destructive one must be priced as
    the destructive one.  The pre-2026-08-22 classifier read only the leading
    token and returned reversible/single -- an ALLOW for a systemic delete.
    """
    cls = classify.classify(
        "Bash", {"command": "ls -la /tmp && rm -rf /var/lib/pgsql"})

    assert cls["verb"] == "delete", (
        "the reeflex_claude in use priced a chained `rm -rf` as %r. This is the "
        "pre-RFX-144 classifier (PyPI reeflex-claude 0.1.7, uploaded "
        "2026-07-06). Install reeflex-claude from THIS repo, not from the "
        "index: `pip install -e ../reeflex-claude`. reeflex_claude loaded from: "
        "%s" % (cls["verb"], reeflex_claude.__file__))
    assert cls["reversibility"] == "irreversible"
    assert cls["blast_radius"] == "systemic", (
        "expected systemic for `rm -rf /var/lib/pgsql` on a chained line, got "
        "%r -- see the message above about the classifier's vintage"
        % cls["blast_radius"])


def test_every_shell_separator_is_read_not_just_the_first_token():
    """The same vintage check across the separators a model actually emits.

    `&&` is the one everybody tests. A model proposing a tool call is just as
    likely to write `;` or a pipe, and the pre-fix classifier read none of them.
    Each case here is a systemic delete hiding behind a benign leading command,
    and each must be priced as the delete.
    """
    lines = [
        "cd /tmp; rm -rf /var/lib/pgsql",
        "echo starting && rm -rf /var/lib/pgsql",
        "true || rm -rf /var/lib/pgsql",
        "cat /etc/hosts | tee /dev/null; rm -rf /var/lib/pgsql",
    ]
    priced = {}
    for line in lines:
        cls = classify.classify("Bash", {"command": line})
        priced[line] = (cls["verb"], cls["reversibility"], cls["blast_radius"])

    wrong = {k: v for k, v in priced.items() if v[0] != "delete"}
    assert not wrong, (
        "the classifier in use priced these as something other than a delete: "
        "%r. reeflex_claude loaded from %s -- see this module's docstring on "
        "the stale 0.1.7 wheel." % (wrong, os.path.abspath(reeflex_claude.__file__)))
