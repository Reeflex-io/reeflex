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

WHAT CHANGED UNDER THIS FILE, AND WHY IT STAYS ANYWAY (RFX-224 / RFX-241)
=========================================================================
The requirement is now `reeflex-claude>=0.2.0,<0.3`, and 0.2.0 is the first
PUBLISHED wheel carrying RFX-144/145/146 -- so the resolve described above can
no longer happen: the stale wheel is excluded BY VERSION rather than by which
copy happens to win.  That makes these tests belt-and-braces instead of the
only guard, which is a better position and not a reason to delete them: the
floor is a declaration, and a venv assembled by hand, an editable install of an
old checkout, or a future floor edit can still put a pre-fix classifier in
front of the seat.  This file is what makes that loud.

IT HAPPENED AGAIN, ONE FIX LATER, AND THE TWO TESTS ABOVE WERE GREEN FOR IT
===========================================================================
`reeflex-litellm 0.1.0` went to PyPI on 2026-09-16T06:29:54Z.  Its floor
resolved `reeflex-claude 0.2.0`, uploaded 23 seconds earlier -- which carries
RFX-144/145/146 and therefore passes both tests above, and PREDATES RFX-301 by
a day.  Measured on 2026-09-17 through this package's own `reeflex-litellm
decide` against a core running the live image: **23 of qa-211's 24 destructive
command-substitution lines came back `allow`** (RFX-326).

`echo $(rm -rf /var/lib/pgsql)` was one of them, under
`reeflex.policy/read_only_internal`.

The vintage check had the right SHAPE and the wrong CORPUS: it asked whether the
classifier reads every command on the line, and the next mispricing to ship was
about reading inside a substitution.  `test_the_seat_refuses_the_substitution_family`
below is the corpus for that fix, driven through THIS PACKAGE'S OWN PATH --
`normalize_tool_call()` then `classify()` -- under a realistic gateway tool
name, because the seat a customer runs is reached by `run_shell`, not by `Bash`.

Watched, in one run on 2026-09-17, against two venvs built from the same test
file: **FAIL** on `reeflex-litellm==0.1.0` + `reeflex-claude==0.2.0` from the
index, **PASS** on this tree.  A test that has only ever been seen green is not
an instrument.
"""

from __future__ import annotations

import os

import pytest

import reeflex_claude
from reeflex_claude import classify

from reeflex_litellm import normalize


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


# ---------------------------------------------------------------------------
# RFX-326 -- the substitution family, through the gateway seat's own path.
# ---------------------------------------------------------------------------

# Every line here really removes the directory it names: ground truth was taken
# by running each one in a real bash against a synthetic victim directory and
# reading the filesystem afterwards, not by arguing about the shell
# (`code-reports/dev-2--068-evidence/10-ground-truth.txt`).
DESTRUCTIVE_SUBSTITUTIONS = [
    ("subst-dollar-paren", "echo $(rm -rf /var/lib/pgsql)"),
    ("subst-backtick", "echo `rm -rf /var/lib/pgsql`"),
    ("subst-bare", "$(rm -rf /var/lib/pgsql)"),
    ("subst-process-in", "cat <(rm -rf /var/lib/pgsql)"),
    ("subst-process-out", "echo hi > >(rm -rf /var/lib/pgsql)"),
    ("subst-double-quoted", 'echo "cleaning: $(rm -rf /var/lib/pgsql)"'),
    ("subst-nested-2", "echo $(echo $(rm -rf /var/lib/pgsql))"),
    ("subst-brace-body", "echo $({ rm -rf /var/lib/pgsql; })"),
    ("subst-backtick-in-dollar", "echo $(echo `rm -rf /var/lib/pgsql`)"),
    ("subst-dollar-in-backtick", "echo `echo $(rm -rf /var/lib/pgsql)`"),
    ("subst-nested-double-quotes",
     'echo "a $(echo "b $(rm -rf /var/lib/pgsql)")"'),
    ("subst-single-quoted-arg", "echo $(rm -rf '/var/lib/pgsql')"),
    ("subst-under-sh-c", "sh -c 'echo $(rm -rf /var/lib/pgsql)'"),
    ("subst-under-bash-c", "bash -c 'echo $(echo $(rm -rf /var/lib/pgsql))'"),
    ("subst-nested-process", "cat <(cat <(rm -rf /var/lib/pgsql))"),
    ("subst-after-arithmetic", "echo $((1+1)) $(rm -rf /var/lib/pgsql)"),
    ("subst-newline-body", "echo $(\nrm -rf /var/lib/pgsql\n)"),
    ("subst-heredoc-body", "cat <<EOF\n$(rm -rf /var/lib/pgsql)\nEOF"),
    ("subst-leading-true", "echo $(true && rm -rf /var/lib/pgsql)"),
    ("subst-brace-in-subst", "echo $({ echo $(rm -rf /var/lib/pgsql); })"),
    ("subst-env-prefix", "echo $(LC_ALL=C rm -rf /var/lib/pgsql)"),
    ("subst-command-builtin", "echo $(command rm -rf /var/lib/pgsql)"),
    ("subst-line-continuation", "echo $(rm \\\n-rf /var/lib/pgsql)"),
    ("subst-second-of-two", "echo $(date -u) $(rm -rf /var/lib/pgsql)"),
    # These two arrived here from STILL_OPEN, moved by the test below rather
    # than by anyone remembering: RFX-329 (PR #164) merged into main while this
    # change was being written, and `test_the_open_gaps_are_still_open_and_named`
    # went red naming both of them within minutes of the rebase. That is the
    # whole reason the exclusion list has a test of its own.
    ("subst-subshell-group", "echo $( (rm -rf /var/lib/pgsql) )"),
    ("bare-subshell-group", "(rm -rf /var/lib/pgsql)"),
]

# Lines the same walk must NOT price as a delete.  Without these, this file is
# passed by a classifier that answers "irreversible delete" to everything --
# which is a gate an operator switches off, and a strictly worse outcome than
# the one being fixed.
BENIGN_SUBSTITUTIONS = [
    ("benign-single-quoted", "echo '$(rm -rf /var/lib/pgsql)'"),
    ("benign-escaped", "echo \\$(rm -rf /var/lib/pgsql)"),
    ("benign-read-in-subst", "echo $(ls -la /tmp)"),
    ("benign-build-stamp", 'echo "built $(date -u +%F)"'),
    ("benign-arithmetic", "echo $((RETRIES + 1))"),
    ("benign-param-expansion", "echo ${HOME}/notes.md"),
    ("benign-sq-inside-subst", "echo $(echo '$(rm -rf /var/lib/pgsql)')"),
    ("benign-deep-read", "echo $(echo $(echo $(ls -la /tmp)))"),
]

# Destructive lines THIS TREE still gets wrong, each with the ticket that owns
# it.  They are excluded so this file states the tree's real position instead of
# being red on somebody else's open defect -- and a line that STOPS diverging
# fails this file too, because a stale exclusion is how a guard quietly stops
# guarding (the rule `conformance.py` residuals and `check_test_census.py`
# waivers already run under).
#
# Measured on main `7f19d37`, 2026-09-17, through this same path.
# It was nine on `0d9ef31` an hour earlier; RFX-329 took two of them.
STILL_OPEN = {
    # The substitution walk stops before this depth.
    "open-nest-4": ("echo $(echo $(echo $(echo $(rm -rf /var/lib/pgsql))))",
                    "RFX-336"),
    "open-nest-5": ("echo $(echo $(echo $(echo $(echo "
                    "$(rm -rf /var/lib/pgsql)))))", "RFX-336"),
    "open-backtick-nest": ("echo `echo \\`rm -rf /var/lib/pgsql\\``",
                           "RFX-336"),
    # A redirection before the command word inside the body.
    "open-redirect-first": ("echo $(>/dev/null rm -rf /var/lib/pgsql)",
                            "RFX-337"),
    # `sh -c` inside `sh -c`, with the substitution escaped for the inner shell.
    "open-nested-sh-c": ("sh -c 'sh -c \"echo \\$(rm -rf /var/lib/pgsql)\"'",
                         "RFX-337"),
    # The substitution PRODUCES the command word; closing it means evaluating
    # the substitution. Declared a residual in conformance.py as
    # `gap-command-substitution`.
    "open-eval-of-subst": ("eval \"$(echo rm -rf /var/lib/pgsql)\"",
                           "RFX-158"),
}


def _price_through_the_seat(command: str) -> dict:
    """Exactly what the gateway seat does with one shell tool call.

    The gateway tool name is `run_shell` and the argument is `cmd`, not `Bash`
    and `command`: an application behind a proxy declares its own schema, and
    this is the path `normalize.py` exists for. Asserting the normalisation
    landed on `Bash` first means a normaliser regression reads as a normaliser
    regression here, rather than as a classifier that mysteriously stopped
    pricing deletes.
    """
    call = normalize.normalize_tool_call({
        "id": "c1", "type": "function",
        "function": {"name": "run_shell",
                     "arguments": '{"cmd": %s}' % _json_str(command)},
    })
    assert call.tool_name == "Bash", (
        "the normaliser did not map `run_shell` with a `cmd` argument onto the "
        "Bash classifier (got %r, source %r) -- the classification below would "
        "be measuring the unknown-tool path, not this command"
        % (call.tool_name, call.mapping_source))
    return classify.classify(call.tool_name, call.tool_input)


def _json_str(s: str) -> str:
    import json
    return json.dumps(s)


def _is_delete(cls: dict) -> bool:
    return cls.get("verb") == "delete" and cls.get("reversibility") == "irreversible"


@pytest.mark.parametrize("case_id,command", DESTRUCTIVE_SUBSTITUTIONS,
                         ids=[c[0] for c in DESTRUCTIVE_SUBSTITUTIONS])
def test_the_seat_refuses_the_substitution_family(case_id, command):
    """RFX-326: a delete inside `$( )` is a delete, at the gateway seat too.

    On `reeflex-claude 0.2.0` -- the wheel `pip install reeflex-litellm`
    resolved on 2026-09-17 -- every one of these is priced `read`/`reversible`,
    which core allows honestly on a dishonest classification.
    """
    cls = _price_through_the_seat(command)
    assert _is_delete(cls), (
        "the classifier behind this seat priced %r as %s/%s instead of an "
        "irreversible delete. The command really removes the directory. This is "
        "the RFX-301 mispricing (published reeflex-claude 0.2.0 and earlier): "
        "install reeflex-claude >= 0.2.1. reeflex_claude %s loaded from %s"
        % (command, cls.get("verb"), cls.get("reversibility"),
           getattr(reeflex_claude, "__version__", "?"),
           os.path.abspath(reeflex_claude.__file__)))


@pytest.mark.parametrize("case_id,command", BENIGN_SUBSTITUTIONS,
                         ids=[c[0] for c in BENIGN_SUBSTITUTIONS])
def test_the_seat_does_not_price_everything_as_a_delete(case_id, command):
    """The control on the test above: these lines destroy nothing.

    A classifier that fails here passes the destructive corpus for the wrong
    reason, and the operator turns the gate off.
    """
    cls = _price_through_the_seat(command)
    assert not _is_delete(cls), (
        "the classifier behind this seat priced the harmless line %r as an "
        "irreversible delete. reeflex_claude %s loaded from %s"
        % (command, getattr(reeflex_claude, "__version__", "?"),
           os.path.abspath(reeflex_claude.__file__)))


def test_the_open_gaps_are_still_open_and_named():
    """A declared exclusion that no longer diverges must fail, not pass quietly.

    Each entry in `STILL_OPEN` is a destructive line this tree gets WRONG today,
    parked with the ticket that owns it. When one of those tickets lands, this
    test goes red and the line moves up into the corpus above -- which is the
    only mechanism that stops an exclusion list from becoming the place a fixed
    defect goes to be forgotten.
    """
    closed = {}
    for case_id, (command, ticket) in sorted(STILL_OPEN.items()):
        cls = _price_through_the_seat(command)
        if _is_delete(cls):
            closed[case_id] = ticket
    assert not closed, (
        "these lines are listed as still-open gaps but the classifier now "
        "prices them correctly: %r. Move each one into "
        "DESTRUCTIVE_SUBSTITUTIONS and delete its STILL_OPEN entry, so the "
        "corpus keeps the ground it has taken." % closed)
