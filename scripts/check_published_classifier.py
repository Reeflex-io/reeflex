#!/usr/bin/env python3
"""check_published_classifier.py — score the PUBLISHED wheel with the tree's corpus.

WHY THIS EXISTS (RFX-241, requirement 3)
========================================
`reeflex-claude` 0.1.7 was the newest wheel on PyPI from 2026-07-06 to
2026-09-16.  RFX-144/145/146 landed on main on 2026-08-22 and taught the
classifier to read every command on the line instead of the first token.  For
those 25 days `pip install reeflex-claude` gave a customer a classifier that
priced

    echo starting && rm -rf /var/lib/pgsql

as `read_only_internal` — reversible/single reached core, and core answered
`allow` honestly on a dishonest classification.  An irreversible production
destruction, executed with no human, from an installed Reeflex seat.

The whole time, the instrument that runs against a published wheel on every
gate run — `gate.py`'s `pypi-smoke` — was GREEN.  It installs the package and
runs `<entry> --help`, then asserts exit 0.  Measured 2026-09-16 on this box:

    reeflex-claude==0.1.7   reeflex-claude --help -> exit 0
    reeflex-claude==0.2.0   reeflex-claude --help -> exit 0

Both pass.  `pypi-smoke` proves the entry point is not dead, and says nothing
about what the wheel DECIDES.

BE PRECISE ABOUT WHAT ELSE EXISTS, because "nothing covered this" would be
wrong.  `release.yml`'s `verify-published` also installs from the index and
invokes the artefact, with real negative controls — a `rfx_gate_` token refused
with exit 2, and the `SETUP_DOC_SHA256` comparison — and RFX-241's own
2026-09-08 comment records it FAILING when pointed at 0.1.7.  It is a real
instrument and it is not this one, for two reasons.  It runs ON A TAG and
installs the version that tag names, so a lag BETWEEN releases is invisible to
it for as long as nobody cuts one — here, 25 days.  And the way it fails on
0.1.7 is `argument command: invalid choice: 'connect'`: a missing subcommand,
i.e. the wheel is the wrong VINTAGE.  That is a proxy, and it only works while
the vintages happen to differ in their CLI surface.  A wheel whose classifier
had regressed without its argparse moving would pass it.  Nothing scored what
the published classifier DECIDES until this component.

So RFX-241 asks for the component neither of them is: "FAILS when a published
wheel's behaviour differs from the checkout's on the conformance corpus, so the
next lag is caught by CI rather than by an adapter author."

WHAT IT DOES
============
1. Loads the CHECKOUT's corpus from `reeflex-claude/reeflex_claude/conformance.py`
   and the CHECKOUT's policy oracle from `reeflex-claude/tests/policy_oracle.py`.
   Ground truth comes from the tree, never from the artefact under test — the
   artefact is the suspect.

   THE ORACLE IS THE SHARED ONE, AND IT IS NOT IN THE PACKAGE (RFX-303/RFX-327).
   This script is the THIRD consumer of the oracle, after the offline unit suite
   and the live `attack-probe-rfx144-agent-prices-own-action.py` — and it imports
   the same module they do, by the same `sys.path` insert the live arm already
   uses.  It does NOT get a copy inside `reeflex_claude`: `policy_oracle.py` says
   in its own docstring that the adapter "does not import this module and must
   not", because the adapter classifies and core decides.  An earlier revision of
   this script carried a private R1-R4 transcription instead; that copy was
   missing R6 and ranked R1 first, which are exactly the two divergences RFX-303
   had just removed — it scored the CORRECT wheel 0.2.0 FAIL on
   `protected-rm-single-file-under-srv` (a false RED on main) while being blind to
   the whole R6 family in the other direction.  One oracle, three planes.
2. Builds a throwaway venv and installs `reeflex-claude` FROM THE INDEX
   (unpinned by default: whatever a customer gets today).
3. Runs every corpus case through THAT wheel's classifier, in that venv, as a
   subprocess.  The two classifiers never share an interpreter, so there is no
   import order in which the wrong one can answer.
4. Applies the checkout's oracle to the published wheel's axes and compares the
   verdict to the corpus's `expect` — the verdict the command's REAL-WORLD
   EFFECT demands, which is a property of the command and not of any
   classifier.
5. Any divergence FAILS unless it is declared in `PUBLISHED_LAG` with the
   ticket that closes it.  A declared entry that no longer diverges also FAILS:
   a stale exclusion is how a gate quietly stops gating (same rule as
   `check_test_census.py`'s waivers and `conformance.py`'s residuals).

WHAT IT CANNOT SEE, SAID OUT LOUD
=================================
* It scores the ADAPTER's classification through a Python transcription of the
  pack (R3, R2, R6, R1, R4), not through a live core.  R0, R5 and R7 are not
  modelled and `target.ref` is compared raw — `tests/policy_oracle.py`'s own
  docstring is the list, and it is the same list the offline unit suite runs
  under.  A policy-pack change that is not in the oracle is invisible here.  The
  live equivalent is `scripts/attack-probe-rfx144-agent-prices-own-action.py`,
  and `gate.py`'s `claude-corpus-live` is what fails when the two planes
  disagree.
* It says nothing about the OTHER published wheels (`reeflex-mcp`,
  `reeflex-holds`) — they have no corpus of this shape.  Their lag is the same
  class of risk and is still unmeasured; RFX-241 requirement 2.
* `residual`-marked cases (the RFX-158 gap family) are excluded, exactly as
  `tests/test_conformance_bash.py` excludes them.  A published wheel is not
  asked to close a gap the checkout has not closed.
* A GREEN here means the published wheel agrees with the corpus THE TREE SHIPS
  TODAY.  It is not a statement that the corpus is complete.  That sentence had
  a measured price (RFX-341): from this component's first run until 2026-09-17
  the corpus was 108 Bash rows and one Read row, so `Write`, `Edit`,
  `MultiEdit` and `NotebookEdit` were not scored at all -- while RFX-338, a
  defect on exactly that route, was open and then fixed on main. This arm's
  green over that family meant "nothing asked", in either direction. If you
  are about to trust a green here for a tool route, check the corpus contains a
  row for it first: `Counter(c["tool"] for c in conformance.CASES)`.

USAGE
    python scripts/check_published_classifier.py [REPO_ROOT]
    python scripts/check_published_classifier.py --version 0.1.7   # the control
    python scripts/check_published_classifier.py --selftest        # no network

EXIT CODES / ANCHORED LINE
    0  PUBLISHED-CLASSIFIER: PASS (...)
    1  PUBLISHED-CLASSIFIER: FAIL (...)
    3  PUBLISHED-CLASSIFIER: SKIP (...)   index unreachable, venv/pip unusable
Only the anchored line at the start of a line decides the verdict; `gate.py`
parses it that way on purpose (RFX-108).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

DIST = "reeflex-claude"

# The corpus's `expect` vocabulary ordered by how much it restrains the agent.
# A published verdict LOWER than the expected one let something through.
RESTRAINT = {"allow": 0, "ask": 1, "deny": 2}

# RFX-217, the floor under this whole check: "0 divergences" is a sentence the
# empty set says just as fluently as a correct wheel does. If the driver
# returns nothing, if the corpus fails to import, if a future refactor renames
# CASES — every one of those produces a clean zero. So the count of cases
# actually SCORED is asserted against a floor, and the floor is printed in the
# PASS line so the next person can see what it was measured against.
# RE-DERIVED 2026-09-17 (RFX-341), because the sentence here had gone stale
# twice over: it said "96 (102 cases, 6 residual)" while the corpus was at 108,
# and a number written into a comment rots on its own. Measured today, by
# running this component: 120 cases, 7 residual -> 113 SCORED. Derive it with
#   python3 -c "import sys; sys.path.insert(0,'reeflex-claude');
#   from reeflex_claude import conformance as c;
#   print(len([x for x in c.CASES if not x['residual']]))"
# and note that the number moves every time anyone adds a row.
#
# THE FLOOR STAYS 40, AND THAT IS NOT LAZINESS ABOUT THE GAP BETWEEN 40 AND
# 113. What this floor exists to catch is a walk that stopped walking -- an
# empty driver result, a corpus that failed to import, a renamed CASES. It is
# deliberately well below the census so that retiring a case stays an ordinary
# change. A whole FAMILY going missing is caught by a different branch and
# caught better: `audit` reports every corpus case with no row back as
# "the published wheel was never asked" and fails, per case, by name.
MIN_SCORED_CASES = 40

# Divergences that are KNOWN and ACCEPTED until a republish carries the fix.
# case id -> the ticket that closes it. An entry here is a promise that someone
# is shipping something, not a way to make the component quiet: it must name a
# ticket, and it FAILS once the published wheel stops diverging on that case.
#
# IT WAS EMPTY WHEN THIS COMPONENT WAS WRITTEN, AND THE CORPUS MOVED UNDER IT.
# On 2026-09-16 published 0.2.0 scored 0 divergences over 78 cases (38bdd31).
# On 2026-09-17 RFX-301 landed on main (PR #155) and added the ten
# `destroy-subst-*` cases below: a destructive command reached through a command
# or process substitution, which published 0.2.0 (uploaded 2026-09-16T06:29Z,
# i.e. BEFORE that fix) prices as `read/reversible/single` and lets through.
#
# These ten are the component doing its job on its first real run. They are a
# LAG, not a gap, and that distinction was measured rather than assumed: this
# tree's own classifier + tests/policy_oracle.py answer all ten correctly
# (`ask` x9 via irreversible_broad_prod, `deny` x1 via irreversible_systemic_prod).
# The fix exists; the artefact a customer installs does not carry it yet.
#
# RFX-301 is the ticket, and it closes these by REPUBLISHING reeflex-claude --
# which is a release action and therefore owner-gated, not something this
# component or the agent that landed it can do. The entries are not a way to
# make the gate quiet: `audit` FAILS each one as STALE the moment the published
# wheel stops diverging, so the republish deletes this block by reddening the
# gate until someone does.
PUBLISHED_LAG: dict = {
    # Command substitution -- the delete runs inside $( ) / ` `, and the
    # published classifier reads only the outer command word.
    "destroy-subst-dollar-paren":    "RFX-301",
    "destroy-subst-backticks":       "RFX-301",
    "destroy-subst-bare":            "RFX-301",
    "destroy-subst-double-quoted":   "RFX-301",
    "destroy-subst-nested":          "RFX-301",
    "destroy-subst-after-separator": "RFX-301",
    "destroy-subst-in-argument":     "RFX-301",
    # Process substitution -- both directions.
    "destroy-subst-process":         "RFX-301",
    "destroy-subst-process-write":   "RFX-301",
    # The same shape on a system path: expect `deny`, published `allow`.
    "destroy-subst-systemic":        "RFX-301",
    # The subshell group (the defect is RFX-329; the lag these entries record is
    # RFX-339). Published 0.2.0 was uploaded 2026-09-16T06:29Z; the fix merged
    # 2026-09-17T18:03Z in PR #164. Six of the seven group rows diverge --
    # measured by the three-arm differential in
    # code-reports/qa--235--20260917-evidence/results.json, and confirmed through
    # core's real pack (`opa eval`, reeflex-core/policy) in
    # live_pack_results.json: on the wheel the index serves today,
    # `(rm -rf /var/lib/pgsql)` comes back ALLOW under reeflex.policy/default_allow.
    #
    # THE TICKET IS RFX-339, NOT RFX-329, AND THE DIFFERENCE MATTERS TO WHOEVER
    # READS THIS NEXT. RFX-329 is the classifier defect and it is CLOSED on main;
    # following it lands you on a ticket that says "fixed", which is not what an
    # entry in this table means. RFX-339 is the republish -- the action that makes
    # these entries stale -- and it is owner-gated, so neither this component nor
    # the agent that wrote these lines can close it.
    #
    # `destroy-group-with-operator` is deliberately NOT here: it already decides
    # correctly on 0.2.0 via the RFX-144 separator path, so declaring it would be
    # a STALE entry and `audit` would fail it -- which is the mechanism working.
    "destroy-group-bare":            "RFX-339",
    "destroy-group-spaced":          "RFX-339",
    "destroy-group-in-substitution": "RFX-339",
    "destroy-group-nested":          "RFX-339",
    "destroy-group-piped":           "RFX-339",
    "destroy-group-then-benign":     "RFX-339",
    # The trailing redirection (the defect is RFX-340; the lag these entries
    # record is RFX-339, the same republish -- read the block above on why an
    # entry must name the republish and not the classifier fix). Published
    # 0.2.0 prices `echo hi > /srv/prod/db.sqlite` read/reversible/single and
    # the real pack ALLOWS it; main prices it delete/irreversible/broad as of
    # this change.
    #
    # EIGHT of the TWELVE rows RFX-340 adds diverge, measured against the wheel
    # the index actually serves rather than assumed from the diff:
    # code-reports/dev-1--159--20260917-evidence/40-published-classifier-BEFORE-lag.txt
    #
    # THE FOUR `everyday-redirect-*` ROWS ARE DELIBERATELY NOT HERE, for the
    # same reason `destroy-group-with-operator` is not: published 0.2.0 already
    # agrees with the tree on all four (0 fail-noisy in that same run), so
    # declaring them would be STALE on arrival and `audit` would fail them.
    # They are the half of RFX-340 that pins what must STAY allowed -- an
    # ordinary `pytest -q > out.log` is not a delete -- and the published wheel
    # never got that wrong.
    #
    # RFX-339 WIDENS BECAUSE OF THIS. The republish now clears the subshell
    # group escapes AND these eight; that is recorded on the ticket rather than
    # left for the next reader to infer. It is owner-gated either way.
    "destroy-redirect-trailing":        "RFX-339",
    "destroy-redirect-trailing-fd":     "RFX-339",
    "destroy-redirect-trailing-both":   "RFX-339",
    "destroy-redirect-varfd":           "RFX-339",
    "destroy-redirect-nospace":         "RFX-339",
    "destroy-redirect-mid-command":     "RFX-339",
    "destroy-redirect-second-target":   "RFX-339",
    "destroy-redirect-in-substitution": "RFX-339",
    # The Write/Edit PATH CAP (the defect is RFX-338, closed on main in PR
    # #169; the lag these two entries record is RFX-339, the republish -- the
    # same distinction the block above draws, and for the same reason: RFX-338
    # now reads "fixed", which is not what an entry in this table means).
    #
    # RFX-341 ADDED THE ROWS THAT MAKE THESE VISIBLE, AND THAT IS THE POINT.
    # Until 2026-09-17 the corpus was 108 Bash rows + 1 Read row, so this
    # component -- whose sensitivity IS the corpus -- could not see the
    # Write/Edit/MultiEdit/NotebookEdit family in either direction. It was not
    # green because the wheel was clean on that family; it was green because
    # nothing asked. RFX-341 landed 11 rows: 1 is residual (RFX-342, excluded
    # here as the suite excludes it), these 2 diverge, and the other 8 are
    # deliberately NOT declared -- measured, the checkout and published 0.2.0
    # agree on all 8, and an entry that does not diverge FAILS as stale.
    #
    # MEASURED on the wheel the index serves today, 2026-09-17: published
    # `reeflex-claude 0.2.0` has no MAX_FILE_PATH_CHARS at all (the attribute
    # is absent, not merely larger), so an 8 KiB `file_path` reaches
    # `_SENSITIVE_PATH_RE` and comes back create|update/recoverable/single ->
    # `allow`, where the checkout answers irreversible/systemic -> `deny`.
    "ctrl-write-path-over-the-cap":   "RFX-339",
    "ctrl-edit-path-over-the-cap":    "RFX-339",
    # The NotebookEdit delete-mode hold (the defect is RFX-342, closed on main
    # by this change; the lag this entry records is RFX-339, the republish --
    # the same distinction the two blocks above draw, and for the same reason).
    #
    # RFX-341 DECLARED THIS ROW A RESIDUAL, so this component EXCLUDED it and
    # could not have seen the divergence. RFX-342 cleared the residual, the row
    # started being scored, and it diverged on the first run afterwards -- the
    # residual mechanism and this ledger composing the way they were meant to,
    # one handing the row to the other.
    #
    # MEASURED, not inferred from the diff: published `reeflex-claude 0.2.0`
    # prices `{"notebook_path": ..., "edit_mode": "delete"}` update/recoverable/
    # single -> `allow`, where the checkout now answers update/irreversible/
    # single -> `ask` under reeflex.policy/irreversible_protected_asset_prod.
    #
    # ONLY THIS ROW, and the two that are absent are absent on purpose:
    #   * `everyday-notebookedit-replace-a-cell` -- RFX-342 changed its REF, not
    #     its verdict, and this component compares VERDICTS. It agrees with
    #     0.2.0 both before and after, so declaring it would be STALE on arrival
    #     and `audit` would fail it. The ref regression lives in the unit suite
    #     (TestRFX341TheRecordNamesTheResource), which is the plane that can see
    #     it -- worth knowing before trusting this arm's green for a ref.
    #   * `ctrl-notebookedit-spelled-with-file-path` -- 0.2.0 already reads
    #     `file_path`, so that spelling never diverged.
    "destroy-notebookedit-deletes-a-production-cell": "RFX-339",

    # The WRITER FAMILY (the defect is RFX-343; the lag these eight entries
    # record is RFX-339, the republish -- the same distinction every block
    # above draws).  Published 0.2.0 prices `tee /srv/prod/db.sqlite` and its
    # seven siblings execute/recoverable/scoped -> `allow`, where the checkout
    # now answers delete/irreversible/broad -> `ask`.
    #
    # MEASURED on this arm, not inferred from the diff:
    # code-reports/dev-2--076--20260918-evidence/10-pypi-tree-arm.txt
    #
    # EACH ENTRY WIDENS WHAT THE REPUBLISH CLEARS, AND THE REPUBLISH IS
    # OWNER-GATED.  RFX-339 is a release action; nothing here performs it or
    # decides it.  What these eight DO record is that the exposure a customer
    # carries today grew by a family of eight, so the cost of not republishing
    # is larger than it was when RFX-339 was last looked at.  Flagged for the
    # owner, not decided -- see the RFX-343 report.
    #
    # THE SIX `everyday-writer-*` ROWS ARE DELIBERATELY NOT HERE, for the same
    # reason the four `everyday-redirect-*` rows are not: published 0.2.0
    # already agrees with the tree on all six, so declaring them would be STALE
    # on arrival and `audit` would fail them.  They are the half of RFX-343
    # that pins what must STAY allowed -- an ordinary `cp a.txt b.txt` is not a
    # delete -- and the published wheel never got that wrong.
    "destroy-writer-tee":         "RFX-339",
    "destroy-writer-tee-pipe":    "RFX-339",
    "destroy-writer-tee-multi":   "RFX-339",
    "destroy-writer-cp-devnull":  "RFX-339",
    "destroy-writer-cp-file":     "RFX-339",
    "destroy-writer-install":     "RFX-339",
    "destroy-writer-sort-o":      "RFX-339",
    "destroy-writer-mv":          "RFX-339",

    # RFX-344 -- `>& PATH cmd`, bash's both-streams redirection written BEFORE
    # the command word.  The lag these two record is RFX-339, the republish,
    # exactly as the writer block above and every block before it.
    #
    # Published 0.2.0 prices both execute/recoverable/scoped -> `allow`, where
    # the checkout now answers delete/irreversible/broad -> `ask`.  MEASURED on
    # this arm, python3.12, real wheel off the real index, and NOT inferred
    # from the diff:
    #   code-reports/dev-1--163--20260918-evidence/71-mine-tree.txt
    #     FAIL-OPEN  destroy-redirect-leading-both-streams
    #     FAIL-OPEN  destroy-redirect-leading-both-streams-nospace
    #
    # THE THREE `everyday-redirect-*-leading` ROWS ARE DELIBERATELY NOT HERE.
    # `>&2 echo hi`, `>&- echo hi` and `>& build.log echo hi` all answer
    # `allow` on 0.2.0 AND on the checkout -- the published wheel never got
    # those wrong, so declaring them would be STALE on arrival and `audit`
    # would fail them.  They are the half of RFX-344 that pins what must STAY
    # allowed.
    #
    # These entries WIDEN WHAT THE REPUBLISH CLEARS, and the republish is
    # OWNER-GATED.  Nothing here performs or decides RFX-339.  What they record
    # is that the exposure a customer on the shipped wheel carries today grew
    # by two more spellings -- on top of the eight the writer family added the
    # same night -- so the cost of not republishing is larger again.  Flagged
    # for the owner, not decided.
    "destroy-redirect-leading-both-streams":         "RFX-339",
    "destroy-redirect-leading-both-streams-nospace": "RFX-339",

    # RFX-351 -- the DATABASE-CLIENT script file, under each client's own
    # documented spelling.  The lag these twelve record is RFX-339, the
    # republish, exactly as every block above.
    #
    # MEASURED on this arm, python3.12, real wheel off the real index, and NOT
    # inferred from the diff:
    #   code-reports/dev-1--166--20260918-evidence/06-published-default-arm.txt
    # Published 0.2.0 prices all nine destroy rows execute/recoverable/scoped
    # -> `allow`, where the checkout now answers execute/irreversible/broad ->
    # `ask`.
    #
    # THE THREE `everyday-*` ROWS ARE DECLARED HERE, AND THAT IS THE DIFFERENCE
    # FROM THE WRITER AND REDIRECT BLOCKS ABOVE.  Each of those could say "the
    # published wheel never got the everyday half wrong".  This one cannot:
    # 0.2.0 reads `-f` as a script flag for mysql, mariadb and sqlcmd, where it
    # is `--force`, `--force` and the CODEPAGE option, so the wheel answers
    # `ask` on an inline `SELECT 1` and the checkout answers `allow`.  Those are
    # fail-NOISY divergences, they are real divergences, and this component
    # fails an undeclared one in either direction.
    #
    # These entries WIDEN WHAT THE REPUBLISH CLEARS and the republish is
    # OWNER-GATED; nothing here performs or decides RFX-339.  What they record
    # is that the exposure grew again -- nine more spellings of an unbounded
    # script against a production database, on top of the writer family's eight
    # and the leading-redirect two, all in about a day.
    "destroy-sqlcmd-input-file":          "RFX-339",
    "destroy-clickhouse-queries-file":    "RFX-339",
    "destroy-clickhouse-queries-file-eq": "RFX-339",
    "destroy-redis-eval-script":          "RFX-339",
    "destroy-mongosh-positional-script":  "RFX-339",
    "destroy-mongo-positional-script":    "RFX-339",
    "destroy-sqlite3-dot-read":           "RFX-339",
    "destroy-mysql-inline-source":        "RFX-339",
    "destroy-mysql-inline-dot-source":    "RFX-339",
    "everyday-mysql-force-inline-select": "RFX-339",
    "everyday-mariadb-force":             "RFX-339",
    "everyday-sqlcmd-codepage":           "RFX-339",

    # qa--251, landing this branch.  A thirteenth row, same republish.  The
    # in-client directive was anchored to a statement boundary so that a column
    # named `source` stops being read as a script (the two `everyday-*-named-
    # source` rows); this row is the discriminator proving the anchor did not
    # cost the directive when it legitimately follows a `;`.  Published 0.2.0
    # has no in-client directive check at all, so it answers `allow` here --
    # MEASURED on the default arm in this round, not inferred:
    #   code-reports/qa--251--20260918-evidence/05-published-default-arm.txt
    # The two everyday rows are deliberately NOT declared: 0.2.0 prices them
    # `allow` and so does the checkout, so an entry for either would be a STALE
    # declaration and would redden this component.  That agreement is also the
    # independent evidence that `allow` is the right answer for them.
    "destroy-mysql-inline-source-after-statement": "RFX-339",
    # RFX-353 (qa--248): the three whole-line flag regexes. `reeflex-claude
    # ==0.2.0` still asks "is there a dash-LETTER anywhere on the line", so the
    # wheel a customer installs today ALLOWS a recursive tree delete spelled
    # `rm -R`, every `git push` that rewrites or removes a remote ref without
    # the literal token `-f`/`--force`, and both git subcommands written behind
    # a global option -- and HOLDS four lines that destroy nothing, including a
    # `git clean` DRY RUN priced delete/irreversible/broad.
    #
    # MEASURED on this arm: 44 fail-open / 4 fail-noisy against 159 cases, the
    # eleven below being the ones this ticket adds. Note which rows are NOT
    # here: destroy-rm-recursive-uppercase-{R,bundled,bundled-rev} use a
    # /srv/prod path, where R6 holds the call whatever the blast radius says,
    # so the published wheel reaches `ask` on them for the wrong reason. The
    # `-unprotected-path` row is the one that shows the decision escape, and it
    # is the one that diverges.
    #
    # Clears on the republish, like everything above it: RFX-339.
    "destroy-rm-recursive-uppercase-unprotected-path":     "RFX-339",
    "destroy-git-push-plus-refspec":                       "RFX-339",
    "destroy-git-push-mirror":                             "RFX-339",
    "destroy-git-push-delete-remote-branch":               "RFX-339",
    "destroy-git-push-empty-source-refspec":               "RFX-339",
    "destroy-git-push-global-option-before-subcommand":    "RFX-339",
    "destroy-git-clean-global-option-before-subcommand":   "RFX-339",
    "destroy-git-clean-require-force-disabled":            "RFX-339",
    # The fail-NOISY half. Same table for the same reason: the component
    # fails an undeclared divergence in EITHER direction, and a gate that
    # asks on a dry run is a gate that gets switched off.
    "everyday-rm-single-file-name-contains-dash-r":        "RFX-339",
    "everyday-git-clean-dry-run-path-contains-dash-f":     "RFX-339",
    "everyday-git-push-dry-run-force":                     "RFX-339",
    "everyday-git-push-force-if-includes":                 "RFX-339",
}

# --------------------------------------------------------------------------
# THE SEAT ARM (RFX-326): the same corpus, one DISTRIBUTION out.
#
# The block above scores `pip install reeflex-claude`. No component scored
# `pip install reeflex-litellm`, and on 2026-09-16 that stopped being a
# theoretical gap: `reeflex-litellm 0.1.0` went to PyPI, its floor
# `reeflex-claude>=0.2.0` resolved the 0.2.0 wheel uploaded 23 seconds earlier,
# and the gateway seat a customer installs allowed 23 of 24 destructive
# command-substitution lines (qa-211, measured through the package's own
# `reeflex-litellm decide` against a core running the live image).
#
# The lag was DECLARED in PUBLISHED_LAG above, with the correct ticket, on the
# correct reasoning -- and the declaration's cost was priced against a world in
# which `reeflex-litellm` was "on no index, so nothing installs this from PyPI
# today either way" (its own pyproject said so). That sentence stopped being
# true the day it was written. A waiver is a statement about blast radius, and
# nothing re-measured the radius when a second published package started
# standing on the waived wheel.
#
# So this arm asks the customer-facing question directly: resolve
# `reeflex-litellm` from the index, and score what THAT resolve decides, through
# the seat's own normaliser rather than through `classify()` in isolation.
SEAT_DIST = "reeflex-litellm"
SEAT_ANCHOR = "PUBLISHED-LITELLM-SEAT"

# The seat's own lag table. Same shape, same rules, same self-clearing
# behaviour: each entry names the ticket that closes it, an entry that stops
# diverging FAILS as STALE, and a declaration naming no ticket FAILS.
#
# These are the same cases as PUBLISHED_LAG, reached one distribution
# further out, and they close the same way: a republish. They are listed
# separately rather than aliased because the two resolves are independent --
# `reeflex-litellm`'s floor is its own declaration and a future edit to it can
# move this arm without moving the other.
SEAT_PUBLISHED_LAG: dict = {
    "destroy-subst-dollar-paren":    "RFX-326",
    "destroy-subst-backticks":       "RFX-326",
    "destroy-subst-bare":            "RFX-326",
    "destroy-subst-double-quoted":   "RFX-326",
    "destroy-subst-nested":          "RFX-326",
    "destroy-subst-after-separator": "RFX-326",
    "destroy-subst-in-argument":     "RFX-326",
    "destroy-subst-process":         "RFX-326",
    "destroy-subst-process-write":   "RFX-326",
    "destroy-subst-systemic":        "RFX-326",
    # The subshell group, reached one distribution further out. MEASURED, not
    # mirrored from the table above: `--seat` on python3.12 against
    # reeflex-litellm==0.1.0 fails open on exactly these six, through the seat's
    # own normaliser, and NOT on `destroy-group-with-operator`. The exposure is
    # two published packages, not one -- which is why this table exists separately
    # rather than aliasing PUBLISHED_LAG.
    #
    # The seat's floor admits whatever reeflex-claude it admits, so this clears
    # when that republish happens: RFX-339.
    "destroy-group-bare":            "RFX-339",
    "destroy-group-spaced":          "RFX-339",
    "destroy-group-in-substitution": "RFX-339",
    "destroy-group-nested":          "RFX-339",
    "destroy-group-piped":           "RFX-339",
    "destroy-group-then-benign":     "RFX-339",
    # The trailing redirection, reached one distribution further out. MEASURED
    # on this arm, not mirrored from the table above -- `--seat` against
    # reeflex-litellm==0.1.0 fails open on exactly these eight, through the
    # seat's own normaliser, and on none of the four `everyday-redirect-*`
    # rows: code-reports/dev-1--159--20260917-evidence/41-seat-arm-BEFORE-lag.txt
    #
    # The two resolves are independent, so the fact that both arms diverge on
    # the same eight is a measurement, not an entailment. The seat's floor
    # admits whatever reeflex-claude it admits, so these clear on the same
    # republish: RFX-339.
    "destroy-redirect-trailing":        "RFX-339",
    "destroy-redirect-trailing-fd":     "RFX-339",
    "destroy-redirect-trailing-both":   "RFX-339",
    "destroy-redirect-varfd":           "RFX-339",
    "destroy-redirect-nospace":         "RFX-339",
    "destroy-redirect-mid-command":     "RFX-339",
    "destroy-redirect-second-target":   "RFX-339",
    "destroy-redirect-in-substitution": "RFX-339",
    # The path cap, reached one distribution further out. MEASURED on this arm
    # rather than mirrored from the table above: `--seat` against
    # reeflex-litellm==0.1.0 fails open on exactly these two of RFX-341's 10
    # scored rows, through the seat's own normaliser, and on none of the other
    # eight. Those eight are also the evidence that the OPERATOR MAP
    # round-trips this family at all: a call the normaliser dropped onto the
    # unknown path would come back as an ERROR here, not as a mispricing.
    "ctrl-write-path-over-the-cap":   "RFX-339",
    "ctrl-edit-path-over-the-cap":    "RFX-339",
    # NotebookEdit delete-mode, one distribution further out. MEASURED on THIS
    # arm and not mirrored from the table above -- the rule this block already
    # states, and it is not a formality here: the two arms fail open for
    # DIFFERENT reasons, and only one of them is fixed by the seat's own change.
    # BOTH causes were read off the published artefacts rather than inferred
    # from this arm's output, which cannot separate them -- a dropped path and
    # a mispriced delete both surface as update/recoverable/single:
    #   * `reeflex-litellm==0.1.0`: `normalize._PATH_KEYS` is
    #     ('file_path','path','filename','file','target_path','filepath',
    #     'dest','destination') -- no `notebook_path`. Fixed in this change.
    #   * `reeflex-claude==0.2.0`: prices delete-mode `recoverable`. Fixed on
    #     main by this change, in a customer's hands only by the republish.
    # So this entry would still diverge with the seat republished and the
    # adapter not, which is why it names RFX-339 like every other entry here.
    "destroy-notebookedit-deletes-a-production-cell": "RFX-339",

    # The WRITER FAMILY, one distribution further out.  MEASURED on THIS arm
    # and not mirrored from the table above -- the rule this block already
    # states.  `--seat` against `reeflex-litellm==0.1.0` fails open on exactly
    # these eight, through the seat's own normaliser, and on NONE of the six
    # `everyday-writer-*` rows:
    # code-reports/dev-2--076--20260918-evidence/11-pypi-seat-arm.txt
    #
    # The fact that both arms diverge on the same eight is a measurement, not
    # an entailment -- the two resolves are independent.  Here the cause is
    # single, unlike the NotebookEdit row above: the seat normaliser passes a
    # Bash `command` through untouched, so the mispricing is entirely
    # `reeflex-claude==0.2.0`'s.  The seat's floor admits whatever
    # reeflex-claude it admits, so these clear on the same republish: RFX-339.
    "destroy-writer-tee":         "RFX-339",
    "destroy-writer-tee-pipe":    "RFX-339",
    "destroy-writer-tee-multi":   "RFX-339",
    "destroy-writer-cp-devnull":  "RFX-339",
    "destroy-writer-cp-file":     "RFX-339",
    "destroy-writer-install":     "RFX-339",
    "destroy-writer-sort-o":      "RFX-339",
    "destroy-writer-mv":          "RFX-339",

    # RFX-344, one distribution further out.  MEASURED ON THIS ARM and not
    # mirrored from the table above -- the rule this block already states, and
    # mirroring is not free: the checker FAILS a declaration that does not
    # actually diverge, so a copied entry reddens the gate as STALE instead of
    # quieting it.  Measured, python3.12:
    #   code-reports/dev-1--163--20260918-evidence/72-mine-seat.txt
    # `--seat` against reeflex-litellm==0.1.0 fails open on the same two rows
    # and on NONE of the three `everyday-redirect-*-leading` rows.
    #
    # The two arms are INDEPENDENT resolves, and the default arm cannot see
    # this table at all.  Measured on #173's head: cutting an entry from
    # SEAT_PUBLISHED_LAG only and running WITHOUT `--seat` returns PASS exit 0,
    # while the same tree WITH `--seat` returns FAIL exit 1.  So a removal arm
    # that does not name its flag proves nothing about this table.
    #
    # Cause here is single, unlike the NotebookEdit row further up: the seat
    # normaliser passes a Bash `command` through untouched, so the mispricing
    # is entirely `reeflex-claude==0.2.0`'s, and the seat's floor admits
    # whatever reeflex-claude it admits.  Both clear on the same republish.
    "destroy-redirect-leading-both-streams":         "RFX-339",
    "destroy-redirect-leading-both-streams-nospace": "RFX-339",

    # RFX-351, one distribution further out.  MEASURED ON THIS ARM and not
    # mirrored from the table above -- the rule this block already states, and
    # mirroring is not free: a copied entry that does not diverge reddens the
    # gate as STALE.  Measured, python3.12, `--seat` against
    # reeflex-litellm==0.1.0:
    #   code-reports/dev-1--166--20260918-evidence/07-published-seat-arm.txt
    # The two arms were extracted and compared as ID SETS rather than eyeballed,
    # and they are equal here: the same nine fail-open and the same three
    # fail-noisy, through the seat's own normaliser.  Equal is a measurement,
    # not an entailment -- the two resolves are independent.
    #
    # Cause is single, as for the writer family: the seat normaliser passes a
    # Bash `command` through untouched, so the mispricing is entirely
    # `reeflex-claude==0.2.0`'s and both clear on the same republish.
    "destroy-sqlcmd-input-file":          "RFX-339",
    "destroy-clickhouse-queries-file":    "RFX-339",
    "destroy-clickhouse-queries-file-eq": "RFX-339",
    "destroy-redis-eval-script":          "RFX-339",
    "destroy-mongosh-positional-script":  "RFX-339",
    "destroy-mongo-positional-script":    "RFX-339",
    "destroy-sqlite3-dot-read":           "RFX-339",
    "destroy-mysql-inline-source":        "RFX-339",
    "destroy-mysql-inline-dot-source":    "RFX-339",
    "everyday-mysql-force-inline-select": "RFX-339",
    "everyday-mariadb-force":             "RFX-339",
    "everyday-sqlcmd-codepage":           "RFX-339",

    # qa--251.  MEASURED ON THIS ARM, not mirrored from the table above -- the
    # rule this block already states, and the first run of this round proved
    # why it matters: on python3.9 the seat arm SKIPs (reeflex-litellm is not
    # installable there) and a SKIP is not a pass, so an entry written from the
    # default arm's result would have been a guess.  Re-run under python3.12 it
    # installs and answers, and this row diverges there too:
    #   code-reports/qa--251--20260918-evidence/06-published-seat-arm.txt
    # reeflex-litellm==0.1.0 answers execute/recoverable/scoped -> `allow`.
    # Same republish, RFX-339, which is owner-gated; nothing here decides it.
    "destroy-mysql-inline-source-after-statement": "RFX-339",
    # RFX-353 (qa--248), reached one distribution further out. MEASURED on THIS
    # arm and compared to the other as an ID SET, not mirrored from it:
    # `--seat` on python3.12 against reeflex-litellm==0.1.0 reports 44
    # fail-open / 4 fail-noisy over 159 cases and diverges on exactly the same
    # eleven ids, through the seat's own normaliser. The two resolves are
    # independent, so the sets coinciding is a measurement and not an
    # entailment -- the seat passes a Bash `command` through untouched, and its
    # floor admits whatever reeflex-claude it admits.
    #
    # Same republish: RFX-339.
    "destroy-rm-recursive-uppercase-unprotected-path":     "RFX-339",
    "destroy-git-push-plus-refspec":                       "RFX-339",
    "destroy-git-push-mirror":                             "RFX-339",
    "destroy-git-push-delete-remote-branch":               "RFX-339",
    "destroy-git-push-empty-source-refspec":               "RFX-339",
    "destroy-git-push-global-option-before-subcommand":    "RFX-339",
    "destroy-git-clean-global-option-before-subcommand":   "RFX-339",
    "destroy-git-clean-require-force-disabled":            "RFX-339",
    "everyday-rm-single-file-name-contains-dash-r":        "RFX-339",
    "everyday-git-clean-dry-run-path-contains-dash-f":     "RFX-339",
    "everyday-git-push-dry-run-force":                     "RFX-339",
    "everyday-git-push-force-if-includes":                 "RFX-339",
}

TICKET_RE = re.compile(r"RFX-\d+")

# The ONE place the verdict line is written. gate.py parses it with an anchored,
# case-sensitive regex and treats anything else as FAIL, so producer and parser
# are a contract between two files -- pinned by
# scripts/tests/test_check_published_classifier.py, which imports both.
ANCHOR = "PUBLISHED-CLASSIFIER"


def anchored_line(status, detail, anchor=ANCHOR):
    return "%s: %s (%s)" % (anchor, status, detail)

# Runs INSIDE the venv under test. Deliberately tiny: it knows how to call a
# classifier and how to print JSON, and nothing about verdicts, corpora or
# tickets. Everything that could be opinionated stays on the checkout's side.
#
# THE PROJECTED KEYS ARE THE ORACLE'S INPUTS, and `target_ref` is one of them
# (RFX-327). R6 (`irreversible_protected_asset_prod`) reads the ref and nothing
# else -- not the verb, not the blast radius. A projection that drops it makes
# every published wheel look R6-clean, because the oracle then scores a ref of
# None, which is under no protected prefix. Dropping a key here does not fail
# loudly; it silently narrows what the component can see. Anything the oracle
# reads must be in this tuple.
DRIVER = r'''
import json, sys, traceback
import reeflex_claude
from reeflex_claude import classify as _classify

cases = json.load(open(sys.argv[1]))
out = {"where": reeflex_claude.__file__,
       "version": getattr(reeflex_claude, "__version__", "?"),
       "python": sys.version.split()[0],
       "corpus_cases": None,
       "rows": {}}
try:
    from reeflex_claude import conformance as _conf
    out["corpus_cases"] = len(_conf.CASES)
except Exception:
    pass
for c in cases:
    try:
        cls = _classify.classify(c["tool"], c["input"])
        out["rows"][c["id"]] = {"cls": {k: cls.get(k) for k in
                                ("verb", "reversibility", "blast_radius", "externality",
                                 "target_ref")}}
    except Exception:
        out["rows"][c["id"]] = {"error": traceback.format_exc().strip().splitlines()[-1]}
json.dump(out, sys.stdout)
'''

# The SEAT driver. Also runs inside the venv under test, and differs from the
# one above in exactly one way that matters: the corpus case does not reach the
# classifier directly. It is expressed as an OpenAI-shaped tool call under a
# GATEWAY tool name and put through `reeflex_litellm.normalize.normalize_tool_call`
# first, because that is the path the seat a customer runs actually takes.
#
# The gateway names are `gw_<classifier tool>` and they are mapped back by the
# OPERATOR MAP, not by the name heuristics. That is deliberate: the heuristics
# cover the tool names a gateway is likely to use (`run_shell`, `write_file`)
# and have no spelling at all for `Glob`, `LS` or `MultiEdit`, so scoring the
# whole corpus through them would silently send a third of it down the
# unknown-tool path and score the wrong thing. The operator map is a real,
# documented, highest-precedence input, and it round-trips every corpus tool.
#
# The round-trip is ASSERTED per case. A normaliser that drops a call onto the
# unknown path reports as an ERROR for that case, which `audit` already fails
# on -- rather than as a mispricing, which would blame the classifier for the
# normaliser's mistake. `scripts/tests/` pins that this is what happens.
SEAT_DRIVER = r'''
import json, os, sys, traceback
import reeflex_claude, reeflex_litellm
from reeflex_claude import classify as _classify
from reeflex_litellm import normalize as _normalize

cases = json.load(open(sys.argv[1]))
tools = sorted({c["tool"] for c in cases})
os.environ["REEFLEX_LITELLM_TOOL_MAP"] = json.dumps(
    {"gw_" + t: t for t in tools})

out = {"where": reeflex_claude.__file__,
       "version": getattr(reeflex_claude, "__version__", "?"),
       "seat_where": reeflex_litellm.__file__,
       "seat_version": getattr(reeflex_litellm, "__version__", "?"),
       "python": sys.version.split()[0],
       "corpus_cases": None,
       "rows": {}}
try:
    from reeflex_claude import conformance as _conf
    out["corpus_cases"] = len(_conf.CASES)
except Exception:
    pass

for c in cases:
    try:
        call = _normalize.normalize_tool_call({
            "id": c["id"], "type": "function",
            "function": {"name": "gw_" + c["tool"],
                         "arguments": json.dumps(c["input"])}})
        if call.tool_name != c["tool"]:
            out["rows"][c["id"]] = {"error":
                "the seat normalised gw_%s onto %r (source %r), not %r -- the "
                "classification below would be the unknown-tool path"
                % (c["tool"], call.tool_name, call.mapping_source, c["tool"])}
            continue
        cls = _classify.classify(call.tool_name, call.tool_input)
        out["rows"][c["id"]] = {"cls": {k: cls.get(k) for k in
                                ("verb", "reversibility", "blast_radius", "externality",
                                 "target_ref")}}
    except Exception:
        out["rows"][c["id"]] = {"error": traceback.format_exc().strip().splitlines()[-1]}
json.dump(out, sys.stdout)
'''


# --------------------------------------------------------------------------
# The verdict. Pure: no network, no venv, no filesystem — so --selftest can
# prove every branch of it on fixtures, which is the half of this tool that
# has to be right before its PASS is worth reading.
# --------------------------------------------------------------------------

def lag_table_name(lag):
    """Name the table a failure line should send its reader to.

    DERIVED from the table's identity rather than passed alongside it, so the
    two cannot drift: there is no call site that can hand `audit` the seat
    table and the classifier arm's label. An anonymous fixture dict is named
    as what it is -- the alternative, defaulting to a real table's name, is
    the misdirection this function exists to remove.
    """
    if lag is SEAT_PUBLISHED_LAG:
        return "SEAT_PUBLISHED_LAG"
    if lag is PUBLISHED_LAG:
        return "PUBLISHED_LAG"
    return "the lag table for this arm"


def audit(rows, cases, oracle, lag=None, min_scored=MIN_SCORED_CASES):
    """Score `rows` (case id -> {"cls": {...}} | {"error": str}) against `cases`.

    Returns (ok, lines, stats). Every failure mode gets its own line naming the
    case and the two verdicts; a reader must never have to diff two tables to
    find out what moved.
    """
    lag = PUBLISHED_LAG if lag is None else lag
    table = lag_table_name(lag)
    lines, stats = [], {"scored": 0, "fail_open": 0, "fail_noisy": 0,
                        "declared": 0, "errors": 0, "missing": 0, "stale": 0}
    failures = []

    scored_cases = [c for c in cases if not c.get("residual")]
    residual = len(cases) - len(scored_cases)

    # -- ledger hygiene, before any verdict rests on it --------------------
    for cid, ticket in sorted(lag.items()):
        if not TICKET_RE.search(str(ticket)):
            failures.append("%s[%s] = %r names no ticket — an exclusion "
                            "nobody can look up is not a declaration"
                            % (table, cid, ticket))
        if cid not in {c["id"] for c in cases}:
            failures.append("%s[%s] names a case the corpus does not "
                            "contain — the id was renamed or the case was deleted"
                            % (table, cid))

    diverged = set()
    for case in scored_cases:
        row = rows.get(case["id"])
        if row is None:
            stats["missing"] += 1
            failures.append("%s: the published wheel was never asked — no row came "
                            "back for it" % case["id"])
            continue
        if "error" in row:
            stats["errors"] += 1
            failures.append("%s: the published classifier RAISED: %s"
                            % (case["id"], row["error"]))
            continue
        stats["scored"] += 1
        got = oracle(row["cls"])
        expect = case["expect"]
        if got == expect:
            continue
        diverged.add(case["id"])
        axes = "%s/%s/%s" % (row["cls"].get("verb"), row["cls"].get("reversibility"),
                             row["cls"].get("blast_radius"))
        open_ward = RESTRAINT.get(got, 0) < RESTRAINT.get(expect, 0)
        stats["fail_open" if open_ward else "fail_noisy"] += 1
        label = "FAIL-OPEN " if open_ward else "fail-noisy"
        detail = ("%s  %s  expect %-5s published %-5s  (%s)\n        %s\n        effect: %s"
                  % (label, case["id"].ljust(28), expect, got, axes,
                     json.dumps(case["input"])[:120], case["effect"]))
        if case["id"] in lag:
            stats["declared"] += 1
            lines.append("  DECLARED  %s  [%s]" % (detail, lag[case["id"]]))
        else:
            failures.append(detail)

    # -- a declaration that is no longer true is a lie about the artefact ---
    for cid, ticket in sorted(lag.items()):
        if cid not in diverged and cid in {c["id"] for c in cases}:
            stats["stale"] += 1
            failures.append("%s[%s] is STALE: the published wheel no longer "
                            "diverges on it. %s shipped — delete the entry rather than "
                            "leave it behind" % (table, cid, ticket))

    # -- the anti-vacuity floor, last, so it reports on a real number -------
    if stats["scored"] < min_scored:
        failures.append("only %d cases were scored, floor is %d. A count this low means "
                        "the corpus, the venv or the driver stopped working — not that "
                        "the published wheel is clean. RFX-217: a bound the empty set "
                        "passes is not a bound" % (stats["scored"], min_scored))

    lines.append("  %d cases scored, %d residual excluded (the RFX-158 gap family, "
                 "excluded here exactly as tests/test_conformance_bash.py excludes them)"
                 % (stats["scored"], residual))
    for f in failures:
        lines.append("  %s" % f)
    return not failures, lines, stats


# --------------------------------------------------------------------------
# The measurement.
# --------------------------------------------------------------------------

def load_corpus(repo_root):
    """The corpus and the oracle, from the CHECKOUT — never from the wheel.

    The oracle is `reeflex-claude/tests/policy_oracle.py`, the SHARED one
    (RFX-303), imported by the same `sys.path` insert the live arm in
    `scripts/attack-probe-rfx144-agent-prices-own-action.py` already uses.  It is
    deliberately not part of the installed package, so it cannot be reached
    through `reeflex_claude` — see this module's header.
    """
    pkg = os.path.join(repo_root, "reeflex-claude")
    if not os.path.isdir(os.path.join(pkg, "reeflex_claude")):
        raise RuntimeError("no reeflex-claude package under %s" % repo_root)
    sys.path.insert(0, pkg)
    sys.path.insert(0, os.path.join(pkg, "tests"))
    for mod in [m for m in list(sys.modules) if m.startswith("reeflex_claude")]:
        del sys.modules[mod]
    sys.modules.pop("policy_oracle", None)
    from reeflex_claude import conformance
    import policy_oracle as _oracle_mod
    if not os.path.abspath(conformance.__file__).startswith(os.path.abspath(pkg)):
        raise RuntimeError("the corpus resolved to %s, which is NOT the tree under "
                           "test (%s)" % (conformance.__file__, pkg))
    if not os.path.abspath(_oracle_mod.__file__).startswith(os.path.abspath(pkg)):
        raise RuntimeError("the oracle resolved to %s, which is NOT the tree under "
                           "test (%s)" % (_oracle_mod.__file__, pkg))
    return conformance, _oracle_mod.policy_oracle


def classify_with_published(python, cases, workdir, driver_src=DRIVER):
    """Run the corpus through the classifier installed in `python`'s venv.

    `driver_src` selects the PLANE: `DRIVER` reaches `classify()` directly,
    `SEAT_DRIVER` reaches it the way the gateway seat does.
    """
    driver = os.path.join(workdir, "driver.py")
    with open(driver, "w") as fh:
        fh.write(driver_src)
    payload = os.path.join(workdir, "cases.json")
    with open(payload, "w") as fh:
        json.dump([{"id": c["id"], "tool": c["tool"], "input": c["input"]}
                   for c in cases], fh)
    proc = subprocess.run([python, driver, payload], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("the driver died inside the published wheel's venv "
                           "(exit %d):\n%s" % (proc.returncode, proc.stderr[-2000:]))
    return json.loads(proc.stdout)


def install_published(workdir, version, index_timeout=300, dist=DIST):
    """A throwaway venv with ONE `dist` in it, from the index.

    For the seat arm `dist` is `reeflex-litellm`, and the resolve that installs
    it is the measurement: pip picks the `reeflex-claude` that package's own
    floor admits, which is exactly the customer-facing fact this arm is about.
    """
    venv = os.path.join(workdir, "venv")
    proc = subprocess.run([sys.executable, "-m", "venv", venv],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return None, None, "venv creation failed: %s" % proc.stderr.strip()[-300:]
    py = os.path.join(venv, "Scripts" if os.name == "nt" else "bin", "python")
    spec = dist if version is None else "%s==%s" % (dist, version)
    proc = subprocess.run([py, "-m", "pip", "install", "-q", "--no-cache-dir",
                           "--disable-pip-version-check", spec],
                          capture_output=True, text=True, timeout=index_timeout)
    if proc.returncode != 0:
        return None, None, ("pip install %s from the index failed: %s"
                            % (spec, (proc.stderr or proc.stdout).strip()[-400:]))
    show = subprocess.run([py, "-m", "pip", "show", dist], capture_output=True, text=True)
    resolved = next((l.split(":", 1)[1].strip() for l in show.stdout.splitlines()
                     if l.startswith("Version:")), "?")
    return py, resolved, None


def run(repo_root, version=None, keep=False, seat=False):
    """Score a published artefact with the checkout's corpus.

    `seat=False` scores `pip install reeflex-claude` through `classify()`.
    `seat=True` scores `pip install reeflex-litellm` through the gateway seat's
    own normaliser (RFX-326) -- a different resolve and a different plane, with
    its own lag table and its own anchored line.
    """
    dist = SEAT_DIST if seat else DIST
    anchor = SEAT_ANCHOR if seat else ANCHOR
    lag = SEAT_PUBLISHED_LAG if seat else PUBLISHED_LAG
    driver_src = SEAT_DRIVER if seat else DRIVER

    lines = ["  repo under test : %s" % repo_root,
             "  plane           : %s" % (
                 "the gateway seat (normalize_tool_call -> classify)" if seat
                 else "the classifier directly (classify)")]
    try:
        conformance, tree_oracle = load_corpus(repo_root)
    except Exception as exc:                                   # pragma: no cover
        return 1, ["  %s" % exc,
                   anchored_line("FAIL", "the checkout's corpus would not load",
                                 anchor)]
    lines.append("  corpus          : %s (%d cases)"
                 % (conformance.__file__, len(conformance.CASES)))
    lines.append("  oracle          : %s (the shared one, RFX-303)"
                 % getattr(sys.modules["policy_oracle"], "__file__", "?"))

    workdir = tempfile.mkdtemp(prefix="rfx241-published-")
    try:
        py, resolved, err = install_published(workdir, version, dist=dist)
        if err:
            lines.append("  %s" % err)
            return 3, lines + [anchored_line(
                "SKIP", "%s is not installable from the index here — no verdict, "
                        "not a pass" % dist, anchor)]
        lines.append("  published wheel : %s==%s (installed from the index)" % (dist, resolved))
        try:
            got = classify_with_published(py, conformance.CASES, workdir,
                                          driver_src=driver_src)
        except RuntimeError as exc:
            lines.append("  %s" % exc)
            return 1, lines + [anchored_line(
                "FAIL", "%s==%s could not classify at all — a wheel that raises is "
                        "not a wheel that passes" % (dist, resolved), anchor)]
        lines.append("  it loaded       : %s (python %s)" % (got["where"], got["python"]))
        if seat:
            # WHICH reeflex-claude the seat's own floor pulled in. This is the
            # measurement, not a detail: the seat is only as honest as the
            # classifier its dependency declaration admits.
            lines.append("  the seat        : %s %s"
                         % (got.get("seat_version"), got.get("seat_where")))
            lines.append("  it resolved     : reeflex-claude %s" % got.get("version"))
        if got.get("corpus_cases") is not None and got["corpus_cases"] != len(conformance.CASES):
            lines.append("  note            : the published wheel ships its OWN corpus of %d "
                         "cases vs this tree's %d — its installed self-statement is a "
                         "different vintage from the one scoring it here"
                         % (got["corpus_cases"], len(conformance.CASES)))
        ok, audit_lines, stats = audit(got["rows"], conformance.CASES,
                                       tree_oracle, lag=lag)
        lines += audit_lines
        summary = ("%s==%s; %d cases scored (floor %d); %d fail-open; %d fail-noisy; "
                   "%d declared" % (dist, resolved, stats["scored"], MIN_SCORED_CASES,
                                    stats["fail_open"], stats["fail_noisy"],
                                    stats["declared"]))
        lines.append(anchored_line("PASS" if ok else "FAIL", summary, anchor))
        return 0 if ok else 1, lines
    finally:
        if keep:
            lines.append("  venv kept at %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Selftest: prove the detector before anything trusts its PASS.
# --------------------------------------------------------------------------

def selftest():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))

    def oracle(cls):
        """Synthetic and small enough to read. NOT the real oracle — the real one
        is tests/policy_oracle.py. This selftest proves `audit`, so its oracle is
        a stub whose answers are obvious by inspection; using the real one here
        would make the fixtures depend on the pack."""
        if cls["verb"] == "read" and cls["externality"] == "internal":
            return "allow"
        if cls["reversibility"] == "irreversible" and cls["blast_radius"] == "systemic":
            return "deny"
        if cls["reversibility"] == "irreversible" and cls["blast_radius"] == "broad":
            return "ask"
        return "allow"

    def case(cid, expect, residual=None):
        return {"id": cid, "expect": expect, "residual": residual,
                "input": {"command": cid}, "effect": "synthetic %s" % cid,
                "tool": "Bash"}

    SAFE = {"verb": "read", "reversibility": "reversible", "blast_radius": "single",
            "externality": "internal"}
    ASKS = {"verb": "delete", "reversibility": "irreversible", "blast_radius": "broad",
            "externality": "internal"}
    DENIES = {"verb": "delete", "reversibility": "irreversible",
              "blast_radius": "systemic", "externality": "internal"}

    cases = [case("c%d" % i, "ask") for i in range(5)] + [case("ok%d" % i, "allow")
                                                          for i in range(5)]
    agree = dict({c["id"]: {"cls": ASKS} for c in cases if c["expect"] == "ask"},
                 **{c["id"]: {"cls": SAFE} for c in cases if c["expect"] == "allow"})

    ok, lines, stats = audit(agree, cases, oracle, lag={}, min_scored=5)
    check("a wheel that agrees with the corpus passes", ok and stats["scored"] == 10)

    lax = dict(agree); lax["c0"] = {"cls": SAFE}
    ok, lines, stats = audit(lax, cases, oracle, lag={}, min_scored=5)
    check("a wheel that ALLOWS a case the corpus expects `ask` FAILS",
          not ok and stats["fail_open"] == 1)
    check("...and the line says FAIL-OPEN", any("FAIL-OPEN" in l for l in lines))
    check("...and names the case", any("c0" in l for l in lines))

    ok, lines, stats = audit(lax, cases, oracle, lag={"c0": "RFX-241"}, min_scored=5)
    check("the same divergence DECLARED with a ticket passes",
          ok and stats["declared"] == 1)
    check("...and is still printed, not hidden", any("DECLARED" in l for l in lines))

    ok, lines, _ = audit(lax, cases, oracle, lag={"c0": "because reasons"}, min_scored=5)
    check("a declaration naming no ticket FAILS", not ok)
    check("...and says why", any("names no ticket" in l for l in lines))

    ok, lines, stats = audit(agree, cases, oracle, lag={"c0": "RFX-241"}, min_scored=5)
    check("a STALE declaration (no longer diverging) FAILS",
          not ok and stats["stale"] == 1)
    check("...and says to delete it", any("STALE" in l for l in lines))

    ok, lines, _ = audit(agree, cases, oracle, lag={"nosuch": "RFX-241"}, min_scored=5)
    check("a declaration for a case the corpus lost FAILS", not ok)

    strict = dict(agree); strict["ok0"] = {"cls": DENIES}
    ok, lines, stats = audit(strict, cases, oracle, lag={}, min_scored=5)
    check("a wheel that BLOCKS an everyday case FAILS too (a noisy gate gets "
          "switched off)", not ok and stats["fail_noisy"] == 1)
    check("...and is labelled fail-noisy, not fail-open",
          stats["fail_open"] == 0 and any("fail-noisy" in l for l in lines))

    ok, lines, stats = audit({}, cases, oracle, lag={}, min_scored=5)
    check("an EMPTY result set FAILS rather than scoring zero divergences",
          not ok and stats["missing"] == 10)
    check("...and says the floor was not reached", any("floor is 5" in l for l in lines))

    ok, lines, stats = audit(agree, cases, oracle, lag={}, min_scored=99)
    check("scoring fewer cases than the floor FAILS even with no divergence",
          not ok and stats["fail_open"] == 0)

    raised = dict(agree); raised["c1"] = {"error": "TypeError: classify() takes 1 arg"}
    ok, lines, stats = audit(raised, cases, oracle, lag={}, min_scored=5)
    check("a classifier that RAISES on a case FAILS", not ok and stats["errors"] == 1)
    check("...and prints the exception", any("TypeError" in l for l in lines))

    resid = cases + [case("gap-x", "ask", residual="RFX-158")]
    ok, lines, stats = audit(dict(agree, **{"gap-x": {"cls": SAFE}}), resid, oracle,
                             lag={}, min_scored=5)
    check("a residual case is excluded, as the suite excludes it",
          ok and stats["scored"] == 10)
    check("...and the exclusion is reported, not silent",
          any("1 residual excluded" in l for l in lines))

    # -- the seat arm's own ledger (RFX-326) -------------------------------
    # The verdict machinery is shared, so what needs proving separately is that
    # the seat arm carries a REAL lag table and a DISTINCT anchored line. A
    # second arm that printed the first arm's anchor would be read by gate.py
    # as the first arm's verdict — two components, one measurement, and nobody
    # would notice while both were green.
    check("the seat arm's anchored line is distinct from the classifier arm's",
          SEAT_ANCHOR != ANCHOR
          and anchored_line("PASS", "x", SEAT_ANCHOR).startswith(SEAT_ANCHOR))
    check("every seat lag entry names a ticket",
          all(TICKET_RE.search(str(t)) for t in SEAT_PUBLISHED_LAG.values()))
    check("the seat driver puts the corpus through the normaliser, not "
          "straight into classify",
          "normalize_tool_call" in SEAT_DRIVER and "REEFLEX_LITELLM_TOOL_MAP" in SEAT_DRIVER)
    check("the seat driver reports a normalisation MISMATCH as an error rather "
          "than classifying whatever it landed on",
          '"error"' in SEAT_DRIVER and "call.tool_name != c[\"tool\"]" in SEAT_DRIVER)

    mismatched = dict(agree)
    mismatched["c2"] = {"error": "the seat normalised gw_Bash onto 'gw_Bash' "
                                 "(source 'unmapped'), not 'Bash'"}
    ok, lines, stats = audit(mismatched, cases, oracle, lag={}, min_scored=5)
    check("a normalisation mismatch FAILS the seat arm (it is not a mispricing)",
          not ok and stats["errors"] == 1)
    check("...and the line names the normaliser, so the classifier is not blamed",
          any("normalised" in l for l in lines))

    # -- the failure line must name the arm's OWN table (RFX-347) ----------
    # `audit` is shared and `lag` is a parameter, so a hardcoded table name in
    # a failure line sends a seat-arm reader to a table the entry is not in --
    # on exactly the day they are trying to find or delete it. Driven here
    # through the REAL SEAT_PUBLISHED_LAG: against synthetic fixtures every
    # entry takes the "corpus does not contain" branch, which is the branch
    # whose TEXT is under test. The negative lookbehind matters: the string
    # "SEAT_PUBLISHED_LAG" CONTAINS "PUBLISHED_LAG", so a naive `not in`
    # assertion here would be vacuous in both directions.
    ok, lines, _ = audit(agree, cases, oracle, lag=SEAT_PUBLISHED_LAG, min_scored=5)
    misdirected = [l for l in lines if re.search(r"(?<!SEAT_)PUBLISHED_LAG\[", l)]
    check("a seat-arm failure line names SEAT_PUBLISHED_LAG, never the "
          "classifier arm's table", not ok and not misdirected)
    check("...and that line is really emitted, so the check above cannot pass "
          "by printing nothing at all",
          any("SEAT_PUBLISHED_LAG[" in l for l in lines))
    check("...while the classifier arm still names its own table unprefixed",
          any(re.search(r"(?<!SEAT_)PUBLISHED_LAG\[", l)
              for l in audit(agree, cases, oracle, lag=PUBLISHED_LAG,
                             min_scored=5)[1]))
    check("the label is derived from the table itself, both arms",
          lag_table_name(PUBLISHED_LAG) == "PUBLISHED_LAG"
          and lag_table_name(SEAT_PUBLISHED_LAG) == "SEAT_PUBLISHED_LAG")
    check("an anonymous fixture table is named as one rather than borrowing a "
          "real table's name",
          lag_table_name({}) == "the lag table for this arm")

    # THREE lines name the table, and a fixture only reaches one branch. That
    # gap is measured, not assumed: reverting the STALE line alone -- leaving
    # the other two derived -- passed the checks above at 31/31, exit 0,
    # BYTE-IDENTICAL to the control. A guard covers only what it reads, so
    # each branch gets its own arm. The label is derived by IDENTITY, so
    # exercising a branch means making the fixture BE the seat table while it
    # runs; the real table is restored in `finally` and then re-asserted.
    real_seat = SEAT_PUBLISHED_LAG
    try:
        for branch, fixture in (("names no ticket", {"c0": "because reasons"}),
                                ("corpus does not contain", {"nosuch": "RFX-241"}),
                                ("is STALE", {"c0": "RFX-241"})):
            globals()["SEAT_PUBLISHED_LAG"] = fixture
            ok, lines, _ = audit(agree, cases, oracle, lag=fixture, min_scored=5)
            hit = [l for l in lines if branch in l]
            check("the seat arm's %r line names its own table" % branch,
                  not ok and hit
                  and all("SEAT_PUBLISHED_LAG[" in l for l in hit)
                  and not any(re.search(r"(?<!SEAT_)PUBLISHED_LAG\[", l)
                              for l in hit))
    finally:
        globals()["SEAT_PUBLISHED_LAG"] = real_seat
    check("...and the real seat table is back after those arms, so no later "
          "check is scored against a fixture",
          SEAT_PUBLISHED_LAG is real_seat and len(SEAT_PUBLISHED_LAG) > 1)

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  selftest %s: %s" % ("PASS" if ok else "FAIL", n))
    if failed:
        print("SELFTEST: FAIL (%d/%d checks failed)" % (len(failed), len(checks)))
        return 1
    print("SELFTEST: PASS (%d checks)" % len(checks))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="check_published_classifier.py",
        description="score the PUBLISHED reeflex-claude wheel with the checkout's corpus")
    p.add_argument("repo_root", nargs="?", default=None,
                   help="repo root (default: the parent of this script's directory)")
    p.add_argument("--version", default=None,
                   help="pin the wheel under test (default: whatever the index resolves, "
                        "i.e. what a customer gets today). `--version 0.1.7` is the "
                        "control: a wheel whose fail-open is measured and ticketed")
    p.add_argument("--keep-venv", action="store_true",
                   help="leave the throwaway venv on disk for inspection")
    p.add_argument("--selftest", action="store_true",
                   help="prove every branch of the verdict on fixtures, no network")
    p.add_argument("--seat", action="store_true",
                   help="score the published reeflex-litellm GATEWAY SEAT instead: "
                        "resolve that package from the index and run the corpus "
                        "through its normaliser into whichever reeflex-claude its "
                        "own floor admits (RFX-326)")
    args = p.parse_args(sys.argv[1:] if argv is None else argv)
    if args.selftest:
        return selftest()
    repo_root = args.repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code, lines = run(repo_root, version=args.version, keep=args.keep_venv,
                      seat=args.seat)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
