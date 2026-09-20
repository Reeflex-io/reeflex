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
   ticket that closes it AND the published version it describes.  A declaration
   is scoped to that one artefact (RFX-377): while the index still serves it, a
   declared case that no longer diverges FAILS as STALE -- a stale exclusion is
   how a gate quietly stops gating (same rule as `check_test_census.py`'s
   waivers and `conformance.py`'s residuals).  Once the index serves something
   else the declaration EXPIRES: it excuses nothing, so a regression on the
   same case in the new wheel fails undeclared and by name, and it does not
   fail the component, so a release does not redden `main` for whoever merges
   next.  Expired rows are printed and counted in the anchored line.

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
#
#   case id -> {"ticket":       the ticket that closes it,
#               "index_serves": the published version that diverges}
#
# AN ENTRY NAMES AN ARTEFACT, NOT A STANDING TRUTH (RFX-377).
# `index_serves` is the whole of that sentence. A declaration here says "the
# wheel the index serves TODAY, at version X, gets this case wrong". It is not
# a statement about reeflex-claude in general, and it must not survive the
# wheel it describes -- because the hazard of a lag entry is not that it
# excuses a divergence that has gone away, it is that it silently excuses a
# DIFFERENT divergence on the SAME case id in a LATER wheel. Pinning the
# version closes that structurally, so `audit` can be strict where it matters
# and quiet where it does not:
#
#   LIVE     index_serves == the version actually installed from the index.
#            The entry excuses the divergence it names, and is printed.
#            If the case does NOT diverge, the entry is a lie about a wheel
#            that is still out there -> STALE -> the component FAILS.
#
#   EXPIRED  index_serves != the version actually installed. The wheel this
#            entry describes is no longer what a customer gets. The entry
#            EXCUSES NOTHING -- a divergence on that case is now undeclared
#            and FAILS by name -- and it does NOT fail the component. It is
#            printed on every run, with the two versions, until deleted.
#
# WHY EXPIRED IS NOT A FAILURE, WHICH IS A REVERSAL OF THE EARLIER DESIGN AND
# WAS PAID FOR. Until 2026-09-20 an entry that stopped diverging failed the
# component unconditionally, deliberately: "the republish deletes this block by
# reddening the gate until someone does". Publishing v0.2.2 at 00:40Z did
# exactly that, and the measurement (RFX-377, qa--262) is what the reversal
# rests on. The reddening does not land on the release round -- that round
# finished green, because the wheels were not on the index yet when its gate
# ran. It lands on `main`, AFTER the release, on whichever agent merges next,
# under a standing rule that no merge may proceed with main's CI red. Three
# components went red at once, six open pull requests were blocked behind a
# tree nobody had changed, and the redness said nothing about any of them.
#
# The pressure to delete is kept, and it is kept where it can be acted on: the
# EXPIRED lines are printed in full and counted in the anchored line, so the
# debt is visible in every gate run rather than being a surprise that blocks a
# merge queue.
#
# WHAT THIS TABLE HELD, AND WHY IT IS EMPTY. It carried 68 entries against
# `reeflex-claude==0.2.0`: ten `destroy-subst-*` (RFX-301) and 58 under RFX-339
# -- the `destroy-group-*` subshell family (defect RFX-329), the
# `destroy-redirect-*` trailing-redirection family (defect RFX-340), the
# `destroy-writer-*` coreutils family, the git/sql/mongo/redis spellings, the
# two path-cap rows and the NotebookEdit row. Every one of them was a real,
# measured fail-open in the wheel a customer could install, and every one of
# them is closed by the artefact the index serves now:
# `reeflex-claude==0.2.1`, uploaded 2026-09-20T00:40:27Z by the v0.2.2 tag,
# scores 191 corpus cases with 0 fail-open and 0 fail-noisy. The entries are
# deleted rather than left to report EXPIRED forever; `git log -- ` this file
# at e175e4e for the measurements behind each one.
PUBLISHED_LAG: dict = {}

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

# The seat's own lag table. Same shape, same rules, same version-scoping: each
# entry names the ticket that closes it AND the published `reeflex-litellm`
# version it describes, an entry that stops diverging on the version it names
# FAILS as STALE, an entry naming a version the index no longer serves EXPIRES
# (excuses nothing, fails nothing, stays printed), and a declaration naming no
# ticket FAILS. Read the long note over PUBLISHED_LAG for why EXPIRED is not a
# failure -- the reasoning is one reasoning, not two.
#
# These are the same cases as PUBLISHED_LAG, reached one distribution
# further out, and they close the same way: a republish. They are listed
# separately rather than aliased because the two resolves are independent --
# `reeflex-litellm`'s floor is its own declaration and a future edit to it can
# move this arm without moving the other.
#
# WHAT THIS TABLE HELD. 68 entries against `reeflex-litellm==0.1.0`, whose
# floor resolved `reeflex-claude==0.2.0`: the same substitution, subshell-group
# and trailing-redirect families as the arm above plus the path-cap and
# NotebookEdit rows, each MEASURED on this arm rather than mirrored from the
# other. The index now serves `reeflex-litellm==0.2.0` (uploaded
# 2026-09-20T00:40:48Z), whose floor resolves `reeflex-claude==0.2.1`; that
# seat scores 191 corpus cases with 0 fail-open and 0 fail-noisy, so all 68
# describe an artefact nobody can install any more. Deleted, not left to
# report EXPIRED forever; `git log -- ` this file at e175e4e for the
# per-family evidence paths.
SEAT_PUBLISHED_LAG: dict = {}

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


def lag_entry(value):
    """(ticket, index_serves) for one lag-table value, or (None, None) shapes.

    A declaration is `{"ticket": "RFX-nnn", "index_serves": "<version>"}`. The
    bare-ticket string this table used to hold is deliberately NOT accepted:
    it is the shape that cannot expire, and a shape that cannot expire is the
    defect (RFX-377). It comes back with `index_serves=None` so ledger hygiene
    can fail it by name rather than by TypeError.
    """
    if isinstance(value, dict):
        return value.get("ticket"), value.get("index_serves")
    return value, None


def audit(rows, cases, oracle, lag=None, min_scored=MIN_SCORED_CASES,
          published_version=None):
    """Score `rows` (case id -> {"cls": {...}} | {"error": str}) against `cases`.

    Returns (ok, lines, stats). Every failure mode gets its own line naming the
    case and the two verdicts; a reader must never have to diff two tables to
    find out what moved.

    `published_version` is the version actually installed from the index. It
    is what splits the lag table into LIVE entries (this wheel) and EXPIRED
    ones (some other wheel). Passing None means "score every entry as live",
    which is only for callers that have no wheel in hand.
    """
    lag = PUBLISHED_LAG if lag is None else lag
    table = lag_table_name(lag)
    lines, stats = [], {"scored": 0, "fail_open": 0, "fail_noisy": 0,
                        "declared": 0, "errors": 0, "missing": 0, "stale": 0,
                        "expired": 0}
    failures = []

    scored_cases = [c for c in cases if not c.get("residual")]
    residual = len(cases) - len(scored_cases)

    # -- LIVE vs EXPIRED, before hygiene, because the two are judged apart --
    # An EXPIRED entry describes a wheel the index no longer serves. It grants
    # nothing (so a regression on the same case id in the new wheel fails,
    # undeclared, by name) and it fails nothing (so a release does not redden
    # main for whoever merges next -- RFX-377). It is printed on every run.
    live, expired = {}, {}
    for cid, value in sorted(lag.items()):
        _, serves = lag_entry(value)
        if published_version is not None and serves is not None \
                and serves != published_version:
            expired[cid] = value
        else:
            live[cid] = value

    for cid, value in sorted(expired.items()):
        ticket, serves = lag_entry(value)
        stats["expired"] += 1
        lines.append("  EXPIRED   %s[%s] was declared against %s, the index now "
                     "serves %s — it excuses nothing on this wheel; delete it (%s)"
                     % (table, cid, serves, published_version, ticket))

    # -- ledger hygiene, before any verdict rests on it --------------------
    # LIVE entries only: an expired entry is inert, and failing on the shape of
    # something that grants no permission is the blocking-on-a-dead-row this
    # whole split exists to stop.
    for cid, value in sorted(live.items()):
        ticket, serves = lag_entry(value)
        if not TICKET_RE.search(str(ticket)):
            failures.append("%s[%s] = %r names no ticket — an exclusion "
                            "nobody can look up is not a declaration"
                            % (table, cid, ticket))
        if serves is None:
            failures.append("%s[%s] = %r names no `index_serves` — a declaration "
                            "that does not say WHICH published version it describes "
                            "cannot expire, and one that cannot expire will excuse a "
                            "future regression on the same case (RFX-377)"
                            % (table, cid, value))
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
        if case["id"] in live:
            ticket, serves = lag_entry(live[case["id"]])
            stats["declared"] += 1
            lines.append("  DECLARED  %s  [%s, %s]" % (detail, ticket, serves))
        else:
            failures.append(detail)

    # -- a LIVE declaration that is no longer true is a lie about the wheel --
    # Scoped to live entries on purpose: the wheel an expired entry describes
    # is not the wheel that was just scored, so "it no longer diverges" is not
    # a fact about that entry at all.
    for cid, value in sorted(live.items()):
        ticket, serves = lag_entry(value)
        if cid not in diverged and cid in {c["id"] for c in cases}:
            stats["stale"] += 1
            failures.append("%s[%s] is STALE: %s is the version this entry names "
                            "and it is what the index serves, and it no longer "
                            "diverges on this case. %s shipped — delete the entry "
                            "rather than leave it behind"
                            % (table, cid, serves, ticket))

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
                                       tree_oracle, lag=lag,
                                       published_version=resolved)
        lines += audit_lines
        summary = ("%s==%s; %d cases scored (floor %d); %d fail-open; %d fail-noisy; "
                   "%d declared" % (dist, resolved, stats["scored"], MIN_SCORED_CASES,
                                    stats["fail_open"], stats["fail_noisy"],
                                    stats["declared"]))
        # The expiry debt rides on the anchored line, not only in the body.
        # gate.py's component detail is the one sentence most readers see, and
        # an EXPIRED row that is only visible to someone scrolling the log is
        # the quiet rot this ledger's rules exist to prevent.
        if stats["expired"]:
            summary += ("; %d EXPIRED (declared against a version the index no "
                        "longer serves — delete them)" % stats["expired"])
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

    # Every fixture below names the version it describes, because that is the
    # shape the table now requires. WHEEL is "the wheel we are pretending to
    # have installed"; OTHER is any other wheel.
    WHEEL, OTHER = "1.0.0", "1.0.1"

    def decl(ticket="RFX-241", serves=WHEEL):
        return {"ticket": ticket, "index_serves": serves}

    ok, lines, stats = audit(lax, cases, oracle, lag={"c0": decl()}, min_scored=5,
                             published_version=WHEEL)
    check("the same divergence DECLARED with a ticket passes",
          ok and stats["declared"] == 1)
    check("...and is still printed, not hidden", any("DECLARED" in l for l in lines))
    check("...and the DECLARED line names the wheel the entry describes",
          any("DECLARED" in l and WHEEL in l for l in lines))

    ok, lines, _ = audit(lax, cases, oracle, lag={"c0": decl(ticket="because reasons")},
                         min_scored=5, published_version=WHEEL)
    check("a declaration naming no ticket FAILS", not ok)
    check("...and says why", any("names no ticket" in l for l in lines))

    # RFX-377: the shape that CANNOT expire is refused outright. A bare ticket
    # string is what this table held before, and it is the exact shape that
    # would go on excusing `c0` after the wheel it was written for was replaced.
    ok, lines, stats = audit(lax, cases, oracle, lag={"c0": "RFX-241"}, min_scored=5,
                             published_version=WHEEL)
    check("a bare-ticket declaration with no `index_serves` FAILS", not ok)
    check("...and says it cannot expire", any("cannot expire" in l for l in lines))
    check("...and is not counted as expired, because it named no version",
          stats["expired"] == 0)

    ok, lines, stats = audit(agree, cases, oracle, lag={"c0": decl()}, min_scored=5,
                             published_version=WHEEL)
    check("a STALE declaration (this wheel, no longer diverging) FAILS",
          not ok and stats["stale"] == 1)
    check("...and says to delete it", any("STALE" in l for l in lines))
    check("...and names the version it is stale against",
          any("STALE" in l and WHEEL in l for l in lines))

    ok, lines, _ = audit(agree, cases, oracle, lag={"nosuch": decl()}, min_scored=5,
                         published_version=WHEEL)
    check("a declaration for a case the corpus lost FAILS", not ok)

    # -- RFX-377: version-scoped expiry, all four corners ------------------
    # (1) the release case. The entry described the previous wheel, the new one
    #     is clean, and the component must NOT go red: this is the whole defect.
    ok, lines, stats = audit(agree, cases, oracle, lag={"c0": decl(serves=OTHER)},
                             min_scored=5, published_version=WHEEL)
    check("a declaration against a version the index no longer serves EXPIRES "
          "instead of failing the component", ok and stats["expired"] == 1)
    check("...and stats do not call it stale", stats["stale"] == 0)
    check("...and it is printed with BOTH versions, not silently dropped",
          any("EXPIRED" in l and OTHER in l and WHEEL in l for l in lines))

    # (2) THE FAIL-CLOSED CORNER, and the reason this is not just "make it
    #     quieter": an expired entry must GRANT NOTHING. The same divergence
    #     that (1) forgave is now undeclared, and must fail by name.
    ok, lines, stats = audit(lax, cases, oracle, lag={"c0": decl(serves=OTHER)},
                             min_scored=5, published_version=WHEEL)
    check("an EXPIRED declaration excuses nothing — the same divergence on the "
          "new wheel FAILS", not ok and stats["fail_open"] == 1
          and stats["declared"] == 0)
    check("...and the failure names the case rather than the ledger",
          any("FAIL-OPEN" in l and "c0" in l for l in lines))

    # (3) an expired entry naming a ticket-less value or a case the corpus lost
    #     is inert, not a failure: it grants nothing, so blocking on its shape
    #     is the blocking-on-a-dead-row this split exists to remove.
    ok, _, stats = audit(agree, cases, oracle,
                         lag={"nosuch": decl(ticket="because reasons", serves=OTHER)},
                         min_scored=5, published_version=WHEEL)
    check("an EXPIRED entry is inert — bad ticket, missing case, still no failure",
          ok and stats["expired"] == 1)

    # (4) no wheel in hand (published_version=None) scores every entry as live,
    #     so a caller that cannot say which artefact it measured gets the strict
    #     reading rather than a free pass.
    ok, _, stats = audit(agree, cases, oracle, lag={"c0": decl(serves=OTHER)},
                         min_scored=5, published_version=None)
    check("with no published version in hand, nothing expires and STALE still "
          "fires", not ok and stats["expired"] == 0 and stats["stale"] == 1)

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
    # Shape assertion over the REAL tables. It is VACUOUS while both are empty,
    # which they are today, and saying so is the point: what carries the weight
    # is the fixture-driven hygiene above, which watches both branches (no
    # ticket, no `index_serves`) actually fire. This line exists to catch the
    # next hand-written entry, not to claim coverage now.
    check("every entry in either real lag table names a ticket AND the "
          "published version it describes (vacuous while both are empty)",
          all(TICKET_RE.search(str(lag_entry(v)[0])) and lag_entry(v)[1]
              for v in list(PUBLISHED_LAG.values())
              + list(SEAT_PUBLISHED_LAG.values())))
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
    # on exactly the day they are trying to find or delete it. The negative
    # lookbehind matters: the string "SEAT_PUBLISHED_LAG" CONTAINS
    # "PUBLISHED_LAG", so a naive `not in` assertion would be vacuous in both
    # directions.
    check("the label is derived from the table itself, both arms",
          lag_table_name(PUBLISHED_LAG) == "PUBLISHED_LAG"
          and lag_table_name(SEAT_PUBLISHED_LAG) == "SEAT_PUBLISHED_LAG")
    check("an anonymous fixture table is named as one rather than borrowing a "
          "real table's name",
          lag_table_name({}) == "the lag table for this arm")

    # FIVE lines name the table, and a fixture only reaches one branch. That
    # gap is measured, not assumed: reverting the STALE line alone -- leaving
    # the others derived -- once passed this block at 31/31, exit 0,
    # BYTE-IDENTICAL to the control. A guard covers only what it reads, so each
    # branch gets its own arm. The label is derived by IDENTITY, so exercising a
    # branch means making the fixture BE the table while it runs; both real
    # tables are restored in `finally` and then re-asserted.
    #
    # BOTH tables are driven, not just the seat's. Until RFX-377 the classifier
    # arm was covered only because its real table happened to be non-empty --
    # both tables are empty now, so a fixture that is not installed as the
    # global proves nothing about either name.
    BRANCHES = (
        # (text in the line, fixture, rows, does it fail the component?)
        ("names no ticket",
         {"c0": {"ticket": "because reasons", "index_serves": WHEEL}}, agree, True),
        ("names no `index_serves`", {"c0": "RFX-241"}, agree, True),
        ("corpus does not contain", {"nosuch": decl()}, agree, True),
        ("is STALE", {"c0": decl()}, agree, True),
        ("EXPIRED", {"c0": decl(serves=OTHER)}, agree, False),
    )
    real_seat, real_main = SEAT_PUBLISHED_LAG, PUBLISHED_LAG
    try:
        for global_name, label, other in (("SEAT_PUBLISHED_LAG", "SEAT_PUBLISHED_LAG[",
                                           r"(?<!SEAT_)PUBLISHED_LAG\["),
                                          ("PUBLISHED_LAG", None, r"SEAT_PUBLISHED_LAG\[")):
            for branch, fixture, rows, should_fail in BRANCHES:
                globals()[global_name] = fixture
                ok, lines, _ = audit(rows, cases, oracle, lag=fixture, min_scored=5,
                                     published_version=WHEEL)
                hit = [l for l in lines if branch in l]
                if label is None:                    # the classifier arm
                    named = all(re.search(r"(?<!SEAT_)PUBLISHED_LAG\[", l) for l in hit)
                else:
                    named = all(label in l for l in hit)
                check("%s's %r line names its own table"
                      % (global_name, branch),
                      ok is not should_fail and hit and named
                      and not any(re.search(other, l) for l in hit))
                globals()[global_name] = (real_seat if global_name == "SEAT_PUBLISHED_LAG"
                                          else real_main)
    finally:
        globals()["SEAT_PUBLISHED_LAG"] = real_seat
        globals()["PUBLISHED_LAG"] = real_main
    check("...and both real tables are back after those arms, so no later "
          "check is scored against a fixture",
          SEAT_PUBLISHED_LAG is real_seat and PUBLISHED_LAG is real_main)

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
