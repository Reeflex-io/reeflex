#!/usr/bin/env python3
"""Score the PUBLISHED n8n connector against the fixes that merged to this tree.

Why this exists
---------------
`smoke-pypi.yml` scores the three PyPI packages a customer can install. The n8n
connector is published to a different index (npm) and — measured 2026-09-18 —
from a different repository (`Reeflex-io/n8n-nodes-reeflex`), so nothing in this
repo looked at it. Between 2026-07-19 and 2026-09-18 five commits landed under
`n8n-nodes-reeflex/` here and none of them reached either published channel; CI
stayed green throughout, because no check read the published bytes.

What a customer actually gets, and from where
---------------------------------------------
Two channels, and they carry different things:

* **npm** (`npm install n8n-nodes-reeflex`) ships `dist/` and `README.md`. It
  carries the NODE — the credential handling, the envelope this node sends, the
  defaults an operator inherits. It ships no `examples/` directory.
* **the publish repo** carries `examples/n8n/` — the importable demo workflows
  and their READMEs. That is where a customer gets `demo3`, the reference
  implementation of the Art.14 human-oversight loop.

A fix merged here reaches a customer only once it appears in the channel that
carries it, so each property below names the channel it is checked in.

How to read a verdict
---------------------
Every property is measured on THREE arms, not two:

* ``tree`` — this checkout. If a property is absent here the probe has gone
  stale (the code was refactored out from under it) and the run is RED. A probe
  that cannot find its subject in the tree is not evidence about the published
  artefact; it is evidence about the probe.
* ``npm`` / ``github`` — the published bytes, fetched from the index itself and
  never from this checkout.

A property present in the tree and absent from a channel is a GAP: a merged fix
a customer does not have. A GAP is allowed ONLY if it is declared in ``LAG``
below, with the ticket that closes it. And a declared row whose gap has since
closed is itself RED — otherwise a declaration written to silence one real gap
goes on silencing the next one, and the table rots into a list of things nobody
rechecks.

One property, every file the commit landed in (RFX-359)
-------------------------------------------------------
A property carries a ``Subject`` per file, and is ``delivered`` on a channel
only when EVERY subject that channel ships carries it. That is not a coverage
nicety: ``session-id-per-workflow`` used to be scored on the node default alone
while its commit had landed in four demo workflows too, where an explicit value
BEATS the node default. A republish of the node only would have satisfied the
one scored subject, and the row would have reported STALE-DECLARATION — whose
text tells the reader to delete it — while four importable workflows went on
serving the old value with nothing left to record them. A declaration must close
on the same set something scores, or it is a waiver that ends its own condition.

A partial delivery therefore prints ``GAP 1/5`` and names the lagging files,
rather than choosing between "delivered" and "missing" for a mixed state.

Exit codes: 0 clean, 1 findings, 3 a channel could not be read (distinct on
purpose — an index that is down must not read as a delivered or missing fix).

Not a release tool. Publishing is owner-gated (see n8n-nodes-reeflex/PUBLISH.md);
this script only measures and reports.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG = "n8n-nodes-reeflex"
REGISTRY = f"https://registry.npmjs.org/{PKG}"
PUBLISH_REPO = "Reeflex-io/n8n-nodes-reeflex"
RAW = f"https://raw.githubusercontent.com/{PUBLISH_REPO}/main"
TIMEOUT = 30

# Logical artefact -> where the same file lives on each arm. `npm` paths are
# inside the tarball's `package/` prefix and point at the COMPILED output, which
# is what an operator's n8n loads; `tree`/`github` paths point at the source.
ARTEFACTS = {
    "node": {
        "tree": "n8n-nodes-reeflex/nodes/ReeflexGate/ReeflexGate.node.ts",
        "github": "nodes/ReeflexGate/ReeflexGate.node.ts",
        "npm": "package/dist/nodes/ReeflexGate/ReeflexGate.node.js",
    },
    # The importable demo workflows. They have no `npm` path on purpose: the
    # tarball ships dist/ and README.md and no examples/ directory, so a demo
    # can only ever lag on the github channel.
    "demo1-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo1-bulk-delete-guard.workflow.json",
        "github": "examples/n8n/demo1-bulk-delete-guard.workflow.json",
    },
    "demo2-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo2-fragmentation-doesnt-work.workflow.json",
        "github": "examples/n8n/demo2-fragmentation-doesnt-work.workflow.json",
    },
    "demo3-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo3-the-approval-loop.workflow.json",
        "github": "examples/n8n/demo3-the-approval-loop.workflow.json",
    },
    "demo4-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo4-nothing-gets-through.workflow.json",
        "github": "examples/n8n/demo4-nothing-gets-through.workflow.json",
    },
    "demo5-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo5-watch-before-you-enforce.workflow.json",
        "github": "examples/n8n/demo5-watch-before-you-enforce.workflow.json",
    },
    "demo3-readme": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo3-README.md",
        "github": "examples/n8n/demo3-README.md",
    },
}

# A workflow file that is deliberately NOT a subject of a property, and why.
# Keyed by the path under `n8n-nodes-reeflex/examples/n8n/`. This table exists so
# that "not scored" is a statement somebody wrote down, not the absence of one:
# `scripts/tests/test_check_published_connector.py` enumerates the demo files on
# DISK and requires each to be either a subject or a row here. Enumerating from
# the table instead would let a demo6 land tomorrow, be scored by nothing, and
# read as covered (RFX-359 is that shape one level down).
UNSCORED_WORKFLOWS = {
    "demo2-fragmentation-doesnt-work.workflow.json":
        "excluded from session-id-per-workflow ONLY. Its session id is generated "
        "in a Code node (`frag-demo-${$execution.id}-…`) and passed as "
        "`={{$json.sessionId}}` on purpose — the demo isolates R5's session "
        "delete budget and needs one id shared by ten items, so the "
        "workflow-scoped default does not apply to it. It IS a subject of "
        "demo-agent-id-per-run (RFX-371): the reason its session id is special "
        "says nothing about its agent id, and the row that excused one was read "
        "as excusing both.",
}


@dataclass(frozen=True)
class Subject:
    """One FILE a property is visible in, and the bytes that show it there.

    A property whose commit landed in several files needs one probe per file:
    the same behaviour is spelled differently in a TypeScript parameter default
    (`default: '={{$workflow.id}}'`) and in an exported workflow
    (`"sessionId": "={{$workflow.id}}"`). One loose regex covering both would
    also match the node's own PROSE — the docstring explaining the default — and
    a probe a comment can satisfy measures nothing.
    """

    artefact: str
    probe: re.Pattern[str]
    where: str


@dataclass(frozen=True)
class Property:
    """One behaviour a merged commit established, and how to see it in bytes.

    `subjects` is the full set of files that commit landed in, not the most
    convenient one. Until RFX-359 this was a single `artefact`, and the
    consequence was not narrow coverage but a retiring declaration: a partial
    republish satisfied the only scored subject, the row went STALE ("delete
    it"), and the four files still serving the old bytes lost their only record.
    The set a row closes on and the set something scores must be the same set.

    A probe is deliberately a regex over the artefact text rather than a parse:
    it has to answer the same question about TypeScript source and about the
    JavaScript `tsc` emits from it, and the emitted default strings are
    byte-identical to the source ones.
    """

    id: str
    ticket: str
    channels: tuple[str, ...]
    subjects: tuple[Subject, ...]
    what: str


# The session id as it is spelled in an exported workflow. Anchored on the
# parameter NAME so that the demo's prose, notes field or a code node mentioning
# the expression cannot satisfy it.
_WORKFLOW_SESSION_ID = re.compile(r'"sessionId":\s*"=\{\{\$workflow\.id\}\}"')

# The agent id as it is spelled in an exported workflow, anchored on the
# parameter NAME for the same reason: demo3's README and the node's own
# docstring both discuss agent ids in prose, and a probe prose can satisfy
# measures the prose. Requires the leading `=` (an n8n expression) AND a
# per-run token, because `"agentId": "=agent:n8n-demo3-approval-loop"` is an
# expression that still evaluates to one string for every importer — the same
# defect wearing an equals sign.
_WORKFLOW_AGENT_ID_PER_RUN = re.compile(
    r'"agentId":\s*"=[^"]*\{\{\$(?:execution|workflow)\.id\}\}[^"]*"')

PROPERTIES: list[Property] = [
    Property(
        id="agent-id-per-execution",
        ticket="RFX-138",
        channels=("npm", "github"),
        # The fix replaced the bare constant 'agent:n8n' with a per-execution
        # value. Core binds a human approval to the actor by comparing agent.id
        # against the held envelope, so a constant shared by every execution
        # makes that comparison vacuous.
        #
        # ONE subject, and that is measured rather than assumed: the demo
        # workflows do NOT inherit this default — each pins its own value, so
        # f9c2977 did not land in them and they are not subjects of THIS row.
        #
        # RFX-371 ANSWERED THE QUESTION THIS COMMENT USED TO PARK. It read:
        # "(Whether a shipped demo SHOULD carry a constant agent id is a
        # separate question and not one this script answers.)" It is answered —
        # measured through core's own decide.process() over the real OPA pack,
        # with the ids read out of the shipped JSON: with the constant, importer
        # B spends the approval a human granted importer A (allow,
        # reeflex.policy/approved_resubmission) and A is then locked out
        # (reeflex_hold_consumed); with a per-run id, B is refused
        # reeflex_hold_actor_mismatch and A keeps its approval. The demos are
        # now scored, by `demo-agent-id-per-run` below — a separate property
        # because it closes on a DIFFERENT commit than f9c2977 and a republish
        # can land one without the other.
        subjects=(
            Subject("node", re.compile(r"agent:n8n/\{\{\$execution\.id\}\}"),
                    "the node's Agent ID parameter default"),
        ),
        what="agent.id default is per-execution, not a constant every workflow shares",
    ),
    Property(
        id="demo-agent-id-per-run",
        ticket="RFX-371",
        # github only: the npm tarball ships dist/ and README.md, no examples/.
        channels=("github",),
        # An explicit value in an imported workflow BEATS the node default, so
        # for anyone importing a demo the correct default above is not the thing
        # that decides. All five demos pinned a constant, which means every
        # importer of a demo presented core with the SAME actor key —
        # indistinguishable, by construction, from one agent that restarted.
        #
        # All FIVE are subjects, including demo2: its exclusion in
        # UNSCORED_WORKFLOWS is about its session id and says nothing about its
        # agent id.
        subjects=(
            Subject("demo1-workflow", _WORKFLOW_AGENT_ID_PER_RUN, "demo1's gate node"),
            Subject("demo2-workflow", _WORKFLOW_AGENT_ID_PER_RUN, "demo2's gate node"),
            Subject("demo3-workflow", _WORKFLOW_AGENT_ID_PER_RUN, "demo3's gate node"),
            Subject("demo4-workflow", _WORKFLOW_AGENT_ID_PER_RUN, "demo4's gate node"),
            Subject("demo5-workflow", _WORKFLOW_AGENT_ID_PER_RUN, "demo5's gate node"),
        ),
        what="an imported demo's agent.id varies per run, so two importers cannot spend each other's approvals",
    ),
    Property(
        id="session-id-per-workflow",
        ticket="RFX-180..184",
        channels=("npm", "github"),
        # Cumulative budgets accumulate per agent.session_id. An
        # execution-scoped session id resets them on every run, so a trigger
        # firing once per item never accumulates.
        #
        # FIVE subjects (RFX-359). f550cbc changed the node default AND the four
        # demo workflows that carry an explicit value, and an explicit value in
        # an imported workflow BEATS the node default — so for anyone who
        # imports demo1/3/4/5 the node's default is not the thing that decides.
        subjects=(
            Subject("node", re.compile(r"default:\s*'=\{\{\$workflow\.id\}\}'"),
                    "the node's Session ID parameter default"),
            Subject("demo1-workflow", _WORKFLOW_SESSION_ID, "demo1's gate node"),
            Subject("demo3-workflow", _WORKFLOW_SESSION_ID, "demo3's gate node"),
            Subject("demo4-workflow", _WORKFLOW_SESSION_ID, "demo4's gate node"),
            Subject("demo5-workflow", _WORKFLOW_SESSION_ID, "demo5's gate node"),
        ),
        what="session id default is workflow-scoped, so budgets survive across runs",
    ),
    Property(
        id="money-verb-needs-amount",
        ticket="RFX-180..184",
        channels=("npm", "github"),
        # Without amount/currency a `transact` is budgeted by count budgets
        # alone, which cannot tell a 1-euro refund from a large payout. Node
        # logic only: no demo declares a money verb.
        subjects=(
            Subject("node", re.compile(r"MONEY_VERBS"), "the node's verb table"),
        ),
        what="a transact with no declared amount is refused here rather than sent",
    ),
    Property(
        id="demo3-node-marked-demo-only",
        ticket="RFX-182",
        channels=("github",),
        # The node POSTs /v1/holds/{id}/resolve with the same credential the
        # acting agent uses, so the loop completes with no human. The name is
        # what an importer reads on the canvas.
        subjects=(
            Subject("demo3-workflow", re.compile(r"DEMO ONLY, NO HUMAN"),
                    "the self-resolving node's name on the canvas"),
        ),
        what="the self-resolving node says on the canvas that no human is in it",
    ),
    Property(
        id="demo3-readme-warns",
        ticket="RFX-182",
        channels=("github",),
        subjects=(
            Subject("demo3-readme", re.compile(r"There is no human in this workflow"),
                    "demo3-README.md's opening warning"),
        ),
        what="demo3's README opens with the no-human warning instead of calling it a simplification",
    ),
]


@dataclass(frozen=True)
class Lag:
    """A gap that is known, ticketed, and not yet closed.

    `closes_when` is the condition a reader can check, not a date — the gaps
    below close on a republish, which is owner-gated and has no scheduled date.
    """

    property_id: str
    channel: str
    ticket: str
    declared: str
    closes_when: str


# Declared 2026-09-18 (dev-2 round 083, RFX-182). Every row was measured on the
# published bytes that day, not inferred from the tree. They close on the same
# event — a republish of the connector from a tree that carries these commits —
# but they are listed per (property, channel) rather than as one blanket waiver,
# so that a partial republish reports the rows it left behind.
#
# What makes "the publish repo carries f550cbc" checkable rather than aspirational
# is that the property it declares is scored on all FIVE files that commit landed
# in (RFX-359). Before that it was scored on one, so a republish of that one file
# satisfied the row's instrument while its stated condition was still false.
LAG: list[Lag] = [
    Lag("agent-id-per-execution", "npm", "RFX-138", "2026-09-18",
        "npm serves a version built from a tree containing f9c2977"),
    Lag("agent-id-per-execution", "github", "RFX-183", "2026-09-18",
        "the publish repo carries f9c2977"),
    Lag("session-id-per-workflow", "npm", "RFX-183", "2026-09-18",
        "npm serves a version built from a tree containing f550cbc"),
    Lag("session-id-per-workflow", "github", "RFX-183", "2026-09-18",
        "the publish repo carries f550cbc"),
    Lag("money-verb-needs-amount", "npm", "RFX-183", "2026-09-18",
        "npm serves a version built from a tree containing f550cbc"),
    Lag("money-verb-needs-amount", "github", "RFX-183", "2026-09-18",
        "the publish repo carries f550cbc"),
    Lag("demo3-node-marked-demo-only", "github", "RFX-182", "2026-09-18",
        "the publish repo carries 25a98040"),
    Lag("demo3-readme-warns", "github", "RFX-182", "2026-09-18",
        "the publish repo carries 25a98040"),
    # Declared 2026-09-20 (dev-2 round 097, RFX-371), measured on the published
    # bytes that day: all five demos in the publish repo still pin the constant.
    # This row is the point of the fix as much as the tree change is — a
    # customer imports from the PUBLISH REPO, so until it is republished the
    # exposure measured in RFX-371 is still what an importer gets. The tree
    # being right is not the delivery.
    Lag("demo-agent-id-per-run", "github", "RFX-371", "2026-09-20",
        "the publish repo carries the commit that made every demo's agentId "
        "a per-run expression"),
]


class ChannelUnavailable(Exception):
    """A published channel could not be read. Not a verdict about a fix."""


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
            return r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise ChannelUnavailable(f"{url}: {exc}") from exc


@dataclass
class Channel:
    name: str
    version: str = ""
    files: dict[str, str] = field(default_factory=dict)

    def text(self, path: str) -> str | None:
        return self.files.get(path)


def load_tree() -> Channel:
    ch = Channel("tree", version="(this checkout)")
    for artefact in ARTEFACTS.values():
        rel = artefact.get("tree")
        if rel is None:
            continue
        p = REPO_ROOT / rel
        if p.exists():
            ch.files[rel] = p.read_text(encoding="utf-8")
    return ch


def load_npm() -> Channel:
    meta = json.loads(_fetch(REGISTRY))
    latest = meta["dist-tags"]["latest"]
    tarball = meta["versions"][latest]["dist"]["tarball"]
    blob = _fetch(tarball)
    ch = Channel("npm", version=latest)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        wanted = {a["npm"] for a in ARTEFACTS.values() if "npm" in a}
        for member in tf.getmembers():
            if member.name in wanted:
                fh = tf.extractfile(member)
                if fh is not None:
                    ch.files[member.name] = fh.read().decode("utf-8", "replace")
    return ch


def load_github() -> Channel:
    ch = Channel("github", version=f"{PUBLISH_REPO}@main")
    for artefact in ARTEFACTS.values():
        rel = artefact.get("github")
        if rel is None:
            continue
        ch.files[rel] = _fetch(f"{RAW}/{rel}").decode("utf-8", "replace")
    return ch


@dataclass
class Finding:
    kind: str
    text: str


def subjects_on(prop: Property, channel_name: str) -> list[tuple[Subject, str]]:
    """The property's subjects that the given channel actually carries a file for.

    `examples/` is not in the npm tarball, so a demo subject is simply not
    scored there — that is the channel shipping different things, not a gap.
    """
    out = []
    for subject in prop.subjects:
        path = ARTEFACTS[subject.artefact].get(channel_name)
        if path is not None:
            out.append((subject, path))
    return out


def evaluate(tree: Channel, published: dict[str, Channel]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    lines: list[str] = []
    declared = {(lag.property_id, lag.channel): lag for lag in LAG}
    seen: set[tuple[str, str]] = set()

    for prop in PROPERTIES:
        # -- tree arm: EVERY subject must be present and match, or the property
        # is not scored at all. One reverted subject makes the published verdict
        # for the others unreadable, so this is loud rather than partial.
        stale = []
        for subject in prop.subjects:
            tree_path = ARTEFACTS[subject.artefact]["tree"]
            tree_text = tree.text(tree_path)
            if tree_text is None:
                stale.append(f"{tree_path} is not in this checkout")
            elif not subject.probe.search(tree_text):
                stale.append(f"/{subject.probe.pattern}/ no longer matches {tree_path}")
        if stale:
            findings.append(Finding(
                "PROBE-STALE",
                f"{prop.id}: {'; '.join(stale)}. Either {prop.ticket}'s fix was "
                f"reverted in that file, or the code moved and this probe now "
                f"measures nothing. Re-ground the probe before trusting any "
                f"published verdict below.",
            ))
            lines.append(f"  {prop.id:32} tree=ABSENT in {len(stale)}/{len(prop.subjects)} "
                         f"subject(s)  (probe stale — published arms not scored)")
            continue

        for channel_name in prop.channels:
            # A channel that was not fetched is not scored here (RFX-360). The
            # earlier code indexed `published[channel_name]` unconditionally, so
            # `--channel github` — the documented way to skip an unreadable
            # index — died with a KeyError and exited 1, the code that means
            # "a fix is missing".
            channel = published.get(channel_name)
            if channel is None:
                continue
            scored = subjects_on(prop, channel_name)
            if not scored:
                continue
            key = (prop.id, channel_name)
            lag = declared.get(key)

            lagging: list[str] = []
            for subject, path in scored:
                pub_text = channel.text(path)
                if pub_text is None:
                    lagging.append(f"{path} (NO-SUCH-FILE)")
                elif not subject.probe.search(pub_text):
                    lagging.append(path)
            delivered = not lagging
            got = f"{len(scored) - len(lagging)}/{len(scored)}"

            if delivered and lag is not None:
                seen.add(key)
                findings.append(Finding(
                    "STALE-DECLARATION",
                    f"{prop.id} on {channel_name}: the published artefact now HAS "
                    f"this fix in all {len(scored)} subject(s), but LAG still "
                    f"declares it missing ({lag.ticket}, declared {lag.declared}). "
                    f"Delete that row — a declaration left in place after its gap "
                    f"closes stops reporting the next one.",
                ))
                lines.append(f"  {prop.id:32} {channel_name:7} delivered {got}  <- STALE LAG ROW")
            elif not delivered and lag is None:
                findings.append(Finding(
                    "UNDECLARED-GAP",
                    f"{prop.id} on {channel_name}: {prop.what} — merged here "
                    f"({prop.ticket}) and absent from {len(lagging)} of "
                    f"{len(scored)} published subject(s) ({channel.version}): "
                    f"{', '.join(lagging)}. A customer installing today does not "
                    f"have it. Either publish, or declare it in LAG with the "
                    f"ticket that closes it.",
                ))
                lines.append(f"  {prop.id:32} {channel_name:7} GAP {got}  <- UNDECLARED")
            elif not delivered:
                seen.add(key)
                lines.append(f"  {prop.id:32} {channel_name:7} GAP {got}  "
                             f"(declared: {lag.ticket}; lagging: {', '.join(lagging)})")
            else:
                lines.append(f"  {prop.id:32} {channel_name:7} delivered {got}")

    for key, lag in declared.items():
        if key in seen:
            continue
        if key[1] not in published:
            # Its channel was not fetched, so nothing scored it this run. Saying
            # "no property scores this row" here would report every npm row as an
            # orphan under `--channel github` (RFX-360).
            continue
        findings.append(Finding(
            "ORPHAN-DECLARATION",
            f"LAG declares {key[0]} on {key[1]} ({lag.ticket}) but no property "
            f"by that name is scored on that channel. A row nothing scores is a "
            f"row nothing rechecks — remove it or fix the id.",
        ))

    return findings, lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--channel", choices=["npm", "github", "all"], default="all",
                    help="limit the published arms that are fetched (default: all)")
    args = ap.parse_args()

    tree = load_tree()
    wanted = ["npm", "github"] if args.channel == "all" else [args.channel]
    published: dict[str, Channel] = {}
    loaders = {"npm": load_npm, "github": load_github}
    for name in wanted:
        try:
            published[name] = loaders[name]()
        except ChannelUnavailable as exc:
            print(f"UNAVAILABLE: could not read the {name} channel — {exc}")
            print("No verdict. An index that cannot be read is not a fix that is "
                  "missing and not a fix that is present.")
            return 3

    print(f"published connector check — {PKG}")
    for name in wanted:
        print(f"  {name}: {published[name].version}")
    print()

    scored = [p for p in PROPERTIES if any(c in published for c in p.channels)]
    probes = sum(len(subjects_on(p, c)) for p in scored for c in p.channels
                 if c in published)
    print(f"scoring {len(scored)} properties as {probes} (subject, channel) probes "
          f"on {'+'.join(wanted)}:")
    findings, lines = evaluate(tree, published)
    for line in lines:
        print(line)
    print()

    if not findings:
        # The scope belongs in the verdict line, not only in this docstring. The
        # previous wording was "every gap between this tree and the published
        # connector is declared" — a claim about the whole diff, from a run that
        # scored five regexes (RFX-359). 17 of the 34 files the tree and the
        # publish repo have in common differed on 2026-09-18; this check reads
        # the ones named above and no others.
        print(f"PASS — of the {probes} (subject, channel) probe(s) named above, "
              f"every gap is declared in LAG ({len(LAG)} rows) and no declared "
              f"row has gone stale.")
        # Count the artefacts actually READ on the channels fetched, not every
        # artefact the properties name: `examples/` is absent from the npm
        # tarball, so a `--channel npm` run that claimed six artefacts would be
        # overclaiming in the same sentence that exists to state its scope.
        artefacts_read = {s.artefact for p in scored for c in p.channels
                          if c in published for s, _ in subjects_on(p, c)}
        print(f"       Scope: {len(scored)} propert(ies) over "
              f"{len(artefacts_read)} artefact(s) "
              f"on {'+'.join(wanted)}. A difference in a file no Property names "
              f"is NOT scored here, and {len(UNSCORED_WORKFLOWS)} workflow(s) are "
              f"excluded by name in UNSCORED_WORKFLOWS.")
        return 0

    print(f"FAIL — {len(findings)} finding(s):")
    for f in findings:
        print(f"\n  [{f.kind}] {f.text}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
