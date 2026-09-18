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
    "demo3-workflow": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo3-the-approval-loop.workflow.json",
        "github": "examples/n8n/demo3-the-approval-loop.workflow.json",
    },
    "demo3-readme": {
        "tree": "n8n-nodes-reeflex/examples/n8n/demo3-README.md",
        "github": "examples/n8n/demo3-README.md",
    },
}


@dataclass(frozen=True)
class Property:
    """One behaviour a merged commit established, and how to see it in bytes.

    `probe` is deliberately a regex over the artefact text rather than a parse:
    it has to answer the same question about TypeScript source and about the
    JavaScript `tsc` emits from it, and the emitted default strings are
    byte-identical to the source ones.
    """

    id: str
    ticket: str
    artefact: str
    channels: tuple[str, ...]
    probe: re.Pattern[str]
    what: str


PROPERTIES: list[Property] = [
    Property(
        id="agent-id-per-execution",
        ticket="RFX-138",
        artefact="node",
        channels=("npm", "github"),
        # The fix replaced the bare constant 'agent:n8n' with a per-execution
        # value. Core binds a human approval to the actor by comparing agent.id
        # against the held envelope, so a constant shared by every execution
        # makes that comparison vacuous.
        probe=re.compile(r"agent:n8n/\{\{\$execution\.id\}\}"),
        what="agent.id default is per-execution, not a constant every workflow shares",
    ),
    Property(
        id="session-id-per-workflow",
        ticket="RFX-180..184",
        artefact="node",
        channels=("npm", "github"),
        # Cumulative budgets accumulate per agent.session_id. An
        # execution-scoped session id resets them on every run, so a trigger
        # firing once per item never accumulates.
        probe=re.compile(r"default:\s*'=\{\{\$workflow\.id\}\}'"),
        what="session id default is workflow-scoped, so budgets survive across runs",
    ),
    Property(
        id="money-verb-needs-amount",
        ticket="RFX-180..184",
        artefact="node",
        channels=("npm", "github"),
        # Without amount/currency a `transact` is budgeted by count budgets
        # alone, which cannot tell a 1-euro refund from a large payout.
        probe=re.compile(r"MONEY_VERBS"),
        what="a transact with no declared amount is refused here rather than sent",
    ),
    Property(
        id="demo3-node-marked-demo-only",
        ticket="RFX-182",
        artefact="demo3-workflow",
        channels=("github",),
        # The node POSTs /v1/holds/{id}/resolve with the same credential the
        # acting agent uses, so the loop completes with no human. The name is
        # what an importer reads on the canvas.
        probe=re.compile(r"DEMO ONLY, NO HUMAN"),
        what="the self-resolving node says on the canvas that no human is in it",
    ),
    Property(
        id="demo3-readme-warns",
        ticket="RFX-182",
        artefact="demo3-readme",
        channels=("github",),
        probe=re.compile(r"There is no human in this workflow"),
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
# published bytes that day, not inferred from the tree. All five close on the
# same event — a republish of the connector from a tree that carries these
# commits — but they are listed per (property, channel) rather than as one
# blanket waiver, so that a partial republish reports the rows it left behind.
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


def evaluate(tree: Channel, published: dict[str, Channel]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    lines: list[str] = []
    declared = {(lag.property_id, lag.channel): lag for lag in LAG}
    seen: set[tuple[str, str]] = set()

    for prop in PROPERTIES:
        paths = ARTEFACTS[prop.artefact]
        tree_text = tree.text(paths["tree"])
        if tree_text is None:
            findings.append(Finding(
                "PROBE-STALE",
                f"{prop.id}: {paths['tree']} is not in this checkout — the probe "
                f"has no subject to measure",
            ))
            lines.append(f"  {prop.id:32} tree=MISSING-FILE  (probe stale)")
            continue
        if not prop.probe.search(tree_text):
            findings.append(Finding(
                "PROBE-STALE",
                f"{prop.id}: /{prop.probe.pattern}/ no longer matches "
                f"{paths['tree']}. Either {prop.ticket}'s fix was reverted, or "
                f"the code moved and this probe now measures nothing. Re-ground "
                f"the probe before trusting any published verdict below.",
            ))
            lines.append(f"  {prop.id:32} tree=ABSENT  (probe stale — published arms not scored)")
            continue

        for channel_name in prop.channels:
            channel = published[channel_name]
            path = paths.get(channel_name)
            if path is None:
                continue
            pub_text = channel.text(path)
            key = (prop.id, channel_name)
            lag = declared.get(key)
            if pub_text is None:
                state = "NO-SUCH-FILE"
                delivered = False
            else:
                delivered = bool(prop.probe.search(pub_text))
                state = "delivered" if delivered else "GAP"

            if delivered and lag is not None:
                seen.add(key)
                findings.append(Finding(
                    "STALE-DECLARATION",
                    f"{prop.id} on {channel_name}: the published artefact now HAS "
                    f"this fix, but LAG still declares it missing ({lag.ticket}, "
                    f"declared {lag.declared}). Delete that row — a declaration "
                    f"left in place after its gap closes stops reporting the next one.",
                ))
                lines.append(f"  {prop.id:32} {channel_name:7} delivered  <- STALE LAG ROW")
            elif not delivered and lag is None:
                findings.append(Finding(
                    "UNDECLARED-GAP",
                    f"{prop.id} on {channel_name}: {prop.what} — merged here "
                    f"({prop.ticket}) and absent from the published artefact "
                    f"({channel.version}). A customer installing today does not "
                    f"have it. Either publish, or declare it in LAG with the "
                    f"ticket that closes it.",
                ))
                lines.append(f"  {prop.id:32} {channel_name:7} {state}  <- UNDECLARED")
            elif not delivered:
                seen.add(key)
                lines.append(f"  {prop.id:32} {channel_name:7} {state}  (declared: {lag.ticket})")
            else:
                lines.append(f"  {prop.id:32} {channel_name:7} delivered")

    for key, lag in declared.items():
        if key in seen:
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
    print(f"scoring {len(scored)} properties x published channels:")
    findings, lines = evaluate(tree, published)
    for line in lines:
        print(line)
    print()

    if not findings:
        print(f"PASS — every gap between this tree and the published connector is "
              f"declared in LAG ({len(LAG)} rows), and no declared row has gone stale.")
        return 0

    print(f"FAIL — {len(findings)} finding(s):")
    for f in findings:
        print(f"\n  [{f.kind}] {f.text}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
