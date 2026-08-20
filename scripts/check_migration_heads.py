#!/usr/bin/env python3
"""check_migration_heads.py — static analysis of an Alembic migration graph.

WHY THIS EXISTS (RFX-49): on 2026-08-20 two independently-green PRs each
branched from `main` before the other landed and each declared the SAME
`down_revision` as their parent. Neither PR was wrong on its own — CI on
each PR was green — but the merged `main` had two alembic heads, and
`alembic upgrade head` refuses to even PLAN:

    ERROR [alembic.util.messaging] Multiple head revisions are present

The deployed container went into a restart loop. This script catches that
CLASS before merge: it parses `revision` / `down_revision` out of every
migration file with `ast` (no import of alembic, no database, no execution
of the files themselves) and fails if the resulting graph has anything
other than exactly one head. It also warns — non-fatally — on two files
sharing the same leading numeric prefix (e.g. two `0010_*` files): that
collision is what made the RFX-49 duplication easy to miss in review.

USAGE
  python check_migration_heads.py <versions-dir> [<versions-dir> ...]

  Multiple directories are merged into one graph (useful when a checker
  needs to validate more than one migrations root at once).

VERDICT — anchored, case-sensitive; parse EXACTLY this line:
  MIGRATION-HEADS: PASS (...)   exit 0 — exactly one head, graph fully resolves
  MIGRATION-HEADS: FAIL (...)   exit 1 — zero/multiple heads, or an unparsable
                                 or broken (dangling-parent) graph
"""

from __future__ import annotations

import ast
import os
import re
import sys

VERSION_FILE_SKIP = {"__init__.py", "env.py"}
PREFIX_RE = re.compile(r"^(\d+)_")


class MigrationInfo:
    def __init__(self, path, revision, down_revisions):
        self.path = path
        self.revision = revision
        self.down_revisions = down_revisions  # tuple[str, ...]; () means root


def _literal_value(node):
    """Evaluate a literal RHS (string / tuple / list / None) without
    executing anything else in the file. Anything else is a parse error."""
    return ast.literal_eval(node)


def parse_migration_file(path):
    """Return (MigrationInfo, None) or (None, error-string). Pure static
    analysis: the file is parsed, never imported or executed."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return None, "SyntaxError: %s" % exc

    revision = None
    down_revision_raw = "__NOT_ASSIGNED__"
    for node in tree.body:
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        if not targets or value is None:
            continue
        if "revision" in targets:
            try:
                revision = _literal_value(value)
            except (ValueError, SyntaxError):
                return None, "`revision` is not a literal"
        if "down_revision" in targets:
            try:
                down_revision_raw = _literal_value(value)
            except (ValueError, SyntaxError):
                return None, "`down_revision` is not a literal"

    if revision is None:
        return None, "no `revision` assignment found"
    if not isinstance(revision, str):
        return None, "`revision` is not a string: %r" % (revision,)

    if down_revision_raw == "__NOT_ASSIGNED__" or down_revision_raw is None:
        down_revisions = ()
    elif isinstance(down_revision_raw, str):
        down_revisions = (down_revision_raw,)
    elif isinstance(down_revision_raw, (tuple, list)):
        if not all(isinstance(x, str) for x in down_revision_raw):
            return None, "`down_revision` tuple/list has a non-string element: %r" % (down_revision_raw,)
        down_revisions = tuple(down_revision_raw)
    else:
        return None, "`down_revision` is not str/tuple/list/None: %r" % (down_revision_raw,)

    return MigrationInfo(path, revision, down_revisions), None


def load_migrations(dirs):
    """Parse every migration file under `dirs`. Returns (migrations, errors)
    where migrations maps revision-id -> MigrationInfo."""
    migrations = {}
    errors = []
    for d in dirs:
        if not os.path.isdir(d):
            errors.append("directory not found: %s" % d)
            continue
        for fname in sorted(os.listdir(d)):
            if not fname.endswith(".py") or fname in VERSION_FILE_SKIP or fname.startswith("_"):
                continue
            path = os.path.join(d, fname)
            info, err = parse_migration_file(path)
            if err:
                errors.append("%s: %s" % (path, err))
                continue
            if info.revision in migrations:
                errors.append(
                    "duplicate revision id %r declared by both %s and %s"
                    % (info.revision, migrations[info.revision].path, path)
                )
                continue
            migrations[info.revision] = info
    return migrations, errors


def compute_heads(migrations):
    """A head is a revision that no other migration names as a parent.
    Returns (heads: sorted list[str], dangling: list[(child, missing_parent)])."""
    parents = set()
    dangling = []
    for info in migrations.values():
        for p in info.down_revisions:
            parents.add(p)
            if p not in migrations:
                dangling.append((info.revision, p))
    heads = sorted(r for r in migrations if r not in parents)
    return heads, dangling


def find_duplicate_prefixes(migrations):
    """Group revisions by leading numeric filename prefix; return only
    prefixes claimed by more than one distinct revision (warning class)."""
    by_prefix = {}
    for info in migrations.values():
        m = PREFIX_RE.match(os.path.basename(info.path))
        if not m:
            continue
        by_prefix.setdefault(m.group(1), set()).add(info.revision)
    return {p: sorted(revs) for p, revs in by_prefix.items() if len(revs) > 1}


def check(dirs):
    """Run the full static check over `dirs`. Returns (ok: bool, lines: list[str])."""
    lines = []
    migrations, errors = load_migrations(dirs)
    lines.append(
        "MIGRATION-HEADS: scanning %s (%d revision(s) parsed)" % (", ".join(dirs), len(migrations))
    )
    for e in errors:
        lines.append("MIGRATION-HEADS: ERROR %s" % e)

    heads, dangling = compute_heads(migrations)
    for child, missing in dangling:
        lines.append(
            "MIGRATION-HEADS: ERROR %s declares down_revision %r, which does not exist"
            % (child, missing)
        )
    for h in sorted(heads):
        lines.append("MIGRATION-HEADS: head = %s (%s)" % (h, migrations[h].path))

    for prefix, revs in sorted(find_duplicate_prefixes(migrations).items()):
        lines.append(
            "MIGRATION-HEADS: WARN duplicate numeric prefix %s used by: %s"
            % (prefix, ", ".join(revs))
        )

    ok = not errors and not dangling and len(heads) == 1
    if ok:
        lines.append("MIGRATION-HEADS: PASS (1 head: %s)" % heads[0])
    elif errors or dangling:
        lines.append("MIGRATION-HEADS: FAIL (unparsable or broken migration graph)")
    else:
        lines.append(
            "MIGRATION-HEADS: FAIL (%d heads — `alembic upgrade head` would refuse to plan)"
            % len(heads)
        )
    return ok, lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    dirs = argv or ["migrations/versions"]
    ok, lines = check(dirs)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
