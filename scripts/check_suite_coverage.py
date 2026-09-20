#!/usr/bin/env python3
"""check_suite_coverage.py — every check artefact in this tree is invoked by
something, or says in writing why it is not (RFX-355).

WHY THIS EXISTS, AND WHY `drift` IS NOT ENOUGH.

`gate.py`'s `drift` component says of itself: "The drift check fails the gate if
a test-looking file exists OUTSIDE these roots (a suite nobody wired in)", and
`check_test_census.py`'s header leans on that sentence. Measured on caf2cd6,
`drift` cannot make that claim, for two independent reasons:

  1. It walks TEST_FILE_PATTERNS — five spellings: test_*.py, *_test.py,
     *_test.rego, *.test.ts, *.test.js. Not *.php. Not attack-probe-*.py,
     repro-*.py, audit-*.py, bite-check-*.py, which are the naming conventions
     this repo uses for its own verdict-producing probes.

  2. Its premise — "inside a suite root means some component runs it" — holds
     only for roots run by DIRECTORY DISCOVERY. It is false for
     reeflex-wordpress/tests, whose two components run hardcoded literal lists
     (Gate.WP_HARNESSES, Gate.WP_SPEC_HARNESSES). A new .php there is inside a
     root, so drift is satisfied by construction, and is in neither literal, so
     nothing invokes it.

Three arms against the shipped tree, each asserted to have landed by sha256:
a stray attack-probe-*.py in scripts/, a stray .php in scripts/, and a stray
.php dropped straight into reeflex-wordpress/tests/ all left drift printing a
line byte-identical to the clean-tree baseline, walked count and all:

    COMPONENT drift: PASS (118 test file(s) walked, none outside the 10
                           enumerated suite roots)

The control — a stray test_*.py, which the pattern list does match — turned it
RED, so the three greens are the guard's blindness and not a dead instrument:

    COMPONENT drift: FAIL (1 test file(s) outside the enumerated suite roots)

Measured twice, by two rounds, each importing gate.py from its own worktree and
asserting REPO_ROOT before believing a line.

THE HISTORY THIS CLOSES. WP_HARNESSES has been hand-appended three separate
times, each time after someone found a harness no automation invoked: RFX-27
(three at once, one of them fatally broken for an unknown period), RFX-219 (the
fifth), RFX-167 (the sixth). `run_corpus_live`'s docstring records the same
class on the probe side: "It existed, it worked, and it was invoked by NOTHING
... Two divergences had accumulated in the gap." One repo over, reeflex-app's
CI path globs were hand-appended three times for the same reason (RFX-354).

SO THIS DOES NOT APPEND A SIXTH PATTERN. Appending is the mechanism that has
been wrong six times across two repos, and it would not close the WordPress arm
at all — that file is INSIDE a root. This enumerates from the AUTHORITY SIDE
(the directory) and requires every artefact to be dispositioned:

  wired       — named, and the invoker that names it is named back. If the
                declared invoker stops containing the basename, that FAILS:
                this is how a suite silently stops being run.
  unwired     — a CHECK that nothing invokes. Allowed, with a reason in
                writing. If the basename LATER turns up in an invoker, that
                FAILS too, as a stale declaration.
  not-a-check — product source, a fixture or data. Exempt from the invoker
                cross-check, because "is it invoked" is not a meaningful
                question about it: wporg-deploy.yml names reeflex-gate.php
                because it DEPLOYS the plugin, which says nothing about any
                check. Still declared, so a new .php cannot appear silently.

That third disposition is here because the first draft of this file did not
have it and called reeflex-gate.php a stale declaration — a checker that cries
wolf on shipped product source is one people start passing --allow-skips to.

Both directions are measured, because a residual list that can silence a real
red without ever going red itself is worth less than no list (RFX-339/RFX-348).
A file on disk with no entry FAILS. An entry with no file on disk FAILS.

The literal lists are IMPORTED from gate.py, never transcribed — a transcription
drifts, and that is RFX-303's lesson, learned on the policy oracle.

TWO WAYS A DECLARATION COULD HAVE BEEN TRUE AND WORTHLESS, both closed here:

  * A WORKFLOW FILE GITHUB NEVER REGISTERS. Only files directly inside the
    repository-root `.github/workflows/` are registered; `subdir/.github/
    workflows/ci.yml` and `.github/workflows/archive/old.yml` are ordinary
    files that never fire. This tree HAS two of the first kind
    (`n8n-nodes-reeflex/.github/workflows/`), so "wired into a workflow" is
    checked against the registrable location, not against any file whose path
    happens to contain `workflows`. Measured against the Actions API on
    2026-09-18: the seven root workflow files are exactly the seven registered
    and active workflows; the two nested ones appear nowhere in it.
  * PROSE ABOUT A CHECK, instead of a call to it. `# we should run check-foo.py
    one day`, or a module docstring describing the component, satisfies a plain
    substring test forever. A Python invoker is now read as the string literals
    it EXECUTES — docstrings and comments excluded (`ast`, no import, no
    execution); YAML invokers are read with whole-line comments stripped.
    This was NOT theoretical: the arm that renamed gate.py's real invocation of
    check_test_census.py left the whole-text version of this check GREEN,
    because gate.py's docstring still described the component. That arm is now
    RED, and it is the shape of the failure this file exists for. Verified not
    to move any declaration in this tree: all ten wired entries still hold when
    only executed literals count.

WHAT THIS DOES NOT MEASURE, said plainly:
  * Whether an invoked file ASSERTS anything. That is check_test_census.py's
    job, and it covers the Python roots only — there is no equivalent for the
    PHP harnesses, so a wp harness that has gone inert is not visible to either
    of us.
  * "Named by an invoker" is still textual. A basename in a trailing comment,
    an unreachable code path or a string that is built up by concatenation is
    beyond it — the first two count as wired, the third does not. This measures
    "nothing at all names it", the failure this repo has actually had six
    times; it does not measure "it runs".
  * Registrability is structural (path shape). It does not ask the Actions API
    whether a registered workflow is disabled, and it cannot: the gate must run
    with no network and no token.
  * The npm and rego planes are enumerated as files, but whether THEIR runners
    are discovery-based was not measured here.

USAGE
    python scripts/check_suite_coverage.py [REPO_ROOT]   # verdict on the tree
    python scripts/check_suite_coverage.py --selftest    # prove the detectors

Anchored verdict line, case-sensitive, like the other checkers:
    SUITE-COVERAGE: PASS (...)   exit 0
    SUITE-COVERAGE: FAIL (...)   exit 1
"""

import argparse
import ast
import os
import shutil
import sys
import tempfile

REPO_ROOT_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------------------
# The declared residual. Every top-level file in scripts/ and every .php in the
# tree is one of these, or this check fails.
#
# `wired`   -> the repo-relative path of the file that must NAME it.
# `unwired` -> a reason, in writing.
# --------------------------------------------------------------------------

WIRED = {
    # scripts/ — invoked by the gate or by a registered workflow
    "attack-probe-rfx144-agent-prices-own-action.py": "gate.py",
    "build-wp-zips.py": ".github/workflows/release.yml",
    # RFX-309/RFX-89 (#197), landed under this branch. Named in five files;
    # only core-deployment.yml names it in an executed `run:` block (104, 108).
    # buildinfo.py and server.py name it inside a comment and a docstring, and
    # the Python reader below counts neither.
    "check_core_deployment.py": ".github/workflows/core-deployment.yml",
    "check_dependency_floors.py": ".github/workflows/gate.yml",
    "check_diagram_contrast.py": ".github/workflows/docs.yml",
    "check_migration_heads.py": "gate.py",
    "check_published_classifier.py": "gate.py",
    "check_published_connector.py": ".github/workflows/smoke-npm.yml",
    "check_published_content.py": "gate.py",
    "check_suite_coverage.py": "gate.py",
    "check_test_census.py": "gate.py",
    # RFX-134 (#200), landed under this branch. Three files in the tree name
    # this script; only gate.yml does so in an executed `run:` block (lines
    # 111 and 113). ci.yml and ci-reeflex-mcp.yml name it in a COMMENT
    # pointing readers at the guard, and the reader below excludes comments —
    # so this is the sole invoker, not merely the first one found.
    "check_workflow_concurrency.py": ".github/workflows/gate.yml",
    "probe_diagrams.py": ".github/workflows/docs.yml",
    "verify_release_artifacts.py": ".github/workflows/release.yml",
}

UNWIRED = {
    # scripts/ — probes and reproductions kept for the record, run by hand.
    # Each one is a verdict-producing script that NOTHING invokes today; that is
    # allowed, and it is written down here so that adding a new one is a
    # decision somebody makes rather than a file that quietly runs nowhere.
    "attack-probe-envelope-boundary.py":
        "attack suite: replays boundary envelopes at a core. Never against the "
        "live instance (fleet rule), so it has no unattended home yet.",
    "attack-probe-r5-fragmented.py":
        "attack suite: fabricates fragmented R5 spend. Same reason.",
    "attack-probe-rfx-core-2.py":
        "attack suite: run by hand against a scratch core on a spare port.",
    "attack-probe-rfx143-undeclared-count.py":
        "attack suite: run by hand; needs a live core it may write forged "
        "attempts into.",
    "attack-probe-rfx153-protected-asset.py":
        "attack suite: run by hand; needs a live core.",
    "attack-probe-rfx214-unknown-tool-externality.py":
        "attack suite: run by hand; needs a live core.",
    "attack-probe-rfx97-release-gate.py":
        "attack suite: mints release approvals; must never run unattended "
        "(RFX-97's own finding was that the probe could mint what a real "
        "caller cannot).",
    "audit-grid-canon.py":
        "reporting tool: prints the canon grid for a human reading a report. "
        "No verdict, nothing to gate on.",
    "audit-probe-canon.py":
        "reporting tool: same, for the probe canon.",
    "bite-check-rfx211-rfx218.py":
        "one-shot: proved RFX-211/RFX-218 bite at the time. Kept as the record "
        "of that measurement, not as a standing check.",
    "export-claude-conformance.py":
        "generator: writes the conformance corpus export. Its OUTPUT is what "
        "gets gated, not this script.",
    "repro-rfx131-blast-radius.php":
        "one-shot reproduction for RFX-131, kept next to its .py twin. The "
        "standing check is reeflex-wordpress/tests/conformance-blast-radius.php.",
    "repro-rfx131-blast-radius.py":
        "one-shot reproduction for RFX-131.",
    "repro-rfx138-adapter-actor-identity.py":
        "one-shot reproduction for RFX-138.",
    "repro-rfx138-pr-comparison.py":
        "one-shot A/B for RFX-138's two arms.",
    "repro-rfx211-rfx218-holds-vocabulary.py":
        "one-shot reproduction for RFX-211/RFX-218.",
}

# Not a check at all: product source, fixtures, data. Exempt from the invoker
# cross-check — an invoker may legitimately name these for reasons that have
# nothing to do with running a check.
NOT_A_CHECK = {
    "diagram_probe_baseline.json":
        "data, not a script: the baseline probe_diagrams.py reads. docs.yml "
        "names it so a change to it rebuilds the site.",
    "reeflex-wordpress/reeflex-gate.php":
        "product: the WordPress plugin entry point. wporg-deploy.yml names it "
        "because it DEPLOYS the plugin and asserts its Version: header.",
    "reeflex-wordpress/uninstall.php":
        "product: WordPress uninstall hook, shipped in trunk/ by "
        "wporg-deploy.yml.",
    "reeflex-verify/wordpress-test-plugin/reeflex-test-abilities/"
    "reeflex-test-abilities.php":
        "fixture: a throwaway WP plugin reeflex-verify.py installs into a "
        "scratch WordPress to give it abilities to gate. Driven by that tool, "
        "never standalone.",
}

# Every .php under reeflex-wordpress/reeflex-gate/ is shipped plugin source.
PLUGIN_SOURCE_PREFIX = os.path.join("reeflex-wordpress", "reeflex-gate")

WP_TESTS_DIR = os.path.join("reeflex-wordpress", "tests")

# Non-harness files that legitimately live in the WordPress harness directory.
WP_SUPPORT = {
    "wp-stubs.php": "shared stub layer every harness includes; not a harness "
                    "itself and has no verdict of its own.",
}

# Where an invoker may live. A basename found in any of these counts as named.
# `.github/workflows` is read NON-recursively on purpose — see REGISTRABLE
# below; a file one directory deeper is not a workflow, it is a file.
INVOKER_PATHS = ["gate.py", ".github/workflows", "bin", "Makefile"]

# GitHub registers a workflow only when the file sits DIRECTLY in the
# repository-root .github/workflows/ and ends .yml/.yaml. Anything else named
# as an invoker is a file that never fires, and a declaration pointing at one
# is a declaration that cannot go red.
WORKFLOW_DIR = os.path.join(".github", "workflows")
WORKFLOW_SUFFIXES = (".yml", ".yaml")

EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "dist-test",
    "build", "site", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist-artifacts", "pypi-dist",
}


def load_wp_literals(repo_root):
    """Import gate.py's harness lists rather than transcribing them (RFX-303).

    Returns (harnesses, spec_harnesses, source) where source says how they were
    obtained, so a reader of the output knows whether the import worked.
    """
    gate_py = os.path.join(repo_root, "gate.py")
    if not os.path.exists(gate_py):
        return set(), set(), "no gate.py at %s" % repo_root
    import importlib.util
    spec = importlib.util.spec_from_file_location("_gate_for_coverage", gate_py)
    mod = importlib.util.module_from_spec(spec)
    saved = sys.path[:]
    sys.path.insert(0, repo_root)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:                                  # pragma: no cover
        return set(), set(), "gate.py did not import: %s" % exc
    finally:
        sys.path[:] = saved
    g = getattr(mod, "Gate", None)
    if g is None:
        return set(), set(), "gate.py has no Gate class"
    harnesses = set(getattr(g, "WP_HARNESSES", []))
    spec_h = set(name for name, _what in getattr(g, "WP_SPEC_HARNESSES", []))
    return harnesses, spec_h, "imported from gate.py"


def walk_files(repo_root, rel_dir=None, suffixes=None, top_level_only=False):
    base = os.path.join(repo_root, rel_dir) if rel_dir else repo_root
    found = []
    if not os.path.isdir(base):
        return found
    for dirpath, dirnames, filenames in os.walk(base):
        # Dot-directories are scratch, tooling caches and evidence dirs — never
        # part of the shipped layout, and a checkout in CI has none of them. A
        # gate that reddens on somebody's local `.evidence-dev2-015/` is a gate
        # people start passing --allow-skips to.
        dirnames[:] = [d for d in dirnames
                       if d not in EXCLUDE_DIRS and not d.startswith(".")]
        if top_level_only:
            dirnames[:] = []
        for f in filenames:
            if suffixes and not any(f.endswith(s) for s in suffixes):
                continue
            found.append(os.path.relpath(os.path.join(dirpath, f), repo_root))
    return sorted(found)


def strip_comments(text):
    """Drop whole-line comments before asking whether a file NAMES a check.

    `# one day we should run scripts/check-foo.py` satisfies a substring test
    for as long as nobody deletes the comment. Used for YAML invokers; for
    Python, code_text_py below is stricter still.
    """
    return "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith("#"))


def code_text_py(source):
    """The string literals a Python invoker EXECUTES, docstrings excluded.

    A script is invoked by its name, and a name in Python is a string literal:
    `os.path.join(REPO_ROOT, "scripts", "check_test_census.py")`. Prose about a
    script is a docstring or a comment, and neither runs anything.

    This is not pedantry. The arm that renamed gate.py's ACTUAL invocation of
    check_test_census.py — the exact shape of a suite silently ceasing to be
    run, which is the RFX-27/RFX-219/RFX-167 history — left this check GREEN
    while it read whole-file text, because gate.py's module docstring still
    described the component. The break was real and the detector was reading
    prose.

    A file that does not parse falls back to the coarser comment-stripped
    reading rather than vanishing: an invoker that cannot be read must not
    quietly become an invoker that names nothing.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return strip_comments(source)
    docstrings = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)) and body:
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    return "\n".join(
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and id(n) not in docstrings)


def registrable(rel_path):
    """Is this path a workflow file GitHub would actually register?

    True only for a direct child of the repo-root .github/workflows/ ending
    .yml/.yaml. `n8n-nodes-reeflex/.github/workflows/ci.yml` is False, and so
    is `.github/workflows/archive/old.yml`.
    """
    rel = os.path.normpath(rel_path)
    return (os.path.dirname(rel) == WORKFLOW_DIR
            and rel.endswith(WORKFLOW_SUFFIXES))


def invoker_text(repo_root):
    """Text of everything that may invoke a check, comments stripped.

    Workflow files are read NON-recursively: only registrable ones are read at
    all, so a declaration can never be satisfied by a file that never fires.
    """
    chunks = {}

    def read(rel):
        try:
            with open(os.path.join(repo_root, rel), encoding="utf-8",
                      errors="replace") as f:
                text = f.read()
        except OSError:
            return
        chunks[rel] = code_text_py(text) if rel.endswith(".py") \
            else strip_comments(text)

    for rel in INVOKER_PATHS:
        p = os.path.join(repo_root, rel)
        if os.path.isfile(p):
            read(rel)
        elif os.path.isdir(p):
            if os.path.normpath(rel) == WORKFLOW_DIR:
                for f in sorted(os.listdir(p)):
                    candidate = os.path.join(rel, f)
                    if os.path.isfile(os.path.join(repo_root, candidate)) \
                            and registrable(candidate):
                        read(candidate)
                continue
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
                for f in filenames:
                    read(os.path.relpath(os.path.join(dirpath, f), repo_root))
    return chunks


def check(repo_root):
    """Returns (failures, notes, counts)."""
    failures, notes = [], []
    chunks = invoker_text(repo_root)
    all_text = "\n".join(chunks.values())

    # ---- plane 1: the WordPress harness directory, derived from the tree ----
    harnesses, spec_h, how = load_wp_literals(repo_root)
    notes.append("wp harness literals: %s (%d + %d)"
                 % (how, len(harnesses), len(spec_h)))
    if how.startswith("gate.py did not import") or how.startswith("no gate.py"):
        failures.append("cannot read gate.py's harness literals (%s) — this "
                        "check refuses to certify a plane it did not read" % how)
    wp_on_disk = {os.path.basename(p)
                  for p in walk_files(repo_root, WP_TESTS_DIR, [".php"],
                                      top_level_only=True)}
    accounted = harnesses | spec_h | set(WP_SUPPORT)
    for name in sorted(wp_on_disk - accounted):
        failures.append(
            "%s/%s is in a suite root but in NO component's harness list — "
            "drift is satisfied by its location and nothing invokes it; add it "
            "to Gate.WP_HARNESSES / Gate.WP_SPEC_HARNESSES or to WP_SUPPORT "
            "with a reason" % (WP_TESTS_DIR, name))
    for name in sorted(accounted - wp_on_disk):
        failures.append(
            "%s is named as a WordPress harness but no such file exists in %s "
            "— a stale entry, and a component that names a missing harness is "
            "one that stopped running it" % (name, WP_TESTS_DIR))
    wp_count = len(wp_on_disk)

    # ---- plane 2: scripts/, top level, enumerated from the directory --------
    scripts_on_disk = {os.path.basename(p)
                       for p in walk_files(repo_root, "scripts", None,
                                           top_level_only=True)}
    scripts_on_disk = {f for f in scripts_on_disk
                       if not f.startswith(".") and f != "__init__.py"}

    # ---- plane 3: every .php in the tree ------------------------------------
    php_all = walk_files(repo_root, None, [".php"])
    php_other = [p for p in php_all
                 if not p.startswith(WP_TESTS_DIR + os.sep)
                 and not p.startswith(PLUGIN_SOURCE_PREFIX + os.sep)
                 and not p.startswith("scripts" + os.sep)]

    subjects = sorted(scripts_on_disk) + php_other
    for subject in subjects:
        key = subject if (subject in WIRED or subject in UNWIRED
                          or subject in NOT_A_CHECK) else os.path.basename(subject)
        base = os.path.basename(subject)
        if key in NOT_A_CHECK:
            continue
        if key in WIRED:
            invoker = WIRED[key]
            looks_like_workflow = "workflows" in invoker.replace("\\", "/").split("/")
            if looks_like_workflow and not registrable(invoker):
                failures.append(
                    "%s is declared wired into %s, which is not a workflow "
                    "GitHub registers — only a direct child of %s ending .yml/"
                    ".yaml ever fires, so that declaration can never go red"
                    % (subject, invoker, WORKFLOW_DIR))
                continue
            text = "\n".join(v for k, v in chunks.items()
                             if k == invoker or k.startswith(invoker + os.sep))
            if not text:
                failures.append(
                    "%s is declared wired into %s, and no such invoker was read"
                    % (subject, invoker))
            elif base not in text:
                failures.append(
                    "%s is declared wired into %s, and %s does not name it — "
                    "either it stopped being invoked or the declaration is "
                    "wrong; both mean it runs nowhere" % (subject, invoker, invoker))
        elif key in UNWIRED:
            if base in all_text:
                failures.append(
                    "%s is declared UNWIRED with a reason, and something under "
                    "%s now names it — the declaration is stale and is "
                    "silencing a file that is in fact wired"
                    % (subject, "/".join(INVOKER_PATHS)))
        else:
            failures.append(
                "%s is dispositioned by nothing: it is neither declared wired "
                "into an invoker nor declared unwired with a reason. A check "
                "artefact nobody invokes and nobody declared is the RFX-355 "
                "defect" % subject)

    # ---- stale declarations: an entry with no file on disk -------------------
    declared = set(WIRED) | set(UNWIRED) | set(NOT_A_CHECK)
    present = set(scripts_on_disk) | set(php_other) \
        | {os.path.basename(p) for p in php_other}
    for name in sorted(declared - present):
        failures.append(
            "declaration for %s is STALE: no such file in the tree. A residual "
            "list that keeps entries for files that no longer exist can "
            "silence a real one" % name)
    for name in sorted(set(WP_SUPPORT) - wp_on_disk):
        failures.append("WP_SUPPORT declaration for %s is STALE: no such file "
                        "in %s" % (name, WP_TESTS_DIR))

    counts = {"wp_php": wp_count, "scripts": len(scripts_on_disk),
              "php_elsewhere": len(php_other), "declared": len(declared)}
    return failures, notes, counts


def report(repo_root, verbose=True):
    failures, notes, counts = check(repo_root)
    if verbose:
        for n in notes:
            print("  | %s" % n)
        for f in failures:
            print("  | UNCOVERED: %s" % f)
    detail = ("%d wp harness file(s), %d script(s), %d .php elsewhere, "
              "%d declared" % (counts["wp_php"], counts["scripts"],
                               counts["php_elsewhere"], counts["declared"]))
    if failures:
        print("SUITE-COVERAGE: FAIL (%d artefact(s) unaccounted or stale; %s)"
              % (len(failures), detail))
        return 1
    print("SUITE-COVERAGE: PASS (%s — every one dispositioned)" % detail)
    return 0


# --------------------------------------------------------------------------
# selftest — prove every detector on a synthetic tree, before any verdict on
# the real one is trusted. A coverage checker that cannot detect an uncovered
# file reports a clean tree over anything, which is this same defect one layer
# down.
# --------------------------------------------------------------------------

_GATE_STUB = '''
class Gate:
    WP_HARNESSES = ["h-one.php"]
    WP_SPEC_HARNESSES = [("h-spec.php", "SPEC x")]
'''

# How a fixture gate.py INVOKES its check — a statement, not a comment. The
# first version of these fixtures named it in a `#` comment, and every one of
# them went green after comments stopped counting: the control was being held
# up by the very loophole case 8 exists to close.
_INVOKES = '\nRUN = ["python", "scripts/wired-check.py"]\n'


def _fixture(tmp, wp_files, script_files, gate_body=_GATE_STUB, workflow="",
             nested_workflow=None, dot_dir_files=()):
    """Build a synthetic tree.

    `nested_workflow` writes the SAME text to pkg/.github/workflows/ci.yml —
    a path GitHub never registers — so a detector can be shown to distinguish
    the two locations rather than matching on the word "workflows".
    `dot_dir_files` land in a dot-directory, which must be invisible.
    """
    root = tempfile.mkdtemp(dir=tmp)
    os.makedirs(os.path.join(root, WP_TESTS_DIR))
    os.makedirs(os.path.join(root, "scripts"))
    os.makedirs(os.path.join(root, ".github", "workflows"))
    with open(os.path.join(root, "gate.py"), "w") as f:
        f.write(gate_body)
    with open(os.path.join(root, ".github", "workflows", "ci.yml"), "w") as f:
        f.write(workflow)
    if nested_workflow is not None:
        nested = os.path.join(root, "pkg", ".github", "workflows")
        os.makedirs(nested)
        with open(os.path.join(nested, "ci.yml"), "w") as f:
            f.write(nested_workflow)
    for n in dot_dir_files:
        scratch = os.path.join(root, ".scratch")
        os.makedirs(scratch, exist_ok=True)
        open(os.path.join(scratch, n), "w").write("<?php\n")
    for n in wp_files:
        open(os.path.join(root, WP_TESTS_DIR, n), "w").write("<?php\n")
    for n in script_files:
        open(os.path.join(root, "scripts", n), "w").write("#\n")
    return root


def selftest():
    tmp = tempfile.mkdtemp(prefix="suite-coverage-selftest-")
    results = []

    def case(name, root, want_fail, want_substr=None):
        failures, _notes, _counts = check(root)
        got_fail = bool(failures)
        ok = got_fail == want_fail
        if ok and want_substr:
            ok = any(want_substr in f for f in failures)
        results.append((name, ok, failures))
        print("  %-58s %s" % (name, "ok" if ok else "MISDETECTED"))
        if not ok:
            for f in failures:
                print("      got: %s" % f)

    try:
        # The clean fixture. If this is not green, every red below is noise.
        wired = {"h-one.php", "h-spec.php", "wp-stubs.php"}
        saved = (dict(WIRED), dict(UNWIRED), dict(WP_SUPPORT), dict(NOT_A_CHECK))
        WIRED.clear(); UNWIRED.clear(); WP_SUPPORT.clear(); NOT_A_CHECK.clear()
        WP_SUPPORT["wp-stubs.php"] = "stubs"
        WIRED["wired-check.py"] = "gate.py"
        UNWIRED["hand-run-probe.py"] = "run by hand"
        NOT_A_CHECK["product.php"] = "shipped source"
        try:
            clean_scripts = {"wired-check.py", "hand-run-probe.py", "product.php"}
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES)
            case("clean fixture passes", root, False)

            # A not-a-check NAMED by an invoker stays green: that is the whole
            # point of the third disposition, and without this case the
            # exemption could be a no-op nobody would notice.
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES,
                            workflow="run: deploy scripts/product.php\n")
            case("not-a-check named by an invoker stays green", root, False)

            # ...and it is still subject to the stale rule.
            NOT_A_CHECK["gone-product.php"] = "shipped source"
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES)
            case("not-a-check declaration for a missing file", root, True,
                 "is STALE")
            del NOT_A_CHECK["gone-product.php"]

            # 1. the WordPress arm — a harness inside the suite root, in no list
            root = _fixture(tmp, wired | {"conformance-stray.php"},
                            clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES)
            case("wp harness in a root but in no component list", root, True,
                 "in NO component's harness list")

            # 2. a gate.py literal naming a harness that no longer exists
            root = _fixture(tmp, {"h-spec.php", "wp-stubs.php"},
                            clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES)
            case("gate.py names a harness that is gone", root, True,
                 "a stale entry")

            # 3. a script dispositioned by nothing
            root = _fixture(tmp, wired,
                            clean_scripts | {"new-probe.py"},
                            gate_body=_GATE_STUB + _INVOKES)
            case("script dispositioned by nothing", root, True,
                 "dispositioned by nothing")

            # 4. declared wired, invoker stopped naming it
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB)
            case("declared wired, invoker no longer names it", root, True,
                 "does not name it")

            # 5. declared unwired, something now invokes it
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES,
                            workflow="run: python scripts/hand-run-probe.py\n")
            case("declared unwired, an invoker now names it", root, True,
                 "declaration is stale")

            # 6. a declaration whose file is gone
            UNWIRED["deleted-probe.py"] = "was run by hand"
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES)
            case("declaration for a file that no longer exists", root, True,
                 "is STALE")
            del UNWIRED["deleted-probe.py"]

            # 7. the instrument's own floor: gate.py unreadable must not pass
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body="this is not python (\n")
            case("gate.py unreadable is a FAIL, never a quiet pass", root, True,
                 "refuses to certify")

            # 8. named ONLY in a comment is not named. Without this the whole
            #    wired plane can be satisfied by an intention.
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + "\n#   wired-check.py TODO\n")
            case("invoker names it only in a whole-line comment", root, True,
                 "does not name it")

            # 8b. named ONLY in the invoker's DOCSTRING. This is the case that
            #     was green until the real gate.py arm exposed it: renaming the
            #     actual call left the component's prose behind, and prose runs
            #     nothing.
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body='"""Runs scripts/wired-check.py."""\n'
                                      + _GATE_STUB)
            case("invoker names it only in its docstring", root, True,
                 "does not name it")

            # 8c. ...and the control for 8b: the SAME name, in a statement.
            #     Without this pair, a matcher that had stopped reading .py
            #     files at all would pass 8b and look correct.
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body='"""Runs nothing in particular."""\n'
                                      + _GATE_STUB + _INVOKES)
            case("...and the same name in an executed literal is green",
                 root, False)

            # 9/10. a declaration pointing at a workflow GitHub never
            #    registers. The nested file EXISTS and CONTAINS the name — the
            #    only difference between these two cases is where it sits, so
            #    a detector that matched on the word "workflows" would pass
            #    both and this pair would catch it.
            WIRED["nested-wired.py"] = "pkg/.github/workflows/ci.yml"
            root = _fixture(tmp, wired, clean_scripts | {"nested-wired.py"},
                            gate_body=_GATE_STUB + _INVOKES,
                            nested_workflow="run: python scripts/nested-wired.py\n")
            case("declared wired into a workflow GitHub never registers", root,
                 True, "not a workflow GitHub registers")
            del WIRED["nested-wired.py"]

            WIRED["root-wired.py"] = ".github/workflows/ci.yml"
            root = _fixture(tmp, wired, clean_scripts | {"root-wired.py"},
                            gate_body=_GATE_STUB + _INVOKES,
                            workflow="run: python scripts/root-wired.py\n")
            case("...and the same file in the registrable location is green",
                 root, False)
            del WIRED["root-wired.py"]

            # 11. a dot-directory is scratch, not the shipped tree: a .php in
            #     one must not redden the gate.
            root = _fixture(tmp, wired, clean_scripts,
                            gate_body=_GATE_STUB + _INVOKES,
                            dot_dir_files=["undeclared-scratch.php"])
            case("a .php in a dot-directory is not an artefact", root, False)
        finally:
            for table, original in zip((WIRED, UNWIRED, WP_SUPPORT, NOT_A_CHECK), saved):
                table.clear(); table.update(original)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [n for n, ok, _ in results if not ok]
    if bad:
        print("SELFTEST: FAIL (%d of %d detector case(s) misdetected: %s)"
              % (len(bad), len(results), ", ".join(bad)))
        return 1
    print("SELFTEST: PASS (%d detector case(s), including the clean control)"
          % len(results))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="check_suite_coverage.py",
                                description=__doc__.splitlines()[0])
    p.add_argument("repo_root", nargs="?", default=REPO_ROOT_DEFAULT)
    p.add_argument("--selftest", action="store_true",
                   help="prove every detector on synthetic fixtures and exit")
    a = p.parse_args(argv)
    if a.selftest:
        return selftest()
    return report(os.path.abspath(a.repo_root))


if __name__ == "__main__":
    sys.exit(main())
