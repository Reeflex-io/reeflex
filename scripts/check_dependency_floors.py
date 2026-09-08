#!/usr/bin/env python3
"""check_dependency_floors.py — every declared dependency must be bounded ABOVE.

WHY THIS EXISTS (PR #123, and the class it belongs to)
------------------------------------------------------
On 2026-09-07 `main` went RED on PR #112 — a commit that touched no file in
`reeflex-holds`. `reeflex-holds/pyproject.toml` said:

    dependencies = ["mcp>=2"]

An open floor. It resolved to `mcp 2.1.1`, whose SDK converts an uncaught tool
exception into a generic `Error executing tool <name>` and drops the original
text. Three tests that had been green for weeks failed on a commit that changed
none of their code, and — the part that matters — for a human-in-the-loop holds
console the SHIPPED behaviour became "a typo, an outage and a missing config all
read the same to the operator". The code was fine. Something we do not control
changed underneath it, and the floor was open, so it was silently ours to absorb.

That PR fixed the one package and closed with: *"Not fixed here: every other
package with an unbounded dependency floor. Worth a sweep."* This script is the
sweep made permanent, so the next open floor is a red PR instead of a red main.

It is deliberately about ONE property, statically checkable, no network, no
installs, no imports of the manifests' contents:

    every requirement this repo declares has an UPPER bound.

Not "is pinned exactly" — an exact pin is its own maintenance debt and stops
patch fixes arriving. Not "is a supported version" — that needs the index and a
resolve. Just: is there a ceiling, so that a major (or, per #123, a MINOR) of
something we do not own cannot change what our users see without a commit here.

WHAT COUNTS AS BOUNDED
----------------------
Python (PEP 508), bounded if ANY clause is `<`, `<=`, `==`, `===` or `~=`:

    mcp>=2,<2.2        BOUNDED      the #123 fix
    anyio>=4.5,<5      BOUNDED
    pyyaml~=6.0        BOUNDED      ~= implies ==6.*
    mcp<2              BOUNDED      a ceiling with no floor is still a ceiling
    mcp>=2             UNBOUNDED    the #123 defect
    pyyaml             UNBOUNDED    no floor AND no ceiling
    urllib3>=1,!=2.0.1 UNBOUNDED    `!=` excludes a point, it does not bound

npm (node-semver), bounded if the range has a `<`, a `^`/`~`, an exact version,
a hyphen range, or an x-range with a fixed major; every branch of a `||` union
must be bounded:

    ^0.23.1            BOUNDED      caret implies an upper bound
    >=1.83 <3          BOUNDED
    1.x                BOUNDED
    5.9.3              BOUNDED
    *                  UNBOUNDED    what `n8n-workflow` used to say: 494 versions
    >=20.15            UNBOUNDED

THE PARSER, AND WHY IT IS NOT TAKEN ON TRUST
--------------------------------------------
A checker of this class is worth exactly what its reader of the manifests is
worth, and this repo has been burned three times this month by an instrument
that was wrong while the code was fine. Two things guard against that here.

1.  **Anchored, string-aware extraction** (`--selftest` proves it on fixtures,
    including a dependency mentioned only inside a `#` comment, which must NOT
    be collected, and an unbounded one which MUST be).

2.  **A cross-check against `tomllib` whenever it is importable.** On Python
    >= 3.11 (CI runs 3.12) every `pyproject.toml` is ALSO parsed by the stdlib
    TOML parser and the two requirement lists must be IDENTICAL. They disagree
    -> that is a FAILURE naming the file, not a quiet fallback. The devbox's
    default `python3` is 3.9, where `tomllib` does not exist; there the anchored
    extractor stands on its fixtures alone, and the run PRINTS which of the two
    it had. An unsupported manifest shape (a Poetry-style
    `[tool.poetry.dependencies]` table, say) is also a FAILURE — an instrument
    that cannot read a file must never report PASS over it.

A FLOOR UNDER THE WALK (the RFX-217 lesson)
-------------------------------------------
"No unbounded requirement was found" is a claim an EMPTY walk satisfies. `drift`
printed the same PASS line at 0 test files as at 52 before RFX-217 put a minimum
under it. So this script refuses to pass if it collected fewer than
MIN_REQUIREMENTS requirements, and it prints the count it measured on every run,
passing or failing, so the next person to move that number can see what it was
set against.

ALLOWANCES, AND WHY THEY ARE NOT A BACK DOOR
--------------------------------------------
Some floors should stay open, and the honest thing is for the instrument to SEE
them and for the decision to be written down — not for the walk to skip them.
`ALLOWED` below takes `(manifest, section, name)` and requires a reason AND a
ticket; an entry without a ticket is refused. Every allowance is printed in full
on every run, and an allowance whose target no longer exists is a FAILURE, so an
allowance cannot rot into blanket permission for a file nobody declares any more.

USAGE
-----
    python scripts/check_dependency_floors.py [REPO_ROOT]
    python scripts/check_dependency_floors.py --selftest

Exit 0 = PASS, 1 = FAIL, 2 = the script could not measure (bad usage/root).
The verdict is one anchored line, which is what `gate.py` parses:

    DEP-FLOORS: PASS (34 requirements over 8 manifests; 0 unbounded; 2 allowed)
    DEP-FLOORS: FAIL (34 requirements over 8 manifests; 3 unbounded; 2 allowed)
"""

import json
import os
import re
import sys

# --------------------------------------------------------------------------
# What we walk. Directories that hold BUILT or INSTALLED copies of manifests
# (a wheel's vendored metadata, node_modules' 300 package.json files) are not
# declarations this repo makes, so they are excluded rather than waived.
# --------------------------------------------------------------------------

EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "dist-test",
    "build", "site", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist-artifacts", "pypi-dist", ".eggs", "htmlcov",
}

# Scratch trees an agent leaves in a worktree (pinned policy copies, throwaway
# venvs). `gate.py`'s drift check already learned this the hard way: a local RED
# was the agent's own `.scratch-*` dir, not the tree.
EXCLUDE_DIR_PREFIXES = (".scratch", ".rfx", "smoke-venv", "venv-")

PYPROJECT = "pyproject.toml"
PACKAGE_JSON = "package.json"
COMPOSER_JSON = "composer.json"
REQ_FILE_RE = re.compile(r"^(requirements|constraints)[A-Za-z0-9._-]*\.txt$")

# npm manifest keys that declare a dependency on something we do not own.
NPM_DEP_SECTIONS = ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies")
# `engines` is not resolved by npm the way a dependency is, but it IS a floor
# with no ceiling, and the whole point of this script is that the instrument
# sees every one of them. It is checked and then ALLOWED, by name, below.
NPM_ENGINE_SECTION = "engines"

COMPOSER_DEP_SECTIONS = ("require", "require-dev")

# --------------------------------------------------------------------------
# The floor under the walk (see the header). Measured 2026-09-08: this tree
# declares 17 requirements over 7 manifests. Set well below 17 so deleting a
# package stays a normal change, and far above zero so a walk that stopped
# matching cannot pass for a tidy tree. The measured count is printed on the
# verdict line of every run, so the next person to move this can see what it
# was set against.
# --------------------------------------------------------------------------

MIN_REQUIREMENTS = 12

# --------------------------------------------------------------------------
# Allowances: (manifest path relative to repo root, section, requirement name)
# -> "reason (TICKET)". A reason with no RFX/PR reference is REFUSED.
# --------------------------------------------------------------------------

ALLOWED = {
    ("n8n-nodes-reeflex/package.json", "engines", "node"):
        "An upper bound here would refuse the Node the customer's n8n upgrades "
        "TO, which is the opposite of the risk this check exists for: npm does "
        "not resolve `engines`, it warns (or refuses, under engine-strict) at "
        "install time, so an open ceiling cannot silently change what our code "
        "runs against the way an unbounded DEPENDENCY can. The floor 20.15 is "
        "the one n8n's own community-node template sets. Kept open on purpose, "
        "recorded here so it is visible on every run rather than invisible. "
        "(RFX sweep after PR #123)",
}


class Unreadable(Exception):
    """The manifest exists and this script cannot honestly parse it."""


# --------------------------------------------------------------------------
# Anchored TOML-subset extraction. Handles exactly the shapes this repo uses:
# `[section]` headers, `key = [ "a", "b" ]` arrays spanning lines, `#` comments
# inside and outside the array, and single- or double-quoted strings.
# --------------------------------------------------------------------------

SECTION_RE = re.compile(r"^\[([^\]]+)\]\s*$")
ARRAY_START_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*\[(.*)$")
# A `key = "value"` line inside a Poetry-style dependency table. We do not
# support that shape; we refuse to report on it (see Unreadable).
INLINE_KV_RE = re.compile(r"^\s*[A-Za-z0-9_.\-\"']+\s*=\s*[\"{]")

TOML_DEP_ARRAYS = {
    "build-system": ("requires",),
    "project": ("dependencies",),
}
TOML_DEP_SECTION_ALL_ARRAYS = ("project.optional-dependencies",)

UNSUPPORTED_TOML_SECTIONS = (
    "tool.poetry.dependencies",
    "tool.poetry.dev-dependencies",
    "tool.poetry.group",
    "tool.pdm.dev-dependencies",
    "tool.hatch.envs",
)


def strip_toml_comment(line):
    """Drop a `#` comment, but only when the `#` is not inside a string."""
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


STRING_RE = re.compile(r"""(?:"((?:[^"\\]|\\.)*)"|'([^']*)')""")


def toml_strings(text):
    """Every quoted string in `text`, in order."""
    return [(a if a is not None else b) for a, b in STRING_RE.findall(text)]


def extract_pyproject_requirements(text, path):
    """[(section, requirement)] for the dependency arrays we support.

    Anchored and string-aware. Raises Unreadable on a manifest shape this
    script cannot honestly read, rather than returning an empty list.
    """
    found = []
    section = None
    collecting = None      # (section_label, buffer) while inside an array
    depth = 0
    for raw in text.splitlines():
        line = strip_toml_comment(raw)
        if collecting is not None:
            label, buf = collecting
            depth += line.count("[") - line.count("]")
            if depth <= 0:
                head = line.rsplit("]", 1)[0] if "]" in line else line
                buf.append(head)
                for s in toml_strings("\n".join(buf)):
                    found.append((label, s))
                collecting = None
                depth = 0
            else:
                buf.append(line)
            continue
        m = SECTION_RE.match(line.strip())
        if m:
            section = m.group(1).strip()
            for bad in UNSUPPORTED_TOML_SECTIONS:
                if section == bad or section.startswith(bad + "."):
                    raise Unreadable(
                        "%s declares dependencies in [%s], a manifest shape this "
                        "checker does not read. Teach it that shape or move the "
                        "declaration to [project].dependencies — do not leave it "
                        "unmeasured." % (path, section))
            continue
        if section is None:
            continue
        am = ARRAY_START_RE.match(line)
        if not am:
            continue
        key, rest = am.group(1), am.group(2)
        wanted = (key in TOML_DEP_ARRAYS.get(section, ())
                  or section in TOML_DEP_SECTION_ALL_ARRAYS)
        label = section if key in TOML_DEP_ARRAYS.get(section, ()) \
            else "%s.%s" % (section, key)
        depth = 1 + rest.count("[") - rest.count("]")
        if depth <= 0:
            # single-line array
            if wanted:
                inner = rest.rsplit("]", 1)[0]
                for s in toml_strings(inner):
                    found.append((label, s))
            depth = 0
            continue
        collecting = (label, [rest]) if wanted else ("__ignored__", [rest])
        if not wanted:
            # still track brackets so we skip the whole array
            collecting = ("__ignored__", [])
    if collecting is not None:
        raise Unreadable("%s: an array is never closed — refusing to guess" % path)
    return [(lab, s) for lab, s in found if lab != "__ignored__"]


def extract_pyproject_requirements_tomllib(text, path):
    """The same list via the stdlib TOML parser, or None if unavailable."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return None
    data = tomllib.loads(text)
    out = []
    for sec, keys in TOML_DEP_ARRAYS.items():
        table = data.get(sec) or {}
        for k in keys:
            for s in table.get(k) or []:
                out.append((sec, s))
    opt = (data.get("project") or {}).get("optional-dependencies") or {}
    for extra, reqs in opt.items():
        for s in reqs:
            out.append(("project.optional-dependencies.%s" % extra, s))
    return out


# --------------------------------------------------------------------------
# Requirement classification
# --------------------------------------------------------------------------

PY_BOUNDING_OPS = ("<=", "<", "==", "===", "~=")
PY_NON_BOUNDING_OPS = (">=", ">", "!=")

NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", re.S)


def parse_py_requirement(req):
    """(name, specifier_text) with extras and environment markers removed."""
    body = req.split(";", 1)[0].strip()
    if body.startswith(("-r", "-c", "-e", "--", ".", "/")):
        return None, None
    if "@" in body and not body.split("@", 1)[0].strip().endswith(
            PY_NON_BOUNDING_OPS + PY_BOUNDING_OPS):
        # PEP 508 direct reference: `name @ https://…`. That IS an exact
        # locator, so it is bounded; report it as such under its own operator.
        name = NAME_RE.match(body).group(1) if NAME_RE.match(body) else body
        return name, "@direct-reference"
    m = NAME_RE.match(body)
    if not m:
        return None, None
    return m.group(1), (m.group(3) or "").strip()


def py_requirement_is_bounded(spec):
    if spec == "@direct-reference":
        return True
    if not spec:
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        for op in ("===", "~=", "==", "<=", "<"):
            if clause.startswith(op):
                return True
    return False


NPM_UNBOUNDED_LITERALS = {"", "*", "x", "X", "latest", "*.*", "*.*.*"}


def npm_range_is_bounded(rng):
    rng = (rng or "").strip()
    if rng in NPM_UNBOUNDED_LITERALS:
        return False
    # A union is only as bounded as its loosest branch.
    if "||" in rng:
        return all(npm_range_is_bounded(part) for part in rng.split("||"))
    # Non-registry locators (file:, link:, git+, npm: alias, a URL, a tag) are
    # exact by construction except for the `*` forms already caught above.
    if re.match(r"^(file:|link:|portal:|git\+|git:|https?:|github:|npm:|workspace:)", rng):
        return "*" not in rng
    if "-" in rng and re.search(r"\d\s+-\s+\d", rng):     # hyphen range: 1.2 - 2.3
        return True
    if rng.startswith(("^", "~")):
        return True
    if "<" in rng:
        return True
    # x-range with a fixed major (1.x, 1.2.x, 1.*) is bounded above.
    if re.match(r"^=?\d+(\.(\d+|[xX*]))*(\.[xX*])?$", rng):
        return True
    if re.match(r"^=?\d+\.[xX*]", rng) or re.match(r"^=?\d+\.\d+\.[xX*]$", rng):
        return True
    # Anything left starting with >= or > and no ceiling.
    return False


# --------------------------------------------------------------------------
# The walk
# --------------------------------------------------------------------------

def iter_manifests(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS and not d.startswith(EXCLUDE_DIR_PREFIXES)
        ]
        dirnames.sort()
        for fn in sorted(filenames):
            if fn in (PYPROJECT, PACKAGE_JSON, COMPOSER_JSON) or REQ_FILE_RE.match(fn):
                full = os.path.join(dirpath, fn)
                yield os.path.relpath(full, root).replace(os.sep, "/"), full


def requirements_in(rel, full):
    """[(section, name, spec, ecosystem)] — raises Unreadable if it cannot."""
    base = os.path.basename(rel)
    try:
        with open(full, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise Unreadable("%s: %s" % (rel, exc))

    out = []
    if base == PYPROJECT:
        mine = extract_pyproject_requirements(text, rel)
        theirs = extract_pyproject_requirements_tomllib(text, rel)
        if theirs is not None and sorted(mine) != sorted(theirs):
            raise Unreadable(
                "%s: the anchored extractor and tomllib DISAGREE.\n"
                "        anchored: %r\n        tomllib : %r\n"
                "        Refusing to report a verdict off a parser that is wrong."
                % (rel, sorted(mine), sorted(theirs)))
        for section, req in mine:
            name, spec = parse_py_requirement(req)
            if name is None:
                continue
            out.append((section, name, spec, "py"))
        return out

    if REQ_FILE_RE.match(base):
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name, spec = parse_py_requirement(line)
            if name is None:
                continue
            out.append(("file", name, spec, "py"))
        return out

    if base in (PACKAGE_JSON, COMPOSER_JSON):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise Unreadable("%s: not valid JSON (%s)" % (rel, exc))
        sections = (NPM_DEP_SECTIONS + (NPM_ENGINE_SECTION,)) \
            if base == PACKAGE_JSON else COMPOSER_DEP_SECTIONS
        for sec in sections:
            table = data.get(sec) or {}
            if not isinstance(table, dict):
                raise Unreadable("%s: `%s` is not an object" % (rel, sec))
            for name in sorted(table):
                out.append((sec, name, table[name], "npm"))
        return out

    raise Unreadable("%s: no reader for this manifest kind" % rel)


def is_bounded(spec, ecosystem):
    return py_requirement_is_bounded(spec) if ecosystem == "py" \
        else npm_range_is_bounded(spec)


TICKET_RE = re.compile(r"\b(RFX-\d+|RFX sweep|PR #\d+|#\d+)\b")


def check_allowances(seen_keys, allowed=None):
    """(ok, lines) — every allowance needs a ticket and a live target.

    NOTE: "an allowance whose target no longer exists is a FAILURE" means this
    function is only meaningful against the REAL repo root. The selftest's
    synthetic trees therefore pass their own (usually empty) allowance table.
    """
    allowed = ALLOWED if allowed is None else allowed
    lines = []
    ok = True
    if not allowed:
        return True, ["allowances: none"]
    lines.append("allowances (%d) — printed on every run, passing or failing:" % len(allowed))
    for key in sorted(allowed):
        reason = allowed[key]
        lines.append("  - %s :: [%s] %s" % (key[0], key[1], key[2]))
        lines.append("      why: %s" % reason)
        if not TICKET_RE.search(reason):
            ok = False
            lines.append("      REFUSED: no ticket/PR reference in the reason — "
                         "an allowance nobody can trace is the class this check exists to kill")
        if key not in seen_keys:
            ok = False
            lines.append("      REFUSED: this requirement no longer exists in the tree — "
                         "a stale allowance is standing permission for a file nobody declares")
    return ok, lines


def run(root, allowed=None):
    allowed = ALLOWED if allowed is None else allowed
    lines = []
    manifests = list(iter_manifests(root))
    total = 0
    unbounded = []
    unreadable = []
    seen_keys = set()
    allowed_hits = 0
    parser_note = "tomllib cross-check: "
    try:
        import tomllib  # noqa: F401
        parser_note += "ON (stdlib)"
    except ImportError:
        try:
            import tomli  # noqa: F401
            parser_note += "ON (tomli)"
        except ImportError:
            parser_note += ("OFF — no tomllib/tomli on this interpreter (%s); the "
                            "anchored extractor stands on its --selftest fixtures"
                            % ".".join(str(x) for x in sys.version_info[:3]))

    for rel, full in manifests:
        try:
            reqs = requirements_in(rel, full)
        except Unreadable as exc:
            unreadable.append(str(exc))
            lines.append("  %-46s UNREADABLE" % rel)
            continue
        lines.append("  %-46s %d requirement(s)" % (rel, len(reqs)))
        for section, name, spec, eco in reqs:
            total += 1
            key = (rel, section, name)
            seen_keys.add(key)
            shown = "%s%s" % (name, (" " + spec) if spec else "")
            if is_bounded(spec, eco):
                lines.append("      bounded    [%s] %s" % (section, shown))
            elif key in allowed:
                allowed_hits += 1
                lines.append("      ALLOWED    [%s] %s" % (section, shown))
            else:
                unbounded.append((rel, section, name, spec))
                lines.append("      UNBOUNDED  [%s] %s   <-- no upper bound" % (section, shown))

    lines.append("")
    lines.append(parser_note)
    ok_allow, allow_lines = check_allowances(seen_keys, allowed)
    lines.extend(allow_lines)
    lines.append("")

    ok = True
    if unreadable:
        ok = False
        lines.append("MANIFESTS THIS CHECKER COULD NOT READ (%d) — a PASS over an "
                     "unread manifest would be a lie:" % len(unreadable))
        for u in unreadable:
            lines.append("  - %s" % u)
        lines.append("")
    if unbounded:
        ok = False
        lines.append("UNBOUNDED DEPENDENCY FLOORS (%d):" % len(unbounded))
        for rel, section, name, spec in unbounded:
            lines.append("  - %s :: [%s] %s%s" % (rel, section, name, (" " + spec) if spec else ""))
        lines.append("")
        lines.append("Give each one an upper bound justified by the API SURFACE this repo")
        lines.append("uses from it, with the reason in a comment beside the pin — see")
        lines.append("reeflex-mcp/pyproject.toml for the shape. If a floor must stay open,")
        lines.append("add it to ALLOWED in scripts/check_dependency_floors.py with a reason")
        lines.append("and a ticket; it will then be printed on every run instead of hidden.")
        lines.append("")
    if total < MIN_REQUIREMENTS:
        ok = False
        lines.append("WALK FLOOR: collected %d requirement(s), expected at least %d "
                     "(MIN_REQUIREMENTS). 'nothing unbounded' is a claim an EMPTY walk "
                     "satisfies — this refuses to be reassuring about a walk that "
                     "stopped matching." % (total, MIN_REQUIREMENTS))
        lines.append("")
    if not ok_allow:
        ok = False

    verdict = "DEP-FLOORS: %s (%d requirements over %d manifests; %d unbounded; %d allowed)" % (
        "PASS" if ok else "FAIL", total, len(manifests), len(unbounded), allowed_hits)
    return ok, lines, verdict


# --------------------------------------------------------------------------
# Selftest — the instrument is proved to FAIL before its PASS is trusted.
# --------------------------------------------------------------------------

def selftest():
    failures = []
    n = [0]

    def check(label, cond):
        n[0] += 1
        print("  %-4s %s" % ("ok" if cond else "FAIL", label))
        if not cond:
            failures.append(label)

    # --- python specifier classification
    check("py: mcp>=2,<2.2 is bounded (the #123 fix)",
          py_requirement_is_bounded(">=2,<2.2"))
    check("py: mcp>=2 is UNBOUNDED (the #123 defect)",
          not py_requirement_is_bounded(">=2"))
    check("py: a bare name is UNBOUNDED", not py_requirement_is_bounded(""))
    check("py: ~=6.0 is bounded (implies ==6.*)", py_requirement_is_bounded("~=6.0"))
    check("py: ==1.2.3 is bounded", py_requirement_is_bounded("==1.2.3"))
    check("py: ==1.2.* is bounded", py_requirement_is_bounded("==1.2.*"))
    check("py: <2 alone is bounded (a ceiling with no floor is a ceiling)",
          py_requirement_is_bounded("<2"))
    check("py: <=2 is bounded", py_requirement_is_bounded("<=2"))
    check("py: ===1.0 is bounded", py_requirement_is_bounded("===1.0"))
    check("py: >=1,!=2.0.1 is UNBOUNDED (!= excludes a point, it does not bound)",
          not py_requirement_is_bounded(">=1,!=2.0.1"))
    check("py: >4 is UNBOUNDED", not py_requirement_is_bounded(">4"))

    # --- python requirement parsing
    name, spec = parse_py_requirement("mkdocs-material[imaging]>=9.5,<10")
    check("py: extras are stripped from the name", name == "mkdocs-material")
    check("py: extras do not eat the specifier", spec == ">=9.5,<10")
    name, spec = parse_py_requirement('pytest>=9,<10 ; python_version >= "3.10"')
    check("py: an environment marker is dropped", name == "pytest" and spec == ">=9,<10")
    check("py: a marker'd requirement is still classified",
          py_requirement_is_bounded(spec))
    name, _ = parse_py_requirement("-r other.txt")
    check("py: an -r include is not a requirement", name is None)

    # --- npm range classification
    check("npm: ^0.23.1 is bounded", npm_range_is_bounded("^0.23.1"))
    check("npm: ~3.8 is bounded", npm_range_is_bounded("~3.8"))
    check("npm: '>=1.83 <3' is bounded", npm_range_is_bounded(">=1.83 <3"))
    check("npm: '*' is UNBOUNDED (what n8n-workflow said: 494 versions)",
          not npm_range_is_bounded("*"))
    check("npm: '' is UNBOUNDED", not npm_range_is_bounded(""))
    check("npm: 'x' is UNBOUNDED", not npm_range_is_bounded("x"))
    check("npm: 'latest' is UNBOUNDED", not npm_range_is_bounded("latest"))
    check("npm: '>=20.15' is UNBOUNDED", not npm_range_is_bounded(">=20.15"))
    check("npm: '5.9.3' is bounded", npm_range_is_bounded("5.9.3"))
    check("npm: '1.x' is bounded", npm_range_is_bounded("1.x"))
    check("npm: '1.2 - 2.3' is bounded", npm_range_is_bounded("1.2 - 2.3"))
    check("npm: '^1 || ^2' is bounded (every branch is)",
          npm_range_is_bounded("^1 || ^2"))
    check("npm: '^1 || *' is UNBOUNDED (a union is as loose as its loosest branch)",
          not npm_range_is_bounded("^1 || *"))
    check("npm: 'file:../x' is bounded (an exact locator)",
          npm_range_is_bounded("file:../x"))

    # --- comment stripping, the trap that would silently under-collect
    check("toml: a # comment is dropped",
          strip_toml_comment('a = 1  # mcp>=2 lives here') == "a = 1  ")
    check("toml: a # INSIDE a string is kept",
          strip_toml_comment('a = "x#y"') == 'a = "x#y"')

    # --- extraction on fixtures
    fx = '\n'.join([
        '[build-system]',
        'requires = ["setuptools>=68,<85"]',
        'build-backend = "setuptools.build_meta"',
        '',
        '[project]',
        'name = "fixture"',
        '# mcp>=2 is mentioned ONLY in a comment and must NOT be collected',
        'dependencies = [',
        '    "mcp>=2,<2.2",   # inline comment, with a ] bracket to confuse a naive reader',
        '    "pyyaml",',
        ']',
        '',
        '[project.optional-dependencies]',
        'dev = ["pytest>=9,<10"]',
        '',
        '[tool.setuptools.packages.find]',
        'include = ["fixture*"]',
    ])
    got = extract_pyproject_requirements(fx, "fixture")
    names = sorted(s for _, s in got)
    check("extract: collects build-system + project + optional-dependencies",
          names == ["mcp>=2,<2.2", "pytest>=9,<10", "pyyaml", "setuptools>=68,<85"])
    check("extract: does NOT collect a dependency mentioned only in a comment",
          "mcp>=2" not in names)
    check("extract: does NOT collect [tool.setuptools…].include as a dependency",
          "fixture*" not in names)
    labels = dict((s, lab) for lab, s in got)
    check("extract: labels the optional-dependencies extra by name",
          labels["pytest>=9,<10"] == "project.optional-dependencies.dev")

    theirs = extract_pyproject_requirements_tomllib(fx, "fixture")
    if theirs is None:
        print("  n/a  cross-check: no tomllib/tomli on this interpreter — "
              "the extractor stands on the fixtures above")
    else:
        check("cross-check: the anchored extractor agrees with tomllib on the fixture",
              sorted(got) == sorted(theirs))

    check("extract: an unsupported (Poetry) shape RAISES rather than returning []",
          _raises(lambda: extract_pyproject_requirements(
              '[tool.poetry.dependencies]\npython = "^3.10"\n', "fx")))
    check("extract: an unclosed array RAISES rather than guessing",
          _raises(lambda: extract_pyproject_requirements(
              '[project]\ndependencies = [\n  "mcp>=2",\n', "fx")))

    # --- allowance hygiene
    ok, _ = check_allowances(set(ALLOWED))
    check("allowances: today's ALLOWED table passes its own hygiene checks", ok)
    saved = dict(ALLOWED)
    try:
        ALLOWED.clear()
        ALLOWED[("a/package.json", "engines", "node")] = "because I said so"
        ok, out = check_allowances({("a/package.json", "engines", "node")})
        check("allowances: a reason with NO ticket is REFUSED", not ok)
        ALLOWED.clear()
        ALLOWED[("gone/package.json", "engines", "node")] = "fine (RFX-1)"
        ok, out = check_allowances(set())
        check("allowances: an allowance whose target no longer exists is REFUSED",
              not ok)
    finally:
        ALLOWED.clear()
        ALLOWED.update(saved)

    # --- end-to-end on a synthetic tree: the checker must FAIL on a bad tree
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "pkg"))
        with open(os.path.join(td, "pkg", PYPROJECT), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname="x"\ndependencies = ["mcp>=2"]\n')
        ok, out, verdict = run(td, allowed={})
        check("e2e: a tree with an unbounded floor FAILS", not ok)
        check("e2e: the verdict line names the count",
              verdict.startswith("DEP-FLOORS: FAIL (1 requirements over 1 manifests; 1 unbounded"))
        check("e2e: the offending file and requirement are printed",
              any("pkg/pyproject.toml" in l for l in out)
              and any("UNBOUNDED" in l and "mcp" in l and ">=2" in l for l in out))

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "pkg"))
        deps = ", ".join('"dep%d>=1,<2"' % i for i in range(MIN_REQUIREMENTS))
        with open(os.path.join(td, "pkg", PYPROJECT), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname="x"\ndependencies = [%s]\n' % deps)
        ok, out, verdict = run(td, allowed={})
        check("e2e: a tree with only bounded floors PASSES", ok)
        check("e2e: the PASS verdict reports 0 unbounded",
              "; 0 unbounded;" in verdict)

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "pkg"))
        with open(os.path.join(td, "pkg", PYPROJECT), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname="x"\ndependencies = ["mcp>=2,<2.2"]\n')
        ok, out, verdict = run(td, allowed={})
        check("e2e: an all-bounded but TINY tree FAILS the walk floor (RFX-217 lesson)",
              not ok and any("WALK FLOOR" in l for l in out))

    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, PACKAGE_JSON), "w", encoding="utf-8") as fh:
            json.dump({"peerDependencies": {"n8n-workflow": "*"},
                       "devDependencies": dict(("d%d" % i, "^1.0.0")
                                               for i in range(MIN_REQUIREMENTS))}, fh)
        ok, out, verdict = run(td, allowed={})
        check("e2e: a package.json peer dep of '*' FAILS", not ok)
        check("e2e: the peer dep is named with its section",
              any("[peerDependencies] n8n-workflow" in l for l in out))

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "node_modules", "left-pad"))
        with open(os.path.join(td, "node_modules", "left-pad", PACKAGE_JSON), "w",
                  encoding="utf-8") as fh:
            json.dump({"dependencies": {"anything": "*"}}, fh)
        ok, out, verdict = run(td, allowed={})
        check("e2e: node_modules is NOT walked (installed copies are not our declarations)",
              "over 0 manifests" in verdict)
        os.makedirs(os.path.join(td, ".scratch-dev1-099"))
        with open(os.path.join(td, ".scratch-dev1-099", PYPROJECT), "w",
                  encoding="utf-8") as fh:
            fh.write('[project]\nname="x"\ndependencies = ["mcp>=2"]\n')
        ok, out, verdict = run(td, allowed={})
        check("e2e: an agent's .scratch-* tree is NOT walked (the local-gate-RED trap)",
              "over 0 manifests" in verdict)

    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "requirements-docs.txt"), "w", encoding="utf-8") as fh:
            fh.write("# a comment\n-r other.txt\nmkdocs-material[imaging]>=9.5,<10\npytest\n")
        ok, out, verdict = run(td, allowed={})
        check("e2e: a requirements .txt is walked, and its bare `pytest` FAILS",
              not ok and any("UNBOUNDED" in l and "pytest" in l for l in out))

    print("")
    print("selftest: %d properties, %d failed" % (n[0], len(failures)))
    for f in failures:
        print("  FAILED: %s" % f)
    return not failures


def _raises(fn):
    try:
        fn()
    except Unreadable:
        return True
    except Exception:
        return False
    return False


def main(argv):
    if "--selftest" in argv:
        print("check_dependency_floors.py --selftest")
        return 0 if selftest() else 1
    args = [a for a in argv[1:] if not a.startswith("-")]
    root = args[0] if args else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(root):
        sys.stderr.write("not a directory: %s\n" % root)
        return 2
    ok, lines, verdict = run(root)
    print("dependency floors — every declared requirement must be bounded ABOVE")
    print("repo root: %s" % root)
    print("")
    for l in lines:
        print(l)
    print(verdict)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
