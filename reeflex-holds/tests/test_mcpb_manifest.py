"""
test_mcpb_manifest.py -- the MCPB bundle's config surface must keep up with
the package's.

WHY THIS EXISTS (RFX-245 residual). RFX-245 was "an approver who could approve
a hold could not list one": `reeflex-holds` read one token for every route,
while core accepts a `REEFLEX_RESOLVER_TOKENS` credential on the resolve route
and refuses it `401` everywhere else. The fix added `REEFLEX_APPROVER_TOKEN`
and corrected `config.py`, the README table, the README's Claude Desktop
snippet and the CHANGELOG -- four of the five places a user is configured
from. It did not touch the fifth: `mcpb/manifest.json`, the one-click bundle
Claude Desktop installs.

That mattered because the manifest is not documentation. `user_config` is the
ONLY channel the bundle has to the human -- it is what the Desktop settings UI
renders a field for -- and `server.mcp_config.env` is the closed list of names
the host hands the server process. A variable in neither cannot be set by a
bundle user at all, whatever the README says. The bundle declares `resolve_hold`
among its four tools, so approving is squarely in scope for it: the defect
RFX-245 describes survived, on that install path, after RFX-245 was fixed.

WHAT THIS PINS, and what it deliberately does not:

  1. Every `REEFLEX_*` variable `config.py` actually reads -- collected from
     the AST, not from a list kept by hand here, so a variable added tomorrow
     is in scope tomorrow -- is either wired in the manifest's env block or
     named in NOT_EXPOSED below with the reason it is not. A declared omission
     is a decision; an undeclared one is this bug.

  2. Every `${user_config.X}` the env block interpolates resolves to a real
     `user_config` key. A typo there fails silently at install time: the host
     substitutes nothing and the server sees an empty string, which
     `config.py` treats exactly like "unset".

  3. Anything carrying a bearer token is marked `sensitive`, so the Desktop UI
     does not render a credential in the clear. Credential-ness is decided by
     the variable's own NAME (see `_is_credential`), not by a set of the two
     that happen to exist today.

  4. Every exposed variable resolves to a `${user_config.*}` field OF ITS OWN.
     Membership in the env block is not a channel to the human: a variable
     wired to a literal, or to a key another variable already owns, renders no
     field the user can type into, so it cannot be set independently. That is
     the same defect as (1), one step sideways.

RFX-418, on how (3) and (4) got here. The RFX-245-residual version of this file
derived the variable LIST from the AST, then decided both properties above from
hand-written or implicit scope. Measured: a new `REEFLEX_SIGNING_TOKEN` wired to
an un-`sensitive` field passed every assertion, and so did a new variable wired
to `${user_config.token}`, which no user can set separately. Deriving the list
and hand-keeping the predicates put back exactly the drift the AST walk removed.

It does NOT claim the bundle works -- no Claude Desktop runs in this suite, and
this file makes no statement about one. It asserts a parity between two files
in this repo, which is the thing that silently drifted.

DECLARED LIMIT: the AST walk matches `<something>.environ.get("LITERAL")`. A
variable read via `os.getenv` or `os.environ[...]` is invisible to it. Measured
2026-09-23: `os.getenv` appears zero times in this monorepo and `config.py` is
the package's sole env-reading surface outside tests, so that is a narrowness
against an idiom this repo does not use -- recorded, not fixed.
"""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PY = _PKG_ROOT / "reeflex_holds" / "config.py"
_MANIFEST = _PKG_ROOT / "mcpb" / "manifest.json"

# Variables config.py reads that the bundle deliberately does not expose.
# Each needs a reason. An entry whose variable config.py no longer reads is a
# FAILURE, not a silent no-op, so this cannot rot into blanket permission --
# the same rule scripts/check_test_census.py applies to its waivers.
NOT_EXPOSED = {
    "REEFLEX_HOLDS_TIMEOUT": (
        "Bounded socket timeout with a working default (10s). Not a "
        "credential and not an endpoint: a bundle user who needs to change it "
        "has a broken network, not a configuration problem. Exposing it would "
        "add a field whose only wrong answers are 'too small' and 'unbounded'."
    ),
}

# Variables whose value is a bearer token and must never render in the clear.
# FLOOR, not the scope: names that do not announce themselves by suffix.
_CREDENTIAL_VARS = {"REEFLEX_TOKEN", "REEFLEX_APPROVER_TOKEN"}

# A variable is a credential if its own name says so. Derived on purpose: the
# variable LIST is read from config.py's AST precisely so that a variable added
# tomorrow is in scope tomorrow, and a hand-kept set of which ones are secret
# would have put that back (qa--338: a new REEFLEX_SIGNING_TOKEN wired to an
# un-`sensitive` field passed every assertion in this file).
_CREDENTIAL_SUFFIXES = ("_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_CREDENTIAL")


def _is_credential(var: str) -> bool:
    return var in _CREDENTIAL_VARS or var.endswith(_CREDENTIAL_SUFFIXES)


def _env_vars_config_reads() -> set[str]:
    """Every `os.environ.get("REEFLEX_...")` literal in config.py, via AST.

    Static on purpose: no import, so this needs none of the package's
    dependencies and cannot be defeated by an import error.
    """
    tree = ast.parse(_CONFIG_PY.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "get"):
            continue
        # os.environ.get(...) -- match the attribute chain, not a bare name.
        value = func.value
        if not (isinstance(value, ast.Attribute) and value.attr == "environ"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            if first.value.startswith("REEFLEX_"):
                found.add(first.value)
    return found


class TestMcpbManifestTracksThePackage(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
        self.env = self.manifest["server"]["mcp_config"]["env"]
        self.user_config = self.manifest["user_config"]

    def test_the_ast_walk_actually_found_something(self) -> None:
        """Non-vacuity: a walk that matched nothing would pass every test below."""
        read = _env_vars_config_reads()
        self.assertGreaterEqual(len(read), 5, "AST walk found %r" % (sorted(read),))
        self.assertIn("REEFLEX_TOKEN", read)
        self.assertIn("REEFLEX_APPROVER_TOKEN", read)

    def test_every_env_var_is_exposed_or_declared_not_exposed(self) -> None:
        """The RFX-245 residual itself: a new variable cannot miss the bundle."""
        for var in sorted(_env_vars_config_reads()):
            with self.subTest(var=var):
                if var in NOT_EXPOSED:
                    self.assertNotIn(
                        var, self.env,
                        "%s is declared NOT_EXPOSED but is wired in the "
                        "manifest env block -- one of the two is wrong" % var,
                    )
                    continue
                self.assertIn(
                    var, self.env,
                    "config.py reads %s but mcpb/manifest.json neither passes "
                    "it to the server nor declares why not. A bundle user has "
                    "no way to set it: user_config is the only field the "
                    "Desktop UI renders. Add it to the env block plus a "
                    "user_config entry, or add it to NOT_EXPOSED with a "
                    "reason." % var,
                )

    def test_no_stale_not_exposed_entry(self) -> None:
        """A declaration expires with the thing it names."""
        read = _env_vars_config_reads()
        for var in sorted(NOT_EXPOSED):
            with self.subTest(var=var):
                self.assertIn(
                    var, read,
                    "NOT_EXPOSED names %s but config.py no longer reads it -- "
                    "drop the entry rather than leaving a standing "
                    "permission." % var,
                )

    def test_every_interpolated_user_config_key_exists(self) -> None:
        """A typo'd `${user_config.X}` substitutes empty and reads as unset."""
        prefix = "${user_config."
        for name, raw in sorted(self.env.items()):
            if not (isinstance(raw, str) and raw.startswith(prefix)):
                continue
            with self.subTest(env=name):
                key = raw[len(prefix):].rstrip("}")
                self.assertIn(
                    key, self.user_config,
                    "manifest env %s interpolates ${user_config.%s}, which no "
                    "user_config entry defines; the host substitutes nothing "
                    "and the server sees an empty string." % (name, key),
                )

    def test_every_exposed_var_has_its_own_user_config_field(self) -> None:
        """Being in the env block is not the same as reaching the human.

        `test_every_env_var_is_exposed_or_declared_not_exposed` is satisfied by
        mere membership in the env block. Membership is not a channel: a
        variable wired to a literal, or to a `${user_config.X}` key some OTHER
        variable already owns, renders no field of its own and cannot be set
        independently -- which is exactly the RFX-245 residual this file was
        written against, one step sideways. So every variable config.py reads
        and the manifest exposes must resolve to a user_config key of its own.
        """
        prefix = "${user_config."
        owner: dict[str, str] = {}
        for var in sorted(_env_vars_config_reads()):
            if var in NOT_EXPOSED or var not in self.env:
                continue  # the exposure test above owns those two cases
            with self.subTest(var=var):
                raw = self.env[var]
                self.assertTrue(
                    isinstance(raw, str) and raw.startswith(prefix),
                    "manifest env %s is wired to %r, not to a ${user_config.*} "
                    "field. The Desktop UI renders a field only for user_config, "
                    "so a bundle user cannot set %s at all." % (var, raw, var),
                )
                key = raw[len(prefix):].rstrip("}")
                self.assertNotIn(
                    key, owner,
                    "manifest env %s and %s both read ${user_config.%s}. One "
                    "field cannot carry two variables: whichever the user types "
                    "goes to both, and %s can never be set on its own."
                    % (var, owner.get(key), key, var),
                )
                owner[key] = var

    def test_the_credential_detector_is_not_vacuous(self) -> None:
        """Non-vacuity: a detector that classifies nothing pins nothing."""
        self.assertTrue(_is_credential("REEFLEX_TOKEN"))
        self.assertTrue(_is_credential("REEFLEX_APPROVER_TOKEN"))
        self.assertTrue(_is_credential("REEFLEX_SOMETHING_SECRET"))
        self.assertFalse(_is_credential("REEFLEX_CORE_URL"))
        self.assertFalse(_is_credential("REEFLEX_HOLDS_TIMEOUT"))

    def test_credential_fields_are_marked_sensitive(self) -> None:
        """A bearer token must not render in the clear in the Desktop UI."""
        prefix = "${user_config."
        credentials = {v for v in self.env if _is_credential(v)}
        credentials |= {v for v in _env_vars_config_reads() if _is_credential(v)} & set(self.env)
        for var in sorted(credentials):
            with self.subTest(var=var):
                raw = self.env[var]
                self.assertTrue(
                    raw.startswith(prefix),
                    "%s is not sourced from user_config (%r)" % (var, raw),
                )
                key = raw[len(prefix):].rstrip("}")
                self.assertTrue(
                    self.user_config[key].get("sensitive") is True,
                    "user_config.%s carries a bearer token and is not marked "
                    "sensitive" % key,
                )


if __name__ == "__main__":
    unittest.main()
