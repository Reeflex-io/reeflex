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
     does not render a credential in the clear.

It does NOT claim the bundle works -- no Claude Desktop runs in this suite, and
this file makes no statement about one. It asserts a parity between two files
in this repo, which is the thing that silently drifted.
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
_CREDENTIAL_VARS = {"REEFLEX_TOKEN", "REEFLEX_APPROVER_TOKEN"}


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

    def test_credential_fields_are_marked_sensitive(self) -> None:
        """A bearer token must not render in the clear in the Desktop UI."""
        prefix = "${user_config."
        for var in sorted(_CREDENTIAL_VARS & set(self.env)):
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
