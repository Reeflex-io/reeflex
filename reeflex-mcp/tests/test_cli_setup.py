"""
test_cli_setup.py -- BUG 3 regression tests (dogfood RCA, 2026-07), exercised
at the cli.cmd_setup() level (not just lifecycle.import_profile()), since
that is where the path/env decisions this bug is about are actually made
before ever reaching lifecycle/client_configs:

  BUG 3(1): `setup` wrote a RELATIVE --config path into the client's
            mcpServers entry. That happens to work while the gateway is
            launched from the exact directory `setup` itself ran in, but
            breaks ("Server disconnected", file not found) the moment the
            client launches the gateway from a different cwd -- the normal
            case for Claude Desktop / Claude Code launching a stdio server.
            Fix: cmd_setup() resolves the path to absolute BEFORE it is
            handed to import_profile()/gateway_entry().

  BUG 3(2): `setup` never wrote the env (REEFLEX_CORE_URL/REEFLEX_MODE) the
            launched gateway needs to reach reeflex-core -- the operator had
            to hand-add it, or the gateway simply could not function. Fix:
            cmd_setup() resolves REEFLEX_CORE_URL (--core-url flag, else
            env/default via config.core_url()) and ALWAYS REEFLEX_MODE=
            observe (never enforce by default), and passes both through.
            REEFLEX_CORE_TOKEN is deliberately never auto-copied from this
            process's environment into the written file (secrets by-
            reference, not by-copy).

These drive cli.cmd_setup() directly with a hand-built argparse.Namespace
(no real subprocess/console-script invocation needed -- same level tests
already exercise cmd_* functions at, see tests/test_lifecycle.py for the
one layer down).
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

from reeflex_mcp import cli, client_configs


def _tmp_client_config(data: dict) -> Path:
    tmpdir = tempfile.mkdtemp()
    path = Path(tmpdir) / "claude_desktop_config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _setup_args(*, path: str, config: str | None = None, core_url: str | None = None) -> argparse.Namespace:
    """Mimics exactly what argparse would hand cmd_setup() for the 'setup'
    subcommand (see cli.py's p_setup.add_argument calls) -- built by hand so
    these tests don't have to go through a real subprocess."""
    return argparse.Namespace(
        config=config,
        client=None,
        path=path,
        environment="staging",
        non_interactive=True,
        core_url=core_url,
    )


_SOME_CLIENT_ENTRY = {
    "mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
    }
}


class _RestoreEnvAndCwd(unittest.TestCase):
    """Shared discipline: any test here that touches REEFLEX_MCP_CONFIG /
    REEFLEX_CORE_URL / REEFLEX_CORE_TOKEN or os.chdir()s must leave the
    process exactly as it found it -- other test modules in the same run
    read cwd/env too."""

    _ENV_KEYS = ("REEFLEX_MCP_CONFIG", "REEFLEX_CORE_URL", "REEFLEX_CORE_TOKEN")

    def setUp(self) -> None:
        self._orig_cwd = os.getcwd()
        self._orig_env = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)
        # Default to an isolated throwaway cwd -- config.config_path()'s
        # relative default ("./reeflex-mcp.yaml") must never resolve into
        # (and write a stray file inside) the actual repo working tree just
        # because a test forgot to chdir. Tests that specifically exercise
        # the run-dir behavior (BUG 3(1)) chdir again to their own run_dir.
        os.chdir(tempfile.mkdtemp())

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestSetupWritesAbsoluteConfigPath(_RestoreEnvAndCwd):
    """BUG 3(1)."""

    def test_config_unset_resolves_to_absolute_from_the_setup_run_dir(self) -> None:
        client_path = _tmp_client_config(_SOME_CLIENT_ENTRY)
        # Where 'setup' is invoked from -- deliberately NOT where a client
        # would later launch the gateway from; the bug was that the path
        # written only ever worked from THIS directory.
        run_dir = tempfile.mkdtemp()
        os.chdir(run_dir)

        rc = cli.cmd_setup(_setup_args(path=str(client_path)))
        self.assertEqual(rc, 0)

        rewritten = client_configs.load_client_config(client_path)
        entry = client_configs.get_mcp_servers(rewritten)[client_configs.OWNERSHIP_NAME]
        args_list = entry["args"]
        self.assertIn("--config", args_list)
        written_path = args_list[args_list.index("--config") + 1]

        self.assertTrue(Path(written_path).is_absolute(), f"expected an absolute path, got {written_path!r}")
        # exactly config.config_path()'s relative default ("./reeflex-mcp.yaml"),
        # resolved from run_dir -- proving the resolution happened AT setup
        # time (this run_dir), not deferred to whatever cwd later launches
        # the gateway.
        self.assertEqual(written_path, str((Path(run_dir) / "reeflex-mcp.yaml").resolve()))

    def test_explicit_relative_config_arg_also_resolved_absolute(self) -> None:
        client_path = _tmp_client_config(_SOME_CLIENT_ENTRY)
        run_dir = tempfile.mkdtemp()
        os.chdir(run_dir)

        rc = cli.cmd_setup(_setup_args(path=str(client_path), config="my-reeflex-mcp.yaml"))
        self.assertEqual(rc, 0)

        rewritten = client_configs.load_client_config(client_path)
        entry = client_configs.get_mcp_servers(rewritten)[client_configs.OWNERSHIP_NAME]
        args_list = entry["args"]
        written_path = args_list[args_list.index("--config") + 1]

        self.assertTrue(Path(written_path).is_absolute())
        self.assertEqual(written_path, str((Path(run_dir) / "my-reeflex-mcp.yaml").resolve()))


class TestSetupWritesCoreEnv(_RestoreEnvAndCwd):
    """BUG 3(2)."""

    def test_env_carries_core_url_flag_and_observe_mode(self) -> None:
        client_path = _tmp_client_config(_SOME_CLIENT_ENTRY)
        os.environ["REEFLEX_CORE_TOKEN"] = "must-never-be-copied-into-the-written-file"

        rc = cli.cmd_setup(_setup_args(path=str(client_path), core_url="https://core.example.internal"))
        self.assertEqual(rc, 0)

        rewritten = client_configs.load_client_config(client_path)
        entry = client_configs.get_mcp_servers(rewritten)[client_configs.OWNERSHIP_NAME]

        self.assertEqual(
            entry["env"],
            {"REEFLEX_CORE_URL": "https://core.example.internal", "REEFLEX_MODE": "observe"},
        )
        # secrets by-reference: REEFLEX_CORE_TOKEN is never auto-populated
        # from this process's own environment into the written file.
        self.assertNotIn("REEFLEX_CORE_TOKEN", json.dumps(entry))

    def test_core_url_falls_back_to_env_then_config_default(self) -> None:
        client_path = _tmp_client_config(_SOME_CLIENT_ENTRY)

        # no --core-url, no $REEFLEX_CORE_URL -> config.core_url()'s own default.
        rc = cli.cmd_setup(_setup_args(path=str(client_path)))
        self.assertEqual(rc, 0)
        rewritten = client_configs.load_client_config(client_path)
        entry = client_configs.get_mcp_servers(rewritten)[client_configs.OWNERSHIP_NAME]
        self.assertEqual(entry["env"]["REEFLEX_CORE_URL"], "http://127.0.0.1:8080")
        self.assertEqual(entry["env"]["REEFLEX_MODE"], "observe")

        # $REEFLEX_CORE_URL set, no --core-url flag -> env wins over the hard default.
        client_path2 = _tmp_client_config(_SOME_CLIENT_ENTRY)
        os.environ["REEFLEX_CORE_URL"] = "http://core-from-env:8080"
        rc2 = cli.cmd_setup(_setup_args(path=str(client_path2)))
        self.assertEqual(rc2, 0)
        rewritten2 = client_configs.load_client_config(client_path2)
        entry2 = client_configs.get_mcp_servers(rewritten2)[client_configs.OWNERSHIP_NAME]
        self.assertEqual(entry2["env"]["REEFLEX_CORE_URL"], "http://core-from-env:8080")

    def test_mode_is_always_observe_never_enforce_even_if_environ_says_enforce(self) -> None:
        """Setup-time REEFLEX_MODE in the scaffolded entry is a FIXED
        'observe' -- it must never pick up this process's own REEFLEX_MODE
        (e.g. an operator running 'setup' from an enforce-mode shell must
        not accidentally scaffold a live client straight into enforce)."""
        client_path = _tmp_client_config(_SOME_CLIENT_ENTRY)
        os.environ["REEFLEX_MODE"] = "enforce"
        try:
            rc = cli.cmd_setup(_setup_args(path=str(client_path)))
        finally:
            os.environ.pop("REEFLEX_MODE", None)

        self.assertEqual(rc, 0)
        rewritten = client_configs.load_client_config(client_path)
        entry = client_configs.get_mcp_servers(rewritten)[client_configs.OWNERSHIP_NAME]
        self.assertEqual(entry["env"]["REEFLEX_MODE"], "observe")


if __name__ == "__main__":
    unittest.main()
