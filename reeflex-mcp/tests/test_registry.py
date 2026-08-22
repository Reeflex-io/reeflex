"""
test_registry.py -- unit tests for reeflex_mcp.registry (reeflex-mcp.yaml
parsing + mode precedence + client/session lookup).
"""

from __future__ import annotations

import os
import tempfile
import unittest

from reeflex_mcp import registry

_ENV_KEYS = ("REEFLEX_MODE", "CLIENT_A_TOKEN", "CLIENT_B_TOKEN")


class _EnvIsolated(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _write_yaml(text: str) -> str:
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(text)
    fh.close()
    return fh.name


_MINIMAL_STDIO = """
upstreams:
  - name: fs
    command: ["python", "server.py"]
    target: { system: filesystem, environment: staging }
"""

_MINIMAL_HTTP = """
mode: enforce
upstreams:
  - name: gh
    url: https://mcp.internal/github
    auth: { token_env: GH_MCP_TOKEN }
    target: { system: github, environment: production }
"""

_WITH_CLIENTS = """
upstreams:
  - name: fs
    command: ["python", "server.py"]
    target: { system: filesystem, environment: dev }
clients:
  - token_env: CLIENT_A_TOKEN
    session_id: agent:alice
  - token_env: CLIENT_B_TOKEN
    session_id: agent:bob
"""


class TestLoadConfigStdio(_EnvIsolated):
    def test_parses_stdio_upstream(self) -> None:
        path = _write_yaml(_MINIMAL_STDIO)
        try:
            cfg = registry.load_config(path)
            self.assertEqual(len(cfg.upstreams), 1)
            up = cfg.upstreams[0]
            self.assertEqual(up.kind, "stdio")
            self.assertEqual(up.name, "fs")
            self.assertEqual(up.command, "python")
            self.assertEqual(up.args, ("server.py",))
            self.assertEqual(up.target_system, "filesystem")
            self.assertEqual(up.target_environment, "staging")
            self.assertTrue(up.required)
            self.assertIsNone(cfg.file_mode)
        finally:
            os.unlink(path)


class TestLoadConfigHttp(_EnvIsolated):
    def test_parses_http_upstream_and_mode(self) -> None:
        path = _write_yaml(_MINIMAL_HTTP)
        try:
            cfg = registry.load_config(path)
            up = cfg.upstreams[0]
            self.assertEqual(up.kind, "http")
            self.assertEqual(up.url, "https://mcp.internal/github")
            self.assertEqual(up.auth_token_env, "GH_MCP_TOKEN")
            self.assertEqual(up.target_environment, "production")
            self.assertEqual(cfg.file_mode, "enforce")
        finally:
            os.unlink(path)


class TestLoadConfigValidation(_EnvIsolated):
    def test_missing_file_raises(self) -> None:
        with self.assertRaises(registry.ConfigError):
            registry.load_config("/no/such/path/reeflex-mcp.yaml")

    def test_not_a_mapping_raises(self) -> None:
        path = _write_yaml("- just\n- a\n- list\n")
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_empty_upstreams_raises(self) -> None:
        path = _write_yaml("upstreams: []\n")
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_both_command_and_url_raises(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: bad
    command: ["python", "x.py"]
    url: https://example.com
    target: { system: x, environment: dev }
"""
        )
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_neither_command_nor_url_raises(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: bad
    target: { system: x, environment: dev }
"""
        )
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_invalid_environment_raises(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: bad
    command: ["python", "x.py"]
    target: { system: x, environment: prod }
"""
        )
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_duplicate_name_raises(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: fs
    command: ["python", "a.py"]
    target: { system: x, environment: dev }
  - name: fs
    command: ["python", "b.py"]
    target: { system: y, environment: dev }
"""
        )
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_double_underscore_in_name_raises(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: fs__weird
    command: ["python", "a.py"]
    target: { system: x, environment: dev }
"""
        )
        try:
            with self.assertRaises(registry.ConfigError):
                registry.load_config(path)
        finally:
            os.unlink(path)

    def test_required_false_parsed(self) -> None:
        path = _write_yaml(
            """
upstreams:
  - name: fs
    command: ["python", "a.py"]
    target: { system: x, environment: dev }
    required: false
"""
        )
        try:
            cfg = registry.load_config(path)
            self.assertFalse(cfg.upstreams[0].required)
        finally:
            os.unlink(path)


class TestTrustAnnotations(_EnvIsolated):
    """RFX-173: whether an upstream is allowed to classify its own tools from
    its own MCP annotations. Per-upstream, boolean, default False."""

    _TWO_UPSTREAMS = """
upstreams:
  - name: audited
    command: ["python", "server.py"]
    target: { system: filesystem, environment: production }
    trust_annotations: true
  - name: thirdparty
    url: https://mcp.example.com/thing
    target: { system: thing, environment: production }
"""

    def test_defaults_to_false(self) -> None:
        path = _write_yaml(_MINIMAL_STDIO)
        try:
            cfg = registry.load_config(path)
            self.assertFalse(cfg.upstreams[0].trust_annotations)
        finally:
            os.unlink(path)

    def test_is_per_upstream_not_global(self) -> None:
        # Trusting the server you audited must NOT extend to the one added
        # next week -- that is the whole point of the flag being per-upstream.
        path = _write_yaml(self._TWO_UPSTREAMS)
        try:
            cfg = registry.load_config(path)
            by_name = {u.name: u for u in cfg.upstreams}
            self.assertTrue(by_name["audited"].trust_annotations)
            self.assertFalse(by_name["thirdparty"].trust_annotations)
        finally:
            os.unlink(path)

    def test_non_boolean_is_a_hard_config_error(self) -> None:
        # A truthy string like "false" silently enabling the trusted tier is
        # exactly the near-miss class this flag exists to prevent.
        for bad in ('"false"', '"yes"', "1", "[]"):
            path = _write_yaml(
                "upstreams:\n"
                "  - name: fs\n"
                '    command: ["python", "server.py"]\n'
                "    target: { system: filesystem, environment: production }\n"
                f"    trust_annotations: {bad}\n"
            )
            try:
                with self.assertRaises(registry.ConfigError, msg=bad):
                    registry.load_config(path)
            finally:
                os.unlink(path)


class TestEffectiveMode(_EnvIsolated):
    def test_file_mode_used_when_env_unset(self) -> None:
        cfg = registry.GatewayConfig(file_mode="enforce", upstreams=(), clients=(), source_path="x")
        self.assertEqual(registry.effective_mode(cfg), "enforce")

    def test_defaults_to_observe_when_neither_set(self) -> None:
        cfg = registry.GatewayConfig(file_mode=None, upstreams=(), clients=(), source_path="x")
        self.assertEqual(registry.effective_mode(cfg), "observe")

    def test_env_overrides_file(self) -> None:
        os.environ["REEFLEX_MODE"] = "observe"
        cfg = registry.GatewayConfig(file_mode="enforce", upstreams=(), clients=(), source_path="x")
        self.assertEqual(registry.effective_mode(cfg), "observe")


class TestClientSessionLookup(_EnvIsolated):
    def test_maps_token_to_session_id(self) -> None:
        path = _write_yaml(_WITH_CLIENTS)
        try:
            cfg = registry.load_config(path)
            os.environ["CLIENT_A_TOKEN"] = "tok-alice"
            os.environ["CLIENT_B_TOKEN"] = "tok-bob"
            self.assertEqual(registry.session_id_for_token(cfg, "tok-alice"), "agent:alice")
            self.assertEqual(registry.session_id_for_token(cfg, "tok-bob"), "agent:bob")
            self.assertIsNone(registry.session_id_for_token(cfg, "unknown-token"))
            self.assertIsNone(registry.session_id_for_token(cfg, None))
        finally:
            os.unlink(path)

    def test_resolves_fresh_not_cached(self) -> None:
        # rotating the env var takes effect on the next call, no restart.
        path = _write_yaml(_WITH_CLIENTS)
        try:
            cfg = registry.load_config(path)
            os.environ["CLIENT_A_TOKEN"] = "old-token"
            self.assertEqual(registry.session_id_for_token(cfg, "old-token"), "agent:alice")
            os.environ["CLIENT_A_TOKEN"] = "new-token"
            self.assertIsNone(registry.session_id_for_token(cfg, "old-token"))
            self.assertEqual(registry.session_id_for_token(cfg, "new-token"), "agent:alice")
        finally:
            os.unlink(path)


class TestResolveEnvRef(_EnvIsolated):
    def test_none_name_returns_none(self) -> None:
        self.assertIsNone(registry.resolve_env_ref(None))

    def test_unset_returns_none(self) -> None:
        self.assertIsNone(registry.resolve_env_ref("CLIENT_A_TOKEN"))

    def test_blank_returns_none(self) -> None:
        os.environ["CLIENT_A_TOKEN"] = "   "
        self.assertIsNone(registry.resolve_env_ref("CLIENT_A_TOKEN"))

    def test_set_returns_value(self) -> None:
        os.environ["CLIENT_A_TOKEN"] = "s3cr3t"
        self.assertEqual(registry.resolve_env_ref("CLIENT_A_TOKEN"), "s3cr3t")


if __name__ == "__main__":
    unittest.main()
