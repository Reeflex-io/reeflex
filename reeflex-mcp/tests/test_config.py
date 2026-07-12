"""
test_config.py -- unit tests for reeflex_mcp.config.

Pure tests, no network. Every test saves/restores the env vars it touches.
"""

from __future__ import annotations

import os
import unittest

from reeflex_mcp import config

_ENV_KEYS = (
    "REEFLEX_CORE_URL",
    "REEFLEX_CORE_TOKEN",
    "REEFLEX_MODE",
    "REEFLEX_VERIFY_SSL",
    "REEFLEX_MCP_TIMEOUT",
    "REEFLEX_MCP_CONFIG",
    "REEFLEX_MCP_TRANSPORT",
    "REEFLEX_MCP_HOST",
    "REEFLEX_MCP_PORT",
    "REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT",
    "REEFLEX_MCP_CALL_TIMEOUT",
)


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


class TestCoreUrl(_EnvIsolated):
    def test_default(self) -> None:
        self.assertEqual(config.core_url(), "http://127.0.0.1:8080")

    def test_custom_strips_trailing_slash(self) -> None:
        os.environ["REEFLEX_CORE_URL"] = "https://gateway.example/"
        self.assertEqual(config.core_url(), "https://gateway.example")


class TestCoreToken(_EnvIsolated):
    def test_unset_returns_empty(self) -> None:
        self.assertEqual(config.core_token(), "")

    def test_standardized_on_core_token_name(self) -> None:
        # D5 (design doc section 19): REEFLEX_CORE_TOKEN, NOT reeflex-holds'
        # REEFLEX_TOKEN outlier.
        os.environ["REEFLEX_CORE_TOKEN"] = "s3cr3t"
        self.assertEqual(config.core_token(), "s3cr3t")
        os.environ["REEFLEX_TOKEN"] = "wrong-var"
        self.assertEqual(config.core_token(), "s3cr3t")

    def test_blank_treated_as_empty(self) -> None:
        os.environ["REEFLEX_CORE_TOKEN"] = "   "
        self.assertEqual(config.core_token(), "")


class TestVerifySsl(_EnvIsolated):
    def test_unset_defaults_true(self) -> None:
        self.assertTrue(config.verify_ssl())

    def test_falsy_values_disable(self) -> None:
        for val in ("0", "false", "no", "off", "FALSE", "Off"):
            os.environ["REEFLEX_VERIFY_SSL"] = val
            self.assertFalse(config.verify_ssl(), f"expected False for {val!r}")

    def test_truthy_and_other_values_keep_on(self) -> None:
        for val in ("1", "true", "yes", "anything-else"):
            os.environ["REEFLEX_VERIFY_SSL"] = val
            self.assertTrue(config.verify_ssl(), f"expected True for {val!r}")


class TestCoreTimeoutSeconds(_EnvIsolated):
    def test_default(self) -> None:
        self.assertEqual(config.core_timeout_seconds(), 10.0)

    def test_custom(self) -> None:
        os.environ["REEFLEX_MCP_TIMEOUT"] = "2.5"
        self.assertEqual(config.core_timeout_seconds(), 2.5)

    def test_invalid_falls_back(self) -> None:
        os.environ["REEFLEX_MCP_TIMEOUT"] = "nope"
        self.assertEqual(config.core_timeout_seconds(), 10.0)

    def test_non_positive_falls_back(self) -> None:
        os.environ["REEFLEX_MCP_TIMEOUT"] = "-1"
        self.assertEqual(config.core_timeout_seconds(), 10.0)


class TestMode(_EnvIsolated):
    def test_default_is_observe(self) -> None:
        self.assertEqual(config.mode(), "observe")

    def test_enforce_recognized(self) -> None:
        os.environ["REEFLEX_MODE"] = "enforce"
        self.assertEqual(config.mode(), "enforce")

    def test_unknown_falls_back_to_observe(self) -> None:
        os.environ["REEFLEX_MODE"] = "yolo"
        self.assertEqual(config.mode(), "observe")

    def test_case_insensitive(self) -> None:
        os.environ["REEFLEX_MODE"] = "ENFORCE"
        self.assertEqual(config.mode(), "enforce")


class TestConfigPath(_EnvIsolated):
    def test_default(self) -> None:
        self.assertEqual(config.config_path(), "./reeflex-mcp.yaml")

    def test_custom(self) -> None:
        os.environ["REEFLEX_MCP_CONFIG"] = "/etc/reeflex/gateway.yaml"
        self.assertEqual(config.config_path(), "/etc/reeflex/gateway.yaml")


class TestTransport(_EnvIsolated):
    def test_default(self) -> None:
        self.assertEqual(config.transport(), "stdio")

    def test_streamable_http(self) -> None:
        os.environ["REEFLEX_MCP_TRANSPORT"] = "streamable-http"
        self.assertEqual(config.transport(), "streamable-http")

    def test_unknown_falls_back(self) -> None:
        os.environ["REEFLEX_MCP_TRANSPORT"] = "carrier-pigeon"
        self.assertEqual(config.transport(), "stdio")


class TestHostPort(_EnvIsolated):
    def test_defaults(self) -> None:
        self.assertEqual(config.host(), "127.0.0.1")
        self.assertEqual(config.port(), 8000)

    def test_custom(self) -> None:
        os.environ["REEFLEX_MCP_HOST"] = "0.0.0.0"
        os.environ["REEFLEX_MCP_PORT"] = "9100"
        self.assertEqual(config.host(), "0.0.0.0")
        self.assertEqual(config.port(), 9100)

    def test_invalid_port_falls_back(self) -> None:
        os.environ["REEFLEX_MCP_PORT"] = "not-a-port"
        self.assertEqual(config.port(), 8000)


class TestTimeouts(_EnvIsolated):
    def test_upstream_connect_default(self) -> None:
        self.assertEqual(config.upstream_connect_timeout_seconds(), 10.0)

    def test_call_timeout_default(self) -> None:
        self.assertEqual(config.call_timeout_seconds(), 30.0)

    def test_both_customizable(self) -> None:
        os.environ["REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT"] = "3"
        os.environ["REEFLEX_MCP_CALL_TIMEOUT"] = "60"
        self.assertEqual(config.upstream_connect_timeout_seconds(), 3.0)
        self.assertEqual(config.call_timeout_seconds(), 60.0)


if __name__ == "__main__":
    unittest.main()
