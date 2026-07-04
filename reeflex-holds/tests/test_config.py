"""
test_config.py -- unit tests for reeflex_holds.config.

Pure tests, no network. Every test saves/restores the env vars it touches.
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_holds import config  # noqa: E402

_ENV_KEYS = (
    "REEFLEX_CORE_URL",
    "REEFLEX_TOKEN",
    "REEFLEX_PRINCIPAL",
    "REEFLEX_VERIFY_SSL",
    "REEFLEX_HOLDS_TIMEOUT",
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
        os.environ["REEFLEX_CORE_URL"] = "https://api.reeflex.io/"
        self.assertEqual(config.core_url(), "https://api.reeflex.io")


class TestCoreToken(_EnvIsolated):
    def test_unset_returns_empty(self) -> None:
        self.assertEqual(config.core_token(), "")

    def test_set_returns_value(self) -> None:
        os.environ["REEFLEX_TOKEN"] = "s3cr3t"
        self.assertEqual(config.core_token(), "s3cr3t")

    def test_blank_treated_as_empty(self) -> None:
        os.environ["REEFLEX_TOKEN"] = "   "
        self.assertEqual(config.core_token(), "")


class TestVerifySsl(_EnvIsolated):
    def test_unset_defaults_true(self) -> None:
        self.assertTrue(config.verify_ssl())

    def test_falsy_values_disable(self) -> None:
        for val in ("0", "false", "no", "off", "FALSE", "Off", "NO"):
            os.environ["REEFLEX_VERIFY_SSL"] = val
            self.assertFalse(config.verify_ssl(), f"expected False for {val!r}")

    def test_truthy_and_other_values_keep_on(self) -> None:
        for val in ("1", "true", "yes", "on", "anything-else"):
            os.environ["REEFLEX_VERIFY_SSL"] = val
            self.assertTrue(config.verify_ssl(), f"expected True for {val!r}")


class TestTimeoutSeconds(_EnvIsolated):
    def test_default(self) -> None:
        self.assertEqual(config.timeout_seconds(), 10.0)

    def test_custom(self) -> None:
        os.environ["REEFLEX_HOLDS_TIMEOUT"] = "2.5"
        self.assertEqual(config.timeout_seconds(), 2.5)

    def test_invalid_falls_back_to_default(self) -> None:
        os.environ["REEFLEX_HOLDS_TIMEOUT"] = "not-a-number"
        self.assertEqual(config.timeout_seconds(), 10.0)

    def test_non_positive_falls_back_to_default(self) -> None:
        os.environ["REEFLEX_HOLDS_TIMEOUT"] = "-5"
        self.assertEqual(config.timeout_seconds(), 10.0)


class TestGetPrincipal(_EnvIsolated):
    def test_unset_raises(self) -> None:
        with self.assertRaises(config.ConfigError):
            config.get_principal()

    def test_missing_colon_raises(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "not-a-valid-principal"
        with self.assertRaises(config.ConfigError):
            config.get_principal()

    def test_valid_human(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:leo"
        self.assertEqual(config.get_principal(), ("human", "leo"))

    def test_valid_agent(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "agent:triage-bot"
        self.assertEqual(config.get_principal(), ("agent", "triage-bot"))

    def test_id_with_colon_splits_on_first_colon_only(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:leo:extra"
        self.assertEqual(config.get_principal(), ("human", "leo:extra"))

    def test_empty_type_raises(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = ":leo"
        with self.assertRaises(config.ConfigError):
            config.get_principal()

    def test_empty_id_raises(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "human:"
        with self.assertRaises(config.ConfigError):
            config.get_principal()

    def test_whitespace_is_stripped(self) -> None:
        os.environ["REEFLEX_PRINCIPAL"] = "  human : leo  "
        self.assertEqual(config.get_principal(), ("human", "leo"))


if __name__ == "__main__":
    unittest.main()
