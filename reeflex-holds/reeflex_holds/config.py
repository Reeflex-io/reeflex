"""
config.py -- environment configuration for reeflex-holds.

All configuration is read fresh from os.environ on every call (no caching),
so tests and a running server can both change the environment and see the
new value on the very next call -- same idiom as reeflex-claude/enforce.py
and the WordPress adapter's class-reeflex-config.php.

Env vars:
  REEFLEX_CORE_URL     reeflex-core base URL. Default http://127.0.0.1:8080.
  REEFLEX_TOKEN        optional bearer token for the core holds API.
                        Added as "Authorization: Bearer <token>" when set and
                        non-blank. NEVER logged, never placed in an exception
                        message or any other output produced by this package.
  REEFLEX_PRINCIPAL    "type:id" of the principal resolving holds, e.g.
                        "human:leo" or "agent:triage-bot". Split on the FIRST
                        colon (an id may itself contain colons). Required only
                        for resolve_hold -- list_holds / get_hold / the freeze
                        probe need no principal.
  REEFLEX_VERIFY_SSL   default true (full TLS verification). Falsy values
                        (0/false/no/off, case-insensitive) DISABLE certificate
                        verification -- dev/self-signed endpoints only, at the
                        operator's own risk. Same env name and semantics as
                        reeflex-claude and the WordPress adapter, by the
                        project's standing TLS-verify-opt-out rule.
  REEFLEX_HOLDS_TIMEOUT  HTTP request timeout in seconds. Default 10.0.
                          Always applied (hard socket timeout) -- this package
                          never issues an unbounded request.

NOTE (flagged for the orchestrator): the other two adapters (reeflex-claude,
reeflex-wordpress) use REEFLEX_CORE_TOKEN for the bearer token. This package
uses REEFLEX_TOKEN per the brief that specified this package. If cross-surface
env-var parity is wanted, REEFLEX_TOKEN should be renamed to REEFLEX_CORE_TOKEN
in a follow-up -- not done here since the brief was explicit about the name.
"""

from __future__ import annotations

import os

_DEFAULT_CORE_URL = "http://127.0.0.1:8080"
_DEFAULT_TIMEOUT_SECONDS = 10.0

# Falsy string values for REEFLEX_VERIFY_SSL (case-insensitive).
# Anything else (including unset) is treated as truthy (verification ON).
_VERIFY_SSL_FALSY = frozenset({"0", "false", "no", "off"})


class ConfigError(Exception):
    """Raised when required configuration is missing or malformed.

    Distinct from network/HTTP errors (see client.py) -- this is always a
    local misconfiguration, never something reeflex-core said.
    """


def core_url() -> str:
    """Return the configured reeflex-core base URL, no trailing slash."""
    return os.environ.get("REEFLEX_CORE_URL", _DEFAULT_CORE_URL).rstrip("/")


def core_token() -> str:
    """Return the optional bearer token, or "" if unset/blank.

    Never logged: callers must not print or embed this value in any message.
    """
    return os.environ.get("REEFLEX_TOKEN", "").strip()


def verify_ssl() -> bool:
    """Parse REEFLEX_VERIFY_SSL. Default True (verification ON -- secure default).

    Falsy values (0/false/no/off, case-insensitive) -> False (opt-in insecure).
    """
    raw = os.environ.get("REEFLEX_VERIFY_SSL", "").strip().lower()
    return raw not in _VERIFY_SSL_FALSY


def timeout_seconds() -> float:
    """Parse REEFLEX_HOLDS_TIMEOUT; default 10.0 seconds. Never <= 0."""
    raw = os.environ.get("REEFLEX_HOLDS_TIMEOUT", "")
    try:
        value = float(raw)
        return value if value > 0 else _DEFAULT_TIMEOUT_SECONDS
    except (ValueError, TypeError):
        return _DEFAULT_TIMEOUT_SECONDS


def get_principal() -> tuple[str, str]:
    """Parse REEFLEX_PRINCIPAL ("type:id") into (type, id).

    Required only when resolving a hold. Raises ConfigError if unset or
    malformed -- this package never guesses or defaults a resolving identity.
    """
    raw = os.environ.get("REEFLEX_PRINCIPAL", "").strip()
    if not raw:
        raise ConfigError(
            "REEFLEX_PRINCIPAL is not set. Required to resolve a hold; "
            "format 'type:id', e.g. 'human:leo' or 'agent:triage-bot'."
        )
    if ":" not in raw:
        raise ConfigError(
            f"REEFLEX_PRINCIPAL={raw!r} is not in 'type:id' format "
            "(e.g. 'human:leo')."
        )
    principal_type, principal_id = raw.split(":", 1)
    principal_type = principal_type.strip()
    principal_id = principal_id.strip()
    if not principal_type or not principal_id:
        raise ConfigError(
            f"REEFLEX_PRINCIPAL={raw!r} has an empty type or id."
        )
    return principal_type, principal_id
