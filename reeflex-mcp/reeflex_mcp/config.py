"""
config.py -- environment configuration for reeflex-mcp.

All configuration is read FRESH from os.environ on every call (no caching),
same idiom as reeflex-holds/config.py, reeflex-claude/enforce.py, and the
WordPress adapter's class-reeflex-config.php -- a running gateway and a test
can both change the environment and see the new value on the very next call.

Env vars:
  REEFLEX_CORE_URL      reeflex-core base URL. Default http://127.0.0.1:8080.
  REEFLEX_CORE_TOKEN    optional bearer token for reeflex-core's /v1/decide.
                        Added as "Authorization: Bearer <token>" when set and
                        non-blank. NEVER logged. This is the project-standard
                        name (design doc D5) -- reeflex-holds' REEFLEX_TOKEN is
                        a documented outlier, not followed here.
  REEFLEX_MODE          "observe" (default) | "enforce". Gateway-side only --
                        core does not branch on mode. See gateway.py for what
                        each mode does (Track 2: observe is the fully-built
                        path; enforce is a minimal, fail-closed scaffold --
                        see gateway.py module docstring).
  REEFLEX_VERIFY_SSL    default true (full TLS verification). Falsy values
                        (0/false/no/off, case-insensitive) DISABLE certificate
                        verification -- dev/self-signed endpoints only, at the
                        operator's own risk (project standing rule).
  REEFLEX_MCP_TIMEOUT   HTTP request timeout in seconds for calls to
                        reeflex-core. Default 10.0. Always applied (hard
                        socket timeout) -- core_client never issues an
                        unbounded request.
  REEFLEX_MCP_CONFIG    path to reeflex-mcp.yaml. Default "./reeflex-mcp.yaml".
  REEFLEX_MCP_TRANSPORT front transport: "stdio" (default) | "streamable-http".
  REEFLEX_MCP_HOST      bind host for streamable-http transport. Default 127.0.0.1.
  REEFLEX_MCP_PORT      bind port for streamable-http transport. Default 8000
                        (deliberately distinct from reeflex-core's 8080).
  REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT
                        seconds allowed for each upstream connect() at boot
                        before it is treated as unreachable (SPEC section 21.2
                        fail-closed-at-boot). Default 10.0.
  REEFLEX_MCP_CALL_TIMEOUT
                        seconds allowed for a single dispatched tools/call to
                        an upstream (SPEC section 21.5 dispatch-with-timeout).
                        Default 30.0.
  REEFLEX_MCP_MAPPINGS_DIR
                        Track 4 (design doc section 8): directory of
                        declarative `<system>.yaml` mapping files. Overrides
                        the YAML registry's own `mappings_dir:` key when set
                        (see registry.effective_mappings_dir()). Unset/blank
                        -> None, meaning "use the YAML value, or failing
                        that this package's own bundled starter mappings"
                        (mappings.DEFAULT_MAPPINGS_DIR).
"""

from __future__ import annotations

import os

_DEFAULT_CORE_URL = "http://127.0.0.1:8080"
_DEFAULT_CORE_TIMEOUT_SECONDS = 10.0
_DEFAULT_CONFIG_PATH = "./reeflex-mcp.yaml"
_DEFAULT_TRANSPORT = "stdio"
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8000
_DEFAULT_UPSTREAM_CONNECT_TIMEOUT = 10.0
_DEFAULT_CALL_TIMEOUT = 30.0

# Falsy string values for REEFLEX_VERIFY_SSL (case-insensitive).
# Anything else (including unset) is treated as truthy (verification ON).
_VERIFY_SSL_FALSY = frozenset({"0", "false", "no", "off"})

_VALID_MODES = frozenset({"observe", "enforce"})
_VALID_TRANSPORTS = frozenset({"stdio", "streamable-http"})


class ConfigError(Exception):
    """Raised when required configuration is missing or malformed.

    Distinct from network/HTTP errors (see core_client.py) -- this is always
    a local misconfiguration, never something reeflex-core said.
    """


def core_url() -> str:
    """Return the configured reeflex-core base URL, no trailing slash."""
    return os.environ.get("REEFLEX_CORE_URL", _DEFAULT_CORE_URL).rstrip("/")


def core_token() -> str:
    """Return the optional bearer token, or "" if unset/blank.

    Never logged: callers must not print or embed this value in any message.
    """
    return os.environ.get("REEFLEX_CORE_TOKEN", "").strip()


def verify_ssl() -> bool:
    """Parse REEFLEX_VERIFY_SSL. Default True (verification ON -- secure default).

    Falsy values (0/false/no/off, case-insensitive) -> False (opt-in insecure).
    """
    raw = os.environ.get("REEFLEX_VERIFY_SSL", "").strip().lower()
    return raw not in _VERIFY_SSL_FALSY


def core_timeout_seconds() -> float:
    """Parse REEFLEX_MCP_TIMEOUT; default 10.0 seconds. Never <= 0."""
    raw = os.environ.get("REEFLEX_MCP_TIMEOUT", "")
    try:
        value = float(raw)
        return value if value > 0 else _DEFAULT_CORE_TIMEOUT_SECONDS
    except (ValueError, TypeError):
        return _DEFAULT_CORE_TIMEOUT_SECONDS


def mode() -> str:
    """Parse REEFLEX_MODE. Default "observe". Unknown values -> "observe"
    (the never-breaks-traffic default), never silently "enforce".

    A reeflex-mcp.yaml `mode:` key can lower this default when config.py's
    caller decides to; registry.py resolves the final precedence (env
    overrides file -- see registry.py effective_mode()).
    """
    raw = os.environ.get("REEFLEX_MODE", "observe").strip().lower()
    return raw if raw in _VALID_MODES else "observe"


def config_path() -> str:
    """Path to reeflex-mcp.yaml. Default "./reeflex-mcp.yaml"."""
    return os.environ.get("REEFLEX_MCP_CONFIG", "").strip() or _DEFAULT_CONFIG_PATH


def mappings_dir_env() -> str | None:
    """Raw REEFLEX_MCP_MAPPINGS_DIR, or None if unset/blank. See
    registry.effective_mappings_dir() for the full env-over-YAML precedence
    (mirrors effective_mode()'s pattern)."""
    raw = os.environ.get("REEFLEX_MCP_MAPPINGS_DIR", "").strip()
    return raw or None


def transport() -> str:
    """Front transport. Default "stdio"."""
    raw = os.environ.get("REEFLEX_MCP_TRANSPORT", "").strip().lower()
    return raw if raw in _VALID_TRANSPORTS else _DEFAULT_TRANSPORT


def host() -> str:
    return os.environ.get("REEFLEX_MCP_HOST", "").strip() or _DEFAULT_HOST


def port() -> int:
    raw = os.environ.get("REEFLEX_MCP_PORT", "")
    try:
        value = int(raw)
        return value if value > 0 else _DEFAULT_PORT
    except (ValueError, TypeError):
        return _DEFAULT_PORT


def upstream_connect_timeout_seconds() -> float:
    """Per-upstream connect() timeout at boot; default 10.0s. Never <= 0."""
    raw = os.environ.get("REEFLEX_MCP_UPSTREAM_CONNECT_TIMEOUT", "")
    try:
        value = float(raw)
        return value if value > 0 else _DEFAULT_UPSTREAM_CONNECT_TIMEOUT
    except (ValueError, TypeError):
        return _DEFAULT_UPSTREAM_CONNECT_TIMEOUT


def call_timeout_seconds() -> float:
    """Per-call dispatch timeout to an upstream; default 30.0s. Never <= 0."""
    raw = os.environ.get("REEFLEX_MCP_CALL_TIMEOUT", "")
    try:
        value = float(raw)
        return value if value > 0 else _DEFAULT_CALL_TIMEOUT
    except (ValueError, TypeError):
        return _DEFAULT_CALL_TIMEOUT
