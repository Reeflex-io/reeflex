"""
core_client.py -- stdlib-only, fail-closed HTTP client for reeflex-core.

Wraps exactly the two endpoints this gateway needs (reeflex-core/app/server.py):

  POST /v1/decide   { ActionEnvelope } -> { Decision }
  GET  /healthz     -> {"status": "ok"} liveness only

THIN PIPE, by design (SPEC section 6 Adapter Contract): this module has NO
policy logic of its own and NEVER reinterprets a Decision. It distinguishes
two failure classes so a caller can fail closed correctly:

  CoreConnectionError -- core was not reached at all, or its response could
                         not be parsed as JSON (connection refused, DNS
                         failure, TLS failure, timeout, garbage body).
  CoreAPIError        -- core WAS reached and answered with a non-2xx status
                         that carries no usable "decision" field (a genuine
                         core-side error we cannot interpret as a verdict).

Note: reeflex-core's own internal-error path (server.py's do_POST wrapper)
still returns a structured `{"decision": "deny", ...}` body on HTTP 500
("failing closed" is core's own invariant too) -- `decide()` treats that as a
normal Decision, not an error, exactly like reeflex-claude/enforce.py does.
This is what lets a caller apply core's own fail-closed verdict verbatim
instead of re-deriving one.

stdlib only (urllib.request + ssl) -- `mcp` (the SDK) is this project's only
third-party dependency, reserved for the MCP protocol surface; this module
never imports it.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from . import config

_MAX_ERROR_LEN = 500  # truncate any external text embedded in an exception message


class CoreAPIError(Exception):
    """reeflex-core answered with a non-2xx status carrying no 'decision' field.

    `status` is the HTTP status code; `body` is core's parsed JSON body
    (whatever shape it happened to be, e.g. {"error": "invalid_json"}).
    """

    def __init__(self, status: int, body: Any, url: str):
        self.status = status
        self.body = body
        self.url = url
        detail = json.dumps(body, separators=(",", ":")) if isinstance(body, (dict, list)) else str(body)
        if len(detail) > _MAX_ERROR_LEN:
            detail = detail[:_MAX_ERROR_LEN] + "...[truncated]"
        super().__init__(f"reeflex-core HTTP {status} on {url}: {detail}")


class CoreConnectionError(Exception):
    """reeflex-core could not be reached or did not answer with valid JSON.

    Covers connection refused, DNS failure, TLS failure, timeout, and a
    response body that isn't parseable JSON. Distinct from CoreAPIError,
    which means core WAS reached and answered with a structured error.
    THIS is the case that must map to fail-closed (deny/hold), never allow.
    """


# ---------------------------------------------------------------------------
# Low-level request
# ---------------------------------------------------------------------------


def _build_ssl_context(url: str) -> ssl.SSLContext | None:
    """Return an SSLContext with verification disabled, or None (use urllib's
    secure default). Only relevant for https:// targets -- see config.verify_ssl.

    OPT-IN INSECURE -- dev/self-signed endpoints only, at the operator's risk.
    Mirrors reeflex-holds/client.py and reeflex-claude/enforce.py exactly.
    """
    if not url.lower().startswith("https://"):
        return None
    if config.verify_ssl():
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    token = config.core_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    # token is not referenced again in this module -- never logged.
    return headers


def _request(method: str, path: str, *, json_body: dict[str, Any] | None = None) -> tuple[int, dict]:
    """Perform one HTTP request against reeflex-core.

    Returns (status, parsed_json_body) for ANY well-formed HTTP response,
    2xx or not. Raises CoreConnectionError on transport failure or a
    response body that is not valid JSON.

    Always applies a hard timeout (config.core_timeout_seconds()) -- no
    unbounded request is ever made by this package.
    """
    base = config.core_url()
    url = f"{base}{path}"

    data = None
    headers = _headers()
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
    else:
        headers.pop("Content-Type", None)

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = _build_ssl_context(url)
    timeout = config.core_timeout_seconds()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    except urllib.error.URLError as exc:
        raise CoreConnectionError(f"reeflex-core unreachable at {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CoreConnectionError(f"reeflex-core request to {url} timed out after {timeout}s") from exc
    except Exception as exc:  # noqa: BLE001 -- any other transport failure
        raise CoreConnectionError(f"reeflex-core request to {url} failed: {exc}") from exc

    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CoreConnectionError(f"reeflex-core response from {url} was not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        parsed = {"value": parsed}

    return status, parsed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decide(envelope: dict) -> dict:
    """POST /v1/decide. Returns core's Decision dict verbatim (SPEC section 5).

    Raises:
      CoreConnectionError -- core unreachable / bad response. Caller MUST
                             treat this as fail-closed (deny/hold), never allow.
      CoreAPIError        -- core reached, non-2xx, and no usable 'decision'
                             field in the body (a genuine protocol mismatch,
                             e.g. 400 invalid_json, 401 unauthorized). Caller
                             MUST also treat this as fail-closed.

    This function never silently returns an "allow"-shaped fallback -- on any
    error it raises, so the caller's own fail-closed handling is exercised
    (never bypassed by a convenient default return value here).
    """
    status, parsed = _request("POST", "/v1/decide", json_body=envelope)
    if "decision" in parsed:
        # Present on 200, and on core's own fail-closed 500 body -- either way
        # this IS core's Decision, carried through verbatim (thin pipe).
        return parsed
    raise CoreAPIError(status, parsed, f"{config.core_url()}/v1/decide")


def healthz() -> bool:
    """GET /healthz. Best-effort liveness probe -- never raises.

    Returns True only on HTTP 200 with {"status": "ok"}. Any transport
    failure, non-200, or malformed body returns False. This is a read-only
    probe with no side effects; callers should not treat a False here as
    proof core is *down* for decision purposes -- only decide()'s own
    CoreConnectionError is the fail-closed signal that matters on the
    decision path. This helper exists for boot-time / doctor-style checks.
    """
    try:
        status, parsed = _request("GET", "/healthz")
    except CoreConnectionError:
        return False
    return status == 200 and parsed.get("status") == "ok"
