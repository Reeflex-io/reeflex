"""
client.py -- thin HTTP client for reeflex-core's HIL holds API.

Wraps exactly the three core holds endpoints plus a reachability probe
(reeflex-core/app/server.py):

  GET  /v1/holds?status=            -> list holds
  GET  /v1/holds/{id}               -> full hold detail (incl. envelope)
  POST /v1/holds/{id}/resolve       -> {decision, principal:{type,id}, reason?}
  GET  /healthz                     -> liveness only (see get_freeze_status)

THIN PIPE, by design (HIL Phase 2 T3 brief): this module has NO policy logic
of its own. Whether a principal may resolve a given hold -- the resolution
policy, actor != approver, R3/systemic immunity -- is decided entirely by
reeflex-core (see app/server.py's validation chain in _handle_resolve_hold).
A rejected call surfaces here as a HoldsAPIError carrying core's own status
code and JSON body verbatim; this client does not retry, override, or
reinterpret that decision.

stdlib only for the HTTP transport (urllib.request + ssl) -- the `mcp`
package (server.py) is this project's only third-party dependency.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import config

_MAX_ERROR_LEN = 500  # truncate any external text embedded in an exception message


class HoldsAPIError(Exception):
    """reeflex-core answered with a non-2xx status.

    `status` is the HTTP status code; `body` is core's parsed JSON error body
    (e.g. {"error": "actor_is_approver", "reason": "...", "hold_id": "..."}).
    This client never reinterprets or swallows the reason -- it is carried
    through verbatim for the MCP client (and the human/agent behind it) to see.
    """

    def __init__(self, status: int, body: dict, url: str):
        self.status = status
        self.body = body
        self.url = url
        reason = body.get("reason") or body.get("error") or "no reason given"
        detail = json.dumps(body, separators=(",", ":"))
        if len(detail) > _MAX_ERROR_LEN:
            detail = detail[:_MAX_ERROR_LEN] + "...[truncated]"
        super().__init__(f"reeflex-core HTTP {status} on {url}: {reason} -- {detail}")


class HoldsConnectionError(Exception):
    """reeflex-core could not be reached or did not answer with valid JSON.

    Covers connection refused, DNS failure, TLS failure, timeout, and a
    response body that isn't parseable JSON. Distinct from HoldsAPIError,
    which means core WAS reached and answered with a structured error.
    """


# ---------------------------------------------------------------------------
# Low-level request
# ---------------------------------------------------------------------------

def _build_ssl_context(url: str) -> ssl.SSLContext | None:
    """Return an SSLContext with verification disabled, or None (use urllib's
    secure default). Only relevant for https:// targets -- see config.verify_ssl.

    OPT-IN INSECURE -- dev/self-signed endpoints only, at the operator's risk.
    Same behavior as reeflex-claude/enforce.py's _build_ssl_context.
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
    headers = {"Accept": "application/json"}
    token = config.core_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    # token is not referenced again in this module -- never logged.
    return headers


def _request(
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> tuple[int, dict]:
    """Perform one HTTP request against reeflex-core.

    Returns (status, parsed_json_body) for ANY well-formed HTTP response,
    2xx or not -- callers that want "raise on error" should use
    `_request_ok`. Raises HoldsConnectionError on transport failure or a
    response body that is not valid JSON (core never returns non-JSON, so
    this indicates a genuinely broken connection/proxy).

    Always applies a hard timeout (config.timeout_seconds()) -- no unbounded
    request is ever made by this package.
    """
    base = config.core_url()
    url = f"{base}{path}"
    if query:
        clean = {k: v for k, v in query.items() if v is not None}
        qs = urllib.parse.urlencode(clean)
        if qs:
            url = f"{url}?{qs}"

    data = None
    headers = _headers()
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = _build_ssl_context(url)
    timeout = config.timeout_seconds()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    except urllib.error.URLError as exc:
        raise HoldsConnectionError(f"reeflex-core unreachable at {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise HoldsConnectionError(f"reeflex-core request to {url} timed out after {timeout}s") from exc
    except Exception as exc:  # noqa: BLE001 -- any other transport failure
        raise HoldsConnectionError(f"reeflex-core request to {url} failed: {exc}") from exc

    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HoldsConnectionError(
            f"reeflex-core response from {url} was not valid JSON: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        parsed = {"value": parsed}

    return status, parsed


def _request_ok(
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict:
    """`_request` wrapper that raises HoldsAPIError on any non-2xx status."""
    status, parsed = _request(method, path, query=query, json_body=json_body)
    if status < 200 or status >= 300:
        raise HoldsAPIError(status, parsed, f"{config.core_url()}{path}")
    return parsed


# ---------------------------------------------------------------------------
# Public API -- one function per MCP tool (see server.py)
# ---------------------------------------------------------------------------

def list_holds(status: str | None = None) -> dict:
    """GET /v1/holds?status=<status>.

    status: pending|approved|rejected|expired|consumed, or None for no filter
    (core's default: all statuses, most recent 100).
    Returns core's paged shape verbatim: {"items": [...], "count": N,
    "next_cursor"?: "..."}.
    """
    return _request_ok("GET", "/v1/holds", query={"status": status})


def get_hold(hold_id: str) -> dict:
    """GET /v1/holds/{id}. Raises HoldsAPIError(status=404) if not found."""
    safe_id = urllib.parse.quote(hold_id, safe="")
    return _request_ok("GET", f"/v1/holds/{safe_id}")


def resolve_hold(hold_id: str, decision: str, reason: str | None = None) -> dict:
    """POST /v1/holds/{id}/resolve, resolving as config.get_principal().

    decision must be "approve" or "reject" -- core's exact vocabulary.
    The principal is ALWAYS read from REEFLEX_PRINCIPAL (config.py), never
    accepted as a parameter here or in the MCP tool -- this is the
    anti-impersonation guarantee: an MCP client cannot resolve a hold "as"
    an arbitrary identity by simply asking to.

    Core independently enforces (this client does not duplicate any of it):
    the hold must be pending and not expired; the rule must be resolvable
    (irreversible_systemic_prod never is); REEFLEX_PRINCIPAL's type must be
    allowed to resolve this rule per the operator's resolution policy; and
    the resolving principal must not be the same identity as the agent that
    triggered the hold (actor != approver). A rejection from any of those
    checks surfaces here as HoldsAPIError, unmodified.
    """
    if decision not in ("approve", "reject"):
        raise ValueError(f"decision must be 'approve' or 'reject', got {decision!r}")

    principal_type, principal_id = config.get_principal()
    safe_id = urllib.parse.quote(hold_id, safe="")
    body: dict[str, Any] = {
        "decision": decision,
        "principal": {"type": principal_type, "id": principal_id},
    }
    if reason:
        body["reason"] = reason
    return _request_ok("POST", f"/v1/holds/{safe_id}/resolve", json_body=body)


def get_freeze_status() -> dict:
    """Best-effort reachability probe -- NOT a real freeze-state query.

    reeflex-core has NO dedicated freeze-status endpoint: REEFLEX_FREEZE is an
    operator-side environment variable, re-read fresh on every /v1/decide call
    (see reeflex-core/app/decide.py _read_freeze), and it is never exposed via
    the HTTP API. Inventing such an endpoint here would violate this package's
    "thin consumer" contract (SPEC / HIL Phase 2 T3 brief), so this function
    does NOT claim to know the REEFLEX_FREEZE boolean.

    What it DOES do: a GET /healthz call -- the only universally
    unauthenticated, side-effect-free endpoint reeflex-core exposes -- to
    report whether core is reachable at all. That is the entirety of what
    "freeze status" can mean from outside core today.
    """
    _FREEZE_NOTE = (
        "reeflex-core has no dedicated freeze-status endpoint; REEFLEX_FREEZE "
        "is an operator-side environment variable re-read on every /v1/decide "
        "call (see reeflex-core/app/decide.py), never exposed via the HTTP "
        "API. This is a best-effort GET /healthz reachability probe only -- "
        "it cannot report the actual REEFLEX_FREEZE value. To infer freeze "
        "state: ask the operator directly, or watch for repeated "
        "'reeflex.policy/frozen' denials in /v1/decide responses or the "
        "audit log."
    )
    try:
        status, parsed = _request("GET", "/healthz")
    except HoldsConnectionError as exc:
        return {
            "core_reachable": False,
            "freeze_state": "unknown",
            "note": f"core unreachable: {exc}. {_FREEZE_NOTE}",
        }
    reachable = status == 200 and parsed.get("status") == "ok"
    return {
        "core_reachable": reachable,
        "freeze_state": "unknown",
        "note": _FREEZE_NOTE,
    }
