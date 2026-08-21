"""
server.py — Minimal HTTP layer for POST /v1/decide + HIL holds API.

Uses Python stdlib http.server only — zero external dependencies.
Binds to HOST:PORT from env REEFLEX_HOST (default 127.0.0.1) and
REEFLEX_PORT (default 8080).

Routes:
  POST /v1/decide                    { ActionEnvelope } -> { Decision }    200/400/500
  GET  /v1/holds?status=&limit=&cursor=   -> JSON list (paged)             200/401
  GET  /v1/holds/{id}                -> full hold detail                   200/401/404
  POST /v1/holds/{id}/resolve        -> resolve a pending hold             200/401/403/404/409
  GET  /healthz                      -> {"status":"ok"}                    200

All other paths/methods -> HTTP 404 or 405.

Content-Type for all responses: application/json; charset=utf-8.

Auth (optional bearer token):
  If env REEFLEX_AUTH_TOKEN is set, ALL routes EXCEPT GET /healthz require
  "Authorization: Bearer <token>"; missing or wrong token -> HTTP 401.
  If REEFLEX_AUTH_TOKEN is unset/empty, auth is disabled (backward compatible).
  GET /healthz is always unauthenticated.

Security hardening (applied to all responses):
  - Server banner suppressed to "reeflex-core".
  - Security headers: X-Content-Type-Options: nosniff, Cache-Control: no-store.
  - Request body size cap: 413 if Content-Length exceeds REEFLEX_MAX_BODY_BYTES
    (default 256 KB) — DoS guard.
  - Unsupported HTTP methods return 405 JSON, not 501 HTML.

=============================================================================
HOLDS API VALIDATION (POST /v1/holds/{id}/resolve)
=============================================================================

Request body: {decision:"approve"|"reject", principal:{type,id}, reason?}

Validation chain (first failure -> 4xx JSON with reason code):
  1. hold exists + status==pending + not expired  else 404/409 "not_resolvable"
  2. NON_RESOLVABLE_RULES guard                   else 403 "rule_not_resolvable"
  3. resolution policy (principal.type allowed)   else 403 "principal_type_not_allowed"
  4. approver is VERIFIABLE (RFX-CORE-2)          else 403 "principal_mismatch"
                                                    or 403 "principal_not_verified"
  5. actor != approver                            else 403 "actor_is_approver"

Resolution policy: from env REEFLEX_RESOLUTION_POLICY (JSON string or path to
JSON file), shape {"default":["human"],"<rule_short_name>":["human","agent"]}.
Absent -> human-only everywhere.  Lookup key = rule short-name (part after the
last "/" in rule_id), falling back to "default".

WHO THE APPROVER IS (RFX-CORE-2) — see app/principal.py for the full write-up.
Checks 3 and 5 only ever examined the principal the CALLER ASSERTED in the
request body, and check 5 was a raw string inequality, so one bearer token
could raise a hold as an agent and approve it as an arbitrary named human;
`decided_by` was then persisted as though a real human had decided.  Check 4
now establishes the approver BEFORE the policy and self-approval checks judge
it:

  REEFLEX_RESOLVER_TOKENS         JSON (or path to JSON) mapping a bearer token
                                  to the principal that token IS:
                                    {"tok": {"type":"human","id":"alice"}}
                                  When set, the approver is taken from the
                                  CREDENTIAL; a body principal that disagrees
                                  -> 403 principal_mismatch, and a token with
                                  no binding -> 403 principal_not_verified.
  REEFLEX_REQUIRE_VERIFIED_APPROVER
                                  true/1/yes -> an unverifiable approver is
                                  refused outright (403 principal_not_verified).
                                  A deployment that CLAIMS four-eyes must set
                                  this (or the token map above).

With neither set, resolution still works — but the hold record, the
hold.resolved webhook and the Art.14 audit line now carry
`decided_by_verified: false` / `principal_source: "asserted"`, so an
unverified claim is no longer indistinguishable from a real human decision,
and core warns on stderr.  The `decided_by` "{type}:{id}" shape is unchanged.

NON_RESOLVABLE_RULES: {"irreversible_systemic_prod"}.  Defensive guard:
systemic is a terminal deny and should never be a hold, but we guard anyway.
"""

from __future__ import annotations

import hmac
import http.server
import json
import os
import sys
import urllib.parse

from .decide import process
from .telemetry import get_emitter

_MAX_BODY_BYTES = int(os.environ.get("REEFLEX_MAX_BODY_BYTES", str(256 * 1024)))

# ---------------------------------------------------------------------------
# Non-resolvable rules (design §R2/systemic — see module docstring)
# ---------------------------------------------------------------------------

NON_RESOLVABLE_RULES: frozenset[str] = frozenset({"irreversible_systemic_prod"})


# ---------------------------------------------------------------------------
# Resolution policy loader
# ---------------------------------------------------------------------------

def _load_resolution_policy() -> dict:
    """Load the resolution policy from env REEFLEX_RESOLUTION_POLICY.

    Returns a dict with at least a "default" key.
    Shape: {"default": ["human"], "<rule_short_name>": ["human", "agent"]}.

    Absent or malformed -> returns {"default": ["human"]} (human-only everywhere).
    """
    raw = os.environ.get("REEFLEX_RESOLUTION_POLICY", "").strip()
    if not raw:
        return {"default": ["human"]}
    # Try as a JSON string first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            if "default" not in parsed:
                parsed["default"] = ["human"]
            return parsed
    except json.JSONDecodeError:
        pass
    # Try as a file path
    try:
        import pathlib
        p = pathlib.Path(raw)
        if p.is_file():
            with open(p, encoding="utf-8") as fh:
                parsed = json.load(fh)
            if isinstance(parsed, dict):
                if "default" not in parsed:
                    parsed["default"] = ["human"]
                return parsed
    except Exception:  # noqa: BLE001
        pass
    return {"default": ["human"]}


def _allowed_principal_types(rule_id: str, policy: dict) -> list[str]:
    """Return the list of allowed principal types for this rule.

    Lookup key = short-name (part after the last "/" in rule_id).
    Falls back to "default" if the short-name is not in the policy.
    """
    if "/" in rule_id:
        short_name = rule_id.rsplit("/", 1)[1]
    else:
        short_name = rule_id
    allowed = policy.get(short_name, policy.get("default", ["human"]))
    if not isinstance(allowed, list):
        allowed = ["human"]
    return [str(x) for x in allowed]


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class _DecideHandler(http.server.BaseHTTPRequestHandler):

    server_version = "reeflex-core"
    sys_version = ""

    def version_string(self) -> str:  # noqa: N802
        """Return a clean server banner with no Python or BaseHTTP version leak."""
        return self.server_version

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: N802
        # Override to prefix with service name; goes to stderr
        print(f"[reeflex-core] {fmt % args}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _authorized(self) -> bool:
        """Return True if the request is authorized.

        Auth is OPTIONAL: if REEFLEX_AUTH_TOKEN is unset or empty the method
        always returns True (backward-compatible).  When set, the request must
        supply a matching bearer token.  Comparison is constant-time.
        """
        expected = os.environ.get("REEFLEX_AUTH_TOKEN")
        if not expected:
            return True
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        provided = header[len(prefix):].strip()
        return hmac.compare_digest(provided, expected)

    # ------------------------------------------------------------------
    # GET — /healthz + /v1/holds routes
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._do_GET_inner()
        except Exception:  # noqa: BLE001
            print("[reeflex-core] ERROR: unexpected GET handler error", file=sys.stderr)
            try:
                self._respond(500, {"error": "internal_error"})
            except Exception:  # noqa: BLE001
                pass

    def _do_GET_inner(self) -> None:
        # /healthz — always unauthenticated
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
            return

        # All other GET routes require auth
        if not self._authorized():
            self._respond(
                401,
                {"error": "unauthorized"},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

        # GET /v1/holds
        if path == "/v1/holds":
            self._handle_list_holds(qs)
            return

        # GET /v1/holds/{id}
        if path.startswith("/v1/holds/") and len(path) > len("/v1/holds/"):
            hold_id = path[len("/v1/holds/"):].strip("/")
            # Reject sub-paths like /v1/holds/{id}/resolve via GET
            if "/" in hold_id:
                self._respond(404, {"error": "not_found"})
                return
            self._handle_get_hold(hold_id)
            return

        self._respond(404, {"error": "not_found"})

    # ------------------------------------------------------------------
    # POST — /v1/decide + /v1/holds/{id}/resolve
    # ------------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._do_POST_inner()
        except Exception:  # noqa: BLE001
            print("[reeflex-core] ERROR: unexpected handler error - failing closed", file=sys.stderr)
            try:
                self._respond(500, {
                    "decision": "deny",
                    "reason": "internal error - failing closed",
                    "rule": "reeflex.core/internal_error",
                    "obligations": [],
                    "modulation": None,
                })
            except Exception:  # noqa: BLE001
                pass

    def _do_POST_inner(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # /v1/decide
        if path == "/v1/decide":
            self._handle_decide()
            return

        # /v1/holds/{id}/resolve
        if path.startswith("/v1/holds/") and path.endswith("/resolve"):
            # Extract hold_id: strip prefix + suffix
            inner = path[len("/v1/holds/"):-len("/resolve")]
            if inner and "/" not in inner:
                self._handle_resolve_hold(inner)
                return

        self._respond(404, {"error": "not_found"})

    # ------------------------------------------------------------------
    # Handler: POST /v1/decide
    # ------------------------------------------------------------------

    def _handle_decide(self) -> None:
        # Auth check BEFORE reading the body
        if not self._authorized():
            self._respond(
                401,
                {"error": "unauthorized"},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        body = self._read_body()
        if body is None:
            return  # _read_body already sent the error response

        # Parse JSON
        try:
            envelope = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_json"})
            return

        # Source IP of the /v1/decide caller, for SIEM/GeoIP enrichment.
        # Behind a reverse proxy the direct peer is the proxy; prefer the
        # left-most X-Forwarded-For hop (the real client) when present.
        xff = self.headers.get("X-Forwarded-For", "")
        src_ip = xff.split(",")[0].strip() if xff.strip() else self.client_address[0]
        status, response = process(envelope, src_ip=src_ip)
        self._respond(status, response)

    # ------------------------------------------------------------------
    # Handler: GET /v1/holds
    # ------------------------------------------------------------------

    def _handle_list_holds(self, qs: dict) -> None:
        from .holds import list_holds  # type: ignore[import]

        status_filter = qs.get("status", [None])[0]
        try:
            limit = int(qs.get("limit", [100])[0])
            limit = max(1, min(limit, 1000))
        except (ValueError, TypeError):
            limit = 100
        cursor = qs.get("cursor", [None])[0]

        try:
            items, next_cursor = list_holds(
                status=status_filter,
                limit=limit,
                cursor=cursor,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[reeflex-core] WARN: list_holds failed: {exc}", file=sys.stderr)
            self._respond(500, {"error": "internal_error"})
            return

        resp: dict = {"items": items, "count": len(items)}
        if next_cursor:
            resp["next_cursor"] = next_cursor
        self._respond(200, resp)

    # ------------------------------------------------------------------
    # Handler: GET /v1/holds/{id}
    # ------------------------------------------------------------------

    def _handle_get_hold(self, hold_id: str) -> None:
        from .holds import get_hold  # type: ignore[import]

        try:
            hold = get_hold(hold_id)
        except Exception as exc:  # noqa: BLE001
            print(f"[reeflex-core] WARN: get_hold failed: {exc}", file=sys.stderr)
            self._respond(500, {"error": "internal_error"})
            return

        if hold is None:
            self._respond(404, {"error": "not_found", "hold_id": hold_id})
            return

        self._respond(200, hold)

    # ------------------------------------------------------------------
    # Handler: POST /v1/holds/{id}/resolve
    # ------------------------------------------------------------------

    def _handle_resolve_hold(self, hold_id: str) -> None:
        # Auth
        if not self._authorized():
            self._respond(
                401,
                {"error": "unauthorized"},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        body = self._read_body()
        if body is None:
            return

        try:
            req_body = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_json"})
            return

        if not isinstance(req_body, dict):
            self._respond(400, {"error": "invalid_json"})
            return

        # Extract and validate fields
        decision = req_body.get("decision", "")
        if decision not in ("approve", "reject"):
            self._respond(
                400,
                {"error": "invalid_request", "reason": "decision must be 'approve' or 'reject'"},
            )
            return

        principal = req_body.get("principal")
        if not isinstance(principal, dict):
            self._respond(
                400,
                {"error": "invalid_request", "reason": "principal is required"},
            )
            return

        principal_type = str(principal.get("type", "")).strip()
        principal_id = str(principal.get("id", "")).strip()
        reason = req_body.get("reason")

        if not principal_type or not principal_id:
            self._respond(
                400,
                {"error": "invalid_request", "reason": "principal.type and principal.id are required"},
            )
            return

        # ---- Validation chain ----
        from .holds import get_hold, is_expired, resolve_hold  # type: ignore[import]
        from .webhook import fire as wh_fire  # type: ignore[import]

        try:
            hold = get_hold(hold_id)
        except Exception as exc:  # noqa: BLE001
            print(f"[reeflex-core] WARN: get_hold failed in resolve: {exc}", file=sys.stderr)
            self._respond(500, {"error": "internal_error"})
            return

        # Check 1: hold exists + status==pending + not expired
        if hold is None:
            self._respond(
                404,
                {"error": "not_resolvable", "reason": "hold not found", "hold_id": hold_id},
            )
            return

        if hold.get("status") != "pending":
            self._respond(
                409,
                {
                    "error": "not_resolvable",
                    "reason": f"hold status is '{hold.get('status')}', not pending",
                    "hold_id": hold_id,
                },
            )
            return

        if is_expired(hold):
            self._respond(
                409,
                {"error": "not_resolvable", "reason": "hold has expired", "hold_id": hold_id},
            )
            return

        # Check 2: NON_RESOLVABLE_RULES guard
        rule_id = hold.get("rule_id", "")
        if "/" in rule_id:
            rule_short = rule_id.rsplit("/", 1)[1]
        else:
            rule_short = rule_id

        if rule_short in NON_RESOLVABLE_RULES:
            self._respond(
                403,
                {
                    "error": "rule_not_resolvable",
                    "reason": f"rule '{rule_id}' cannot be resolved by any principal",
                    "hold_id": hold_id,
                },
            )
            return

        # Check 3: resolution policy — principal.type must be allowed
        policy = _load_resolution_policy()
        allowed_types = _allowed_principal_types(rule_id, policy)
        if principal_type not in allowed_types:
            self._respond(
                403,
                {
                    "error": "principal_type_not_allowed",
                    "reason": (
                        f"principal type '{principal_type}' is not allowed for rule '{rule_id}'; "
                        f"allowed: {allowed_types}"
                    ),
                    "hold_id": hold_id,
                },
            )
            return

        # Check 4: the approver must be VERIFIABLE (RFX-CORE-2).
        # Establishes WHO the approver is before asking whether they may
        # approve. Previously the principal came straight out of the request
        # body and was recorded as fact, so one credential could raise a hold
        # as an agent and approve it as an arbitrary named human -- four-eyes
        # was not enforced at the core boundary at all. See app/principal.py.
        from .principal import (  # type: ignore[import]
            PrincipalRefused, is_self_approval, resolve_approver,
        )

        _auth_header = self.headers.get("Authorization", "")
        _bearer = (
            _auth_header[len("Bearer "):].strip()
            if _auth_header.startswith("Bearer ") else ""
        )
        try:
            approver = resolve_approver(_bearer, principal_type, principal_id)
        except PrincipalRefused as refused:
            self._respond(
                403,
                {
                    "error": refused.error,
                    "reason": refused.reason,
                    "hold_id": hold_id,
                },
            )
            return

        # The verified principal is authoritative from here on -- the rest of
        # the chain must judge the REAL approver, not the asserted one.
        principal_type = approver["type"]
        principal_id = approver["id"]

        # Check 3 (again, on the AUTHORITATIVE type). Check 3 above ran against
        # the type the caller ASSERTED, which is the only thing available that
        # early. If the credential binds this caller to a DIFFERENT type than
        # it claimed -- e.g. it is bound as `agent` but wrote `"type":"human"`
        # to get past a human-only rule -- the asserted type must not be what
        # the policy was evaluated on. Re-checking here is cheap and closes
        # that gap; the error code is deliberately the same one, since it is
        # the same refusal.
        if principal_type not in allowed_types:
            self._respond(
                403,
                {
                    "error": "principal_type_not_allowed",
                    "reason": (
                        f"principal type '{principal_type}' (the type bound to this "
                        f"credential) is not allowed for rule '{rule_id}'; "
                        f"allowed: {allowed_types}"
                    ),
                    "hold_id": hold_id,
                },
            )
            return

        # Check 5: actor != approver.
        # Compares NORMALIZED identities across every identity that names the
        # raiser (agent.id, agent.on_behalf_of, agent.session_id), so the guard
        # is no longer defeated by a case variant of the same id, an invisible
        # character, an omitted agent.id, or approving as the human the agent
        # declares it acts for. See principal.actor_identities().
        envelope = hold.get("envelope") or {}
        if is_self_approval(envelope, principal_type, principal_id):
            self._respond(
                403,
                {
                    "error": "actor_is_approver",
                    "reason": "the principal resolving the hold must not be the same as the agent that triggered it",
                    "hold_id": hold_id,
                },
            )
            return

        # ---- Perform resolution ----
        try:
            updated = resolve_hold(
                hold_id=hold_id,
                decision=decision,
                principal_type=principal_type,
                principal_id=principal_id,
                reason=reason if isinstance(reason, str) else None,
                verified=approver["verified"],
                principal_source=approver["source"],
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[reeflex-core] WARN: resolve_hold failed: {exc}", file=sys.stderr)
            self._respond(500, {"error": "internal_error"})
            return

        if updated is None:
            self._respond(
                404,
                {"error": "not_resolvable", "reason": "hold not found after resolve", "hold_id": hold_id},
            )
            return

        # Fire webhook hold.resolved (fire-and-forget)
        try:
            wh_fire("hold.resolved", {
                "hold_id": hold_id,
                "rule_id": rule_id,
                "status": updated.get("status", ""),
                "decided_by": updated.get("decided_by", ""),
                # Additive provenance (RFX-CORE-2): whether that decided_by was
                # VERIFIED against the caller's credential or merely asserted
                # by it. Subscribers that ignore these fields behave exactly as
                # before; the frozen "{type}:{id}" shape of decided_by is
                # unchanged.
                "decided_by_verified": updated.get("decided_by_verified", False),
                "principal_source": updated.get("principal_source", "asserted"),
            })
        except Exception:  # noqa: BLE001
            pass

        self._respond(200, updated)

    # ------------------------------------------------------------------
    # Unsupported methods
    # ------------------------------------------------------------------

    def _method_not_allowed(self) -> None:
        self._respond(405, {"error": "method_not_allowed"}, extra_headers={"Allow": "GET, POST"})

    def do_PUT(self) -> None:     # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:   # noqa: N802
        self._method_not_allowed()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes | None:
        """Read the request body, enforcing the size cap.

        Returns the raw bytes, or None if an error was already sent.
        """
        length_str = self.headers.get("Content-Length", "")
        try:
            length = int(length_str)
        except (ValueError, TypeError):
            self._respond(411, {"error": "content_length_required"})
            return None

        if length > _MAX_BODY_BYTES:
            self._respond(413, {"error": "payload_too_large"})
            return None

        return self.rfile.read(length)

    def _respond(
        self,
        status: int,
        body: dict,
        extra_headers: dict | None = None,
    ) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)


def run() -> None:
    host = os.environ.get("REEFLEX_HOST", "127.0.0.1")
    port = int(os.environ.get("REEFLEX_PORT", "8080"))

    server = http.server.HTTPServer((host, port), _DecideHandler)
    print(f"[reeflex-core] listening on http://{host}:{port}/v1/decide", file=sys.stderr)

    # Start webhook emitter
    from .webhook import start as webhook_start  # type: ignore[import]
    try:
        webhook_start()
    except Exception:  # noqa: BLE001
        pass

    # Lifecycle telemetry: start.
    emitter = get_emitter()
    emitter.start()
    try:
        emitter.emit_lifecycle("start")
    except Exception:  # noqa: BLE001
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[reeflex-core] shutdown", file=sys.stderr)
    finally:
        try:
            emitter.emit_lifecycle("stop")
            emitter.stop(timeout_s=2.0)
        except Exception:  # noqa: BLE001
            pass
        server.server_close()
