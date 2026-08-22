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
  GET  /healthz            -> {"status":"ok","ledger":{...},"server":{...}} 200

All other paths/methods -> HTTP 404 or 405.

Concurrency (RFX-198 — see the block above run() for the measurement and for
why this could not land before RFX-197):
  Requests are served on a BOUNDED pool of worker threads, because each
  decision forks an `opa eval` subprocess and an unbounded thread-per-request
  server would fork the box to death under the same burst that used to be
  refused at the socket.
  REEFLEX_MAX_WORKERS      concurrent decisions (default: 2 x CPU, clamped 4..32)
  REEFLEX_MAX_PENDING      submitted-but-unfinished before shedding 503
                           (default: workers x 8)
  REEFLEX_LISTEN_BACKLOG   listen(2) backlog (default 128; the stdlib default
                           of 5 is what turned a 120-request burst into 82
                           connection resets)
  REEFLEX_REQUEST_TIMEOUT  seconds a client may hold a worker (default 30)
  Overload is refused with HTTP 503 {"error":"overloaded"} and Retry-After,
  never with a silent reset; /healthz.server.shed_total counts those refusals
  so "denied for load" is distinguishable from "denied by policy".

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
                                  ON BY DEFAULT SINCE 0.2.0.  An unverifiable
                                  approver is refused outright (403
                                  principal_not_verified, carrying a `remedy`
                                  object that names the principal and the two
                                  settings that would change the answer).
                                  `=false` restores the 0.1.x behaviour.

So OUT OF THE BOX a hold cannot be resolved by an approver core cannot
authenticate: the deployment either binds credentials (REEFLEX_RESOLVER_TOKENS)
or says, explicitly, that it does not want them bound.  With the opt-out set,
resolution still works — but the hold record, the hold.resolved webhook and
the Art.14 audit line carry `decided_by_verified: false` / `principal_source:
"asserted"`, so an unverified claim is not indistinguishable from a real human
decision, and core warns on stderr.  The `decided_by` "{type}:{id}" shape is
unchanged in every case.

NON_RESOLVABLE_RULES: {"irreversible_systemic_prod"}.  Defensive guard:
systemic is a terminal deny and should never be a hold, but we guard anyway.
"""

from __future__ import annotations

import concurrent.futures
import hmac
import http.server
import json
import os
import sys
import threading
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

    def _authorized(self, *, allow_resolver_tokens: bool = False) -> bool:
        """Return True if the request is authorized.

        Auth is OPTIONAL: if REEFLEX_AUTH_TOKEN is unset or empty the method
        always returns True (backward-compatible).  When set, the request must
        supply a matching bearer token.  Comparison is constant-time.

        `allow_resolver_tokens` — A RESOLVER CREDENTIAL IS ALSO A CREDENTIAL.
        Measured while flipping REEFLEX_REQUIRE_VERIFIED_APPROVER on by default
        (RFX-84): with REEFLEX_AUTH_TOKEN set, the ONLY bearer that gets past
        this method is that one shared string — so the only principal a
        deployment could bind in REEFLEX_RESOLVER_TOKENS was the one mapped to
        the gate's own token.  Every other approver's credential was refused
        401 at the door and never reached the verification it was created for.
        A deployment with auth enabled therefore could not have two verified
        approvers, which is to say it could not have four-eyes at all.

        That was a latent limitation of an OPT-IN feature.  Making verified
        approvers the default puts it on the default path, so it is closed
        here: on the hold-resolution routes ONLY, a bearer that
        `REEFLEX_RESOLVER_TOKENS` binds to a principal is accepted as
        authenticated.  It is a secret the operator issued, for exactly this
        purpose, and it names who it belongs to — strictly more identifying
        than the shared token it is being accepted alongside.

        SCOPED TO THE HOLDS ROUTES, DELIBERATELY.  An approver's credential
        does NOT become a key to `POST /v1/decide`: the party that approves
        actions and the party that submits them are different roles, and this
        default exists to keep them apart.  So `/v1/decide` still takes the
        gate token and nothing else.
        """
        expected = os.environ.get("REEFLEX_AUTH_TOKEN")
        if not expected:
            return True
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        provided = header[len(prefix):].strip()
        if hmac.compare_digest(provided, expected):
            return True
        if allow_resolver_tokens:
            # principal_for_token() is itself a constant-time compare against
            # every configured token (app/principal.py), so this does not
            # become a timing oracle for the resolver map.
            from .principal import principal_for_token  # type: ignore[import]
            return principal_for_token(provided) is not None
        return False

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
            # RFX-197: report whether this core can REMEMBER, not only whether
            # it can answer.
            #
            # The defect RFX-197 filed was not that the session ledger was
            # ephemeral -- it was that nothing said so. A core whose cumulative
            # budgets reset on every restart, and a core whose budgets are
            # shared with a second replica, were indistinguishable from outside:
            # both answered {"status":"ok"}. An operator running two replicas
            # behind a load balancer multiplied every session budget by two and
            # had no way to see it.
            #
            # `ledger.durable` is that answer, and `ledger.path` is what makes
            # the RESIDUAL checkable: two replicas share one budget only if they
            # share this path AND the volume behind it. Comparing /healthz
            # across replicas is now a real check an operator can run, where
            # before there was nothing to compare. Unauthenticated like the rest
            # of this route: it exposes a mode and a path, no session data, no
            # spend, no identities.
            _ledger_health: dict = {}
            try:
                from .ledger import ledger_epoch  # local: keep import cost off
                _epoch = ledger_epoch()
                _ledger_health = {
                    "durable": bool(_epoch.get("durable")),
                    "path": _epoch.get("path", ""),
                    "epoch_id": _epoch.get("epoch_id", ""),
                    "window_seconds": _epoch.get("window_seconds", 0),
                    "restored_sessions": _epoch.get("restored_sessions", 0),
                    "restored_entries": _epoch.get("restored_entries", 0),
                    "scan_truncated": bool(_epoch.get("scan_truncated")),
                }
            except Exception:  # noqa: BLE001
                # /healthz is a liveness probe first: the image's own HEALTHCHECK
                # depends on it, so it must answer 200 even if the ledger cannot
                # describe itself. An absent "ledger" key is honest about that;
                # a fabricated durable:true would not be.
                _ledger_health = {}
            # RFX-198: report how many decisions this core can serve at once,
            # and how many it has REFUSED for load rather than for policy.
            # Same argument as the ledger block above -- a single-threaded core
            # and a 32-worker core both answered {"status":"ok"}, and a
            # decision refused because the accept queue was full looked, from
            # every surface, exactly like a network fault.
            _server_health: dict = {}
            try:
                _srv = getattr(self, "server", None)
                if isinstance(_srv, PooledHTTPServer):
                    _server_health = _srv.health()
            except Exception:  # noqa: BLE001
                _server_health = {}
            _health: dict = {"status": "ok"}
            if _ledger_health:
                _health["ledger"] = _ledger_health
            if _server_health:
                _health["server"] = _server_health
            self._respond(200, _health)
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
        # Auth. A resolver credential counts here (see _authorized): an
        # approver whose token REEFLEX_RESOLVER_TOKENS binds to a principal
        # must be able to reach the endpoint that verifies it, or the map can
        # only ever hold the one principal bound to the shared gate token.
        if not self._authorized(allow_resolver_tokens=True):
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
            # `remedy` is additive (see principal.PrincipalRefused): a refusal
            # this core ships as a DEFAULT has to carry its own instructions,
            # and a dashboard should not have to string-match `reason` to
            # render them. Omitted entirely when empty, so the response shape
            # for a refusal with nothing useful to say is unchanged.
            body = {
                "error": refused.error,
                "reason": refused.reason,
                "hold_id": hold_id,
            }
            if refused.remedy:
                body["remedy"] = refused.remedy
            self._respond(403, body)
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


# ===========================================================================
# RFX-198 — THE REQUEST PATH SERVES MORE THAN ONE DECISION AT A TIME
# ===========================================================================
#
# Until RFX-198 this module ended with
#
#     server = http.server.HTTPServer((host, port), _DecideHandler)
#
# `http.server.HTTPServer` — NOT `ThreadingHTTPServer` — so exactly one
# request was served at a time; and `request_queue_size` was never set, so the
# listen backlog was socketserver.TCPServer's default of FIVE. Measured on the
# customer artefact at main 1b80c8b, identical read envelopes, distinct
# session_ids, one client host:
#
#     rung              wall  answered  dec/sec     p50     worst   >5s   >10s
#     SEQUENTIAL  120    6.0s  120/120     19.9    50ms      66ms     0      0
#     CONCURRENT    4    0.2s    4/4       18.9   123ms     209ms     0      0
#     CONCURRENT   16    1.4s   16/16      11.3   448ms    1407ms     0      0
#     CONCURRENT  120   53.8s  120/120      2.2  7393ms   53807ms    64     36
#
# Concurrency made the engine NINE TIMES SLOWER per decision than doing the
# same work one call at a time.
#
# TWO EARLIER FIGURES IN THIS COMMENT WERE WRONG AND ARE CORRECTED ABOVE. A
# first pass recorded "CONCURRENT(120) 7.7 s, 38/120 answered, 82 ECONNRESET".
# Re-measured with a client patient enough to wait (120 s timeout), all 120 are
# eventually answered — the resets were an artefact of the PROBE's timeout, not
# a property of the server. The defect is real either way but its shape is
# different, and the numbers above are the ones an instrument can defend.
#
# WHY THAT IS A SAFETY DEFECT AND NOT ONLY A PERFORMANCE ONE. Every adapter
# fails CLOSED when core does not answer — reeflex-claude 5 s, reeflex-wordpress
# 5 s, reeflex-mcp 10 s, read out of the published packages. That default is
# correct. Its consequence is that a saturated core does not wave work through,
# it REFUSES: at width 120, 64 of 120 legitimate decisions came back slower than
# the 5 s adapter deadline and 36 slower than the 10 s one — refusals with no
# policy consulted and no audit line saying why. A less patient client sees the
# same load as hard connection resets instead. Either way the operator's only
# pressure-relief valve is to switch the adapter from enforce to observe, which
# turns the product off. So an availability failure of the enforcement plane
# converts, in one step, into no enforcement at all.
#
# WHY THIS COULD NOT BE FIXED BEFORE RFX-197 (the ordering qa--030 flagged).
# R5's cumulative budget is a read-decide-write: compute_cumulative() -> OPA
# eval -> append_entry(). qa--030 built two images differing in ONE line of
# this file and measured, on six simultaneous same-session deletes against the
# shipped limit of 20:
#
#     as shipped (HTTPServer)      : 20 through, held at 20
#     ThreadingHTTPServer only     : 30 through, ZERO holds   <- DEFEATED
#
# So the anti-fragmentation guarantee held for exactly one reason: this server
# was single-threaded and requests never overlapped. That was an accident of a
# dev-server choice, not a designed guard, and making core concurrent would
# have removed it silently with every test still green. RFX-197 put the real
# guard in — ledger.session_guard(session_id), striped over 64 stripes, held
# across all three steps — so same-session calls now serialise on the LEDGER
# and unrelated sessions run in parallel. THAT is the prerequisite, and it is
# why this block may exist.
#
# THREE CHOICES HERE, AND WHY EACH IS NOT THE OBVIOUS ONE.
#
# 1. A BOUNDED POOL, not ThreadingHTTPServer. ThreadingMixIn spawns one thread
#    per connection, unbounded, and every decision forks an `opa eval`
#    subprocess (app/opa.py:93, ~54 ms). Unbounded threads therefore mean
#    unbounded concurrent subprocesses: a burst that used to be refused at the
#    socket would instead fork the box to death, which is the same denial with
#    a worse blast radius. The pool size is the real resource being bounded —
#    concurrent policy evaluations.
#
# 2. LOAD IS SHED WITH AN ANSWER, not with a reset. Past `max_pending` the
#    server writes a 503 naming `overloaded` and closes, instead of letting
#    the connection sit until the client's timeout. Both outcomes are a
#    fail-closed refusal at the adapter — that part is unchanged and correct —
#    but one of them tells the operator WHICH failure it was. `shed_total` on
#    /healthz is the count of decisions refused for load rather than for
#    policy, which is a number nobody could obtain before.
#
# 3. A REQUEST TIMEOUT, which a bounded pool now REQUIRES. The handler had no
#    `timeout`, so a client that opened a connection and never finished its
#    request line held its worker forever. Under the old single-threaded
#    server that was already fatal, so it changed nothing; under a pool of N
#    it is a way to occupy all N cheaply. Bounding the pool without bounding
#    how long a worker can be held would trade a throughput bug for an
#    availability one.
#
# WHAT THIS DOES NOT FIX, stated here rather than only in the roadmap: every
# decision still forks `opa eval`. That fork is now the throughput ceiling
# (~54 ms of mostly process startup and policy compile, per decision, per
# worker). app/opa.py's own header already names the fix — a long-running
# `opa run --server` sidecar behind REEFLEX_OPA_MODE=server. This change makes
# core use the cores it has; it does not make a single decision cheaper.

# Listen backlog. The old default of 5 (inherited from TCPServer) is what
# turned the 120-concurrent burst into 82 connection resets.
_LISTEN_BACKLOG = int(os.environ.get("REEFLEX_LISTEN_BACKLOG", "128"))

# Request read timeout, in seconds — how long a worker may be held by a client
# that has not finished sending its request. A decision costs ~54 ms and the
# OPA subprocess timeout is 10 s (REEFLEX_OPA_TIMEOUT), so 30 s is generous
# for any honest client and finite for a dishonest one.
_REQUEST_TIMEOUT_SECONDS = float(os.environ.get("REEFLEX_REQUEST_TIMEOUT", "30"))

# Workers dedicated to answering shed connections, and how long one may wait
# for a shed client's request to arrive before giving up on delivering the 503.
# Answering a shed costs an RTT, not an OPA eval, so a handful of workers
# serve thousands per second.
_SHED_WORKERS = max(1, int(os.environ.get("REEFLEX_SHED_WORKERS", "4")))
_SHED_WAIT_SECONDS = float(os.environ.get("REEFLEX_SHED_WAIT", "0.25"))


def _max_workers() -> int:
    """Concurrent policy evaluations permitted. REEFLEX_MAX_WORKERS overrides.

    Each worker may hold one `opa eval` subprocess, so this is a bound on
    processes, not just threads. Default: two per CPU (decisions are dominated
    by waiting on that subprocess, not by this process's own CPU), clamped to
    [4, 32] so a 1-core box still serves a burst and a 128-core box does not
    fork 256 OPA processes at once.
    """
    raw = os.environ.get("REEFLEX_MAX_WORKERS", "").strip()
    if raw:
        try:
            n = int(raw)
        except ValueError:
            n = 0
        if n > 0:
            return n
    return max(4, min(32, (os.cpu_count() or 1) * 2))


def _max_pending(workers: int) -> int:
    """Submitted-but-not-finished requests permitted before shedding."""
    raw = os.environ.get("REEFLEX_MAX_PENDING", "").strip()
    if raw:
        try:
            n = int(raw)
        except ValueError:
            n = 0
        if n > 0:
            return n
    return workers * 8


def _overloaded_wire() -> bytes:
    """The shed response, pre-rendered.

    Pre-rendered and written straight to the socket, because a shed must not
    cost what a decision costs: no handler instance, no parsing, no policy
    engine. It is delivered on the small shed pool rather than on the accept
    thread — see _shed_conn, which had to wait for the client's request to
    arrive before answering, and measured why. Kept byte-identical in shape to
    _respond(): same
    Content-Type, same nosniff/no-store headers, JSON body with an `error`
    key, so an adapter parses it the same way it parses every other refusal.
    """
    body = json.dumps(
        {
            "error": "overloaded",
            "reason": "core is at its concurrent-decision limit; retry",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    head = (
        "HTTP/1.0 503 Service Unavailable\r\n"
        "Server: reeflex-core\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Cache-Control: no-store\r\n"
        "Retry-After: 1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    return head + body


_OVERLOADED_WIRE = _overloaded_wire()


class PooledHTTPServer(http.server.HTTPServer):
    """HTTPServer that serves requests on a BOUNDED pool of worker threads.

    Mirrors socketserver.ThreadingMixIn's flow (finish_request ->
    shutdown_request, errors to handle_error) but hands each connection to a
    fixed-size ThreadPoolExecutor instead of spawning an unbounded thread per
    connection. See the RFX-198 block above for why bounded.
    """

    # NO `daemon_threads = True` here, deliberately. That attribute is read by
    # socketserver.ThreadingMixIn, which this class does not use, so setting it
    # would look like a shutdown guarantee and provide none. The real behaviour
    # is ThreadPoolExecutor's: its workers are non-daemon and registered with
    # threading._register_atexit, so the interpreter waits for an in-flight
    # decision to finish rather than killing it halfway through the
    # read-decide-write cycle. That is what we want -- a decision cut off
    # between the OPA eval and ledger.append_entry() would be enforced and
    # unrecorded -- but see server_close() for the shutdown(wait=False) that
    # keeps a closing server from blocking on a slow SIEM.

    def __init__(
        self,
        server_address,
        RequestHandlerClass,  # noqa: N803 — stdlib's own parameter name
        *,
        workers: int,
        backlog: int,
        max_pending: int,
    ) -> None:
        # MUST be set before super().__init__: TCPServer.server_activate()
        # calls socket.listen(self.request_queue_size) during construction, so
        # assigning it afterwards would listen with the old default of 5 and
        # silently change nothing.
        self.request_queue_size = backlog

        self.workers = workers
        self.max_pending = max_pending
        self._pending = 0
        self._pending_lock = threading.Lock()
        self.shed_total = 0
        self.shed_undelivered = 0
        self._shed_pending = 0
        self._shed_capacity = _SHED_WORKERS * 16
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="reeflex-decide",
        )
        # A separate, tiny pool: a shed connection must not queue behind the
        # decisions that caused the shed, and answering one costs an RTT, not
        # an OPA eval.
        self._shed_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=_SHED_WORKERS,
            thread_name_prefix="reeflex-shed",
        )
        super().__init__(server_address, RequestHandlerClass)

    # -- accept loop ------------------------------------------------------

    def process_request(self, request, client_address) -> None:
        """Called on the accept thread. Must not block or the backlog fills."""
        with self._pending_lock:
            if self._pending >= self.max_pending:
                self.shed_total += 1
                shed = True
            else:
                self._pending += 1
                shed = False

        if shed:
            self._shed(request)
            return

        try:
            self._pool.submit(self._run_request, request, client_address)
        except RuntimeError:
            # Pool already shut down (server_close raced an inbound
            # connection). Close the socket rather than leaking it, and
            # release the slot we just took.
            with self._pending_lock:
                self._pending -= 1
            self.shutdown_request(request)

    def _run_request(self, request, client_address) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:  # noqa: BLE001
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            with self._pending_lock:
                self._pending -= 1

    def _shed(self, request) -> None:
        """Hand a shed connection to the shed pool, or close it outright.

        Shedding is NOT done on the accept thread. Delivering the 503 means
        waiting for the client's request to arrive first (see _shed_conn), and
        a blocking wait on the accept thread is exactly the backlog
        starvation this whole change removes.
        """
        with self._pending_lock:
            if self._shed_pending >= self._shed_capacity:
                # The shed path itself is saturated. Close without answering
                # and COUNT it, so /healthz never implies we told the caller
                # something we did not.
                self.shed_undelivered += 1
                self.shutdown_request(request)
                return
            self._shed_pending += 1
        try:
            self._shed_pool.submit(self._shed_conn, request)
        except RuntimeError:            # pool shut down (server closing)
            with self._pending_lock:
                self._shed_pending -= 1
                self.shed_undelivered += 1
            self.shutdown_request(request)

    def _shed_conn(self, request) -> None:
        """Answer 503 on a shed worker, then close.

        TWO MEASURED REASONS THIS IS NOT JUST sendall()+close().

        1. A client mid-write. With 120 simultaneous callers, most have not
           finished sending when we accept them. Closing first makes their
           send() fail, so they raise BrokenPipe and never read the response
           at all — measured on the first cut of this method: of 118 shed
           connections, 104 clients raised BrokenPipe and 14 read the 503. So
           we wait for the request to ARRIVE before answering. That wait costs
           one RTT in the normal case (the request is already in flight), not
           the timeout; the timeout is only paid by a client that connects and
           says nothing, which is not waiting on a response anyway.

        2. Unread inbound data at close sends an RST, which discards the bytes
           we just wrote. So the rest of the request is drained too, without
           blocking, once the first segment has landed.

        The entire argument for shedding is that the caller learns WHICH
        refusal this was. A shed the caller cannot read is worth no more than
        the reset it replaced, so this method is the feature, not a courtesy
        around it.
        """
        delivered = False
        try:
            request.settimeout(_SHED_WAIT_SECONDS)
            first = request.recv(65536)          # returns as soon as data lands
            if first:
                # Drain whatever else is already queued, non-blocking.
                request.setblocking(False)
                drained = len(first)
                while drained < _MAX_BODY_BYTES:
                    try:
                        chunk = request.recv(65536)
                    except (BlockingIOError, InterruptedError, OSError):
                        break
                    if not chunk:
                        break
                    drained += len(chunk)
                request.settimeout(_SHED_WAIT_SECONDS)
            request.sendall(_OVERLOADED_WIRE)
            delivered = True
        except Exception:  # noqa: BLE001
            # Client gone, or socket unwritable. Never raises: this runs on a
            # pool worker whose only job is to close this connection.
            pass
        finally:
            self.shutdown_request(request)
            with self._pending_lock:
                self._shed_pending -= 1
                if not delivered:
                    self.shed_undelivered += 1

    # -- introspection ----------------------------------------------------

    def health(self) -> dict:
        """The concurrency model, for /healthz.

        RFX-197 put the ledger's mode on /healthz because a core that could
        not remember was indistinguishable from one that could. Same argument
        here: a core that serves one decision at a time and a core that serves
        thirty-two answered identically, and `shed_total` is the only place a
        refusal-for-load is ever counted.
        """
        with self._pending_lock:
            pending = self._pending
            shed = self.shed_total
            undelivered = self.shed_undelivered
        return {
            "concurrency": "pool",
            "workers": self.workers,
            "listen_backlog": self.request_queue_size,
            "max_pending": self.max_pending,
            "pending": pending,
            "shed_total": shed,
            # Of those, the ones we could not even tell. Reported separately
            # rather than folded in, because "refused and told why" and
            # "refused silently" are different facts about the same outage.
            "shed_undelivered": undelivered,
        }

    def server_close(self) -> None:
        super().server_close()
        # wait=False: the listening socket is already closed, so no new work
        # can arrive; in-flight decisions finish on their own threads.
        self._pool.shutdown(wait=False)
        self._shed_pool.shutdown(wait=False)


def run() -> None:
    host = os.environ.get("REEFLEX_HOST", "127.0.0.1")
    port = int(os.environ.get("REEFLEX_PORT", "8080"))

    workers = _max_workers()
    max_pending = _max_pending(workers)
    _DecideHandler.timeout = _REQUEST_TIMEOUT_SECONDS

    server = PooledHTTPServer(
        (host, port),
        _DecideHandler,
        workers=workers,
        backlog=_LISTEN_BACKLOG,
        max_pending=max_pending,
    )
    print(f"[reeflex-core] listening on http://{host}:{port}/v1/decide", file=sys.stderr)
    print(
        f"[reeflex-core] concurrency: {workers} workers, "
        f"listen backlog {_LISTEN_BACKLOG}, shed above {max_pending} pending, "
        f"request timeout {_REQUEST_TIMEOUT_SECONDS:g}s",
        file=sys.stderr,
    )

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
