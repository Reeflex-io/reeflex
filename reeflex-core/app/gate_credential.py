"""
gate_credential.py -- accept a PORTAL-ISSUED, GATE-SCOPED credential on
POST /v1/decide, by asking the portal that issued it (RFX-224).

WHY THIS EXISTS. A core started with REEFLEX_AUTH_TOKEN refuses every route
except GET /healthz, and that single shared string is the operator's own: it is
not scoped to anything, cannot be handed to one agent, and cannot be taken back
from one agent.  The consequence was measured on the hosted onboarding path
(dev-2 round 044): a customer pasted the one-line onboarding, its first real
/v1/decide reached an engine with auth on, and the line exited 1 with
`core HTTP 401`.  The engine was up, the URL was right, and the only remedy was
a credential a stranger has no way to hold.

So this adds a SECOND thing /v1/decide will accept: an `rfx_ac_` credential the
portal minted for one gate, bounded in time, and revocable -- individually, or
by revoking the gate, which is the remedy the documentation actually gives a
customer whose credential leaked.

============================================================================
WHY IT ASKS INSTEAD OF VERIFYING A SIGNATURE, AND WHAT THAT COSTS
============================================================================

The cheap design is a self-contained signed token: the portal HMACs
{gate, exp} with a key the operator also puts on core, and core verifies it
offline with no round trip.  It was rejected for one reason: core has no
database and no state, so an offline verifier CANNOT LEARN THAT A GATE WAS
REVOKED.  It would accept a stolen credential for the whole of its lifetime,
and "revoke the gate" -- the one control the docs promise -- would be advice
that does nothing until the credential expired on its own.  Getting revocation
back would mean a second mechanism (a pushed or pulled revocation feed, with
its own staleness bound), i.e. strictly more moving parts than one call.  It
also removes a shared secret from the deployment story, which is the part an
operator gets wrong.

THE COST, NAMED RATHER THAN GLOSSED:

  * ONE OUTBOUND HTTP CALL, on the auth path, on a cache miss.  A governance
    decision that used to be local now waits on the portal.  Cache TTL exists
    to keep this off the per-decision path (default 30s); measure it in your
    deployment rather than believing this paragraph.
  * A NEW FAILURE MODE.  Portal unreachable => the credential cannot be
    validated => 401 => the adapter fails CLOSED and denies.  That is the safe
    direction and it is also an availability coupling that did not exist
    before.  It applies ONLY to callers using a portal credential: a caller
    presenting REEFLEX_AUTH_TOKEN never reaches this module, so an operator's
    own traffic is unaffected by the portal being down.
  * REVOCATION IS NOT INSTANT, it is bounded by the cache TTL.  With the
    default, a revoked gate keeps deciding for up to 30 more seconds on cores
    that have already seen its credential.  Set the TTL to 0 to remove the
    window at the price of a call per decision.

INERT BY DEFAULT.  With REEFLEX_GATE_INTROSPECTION_URL unset -- which is every
existing deployment -- nothing here runs and the auth behaviour is exactly what
it was.  Opting in is one environment variable, and it is the operator saying
"this portal may issue credentials for my engine", which is a real trust
statement and should look like one.

SCOPED TO /v1/decide, DELIBERATELY, and for the same reason server.py gives for
keeping resolver credentials off it: the party that SUBMITS actions and the
party that APPROVES them are different roles, and an onboarding credential
handed to an agent must not become a key to resolving that agent's own holds.

============================================================================
WHAT "GATE-SCOPED" CAN AND CANNOT MEAN HERE
============================================================================

The Action Envelope has no gate axis (reeflex-spec/SPEC.md) -- core decides on
what the action IS, blind to who asked.  So the scope this enforces is NOT
"this credential may only produce decisions about gate X's resources"; there is
no such dimension to enforce.  It is narrower and worth stating exactly:

    a credential minted for gate A cannot be used to submit decisions
    DECLARED as gate B.

The declaration is the `X-Reeflex-Gate` request header, and it is REQUIRED
when the caller authenticates with a portal credential: absent means 403, not
"accepted with no scope".  A required declaration that mismatches is 403
(authenticated, not allowed) rather than 401 (not authenticated), because the
two are different facts and an operator reading a log should not have to guess
which one happened.

That binds attribution and it stops one gate's credential from being replayed
as another's.  It does not, and cannot, stop the holder of gate A's credential
from asking gate A's questions -- for that, revoke it.

Env:
  REEFLEX_GATE_INTROSPECTION_URL
        The portal's introspection endpoint, e.g.
        https://app.reeflex.io/api/v1/agent/introspect
        UNSET (the default) disables this module entirely.
  REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS
        How long a POSITIVE answer is reused.  Default 30.  0 disables the
        cache (a call per decision).  Negative answers are NEVER cached -- a
        freshly minted credential must work on its first use, and caching a
        miss would make the first decision after onboarding fail for no
        recoverable reason.
  REEFLEX_GATE_INTROSPECTION_TIMEOUT
        Seconds.  Default 5.0.  On timeout the credential is not validated and
        the request is refused (fail closed).
  REEFLEX_GATE_INTROSPECTION_CA_BUNDLE
        Optional path to a CA bundle for the portal's certificate, for a
        self-hosted portal behind a private CA.  There is NO switch to turn
        verification off: this call carries a credential, and an unverified
        TLS connection to "whoever answers on that name" is how that
        credential leaves the building.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

# The portal's credential family: `rfx_gate_` / `rfx_ek_` / `rfx_reg_` /
# `rfx_ac_`.  Only the last one is ours to accept, and checking the literal
# prefix first means a mistyped gate token is refused locally instead of
# being sent to the portal for it to refuse.
GATE_CREDENTIAL_PREFIX = "rfx_ac_"

# Generous next to the 50 characters an `rfx_ac_` value actually is.  A cap
# before anything is sent anywhere: nothing is gained by forwarding a
# megabyte of bearer header to the portal.
_MAX_CREDENTIAL_CHARS = 200

# Bound on the positive cache, so a burst of distinct credentials cannot grow
# it without limit.  When full the whole cache is dropped rather than
# LRU-evicted: at this size the difference is a handful of extra introspection
# calls, and an eviction policy is state that can be wrong.
_MAX_CACHE_ENTRIES = 512

_GATE_HEADER = "X-Reeflex-Gate"

# status values returned to server.py
ACCEPT = "accept"
UNAUTHENTICATED = "unauthenticated"
GATE_MISMATCH = "gate_mismatch"
GATE_NOT_DECLARED = "gate_not_declared"

_cache: Dict[str, Tuple[str, float]] = {}
_cache_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def introspection_url() -> str:
    return os.environ.get("REEFLEX_GATE_INTROSPECTION_URL", "").strip()


def enabled() -> bool:
    """True when this deployment has opted in.  Read from the environment on
    every call rather than captured at import: the test suite and the server's
    own restart-free reconfiguration both change it, and a module-level
    constant would silently keep the value the first import saw."""

    return bool(introspection_url())


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        print(
            f"[reeflex-core] WARNING: {name}={raw!r} is not a number; using {default}",
            file=sys.stderr,
        )
        return default
    return value if value >= 0 else default


def cache_seconds() -> float:
    return _float_env("REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS", 30.0)


def timeout_seconds() -> float:
    value = _float_env("REEFLEX_GATE_INTROSPECTION_TIMEOUT", 5.0)
    # A zero timeout would mean "never wait", i.e. every portal credential is
    # refused, which is a silent total outage of this feature rather than a
    # fast one.  Treated as the default instead.
    return value if value > 0 else 5.0


def _ssl_context() -> Optional[ssl.SSLContext]:
    bundle = os.environ.get("REEFLEX_GATE_INTROSPECTION_CA_BUNDLE", "").strip()
    if not bundle:
        return None
    return ssl.create_default_context(cafile=bundle)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(credential: str) -> str:
    """SHA-256 of the credential, so the raw secret is not a dictionary key.

    Not a security boundary -- anything with our memory has the request too --
    but a heap dump, a `repr()` in a traceback and an accidental log of the
    cache all become non-disclosing for free, and free is the right price for
    that.
    """

    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def _cache_get(credential: str) -> Optional[str]:
    ttl = cache_seconds()
    if ttl <= 0:
        return None
    key = _cache_key(credential)
    now = time.monotonic()
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        gate_id, expires_at = entry
        if expires_at <= now:
            _cache.pop(key, None)
            return None
        return gate_id


def _cache_put(credential: str, gate_id: str, *, credential_expires_in: Optional[float]) -> None:
    ttl = cache_seconds()
    if ttl <= 0:
        return
    # Never cache past the credential's OWN deadline.  Without this a
    # credential with four seconds left would be honoured for the full cache
    # TTL, which turns `expires_at` into a suggestion.
    if credential_expires_in is not None:
        ttl = min(ttl, max(credential_expires_in, 0.0))
    if ttl <= 0:
        return
    key = _cache_key(credential)
    with _cache_lock:
        if len(_cache) >= _MAX_CACHE_ENTRIES:
            _cache.clear()
        _cache[key] = (gate_id, time.monotonic() + ttl)


def clear_cache() -> None:
    """Drop every cached answer.  For tests, and for an operator who has just
    revoked something and does not want to wait out the TTL."""

    with _cache_lock:
        _cache.clear()


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

def _introspect(credential: str) -> Optional[Tuple[str, Optional[float]]]:
    """Ask the portal.  Returns `(gate_id, seconds_until_expiry)` or None.

    None for EVERY failure -- unknown credential, revoked, expired, gate
    revoked, portal down, portal answering nonsense.  The portal deliberately
    returns the same `{"active": false}` for the first four (it is not an
    oracle for which check failed), and collapsing transport failures into the
    same answer here is the fail-closed direction: a credential we could not
    validate is a credential we do not accept.

    The distinction that IS kept is in the log line, not in the return value:
    an operator debugging "why is everything denied" needs to see
    "portal unreachable" rather than "unknown credential", and stderr is where
    that goes.  The CALLER never learns which, for the same anti-oracle reason.
    """

    url = introspection_url()
    body = json.dumps({"token": credential}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            # No Authorization header, on purpose: the credential is the
            # SUBJECT of this question, not the identity of the asker, and it
            # travels in the body so an intermediary's access log does not
            # treat it as our own bearer.  See the portal endpoint's docstring.
            "User-Agent": "reeflex-core/gate-introspection",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            req, timeout=timeout_seconds(), context=_ssl_context()
        ) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        print(
            f"[reeflex-core] gate introspection: {url} answered HTTP {exc.code} "
            "-- refusing the credential (fail closed)",
            file=sys.stderr,
        )
        return None
    except Exception as exc:  # noqa: BLE001 - every transport failure is one answer
        print(
            f"[reeflex-core] gate introspection: could not reach {url} ({exc}) "
            "-- refusing the credential (fail closed)",
            file=sys.stderr,
        )
        return None

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        print(
            f"[reeflex-core] gate introspection: {url} did not answer JSON "
            "-- refusing the credential (fail closed)",
            file=sys.stderr,
        )
        return None

    if not isinstance(parsed, dict) or parsed.get("active") is not True:
        return None
    gate_id = parsed.get("gate_id")
    if not isinstance(gate_id, str) or not gate_id:
        # `active: true` with no gate means the portal cannot tell us what this
        # credential is scoped to, so there is no scope to enforce.  Refused,
        # because "authenticated but unscoped" is exactly the property this
        # whole module exists to avoid.
        print(
            f"[reeflex-core] gate introspection: {url} said active with no "
            "gate_id -- refusing (a credential with no scope is not a scoped "
            "credential)",
            file=sys.stderr,
        )
        return None

    return gate_id, _seconds_until(parsed.get("expires_at"))


def _seconds_until(rfc3339: object) -> Optional[float]:
    """Seconds from now until an RFC3339 instant, or None if unparseable.

    None means "do not shorten the cache TTL on this account" and NOT "expired":
    the portal has already refused an expired credential before answering
    `active`, so a timestamp we cannot read is a formatting problem, not an
    authorization one, and treating it as a refusal would break every caller
    over a date format.
    """

    if not isinstance(rfc3339, str) or not rfc3339:
        return None
    try:
        from datetime import datetime, timezone

        text = rfc3339.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (parsed - datetime.now(timezone.utc)).total_seconds()
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# The one entry point server.py calls
# ---------------------------------------------------------------------------

def authorize(bearer: str, declared_gate: Optional[str]) -> Tuple[str, str]:
    """Decide whether `bearer` may submit a decision declared for
    `declared_gate`.

    Returns `(status, detail)` where status is one of ACCEPT,
    UNAUTHENTICATED, GATE_MISMATCH, GATE_NOT_DECLARED.  `detail` is for the
    response body and the log; it never contains the credential.

    THE CHEAP LOCAL CHECKS COME FIRST and each one is a reason not to make a
    network call: not opted in, not a credential of ours, absurdly long, no
    gate declared.  Only a bearer that has passed all four is worth asking the
    portal about.
    """

    if not enabled():
        return UNAUTHENTICATED, "no portal credential source is configured"
    if not bearer or not bearer.startswith(GATE_CREDENTIAL_PREFIX):
        return UNAUTHENTICATED, "not a portal-issued gate credential"
    if len(bearer) > _MAX_CREDENTIAL_CHARS:
        return UNAUTHENTICATED, "not a portal-issued gate credential"

    declared = (declared_gate or "").strip()
    if not declared:
        return (
            GATE_NOT_DECLARED,
            f"this credential is scoped to one gate, so the request must "
            f"declare which gate it is for in the {_GATE_HEADER} header",
        )

    gate_id = _cache_get(bearer)
    if gate_id is None:
        answer = _introspect(bearer)
        if answer is None:
            return UNAUTHENTICATED, "the portal did not confirm this credential"
        gate_id, expires_in = answer
        _cache_put(bearer, gate_id, credential_expires_in=expires_in)

    if declared != gate_id:
        # A plain comparison, not `hmac.compare_digest`: a gate id is a public
        # identifier that the portal hands out in the clear and the client
        # sends in a header, so there is no secret here to leak by timing.
        # Using a constant-time compare anyway would imply there is.
        return (
            GATE_MISMATCH,
            "this credential belongs to a different gate than the request "
            "declared",
        )

    return ACCEPT, gate_id
