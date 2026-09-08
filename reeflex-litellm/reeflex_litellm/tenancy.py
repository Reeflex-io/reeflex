"""
tenancy.py -- which Reeflex org a request behind the gateway belongs to.

THE PROBLEM THIS EXISTS FOR
===========================
One LiteLLM proxy fronts every agent in a company.  Two departments call it with
two different virtual keys.  Without this module both departments' decisions
carry the same `agent.id`, spend the same R5 budget, and -- if the seat pushes
evidence -- land in ONE Reeflex org, where either department can read the
other's holds.  That is not a reporting inconvenience: core's hold check 8
(RFX-138) binds an approval to an actor, so a shared `agent.id` means the
payments team's approval can be spent by the marketing team's agent.

WHAT LITELLM ACTUALLY GIVES US (measured, litellm 1.100.0)
==========================================================
`async_post_call_success_hook`'s second argument is `user_api_key_dict`, a
`UserAPIKeyAuth` -- 102 fields, populated by the proxy's own authentication,
NOT by the caller's request body.  That is the whole point: the caller cannot
set it.  The fields this module reads, and why each:

  api_key        For a virtual key, `user_api_key_auth.py` replaces the
                 presented key with `hash_token(key)` -- a sha256 hex digest --
                 before the object is built (`if api_key.startswith("sk-"):
                 api_key = hash_token(token=api_key)`).  For the master key it
                 is replaced by the constant alias `litellm_proxy_master_key`.
                 SO IT IS NOT ALWAYS A HASH.  A deployment using `custom_auth`
                 builds this object itself and may put the RAW credential here.
                 litellm's own code makes exactly this distinction --
                 `_stampable_key_hash()` in `proxy/litellm_pre_call_utils.py`
                 accepts the value only when `via_virtual_key` is set AND the
                 value is the master alias or matches a sha256-hex regex,
                 commenting "Custom-auth credentials arrive raw (never forward
                 auth material)".  `safe_key_hash()` below applies the same two
                 tests, for the same reason: this value can reach an audit
                 record, and an audit record holding a live credential is a
                 secret leak that outlives the request.

  key_alias      operator-assigned name for a virtual key.  Never secret, stable
                 across key rotation.  The best thing to write a map against.
  team_id        litellm's team.  "Two departments behind one gateway" IS two
                 teams, so this is the primary binding.
  team_alias     human-readable team name; recorded, never matched on.
  org_id         LITELLM's own organization -- recorded under its own name
                 (`litellm_org_id`) and NEVER treated as a Reeflex org.  They
                 are different systems' identifiers and conflating them would
                 silently attribute one company's evidence to another's org id.
  user_id        the litellm user the key belongs to; recorded.
  end_user_id    the downstream end user (OpenAI `user` field); recorded.
  via_virtual_key
                 litellm's own marker that the proxy authenticated this key,
                 and a precondition for trusting `api_key` at all.  MEASURED
                 (1.100.0): the field is declared `exclude=True` and litellm's
                 model validator POPS it from validated input -- "Stripped from
                 validated input so custom auth handlers, JWT claims, or key
                 metadata cannot forge it" -- so only the proxy's own DB
                 virtual-key / master-key auth paths set it, by post-
                 construction assignment.  That unforgeability is the whole
                 reason this module may rely on it, and it is pinned by
                 tests/test_litellm_contract.py: a release that ever accepted
                 it as caller input would let a caller forge a key identifier,
                 and that test goes red instead.

                 A CONSEQUENCE FOR ANYONE WRITING A TEST: you cannot pass
                 `via_virtual_key=True` to the constructor.  Doing so yields
                 False, every `key_hash` lookup misses, and the suite measures
                 a fallback path rather than the one it names.

THE MAP, AND THE ABSENCE OF A DEFAULT ORG
=========================================
The binding is EXPLICIT and comes from `REEFLEX_LITELLM_TENANCY_MAP_FILE` (a
path to JSON -- preferred, so credentials stay out of the process environment)
or `REEFLEX_LITELLM_TENANCY_MAP` (inline JSON).  Shape:

    {
      "version": 1,
      "tenants": {
        "acme-payments": {
          "org": "acme-payments",
          "label": "ACME Payments",
          "principal": "payments-oncall@acme.example",
          "environment": "production",
          "on_prem_hosts": ["llm.internal.acme.example"],
          "evidence": {
            "ingest_url": "https://app.reeflex.io/api/v1/evidence",
            "gate_token_env": "RFX_GATE_TOKEN_PAYMENTS",
            "signing_key_env": "RFX_EVIDENCE_KEY_PAYMENTS"
          }
        }
      },
      "bind": {
        "key_hash":  {"<sha256hex>": "acme-payments"},
        "key_alias": {"payments-bot": "acme-payments"},
        "team_id":   {"team_9f2c": "acme-payments"}
      }
    }

Resolution precedence is most-specific-first: `key_hash`, then `key_alias`, then
`team_id`.  A key bound directly overrides its team, which is what an operator
means by binding a key directly.

THERE IS NO DEFAULT TENANT AND THE LOADER REFUSES TO ACCEPT ONE.  A `default`,
`*` or `fallback` entry is a LOAD ERROR (`TenancyConfigError`), not a warning:
a catch-all is precisely the defect this module exists to prevent, and a
deployment that grows a second department would inherit it silently.  An
unresolved identity is `deny`, with a reason that names the identity that
arrived and the env var to fix it -- so an operator sees a refusal that tells
them what to do, rather than evidence quietly filed under the wrong company.

NO MAP CONFIGURED IS ALSO A DENY.  It is not "tenancy off": a seat that ships
disabled by default would put every deployment one un-read README away from the
defect.  Configuring one tenant is eight lines of JSON, and a single-tenant
operator who writes them has NAMED their org rather than defaulted into one.

WHAT THIS MODULE DOES NOT DO
============================
It does not authenticate anything.  `user_api_key_dict` is the proxy's
authentication result and this module trusts it exactly as far as the proxy's
own code does.  If LiteLLM's key auth is wrong, this is wrong with it.

It does not make the Reeflex org true.  Isolation of the evidence and the holds
is enforced by the SERVER -- Postgres row-level security on `org_id` in
reeflex-app, where the org is derived from the gate token, never from a field a
client sends (EVIDENCE-INGEST-SPEC-v1 §3).  What this module decides is WHICH
GATE CREDENTIAL a request's evidence is signed with.  Naming the wrong org in a
record does not move the record; presenting the wrong credential does.

Env:
  REEFLEX_LITELLM_TENANCY_MAP_FILE  path to the JSON map (preferred)
  REEFLEX_LITELLM_TENANCY_MAP       the JSON map inline
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from typing import Any, Mapping, Optional

MAP_FILE_ENV = "REEFLEX_LITELLM_TENANCY_MAP_FILE"
MAP_INLINE_ENV = "REEFLEX_LITELLM_TENANCY_MAP"

# The refusal identifiers an unresolved caller produces.  `ERROR_UNMAPPED` is
# the caller-visible `error`; `RULE_UNMAPPED` is the rule id, namespaced to this
# adapter because core did not decide it -- the request never reached core.
ERROR_UNMAPPED = "reeflex_tenant_unmapped"
RULE_UNMAPPED = "reeflex.litellm/tenancy_unmapped"

# litellm's constant for the master key's stand-in value (litellm/constants.py,
# LITELLM_PROXY_MASTER_KEY_ALIAS).  Hardcoded rather than imported so this
# module keeps working without litellm installed; pinned by
# tests/test_litellm_contract.py, which imports the real constant and asserts
# they are equal, so a rename upstream goes red here instead of silently
# turning every master-key request into an unrecognised identity.
MASTER_KEY_ALIAS = "litellm_proxy_master_key"

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Keys a `bind` table may NOT contain, in any binding dimension.  See the
# module docstring: a catch-all IS the defect.
_FORBIDDEN_BIND_KEYS = frozenset({"*", "default", "fallback", "any", ""})

_BIND_DIMENSIONS = ("key_hash", "key_alias", "team_id")


class TenancyConfigError(ValueError):
    """The map is absent, unreadable or unsafe.  Always fail closed on this."""


class GatewayIdentity:
    """What the PROXY says about the caller.  Never caller-supplied.

    Every field is Optional because a deployment may authenticate with a team
    key and no alias, an alias and no team, or the master key and neither.
    `key_hash` is None whenever the presented credential could not be shown to
    be non-secret -- see `safe_key_hash()`.
    """

    __slots__ = ("key_hash", "key_alias", "team_id", "team_alias",
                 "litellm_org_id", "litellm_org_alias", "user_id",
                 "end_user_id", "via_virtual_key", "key_material_withheld")

    def __init__(self, key_hash=None, key_alias=None, team_id=None,
                 team_alias=None, litellm_org_id=None, litellm_org_alias=None,
                 user_id=None, end_user_id=None, via_virtual_key=False,
                 key_material_withheld=False):
        self.key_hash = key_hash
        self.key_alias = key_alias
        self.team_id = team_id
        self.team_alias = team_alias
        self.litellm_org_id = litellm_org_id
        self.litellm_org_alias = litellm_org_alias
        self.user_id = user_id
        self.end_user_id = end_user_id
        self.via_virtual_key = via_virtual_key
        # True when an api_key was present but failed the non-secret test, so
        # it was DROPPED rather than recorded.  Surfaced so an operator can see
        # why their key did not match, without the value ever being written.
        self.key_material_withheld = key_material_withheld

    def describe(self) -> str:
        """A short, non-secret description for a refusal reason and a log line.

        Deliberately does NOT include `key_hash` in full: the digest of a live
        credential is not itself a credential, but it is an offline-guessable
        one for a short key, and the first 12 characters identify the key for an
        operator just as well.
        """
        bits = []
        if self.key_alias:
            bits.append("key_alias=%s" % self.key_alias)
        if self.key_hash:
            bits.append("key=%s..." % self.key_hash[:12])
        if self.team_id:
            bits.append("team_id=%s" % self.team_id)
        if self.team_alias:
            bits.append("team=%s" % self.team_alias)
        if self.user_id:
            bits.append("user_id=%s" % self.user_id)
        if self.key_material_withheld:
            bits.append("key=<withheld: not a proxy-issued virtual key>")
        return ", ".join(bits) if bits else "no key, team or user identity"

    def as_record(self) -> dict:
        """The non-secret identity facts, for `gateway_routing` and the ledger."""
        out = {
            "key_alias": self.key_alias,
            "key_hash_prefix": self.key_hash[:12] if self.key_hash else None,
            "team_id": self.team_id,
            "team_alias": self.team_alias,
            "litellm_org_id": self.litellm_org_id,
            "user_id": self.user_id,
            "end_user_id": self.end_user_id,
            "via_virtual_key": bool(self.via_virtual_key),
        }
        if self.key_material_withheld:
            out["key_material_withheld"] = True
        return out


class Tenant:
    """One Reeflex org, and the gateway facts that belong to it."""

    __slots__ = ("org", "label", "principal", "environment", "on_prem_hosts",
                 "cloud_hosts", "evidence", "matched_on", "matched_value")

    def __init__(self, org, label=None, principal=None, environment=None,
                 on_prem_hosts=(), cloud_hosts=(), evidence=None,
                 matched_on=None, matched_value=None):
        self.org = org
        self.label = label or org
        self.principal = principal
        self.environment = environment
        # Which model endpoints this tenant DECLARES as on-premise / as cloud.
        # A declaration, never an inference -- see routing.py's `placement`.
        self.on_prem_hosts = tuple(on_prem_hosts or ())
        self.cloud_hosts = tuple(cloud_hosts or ())
        self.evidence = dict(evidence or {})
        # How this tenant was reached on THIS request.  Set by resolve(), not by
        # the map: the same tenant can be reached by key on one request and by
        # team on the next, and an evidence record that says which is a record
        # an operator can audit their own map with.
        self.matched_on = matched_on
        self.matched_value = matched_value

    def bound(self, matched_on: str, matched_value: Optional[str]) -> "Tenant":
        return Tenant(self.org, self.label, self.principal, self.environment,
                      self.on_prem_hosts, self.cloud_hosts, self.evidence,
                      matched_on=matched_on, matched_value=matched_value)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("Tenant(org=%r, matched_on=%r)" % (self.org, self.matched_on))


# The sentinel used by the library API when no tenancy resolution has happened.
# It has NO org, which is the point: it can never be mistaken for a real tenant
# and it cannot select a gate credential.  `guardrail.py` never produces it --
# a request that reaches the hook is always resolved or refused.  It exists so
# `enforce.rule_one_call()` stays callable in a unit test without a map, and so
# an envelope built that way is STAMPED `tenancy: "unscoped"` rather than
# looking tenant-scoped.
UNSCOPED = Tenant(org=None, label="unscoped", matched_on="unscoped")


class Resolution:
    """The answer for one request: a tenant, or a refusal reason."""

    __slots__ = ("tenant", "identity", "reason")

    def __init__(self, tenant: Optional[Tenant], identity: GatewayIdentity,
                 reason: Optional[str] = None):
        self.tenant = tenant
        self.identity = identity
        self.reason = reason

    @property
    def resolved(self) -> bool:
        return self.tenant is not None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return ("Resolution(tenant=%r, reason=%r)"
                % (self.tenant.org if self.tenant else None, self.reason))


# ---------------------------------------------------------------------------
# Reading the proxy's authentication result
# ---------------------------------------------------------------------------

def safe_key_hash(api_key, via_virtual_key: bool):
    """The key identifier, or (None, withheld) when it is not safe to record.

    Returns `(value, withheld)`.  `value` is non-None only when litellm's own
    two conditions hold: the proxy authenticated the key (`via_virtual_key`) AND
    the value has a known non-secret shape -- the master key's alias, or a
    sha256 hex digest, which is what `hash_token()` produces for every `sk-`
    virtual key.  Anything else is a credential that a `custom_auth` callback
    put there raw, and it is dropped.

    `withheld` is True when something WAS present and was dropped, so a refusal
    can say "your key was not recognised because it is not a proxy-issued
    virtual key" instead of "no key" -- two very different operator problems.
    """
    if not isinstance(api_key, str) or not api_key.strip():
        return None, False
    if not via_virtual_key:
        return None, True
    v = api_key.strip()
    if v == MASTER_KEY_ALIAS or _SHA256_HEX.match(v):
        return v, False
    return None, True


def _get(obj, name):
    """Read one attribute from a pydantic model OR a plain dict.

    Both shapes are real: litellm hands the hook a `UserAPIKeyAuth`, and the
    package's own tests -- which must run without litellm installed -- use
    dicts.  Reading both here keeps a single code path under test.
    """
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _s(v) -> Optional[str]:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return None


def read_identity(user_api_key_dict) -> GatewayIdentity:
    """Extract the non-secret identity facts from the proxy's auth result."""
    via = bool(_get(user_api_key_dict, "via_virtual_key"))
    key_hash, withheld = safe_key_hash(_get(user_api_key_dict, "api_key"), via)
    if key_hash is None and not withheld:
        # Fall back to the DB column, which is the stored (hashed) token.  Held
        # to the same shape test: a `custom_auth` object can populate it too.
        key_hash, withheld = safe_key_hash(_get(user_api_key_dict, "token"), via)
    return GatewayIdentity(
        key_hash=key_hash,
        key_alias=_s(_get(user_api_key_dict, "key_alias")),
        team_id=_s(_get(user_api_key_dict, "team_id")),
        team_alias=_s(_get(user_api_key_dict, "team_alias")),
        litellm_org_id=_s(_get(user_api_key_dict, "org_id")),
        litellm_org_alias=_s(_get(user_api_key_dict, "organization_alias")),
        user_id=_s(_get(user_api_key_dict, "user_id")),
        end_user_id=_s(_get(user_api_key_dict, "end_user_id")),
        via_virtual_key=via,
        key_material_withheld=withheld,
    )


# ---------------------------------------------------------------------------
# The map
# ---------------------------------------------------------------------------

class TenancyMap:
    """A loaded, validated binding from gateway identity to Reeflex org."""

    __slots__ = ("tenants", "bind", "source")

    def __init__(self, tenants: dict, bind: dict, source: str):
        self.tenants = tenants
        self.bind = bind
        self.source = source

    def resolve(self, identity: GatewayIdentity) -> Resolution:
        for dimension, value in (("key_hash", identity.key_hash),
                                 ("key_alias", identity.key_alias),
                                 ("team_id", identity.team_id)):
            if not value:
                continue
            org = self.bind.get(dimension, {}).get(value)
            if org:
                return Resolution(self.tenants[org].bound(dimension, value),
                                  identity)
        return Resolution(None, identity, _unmapped_reason(identity, self.source))


def _unmapped_reason(identity: GatewayIdentity, source: str) -> str:
    return (
        "Reeflex: this gateway caller is not mapped to a Reeflex org, so the "
        "tool call was not ruled on and is refused. The proxy authenticated "
        "[%s]. Bind it in the tenancy map (%s) under key_hash, key_alias or "
        "team_id. There is deliberately no default org: filing one "
        "department's actions under another department's evidence would be "
        "worse than this refusal." % (identity.describe(), source)
    )


def _no_map_reason(detail: str) -> str:
    return (
        "Reeflex: the gateway has no usable tenancy map, so no tool call can "
        "be attributed to a Reeflex org and all are refused: %s. Set %s (a "
        "path to the JSON map) or %s (the map inline)."
        % (detail, MAP_FILE_ENV, MAP_INLINE_ENV)
    )


def parse_map(raw: Any, source: str) -> TenancyMap:
    """Validate a decoded map.  Raises TenancyConfigError on anything unsafe."""
    if not isinstance(raw, dict):
        raise TenancyConfigError("tenancy map must be a JSON object, got %s"
                                 % type(raw).__name__)

    tenants_raw = raw.get("tenants")
    if not isinstance(tenants_raw, dict) or not tenants_raw:
        raise TenancyConfigError("tenancy map has no `tenants` object")

    tenants = {}
    for name, spec in tenants_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise TenancyConfigError("tenant name must be a non-empty string")
        if not isinstance(spec, dict):
            raise TenancyConfigError("tenant %r must be a JSON object" % name)
        org = spec.get("org") or name
        if not isinstance(org, str) or not org.strip():
            raise TenancyConfigError("tenant %r has an empty `org`" % name)
        env = spec.get("environment")
        if env is not None and env not in ("production", "staging", "dev"):
            # Rejected rather than coerced: silently downgrading an operator's
            # typo'd "prod" to the default would change which R2/R3 branch runs.
            raise TenancyConfigError(
                "tenant %r has environment %r; allowed: production, staging, dev"
                % (name, env))
        evidence = spec.get("evidence")
        if evidence is not None and not isinstance(evidence, dict):
            raise TenancyConfigError("tenant %r `evidence` must be an object"
                                     % name)
        _reject_inline_secrets(name, evidence or {})
        tenants[name.strip()] = Tenant(
            org=org.strip(),
            label=spec.get("label"),
            principal=spec.get("principal"),
            environment=env,
            on_prem_hosts=_host_list(name, "on_prem_hosts", spec),
            cloud_hosts=_host_list(name, "cloud_hosts", spec),
            evidence=evidence or {},
        )

    bind_raw = raw.get("bind")
    if not isinstance(bind_raw, dict) or not bind_raw:
        raise TenancyConfigError("tenancy map has no `bind` object")

    for unknown in set(bind_raw) - set(_BIND_DIMENSIONS):
        raise TenancyConfigError(
            "tenancy map `bind` has unknown dimension %r; allowed: %s"
            % (unknown, ", ".join(_BIND_DIMENSIONS)))

    bind = {}
    for dimension in _BIND_DIMENSIONS:
        table = bind_raw.get(dimension) or {}
        if not isinstance(table, dict):
            raise TenancyConfigError("`bind.%s` must be an object" % dimension)
        clean = {}
        for k, v in table.items():
            key = k.strip() if isinstance(k, str) else k
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_BIND_KEYS:
                # THE CATCH-ALL REFUSAL.  See the module docstring.
                raise TenancyConfigError(
                    "`bind.%s` contains a catch-all entry %r. There is no "
                    "default org by design: bind every key or team "
                    "explicitly, and let an unknown one be refused."
                    % (dimension, k))
            if v not in tenants:
                raise TenancyConfigError(
                    "`bind.%s[%s]` names tenant %r, which is not in `tenants`"
                    % (dimension, key, v))
            clean[key] = v
        bind[dimension] = clean

    if not any(bind[d] for d in _BIND_DIMENSIONS):
        raise TenancyConfigError("tenancy map binds nothing: every `bind` "
                                 "table is empty, so every caller is refused")

    return TenancyMap(tenants, bind, source)


def _host_list(tenant_name: str, field: str, spec: dict) -> tuple:
    """A declared host list, lower-cased.  Rejected rather than coerced if not
    a list of strings: an operator who wrote a bare string meant one host and
    would otherwise get a per-character list that matches nothing, silently
    turning every declaration into `undeclared`."""
    raw = spec.get(field)
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)) or not all(
            isinstance(h, str) for h in raw):
        raise TenancyConfigError(
            "tenant %r `%s` must be a list of host strings" % (tenant_name, field))
    return tuple(h.strip().lower() for h in raw if h.strip())


def _reject_inline_secrets(name: str, evidence: dict) -> None:
    """Refuse a map that carries credential VALUES rather than references.

    The map is a config file an operator will copy between hosts, paste into a
    ticket and check into git.  A gate token or an evidence signing key written
    into it is a credential in all three places.  Only `*_env` references and a
    URL are accepted; the value-carrying spellings are named explicitly so the
    error tells the operator what to write instead.
    """
    for bad, good in (("gate_token", "gate_token_env"),
                      ("signing_key", "signing_key_env"),
                      ("evidence_key", "signing_key_env"),
                      ("token", "gate_token_env")):
        if bad in evidence:
            raise TenancyConfigError(
                "tenant %r `evidence` carries %r inline. Reference the "
                "credential by environment-variable NAME instead: %r."
                % (name, bad, good))


# ---------------------------------------------------------------------------
# Loading, with a cache keyed on the configuration that produced it
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_cache = None            # tuple(cache_key, TenancyMap)


def load_map(force: bool = False) -> TenancyMap:
    """Load and validate the map.  Raises TenancyConfigError when unusable.

    Cached on the (file path, mtime, size, inline JSON) tuple, so an operator
    editing the map file gets the new one on the next request without a proxy
    restart, and a test changing the env var is not served a stale map.  The
    hook calls this per request; the cache is what keeps that free (measured in
    the README's latency table).
    """
    global _cache
    key = _cache_key()
    if not force:
        cached = _cache
        if cached is not None and cached[0] == key:
            return cached[1]
    with _lock:
        cached = _cache
        if not force and cached is not None and cached[0] == key:
            return cached[1]
        loaded = _load_uncached()
        _cache = (key, loaded)
        return loaded


def _cache_key():
    path = os.environ.get(MAP_FILE_ENV, "").strip()
    stat = None
    if path:
        try:
            st = os.stat(path)
            stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            stat = None
    return (path, stat, os.environ.get(MAP_INLINE_ENV, ""))


def _load_uncached() -> TenancyMap:
    path = os.environ.get(MAP_FILE_ENV, "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except OSError as exc:
            raise TenancyConfigError("cannot read %s=%s: %s"
                                     % (MAP_FILE_ENV, path, exc)) from exc
        except ValueError as exc:
            raise TenancyConfigError("%s=%s is not valid JSON: %s"
                                     % (MAP_FILE_ENV, path, exc)) from exc
        return parse_map(raw, "%s=%s" % (MAP_FILE_ENV, path))

    inline = os.environ.get(MAP_INLINE_ENV, "").strip()
    if inline:
        try:
            raw = json.loads(inline)
        except ValueError as exc:
            raise TenancyConfigError("%s is not valid JSON: %s"
                                     % (MAP_INLINE_ENV, exc)) from exc
        return parse_map(raw, MAP_INLINE_ENV)

    raise TenancyConfigError("neither %s nor %s is set"
                             % (MAP_FILE_ENV, MAP_INLINE_ENV))


def reset_cache() -> None:
    """Drop the cached map.  For tests and for an operator-triggered reload."""
    global _cache
    with _lock:
        _cache = None


# ---------------------------------------------------------------------------
# The one call the hook makes
# ---------------------------------------------------------------------------

def resolve(user_api_key_dict) -> Resolution:
    """Map one authenticated gateway caller to a Reeflex org.

    NEVER raises and NEVER returns a tenant it did not find.  A broken map, an
    absent map and an unbound key all produce `Resolution(tenant=None)` with a
    reason the operator can act on -- and the caller of this function turns that
    into a refusal.  There is no path through this function that returns a
    tenant for an identity the map does not name.
    """
    identity = read_identity(user_api_key_dict)
    try:
        mapping = load_map()
    except TenancyConfigError as exc:
        return Resolution(None, identity, _no_map_reason(str(exc)))
    except Exception as exc:  # pragma: no cover - defensive; still fail closed
        return Resolution(None, identity,
                          _no_map_reason("%s: %s" % (type(exc).__name__, exc)))
    return mapping.resolve(identity)


def session_scope(tenant: Optional[Tenant]) -> str:
    """The session-id namespace for a tenant.

    R5's cumulative budget is keyed on `agent.session_id`.  Two departments
    behind one gateway that both name their session `nightly` must not share a
    budget, so the tenant's org is part of the namespace.  `unscoped` is used
    when there is no tenant, so a namespace collision with a real org is not
    possible either.
    """
    if tenant is None or not tenant.org:
        return "unscoped"
    return tenant.org


def digest(value: str) -> str:
    """sha256 hex of a string -- for an operator computing a `key_hash` entry.

    Exposed because the map's `key_hash` dimension must hold exactly what
    litellm's `hash_token()` produces, and an operator should not have to guess
    the algorithm.  `reeflex-litellm key-hash <key>` in cli.py calls this.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
