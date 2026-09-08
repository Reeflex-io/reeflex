"""
routing.py -- `gateway_routing`: which model answered, where it ran, whose key asked.

WHY A GATEWAY DECISION NEEDS THIS AND A HOOK DOES NOT
=====================================================
The Claude Code hook and the WordPress gate each sit in ONE place, in front of
ONE system.  A gateway does not: the same envelope, from the same company, may
have been answered by a model on a box in the building or by a model in someone
else's cloud, and the two are different facts about where the company's prompt
and the proposed action travelled.  A decision record that does not say which
cannot answer the question an auditor actually asks.

EVERY FIELD HERE IS READ, NOT INFERRED -- WITH ONE EXPLICIT EXCEPTION
=====================================================================
Measured against litellm 1.100.0:

  response._hidden_params   the proxy's OWN source for the `x-litellm-api-base`
                            and `x-litellm-model-id` response headers
                            (`ProxyBaseLLMRequestProcessing` in
                            `proxy/common_request_processing.py` reads exactly
                            `hidden_params["api_base"]`, `["model_id"]`).  So
                            `api_base` and `model_id` are values the proxy
                            already publishes about this request, not something
                            this module reaches into internals for.
  response.model            the model that actually answered.
  data["model"]             the model group the caller asked for.
  data["stream"]            whether the caller asked for a stream.
  user_api_key_dict         the caller's authenticated key/team (tenancy.py).

THE EXCEPTION IS `placement`, AND IT IS A DECLARATION.
An `api_base` host does not carry whether it is on-premise.  A private RFC1918
address is a good hint and a bad fact -- a VPC endpoint in a public cloud is
private too, and a reverse proxy in the building can be public.  So:

  * `api_base_is_private` is MEASURED -- loopback / RFC1918 / link-local /
    unique-local, computed from the host.  It is a hint, labelled as one.
  * `placement` is DECLARED by the operator, per tenant, in the tenancy map's
    `on_prem_hosts` / `cloud_hosts`.  A host in neither list is
    `"undeclared"` -- never guessed into `"cloud"`.  An evidence record that
    says `undeclared` is worth more than one that says `cloud` because a
    heuristic said so.

WHAT IS DELIBERATELY NOT RECORDED
=================================
No prompt, no completion, no tool arguments -- `gateway_routing` is routing
metadata, and the ingest contract's §1 principle ("metadata only, never
payloads") is the right rule for the adapter's own ledger too.

The `api_base` is reduced to HOST[:PORT].  A URL can carry credentials
(`https://user:token@host/...`) and a path can carry a deployment name or an
API version that is not ours to publish; `_host_of()` drops userinfo, path,
query and fragment, and the test suite asserts a credential-bearing api_base
does not survive it.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from . import tenancy as _tenancy

GATEWAY = "litellm"

# Global fallbacks for operators running one placement policy across every
# tenant.  A tenant's own declaration wins.
ONPREM_HOSTS_ENV = "REEFLEX_LITELLM_ONPREM_HOSTS"
CLOUD_HOSTS_ENV = "REEFLEX_LITELLM_CLOUD_HOSTS"

PLACEMENT_ON_PREM = "on_prem"
PLACEMENT_CLOUD = "cloud"
PLACEMENT_UNDECLARED = "undeclared"


def _get(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _s(v) -> Optional[str]:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return None


def _host_of(api_base) -> Optional[str]:
    """HOST[:PORT] from a URL, with userinfo, path, query and fragment dropped.

    Returns None for anything unparseable rather than echoing the raw string --
    an unparseable `api_base` could be anything, including a credential, and
    this value is written to an evidence ledger.
    """
    v = _s(api_base)
    if v is None:
        return None
    try:
        parts = urlsplit(v if "//" in v else "//" + v)
        host = parts.hostname
        if not host:
            return None
        port = parts.port
    except ValueError:
        return None
    host = host.lower()
    return "%s:%d" % (host, port) if port else host


def _is_private(host_port: Optional[str]) -> Optional[bool]:
    """True/False when the host is an IP literal or `localhost`; None otherwise.

    None -- not False -- for a DNS name, because this function did not resolve
    it and does not know.  Recording False for `llm.internal.acme.example`
    would be an assertion the instrument cannot make.
    """
    if not host_port:
        return None
    host = host_port.rsplit(":", 1)[0] if ":" in host_port else host_port
    host = host.strip("[]")
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def _env_hosts(name: str) -> tuple:
    raw = os.environ.get(name, "")
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def placement_of(host_port: Optional[str],
                 tenant: Optional["_tenancy.Tenant"]) -> str:
    """The operator's DECLARED placement for this endpoint, or `undeclared`.

    Matching is on the host, ignoring the port: an operator declares a machine,
    not a listener, and requiring the port would make a declaration silently
    stop applying the day someone moves the model to another port.
    """
    if not host_port:
        return PLACEMENT_UNDECLARED
    host = host_port.rsplit(":", 1)[0] if ":" in host_port else host_port
    on_prem = tuple(getattr(tenant, "on_prem_hosts", ()) or ()) + \
        _env_hosts(ONPREM_HOSTS_ENV)
    cloud = tuple(getattr(tenant, "cloud_hosts", ()) or ()) + \
        _env_hosts(CLOUD_HOSTS_ENV)
    # on-prem is checked first: if an operator has declared a host both ways
    # the safer reading of their intent is the narrower one, and the
    # contradiction is theirs to fix.
    for declared in on_prem:
        if host == declared or host_port == declared:
            return PLACEMENT_ON_PREM
    for declared in cloud:
        if host == declared or host_port == declared:
            return PLACEMENT_CLOUD
    return PLACEMENT_UNDECLARED


def build(*, data: dict, response: Any,
          tenant: Optional["_tenancy.Tenant"],
          identity: Optional["_tenancy.GatewayIdentity"],
          model: str) -> dict:
    """The `gateway_routing` block for one request.

    Never raises: it is called on the path that produces a governance record,
    and a routing block that could throw would turn a missing label into a
    failed decision.  Anything it cannot read is `None`, which reads as "this
    gateway did not know", not as a value.
    """
    hidden = _get(response, "_hidden_params") or {}
    if not isinstance(hidden, Mapping):
        hidden = {}

    api_base_host = _host_of(hidden.get("api_base"))
    served = _s(_get(response, "model"))
    requested = _s(data.get("model")) or _s(
        (data.get("metadata") or {}).get("model_group")
            if isinstance(data.get("metadata"), Mapping) else None)

    block = {
        "gateway": GATEWAY,
        "adapter": "reeflex-litellm",
        "model": model,
        "model_requested": requested,
        "model_served": served,
        "deployment_id": _s(hidden.get("model_id")),
        "provider": _s(hidden.get("custom_llm_provider"))
                    or _s(_get(response, "custom_llm_provider")),
        "api_base_host": api_base_host,
        "api_base_is_private": _is_private(api_base_host),
        "placement": placement_of(api_base_host, tenant),
        "stream": bool(data.get("stream")),
        "tenant": {
            "org": getattr(tenant, "org", None),
            "label": getattr(tenant, "label", None),
            "matched_on": getattr(tenant, "matched_on", None),
            "matched_value": getattr(tenant, "matched_value", None),
        },
        "caller": identity.as_record() if identity is not None else None,
    }
    return block
