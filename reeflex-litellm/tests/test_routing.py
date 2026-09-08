"""
`gateway_routing`: which model answered, where it ran, whose key asked (RFX-243).

WHY THIS BLOCK NEEDS ITS OWN TESTS
==================================
A hook sits in front of one system. A gateway does not: the same envelope from
the same company may have been answered by a model on a box in the building or
by a model in someone else's cloud. A record that cannot say which cannot answer
the question an auditor asks.

The property defended here is that every field is READ, not inferred -- with one
labelled exception. `placement` is DECLARED by the operator, because an
`api_base` host does not carry whether it is on-premise: a VPC endpoint in a
public cloud is private too, and a reverse proxy in the building can be public.
A record that says `undeclared` is worth more than one that says `cloud` because
a heuristic said so.
"""

from __future__ import annotations

import json

import pytest

from reeflex_litellm import routing, tenancy

import conftest


def response(api_base=None, model="gpt-4o-mini-2024", model_id=None,
             provider=None):
    hidden = {}
    if api_base is not None:
        hidden["api_base"] = api_base
    if model_id is not None:
        hidden["model_id"] = model_id
    if provider is not None:
        hidden["custom_llm_provider"] = provider
    return {"model": model, "_hidden_params": hidden}


def build(data=None, resp=None, tenant=None, identity=None,
          model="gpt-4o-mini"):
    return routing.build(data=data if data is not None else {"model": model},
                         response=resp if resp is not None else response(),
                         tenant=tenant, identity=identity, model=model)


# ---------------------------------------------------------------------------
# What answered
# ---------------------------------------------------------------------------

def test_it_records_the_model_the_caller_asked_for_and_the_one_that_answered():
    """Two different facts. A proxy routing a model GROUP answers with a
    concrete deployment, and an auditor asking "what ran?" needs the second."""
    block = build(data={"model": "gpt-4o-mini"},
                  resp=response(model="gpt-4o-mini-2024-07-18"))
    assert block["model_requested"] == "gpt-4o-mini"
    assert block["model_served"] == "gpt-4o-mini-2024-07-18"


def test_it_records_the_deployment_id_the_proxy_publishes():
    """`model_id` is what litellm puts in its own `x-litellm-model-id` response
    header, so this is a value the proxy already publishes, not an internal."""
    block = build(resp=response(model_id="deployment-7"))
    assert block["deployment_id"] == "deployment-7"


def test_it_names_the_gateway_and_the_adapter():
    block = build()
    assert block["gateway"] == "litellm"
    assert block["adapter"] == "reeflex-litellm"


def test_it_records_whether_the_caller_asked_for_a_stream():
    """RFX-242: `mode: post_call` does not fire for a streamed response, so a
    streamed tool call is UNGOVERNED by this seat. Recording the flag is what
    lets an operator find the requests this seat could not rule on."""
    assert build(data={"model": "m", "stream": True})["stream"] is True
    assert build(data={"model": "m"})["stream"] is False


def test_a_response_with_no_hidden_params_still_produces_a_block():
    """Never raises: it is on the path that produces a governance record, and a
    routing block that could throw would turn a missing label into a failed
    decision."""
    block = routing.build(data={}, response={}, tenant=None, identity=None,
                          model="m")
    assert block["api_base_host"] is None
    assert block["placement"] == "undeclared"


def test_a_hidden_params_of_the_wrong_type_is_survived():
    block = routing.build(data={}, response={"_hidden_params": "nonsense"},
                          tenant=None, identity=None, model="m")
    assert block["api_base_host"] is None


# ---------------------------------------------------------------------------
# The api_base is reduced to a host, and cannot carry a credential
# ---------------------------------------------------------------------------

def test_the_api_base_is_reduced_to_host_and_port():
    block = build(resp=response(api_base="https://api.openai.com/v1/chat"))
    assert block["api_base_host"] == "api.openai.com"


def test_a_non_default_port_is_kept():
    """An operator running two models on one box distinguishes them by port."""
    block = build(resp=response(api_base="http://10.1.2.3:8000/v1"))
    assert block["api_base_host"] == "10.1.2.3:8000"


def test_a_credential_in_the_api_base_does_not_survive():
    """A URL can carry userinfo, and this value is written to an evidence
    ledger. A secret that reaches a ledger outlives the request."""
    block = build(resp=response(
        api_base="https://user:s3cret-token@llm.internal.example/v1"))
    assert block["api_base_host"] == "llm.internal.example"
    assert "s3cret-token" not in json.dumps(block)
    assert "user" not in (block["api_base_host"] or "")


def test_a_path_and_query_do_not_survive():
    """A path can carry a deployment name or an API version that is not ours to
    publish."""
    block = build(resp=response(
        api_base="https://acme.openai.azure.com/openai/deployments/secret-dep"
                 "/chat?api-version=2024-02-01"))
    assert block["api_base_host"] == "acme.openai.azure.com"
    assert "secret-dep" not in json.dumps(block)


def test_an_unparseable_api_base_becomes_None_rather_than_being_echoed():
    """An unparseable value could be anything, including a credential."""
    block = build(resp=response(api_base="http://[not-an-address"))
    assert block["api_base_host"] is None


def test_a_bare_host_with_no_scheme_is_still_read():
    block = build(resp=response(api_base="llm.internal.example:9000"))
    assert block["api_base_host"] == "llm.internal.example:9000"


def test_the_host_is_lowercased_so_a_declaration_matches():
    block = build(resp=response(api_base="https://LLM.Internal.Example/v1"))
    assert block["api_base_host"] == "llm.internal.example"


# ---------------------------------------------------------------------------
# `api_base_is_private` is a MEASURED hint, and says None when it cannot know
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host,expected", [
    ("http://127.0.0.1:8000", True),
    ("http://localhost:8000", True),
    ("http://10.1.2.3", True),
    ("http://192.168.1.10", True),
    ("http://172.16.0.9", True),
    ("http://169.254.1.1", True),
    ("https://8.8.8.8", False),
])
def test_an_ip_literal_is_measured_private_or_public(host, expected):
    assert build(resp=response(api_base=host))["api_base_is_private"] is expected


def test_a_dns_name_reports_None_because_this_code_did_not_resolve_it():
    """None, NOT False. Recording False for `llm.internal.acme.example` would
    be an assertion the instrument cannot make -- and it is the assertion an
    auditor would most want to be true."""
    block = build(resp=response(api_base="https://llm.internal.acme.example/v1"))
    assert block["api_base_is_private"] is None


def test_an_ipv6_loopback_is_measured():
    assert build(resp=response(api_base="http://[::1]:8000"))[
        "api_base_is_private"] is True


# ---------------------------------------------------------------------------
# `placement` is DECLARED, never guessed -- the labelled exception
# ---------------------------------------------------------------------------

def test_a_host_the_tenant_declared_on_prem_is_on_prem(tenancy_map):
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(resp=response(api_base="https://llm.internal.acme.example/v1"),
                  tenant=tenant)
    assert block["placement"] == "on_prem"


def test_a_host_the_tenant_declared_cloud_is_cloud(tenancy_map):
    tenant = tenancy.resolve(conftest.caller(team_id="team_mkt")).tenant
    block = build(resp=response(api_base="https://api.openai.com/v1"),
                  tenant=tenant)
    assert block["placement"] == "cloud"


def test_an_undeclared_host_is_undeclared_and_is_NEVER_guessed_cloud(
        tenancy_map):
    """THE LOAD-BEARING ONE. A public-looking host is still `undeclared`,
    because a reverse proxy in the building can be public and this code cannot
    tell. An honest `undeclared` is worth more than a confident guess."""
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(resp=response(api_base="https://api.anthropic.com/v1"),
                  tenant=tenant)
    assert block["placement"] == "undeclared"


def test_a_PRIVATE_address_is_still_undeclared_without_a_declaration(
        tenancy_map):
    """The other half: a private address is a good hint and a bad fact -- a VPC
    endpoint in a public cloud is private too. The hint is recorded separately;
    it does not become the placement."""
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(resp=response(api_base="http://10.0.0.5:8000"), tenant=tenant)
    assert block["api_base_is_private"] is True
    assert block["placement"] == "undeclared"


def test_a_declaration_matches_regardless_of_port(tenancy_map):
    """An operator declares a MACHINE, not a listener. Requiring the port would
    make a declaration silently stop applying the day someone moves the model
    to another port."""
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(resp=response(
        api_base="https://llm.internal.acme.example:8443/v1"), tenant=tenant)
    assert block["placement"] == "on_prem"


def test_a_proxy_wide_env_declaration_applies_when_a_tenant_declares_nothing(
        monkeypatch, tenancy_map):
    monkeypatch.setenv("REEFLEX_LITELLM_ONPREM_HOSTS",
                       "gpu-1.dc.example, gpu-2.dc.example")
    tenant = tenancy.resolve(conftest.caller(team_id="team_mkt")).tenant
    block = build(resp=response(api_base="https://gpu-2.dc.example/v1"),
                  tenant=tenant)
    assert block["placement"] == "on_prem"


def test_a_host_declared_both_ways_resolves_to_on_prem(monkeypatch,
                                                       tenancy_map):
    """A contradiction is the operator's to fix. Reading it as the narrower of
    the two is the safer reading of their intent, and it is documented."""
    monkeypatch.setenv("REEFLEX_LITELLM_CLOUD_HOSTS",
                       "llm.internal.acme.example")
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(resp=response(api_base="https://llm.internal.acme.example/v1"),
                  tenant=tenant)
    assert block["placement"] == "on_prem"


def test_placement_is_undeclared_when_there_is_no_tenant_and_no_env():
    assert build(resp=response(api_base="https://api.openai.com/v1"))[
        "placement"] == "undeclared"


# ---------------------------------------------------------------------------
# Who asked
# ---------------------------------------------------------------------------

def test_it_records_the_tenant_and_how_the_tenant_was_reached(tenancy_map):
    """`matched_on` lets an operator audit their own map: the same tenant can
    be reached by key on one request and by team on the next."""
    tenant = tenancy.resolve(conftest.caller(team_id="team_pay")).tenant
    block = build(tenant=tenant)
    assert block["tenant"]["org"] == "acme-payments"
    assert block["tenant"]["label"] == "ACME Payments"
    assert block["tenant"]["matched_on"] == "team_id"
    assert block["tenant"]["matched_value"] == "team_pay"


def test_it_records_the_calling_key_and_team_without_key_material(tenancy_map):
    identity = tenancy.read_identity(conftest.caller(
        team_id="team_pay", key_alias="payments-bot", api_key="a" * 64))
    block = build(identity=identity)
    caller = block["caller"]
    assert caller["key_alias"] == "payments-bot"
    assert caller["team_id"] == "team_pay"
    assert caller["key_hash_prefix"] == "a" * 12
    assert caller["via_virtual_key"] is True
    assert "a" * 64 not in json.dumps(block)


def test_litellms_own_org_id_is_recorded_under_its_own_name(tenancy_map):
    """Recorded so an operator can correlate with litellm's own admin UI, and
    named `litellm_org_id` so it can never be read as a Reeflex org."""
    identity = tenancy.read_identity(conftest.caller(team_id="team_pay",
                                                     org_id="litellm-org-7"))
    block = build(identity=identity)
    assert block["caller"]["litellm_org_id"] == "litellm-org-7"
    assert "org" not in block["caller"]


def test_the_block_carries_no_prompt_or_tool_arguments():
    """§1's principle -- metadata only, never payloads -- is the right rule for
    the adapter's own ledger too."""
    block = build(data={"model": "m",
                        "messages": [{"role": "user",
                                      "content": "my secret prompt"}],
                        "tools": [{"function": {"name": "run_shell"}}]},
                  resp=response())
    text = json.dumps(block)
    assert "my secret prompt" not in text
    assert "messages" not in block
    assert "tools" not in block
