"""
Which Reeflex org a gateway caller belongs to -- and the refusals (RFX-243).

The isolation PROOF (two keys, two orgs, neither reads the other's holds) is in
test_tenancy_isolation.py. This file pins the mechanism underneath it: what the
map accepts, what it refuses to accept, and what an unresolved caller gets.

THE PROPERTY THIS FILE EXISTS TO DEFEND is that there is no path to a tenant the
map does not name. Every test below is either an instance of that or a
configuration the loader must reject because it would create one.
"""

from __future__ import annotations

import copy
import json

import pytest

from reeflex_litellm import tenancy as T

import conftest


# ---------------------------------------------------------------------------
# No map, and unknown callers: the fail-closed default
# ---------------------------------------------------------------------------

def test_with_no_map_configured_every_caller_is_refused():
    """NOT "tenancy off". A seat that shipped disabled by default would put
    every deployment one un-read README away from filing two departments'
    actions in one org."""
    res = T.resolve(conftest.caller(team_id="team_pay"))
    assert res.resolved is False
    assert res.tenant is None
    # The reason has to be actionable: it names BOTH env vars, because an
    # operator reading it has not yet chosen between file and inline.
    assert T.MAP_FILE_ENV in res.reason
    assert T.MAP_INLINE_ENV in res.reason


def test_a_caller_the_map_does_not_bind_is_refused_by_name(tenancy_map):
    """The reason names the identity that ARRIVED, so an operator can copy it
    into the map rather than guess which key was refused."""
    res = T.resolve(conftest.caller(team_id="team_unknown",
                                    key_alias="rogue-bot"))
    assert res.resolved is False
    assert "rogue-bot" in res.reason
    assert "team_unknown" in res.reason
    assert T.MAP_INLINE_ENV in res.reason


def test_the_refusal_reason_says_there_is_no_default_org(tenancy_map):
    """The absence of a fallback is a DESIGN decision, and the refusal says so.
    Without that sentence the first thing an operator does is look for the
    setting that turns on a default."""
    res = T.resolve(conftest.caller(team_id="nope"))
    assert "no default org" in res.reason


def test_a_caller_with_no_identity_at_all_is_refused(tenancy_map):
    res = T.resolve(conftest.caller())
    assert res.resolved is False
    assert "no key, team or user identity" in res.reason


def test_a_none_auth_object_is_refused_and_does_not_raise(tenancy_map):
    """litellm hands the hook `None` when there is no auth result. `resolve()`
    is on the request path and must never raise."""
    res = T.resolve(None)
    assert res.resolved is False
    assert res.tenant is None


def test_a_broken_map_refuses_rather_than_falling_back(monkeypatch):
    """An unparseable map is the case where "fail open" is most tempting and
    most wrong: the operator INTENDED tenancy, and their typo must not silently
    become one shared org."""
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP", "{not json")
    T.reset_cache()
    res = T.resolve(conftest.caller(team_id="team_pay"))
    assert res.resolved is False
    assert "not valid JSON" in res.reason


def test_an_unreadable_map_file_refuses(monkeypatch, tmp_path):
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP_FILE",
                       str(tmp_path / "absent.json"))
    T.reset_cache()
    res = T.resolve(conftest.caller(team_id="team_pay"))
    assert res.resolved is False
    assert "cannot read" in res.reason


# ---------------------------------------------------------------------------
# Resolution and precedence
# ---------------------------------------------------------------------------

def test_a_bound_team_resolves_to_its_org(tenancy_map):
    res = T.resolve(conftest.caller(team_id="team_pay"))
    assert res.resolved is True
    assert res.tenant.org == "acme-payments"
    assert res.tenant.matched_on == "team_id"
    assert res.tenant.matched_value == "team_pay"


def test_a_bound_key_alias_resolves_to_its_org(tenancy_map):
    res = T.resolve(conftest.caller(key_alias="marketing-bot"))
    assert res.tenant.org == "acme-marketing"
    assert res.tenant.matched_on == "key_alias"


def test_a_directly_bound_key_hash_overrides_the_team(install_map):
    """Precedence is most-specific-first. An operator who binds one KEY into a
    tenant means that key, even when its team points elsewhere -- otherwise
    the direct binding would be silently unreachable."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    # `team_mkt` -> marketing, but this key_hash -> payments.
    raw["bind"]["key_hash"] = {"d" * 64: "acme-payments"}
    install_map(raw)
    res = T.resolve(conftest.caller(team_id="team_mkt", api_key="d" * 64))
    assert res.tenant.org == "acme-payments"
    assert res.tenant.matched_on == "key_hash"


def test_a_key_alias_binding_overrides_the_team(install_map):
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["bind"]["key_alias"] = {"payments-bot": "acme-payments"}
    raw["bind"]["team_id"] = {"team_mkt": "acme-marketing"}
    install_map(raw)
    res = T.resolve(conftest.caller(team_id="team_mkt",
                                    key_alias="payments-bot"))
    assert res.tenant.org == "acme-payments"
    assert res.tenant.matched_on == "key_alias"


def test_the_tenant_carries_the_operators_declared_facts(tenancy_map):
    t = T.resolve(conftest.caller(team_id="team_pay")).tenant
    assert t.label == "ACME Payments"
    assert t.principal == "payments-oncall@acme.example"
    assert t.environment == "production"
    assert t.on_prem_hosts == ("llm.internal.acme.example",)


# ---------------------------------------------------------------------------
# The loader refuses to accept a catch-all -- THE defect this module prevents
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("catch_all", ["*", "default", "fallback", "any", "",
                                       "DEFAULT", "Fallback"])
@pytest.mark.parametrize("dimension", ["key_hash", "key_alias", "team_id"])
def test_a_catch_all_bind_entry_is_a_load_error(install_map, dimension,
                                                catch_all):
    """A LOAD ERROR, not a warning: a warning in a proxy log is a line nobody
    reads, and the deployment that grows a second department inherits the
    defect silently. Case-insensitive, because `DEFAULT` is the same mistake.
    """
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["bind"][dimension] = {catch_all: "acme-payments"}
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "catch-all" in str(exc.value)


def test_a_map_that_is_ONLY_a_catch_all_still_refuses(install_map):
    raw = {"version": 1,
           "tenants": {"solo": {"org": "solo"}},
           "bind": {"team_id": {"*": "solo"}}}
    with pytest.raises(T.TenancyConfigError):
        install_map(raw)


def test_a_map_binding_nothing_is_a_load_error(install_map):
    """Every bind table empty means every caller is refused. That is a
    configuration mistake, not a policy, so it fails at load where an operator
    is watching rather than per-request where they are not."""
    raw = {"version": 1, "tenants": {"solo": {"org": "solo"}},
           "bind": {"team_id": {}}}
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "binds nothing" in str(exc.value)


def test_a_bind_naming_an_undefined_tenant_is_a_load_error(install_map):
    """Otherwise `resolve()` would KeyError on the request path -- and a
    tenancy lookup that raises is a tenancy lookup that fails open in whatever
    the caller's except-clause does."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["bind"]["team_id"]["team_ghost"] = "no-such-tenant"
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "not in `tenants`" in str(exc.value)


def test_an_unknown_bind_dimension_is_a_load_error(install_map):
    """An operator who writes `bind.user_id` has expressed an intention this
    adapter does not implement. Accepting the map and ignoring the table would
    leave them believing those callers are bound."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["bind"]["user_id"] = {"alice": "acme-payments"}
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "unknown dimension" in str(exc.value)


def test_a_map_with_no_tenants_is_a_load_error(install_map):
    with pytest.raises(T.TenancyConfigError):
        install_map({"version": 1, "bind": {"team_id": {"t": "x"}}})


def test_a_bad_environment_is_rejected_not_coerced(install_map):
    """`environment` is a DECISION input for R2/R3. Silently defaulting a
    typo'd `prod` to `production` would be lucky; silently defaulting it to the
    fallback would price a production action against the wrong branch."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["tenants"]["acme-payments"]["environment"] = "prod"
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "production, staging, dev" in str(exc.value)


def test_a_host_list_written_as_a_bare_string_is_rejected(install_map):
    """`"on_prem_hosts": "host"` would iterate into a per-character tuple that
    matches nothing, turning every placement declaration into `undeclared`
    without an error anywhere."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["tenants"]["acme-payments"]["on_prem_hosts"] = "llm.internal"
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert "list of host strings" in str(exc.value)


@pytest.mark.parametrize("bad,good", [("gate_token", "gate_token_env"),
                                      ("signing_key", "signing_key_env"),
                                      ("evidence_key", "signing_key_env"),
                                      ("token", "gate_token_env")])
def test_a_credential_VALUE_in_the_map_is_a_load_error(install_map, bad, good):
    """The map is a file an operator copies between hosts, pastes into a ticket
    and checks into git. Secrets by reference only -- and the error names the
    spelling to use instead, so the refusal is a fix rather than a puzzle."""
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    raw["tenants"]["acme-payments"]["evidence"][bad] = "s3cret-value"
    with pytest.raises(T.TenancyConfigError) as exc:
        install_map(raw)
    assert good in str(exc.value)
    assert "s3cret-value" not in str(exc.value)


# ---------------------------------------------------------------------------
# The key identifier: recorded only when it is demonstrably not a secret
# ---------------------------------------------------------------------------

def test_a_sha256_shaped_virtual_key_hash_is_recorded():
    value, withheld = T.safe_key_hash("a" * 64, via_virtual_key=True)
    assert value == "a" * 64
    assert withheld is False


def test_the_master_key_alias_is_recorded():
    value, withheld = T.safe_key_hash(T.MASTER_KEY_ALIAS, via_virtual_key=True)
    assert value == T.MASTER_KEY_ALIAS
    assert withheld is False


def test_a_raw_credential_is_DROPPED_not_recorded():
    """A custom_auth handler can assign `api_key` after construction, bypassing
    litellm's own hashing validator. An audit record holding a live credential
    is a leak that outlives the request, so the value is dropped -- and
    `withheld` is True so a refusal can say WHY the key did not match."""
    value, withheld = T.safe_key_hash("sk-live-secret-abc",
                                      via_virtual_key=True)
    assert value is None
    assert withheld is True


def test_a_key_not_validated_by_the_proxy_is_dropped():
    """`via_virtual_key` is litellm's unforgeable marker that IT authenticated
    the key (see test_litellm_contract.py). Without it there is no reason to
    believe the value is a hash rather than a secret."""
    value, withheld = T.safe_key_hash("a" * 64, via_virtual_key=False)
    assert value is None
    assert withheld is True


def test_no_key_at_all_is_not_reported_as_withheld():
    """"absent" and "present but unsafe" are different operator problems and
    the refusal reason distinguishes them."""
    assert T.safe_key_hash(None, via_virtual_key=True) == (None, False)
    assert T.safe_key_hash("   ", via_virtual_key=True) == (None, False)


def test_a_withheld_key_says_so_in_the_refusal(tenancy_map):
    res = T.resolve(conftest.caller(api_key="sk-live-secret-abc"))
    assert res.resolved is False
    assert "withheld" in res.reason
    assert "sk-live-secret-abc" not in res.reason


def test_the_identity_description_never_carries_key_material(tenancy_map):
    """The digest of a live credential is offline-guessable for a short key, so
    only the first 12 characters go into a log line or a refusal."""
    ident = T.read_identity(conftest.caller(api_key="a" * 64,
                                            team_id="team_pay"))
    described = ident.describe()
    assert "a" * 64 not in described
    assert "aaaaaaaaaaaa..." in described
    record = ident.as_record()
    assert record["key_hash_prefix"] == "a" * 12
    assert "a" * 64 not in json.dumps(record)


def test_litellms_own_org_id_is_never_treated_as_a_reeflex_org(tenancy_map):
    """Two different systems' identifiers. Conflating them would attribute one
    company's evidence to another company's org id -- and it would look like it
    worked."""
    res = T.resolve(conftest.caller(team_id="team_pay", org_id="litellm-org-7"))
    assert res.tenant.org == "acme-payments"
    assert res.identity.litellm_org_id == "litellm-org-7"
    # There is no bind dimension for it, so it cannot be mapped even on purpose.
    assert "org_id" not in T._BIND_DIMENSIONS


def test_the_db_token_column_is_read_when_api_key_is_absent(tenancy_map):
    """A `UserAPIKeyAuth` built from the DB row can carry the hashed token in
    `token` rather than `api_key`."""
    ident = T.read_identity(conftest.caller(api_key=None, token="a" * 64))
    assert ident.key_hash == "a" * 64


# ---------------------------------------------------------------------------
# Loading: file source, and the cache that keeps the lookup free
# ---------------------------------------------------------------------------

def test_the_map_loads_from_a_file(monkeypatch, tmp_path):
    """The preferred source -- it keeps the map out of the process environment,
    where a crash dump or a `/proc/<pid>/environ` read would carry it."""
    path = tmp_path / "tenancy.json"
    path.write_text(json.dumps(conftest.TENANCY_MAP), encoding="utf-8")
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP_FILE", str(path))
    T.reset_cache()
    res = T.resolve(conftest.caller(team_id="team_pay"))
    assert res.tenant.org == "acme-payments"
    # The loaded map names its own source, so a refusal reason can tell the
    # operator WHICH map refused them when both env vars are in play.
    assert str(path) in T.load_map().source


def test_editing_the_map_file_takes_effect_without_a_restart(monkeypatch,
                                                             tmp_path):
    """The cache key includes the file's mtime and size. An operator who adds a
    department and does NOT restart the proxy would otherwise see their new key
    refused for as long as the process lived."""
    path = tmp_path / "tenancy.json"
    raw = copy.deepcopy(conftest.TENANCY_MAP)
    del raw["bind"]["team_id"]["team_mkt"]
    path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP_FILE", str(path))
    T.reset_cache()
    assert T.resolve(conftest.caller(team_id="team_mkt")).resolved is False

    # The operator adds the department. mtime_ns + size is the cache key, and
    # os.stat is called per request.
    raw["bind"]["team_id"]["team_mkt"] = "acme-marketing"
    path.write_text(json.dumps(raw) + " ", encoding="utf-8")
    res = T.resolve(conftest.caller(team_id="team_mkt"))
    assert res.resolved is True
    assert res.tenant.org == "acme-marketing"


def test_the_file_source_wins_over_the_inline_one(monkeypatch, tmp_path):
    """Documented precedence. Both set is an operator mistake, and resolving it
    silently toward the LESS secret-exposing source is the safer reading."""
    path = tmp_path / "tenancy.json"
    path.write_text(json.dumps(conftest.TENANCY_MAP), encoding="utf-8")
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP_FILE", str(path))
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP",
                       json.dumps({"version": 1,
                                   "tenants": {"other": {"org": "other"}},
                                   "bind": {"team_id": {"team_pay": "other"}}}))
    T.reset_cache()
    assert T.resolve(
        conftest.caller(team_id="team_pay")).tenant.org == "acme-payments"


# ---------------------------------------------------------------------------
# The session namespace
# ---------------------------------------------------------------------------

def test_the_session_scope_is_the_org(tenancy_map):
    t = T.resolve(conftest.caller(team_id="team_pay")).tenant
    assert T.session_scope(t) == "acme-payments"


def test_an_absent_tenant_scopes_to_unscoped_never_to_a_real_org():
    """`unscoped` cannot collide with a real org, so a library caller with no
    tenancy can never land in one's budget."""
    assert T.session_scope(None) == "unscoped"
    assert T.session_scope(T.UNSCOPED) == "unscoped"


def test_the_unscoped_sentinel_has_no_org_and_so_cannot_select_a_credential():
    """It is the reason `UNSCOPED` is safe to exist at all: with no org there is
    no tenant `evidence` block, so it can never present a gate token."""
    assert T.UNSCOPED.org is None
    assert T.UNSCOPED.evidence == {}


# ---------------------------------------------------------------------------
# The operator's two CLI commands
# ---------------------------------------------------------------------------

def test_the_key_hash_command_prints_the_digest_the_map_expects(capsys):
    """An operator must not have to guess the algorithm, and must not have to
    paste a live key into a shell pipeline they found on the internet.
    Agreement with litellm's own `hash_token()` is pinned in
    test_litellm_contract.py, which needs litellm installed; this pins the
    command itself."""
    from reeflex_litellm import cli
    assert cli.main(["key-hash", "sk-operator-key-1"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == T.digest("sk-operator-key-1")
    assert T._SHA256_HEX.match(printed)


def test_the_tenancy_command_validates_a_good_map(capsys, tenancy_map):
    from reeflex_litellm import cli
    assert cli.main(["tenancy"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out["tenants"]) == {"acme-payments", "acme-marketing"}
    assert out["bind"]["team_id"]["team_pay"] == "acme-payments"


def test_the_tenancy_command_FAILS_on_a_map_that_would_refuse_everything(
        capsys, monkeypatch):
    """Every tenancy misconfiguration is a TOTAL refusal at runtime. An
    operator wants that as a non-zero exit at deploy time, not as an outage."""
    from reeflex_litellm import cli
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP",
                       json.dumps({"version": 1,
                                   "tenants": {"a": {"org": "a"}},
                                   "bind": {"team_id": {"*": "a"}}}))
    T.reset_cache()
    assert cli.main(["tenancy"]) == 1
    assert "INVALID" in capsys.readouterr().err


def test_the_tenancy_command_prints_no_credential_value(capsys, monkeypatch,
                                                        tenancy_map):
    """It prints the env var NAMES the map references -- never a value, and
    never whether one is set, which would be an oracle for a missing
    credential."""
    from reeflex_litellm import cli
    monkeypatch.setenv("RFX_TEST_GATE_TOKEN_PAYMENTS", "tok-do-not-print")
    monkeypatch.setenv("RFX_TEST_SIGNING_KEY_PAYMENTS", "ab" * 32)
    assert cli.main(["tenancy"]) == 0
    text = capsys.readouterr().out
    assert "tok-do-not-print" not in text
    assert "ab" * 32 not in text
    assert "RFX_TEST_GATE_TOKEN_PAYMENTS" in text
