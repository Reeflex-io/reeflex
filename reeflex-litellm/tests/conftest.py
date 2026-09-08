import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stubcore  # noqa: E402

from reeflex_litellm import tenancy  # noqa: E402

# Every env var this package reads.  Cleared before each test so a value set by
# one test -- or by the shell that launched the suite -- cannot change another
# test's answer.  A governance adapter whose verdict depends on ambient
# environment is the defect this fixture exists to prevent from hiding.
_ENV_KEYS = (
    "REEFLEX_CORE_URL", "REEFLEX_CORE_TOKEN", "REEFLEX_VERIFY_SSL",
    "REEFLEX_LITELLM_TIMEOUT", "REEFLEX_LITELLM_MAX_INFLIGHT",
    "REEFLEX_LITELLM_HOLD_WAIT", "REEFLEX_LITELLM_HOLD_POLL",
    "REEFLEX_LITELLM_APPROVER", "REEFLEX_LITELLM_TOOL_MAP",
    "REEFLEX_LITELLM_PRINCIPAL", "REEFLEX_LITELLM_ENVIRONMENT",
    "REEFLEX_CLAUDE_PRINCIPAL", "REEFLEX_CLAUDE_ENVIRONMENT",
    "REEFLEX_CLAUDE_TIMEOUT", "REEFLEX_CLAUDE_STRICT",
    # RFX-243
    "REEFLEX_LITELLM_TENANCY_MAP", "REEFLEX_LITELLM_TENANCY_MAP_FILE",
    "REEFLEX_LITELLM_ONPREM_HOSTS", "REEFLEX_LITELLM_CLOUD_HOSTS",
    "REEFLEX_LITELLM_LEDGER_PATH", "REEFLEX_LITELLM_EVIDENCE_PUSH",
    "REEFLEX_LITELLM_EVIDENCE_TIMEOUT",
    # The pending-hold push. In _ENV_KEYS for the same reason as the rest: it
    # makes a network call on the DECISION path, so a value leaking in from the
    # shell would change what other tests measure.
    "REEFLEX_LITELLM_HOLDS_PUSH",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    # The tenancy map is CACHED in-process, keyed on the configuration that
    # produced it.  The key includes the env vars above, so a stale map cannot
    # actually be served -- but resetting explicitly means a test that asserts
    # "no map -> deny" is testing the load path rather than a cache miss.
    tenancy.reset_cache()
    yield
    tenancy.reset_cache()


# ---------------------------------------------------------------------------
# Tenancy (RFX-243)
# ---------------------------------------------------------------------------

# Two tenants, because one tenant cannot demonstrate isolation.  Bound on three
# different dimensions between them so the precedence order is exercised by the
# fixtures the rest of the suite uses, not only by the tenancy tests.
TENANCY_MAP = {
    "version": 1,
    "tenants": {
        "acme-payments": {
            "org": "acme-payments",
            "label": "ACME Payments",
            "principal": "payments-oncall@acme.example",
            "environment": "production",
            "on_prem_hosts": ["llm.internal.acme.example"],
            "evidence": {
                "ingest_url": "https://app.invalid/api/v1/evidence",
                "gate_token_env": "RFX_TEST_GATE_TOKEN_PAYMENTS",
                "signing_key_env": "RFX_TEST_SIGNING_KEY_PAYMENTS",
            },
        },
        "acme-marketing": {
            "org": "acme-marketing",
            "label": "ACME Marketing",
            "principal": "growth@acme.example",
            "environment": "staging",
            "cloud_hosts": ["api.openai.com"],
            "evidence": {
                "ingest_url": "https://app.invalid/api/v1/evidence",
                "gate_token_env": "RFX_TEST_GATE_TOKEN_MARKETING",
                "signing_key_env": "RFX_TEST_SIGNING_KEY_MARKETING",
            },
        },
    },
    "bind": {
        "team_id": {"team_pay": "acme-payments",
                    "team_mkt": "acme-marketing"},
        "key_alias": {"payments-bot": "acme-payments",
                      "marketing-bot": "acme-marketing"},
        "key_hash": {"a" * 64: "acme-payments"},
    },
}


def caller(*, team_id=None, key_alias=None, api_key=None,
           via_virtual_key=True, **extra):
    """A stand-in for litellm's `UserAPIKeyAuth`, as a plain dict.

    A dict rather than the real model so the whole suite runs without litellm
    installed -- `tenancy._get()` reads a Mapping and an object through one code
    path.  `tests/test_litellm_contract.py` builds the REAL `UserAPIKeyAuth` and
    asserts this shape agrees with it, so the double cannot drift from the thing
    it doubles.
    """
    d = {"team_id": team_id, "key_alias": key_alias, "api_key": api_key,
         "via_virtual_key": via_virtual_key}
    d.update(extra)
    return d


PAYMENTS_CALLER = dict(team_id="team_pay", key_alias="payments-bot")
MARKETING_CALLER = dict(team_id="team_mkt", key_alias="marketing-bot")


@pytest.fixture
def tenancy_map(monkeypatch):
    """Install the two-tenant map.  Returns the raw dict so a test can mutate a
    copy and re-install it without re-typing the whole thing."""
    monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP", json.dumps(TENANCY_MAP))
    tenancy.reset_cache()
    yield copy.deepcopy(TENANCY_MAP)
    tenancy.reset_cache()


@pytest.fixture
def install_map(monkeypatch):
    """Install an arbitrary map dict.  `install_map(d)` -> the loaded map."""
    def _install(raw):
        monkeypatch.setenv("REEFLEX_LITELLM_TENANCY_MAP", json.dumps(raw))
        tenancy.reset_cache()
        return tenancy.load_map(force=True)
    return _install


@pytest.fixture
def stub(clean_env):
    # Depends on clean_env explicitly so the ordering is declared, not inferred:
    # clean_env deletes REEFLEX_CORE_URL and this fixture sets it, so an
    # autouse-ordering change would otherwise silently point the suite at
    # whatever core the shell had configured.
    s = stubcore.StubCore()
    url = s.start()
    os.environ["REEFLEX_CORE_URL"] = url
    try:
        yield s
    finally:
        os.environ.pop("REEFLEX_CORE_URL", None)
        s.stop()
