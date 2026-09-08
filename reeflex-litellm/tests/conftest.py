import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stubcore  # noqa: E402

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
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    yield


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
