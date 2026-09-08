"""
The cross-package contract: does the config `reeflex-claude connect --agent
litellm` hands a customer actually configure THIS package?

WHY THIS FILE EXISTS
====================
`reeflex-claude connect --agent litellm` (RFX-224) writes a LiteLLM config
fragment. Its first version was wrong in three ways at once and every suite in
the repository was green over it:

  1. `litellm_settings: callbacks: ["reeflex_litellm.ReeflexGate"]` — a class
     name this package does not define. `reeflex_litellm.__all__` is
     `["__version__"]`; the guardrail is `guardrail.ReeflexActionGuardrail`.
  2. `litellm_settings.callbacks` is the OBSERVER plane. The seat is a
     GUARDRAIL, registered under `guardrails:` with `mode: post_call`, and that
     mode is what lets it read the tool calls a model proposed and remove or
     withhold them. A callback that only logs would have left the proxy
     ungoverned while looking configured.
  3. `REEFLEX_ENVIRONMENT` is read by nothing. The variable is
     `REEFLEX_LITELLM_ENVIRONMENT` (envelope.py), so a staging gate was
     silently priced against `production`, its default.

Nothing could see it. `reeflex-claude`'s own test asserted the fragment against
its own wording (`assert "reeflex_litellm.ReeflexGate" in body`), which is a
test of the wording; a fragment is inert until an operator starts a proxy with
it; and the two packages are separate distributions, so neither one's suite
imports the other -- EXCEPT here. `gate.py` installs `reeflex-claude` beside
`reeflex-litellm` into one venv for `pytest-litellm` (RFX-236), so this is the
one suite in the repository that can resolve the fragment's dotted path against
the real class.

WHAT IS ASSERTED, AND THE CONTROL
=================================
The dotted path is resolved with `importlib`, the way litellm's own
`get_instance_fn` resolves it, and the class it lands on must be the guardrail.
The control is the OLD string: it must still fail to resolve. Without that
half, "the path resolved" would also pass on a test that resolved nothing.

Every `REEFLEX_*` name the fragment sets must appear in this package's source,
which is what makes a typo'd variable a red test rather than a silent default.
"""

from __future__ import annotations

import importlib
import os
import re

import pytest

# A PLAIN IMPORT, deliberately not `pytest.importorskip`. `reeflex-claude` is a
# HARD dependency of this package, so its absence means the venv is wrong; a
# skip would report green over the one suite that can check this contract, and
# a silently-skipped suite is the failure this repo has already had twice
# (RFX-89, and two SKIPPED litellm contract tests found in RFX-243).
from reeflex_claude import connect as connect_mod  # noqa: E402
from reeflex_litellm import guardrail as guardrail_mod  # noqa: E402

PKG_DIR = os.path.dirname(os.path.abspath(guardrail_mod.__file__))

# The fragment as an operator receives it, rendered with the same substitution
# `write_litellm_config` performs -- reading the template raw would skip the
# formatting, which is where a stray `%` becomes a crash on a real run.
GATE_ID = "11111111-1111-4111-8111-111111111111"

FRAGMENT = connect_mod._LITELLM_FRAGMENT % {
    "core_url": "https://core.test",
    "environment": "staging",
    "gate_name": "acme-prod",
    # RFX-224's second precondition added `%(gate_id)s` to the template, and
    # this dict is why that mattered: a placeholder with no key here is a
    # `KeyError` AT COLLECTION, so the whole file errors out rather than
    # failing one case. It is the seam this suite exists for -- `reeflex-claude`
    # is a different distribution, its own suite never collects this file and
    # stayed green, and only `gate.py`'s `reeflex-litellm/tests` component sees
    # it. Found exactly that way.
    "gate_id": GATE_ID,
}

# The YAML litellm would actually load, with the comment lines removed. The
# fragment EXPLAINS the `litellm_settings.callbacks` mistake in a comment, so
# an assertion over the raw text cannot tell the explanation from the defect --
# and one that could not would have to choose between documenting the trap and
# testing for it.
YAML_ONLY = "\n".join(
    line for line in FRAGMENT.splitlines() if not line.lstrip().startswith("#"))


def _resolve_dotted(path):
    """Resolve `a.b.C` the way litellm's `get_instance_fn` does: import the
    module part, then getattr the rest. Measured against litellm 1.100.0, where
    the bad path raised `AttributeError: module 'reeflex_litellm' has no
    attribute 'ReeflexGate'` and the good one returned the class."""

    module_name, _, attr = path.rpartition(".")
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def test_the_guardrail_the_fragment_names_is_the_class_this_package_defines():
    match = re.search(r"^\s*guardrail:\s*(\S+)\s*$", FRAGMENT, re.M)
    assert match, "the fragment declares no `guardrail:` dotted path"
    resolved = _resolve_dotted(match.group(1))
    assert resolved is guardrail_mod.ReeflexActionGuardrail


def test_CONTROL_the_class_name_the_first_fragment_used_still_does_not_exist():
    """The half that makes the test above mean something. If this ever starts
    resolving, the assertion above stops distinguishing a correct fragment from
    an incorrect one, and this test says so instead of going quietly green."""

    with pytest.raises((AttributeError, ImportError)):
        _resolve_dotted("reeflex_litellm.ReeflexGate")


def test_the_seat_is_registered_as_a_guardrail_not_as_an_observer():
    assert re.search(r"^guardrails:\s*$", YAML_ONLY, re.M)
    assert re.search(r"^\s*mode:\s*post_call\s*$", YAML_ONLY, re.M)
    # `litellm_settings.callbacks` would load the class as a CustomLogger:
    # it would see requests and never be asked whether one may proceed.
    assert "litellm_settings" not in YAML_ONLY
    assert "callbacks" not in YAML_ONLY


def test_every_reeflex_param_in_the_fragment_is_a_kwarg_the_guardrail_accepts():
    """litellm passes every key under `litellm_params` to the guardrail's
    constructor, so a misspelled `reeflex_*` key is either a TypeError at proxy
    startup or -- worse, depending on the version -- silently ignored, leaving
    a hold-wait or session header the operator believes they configured."""

    import inspect

    params = set(re.findall(r"^\s+(reeflex_[a-z_]+):", FRAGMENT, re.M))
    assert params, "the fragment sets no reeflex_* guardrail params"
    sig = inspect.signature(guardrail_mod.ReeflexActionGuardrail.__init__)
    accepted = set(sig.parameters)
    takes_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD
                       for p in sig.parameters.values())
    for name in sorted(params):
        assert name in accepted or takes_kwargs, (
            "the fragment sets %r, which ReeflexActionGuardrail.__init__ does "
            "not accept: %s" % (name, sorted(accepted)))


def test_every_env_var_the_fragment_sets_is_one_this_package_reads():
    names = set(re.findall(r"^\s+(REEFLEX_[A-Z_]+):", FRAGMENT, re.M))
    assert names, "the fragment sets no REEFLEX_* variables"

    source = ""
    for entry in sorted(os.listdir(PKG_DIR)):
        if entry.endswith(".py"):
            with open(os.path.join(PKG_DIR, entry), encoding="utf-8") as fh:
                source += fh.read()

    for name in sorted(names):
        assert name in source, (
            "the fragment sets %s and no module in reeflex_litellm mentions "
            "it -- REEFLEX_ENVIRONMENT was exactly this defect, silently "
            "leaving the environment at its `production` default" % name)


def test_the_fragment_requires_a_tenancy_map_because_there_is_no_default_org():
    """A gateway with no map refuses every tool call (RFX-243). A fragment that
    did not mention it would hand the operator a proxy that looks configured
    and refuses everything, with the reason two documents away."""

    assert "REEFLEX_LITELLM_TENANCY_MAP_FILE" in FRAGMENT
    assert "reeflex-litellm tenancy" in FRAGMENT, (
        "the fragment must name the offline validator: every tenancy "
        "misconfiguration is a total refusal at runtime")


def test_the_install_line_names_this_distribution_and_the_proxy_extra():
    """`reeflex_litellm.guardrail` is the only module importing litellm, so the
    bare install is not enough to run a proxy -- the `[proxy]` extra is."""

    assert "pip install 'reeflex-litellm[proxy]'" in FRAGMENT
    # The from-source path must name a directory that exists. The first version
    # said `subdirectory=integrations/reeflex-litellm`; this package is at the
    # repository root, so that install was a 404 on the subdirectory.
    match = re.search(r"subdirectory=(\S+)'", FRAGMENT)
    assert match, "no git+https fallback install in the fragment"
    assert match.group(1) == "reeflex-litellm"
    repo_root = os.path.dirname(os.path.dirname(PKG_DIR))
    candidate = os.path.join(repo_root, match.group(1), "pyproject.toml")
    if os.path.exists(os.path.join(repo_root, "gate.py")):
        # Only meaningful from a source checkout; skipped when this suite runs
        # against an installed wheel, where the repository layout is absent.
        assert os.path.exists(candidate), candidate


def test_no_credential_reaches_the_fragment():
    assert "rfx_" not in FRAGMENT
    assert "REEFLEX_CORE_TOKEN:" not in FRAGMENT


def test_the_fragment_does_not_set_a_gate_id_this_package_would_ignore():
    """RFX-224's second precondition, from this side of the seam -- and the
    first draft of it set `REEFLEX_GATE_ID:` in this fragment.

    THE TEST ABOVE CAUGHT IT: nothing in `reeflex_litellm` reads that name, so
    setting it would have been the `REEFLEX_ENVIRONMENT` defect this file was
    written for, repeated by the author of the code that had it. The
    gate-scoped credential path lives in `reeflex-claude`'s adapter (Claude
    Code and OpenCode share it); this package has its own `enforce.py` which
    sends no `X-Reeflex-Gate` and reads no credential store, so a proxy
    authenticates the way it always has, with the operator's own bearer.

    This test pins the ABSENCE, so the variable cannot come back without the
    code that reads it -- and the id stays in the fragment as a COMMENT, which
    is where a value an operator may want to see but no program consumes
    belongs.
    """

    assert "REEFLEX_GATE_ID" not in YAML_ONLY
    assert f"id {GATE_ID}" in FRAGMENT, "the gate id should still be readable as a comment"
    # And the limit is stated where an operator will hit it, not only in a
    # commit message.
    assert "does NOT yet send" in FRAGMENT
    assert "REEFLEX_CORE_TOKEN" in FRAGMENT


def test_the_fragment_names_the_credential_file_by_reference_and_never_a_value(tmp_path, monkeypatch):
    """The invariant that did NOT change. `connect` now holds a credential; the
    fragment must still carry none, and must point at the 0600 file rather than
    copy a secret into a config that is often under version control."""

    monkeypatch.setenv("HOME", str(tmp_path))
    written = connect_mod.write_litellm_config(
        core_url="https://core.test", environment="staging",
        gate_name="acme-prod", dry_run=False, gate_id=GATE_ID,
    )[0]
    body = written.read_text(encoding="utf-8")

    # No member of the portal's credential family, by prefix, so a future one
    # is covered without anyone remembering to extend this list.
    for prefix in ("rfx_ac_", "rfx_reg_", "rfx_gate_", "rfx_ek_"):
        assert prefix not in body, prefix
    assert "credentials.json" in body
    assert "mode 0600" in body
