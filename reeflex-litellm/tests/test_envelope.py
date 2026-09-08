"""The gateway envelope: what the overlay changes, and what it must not."""

from __future__ import annotations

import copy

from reeflex_claude import classify as claude_classify
from reeflex_claude import envelope as claude_envelope

from reeflex_litellm import envelope, normalize

import stubcore


def call(name="run_shell", args=None, call_id="call_1"):
    return normalize.normalize_tool_call(
        stubcore.tool_call(call_id, name, args if args is not None
                           else {"command": "rm -rf ./build"}))


def build(**kw):
    kw.setdefault("session_id", "sess-1")
    kw.setdefault("model", "qwen3-coder")
    kw.setdefault("call", call())
    return envelope.build_gateway_envelope(**kw)


# -- the overlay -------------------------------------------------------------

def test_the_agent_id_names_the_gateway_the_tenant_and_the_model():
    """RFX-138: an approval is granted to a PARTY. Every agent behind one
    gateway shipping the same agent.id is that ticket's defect.

    RFX-243 CHANGED THIS STRING: the tenant org sits between the gateway and
    the model. `unscoped` is the library-API default -- the hook never produces
    it, because a request that reaches the hook is resolved to an org or
    refused. Pinned exactly rather than by prefix because this is the ONE
    adapter-controlled field that reaches an Attest report (§4 `agent_id`), so
    a silent change to it changes what a customer's report says.
    """
    env = build(model="gpt-4o-mini")
    assert env["agent"]["id"] == "agent:litellm-gateway/unscoped/gpt-4o-mini"


def test_two_models_behind_one_gateway_are_different_actors():
    a = build(model="model-a")["agent"]["id"]
    b = build(model="model-b")["agent"]["id"]
    assert a != b


def test_the_session_is_namespaced_so_it_cannot_collide_with_another_seat():
    """R5's cumulative budget is keyed on agent.session_id. A collision with a
    Claude Code session would make two unrelated callers spend one budget.

    RFX-243 added the tenant segment (`litellm:<org>:<session>`), which is what
    keeps two DEPARTMENTS' budgets apart too -- see test_tenancy_isolation.py.
    """
    env = build(session_id="abc")
    assert env["agent"]["session_id"] == "litellm:unscoped:abc"
    claude = claude_envelope.build_envelope(
        {"session_id": "abc", "tool_name": "Bash",
         "tool_input": {"command": "ls"}},
        claude_classify.classify("Bash", {"command": "ls"}))
    assert env["agent"]["session_id"] != claude["agent"]["session_id"]


def test_the_ability_carries_the_gateway_tool_name_not_the_mapped_one():
    """core's audit line carries action.ability. Writing the classifier tool
    there would tell a human the model asked for a tool it never named."""
    env = build(call=call("acme_infra_runner", {"cmd": "rm -rf ./build"}))
    assert env["action"]["ability"] == "litellm/acme_infra_runner"
    assert env["context"]["classifier_tool_name"] == "Bash"


def test_the_namespace_is_the_gateway_not_claude_code():
    env = build()
    assert env["action"]["namespace"] == "litellm-gateway"


def test_the_principal_comes_from_the_gateways_own_env_var(monkeypatch):
    """Read from REEFLEX_LITELLM_PRINCIPAL, not REEFLEX_CLAUDE_PRINCIPAL, so a
    box running both adapters does not leak one seat's principal into the
    other's envelopes."""
    monkeypatch.setenv("REEFLEX_CLAUDE_PRINCIPAL", "claude-person")
    monkeypatch.setenv("REEFLEX_LITELLM_PRINCIPAL", "gateway-person")
    assert build()["agent"]["on_behalf_of"] == "gateway-person"


def test_an_explicit_principal_beats_the_env_var(monkeypatch):
    monkeypatch.setenv("REEFLEX_LITELLM_PRINCIPAL", "env-person")
    assert build(principal="arg-person")["agent"]["on_behalf_of"] == "arg-person"


def test_the_environment_defaults_to_production_and_only_accepts_the_enum(monkeypatch):
    assert build()["target"]["environment"] == "production"
    monkeypatch.setenv("REEFLEX_LITELLM_ENVIRONMENT", "staging")
    assert build()["target"]["environment"] == "staging"
    monkeypatch.setenv("REEFLEX_LITELLM_ENVIRONMENT", "Prod")
    assert build()["target"]["environment"] == "production"


def test_the_context_records_the_gateway_facts_a_human_needs():
    c = call("acme_infra_runner", {"cmd": "rm -rf ./build"}, call_id="call_77")
    env = build(call=c, model="qwen3-coder")
    ctx = env["context"]
    assert ctx["gateway"] == "litellm"
    assert ctx["gateway_model"] == "qwen3-coder"
    assert ctx["gateway_tool_name"] == "acme_infra_runner"
    assert ctx["gateway_tool_call_id"] == "call_77"
    assert ctx["normalization"] == "name_and_shape"
    assert ctx["arguments_parsed"] is True


# -- what the overlay must NOT touch ----------------------------------------

def test_the_axes_are_the_classifiers_untouched():
    """There is one classifier and the overlay does not re-price anything."""
    c = call("run_shell", {"command": "rm -rf /"})
    cls = claude_classify.classify("Bash", {"command": "rm -rf /"})
    env = build(call=c)
    assert env["axes"] == {
        "reversibility": cls["reversibility"],
        "blast_radius": cls["blast_radius"],
        "externality": cls["externality"],
    }
    assert env["context"]["danger_signature"] == cls["danger_signature"]
    assert env["context"]["classification_tier"] == cls["classification_tier"]
    assert env["magnitude"]["count"] == max(int(cls.get("magnitude_count", 1)), 1)


def test_no_provenance_block_is_ever_sent():
    """core computes provenance unconditionally and discards a caller's block
    (RFX-132/143). Sending one would be a claim this adapter cannot make."""
    assert "provenance" not in build()


def test_approval_is_absent_at_interception():
    env = build()
    assert env["approval"]["present"] is False


def test_an_empty_session_id_is_refused_not_defaulted():
    """An envelope with no session cannot be charged to a cumulative budget, so
    accepting one would make R5 unenforceable for that request."""
    try:
        build(session_id="")
    except ValueError:
        return
    raise AssertionError("an empty session_id must raise, not be defaulted")


# -- the resubmission -------------------------------------------------------

def test_with_approval_changes_the_nonce_and_nothing_the_hold_is_bound_to():
    """Measured on ghcr.io/reeflex-io/reeflex-core:v0.2.0:

      * a repeated nonce is a hard 400 replay, so the nonce MUST change;
      * hold checks 5/7/8 compare {action, axes, magnitude, target}, the
        decision inputs in params, and the whole agent block, so none of those
        may change.
    """
    env = build()
    before = copy.deepcopy(env)
    out = envelope.with_approval(env, "hold-abc", approver="alice@example.test")

    assert out["meta"]["nonce"] != before["meta"]["nonce"]
    for block in ("action", "axes", "magnitude", "target", "params", "agent"):
        assert out[block] == before[block], block
    assert out["approval"] == {"present": True, "hold_id": "hold-abc",
                               "by": "alice@example.test", "role": "human"}
    # and the original is not mutated
    assert env["approval"]["present"] is False
    assert env["meta"]["nonce"] == before["meta"]["nonce"]


def test_two_resubmissions_of_the_same_envelope_get_different_nonces():
    env = build()
    a = envelope.with_approval(env, "h1")["meta"]["nonce"]
    b = envelope.with_approval(env, "h1")["meta"]["nonce"]
    assert a != b
