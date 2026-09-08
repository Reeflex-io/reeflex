#!/usr/bin/env python3.12
"""
repro-rfx138-adapter-actor-identity.py -- RFX-138 (dev-1--046 / dev-1--047).

dev-1--047 adds:
  * a CENSUS that asks core's OWN approval_actor_key() whether two distinct
    instances of each shipped adapter are distinguishable at all -- the
    property, measured directly, with no HTTP in the way;
  * MCP rows, because reeflex-mcp is the one shipped adapter that actually
    RESUBMITS with approval.hold_id (gateway.py section "enforce mode"), so it
    is where the consequence is reachable rather than hypothetical.

Exercises RFX-138's CLOSING CRITERION:

    "another agent, or the same agent claiming a different on_behalf_of,
     cannot spend the approval"

against a REAL reeflex-core over HTTP, at the SHIPPED 0.2.0 strict default
(REEFLEX_REQUIRE_VERIFIED_APPROVER unset) with a REAL resolver-token map, so
nothing below is bought by weakening configuration.

The point of this file, and the reason it is not the ticket's own probe:
qa--018 measured variants A and B with HAND-WRITTEN envelopes carrying
distinct `agent.id` values.  Core's check 8 keys on
`(agent.id, agent.on_behalf_of)`.  So the criterion is only met for a customer
if the SHIPPED ADAPTERS put a per-agent value in `agent.id`.  Rows A-REAL and
B-REAL therefore build their envelopes with the adapter's OWN code
(reeflex_claude.envelope.build_envelope / reeflex_mcp.normalize.build_envelope),
imported by explicit path, never hand-typed.

Every row prints the verdict core actually returned.  A row is scored by the
REFUSAL CORE GAVE, never by whether the probe expected one.

HOW TO RUN IT.  Start a core from any tree, at the SHIPPED default (leave
REEFLEX_REQUIRE_VERIFIED_APPROVER unset) with a REEFLEX_RESOLVER_TOKENS map
that binds one bearer to a human approver, then:

  REEFLEX_PROBE_BASE=http://127.0.0.1:8471 \
  REEFLEX_PROBE_APPROVER_TOKEN=<the bearer> \
  REEFLEX_PROBE_APPROVER_ID=<the principal it is bound to> \
  python3.12 scripts/repro-rfx138-adapter-actor-identity.py

REEFLEX_PROBE_TREE selects which checkout's ADAPTERS are graded and defaults
to this file's own repo.  Pointing it at a pre-fix checkout while leaving core
where it is, is how the before/after was measured: the same core binary, the
same requests, only the adapter code differs.

Exit code is 0 only when every row scored as intended.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("REEFLEX_PROBE_BASE", "http://127.0.0.1:8471")
#: Which checkout's ADAPTERS are graded.  Defaults to this script's own repo.
TREE = os.environ.get(
    "REEFLEX_PROBE_TREE",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
APPROVER_TOKEN = os.environ.get("REEFLEX_PROBE_APPROVER_TOKEN", "tok_rfx138_manager")
APPROVER_ID = os.environ.get("REEFLEX_PROBE_APPROVER_ID", "manager@rfx138.invalid")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def _post(path, body, token=None):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:300]}


def decide(env):
    return _post("/v1/decide", env)


def resolve(hold_id):
    return _post(
        "/v1/holds/%s/resolve" % hold_id,
        {"decision": "approve",
         "principal": {"type": "human", "id": APPROVER_ID}},
        token=APPROVER_TOKEN,
    )


def verdict(resp):
    """The single string a row is scored on."""
    if not isinstance(resp, dict):
        return str(resp)[:80]
    d = resp.get("decision")
    if d is None:
        return "ERROR:" + json.dumps(resp)[:120]
    r = resp.get("reason") or resp.get("rule") or ""
    return "%s / %s" % (d, r)


# --------------------------------------------------------------------------
# Envelope sources
# --------------------------------------------------------------------------
def _load(path, name):
    """Import a module by explicit PATH, not by import name (RFX-172: the
    shared venv's editable install points at ONE agent's worktree, so an
    import-by-name silently reads somebody else's checkout)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def handwritten(agent_id, obo, session_id):
    """The ticket's own shape: a per-agent `agent.id`, typed by a human.

    Irreversible + broad + production delete of 901 objects -- the exact
    envelope qa--018 used, and the exact shape R2 exists to hold.
    """
    return {
        "reeflex_version": "0.1",
        "agent": {"id": agent_id, "on_behalf_of": obo, "session_id": session_id},
        "action": {"namespace": "wordpress", "verb": "delete",
                   "ability": "wordpress/delete-posts"},
        "target": {"kind": "post", "ref": "post:bulk",
                   "environment": "production"},
        "params": {},
        "magnitude": {"count": 901},
        "axes": {"reversibility": "irreversible", "blast_radius": "broad",
                 "externality": "internal"},
        "approval": {"present": False, "hold_id": None},
    }


def mcp_derive(scenario):
    """RUN the shipped gateway's own `_derive_session_and_agent()`.

    reeflex-mcp's gateway module cannot simply be imported here: it pulls in
    `mcp.server.fastmcp`, and the mcp SDK pinned by that package is not the one
    installed on this box (gate.py builds a venv PER package for exactly this
    reason -- see [[adapter-suites-need-the-right-interpreter]]).  Retyping the
    derivation into the probe would make the census measure MY copy, which is
    the one thing it must not do.

    So: read the real source, lift THAT FUNCTION's own text out with ast, and
    execute it against a stub `self`.  Nothing about the identity logic is
    reproduced here -- only the three collaborators it touches (`uuid`, a
    `regcfg.session_id_for_token`, and the request object) are supplied.

    scenario is "stdio:<pid>" (one gateway process per agent) or
    "http:<Mcp-Session-Id>" (the realistic case: two front clients on ONE
    gateway, separated only by the transport session).
    """
    import ast
    import uuid as _uuid

    src = open(TREE + "/reeflex-mcp/reeflex_mcp/gateway.py").read()
    fn_node = None
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == "_derive_session_and_agent":
            fn_node = node
    if fn_node is None:
        raise AssertionError("_derive_session_and_agent not found in gateway.py")
    fn_node.decorator_list = []

    class _Regcfg:
        @staticmethod
        def session_id_for_token(cfg, bearer):
            return None            # no `clients:` mapping -- the anonymous case

    ns = {"uuid": _uuid, "regcfg": _Regcfg}
    exec(compile(ast.Module(body=[fn_node], type_ignores=[]),
                 "<gateway._derive_session_and_agent>", "exec"), ns)
    derive = ns["_derive_session_and_agent"]

    class _NoContext:
        @property
        def request_context(self):
            raise LookupError

    class _Mcp:
        _mcp_server = _NoContext()

    class _Self:
        gw_config = None

    kind, _, value = scenario.partition(":")
    s = _Self()
    if kind == "stdio":
        s._stdio_session_id = value
        s.mcp = _Mcp()
    else:
        s._stdio_session_id = "<stdio path not taken>"
        headers = {"authorization": "", "mcp-session-id": value}

        class _Ctx:
            class request:
                pass
        _Ctx.request.headers = headers

        class _Srv:
            request_context = _Ctx()

        class _HttpMcp:
            _mcp_server = _Srv()

        s.mcp = _HttpMcp()
    return derive(s)


def n8n_default_agent_id():
    """The `Agent ID` node property's default, read out of the .ts source.

    Same reason as the MCP extractor: a default I retype is a default I chose.
    """
    import re
    src = open(TREE + "/n8n-nodes-reeflex/nodes/ReeflexGate/ReeflexGate.node.ts").read()
    m = re.search(r"name:\s*'agentId'.*?default:\s*'([^']*)'", src, re.S)
    return m.group(1) if m else "<not found>"


def n8n_render(default_value, execution_id):
    """Resolve an n8n parameter default the way n8n would, for ONE execution.

    A leading '=' marks the value as an expression; `{{$execution.id}}` is the
    only interpolation used here.  A plain string is returned unchanged, which
    is the whole point: a constant renders identically for every execution.
    """
    if not default_value.startswith("="):
        return default_value
    return default_value[1:].replace("{{$execution.id}}", execution_id)


def _load_mcp_normalize():
    """reeflex_mcp.normalize uses relative imports, so it cannot be loaded by
    file path like the others.  Import it as a package with TREE first on
    sys.path -- and then ASSERT the module that actually loaded lives under
    TREE, because a shared editable install elsewhere on this box would
    otherwise silently hand back somebody else's checkout (RFX-172).
    """
    root = TREE + "/reeflex-mcp"
    if sys.path[0] != root:
        sys.path.insert(0, root)
    for stale in [m for m in sys.modules if m.startswith("reeflex_mcp")]:
        del sys.modules[stale]
    import reeflex_mcp.normalize as mod  # noqa: E402
    assert mod.__file__.startswith(root), \
        "loaded normalize.py from %s, not from the tree under test" % mod.__file__
    return mod


def mcp_envelope(session_id, agent_id, obo):
    """Built by the SHIPPED reeflex-mcp adapter's own normalize.build_envelope.

    agent_id is whatever the gateway's own derivation hands it (see
    mcp_agent_ids_from_source()).  Action/target/axes are then pinned to the
    same R2-holding shape every other row uses, so WHO is acting stays the
    only variable across the whole table.
    """
    mod = _load_mcp_normalize()
    env = mod.build_envelope(
        session_id=session_id,
        agent_id=agent_id,
        on_behalf_of=obo,
        upstream_name="wp",
        target_system="wordpress",
        target_environment="production",
        tool_name="delete-posts",
        arguments={"ids": list(range(901))},
    )
    env["action"] = {"namespace": "wordpress", "verb": "delete",
                     "ability": "wordpress/delete-posts"}
    env["target"] = {"kind": "post", "ref": "post:bulk",
                     "environment": "production"}
    env["magnitude"] = {"count": 901}
    env["axes"] = {"reversibility": "irreversible", "blast_radius": "broad",
                   "externality": "internal"}
    env["params"] = {}
    return env


def census():
    """Ask CORE's OWN key function whether two instances are distinguishable.

    No HTTP, no policy, no hold: `approval_actor_key` IS the comparison check 8
    makes, imported from the tree under test.  If it returns the same tuple for
    two different agents, check 8 cannot tell them apart and every HTTP row
    below is a formality.
    """
    print("\n" + "#" * 78)
    print("CENSUS -- what each SHIPPED adapter puts in the actor key")
    print("#" * 78)
    key = _load(TREE + "/reeflex-core/app/principal.py",
                "rfx138_core_principal").approval_actor_key

    rows = []

    def line(adapter, note, env_a, env_b):
        ka, kb = key(env_a), key(env_b)
        same = ka == kb
        rows.append({"adapter": adapter, "note": note,
                     "agent_a": env_a.get("agent"), "agent_b": env_b.get("agent"),
                     "key_a": list(ka), "key_b": list(kb),
                     "distinguishable": not same})
        print("\n  %s -- %s" % (adapter, note))
        print("    instance A agent=%s" % json.dumps(env_a.get("agent")))
        print("    instance B agent=%s" % json.dumps(env_b.get("agent")))
        print("    approval_actor_key A = %s" % (ka,))
        print("    approval_actor_key B = %s" % (kb,))
        print("    -> %s" % ("DISTINGUISHABLE"
                             if not same else
                             "IDENTICAL: check 8 cannot separate these two agents"))

    line("reeflex-claude",
         "two Claude Code sessions, no REEFLEX_CLAUDE_PRINCIPAL (the default)",
         claude_envelope("alpha-real-session", None),
         claude_envelope("beta-real-session", None))

    mcp_a = mcp_derive("http:transport-alpha")
    mcp_b = mcp_derive("http:transport-beta")
    print("\n  [instrument] gateway._derive_session_and_agent() RUN, anonymous "
          "HTTP front:\n      client A -> %s\n      client B -> %s"
          % (mcp_a, mcp_b))
    line("reeflex-mcp",
         "two front clients on one gateway, no `clients:` bearer mapping, "
         "identity from the adapter's own derivation",
         mcp_envelope(mcp_a[0], mcp_a[1], mcp_a[2]),
         mcp_envelope(mcp_b[0], mcp_b[1], mcp_b[2]))

    n8n_default = n8n_default_agent_id()
    print("\n  [instrument] ReeflexGate.node.ts Agent ID default read from "
          "source: %r" % n8n_default)
    print("  [instrument LIMIT] n8n is NOT running here.  When the default is "
          "an n8n\n      expression (leading '='), the probe substitutes "
          "$execution.id the way n8n\n      would; that substitution is the "
          "probe's, not n8n's.  Session ID's default\n      on the same node "
          "is already '={{$execution.id}}', which is the precedent the\n"
          "      substitution follows.")
    line("n8n-nodes-reeflex",
         "two workflow executions at the node's DEFAULT Agent ID",
         handwritten(n8n_render(n8n_default, "1001"), None, "n8n-exec-1001"),
         handwritten(n8n_render(n8n_default, "1002"), None, "n8n-exec-1002"))

    line("(control) SPEC-minimal",
         "no agent.id at all -- core's session fallback is reached",
         handwritten(None, None, "sess-minimal-alpha"),
         handwritten(None, None, "sess-minimal-beta"))

    return rows


def claude_envelope(session_id, principal):
    """Built by the SHIPPED reeflex-claude adapter's own code.

    The AGENT BLOCK is 100% the adapter's -- that is the thing under test.
    Everything else is then pinned to the same R2-holding shape the
    handwritten rows use, so that across all six rows the only variable is
    WHO is acting.  What is overridden is listed in the report.
    """
    os.environ.pop("REEFLEX_CLAUDE_PRINCIPAL", None)
    if principal is not None:
        os.environ["REEFLEX_CLAUDE_PRINCIPAL"] = principal
    mod = _load(TREE + "/reeflex-claude/reeflex_claude/envelope.py",
                "rfx138_claude_envelope_%d" % abs(hash(session_id)))
    clsmod = _load(TREE + "/reeflex-claude/reeflex_claude/classify.py",
                   "rfx138_claude_classify_%d" % abs(hash(session_id)))
    payload = {
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /srv/prod/data"},
        "cwd": "/srv/prod",
    }
    cls = clsmod.classify(payload["tool_name"], payload["tool_input"])
    env = mod.build_envelope(payload, cls)
    # Pin the ACTION so the hold is the same action in every row -- only the
    # agent block is under test here.
    env["action"] = {"namespace": "wordpress", "verb": "delete",
                     "ability": "wordpress/delete-posts"}
    env["target"] = {"kind": "post", "ref": "post:bulk",
                     "environment": "production"}
    env["magnitude"] = {"count": 901}
    env["axes"] = {"reversibility": "irreversible", "blast_radius": "broad",
                   "externality": "internal"}
    env["params"] = {}
    return env


# --------------------------------------------------------------------------
# The chain: raise -> a human approves -> somebody else resubmits
# --------------------------------------------------------------------------
def run_row(label, make_raiser, make_resubmitter, note, expect):
    """`make_*` are FACTORIES, not dicts.

    The shipped adapter stamps a per-envelope nonce and core rejects a replay
    (`invalid_envelope: replay: nonce already seen`), so re-POSTing the SAME
    dict at step 4 measures the replay guard instead of the lockout.  Building
    a fresh envelope per step keeps step 4 about the thing it is about.

    `expect` is "DENY" (a different party must be refused) or "ALLOW" (the
    non-vacuity floor: the same party, and a legitimate restart, must still
    get through).  A guard that refuses everything is not a guard, so the
    ALLOW rows are scored as failures when they DENY.
    """
    print("\n" + "=" * 78)
    print("ROW %s [expect %s] -- %s" % (label, expect, note))
    print("=" * 78)
    raiser_env = make_raiser()
    resubmitter_env = make_resubmitter()
    ra = raiser_env["agent"]
    rb = resubmitter_env["agent"]
    print("  raiser      agent.id=%r on_behalf_of=%r session_id=%r"
          % (ra.get("id"), ra.get("on_behalf_of"), ra.get("session_id")))
    print("  resubmitter agent.id=%r on_behalf_of=%r session_id=%r"
          % (rb.get("id"), rb.get("on_behalf_of"), rb.get("session_id")))

    st, d1 = decide(raiser_env)
    print("  1. raise            -> %s" % verdict(d1))
    hold_id = d1.get("hold_id")
    if d1.get("decision") != "require_approval" or not hold_id:
        print("  PRECONDITION NOT REPRODUCED -- no hold raised. Row is VOID.")
        return {"row": label, "result": "VOID-no-hold", "verdict": verdict(d1)}

    st, r = resolve(hold_id)
    print("  2. human approves   -> HTTP %s status=%s decided_by=%s verified=%s"
          % (st, r.get("status"), r.get("decided_by"),
             r.get("decided_by_verified")))
    if r.get("status") != "approved":
        print("  PRECONDITION NOT REPRODUCED -- hold not approved. Row is VOID.")
        return {"row": label, "result": "VOID-not-approved", "verdict": str(r)[:120]}

    other = make_resubmitter()
    other["approval"] = {"present": True, "hold_id": hold_id}
    st, d3 = decide(other)
    v3 = verdict(d3)
    print("  3. OTHER resubmits  -> %s" % v3)

    orig = make_raiser()
    orig["approval"] = {"present": True, "hold_id": hold_id}
    st, d4 = decide(orig)
    v4 = verdict(d4)
    print("  4. the approved one -> %s" % v4)

    allowed = d3.get("decision") == "allow"
    if expect == "DENY":
        if allowed:
            result = "FAIL-OPEN: a DIFFERENT party spent the approval"
        elif "actor_mismatch" in v3:
            result = "BOUND: reeflex_hold_actor_mismatch"
        else:
            result = "refused, but NOT by the actor guard: " + v3
    else:  # expect ALLOW -- the non-vacuity floor
        if allowed:
            result = "FLOOR OK: the approved party still gets through"
        else:
            result = "FAIL-CLOSED: the party the human approved was REFUSED"
    print("  RESULT: %s" % result)
    if expect == "DENY" and allowed and d4.get("decision") == "deny":
        print("          ...and the party the human DID approve is now locked "
              "out (%s)." % v4)
    return {"row": label, "expect": expect, "result": result,
            "step3": v3, "step4": v4,
            "raiser_agent": ra, "resubmitter_agent": rb}


def main():
    print("probe_actor_binding.py -- RFX-138 closing criterion")
    print("core: %s   tree: %s" % (BASE, TREE))
    st, health = _post("/v1/decide", handwritten("agent:warmup", None, "s-warmup"))
    print("warm-up decide -> HTTP %s %s" % (st, verdict(health)))

    census_rows = census()

    H = lambda *a: (lambda: handwritten(*a))          # noqa: E731
    C = lambda *a: (lambda: claude_envelope(*a))      # noqa: E731
    M = lambda *a: (lambda: mcp_envelope(*a))         # noqa: E731

    rows = []

    # -- A-HAND: the ticket's own variant A, hand-written distinct agent.id ---
    rows.append(run_row(
        "A-HAND",
        H("agent:qa018-ALPHA", None, "sess-alpha"),
        H("agent:qa018-BETA", None, "sess-beta"),
        "variant A as the ticket measured it: two DISTINCT hand-written agent.id",
        "DENY"))

    # -- B-HAND: the ticket's own variant B, on_behalf_of substitution --------
    rows.append(run_row(
        "B-HAND",
        H("agent:shared-bot", "alice@customer.test", "sess-obo"),
        H("agent:shared-bot", "bob@customer.test", "sess-obo"),
        "variant B as the ticket measured it: same bot, on_behalf_of alice->bob",
        "DENY"))

    # -- A-REAL: variant A through the SHIPPED reeflex-claude adapter --------
    rows.append(run_row(
        "A-REAL",
        C("alpha-real-session", None),
        C("beta-real-session", None),
        "variant A through the SHIPPED reeflex-claude adapter: two different "
        "Claude Code agents, envelopes built by the adapter's own code",
        "DENY"))

    # -- B-REAL: variant B through the shipped adapter -----------------------
    rows.append(run_row(
        "B-REAL",
        C("obo-real-session", "user:alice@customer.test"),
        C("obo-real-session", "user:bob@customer.test"),
        "variant B through the SHIPPED reeflex-claude adapter: "
        "REEFLEX_CLAUDE_PRINCIPAL alice->bob",
        "DENY"))

    # -- C-LEGIT: the same party resubmitting must STILL be allowed ----------
    #    A guard that denies everything is not a guard.  This is the
    #    non-vacuity floor for the rows above.
    rows.append(run_row(
        "C-LEGIT",
        H("agent:qa018-ALPHA", None, "sess-alpha"),
        H("agent:qa018-ALPHA", None, "sess-alpha"),
        "NON-VACUITY FLOOR: the SAME party resubmitting must still be ALLOWED",
        "ALLOW"))

    # -- D-RESTART: same agent.id, agent restarted (new session_id) ----------
    #    approval_actor_key()'s docstring says this must be allowed ON PURPOSE
    #    (a hold lives 4h; binding the session would deny an action a human
    #    already approved).  Pin the intended behaviour so a future "tighten
    #    the key" change has to argue with a test.
    rows.append(run_row(
        "D-RESTART",
        H("agent:qa018-ALPHA", None, "sess-before-restart"),
        H("agent:qa018-ALPHA", None, "sess-after-restart"),
        "same named agent, restarted between raise and resubmit -- ALLOWED "
        "by design (approval_actor_key excludes session when the agent is named)",
        "ALLOW"))

    # -- E-MINIMAL: SPEC-minimal envelope, no agent.id at all ----------------
    #    Here the session fallback IS reached.  Two sessions must differ.
    rows.append(run_row(
        "E-MINIMAL",
        H(None, None, "sess-minimal-alpha"),
        H(None, None, "sess-minimal-beta"),
        "SPEC-minimal envelope (no agent.id): the session fallback is reached, "
        "so two agents SHOULD be distinguishable",
        "DENY"))

    # -- F-REAL-MINIMAL: the adapter constant vs the SPEC-minimal fallback ---
    #    E-MINIMAL is BOUND and A-REAL is not, and the ONLY difference is that
    #    the adapter fills agent.id with a constant.  This row isolates that:
    #    same two sessions as A-REAL, agent.id stripped back out.
    rows.append(run_row(
        "F-ISOLATE",
        H(None, None, "claude:alpha-real-session"),
        H(None, None, "claude:beta-real-session"),
        "A-REAL's two sessions with agent.id REMOVED -- isolates the constant "
        "as the sole cause",
        "DENY"))

    # -- G-MCP: two anonymous reeflex-mcp front clients ----------------------
    #    reeflex-mcp is the one shipped adapter that RESUBMITS with
    #    approval.hold_id itself (gateway.py enforce mode), so this is the row
    #    where the constant has a reachable consequence rather than a
    #    hypothetical one.
    ma = mcp_derive("http:transport-alpha")
    mb = mcp_derive("http:transport-beta")
    rows.append(run_row(
        "G-MCP",
        M(*ma),
        M(*mb),
        "two anonymous reeflex-mcp front clients (no `clients:` bearer "
        "mapping), identity from the gateway's own derivation, envelope from "
        "the adapter's own normalize.py",
        "DENY"))

    # -- H-MCP-LEGIT: the same MCP client resubmitting must STILL be allowed --
    rows.append(run_row(
        "H-MCP-LEGIT",
        M(*ma),
        M(*ma),
        "NON-VACUITY FLOOR for G-MCP: the SAME front client resubmitting",
        "ALLOW"))

    # -- I-MCP-CONFIGURED: a `clients:` bearer identity is durable and must
    #    survive a reconnect -- the restart tolerance the anonymous branches
    #    have nothing to protect.  Two DIFFERENT configured clients must still
    #    be separated.
    rows.append(run_row(
        "I-MCP-CONFIG",
        M("client:team-a", "client:team-a", None),
        M("client:team-b", "client:team-b", None),
        "two DIFFERENT configured `clients:` identities (the branch this "
        "round deliberately does not touch)",
        "DENY"))

    print("\n" + "#" * 78)
    print("SUMMARY -- %s" % TREE)
    print("#" * 78)
    print("  CENSUS (core's own approval_actor_key over each adapter's own builder)")
    for c in census_rows:
        print("    %-22s %s" % (c["adapter"],
                                "distinguishable"
                                if c["distinguishable"] else
                                "IDENTICAL -- check 8 is vacuous here"))
    print("  ROWS")
    for r in rows:
        print("    %-12s [want %-5s] %s" % (r["row"], r["expect"], r["result"]))
    out = os.environ.get("REEFLEX_PROBE_OUT")
    if out:
        with open(out, "w") as fh:
            json.dump({"census": census_rows, "rows": rows}, fh, indent=2, default=str)
        print("\nrows -> %s" % out)

    # The verdict is the EXIT CODE, not the prose above: a probe whose only
    # output is a table gets read as green by whoever is skimming.
    bad_census = [c["adapter"] for c in census_rows if not c["distinguishable"]]
    bad_rows = [r["row"] for r in rows
                if not (r["result"].startswith("BOUND")
                        or r["result"].startswith("FLOOR OK"))]
    if bad_census or bad_rows:
        print("\nRFX-138 REPRODUCES: YES — indistinguishable adapters %s; "
              "rows that did not score as intended %s" % (bad_census, bad_rows))
        return 1
    print("\nRFX-138 REPRODUCES: NO — every adapter is distinguishable, every "
          "substitution is refused by the actor guard, every floor still "
          "allows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
