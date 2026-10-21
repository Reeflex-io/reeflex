"""integrations/devin/reeflex_boundary_gate.py (RFX-450): which changes it
gates, and the exit code each core answer produces. Core is a fake here; the
verdicts the real pack gives these envelopes are measured in the round report,
not asserted in this file."""

import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.path.join(_HERE, "..", "..", "integrations", "devin", "reeflex_boundary_gate.py")
_spec = importlib.util.spec_from_file_location("reeflex_boundary_gate", _PATH)
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)

DEVIN = "devin-ai-integration[bot]"


class FakeCore:
    def __init__(self, decisions, hold_states=(), status=200):
        self.decisions = list(decisions)
        self.hold_states = list(hold_states)
        self.status = status
        self.calls = []

    def __call__(self, method, path, body):
        self.calls.append((method, path, json.loads(json.dumps(body)) if body is not None else None))
        if self.status != 200:
            return self.status, {"error": "internal_error"}
        if method == "POST":
            return 200, self.decisions.pop(0)
        return 200, {"status": self.hold_states.pop(0)}


ALLOW = {"decision": "allow", "rule": "reeflex.policy/default_allow", "decision_id": "d0"}
DENY = {"decision": "deny", "rule": "reeflex.policy/irreversible_systemic_prod", "decision_id": "d1"}
HOLD = {"decision": "require_approval", "rule": "reeflex.policy/irreversible_broad_prod",
        "decision_id": "d2", "hold_id": "h1", "expires_ts": "2026-10-21T20:00:00Z"}
RESUBMITTED = {"decision": "allow", "rule": "reeflex.policy/approved_resubmission", "decision_id": "d3"}


def _run(argv, core, files=("migrations/0042_add_ledger.sql",), author=DEVIN, env=None):
    with tempfile.TemporaryDirectory() as tmp:
        event = os.path.join(tmp, "event.json")
        with open(event, "w") as fh:
            json.dump({"pull_request": {"number": 7, "user": {"login": author}, "base": {"ref": "main"},
                                        "head": {"sha": "abc123"}}}, fh)
        changed = os.path.join(tmp, "changed.txt")
        with open(changed, "w") as fh:
            fh.write("\n".join(files) + "\n")
        argv = [a.replace("@EVENT", event).replace("@CHANGED", changed) for a in argv]
        base_env = {"REEFLEX_CORE_URL": "http://core.invalid", "REEFLEX_POLL_SECONDS": "0",
                    "GITHUB_REPOSITORY": "acme/payments", "GITHUB_RUN_ID": "99"}
        with mock.patch.dict(os.environ, {**base_env, **(env or {})}, clear=False), \
                mock.patch.object(g, "print", create=True):
            return g.main(argv, http=core)


MERGE = ["merge", "--changed-files", "@CHANGED", "--event", "@EVENT"]


class WhatIsGated(unittest.TestCase):
    def test_default_patterns_catch_the_paths_the_recipe_names(self):
        pats = g.split_list(g.DEFAULT_PATHS)
        hits = g.risky_files(["migrations/0042.sql", "svc/migrations/x.py", "infra/vpc.yaml", "modules/db/main.tf",
                              "Dockerfile", "api/Dockerfile", ".github/workflows/deploy.yml", ".gitlab-ci.yml",
                              "src/app.py", "README.md", "docs/infra.md"], pats)
        self.assertEqual(hits, ["migrations/0042.sql", "svc/migrations/x.py", "infra/vpc.yaml", "modules/db/main.tf",
                                "Dockerfile", "api/Dockerfile", ".github/workflows/deploy.yml", ".gitlab-ci.yml"])

    def test_a_human_authored_pr_is_not_gated_and_core_is_not_asked(self):
        core = FakeCore([])
        self.assertEqual(_run(MERGE, core, author="alice"), 0)
        self.assertEqual(core.calls, [])

    def test_a_devin_pr_touching_only_application_code_is_not_gated(self):
        core = FakeCore([])
        self.assertEqual(_run(MERGE, core, files=("src/app.py", "README.md")), 0)
        self.assertEqual(core.calls, [])

    def test_the_authors_list_is_configurable(self):
        core = FakeCore([ALLOW])
        self.assertEqual(_run(MERGE, core, author="other-bot[bot]",
                              env={"REEFLEX_GATE_AUTHORS": "other-bot[bot]"}), 0)
        self.assertEqual(len(core.calls), 1)


class WhatCoreSays(unittest.TestCase):
    def test_allow_exits_0(self):
        core = FakeCore([ALLOW])
        self.assertEqual(_run(MERGE, core), 0)
        method, path, body = core.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/decide"))
        self.assertEqual(body["agent"]["id"], "agent:devin")
        self.assertEqual(body["agent"]["on_behalf_of"], DEVIN)
        self.assertEqual(body["target"]["environment"], "production")
        self.assertEqual(body["approval"], {"present": False})
        self.assertEqual(body["params"]["gated_paths"], ["migrations/0042_add_ledger.sql"])

    def test_deny_exits_1(self):
        self.assertEqual(_run(MERGE, FakeCore([DENY])), 1)

    def test_a_hold_approved_in_the_portal_is_resubmitted_with_the_same_envelope(self):
        core = FakeCore([HOLD, RESUBMITTED], hold_states=["pending", "pending", "approved"])
        self.assertEqual(_run(MERGE, core), 0)
        posts = [c for c in core.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 2)
        first, second = posts[0][2], posts[1][2]
        self.assertEqual(second["approval"], {"present": True, "hold_id": "h1"})
        for key in ("agent", "action", "target", "params", "magnitude", "axes"):
            self.assertEqual(first[key], second[key], key)
        self.assertNotEqual(first["meta"]["nonce"], second["meta"]["nonce"])
        self.assertEqual([c[1] for c in core.calls if c[0] == "GET"], ["/v1/holds/h1"] * 3)

    def test_a_rejected_hold_exits_1_and_is_not_resubmitted(self):
        core = FakeCore([HOLD], hold_states=["rejected"])
        self.assertEqual(_run(MERGE, core), 1)
        self.assertEqual(len([c for c in core.calls if c[0] == "POST"]), 1)

    def test_an_expired_hold_exits_1(self):
        self.assertEqual(_run(MERGE, FakeCore([HOLD], hold_states=["expired"])), 1)

    def test_an_approval_core_then_refuses_exits_1(self):
        refused = {"decision": "deny", "rule": "reeflex.core/hold_validation", "decision_id": "d4"}
        self.assertEqual(_run(MERGE, FakeCore([HOLD, refused], hold_states=["approved"])), 1)

    def test_waiting_past_the_limit_exits_1(self):
        core = FakeCore([HOLD], hold_states=["pending"] * 3)
        ticks = iter([0.0, 5.0, 10.0, 99.0])
        out = g.gate(core, g.deploy_envelope(repo="r", target="t", environment="production", sha=None,
                                             actor=None, session_id="s"),
                     wait_s=30, poll_s=0, portal=None, log=lambda s: None,
                     sleep=lambda s: None, clock=lambda: next(ticks))
        self.assertEqual(out[0], 1)
        self.assertEqual(out[1]["hold_status"], "timeout")


class FailClosed(unittest.TestCase):
    def test_a_5xx_from_core_exits_1(self):
        self.assertEqual(_run(MERGE, FakeCore([], status=500)), 1)

    def test_an_unreachable_core_exits_1(self):
        def down(method, path, body):
            raise g.GateError("reeflex-core unreachable")
        self.assertEqual(_run(MERGE, down), 1)

    def test_no_core_url_exits_1(self):
        with mock.patch.dict(os.environ, {"REEFLEX_CORE_URL": ""}):
            self.assertEqual(_run(MERGE, None, env={"REEFLEX_CORE_URL": ""}), 1)

    def test_a_real_http_call_to_a_closed_port_is_unreachable_not_allow(self):
        http = g.make_http("http://127.0.0.1:9", None, timeout=2)
        with self.assertRaises(g.GateError):
            g.decide(http, g.deploy_envelope(repo="r", target="t", environment="production", sha=None,
                                            actor=None, session_id="s"))


class SaysWhyItRefused(unittest.TestCase):
    def test_a_403_prints_cores_reason_not_only_forbidden(self):
        def core(method, path, body):
            return 403, {"error": "forbidden", "reason": "gate_not_declared"}
        with self.assertRaises(g.GateError) as cm:
            g.decide(core, g.deploy_envelope(repo="r", target="t", environment="production", sha=None,
                                            actor=None, session_id="s"))
        self.assertIn("gate_not_declared", str(cm.exception))

    def test_a_token_that_may_decide_but_not_read_holds_fails_closed_and_says_so(self):
        calls = []

        def core(method, path, body):
            calls.append((method, path))
            return (200, HOLD) if method == "POST" else (401, {"error": "unauthorized"})
        with self.assertRaises(g.GateError) as cm:
            g.gate(core, g.deploy_envelope(repo="r", target="t", environment="production", sha=None,
                                           actor=None, session_id="s"),
                   wait_s=30, poll_s=0, portal=None, log=lambda s: None, sleep=lambda s: None)
        self.assertIn("operator token", str(cm.exception))
        self.assertEqual(calls, [("POST", "/v1/decide"), ("GET", "/v1/holds/h1")])
        self.assertEqual(_run(MERGE, core), 1)


class Deploy(unittest.TestCase):
    def test_a_deploy_is_asked_every_time(self):
        core = FakeCore([HOLD, RESUBMITTED], hold_states=["approved"])
        self.assertEqual(_run(["deploy", "--target", "payments-api"], core,
                              env={"GITHUB_ACTOR": "alice", "GITHUB_SHA": "abc"}), 0)
        body = core.calls[0][2]
        self.assertEqual(body["action"]["verb"], "execute")
        self.assertEqual(body["target"]["ref"], "acme/payments:payments-api")
        self.assertEqual(body["agent"]["on_behalf_of"], "alice")


if __name__ == "__main__":
    unittest.main()
