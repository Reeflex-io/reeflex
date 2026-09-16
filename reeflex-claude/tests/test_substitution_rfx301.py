"""
test_substitution_rfx301.py -- RFX-301, at the HOOK plane.

WHY THIS FILE EXISTS NEXT TO test_conformance_bash.py
=====================================================
The corpus in reeflex_claude/conformance.py carries the RFX-301 cases and
test_conformance_bash.py scores them, but it scores `classify()` against a
policy oracle -- two function calls away from what a customer runs.  The defect
this file guards was invisible at exactly that distance for a different reason:
the classifier was not silent about the substitution, it was CONFIDENT and
wrong -- `echo $(rm -rf /var/lib/pgsql)` came back read/reversible/single and
the verdict was ALLOW.  A refactor that re-flattens the parser would put that
verdict back while every string in the classify-plane suite still reads
plausibly.

So these tests drive the REAL entry point: `python -m reeflex_claude.cli hook`
as a subprocess, one PreToolUse JSON on stdin, one verdict on stdout -- the
same plane the round-056 measurement used against a live reeflex-core v0.2.1.
The core here is a stdlib stub that applies the policy oracle to the envelope
it actually received, so the assertion is on a DECISION derived from the axes
that went over the wire, not on a dict the test built itself.

The oracle is imported from test_conformance_bash rather than copied: two
transcriptions of the same policy drift apart, and the one that drifts is
always the copy nobody is reading.

WHAT THIS DOES NOT COVER, said here so the next reader does not have to infer
it: the stub is R1-R4 of the shipped pack for a first call in a session.  A
real core v0.2.1 has at least one asking rule the oracle does not model
(`reeflex.policy/irreversible_protected_asset_prod`, measured round 056), and
that rule can only make a verdict stricter.  The live arm of this corpus is
scripts/attack-probe-rfx144-agent-prices-own-action.py, run in the gate.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from reeflex_claude.classify import classify
from test_conformance_bash import policy_oracle

_TIMEOUT = 20


class _OracleHandler(http.server.BaseHTTPRequestHandler):
    """A core that decides from the envelope it was sent, not from a canned string."""

    last_envelope: dict = {}

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        envelope = json.loads(self.rfile.read(length) or b"{}")
        type(self).last_envelope = envelope

        axes = envelope.get("axes") or {}
        verdict = policy_oracle(
            {"verb": (envelope.get("action") or {}).get("verb"),
             "reversibility": axes.get("reversibility"),
             "blast_radius": axes.get("blast_radius"),
             "externality": axes.get("externality")},
            environment=(envelope.get("target") or {}).get("environment", "production"),
        )
        decision = {"allow": "allow", "ask": "require_approval", "deny": "deny"}[verdict]
        body = json.dumps({"decision": decision,
                           "reason": "oracle: %s" % verdict,
                           "rule": "test-oracle/%s" % verdict,
                           "obligations": []}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _HookPlaneCase(unittest.TestCase):
    """Runs the installed hook against a stub core that reasons from the wire."""

    @classmethod
    def setUpClass(cls):
        class Handler(_OracleHandler):
            pass
        cls.handler = Handler
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def hook(self, command, strict=False):
        """Return (permissionDecision, envelope the stub core received)."""
        env = dict(os.environ)
        env.update({
            "PYTHONPATH": _PARENT,
            "REEFLEX_CORE_URL": "http://127.0.0.1:%d" % self.port,
            "REEFLEX_CORE_TOKEN": "test-token-not-a-secret",
            "REEFLEX_GATE_ID": "rfx301-test-gate",
            "REEFLEX_CLAUDE_AUDIT_LOG": os.devnull,
        })
        env.pop("REEFLEX_CLAUDE_STRICT", None)
        if strict:
            env["REEFLEX_CLAUDE_STRICT"] = "1"

        payload = {"session_id": "rfx301-test-session",
                   "tool_name": "Bash",
                   "tool_input": {"command": command}}
        proc = subprocess.run(
            [sys.executable, "-m", "reeflex_claude.cli", "hook"],
            input=json.dumps(payload), capture_output=True, text=True,
            env=env, cwd=_PARENT, timeout=_TIMEOUT)
        self.assertEqual(0, proc.returncode,
                         "the hook must always exit 0: %r" % proc.stderr[-400:])
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        return out["hookSpecificOutput"]["permissionDecision"], self.handler.last_envelope


# Every command here really does delete the target when bash runs it; that was
# measured against synthetic victim directories rather than argued (round 056,
# 06-shell-truth.txt), and it is a property of the shell, not of this parser.
DESTRUCTIVE_FORMS = [
    ("dollar_paren",      "echo $(rm -rf /var/lib/pgsql)"),
    ("backticks",         "echo `rm -rf /var/lib/pgsql`"),
    ("bare_substitution", "$(rm -rf /var/lib/pgsql)"),
    ("process_read",      "cat <(rm -rf /var/lib/pgsql)"),
    ("process_write",     "echo hi > >(rm -rf /var/lib/pgsql)"),
    ("double_quoted",     'echo "cleaning up: $(rm -rf /var/lib/pgsql)"'),
    ("nested",            "echo $(echo $(rm -rf /var/lib/pgsql))"),
    ("after_separator",   "true && echo $(rm -rf /var/lib/pgsql)"),
    ("in_argument",       "tar -czf /tmp/b.tgz $(rm -rf /var/lib/pgsql)"),
]

# Each destructive form's own benign twin: same syntax, harmless body.  A fix
# that denies the left column by denying the syntax fails the right one.
BENIGN_TWINS = [
    ("dollar_paren",      "echo $(ls -la /tmp)"),
    ("backticks",         "echo `ls -la /tmp`"),
    ("bare_substitution", "$(ls /tmp)"),
    ("process_read",      "cat <(ls -la /tmp)"),
    ("process_write",     "echo hi > >(cat > /tmp/out.log)"),
    ("double_quoted",     'echo "listing: $(ls -la /tmp)"'),
    ("nested",            "echo $(echo $(ls /tmp))"),
    ("after_separator",   "true && echo $(ls /tmp)"),
    ("in_argument",       "tar -czf /tmp/b.tgz $(ls /tmp)"),
]

# Text that LOOKS like a substitution and is not.  These are the reason the
# scanner is quote-aware instead of a regex: pricing them as deletes is the
# false positive that gets the gate switched off.
NOT_SUBSTITUTIONS = [
    ("single_quoted",     "echo '$(rm -rf /var/lib/pgsql)'"),
    ("escaped_dollar",    "echo \\$(rm -rf /var/lib/pgsql)"),
    ("arithmetic",        "echo $((RETRIES + 1))"),
    ("parameter",         "echo ${HOME}/notes.md"),
    ("grep_for_the_text", "grep -rn '$(' src/"),
]


class TestSubstitutionReachesAHuman(_HookPlaneCase):
    """The RFX-301 headline, as a verdict from the real entry point."""

    def test_every_destructive_form_is_refused(self):
        wrong = []
        for name, command in DESTRUCTIVE_FORMS:
            decision, envelope = self.hook(command)
            if decision != "deny":
                wrong.append("%s: %r -> %s (axes %s)"
                             % (name, command, decision, envelope.get("axes")))
        self.assertEqual([], wrong, "\n" + "\n".join(wrong))

    def test_the_axes_on_the_wire_name_the_delete(self):
        """Not just the verdict: the envelope must describe what really happens."""
        _, envelope = self.hook("echo $(rm -rf /var/lib/pgsql)")
        self.assertEqual("delete", envelope["action"]["verb"])
        self.assertEqual("irreversible", envelope["axes"]["reversibility"])
        self.assertEqual("systemic", envelope["axes"]["blast_radius"])
        self.assertEqual("/var/lib/pgsql", envelope["target"]["ref"])

    def test_a_broad_target_reaches_a_human_rather_than_a_refusal(self):
        """`ask` and `deny` are different answers and the distinction is the product."""
        decision, envelope = self.hook("echo $(rm -rf /srv/prod/data)")
        self.assertEqual("ask", decision)
        self.assertEqual("broad", envelope["axes"]["blast_radius"])


class TestTheSyntaxIsNotWhatIsRefused(_HookPlaneCase):
    """A gate that refuses `$(` refuses every build script on earth."""

    def test_every_benign_twin_is_allowed(self):
        wrong = []
        for name, command in BENIGN_TWINS:
            decision, envelope = self.hook(command)
            if decision != "allow":
                wrong.append("%s: %r -> %s (axes %s)"
                             % (name, command, decision, envelope.get("axes")))
        self.assertEqual([], wrong, "\n" + "\n".join(wrong))

    def test_text_that_only_looks_like_a_substitution_is_allowed(self):
        wrong = []
        for name, command in NOT_SUBSTITUTIONS:
            decision, envelope = self.hook(command)
            if decision != "allow":
                wrong.append("%s: %r -> %s (axes %s)"
                             % (name, command, decision, envelope.get("axes")))
        self.assertEqual([], wrong, "\n" + "\n".join(wrong))


class TestWhatIsStillUnread(_HookPlaneCase):
    """
    The residual, asserted rather than described.

    `$(echo rm) -rf /srv/prod/data` is the corpus case gap-command-substitution
    (RFX-158): the substitution IS the command word, so the destructive word is
    produced at runtime and is not in the text this classifier is given.  RFX-301
    does not close it, and a test that quietly started passing would mean the
    corpus residual is stale -- which is its own defect.
    """

    def test_the_command_word_form_is_still_open(self):
        decision, _ = self.hook("$(echo rm) -rf /srv/prod/data")
        self.assertEqual(
            "allow", decision,
            "gap-command-substitution now reaches a human -- good, but the "
            "corpus still marks it residual=RFX-158; update the corpus.")

    def test_variable_indirection_is_still_open(self):
        decision, _ = self.hook("RM=rm; $RM -rf /srv/prod/data")
        self.assertEqual(
            "allow", decision,
            "gap-variable-indirection now reaches a human -- update the corpus.")


class TestStrictModeCosts(_HookPlaneCase):
    """
    Reading substitution bodies interacts with the one knob operators have.

    In strict mode an unrecognised `execute` is priced irreversible/broad
    (RFX-145), so a substituted command the classifier does not recognise now
    reaches a human where the line used to be a read.  That is the same price
    the same command pays written WITHOUT the substitution, which is why it is
    recorded here as a cost rather than fixed: strict mode is the documented
    safe-but-noisy setting, and this makes it consistent instead of blind.
    """

    def test_unrecognised_body_asks_in_strict_mode_only(self):
        self.assertEqual("allow", self.hook("echo $(date -u +%F)")[0])
        self.assertEqual("ask", self.hook("echo $(date -u +%F)", strict=True)[0])

    def test_a_read_body_still_allows_in_strict_mode(self):
        self.assertEqual("allow", self.hook("echo $(ls -la /tmp)", strict=True)[0])


class TestTheClassifyPlaneAgrees(unittest.TestCase):
    """
    One join between the two planes, so a disagreement is a failure rather
    than something a reader has to notice.
    """

    def test_hook_forms_are_not_benign_at_the_classify_plane(self):
        for name, command in DESTRUCTIVE_FORMS:
            with self.subTest(form=name):
                cls = classify("Bash", {"command": command})
                self.assertEqual("delete", cls["verb"])
                self.assertEqual("irreversible", cls["reversibility"])
                self.assertEqual("systemic", cls["blast_radius"])


if __name__ == "__main__":
    unittest.main()
