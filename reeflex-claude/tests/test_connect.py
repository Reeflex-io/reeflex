"""
Tests for `reeflex-claude connect` (RFX-224).

Three things are worth testing here and they are not the happy path (which is
measured end-to-end against a real portal and a real core, see the round
report):

  1. **The refusals.** Every one of them is a message a customer reads while
     nothing works yet, and a wrong credential pasted into `--token` must be
     named rather than forwarded to a server.
  2. **What gets written.** No token in any config file, on any of the three
     agent paths -- the claim the setup document makes on the customer's
     behalf.
  3. **The pin.** `SETUP_DOC_SHA256` against `docs/setup/v1/agent-setup.md`.
     That constant is duplicated in reeflex-app (which cannot see this repo)
     and this is the assertion that keeps the two honest.

The portal is a stub `http.server` on a loopback port rather than a mock of
`urllib`: the exchange and the hello are HTTP contracts with another
repository, and a test that patched `_post_json` would prove this module calls
a function it defines itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from reeflex_claude import connect as connect_mod
from reeflex_claude.cli import build_parser, main
from reeflex_claude.setup_settings import is_ours

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_DOC = REPO_ROOT / "docs" / "setup" / "v1" / "agent-setup.md"

VALID_TOKEN = "rfx_reg_" + "A" * 43
GATE_ID = "8b7c1f2e-0000-4000-8000-000000000001"


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------

def test_the_setup_document_exists_where_the_portal_says_it_does():
    """RFX-224's criterion: "agent-setup.md v1 exists in the monorepo under
    docs/setup/, versioned, and is what the portal serves -- one source"."""

    assert SETUP_DOC.is_file(), SETUP_DOC


def test_the_pinned_digest_describes_the_document():
    """The number the portal prints beside a customer's line. Both halves of
    this feature write it down -- here and in reeflex-app's
    `reeflex_app/setup_docs/__init__.py` -- because neither repository's CI
    can see the other, so a copy that drifts has to make BOTH suites red."""

    on_disk = hashlib.sha256(SETUP_DOC.read_bytes()).hexdigest()
    assert on_disk == connect_mod.SETUP_DOC_SHA256, (
        f"agent-setup.md hashes to {on_disk} but SETUP_DOC_SHA256 says "
        f"{connect_mod.SETUP_DOC_SHA256}. If the change was intended, update "
        "this constant AND the identical one in reeflex-app "
        "(reeflex_app/setup_docs/__init__.py), and re-copy the file."
    )


def test_the_document_carries_no_credential_shaped_string():
    text = SETUP_DOC.read_text(encoding="utf-8")
    import re

    for prefix in ("rfx_gate_", "rfx_ek_", "rfx_reg_"):
        assert not re.search(prefix + r"[0-9A-Za-z]{8,}", text), prefix


# ---------------------------------------------------------------------------
# The CLI surface
# ---------------------------------------------------------------------------

def test_connect_is_a_subcommand_with_the_flags_the_portal_prints():
    """The portal composes a line from these flag names. If one is renamed,
    every line already on a customer's clipboard breaks -- so the names are
    pinned here, on the side that owns them."""

    args = build_parser().parse_args(
        ["connect", "--gate", GATE_ID, "--token", VALID_TOKEN,
         "--portal", "https://portal.test", "--agent", "opencode"]
    )
    assert args.command == "connect"
    assert args.gate == GATE_ID
    assert args.token == VALID_TOKEN
    assert args.portal == "https://portal.test"
    assert args.agent == "opencode"
    assert args.dry_run is False


def test_the_three_agents_the_portal_offers_are_the_three_it_accepts():
    assert connect_mod.AGENTS == ("claude", "opencode", "litellm")
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["connect", "--token", VALID_TOKEN, "--agent", "emacs"]
        )


def test_a_missing_token_exits_2_and_says_where_to_get_one(capsys):
    assert main(["connect"]) == 2
    err = capsys.readouterr().err
    assert "--token is required" in err
    assert "Connect an agent" in err


@pytest.mark.parametrize(
    "wrong",
    [
        "rfx_gate_" + "A" * 43,   # the gate's machine credential
        "rfx_ek_" + "A" * 43,     # evidence signing key material
        "some-random-string",
    ],
)
def test_a_credential_from_the_wrong_family_is_refused_before_any_request(wrong, capsys):
    """AND WITHOUT CONTACTING ANYTHING. `--portal` points at a port nothing is
    listening on, so if this ever started sending the value before checking
    its shape, the test would fail with a connection error instead of the
    exit code -- which is the failure mode worth catching: a gate token
    forwarded to a server and rejected has still left the customer's most
    valuable credential in one more place."""

    code = main(["connect", "--token", wrong, "--portal", "http://127.0.0.1:1"])
    assert code == 2
    err = capsys.readouterr().err
    assert "rfx_reg_" in err
    # The message names the two credentials it is NOT, so a customer who
    # pasted the wrong one knows which screen to go back to.
    if wrong.startswith("rfx_"):
        assert "rfx_gate_" in err and "rfx_ek_" in err


def test_dry_run_exchanges_nothing_and_writes_nothing(tmp_path, capsys, monkeypatch):
    """The "readable before it runs" property, as a command rather than as a
    document: `--dry-run` prints the path it would touch and stops. `--portal`
    is an unreachable address, so any HTTP call at all would fail the test."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.chdir(tmp_path)

    code = main([
        "connect", "--token", VALID_TOKEN, "--gate", GATE_ID,
        "--portal", "http://127.0.0.1:1", "--dry-run", "--global",
    ])
    assert code == 0
    out = capsys.readouterr().out
    assert "--dry-run" in out
    assert "would merge a PreToolUse hook entry" in out
    assert "Nothing was exchanged, written, decided or reported" in out
    # Nothing on disk.
    assert not (tmp_path / ".claude").exists()
    assert list(tmp_path.glob("**/reeflex.js")) == []


def test_dry_run_names_the_pinned_document_and_its_digest(capsys):
    main(["connect", "--token", VALID_TOKEN, "--portal", "http://127.0.0.1:1", "--dry-run"])
    out = capsys.readouterr().out
    assert "docs/setup/v1/agent-setup.md" in out
    assert connect_mod.SETUP_DOC_SHA256 in out


# ---------------------------------------------------------------------------
# The config writers -- what lands on disk
# ---------------------------------------------------------------------------

def test_the_claude_config_carries_the_core_url_and_no_token(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    path, what = connect_mod.write_claude_config(
        core_url="https://core.test", environment="staging",
        target="project", dry_run=False,
    )
    body = path.read_text(encoding="utf-8")
    settings = json.loads(body)

    assert "wrote a new hook entry" in what
    assert settings["env"]["REEFLEX_CORE_URL"] == "https://core.test"
    assert settings["env"]["REEFLEX_MODE"] == "enforce"
    assert settings["env"]["REEFLEX_CLAUDE_ENVIRONMENT"] == "staging"
    assert settings["env"]["REEFLEX_VERIFY_SSL"] == "true"
    # THE CLAIM THE SETUP DOCUMENT MAKES: no credential of any kind is written
    # into a file a customer may well commit.
    assert "REEFLEX_CORE_TOKEN" not in body
    assert "rfx_" not in body
    # And the hook entry is the RFX-204/205 shape, because this delegates to
    # `setup_settings` rather than composing its own.
    block = settings["hooks"]["PreToolUse"][0]
    assert block["matcher"] == "*"
    # Recognised by `setup_settings.is_ours`, the function that OWNS this
    # convention, rather than by a hand-rolled substring: in a source checkout
    # `reeflex-claude` is not on PATH and the entry is legitimately
    # `<abs python> -m reeflex_claude.cli hook` -- the module name, with an
    # underscore. A test that grepped for the distribution name would fail
    # here while the file was perfectly correct.
    command = block["hooks"][0]["command"]
    assert is_ours(command), command
    # Absolute either way (RFX-205): a bare name is `command not found` when
    # Claude Code is launched outside the venv, which is a SILENT ALLOW.
    assert os.path.isabs(command.split()[0]), command


def test_the_claude_config_leaves_an_unrelated_hook_alone(tmp_path, monkeypatch):
    """`connect` runs on a machine that already has a settings.json. It merges
    (setup_settings' documented contract) -- a customer losing another tool's
    hook to our onboarding would be a far worse first impression than a
    missing one."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".claude" / "settings.json"
    existing.parent.mkdir(parents=True)
    existing.write_text(json.dumps({
        "env": {"SOMETHING_ELSE": "keep me"},
        "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool"}]}
        ]},
    }))

    path, _what = connect_mod.write_claude_config(
        core_url="https://core.test", environment="dev", target="project", dry_run=False,
    )
    settings = json.loads(path.read_text(encoding="utf-8"))
    assert settings["env"]["SOMETHING_ELSE"] == "keep me"
    commands = [
        h["command"]
        for block in settings["hooks"]["PreToolUse"]
        for h in block["hooks"]
    ]
    assert "other-tool" in commands
    assert any(is_ours(c) for c in commands), commands
    assert not is_ours("other-tool")  # the control for the line above


def test_the_opencode_plugin_enforces_and_carries_no_token(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    path, what = connect_mod.write_opencode_config(
        core_url="https://core.test", environment="production", dry_run=False,
    )
    body = path.read_text(encoding="utf-8")

    assert path == tmp_path / "opencode" / "plugin" / "reeflex.js"
    assert "wrote a new plugin" in what
    assert "rfx_" not in body
    # The enforcement primitive: a THROW out of `tool.execute.before`.
    assert "tool.execute.before" in body
    assert body.count("throw new Error") >= 4
    # Fail-closed on every path, including the plugin's own failure -- an
    # adapter that let a call through because it could not decide would be
    # worse than no adapter.
    assert 'if (verdict === "allow") return;' in body
    assert 'verdict === "ask"' in body
    assert "https://core.test" in body


def test_the_opencode_writer_refuses_to_clobber_a_foreign_plugin(tmp_path, monkeypatch):
    """`~/.config/opencode/plugin/` is a shared directory -- on the machine
    this was written on it already held another tool's plugin. Overwriting a
    file we did not write is not ours to do."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = tmp_path / "opencode" / "plugin" / "reeflex.js"
    path.parent.mkdir(parents=True)
    path.write_text("export const SomeoneElse = () => {};")

    with pytest.raises(connect_mod.ConnectError, match="not written by reeflex-claude"):
        connect_mod.write_opencode_config(
            core_url="https://core.test", environment="dev", dry_run=False,
        )
    assert path.read_text() == "export const SomeoneElse = () => {};"


def test_the_opencode_writer_replaces_its_own_previous_plugin(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    connect_mod.write_opencode_config(
        core_url="https://old.test", environment="dev", dry_run=False,
    )
    path, what = connect_mod.write_opencode_config(
        core_url="https://new.test", environment="dev", dry_run=False,
    )
    assert "replaced" in what
    assert "https://new.test" in path.read_text(encoding="utf-8")
    assert "https://old.test" not in path.read_text(encoding="utf-8")


def test_the_litellm_fragment_configures_the_seat_that_exists(tmp_path, monkeypatch):
    """THE VERSION OF THIS TEST THAT SHIPPED FIRST ASSERTED THE DEFECT.

    It read `assert "reeflex_litellm.ReeflexGate" in body` — pinning a class
    name `reeflex_litellm` does not define (`__all__ = ["__version__"]`; the
    class is `guardrail.ReeflexActionGuardrail`) — under a `litellm_settings.
    callbacks` key, which observes rather than governs, with
    `REEFLEX_ENVIRONMENT`, which nothing reads. Three defects in fifteen lines,
    green, because a test comparing a fragment against its own wording measures
    the wording.

    So the assertions below are about the CONTRACT with the package being
    configured, and the ones that need `reeflex_litellm` importable — the
    dotted path resolving to a real class, every env var being one the seat
    reads — live in `reeflex-litellm/tests/test_connect_fragment.py`, the suite
    whose venv holds both distributions. This half is what reeflex-claude's own
    suite can honestly check.
    """

    monkeypatch.setenv("HOME", str(tmp_path))
    path, what = connect_mod.write_litellm_config(
        core_url="https://core.test", environment="staging",
        gate_name="acme-prod", dry_run=False,
    )
    body = path.read_text(encoding="utf-8")
    # The YAML litellm would load, comment lines dropped: the fragment EXPLAINS
    # the `litellm_settings.callbacks` mistake in a comment, so an assertion
    # over the raw text cannot tell the explanation from the defect.
    yaml_only = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#"))

    assert "config.yaml is not touched" in what
    # A guardrail with a post_call mode, which is what can change a response.
    assert "guardrails:" in yaml_only
    assert "reeflex_litellm.guardrail.ReeflexActionGuardrail" in yaml_only
    assert "mode: post_call" in yaml_only
    # NOT the callbacks path: keep the old defect out by name.
    assert "litellm_settings" not in yaml_only
    assert "callbacks" not in yaml_only
    assert "ReeflexGate" not in yaml_only.replace("ReeflexActionGuardrail", "")
    # The env var the seat actually reads, carrying the gate's environment
    # rather than silently defaulting to production.
    assert 'REEFLEX_LITELLM_ENVIRONMENT: "staging"' in body
    assert "REEFLEX_ENVIRONMENT:" not in body
    # Tenancy is required and has no default org, so the fragment must say so
    # or the operator's first tool call is a refusal they cannot explain.
    assert "REEFLEX_LITELLM_TENANCY_MAP_FILE" in body
    assert "reeflex-litellm tenancy" in body
    # The install line a customer can run, and the source path that is a real
    # directory in this repository (`reeflex-litellm/`, not `integrations/`).
    assert "pip install 'reeflex-litellm[proxy]'" in body
    assert "subdirectory=reeflex-litellm" in body
    assert (REPO_ROOT / "reeflex-litellm" / "pyproject.toml").exists()
    assert "https://core.test" in body
    assert "acme-prod" in body
    assert "rfx_" not in body


# ---------------------------------------------------------------------------
# The exchange, against a stub portal
# ---------------------------------------------------------------------------

class _StubPortal:
    """A loopback HTTP server that answers the two agent-plane routes.

    `script` maps a path to `(status, body)`. Requests are recorded so a test
    can assert on the bearer token and the hello payload -- which is the point
    of a real server: the contract under test is the HTTP one.
    """

    def __init__(self, script):
        self.script = script
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                outer.requests.append({
                    "path": self.path,
                    "auth": self.headers.get("authorization"),
                    "body": json.loads(raw) if raw else None,
                })
                status, body = outer.script.get(self.path, (404, {"detail": "not found"}))
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()


def _connect_ok(core_url):
    return (200, {
        "gate": {"id": GATE_ID, "name": "acme-prod", "environment": "production"},
        "core_url": core_url,
        "portal_url": "https://portal.test",
        "hello_url": "https://portal.test/api/v1/agent/hello",
        "expires_at": "2026-09-08T10:00:00+00:00",
        "portal_time": "2026-09-08T09:45:00+00:00",
    })


def test_a_401_from_the_portal_becomes_a_message_about_minting_a_fresh_line(capsys):
    with _StubPortal({"/api/v1/agent/connect": (401, {"detail": "unauthorized"})}) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
    assert code == 1
    err = capsys.readouterr().err
    assert "refused this registration token" in err
    assert "ONE exchange" in err
    # It must not tell the customer to retry the same line -- there is no
    # failure mode behind a 401 here that a retry fixes.
    assert "try again" not in err.lower()


def test_a_404_from_the_portal_names_both_of_its_two_causes(capsys):
    with _StubPortal({}) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
    assert code == 1
    err = capsys.readouterr().err
    assert "404" in err
    assert "portal URL is wrong" in err
    assert "switched on" in err


def test_the_bearer_token_is_sent_and_the_gate_id_is_checked_against_the_answer(
    tmp_path, monkeypatch, capsys
):
    """The token decides which gate this is, server-side. `--gate` is checked
    AGAINST the answer so two mixed-up lines are refused rather than silently
    configuring an agent for the wrong environment."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    with _StubPortal({"/api/v1/agent/connect": _connect_ok("http://127.0.0.1:1")}) as portal:
        code = main([
            "connect", "--token", VALID_TOKEN,
            "--gate", "00000000-0000-4000-8000-00000000dead",
            "--portal", portal.url,
        ])
        assert portal.requests[0]["auth"] == f"Bearer {VALID_TOKEN}"

    assert code == 1
    err = capsys.readouterr().err
    assert "belongs to gate" in err
    assert "mixed up" in err
    # AND NOTHING WAS WRITTEN. The mismatch is caught before the config step,
    # so a wrong-environment hook never reaches disk.
    assert not (tmp_path / ".claude").exists()


def test_an_unreachable_core_reports_nothing_to_the_portal(tmp_path, monkeypatch, capsys):
    """The difference between this and a ping. Port 1 is unreachable, so the
    decision never happens -- and no hello is sent, because a verdict we did
    not receive is not a verdict."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("http://127.0.0.1:1"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
        paths = [r["path"] for r in portal.requests]

    assert code == 1
    assert paths == ["/api/v1/agent/connect"]
    err = capsys.readouterr().err
    assert "could not get a decision out of" in err
    assert "Nothing has been reported to the portal" in err
    # The hook config IS written, and the message says why that is the safe
    # direction: it fails CLOSED until core is reachable.
    assert (tmp_path / ".claude" / "settings.json").exists()
    assert "fail CLOSED" in err


def _core_fails_closed(reason):
    """The shape `enforce._fail_closed` returns: not reachable, and the reason
    string is the only place the HTTP status survives."""

    return lambda _envelope: (
        "deny",
        f"Reeflex: core unreachable or error -- failing closed: {reason} "
        "[rule=reeflex.core/fail_closed]",
        "reeflex.core/fail_closed",
        False,
        [],
    )


def test_an_authenticated_core_refusing_the_smoke_names_the_credential(
    tmp_path, monkeypatch, capsys
):
    """A core started with `REEFLEX_AUTH_TOKEN` refuses everything but
    `/healthz`, so a 401 means the URL is right and the engine is up. Telling
    the reader to fix the URL or start the engine would send them somewhere
    that cannot help -- on the hosted default this is the first thing a
    stranger who pasted the line reads."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        _core_fails_closed("core HTTP 401: Unauthorized"),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
        paths = [r["path"] for r in portal.requests]

    assert code == 1
    # A verdict that was never received is still not reported.
    assert paths == ["/api/v1/agent/connect"]
    err = capsys.readouterr().err
    assert "REEFLEX_CORE_TOKEN" in err
    assert "is up and answered" in err
    # The remedy that does not apply must be GONE, not merely accompanied.
    assert "start the engine" not in err
    # And the spent token is stated, because the retry needs a fresh line.
    assert "spent" in err


def test_a_failure_that_is_not_auth_keeps_the_generic_remedy(
    tmp_path, monkeypatch, capsys
):
    """The control for the test above: the credential advice must be reserved
    for 401/403. A 500 is not an auth problem and must not send the reader
    hunting for a bearer token."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        _core_fails_closed("core HTTP 500: Internal Server Error"),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])

    assert code == 1
    err = capsys.readouterr().err
    assert "start the engine" in err
    assert "REEFLEX_CORE_TOKEN" not in err


def test_the_hello_carries_cores_verdict_vocabulary_not_claude_codes(monkeypatch):
    """`enforce.call_core_and_map` renames core's `require_approval` to Claude
    Code's `ask`; the portal stores core's word and refuses `ask` outright.
    This is the one place that renaming is undone, so it is pinned here."""

    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("ask", "needs a human", "reeflex.policy/r2", True, []),
    )
    result = connect_mod.smoke_decision(
        core_url="https://core.test", environment="production"
    )
    assert result["verdict"] == "require_approval"
    assert result["rule"] == "reeflex.policy/r2"
    # The action is read off the ENVELOPE (`build_envelope` composes
    # `ability`); `classify` returns no such key at all.
    assert "claude-code/Bash" in result["action"]


def test_smoke_decision_restores_the_environment_it_borrowed(monkeypatch):
    """`enforce` reads its config from the environment, so `smoke_decision`
    sets two variables for the duration of one call. Leaving them set would
    change the behaviour of anything else in the same process -- including,
    on a source checkout, the next test."""

    monkeypatch.setenv("REEFLEX_CORE_URL", "http://sentinel.test")
    monkeypatch.delenv("REEFLEX_CLAUDE_ENVIRONMENT", raising=False)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "ok", "reeflex.policy/benign", True, []),
    )

    connect_mod.smoke_decision(core_url="https://core.test", environment="dev")

    assert os.environ["REEFLEX_CORE_URL"] == "http://sentinel.test"
    assert "REEFLEX_CLAUDE_ENVIRONMENT" not in os.environ


def test_the_full_flow_reports_the_verdict_it_received(tmp_path, monkeypatch, capsys):
    """Exchange -> write -> decide -> report, with a stub portal and a stubbed
    core call. The end-to-end version of this, against a real portal and a
    real `reeflex-core`, is in the round report -- this pins the SHAPE of the
    hello, which is a cross-repository contract."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "benign read", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True, "hello_id": "x"}),
    }) as portal:
        code = main([
            "connect", "--token", VALID_TOKEN, "--gate", GATE_ID,
            "--portal", portal.url, "--agent", "claude", "--global",
        ])
        hello = [r for r in portal.requests if r["path"] == "/api/v1/agent/hello"][0]

    assert code == 0
    assert hello["auth"] == f"Bearer {VALID_TOKEN}"
    assert hello["body"]["agent_kind"] == "claude-code"
    assert hello["body"]["verdict"] == "allow"
    assert hello["body"]["rule"] == "reeflex.policy/benign_read"
    assert hello["body"]["core_url"] == "https://core.test"
    assert hello["body"]["client_version"]
    assert hello["body"]["decided_at"]
    # Only the fields reeflex-app's closed-set validator accepts. An extra key
    # here is a 422 there, and this is the side that would have to notice.
    assert set(hello["body"]) <= {
        "agent_kind", "client_version", "core_url", "verdict", "rule", "action",
        "session_id", "decided_at",
    }

    out = capsys.readouterr().out
    assert "verdict: allow" in out
    assert "YOUR AGENT'S REPORT" in out
    assert (tmp_path / ".claude" / "settings.json").exists()


def test_the_opencode_flow_reports_its_own_agent_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "benign read", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main([
            "connect", "--token", VALID_TOKEN, "--portal", portal.url,
            "--agent", "opencode",
        ])
        hello = [r for r in portal.requests if r["path"] == "/api/v1/agent/hello"][0]

    assert code == 0
    assert hello["body"]["agent_kind"] == "opencode"
    assert (tmp_path / ".config" / "opencode" / "plugin" / "reeflex.js").is_file()


# ---------------------------------------------------------------------------
# The engine credential the exchange now returns (RFX-224, second precondition)
#
# The store's own behaviour is `tests/test_credentials_rfx224.py`; what is
# pinned here is the four things `connect` does with it -- store it, tell the
# operator where without printing it, put the gate id (and only the gate id)
# into the config, and do all of that BEFORE the smoke.
# ---------------------------------------------------------------------------

CORE_CREDENTIAL = "rfx_ac_" + "C" * 43


def _connect_ok_with_credential(core_url, *, gate_id=None):
    """`_connect_ok` plus what a current portal actually returns.

    `_connect_ok` deliberately stays credential-free: every test written
    against it is now also the backward-compatibility case for an OLDER portal
    that issues none, which is coverage for free rather than coverage to
    write.
    """

    status, body = _connect_ok(core_url)
    body = dict(body)
    if gate_id is not None:
        body["gate"] = dict(body["gate"], id=gate_id)
    body["core_credential"] = {
        "token": CORE_CREDENTIAL,
        "expires_at": "2026-10-08T09:45:00+00:00",
        "gate_header": "X-Reeflex-Gate",
    }
    body["introspect_url"] = "https://portal.test/api/v1/agent/introspect"
    return status, body


def test_the_credential_is_stored_at_0600_and_never_printed(tmp_path, monkeypatch, capsys):
    """The claim the onboarding screen now makes, checked as mode bits and as
    the absence of the value from stdout AND stderr.

    THE `not in out` HALF IS THE POINT. A command that stored the credential
    correctly and then echoed it would put it in the same shell scrollback the
    whole design exists to keep it out of -- and no file-permission assertion
    would have noticed.
    """

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "benign read", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])

    assert code == 0
    store = tmp_path / "creds.json"
    assert store.is_file()
    assert oct(store.stat().st_mode)[-3:] == "600"
    entry = json.loads(store.read_text())["credentials"][0]
    assert entry["token"] == CORE_CREDENTIAL
    assert entry["gate_id"] == GATE_ID
    assert entry["core_url"] == "https://core.test"

    captured = capsys.readouterr()
    assert CORE_CREDENTIAL not in captured.out
    assert CORE_CREDENTIAL not in captured.err
    # It says WHERE, and it says the two facts that matter about it.
    assert "creds.json" in captured.out
    assert "0600" in captured.out
    assert "2026-10-08" in captured.out


def test_the_config_gets_the_gate_id_and_still_no_secret(tmp_path, monkeypatch):
    """`settings.json` is world-readable and routinely committed. The gate id
    is a public identifier the portal prints on screen; the credential is not,
    and must not appear in this file even though `connect` now holds one."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "ok", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        assert main(["connect", "--token", VALID_TOKEN, "--portal", portal.url]) == 0

    body = (tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8")
    settings = json.loads(body)
    assert settings["env"]["REEFLEX_GATE_ID"] == GATE_ID
    assert "REEFLEX_CORE_TOKEN" not in body
    assert CORE_CREDENTIAL not in body
    # No member of the credential family, by prefix, so a future one is
    # covered without anyone remembering to extend this.
    assert "rfx_ac_" not in body
    assert "rfx_reg_" not in body
    assert "rfx_gate_" not in body


def test_the_credential_is_stored_before_the_smoke_and_the_smoke_can_see_it(
    tmp_path, monkeypatch
):
    """THE ORDERING, AND IT IS LOAD-BEARING.

    Step 3 is the hook's OWN code path (`enforce`), which finds the credential
    through the store. Storing it after the smoke would make step 3 exercise a
    configuration nobody will ever run -- which is the exact class of mistake
    that let this feature ship with a first decision that 401s.

    Asserted by having the stubbed decision READ the store at the moment it is
    called, rather than by reading the source. It is the only order in which
    that read can succeed.
    """

    seen = {}
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)

    def _spy(_envelope):
        from reeflex_claude.credentials import lookup

        seen["gate_env"] = os.environ.get("REEFLEX_GATE_ID")
        seen["credential"] = lookup(core_url="https://core.test", gate_id=GATE_ID)
        return ("allow", "ok", "reeflex.policy/benign_read", True, [])

    monkeypatch.setattr(connect_mod, "call_core_and_map", _spy)

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        assert main(["connect", "--token", VALID_TOKEN, "--portal", portal.url]) == 0

    assert seen["credential"] == CORE_CREDENTIAL, "the smoke ran before the store"
    assert seen["gate_env"] == GATE_ID, "the smoke declared no gate"


def test_the_operators_own_token_means_nothing_is_stored(tmp_path, monkeypatch, capsys):
    """Their credential wins in `enforce`, so storing one they will not use
    would leave a secret on disk for nothing."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.setenv("REEFLEX_CORE_TOKEN", "the-operators-own-not-a-secret")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "ok", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        assert main(["connect", "--token", VALID_TOKEN, "--portal", portal.url]) == 0

    assert not (tmp_path / "creds.json").exists()
    out = capsys.readouterr().out
    assert "Yours wins" in out


def test_an_older_portal_that_issues_no_credential_behaves_exactly_as_before(
    tmp_path, monkeypatch, capsys
):
    """A new client against an old portal. `_connect_ok` has no
    `core_credential`, so nothing is stored and the pre-existing advice about
    exporting `REEFLEX_CORE_TOKEN` is what the operator reads."""

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map",
        lambda _envelope: ("allow", "ok", "reeflex.policy/benign_read", True, []),
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        assert main(["connect", "--token", VALID_TOKEN, "--portal", portal.url]) == 0

    assert not (tmp_path / "creds.json").exists()
    out = capsys.readouterr().out
    assert "issued no engine credential" in out
    assert "REEFLEX_CORE_TOKEN" in out


def test_a_credential_that_cannot_be_stored_stops_the_run_and_reports_nothing(
    tmp_path, monkeypatch, capsys
):
    """A hard failure, not a warning. The alternative is finishing with an
    agent configured to call an engine it cannot authenticate to, whose next
    tool call fails CLOSED -- and the registration token is spent by then, so
    the operator would have to work out for themselves that the remedy is a
    fresh line."""

    monkeypatch.setenv("HOME", str(tmp_path))
    store = tmp_path / "creds.json"
    store.write_text("{ not json")
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(store))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
        paths = [r["path"] for r in portal.requests]

    assert code == 1
    assert paths == ["/api/v1/agent/connect"], "a hello was reported anyway"
    err = capsys.readouterr().err
    assert "could not be stored" in err
    assert "fresh line" in err
    assert store.read_text() == "{ not json"


def test_a_403_from_the_engine_never_advises_exporting_a_token(tmp_path, monkeypatch, capsys):
    """SUBJECT. 403 is the SCOPED refusal: the engine knows the credential and
    will not accept it for the gate this request declared. Its cause is two
    onboardings crossed on one machine -- never a missing token -- so the
    remedy must not send the reader to their secret store.

    The CONTROL is `test_an_authenticated_core_refusing_the_smoke_names_the_
    credential` above, which keeps the 401 wording; if this fix had been made
    by widening that branch, this test would pass and that one would fail.
    """

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REEFLEX_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    monkeypatch.delenv("REEFLEX_CORE_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        connect_mod, "call_core_and_map", _core_fails_closed("core HTTP 403: Forbidden")
    )

    with _StubPortal({
        "/api/v1/agent/connect": _connect_ok_with_credential("https://core.test"),
        "/api/v1/agent/hello": (200, {"recorded": True}),
    }) as portal:
        code = main(["connect", "--token", VALID_TOKEN, "--portal", portal.url])
        paths = [r["path"] for r in portal.requests]

    assert code == 1
    assert paths == ["/api/v1/agent/connect"]
    err = capsys.readouterr().err
    assert "refused it for the gate this request declared" in err
    assert "scoped to ONE gate" in err
    assert "REEFLEX_GATE_ID" in err
    # The 401 advice must NOT appear on this path.
    assert "REEFLEX_CORE_TOKEN" not in err
    assert "secret store" not in err
