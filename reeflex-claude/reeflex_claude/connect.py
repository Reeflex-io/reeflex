"""
connect.py -- `reeflex-claude connect`: the one line a portal puts on a
customer's clipboard (RFX-224).

    pip install 'reeflex-claude>=0.2.0' && reeflex-claude connect \\
      --gate <gate-id> --token <rfx_reg_...> --portal https://app.reeflex.io

WHAT IT IS NOT. It is not "fetch a URL and follow whatever it says". That is
the exact instruction shape this product exists to put a gate in front of --
an agent executing unverified remote instructions with the customer's
privileges -- and an onboarding that used it would contradict the product on
its first screen. So the procedure is FIXED IN THIS FILE, published in
`docs/setup/v1/agent-setup.md`, shown in full by the portal beside the copy
button, and pinned by SHA-256 (`SETUP_DOC_SHA256` below, asserted by
tests/test_connect.py against the checked-in document). Nothing is downloaded
and executed. `--dry-run` prints every path it would write and exits.

THE FOUR STEPS, AND WHERE THE HONEST LIMITS ARE

1. EXCHANGE. `POST <portal>/api/v1/agent/connect`, Bearer the registration
   token. The response carries which gate, which environment, which core URL
   -- and ONE secret: an `rfx_ac_` engine credential the portal minted for
   that one gate. The token is spent by this call.
2. WRITE ONE CONFIG, AND ONE CREDENTIAL FILE. `--agent claude` merges a
   PreToolUse hook entry (the existing `setup_settings` code path, so the
   RFX-204/205 fixes -- absolute hook path, wildcard matcher -- apply here
   unchanged). `--agent opencode` writes a plugin. `--agent litellm` writes a
   proxy config fragment. **No secret is written into any of them** -- they
   get the gate id, which is not one. The engine credential goes to
   `~/.reeflex/credentials.json` at 0600, outside the project directory so it
   cannot be committed; `credentials.py` records why not settings.json, not
   the shell profile, and not the pasted line.
3. ONE REAL DECISION. A benign read is put through this package's OWN
   classifier and envelope builder and sent to core's `/v1/decide`. Not a
   ping, not a `/healthz`: the round trip exercises the code path the hook
   uses, so a misconfigured core fails HERE rather than on the customer's
   first real tool call.
4. REPORT IT. `POST <portal>/api/v1/agent/hello`, same bearer. The portal
   labels what arrives as the agent's own report, because that is what it is:
   this call is not signed with the gate's evidence key (that is the
   connector's job, a separate component, on a different plane). If step 3
   did not reach core, nothing is reported and the command exits non-zero.

WHAT THIS STILL DOES NOT DO, in the code as well as in the document: it does
not INVENT a credential, and it does not go looking for the engine operator's
own one. `reeflex-core`'s original bearer is the operator's `REEFLEX_AUTH_TOKEN`
and this command has no way to know it. What it now has is a credential the
PORTAL minted, received over TLS in the exchange response -- which is a
different thing from inventing one, and the distinction is the whole design:

    a credential is not in the line, it is in the exchange.

If `REEFLEX_CORE_TOKEN` is already exported, that wins and nothing is stored:
an operator running their own engine keeps their own credential. And if the
portal is an older build that returns no credential, this says so and behaves
exactly as it did before. Secrets by reference only -- the same rule the fleet
that wrote this runs under; this file never prints the credential, never puts
it in argv, and never writes it anywhere a repository could pick it up.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import __version__
from .classify import classify
from .enforce import call_core_and_map
from .envelope import build_envelope
from .setup_settings import (
    DEFAULT_MATCHER,
    DEFAULT_TIMEOUT,
    SettingsError,
    hook_command_for_settings,
    load_settings,
    merge_env,
    merge_hook_entry,
    resolve_settings_path,
    write_settings,
)

DEFAULT_PORTAL_URL = "https://app.reeflex.io"
REGISTRATION_TOKEN_PREFIX = "rfx_reg_"
AGENTS = ("claude", "opencode", "litellm")

# The agent kinds the portal's screen knows friendly names for. Sent verbatim
# as `agent_kind` in the hello; the portal stores an unrecognised value rather
# than refusing it, so a downstream adapter can add its own.
_AGENT_KIND = {
    "claude": "claude-code",
    "opencode": "opencode",
    "litellm": "litellm",
}

# SHA-256 of `docs/setup/v1/agent-setup.md` in this repository. The portal
# renders that document inline and prints this digest beside the line it
# hands out; `tests/test_connect.py` asserts this constant against the file,
# and reeflex-app's `tests/onboard/test_setup_doc.py` asserts the same
# constant against its byte-identical copy. Two suites, one number: if the
# document moves and only one side is updated, both go red naming the digest.
SETUP_DOC_SHA256 = "e1a56d728757b66f7f49228b62c2a6a7340374ec059c5d1b36a8aa943c2bb062"

_HTTP_TIMEOUT_SECONDS = 20

# The action step 3 asks about. A BENIGN READ, classified by this package's
# own classifier rather than hand-written as an envelope: hand-writing the
# envelope would test the transport and skip the two components most likely
# to be misconfigured. `ls` of the current directory is read-only, internal
# and single-target, so a working gate answers `allow` -- which makes a
# `deny` here a real signal (usually a core pointed at the wrong policy) and
# not noise.
_SMOKE_TOOL = "Bash"
_SMOKE_INPUT = {"command": "ls -la ."}


class ConnectError(Exception):
    """Anything that stops the flow. Carries an operator-facing message; it
    never carries the registration token."""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _post_json(
    url: str,
    *,
    token: str,
    payload: Optional[Dict[str, Any]] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """One POST with a bearer token. Raises `ConnectError` with a message that
    names the URL and the status but NEVER the token."""

    body = json.dumps(payload if payload is not None else {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "User-Agent": f"reeflex-claude/{__version__}",
        },
        method="POST",
    )
    ctx = None if verify_ssl else ssl._create_unverified_context()  # noqa: S323
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS, context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        if exc.code == 401:
            raise ConnectError(
                f"the portal refused this registration token ({url} -> 401). "
                "A token is good for ONE exchange, for ONE gate, and expires "
                "after a few minutes -- and it is refused after being "
                "withdrawn. Mint a fresh line on the portal's Connect an "
                "agent screen and paste that one."
            ) from exc
        if exc.code == 404:
            raise ConnectError(
                f"{url} answered 404. Either the portal URL is wrong, or that "
                "deployment does not have one-line agent onboarding switched "
                "on -- in which case the portal's Gates screen has the manual "
                "path."
            ) from exc
        raise ConnectError(f"{url} -> HTTP {exc.code}. {detail}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ConnectError(f"could not reach {url}: {exc}") from exc

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ConnectError(f"{url} did not answer JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ConnectError(f"{url} answered JSON that is not an object")
    return parsed


# ---------------------------------------------------------------------------
# Step 2 -- the config writers. One per agent, each returning the paths it
# wrote (or would write, under --dry-run) so the caller can print them.
# ---------------------------------------------------------------------------

def _core_env(core_url: str, environment: str, gate_id: str = "") -> Dict[str, str]:
    """The env block every agent gets. STILL NO SECRET: see the module
    docstring. `REEFLEX_GATE_ID` is a public identifier -- the portal prints it
    on the screen and in the pasted line -- and it does two jobs in the hook:
    it is sent as `X-Reeflex-Gate` (an engine that accepts a portal credential
    requires it, so one gate's credential cannot be replayed as another's) and
    it selects which stored credential to use."""

    env = {
        "REEFLEX_CORE_URL": core_url,
        "REEFLEX_MODE": "enforce",
        "REEFLEX_CLAUDE_ENVIRONMENT": environment,
        "REEFLEX_VERIFY_SSL": "true",
    }
    if gate_id:
        env["REEFLEX_GATE_ID"] = gate_id
    return env


def write_claude_config(
    *, core_url: str, environment: str, target: str, dry_run: bool, gate_id: str = ""
) -> Tuple[Path, str]:
    """Merge the PreToolUse hook entry into Claude Code's settings.json.

    Delegates to `setup_settings`, which is the same code `reeflex-claude
    setup` uses -- so the absolute-path hook command (RFX-205: a bare
    `reeflex-claude hook` is `command not found` when Claude Code is launched
    outside the venv, which is a silent ALLOW) and the wildcard matcher
    (RFX-204: an allowlist of tool names exempts every `mcp__*` tool) are not
    re-implemented here and cannot drift.
    """

    path = resolve_settings_path(target)
    if dry_run:
        return path, "would merge a PreToolUse hook entry"

    try:
        settings = load_settings(path)
        replaced = merge_hook_entry(
            settings,
            command=hook_command_for_settings(),
            matcher=DEFAULT_MATCHER,
            timeout=DEFAULT_TIMEOUT,
        )
        merge_env(settings, _core_env(core_url, environment, gate_id))
        write_settings(path, settings)
    except SettingsError as exc:
        raise ConnectError(str(exc)) from exc
    return path, ("updated the existing hook entry" if replaced else "wrote a new hook entry")


# The OpenCode plugin. OpenCode's plugin API (verified against opencode
# 1.18.23) calls `tool.execute.before` for every tool call, and a THROW from
# that handler aborts the call -- which is the enforcement primitive, the
# direct analogue of Claude Code's `permissionDecision: "deny"`.
#
# It shells out to the SAME `reeflex-claude hook` this package installs rather
# than re-implementing classify/envelope/decide in JavaScript. That is the
# whole reason this is ~40 lines: one adapter, two front ends, no second
# classifier to keep in step with the first.
#
# `ask` (core's `require_approval`) is treated as a REFUSAL here and says so,
# because this hook has no way to prompt a human: an approval it cannot ask
# for is not an approval, and the fail-closed direction is the only honest one
# for a governance gate. Claude Code, which does have an approval UI, gets
# `ask` (see hook.py).
_OPENCODE_PLUGIN = '''// Reeflex governance gate for OpenCode -- written by `reeflex-claude connect`.
// Regenerate with: reeflex-claude connect --agent opencode --gate <id> --token <t>
//
// It calls the `reeflex-claude hook` binary (the same PreToolUse adapter Claude
// Code uses) and THROWS when the verdict is not `allow`. A throw from
// `tool.execute.before` aborts the tool call; that is the enforcement.
//
// FAIL-CLOSED, INCLUDING WHEN THIS PLUGIN ITSELF BREAKS. Every failure path
// below throws: hook missing, hook non-zero, unparseable output, verdict
// `ask` (nothing here can prompt a human, so an approval it cannot ask for is
// a refusal). An adapter that let a call through because it could not decide
// would be worse than no adapter, because the audit trail would say nothing
// happened.
import { spawnSync } from "node:child_process";

const HOOK = %(hook_cmd)s;
const CORE_URL = %(core_url)s;
const ENVIRONMENT = %(environment)s;
// The gate this agent was connected to. NOT a secret -- the portal prints it
// on screen. The hook sends it as `X-Reeflex-Gate` and uses it to find the
// engine credential `connect` stored at 0600 outside the project directory.
const GATE_ID = %(gate_id)s;

export const ReeflexPlugin = async ({ directory }) => {
  const cwd = directory || process.cwd();
  return {
    "tool.execute.before": async (input, output) => {
      const payload = JSON.stringify({
        session_id: "opencode-" + String(input.sessionID || "session"),
        hook_event_name: "PreToolUse",
        tool_name: input.tool,
        tool_input: output.args,
        cwd,
      });
      const env = { ...process.env, REEFLEX_CORE_URL: CORE_URL,
                    REEFLEX_CLAUDE_ENVIRONMENT: ENVIRONMENT, REEFLEX_MODE: "enforce" };
      if (GATE_ID) env.REEFLEX_GATE_ID = GATE_ID;
      const run = spawnSync(HOOK[0], HOOK.slice(1), { input: payload, env, encoding: "utf8" });
      if (run.error || run.status !== 0) {
        throw new Error("reeflex: gate did not answer (" +
          (run.error ? run.error.message : "exit " + run.status) +
          ") -- refusing " + input.tool + ". Check `reeflex-claude check`.");
      }
      let verdict, reason;
      try {
        const out = JSON.parse(run.stdout);
        verdict = out.hookSpecificOutput.permissionDecision;
        reason = out.hookSpecificOutput.permissionDecisionReason;
      } catch (e) {
        throw new Error("reeflex: could not read the gate's verdict -- refusing " +
          input.tool + ". " + String(e));
      }
      if (verdict === "allow") return;
      if (verdict === "ask") {
        throw new Error("reeflex: this action needs a human approval and OpenCode " +
          "cannot ask for one here, so it is refused. " + reason);
      }
      throw new Error("reeflex: denied -- " + reason);
    },
  };
};
'''


def _opencode_plugin_path() -> Path:
    """`~/.config/opencode/plugin/reeflex.js`, honouring `XDG_CONFIG_HOME`.

    The plugin DIRECTORY, not `opencode.json`: OpenCode loads every `.js` in
    it, so this adds a file and never rewrites a config the customer (or
    another tool) also writes to. Measured on this box, a second plugin
    already lives there.
    """

    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "opencode" / "plugin" / "reeflex.js"


def write_opencode_config(
    *, core_url: str, environment: str, dry_run: bool, gate_id: str = ""
) -> Tuple[Path, str]:
    path = _opencode_plugin_path()
    if dry_run:
        return path, "would write an OpenCode plugin"

    hook = _resolve_hook_argv()
    body = _OPENCODE_PLUGIN % {
        "hook_cmd": json.dumps(hook),
        "core_url": json.dumps(core_url),
        "environment": json.dumps(environment),
        "gate_id": json.dumps(gate_id),
    }
    existed = path.exists()
    if existed and "ReeflexPlugin" not in path.read_text(encoding="utf-8"):
        raise ConnectError(
            f"{path} exists and was not written by reeflex-claude. Refusing to "
            "overwrite it -- move it aside and re-run."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path, ("replaced the previous Reeflex plugin" if existed else "wrote a new plugin")


# The LiteLLM fragment. A proxy is configured by YAML, not by a hook, so what
# `connect` can honestly do is write the fragment and print the two lines to
# paste -- it does NOT edit a running proxy's config.yaml, because that file is
# the operator's and may be templated, mounted read-only or under version
# control.
#
# EVERY LINE IN IT IS PINNED BY tests/test_connect.py AGAINST THE PACKAGE IT
# CONFIGURES, because the first version of this fragment was wrong in three
# ways at once and nothing could see it: no test read it, `reeflex-litellm` is
# a different distribution, and a fragment is inert until an operator starts a
# proxy with it. Measured with litellm's OWN resolver (1.100.0,
# `litellm.proxy.proxy_server.get_instance_fn`):
#
#   reeflex_litellm.ReeflexGate                         -> AttributeError:
#       module 'reeflex_litellm' has no attribute 'ReeflexGate'
#   reeflex_litellm.guardrail.ReeflexActionGuardrail    -> the class
#
# The three: (1) that class name does not exist in the package
# (`__all__ = ["__version__"]`); (2) the seat is a GUARDRAIL under `guardrails:`
# with `mode: post_call` -- what lets it read the tool calls a model proposed
# and CHANGE the response -- not a `litellm_settings.callbacks` entry, which
# only observes; (3) `REEFLEX_ENVIRONMENT` is read by nothing, the variable is
# `REEFLEX_LITELLM_ENVIRONMENT`, so a staging gate was silently priced against
# `production` (the default). Keep this fragment and
# `reeflex-litellm/proxy/config.yaml` in step.
_LITELLM_FRAGMENT = """# Reeflex governance seat for LiteLLM -- written by `reeflex-claude connect`.
#
# Add the `guardrails:` entry below to your proxy's config.yaml and set the
# environment beside it. Nothing is merged for you: that file is yours, and it
# may be templated, mounted read-only or under version control.
#
#     pip install 'reeflex-litellm[proxy]'
#
# The `proxy` extra is what pulls litellm itself. To run it from the source
# tree instead of the index:
#
#     pip install 'git+https://github.com/Reeflex-io/reeflex@main#subdirectory=reeflex-litellm'
#
# IT IS A GUARDRAIL, NOT A CALLBACK. `mode: post_call` is what lets it read the
# tool calls a model proposed and remove or withhold them; a
# `litellm_settings.callbacks` entry only observes. The `guardrail:` value is a
# dotted import path litellm resolves itself, so it must name the class exactly.
guardrails:
  - guardrail_name: "reeflex-action-gate"
    litellm_params:
      guardrail: reeflex_litellm.guardrail.ReeflexActionGuardrail
      mode: post_call
      default_on: true
      # Seconds a response may be withheld while a hold waits for a human.
      # 0 = do not wait: refuse now and name the hold so the caller can retry.
      reeflex_hold_wait: 30
      # The request header carrying the session R5's cumulative budget is
      # charged against. Without it (or an OpenAI `user` field) the budget is
      # scoped to ONE REQUEST.
      reeflex_session_header: x-reeflex-session

environment_variables:
  REEFLEX_CORE_URL: "%(core_url)s"
  REEFLEX_LITELLM_ENVIRONMENT: "%(environment)s"
  # NOT a secret -- the portal prints it on screen. An engine that accepts a
  # portal-issued credential requires it, so that one gate's credential cannot
  # be replayed as another gate's.
  REEFLEX_GATE_ID: "%(gate_id)s"
  # REQUIRED, and there is deliberately NO default org: each proxy key or team
  # must be mapped to a Reeflex org, or every tool call is refused. Write the
  # map, then validate it OFFLINE -- `reeflex-litellm tenancy` exits non-zero
  # if it would not load, and you want that at deploy time rather than as an
  # outage. An example ships at reeflex-litellm/examples/tenancy-map.example.json.
  REEFLEX_LITELLM_TENANCY_MAP_FILE: "/etc/reeflex/tenancy.json"
  # This gate is %(gate_name)s. NO CREDENTIAL IS WRITTEN INTO THIS FILE, and
  # for a proxy that is not merely tidiness. `connect` did store the engine
  # credential the portal minted -- at ~/.reeflex/credentials.json, mode 0600,
  # owned by the user who ran `connect`. A LiteLLM proxy usually runs as a
  # different user (a systemd unit, a container), which cannot read that file
  # and should not be given a copy of a config that could. So for a proxy:
  # read the value out of that file yourself and put it in the proxy's own
  # secret store as REEFLEX_CORE_TOKEN. It is deliberately not printed here.
"""


def write_litellm_config(
    *, core_url: str, environment: str, gate_name: str, dry_run: bool, gate_id: str = ""
) -> Tuple[Path, str]:
    path = Path.home() / ".reeflex" / "litellm" / "reeflex.yaml"
    if dry_run:
        return path, "would write a LiteLLM config fragment"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _LITELLM_FRAGMENT
        % {
            "core_url": core_url,
            "environment": environment,
            "gate_name": gate_name,
            "gate_id": gate_id,
        },
        encoding="utf-8",
    )
    return path, "wrote a config fragment (your config.yaml is not touched)"


# ---------------------------------------------------------------------------
# Step 3 -- one real decision
# ---------------------------------------------------------------------------

def _resolve_hook_argv() -> list:
    """How to invoke the installed hook. Same resolution `cli.resolve_hook_
    command` uses; duplicated here only to avoid importing `cli` from a module
    `cli` imports."""

    exe = shutil.which("reeflex-claude")
    if exe:
        return [exe, "hook"]
    return [sys.executable, "-m", "reeflex_claude.cli", "hook"]


def smoke_decision(
    *, core_url: str, environment: str, gate_id: str = ""
) -> Dict[str, Any]:
    """Put one benign read through classify -> envelope -> POST /v1/decide.

    Returns the raw pieces the hello needs. Raises `ConnectError` when core
    could not be reached -- a verdict that was never received is not reported
    to the portal, which is the difference between this and a ping.

    THE ENVIRONMENT VARIABLES ARE SET FOR THE DURATION OF THIS CALL because
    `enforce.call_core_and_map` reads its configuration from the environment
    (it is written for a hook process whose env comes from settings.json). The
    previous values are restored: `connect` must not leave a mutated
    environment behind for whatever else this Python process goes on to do.

    NO SECRET IS PUT INTO THIS PROCESS'S ENVIRONMENT, and that is a deliberate
    choice over the shorter alternative. `enforce` finds the engine credential
    through the STORE (keyed by core_url + `REEFLEX_GATE_ID`), so this sets
    only the non-secret gate id. Exporting the credential as
    `REEFLEX_CORE_TOKEN` here would have been two fewer lines and would have
    put a secret into an environment inherited by every subprocess for the
    rest of the run -- including, on this very code path, nothing at all, but
    the next person to add a subprocess would not have known.
    """

    cls = classify(_SMOKE_TOOL, dict(_SMOKE_INPUT))
    payload = {
        "session_id": "reeflex-claude-connect",
        "hook_event_name": "PreToolUse",
        "tool_name": _SMOKE_TOOL,
        "tool_input": dict(_SMOKE_INPUT),
        "cwd": os.getcwd(),
    }

    saved = {
        k: os.environ.get(k)
        for k in ("REEFLEX_CORE_URL", "REEFLEX_CLAUDE_ENVIRONMENT", "REEFLEX_GATE_ID")
    }
    os.environ["REEFLEX_CORE_URL"] = core_url
    os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = environment
    if gate_id:
        os.environ["REEFLEX_GATE_ID"] = gate_id
    try:
        envelope = build_envelope(payload, cls)
        decision, reason, rule, reachable, _obligations = call_core_and_map(envelope)
        # Read the action off the ENVELOPE, not off `classify`'s output:
        # `ability` is composed by `build_envelope` (`claude-code/<tool>`) and
        # is not a key `classify` returns at all. Taking it from the envelope
        # means the portal shows the same string core decided on.
        acted = envelope.get("action", {})
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    if not reachable:
        # An engine started with `REEFLEX_AUTH_TOKEN` refuses every route
        # except `GET /healthz`, so a 401/403 here is what a correctly-running
        # AUTHENTICATED core looks like from the outside -- the URL is right
        # and the engine is up. The generic remedy below ("fix the URL or start
        # the engine") is the wrong advice for that case and sends the reader
        # somewhere that cannot help; on the hosted default (`api-dev`) it is
        # also the FIRST thing a stranger who pasted the line will read.
        if "core HTTP 403" in reason:
            # 403 is the SCOPED refusal and has a different cause from 401: the
            # engine knows the credential and will not accept it for the gate
            # this request declared. That is either two onboardings crossed on
            # one machine or a credential moved between projects -- never a
            # missing token, so it must never suggest exporting one.
            remedy = (
                f"{core_url} is up and recognised the credential, but refused "
                "it for the gate this request declared. The credential is "
                "scoped to ONE gate. If this machine has onboarded more than "
                "one, check REEFLEX_GATE_ID in the config written above; "
                "otherwise mint a fresh line for the gate you want and paste "
                "that -- the token you just used is spent."
            )
        elif "core HTTP 401" in reason:
            remedy = (
                f"{core_url} is up and answered -- it refused the request "
                "because it did not accept a credential for it. Two causes, in "
                "the order they are likely: that engine has not been told to "
                "accept credentials from this portal (its operator sets "
                "REEFLEX_GATE_INTROSPECTION_URL), or it wants its OWN bearer, "
                "in which case export REEFLEX_CORE_TOKEN from your shell "
                "profile or secret store. `connect` does not invent either. "
                "Then mint a fresh line and paste it again -- the token you "
                "just used is spent."
            )
        else:
            remedy = (
                "Fix the URL or start the engine, then re-run "
                "`reeflex-claude check`."
            )
        raise ConnectError(
            f"could not get a decision out of {core_url}: {reason}\n"
            "Nothing has been reported to the portal -- a verdict we did not "
            "receive is not a verdict. The hook config above is written and "
            "will fail CLOSED (deny) until core is reachable, which is the "
            f"safe direction. {remedy}"
        )

    # `enforce` maps core's three verdicts onto Claude Code's vocabulary
    # (`require_approval` -> `ask`). The portal stores CORE's word, so the one
    # renaming is undone here rather than teaching the portal a second
    # vocabulary.
    verdict = {"allow": "allow", "deny": "deny", "ask": "require_approval"}.get(decision, decision)
    return {
        "verdict": verdict,
        "rule": rule or None,
        "reason": reason,
        "action": f"{acted.get('verb', '')} {acted.get('ability', '')}".strip(),
        "session_id": payload["session_id"],
    }


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------

def cmd_connect(args) -> int:
    agent = args.agent
    if agent not in AGENTS:
        print(f"[reeflex-claude] ERROR: --agent must be one of {AGENTS}", file=sys.stderr)
        return 2
    token = (args.token or "").strip()
    if not token:
        print(
            "[reeflex-claude] ERROR: --token is required. It is the registration "
            "token from the portal's 'Connect an agent' screen.",
            file=sys.stderr,
        )
        return 2
    if not token.startswith(REGISTRATION_TOKEN_PREFIX):
        # A gate token or an evidence key pasted here would otherwise be sent
        # to the portal and rejected, having been in this process's argv for
        # no reason. Say which credential is wanted instead.
        print(
            f"[reeflex-claude] ERROR: that does not look like a registration token "
            f"(they start with `{REGISTRATION_TOKEN_PREFIX}`). A gate token "
            "(`rfx_gate_`) or an evidence key (`rfx_ek_`) is a different, "
            "longer-lived credential and is not what this command wants.",
            file=sys.stderr,
        )
        return 2

    portal = (args.portal or DEFAULT_PORTAL_URL).rstrip("/")
    verify_ssl = args.verify_ssl != "false"

    print(f"[reeflex-claude] connect v{__version__}")
    print(f"[reeflex-claude]   portal: {portal}")
    print(f"[reeflex-claude]   agent:  {agent}")
    print(f"[reeflex-claude]   setup document: docs/setup/v1/agent-setup.md")
    print(f"[reeflex-claude]   sha256: {SETUP_DOC_SHA256}")

    try:
        return _run(args, agent=agent, token=token, portal=portal, verify_ssl=verify_ssl)
    except ConnectError as exc:
        print(f"[reeflex-claude] ERROR: {exc}", file=sys.stderr)
        return 1


def _store_core_credential(
    config: Dict[str, Any],
    *,
    core_url: str,
    gate_id: str,
    gate_name: str,
    environment: str,
    portal: str,
) -> Tuple[Optional[Path], Optional[str]]:
    """Put the exchange's engine credential where the hook will find it.

    Returns `(path, expires_at)`, or `(None, None)` when there is nothing to
    store -- which is either an older portal that issues none, or an operator
    whose own `REEFLEX_CORE_TOKEN` already wins.

    A CREDENTIAL WE CANNOT STORE IS A HARD FAILURE, not a warning. The
    alternative is finishing with an agent configured to call an engine it
    cannot authenticate to, whose next tool call fails CLOSED -- and the
    registration token is spent by now, so the operator would have to work out
    for themselves that the remedy is a fresh line. Better to say it here,
    while the reason is on the screen.
    """

    raw = config.get("core_credential")
    if not isinstance(raw, dict):
        return None, None
    value = raw.get("token")
    if not isinstance(value, str) or not value:
        return None, None

    expires_at = raw.get("expires_at")
    expires_at = expires_at if isinstance(expires_at, str) else None

    # The operator's own credential takes precedence in `enforce`, so storing
    # one they will not use would leave a secret on disk for nothing.
    if os.environ.get("REEFLEX_CORE_TOKEN", "").strip():
        return None, None

    from .credentials import CredentialStoreError, store

    try:
        path = store(
            core_url=core_url,
            gate_id=gate_id,
            token=value,
            expires_at=expires_at,
            portal_url=portal,
            gate_name=gate_name or None,
            environment=environment or None,
        )
    except CredentialStoreError as exc:
        raise ConnectError(
            f"the portal issued an engine credential and it could not be "
            f"stored: {exc}\\nNothing has been reported to the portal. The "
            "registration token is spent, so fix the path above and paste a "
            "fresh line."
        ) from exc
    return path, expires_at


def _run(args, *, agent: str, token: str, portal: str, verify_ssl: bool) -> int:
    # --- 1. exchange -------------------------------------------------------
    if args.dry_run:
        print("[reeflex-claude] --dry-run: NOT exchanging the token, NOT writing anything.")
        config = {
            "gate": {"id": args.gate or "<from the portal>", "name": "<from the portal>",
                     "environment": "<from the portal>"},
            "core_url": "<from the portal>",
        }
    else:
        config = _post_json(
            f"{portal}/api/v1/agent/connect", token=token, verify_ssl=verify_ssl
        )

    gate = config.get("gate") or {}
    gate_id = str(gate.get("id", ""))
    gate_name = str(gate.get("name", ""))
    environment = str(gate.get("environment", "production"))
    core_url = str(config.get("core_url", "")).rstrip("/")

    if not args.dry_run:
        if not gate_id or not core_url:
            raise ConnectError(
                "the portal's connect response was missing `gate.id` or `core_url`."
            )
        # THE PASTED GATE ID IS CHECKED AGAINST THE ONE THE PORTAL NAMES. The
        # token alone decides which gate this is (the id in the line is not
        # trusted input server-side), so a mismatch means the line was
        # assembled wrongly or two lines were mixed up -- and continuing would
        # configure an agent for a different environment than the operator
        # believes. Refuse rather than silently prefer one.
        if args.gate and args.gate != gate_id:
            raise ConnectError(
                f"--gate says {args.gate} but that token belongs to gate {gate_id}. "
                "Two lines have probably been mixed up. Mint a fresh one and "
                "paste it whole."
            )
        print(f"[reeflex-claude] exchanged. gate {gate_name!r} ({environment}), id {gate_id}")
        print(f"[reeflex-claude]   the token is now spent; it cannot be exchanged again.")
        print(f"[reeflex-claude]   engine for this gate: {core_url}")

    # --- 2. write one config, and the credential the hook will need --------
    #
    # THE CREDENTIAL IS STORED BEFORE THE SMOKE, not after, and the order is
    # load-bearing: step 3 is the hook's own code path (`enforce`), which finds
    # the credential through the store. Storing it afterwards would make step 3
    # measure a configuration nobody will ever run -- the exact class of
    # mistake that let this feature ship with a first decision that 401s.
    stored_at = None
    credential_expires_at = None
    if not args.dry_run:
        stored_at, credential_expires_at = _store_core_credential(
            config, core_url=core_url, gate_id=gate_id, gate_name=gate_name,
            environment=environment, portal=portal,
        )

    if agent == "claude":
        path, what = write_claude_config(
            core_url=core_url or "<from the portal>",
            environment=environment,
            target=args.target,
            dry_run=args.dry_run,
            gate_id=gate_id,
        )
    elif agent == "opencode":
        path, what = write_opencode_config(
            core_url=core_url or "<from the portal>",
            environment=environment,
            dry_run=args.dry_run,
            gate_id=gate_id,
        )
    else:
        path, what = write_litellm_config(
            core_url=core_url or "<from the portal>",
            environment=environment,
            gate_name=gate_name or "this gate",
            dry_run=args.dry_run,
            gate_id=gate_id,
        )
    print(f"[reeflex-claude] {what}: {path}")
    # Three cases, and each gets its own sentence because the operator's next
    # move is different in each.
    if os.environ.get("REEFLEX_CORE_TOKEN", "").strip():
        print(
            "[reeflex-claude] REEFLEX_CORE_TOKEN is set in your environment, so "
            "that is what the hook will present. Yours wins; nothing was "
            "stored for this gate."
        )
    elif stored_at is not None:
        print(f"[reeflex-claude] stored this gate's engine credential: {stored_at} (mode 0600)")
        print(
            "[reeflex-claude]   it is not printed anywhere, it is not in the "
            "line you pasted, and it is outside this project directory so it "
            "cannot be committed."
        )
        if credential_expires_at:
            print(f"[reeflex-claude]   good for gate {gate_id} only, until {credential_expires_at}")
        print(
            "[reeflex-claude]   revoke it by revoking this gate in the portal, "
            "which also stops the agent it configured."
        )
    elif not args.dry_run:
        print(
            "[reeflex-claude] this portal issued no engine credential (an older "
            "build). Nothing was stored -- if your engine requires a bearer "
            "token, export REEFLEX_CORE_TOKEN yourself (shell profile, CI "
            "secret store) before the agent starts. A core with auth switched "
            "off needs none."
        )

    if args.dry_run:
        print(
            "[reeflex-claude] --dry-run complete. Nothing was exchanged, written, "
            "decided or reported. Re-run without --dry-run to do it."
        )
        return 0

    # --- 3. one real decision ---------------------------------------------
    print(f"[reeflex-claude] asking {core_url}/v1/decide one real question ...")
    result = smoke_decision(core_url=core_url, environment=environment, gate_id=gate_id)
    print(
        f"[reeflex-claude]   verdict: {result['verdict']}"
        + (f"  rule: {result['rule']}" if result["rule"] else "")
    )

    # --- 4. report it ------------------------------------------------------
    _post_json(
        f"{portal}/api/v1/agent/hello",
        token=token,
        payload={
            "agent_kind": _AGENT_KIND[agent],
            "client_version": __version__,
            "core_url": core_url,
            "verdict": result["verdict"],
            "rule": result["rule"],
            "action": result["action"],
            "session_id": result["session_id"],
            "decided_at": datetime.now(timezone.utc).isoformat(),
        },
        verify_ssl=verify_ssl,
    )
    print(
        "[reeflex-claude] reported to the portal. It will show as YOUR AGENT'S "
        "REPORT, not as a verified record -- signed decision records come from "
        "the evidence connector, which is a separate component."
    )
    print("[reeflex-claude] Now run: reeflex-claude check")
    return 0
