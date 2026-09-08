# Reeflex agent setup — v1

This document is the whole of what `reeflex-claude connect` does. Read it
before you paste anything. It is versioned and content-addressed: the portal
shows this file's SHA-256 next to the line it gives you, and the same file is
public at `docs/setup/v1/agent-setup.md` in `github.com/Reeflex-io/reeflex`, so
you can check that what you are about to run is what you were shown.

Reeflex exists to put a gate in front of an agent executing instructions it
did not write. So this setup is **not** "fetch a URL and follow it". Nothing
below is hidden behind a fetch, there is no remote script, and the command you
paste does exactly these steps and stops.

## What it needs before it will run

- Python 3.10 or newer, and `pip`.
- A registration token from your portal's **Connect an agent** screen. It is
  scoped to ONE gate, it is single-use, and it expires — 15 minutes by default.
- Nothing else. No credential of ours is written into any file you commit.

## Step 1 — install the adapter

    pip install 'reeflex-claude>=0.2.0'

`reeflex-claude` is a public package on PyPI. Its source is
`reeflex-claude/` in `github.com/Reeflex-io/reeflex` (Apache 2.0).

## Step 2 — exchange the registration token

`connect` sends the token to your portal, once, over TLS:

    POST <portal>/api/v1/agent/connect
    Authorization: Bearer rfx_reg_...

The response contains **no secret**. It contains which gate the token was
minted for, that gate's environment (`production` / `staging` / `dev`), and
the URL of the `reeflex-core` your decisions should go to. The token is spent
by this call: a second exchange of the same token is refused.

Your gate's own token and evidence key are NOT returned here. They were shown
once when you registered the gate and are not recoverable — not by us either.
This flow does not need them.

## Step 3 — the files it writes

Exactly one config file per agent, and one credentials-free settings block.
`connect` prints each path before writing it and refuses to clobber an
unrelated file.

- `--agent claude` (default) → merges a `PreToolUse` hook entry into
  `~/.claude/settings.json` (or `./.claude/settings.json` with `--project`).
  The hook command is the string `reeflex-claude hook`. The env block it
  writes holds `REEFLEX_CORE_URL`, `REEFLEX_MODE=enforce`,
  `REEFLEX_CLAUDE_ENVIRONMENT` and `REEFLEX_VERIFY_SSL=true`.
- `--agent opencode` → writes `~/.config/opencode/plugin/reeflex.js`, a plugin
  whose `tool.execute.before` shells out to `reeflex-claude hook` and throws
  when the verdict is `deny`. It does not touch your `opencode.json`.
- `--agent litellm` → writes `~/.reeflex/litellm/reeflex.yaml`, a fragment for
  your proxy's `config.yaml`, and prints the two lines to add. It edits no
  file your proxy already reads.

**No token is written into any of them.** If your `reeflex-core` requires a
bearer token, export `REEFLEX_CORE_TOKEN` in your own shell or secret store
before the agent starts; `connect` reads it from the environment if it is
there, tells you when it is not, and never invents one. `reeflex-core` with
auth switched off — the public dev endpoint, for instance — needs no token.

## Step 4 — one real decision

`connect` then asks your `reeflex-core` one real question, through the same
code path the hook uses:

    POST <core>/v1/decide

The action is a benign read (`reeflex-claude connect --check`, classified by
the adapter's own classifier, not hand-written) so a correctly configured gate
answers `allow`. `connect` prints the verdict and the rule that produced it,
and reports both back to the portal:

    POST <portal>/api/v1/agent/hello
    Authorization: Bearer rfx_reg_...   (the same token, now spent)

That report is what makes the line appear on your portal's Connect screen. It
is a **report**, and the portal labels it as one: the round trip to core is
real, but we did not witness it. Signed, verifiable decision records are a
different pipeline — the evidence connector — and they are what compliance
reporting reads.

If core is unreachable, `connect` says so and exits non-zero. It does not
report a verdict it did not receive.

## Step 5 — what this does NOT do

- It does not install the evidence connector. That is a separate, not-yet-
  published component; ask your portal's support address for it.
- It does not run `reeflex-core` for you. If the URL from step 2 points at
  your own engine, start it yourself.
- It does not change your agent's model, provider, permissions or any setting
  other than the hook entry named in step 3.
- It does not send your prompts, your code or your files anywhere. The hook
  sends the action envelope described in `reeflex-spec/SPEC.md` — verb,
  ability, three axes, magnitude, target environment — and nothing else.

## Verifying this document

    sha256sum agent-setup.md

Compare it with the digest shown beside the line in the portal. They must
match. If they do not, stop and ask the address in the portal footer.
