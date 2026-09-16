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
  The exchange in step 2 does return one secret; step 3 says where it is put,
  and it is not in your project directory.

## Step 1 — install the adapter

    pip install 'reeflex-claude>=0.2.0'

`reeflex-claude` is a public package on PyPI. Its source is
`reeflex-claude/` in `github.com/Reeflex-io/reeflex` (Apache 2.0).

## Step 2 — exchange the registration token

`connect` sends the token to your portal, once, over TLS:

    POST <portal>/api/v1/agent/connect
    Authorization: Bearer rfx_reg_...

The response contains which gate the token was minted for, that gate's
environment (`production` / `staging` / `dev`), the URL of the `reeflex-core`
your decisions should go to — and **exactly one secret**: an `rfx_ac_` engine
credential, minted in the same transaction and scoped to that one gate. The
token is spent by this call: a second exchange of the same token is refused.

That credential is what the hook presents to `reeflex-core` on an engine that
runs with auth switched on. It travels in the response body, over TLS, to a
process that has already proved it holds your line — it is not in the line you
pasted, and it is not printed. Step 3 says which file it lands in.

Your gate's own token and evidence key are NOT returned here. They were shown
once when you registered the gate and are not recoverable — not by us either.
This flow does not need them.

*Changed 2026-09-08.* Until then this step said the response contained no
secret, and that was accurate at the time. What changed is where the engine
credential travels, not what the pasted line carries: fifteen minutes after it
is minted, and immediately after it is spent, that line is inert.

## Step 3 — the files it writes

Two kinds of file, and the split is the point: one config file per agent, which
carries no secret and which you can commit or share, and one credentials file,
which carries the secret from step 2 and nothing else. `connect` names every
path on your screen before or as it writes it, and refuses to clobber an
unrelated file.

### The config file — no secret in it

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

**No token is written into any of these.** What they carry is the gate id,
which is not a secret — so the settings block your team shares stays
shareable.

### The credentials file — the secret from step 2, and nothing else

- `~/.reeflex/credentials.json`, directory `0700`, file `0600`, keyed by
  (core URL, gate id) so one machine can hold several gates without one
  overwriting another. It is outside your project directory, so it is not
  something you commit by accident.
- `connect` prints its path, the gate it is good for and its expiry. It does
  not print the value.
- Revoke it by revoking that gate in the portal, which also stops the agent it
  configured.
- **The limit, stated plainly:** a file readable by the user who ran `connect`
  is readable by anything running as that user, including the agent being
  governed. What bounds the damage is that this credential is scoped to one
  gate, expires, and can be revoked from the portal — not that the file is out
  of reach. A keyring is the upgrade path and is not here yet.

**If you already export `REEFLEX_CORE_TOKEN`, yours wins.** With it set,
`connect` stores nothing, says so, and the hook presents your token — a
self-hosted engine's own credential stays your business. A portal old enough
to issue no credential also stores nothing, and `connect` says that too and
tells you to export `REEFLEX_CORE_TOKEN` yourself. An engine running with auth
switched off needs neither.

Do not assume the engine your portal points you at is one of those. The hosted
dev engine at `https://api-dev.reeflex.io` **requires a bearer token**: on
2026-09-16 `POST /v1/decide` without one answered `401 unauthorized`, and
`/healthz` was the route that answered without credentials. Needing a token
there is why step 2 returns one.

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
  other than the hook entry named in step 3. The other thing it writes is the
  credentials file, also named in step 3.
- It does not send your prompts, your code or your files anywhere. The hook
  sends the action envelope described in `reeflex-spec/SPEC.md` — verb,
  ability, three axes, magnitude, target environment — and nothing else.

## Verifying this document

    sha256sum agent-setup.md

Compare it with the digest shown beside the line in the portal. They must
match. If they do not, stop and ask the address in the portal footer. That is
the comparison that answers "is what I am about to run what I was shown".

`connect` also prints a digest of its own — the version of this document the
adapter you installed was built against. It is a third value and it is not
part of the check above:

- **Adapter digest = portal digest.** The adapter implements the document you
  just read.
- **Adapter digest ≠ portal digest.** Ordinarily this means the adapter is
  older than the document — a new release of the document reaches the portal
  as soon as it is deployed, and reaches the adapter only when you upgrade it.
  The procedure that adapter runs is the document at ITS digest. Upgrade with
  `pip install -U 'reeflex-claude'` and the two converge. If they still differ
  after an upgrade, ask the address in the portal footer before you paste.
