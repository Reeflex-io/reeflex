# reeflex-holds -- MCPB (MCP Bundle) reference build

This directory produces a Claude Desktop one-click install bundle (`.mcpb`)
for the `reeflex-holds` MCP server (PyPI: `reeflex-holds`). It wraps the
published PyPI package; it does not fork or reimplement it.

## What's committed vs. generated

Committed source (this is what a `git status` should show as tracked):

- `manifest.json` -- the MCPB manifest (schema `manifest_version: "0.3"`).
- `server/main.py` -- a thin shim: `from reeflex_holds.server import main` /
  `main()`. This is the file Claude Desktop actually launches
  (`python ${__dirname}/server/main.py`).
- `build.ps1` / `build.sh` -- the pack recipes (Windows / macOS+Linux).
- `.mcpbignore` -- excludes cache/test cruft from the packed bundle.
- `.gitignore` -- keeps build outputs out of git.
- This `README.md`.

Generated (gitignored, rebuilt by `build.ps1` / `build.sh`, never committed):

- `server/lib/` -- `reeflex-holds` and its dependencies, `pip install
  --target`-ed in.
- `*.mcpb` -- the packed bundle itself.

## Why bundles are platform+ABI specific

`reeflex-holds` declares exactly one dependency, `mcp>=1.2.0` (see
`reeflex-holds/pyproject.toml`). That SDK transitively pulls in compiled
wheels:

- `pydantic_core` (Rust)
- `cryptography` / `cffi` (C)
- `rpds-py` (Rust)

Compiled wheels are specific to an OS + CPU architecture + Python ABI. A
`server/lib/` populated by `pip install --target` on Windows x64 contains
`win_amd64` wheels and will NOT run on macOS or Linux (and vice versa). There
is no universal/"fat" Python MCPB bundle for this package -- each platform
needs its own build.

## How to build

Each script produces exactly ONE bundle: the one matching the platform/arch
it is run on. There is no cross-compilation here.

### Windows (this worktree, this machine)

```powershell
cd reeflex-holds/mcpb
./build.ps1              # builds reeflex-holds 0.1.1 by default
./build.ps1 -Version 0.1.1
```

Produces `reeflex-holds-<version>-win32-<x64|arm64>.mcpb` in this directory.

### macOS / Linux

```bash
cd reeflex-holds/mcpb
./build.sh                # builds reeflex-holds 0.1.1 by default
./build.sh 0.1.1
```

Produces `reeflex-holds-<version>-<darwin|linux>-<x64|arm64>.mcpb` in this
directory.

Both scripts:

1. `pip install --target server/lib reeflex-holds==<version>` from PyPI
   (`reeflex-holds` has been published to PyPI since 0.1.1 -- see the
   package's own `pyproject.toml` note, which predates that publish).
2. Pack `manifest.json` (kept at the zip root) + `server/` via
   `npx @anthropic-ai/mcpb pack` if the `mcpb` CLI is reachable, else fall
   back to a plain zip (which does **not** honor `.mcpbignore` -- prefer
   having the CLI available).

Neither script runs, imports at module level in a way that executes, or
otherwise starts the `reeflex-holds` MCP server. `pip install` and `zip`/
`mcpb pack` are the only subprocesses invoked.

## Platform matrix -- current reality

| Platform     | Arch    | Status                                             |
|--------------|---------|-----------------------------------------------------|
| Windows      | x64     | Built locally in this worktree; see PROOF below.    |
| Windows      | arm64   | Buildable by running `build.ps1` on that hardware.  |
| macOS        | arm64   | NOT built here -- needs `build.sh` run on Apple Silicon. |
| macOS        | x64     | NOT built here -- needs `build.sh` run on an Intel Mac. |
| Linux        | x64     | NOT built here -- needs `build.sh` run on Linux x64.     |
| Linux        | arm64   | NOT built here -- needs `build.sh` run on Linux arm64.   |

**Upgrade path (not built in this change, YAGNI for a reference bundle):** a
CI matrix job (GitHub Actions `strategy.matrix` over
`{windows-latest, macos-latest, macos-13, ubuntu-latest}` or equivalent
arm64 runners) that checks out this directory, runs the matching
`build.ps1`/`build.sh`, and uploads each `.mcpb` as a release asset per tag.
That job is deliberately NOT added here -- this reference bundle only proves
the Windows path locally. Adding the CI matrix is a follow-up, gated on
Leo's GO for anything that publishes/attaches release assets.

## Configuration -- how the token gets to the server

The manifest declares four `user_config` entries (`core_url`, `token`,
`principal`, `verify_ssl`), which Claude Desktop's install UI prompts the
user for and substitutes into `server.mcp_config.env` at launch
(`${user_config.token}` etc. -- see `manifest.json`).

**The bearer token (`REEFLEX_TOKEN`) is ALWAYS supplied by the user at
install/configure time, via the `sensitive: true` `user_config.token`
field. It is never embedded in `manifest.json`, never baked into
`server/main.py` or `server/lib/`, and never written by `build.ps1` /
`build.sh`.** The same applies to `principal` (an identity, not a secret,
but still user-supplied, never hardcoded) and to `core_url`/`verify_ssl`.

Note the one cross-package naming outlier, surfaced honestly rather than
silently reconciled: `reeflex-holds` reads `REEFLEX_TOKEN`, while the other
two Reeflex adapters (`reeflex-claude`, `reeflex-wordpress`) read
`REEFLEX_CORE_TOKEN` for the equivalent value. See
`reeflex-holds/reeflex_holds/config.py`'s module docstring for the same note
at the source. The manifest's `user_config.token` title says "Gate token
(REEFLEX_TOKEN)" so an installer isn't misled into thinking it is the
`REEFLEX_CORE_TOKEN` name used elsewhere.

## Verifying a built bundle (structurally, without running it)

```bash
# from reeflex-holds/mcpb/
mkdir /tmp/mcpb-check && cd /tmp/mcpb-check
unzip ../reeflex-holds-0.1.1-win32-x64.mcpb -d unpacked
python -c "import json; m = json.load(open('unpacked/manifest.json')); print(m['manifest_version'], m['name'], m['version'], m['server']['entry_point'])"
ls unpacked/server/lib | grep -E '^(reeflex_holds|mcp|pydantic_core)'
```

Or, if the `mcpb` CLI is available:

```bash
npx @anthropic-ai/mcpb validate manifest.json
```

This directory's build was verified this way as part of the change that
added it -- see the dev round report for the exact output (zip listing,
manifest fields, `server/lib/` contents, `mcpb validate` output).
