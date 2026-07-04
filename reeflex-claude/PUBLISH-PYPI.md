# Publishing reeflex-claude to PyPI

**STATUS: procedure only.** This document does not publish anything by
itself. Publishing a package is a GATE (CLAUDE.md §6: "package publication
(npm/packagist)" — the same rule applies here) and requires an explicit
human GO before step 4. Steps 1-3 (build, check, clean-venv test) are safe
to run at any time and produce no public side effects.

Convention (per the project's release-artifacts rule): the local
`releases/<tag>/` directory is the SOURCE of the published artifacts;
PyPI is the publication target, never the other way around. Build there
first, verify there, upload from there, then read back from PyPI itself to
prove the published bytes actually work.

## 0. Prerequisites

- `python -m pip install --upgrade build twine`
- A PyPI API token scoped to the `reeflex-claude` project, stored **by
  reference** in Vault — never on disk, never in `~/.pypirc`, never in this
  repo or in any report/journal. Confirm the exact Vault path with Leo
  before the first real publish. Fetch it the same way other release
  tokens in this project are handled (see the GHCR push-token precedent):
  fetch LOCALLY (not on a shared VM), pipe it straight into the upload
  command's environment for that one command, and never let it land in a
  password manager export, a shell history file, or `.pypirc`.
- A clean working tree, checked out at the commit tagged for the release
  (e.g. `v0.1.6`), so the built artifact matches the tag exactly.

## 1. Build (local = source of truth)

Build into the release's local artifact directory, not into
`reeflex-claude/dist/` directly, so the published bytes live in the same
place as every other release's artifacts:

```bash
cd reeflex-claude
python -m build --outdir ..\releases\v0.1.6\pypi
```

This produces:

```
releases/v0.1.6/pypi/reeflex_claude-0.1.6-py3-none-any.whl
releases/v0.1.6/pypi/reeflex_claude-0.1.6.tar.gz
```

## 2. Verify the package metadata

```bash
python -m twine check releases\v0.1.6\pypi\*
```

Both artifacts must print `PASSED`. Do not proceed past a `FAILED`, and
investigate any `WARNING` before continuing.

## 3. Clean-venv local install test (pre-publish gate)

Never skip this — it repeats the same proof as this hotfix's BUILD PROOF
step, but against the EXACT bytes about to be uploaded:

```bash
python -m venv .venv-pypi-check
.venv-pypi-check\Scripts\pip install releases\v0.1.6\pypi\reeflex_claude-0.1.6-py3-none-any.whl
.venv-pypi-check\Scripts\reeflex-claude check
rmdir /s /q .venv-pypi-check
```

Expect `PASS -- fail-closed verified` (the probe forces the core
unreachable by design — see `reeflex_claude/cli.py:run_deny_probe`). If this
fails, STOP. Do not proceed to step 4.

## 4. Upload — GATE: requires an explicit human GO before this step

Token is env-only for the single upload command, fetched from Vault
immediately before use, and never written to `.pypirc` or any file:

```bash
# Adapt the Vault fetch to this project's standard secret-retrieval pattern
# (LOCAL fetch, piped directly into the command's environment — see the
# GHCR push-token precedent: never on a shared VM, never via a password
# manager export, never via a CLI call that lands in shell history).
set TWINE_USERNAME=__token__
set TWINE_PASSWORD=<fetched from Vault for this command only>
python -m twine upload releases\v0.1.6\pypi\*
```

Unset `TWINE_PASSWORD` from the shell/session immediately afterward.

## 5. Post-publish read-back proof

Never trust a bare "uploaded" report. Prove the exact published package
installs and works, from PyPI itself (not from the local wheel), in a
throwaway venv:

```bash
python -m venv .venv-pypi-live
.venv-pypi-live\Scripts\pip install reeflex-claude==0.1.6
.venv-pypi-live\Scripts\reeflex-claude check
rmdir /s /q .venv-pypi-live
```

Expect the same `PASS -- fail-closed verified`. Record the raw output
(command + full stdout) in the release report — a screenshot or a bare
"done" is not sufficient proof (WoW §2 EXIT gate).

## 6. CI end-state (not yet implemented; tracked as a follow-up)

The manual-token flow above is the bootstrap path only. The target
end-state is **PyPI Trusted Publishing** (OIDC — no long-lived API token at
all): a GitHub Actions workflow scoped to release tags (e.g. triggered on
`v*` tag push), registered as a Trusted Publisher on the `reeflex-claude`
PyPI project, running `pypa/gh-action-pypi-publish` with
`id-token: write` permission. Moving to Trusted Publishing removes the
Vault-token step from this document entirely for future releases. This is
a follow-up item, not part of this hotfix — do not implement it as a side
effect of this brief.
