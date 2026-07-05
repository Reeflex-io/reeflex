# Releasing Reeflex

Reeflex is a monorepo that ships to five channels from one tagged commit. This
document describes the **one-gesture** release flow driven by
[`.github/workflows/release.yml`](../.github/workflows/release.yml), the
**one-time registry setup** a human must do, and the **manual fallback** (the
process used for v0.1.6, before this workflow existed).

---

## 1. The one gesture

A release is a single act:

```bash
# from a clean, green `main` at the commit you want to release
git tag -s v0.1.7 -m "Reeflex v0.1.7"
git push origin v0.1.7
```

Pushing a `v*` tag triggers `release.yml`, which fans out to:

| Channel | Package | Auth |
|---|---|---|
| GitHub Release | all artifacts + `SHA256SUMS` attached to the tag | `GITHUB_TOKEN` |
| PyPI | `reeflex-claude` **and** `reeflex-holds` | OIDC Trusted Publishing |
| npm | `n8n-nodes-reeflex` (with provenance) | OIDC or `NPM_TOKEN` |
| GHCR | `ghcr.io/reeflex-io/reeflex-core` **only if core changed** | `GITHUB_TOKEN` |
| Job summary | a channel checklist (version + URL + ✅/⏭️/❌ per channel) | — |

Publishing a **GitHub Release** through the web UI also works: the UI creates
the tag, and the tag push is what triggers the workflow. Either gesture leads to
the same run. (If a release object already exists for the tag, the workflow just
attaches assets to it and leaves the body untouched.)

**Manual re-run / re-release:** use the `workflow_dispatch` trigger (Actions →
Release → Run workflow). It requires a `tag` input (an existing tag, e.g.
`v0.1.7`) and offers a `push_core` boolean (see §4). Re-runs are safe: PyPI uses
`skip-existing`, npm skips an already-published version, and GHCR just re-pushes
the same tag.

> **GATE.** Every publish is a public, largely irreversible act (PyPI/npm do not
> allow re-uploading a version). Per the project gates, pushing a release tag
> requires a human GO. The workflow automates the *mechanics*, not the decision.

### Pre-flight (before you tag)

- CI is green on the commit you are tagging.
- Versions are bumped in each package that changed:
  - `reeflex-claude/pyproject.toml` → `version`
  - `reeflex-holds/pyproject.toml` → `version`
  - `n8n-nodes-reeflex/package.json` → `version`
  - `reeflex-wordpress/reeflex-gate.php` → the `Version:` header
  These are **independent** — the release tag (`v0.1.6`) is the umbrella, not each
  package's version (e.g. v0.1.6 shipped `reeflex-claude 0.1.6`,
  `reeflex-holds 0.1.0`, `n8n-nodes-reeflex 0.1.0`, `reeflex-gate 0.1.5`).
- `CHANGELOG.md` updated.
- A local copy of the built artifacts lands in `reeflex/releases/<tag>/` (local =
  source of truth, GitHub = publication). The workflow builds its own copies; keep
  the local ones for the record.

---

## 2. One-time registry setup (a human, once)

The workflow is **tokenless by design** for PyPI and prefers tokenless for npm.
This requires configuring the registries once.

### 2.1 PyPI — Trusted Publishers (OIDC) for BOTH projects

For **each** of `reeflex-claude` and `reeflex-holds`, add a GitHub Actions
Trusted Publisher (PyPI → project → *Settings* → *Publishing* → *Add a new
publisher*):

| Field | Value |
|---|---|
| Owner | `Reeflex-io` |
| Repository | `reeflex` |
| Workflow name | `release.yml` |
| Environment | *(leave blank, unless you enable the `pypi` environment — see below)* |

- `reeflex-claude` already exists on PyPI, so add the publisher on the existing
  project.
- `reeflex-holds` is **not yet on PyPI** (the name is not reserved). Use PyPI's
  **"pending publisher"** flow: create the trusted publisher for the
  not-yet-existing project name `reeflex-holds`; the first successful OIDC publish
  creates the project. Reserving the name (`reeflex`, `reeflex-core`,
  `reeflex-claude` are reserved; `reeflex-holds` is not yet) is a GATE.

Optional hardening: create a GitHub **Environment** named `pypi`, uncomment
`environment: pypi` in the `pypi` job, and set the *Environment* field on both
PyPI publishers to `pypi`. This lets you gate the publish behind required
reviewers.

**No PyPI token is stored in the repo.** The Vault entry `/credentials/pypi`
(account + 2FA + a legacy API token) is **bootstrap/fallback only** — see §3.

### 2.2 npm — trusted publishing OR the `NPM_TOKEN` secret

Two options; prefer the first if your npm account supports it:

1. **OIDC trusted publishing (preferred).** Configure trusted publishing for
   `n8n-nodes-reeflex` on npmjs.com pointing at repo `Reeflex-io/reeflex` and
   workflow `release.yml`. Then no token is needed — `id-token: write` (already in
   the job) plus `--provenance` does both auth and provenance.
2. **`NPM_TOKEN` repo secret (bootstrap/fallback).** Create an **automation**
   access token on npmjs.com and store it as the `NPM_TOKEN` GitHub Actions
   secret. The `npm` job reads it via `NODE_AUTH_TOKEN`. This is the current
   bootstrap path until trusted publishing is set up.

The npm token in Vault `/credentials/npm` is the source for the `NPM_TOKEN`
secret; the secret is the fallback, not the primary path.

### 2.3 GHCR — nothing to configure

The `ghcr` job authenticates with the run's `GITHUB_TOKEN` (`packages: write`).
The image `ghcr.io/reeflex-io/reeflex-core` is already public. No PAT is needed
for pushing from CI. (The Vault `/credentials/GHCR_TOKEN` is only for
pushing from a workstation/VM by hand.)

### 2.4 Secrets summary

| Secret | Used by | Status |
|---|---|---|
| `GITHUB_TOKEN` (built-in) | GitHub Release, GHCR | always |
| PyPI OIDC (no secret) | PyPI publish | **primary** |
| npm OIDC (no secret) | npm publish | preferred |
| `NPM_TOKEN` (repo secret) | npm publish | bootstrap/fallback |
| `PYPI_API_TOKEN` (repo secret) | PyPI publish | **bootstrap only**, commented out |

The Vault tokens (`/credentials/pypi`, `/credentials/npm`) stay **bootstrap /
fallback only**. The steady state is OIDC — no long-lived publish token in the
repo.

---

## 3. What the workflow does, job by job

1. **prepare** — resolves the release tag (from the pushed tag, or the
   `workflow_dispatch` `tag` input), detects whether `reeflex-core/` or the
   `Dockerfile` changed since the previous tag (for the GHCR guard), and extracts
   each package version for the summary.
2. **build** — builds every artifact **once** from the tagged commit:
   - the four zips via `scripts/build-wp-zips.py` (see §5),
   - `python -m build` for `reeflex-claude` and `reeflex-holds` (sdist + wheel),
   - `npm ci && npm run build && npm pack` for `n8n-nodes-reeflex`,
   - `SHA256SUMS` over all of them.
   Uploads them as workflow artifacts for the publish jobs.
3. **github-release** — attaches all artifacts + `SHA256SUMS` to the release for
   the tag (creating the release if needed).
4. **pypi** — publishes `reeflex-claude` and `reeflex-holds` via OIDC
   (`skip-existing: true`).
5. **npm** — rebuilds from the tag and `npm publish --provenance --access public
   --tag latest`, skipping if the version already exists.
6. **ghcr** — builds + pushes `reeflex-core` tagged with the release tag **and**
   `latest`, **only when core changed** (§4).
7. **summary** — writes the channel checklist to the job summary.

---

## 4. The GHCR guard (why core does not always ship)

The core image is expensive to churn and is versioned on its own cadence. The
`ghcr` job runs **only when the release actually changes core.** The rule:

- On a tag release, the workflow diffs `reeflex-core/` and the root `Dockerfile`
  between the previous tag and this tag. If nothing changed there, the GHCR job is
  **skipped** and the published `latest` stays where it was.
- Override with the `workflow_dispatch` input `push_core: true` (forces a build +
  push regardless of the diff).
- The first tag (no previous tag) always builds.

This encodes what happened for **v0.1.6**: it was an adapters/surfaces release
with **no core change**, so GHCR stayed at `v0.1.5`
(`ghcr.io/reeflex-io/reeflex-core:v0.1.5`). The workflow reproduces that
automatically — v0.1.6 would have skipped GHCR.

When core *does* change, the image is pushed as both `:v0.1.x` and `:latest`.

---

## 5. WordPress zip layout (and the file counts)

`scripts/build-wp-zips.py` builds the four zip artifacts with Python's stdlib
`zipfile` (the runner has no `zip` binary). It is the single source of truth for
packaging and can be run locally:

```bash
python scripts/build-wp-zips.py --out dist-artifacts
```

- **`reeflex-gate-wordpress-standard.zip`** — everything under a top-level
  `reeflex-gate/` folder: the loader `reeflex-gate.php`, all
  `reeflex-gate/class-*.php`, `index.php`, `languages/index.php`, `uninstall.php`,
  `readme.txt`, `license.txt`.
- **`reeflex-gate-wordpress-mu.zip`** — the loader `reeflex-gate.php` at the **ZIP
  root** (mu-plugins auto-loads only top-level `.php`) plus the `class-*.php`,
  `index.php`, and `languages/index.php` in a `reeflex-gate/` subfolder. No
  readme/license/uninstall.
- **`reeflex-verify.zip`** — `reeflex-verify.py` + its README.
- **`reeflex-test-abilities.zip`** — the WP test-abilities plugin.

**File counts (as of v0.1.6): 14 in standard, 11 in mu.** The `class-*.php` list
is **globbed**, so adding a class grows both zips automatically. HIL Phase 2 added
two classes (the holds-store + normalizer split), moving the counts from the
earlier **12 standard / 9 mu** to **14 standard / 11 mu**. A future maintainer who
adds or removes a class should expect these numbers to move — that is expected,
not a regression.

The archives are written deterministically (fixed member order + fixed mtime), so
re-running on unchanged sources yields byte-identical zips.

---

## 6. Manual fallback (the v0.1.6 process)

If Actions is unavailable, or before the registry-side OIDC is configured, a
release can be built and published by hand. This is exactly what was done for
v0.1.6:

1. **Build the zips** locally:
   `python scripts/build-wp-zips.py --out reeflex/releases/v0.1.7`
2. **Build the Python dists:**
   `python -m build reeflex-claude` and `python -m build reeflex-holds`; copy the
   `dist/*` into `reeflex/releases/v0.1.7/`.
3. **Build the npm tarball:**
   `cd n8n-nodes-reeflex && npm ci && npm run build && npm pack`; move the `.tgz`
   into the release dir.
4. **Hash everything:** `sha256sum -b * > SHA256SUMS` in the release dir.
5. **Publish** (each is a GATE — human GO):
   - GitHub Release: `gh release create v0.1.7 <files> --notes-file RELEASE-NOTES.md`
     (or `gh release upload` onto an existing release), then hash-verify the
     uploaded assets read-back.
   - PyPI: `twine upload` with the token from Vault `/credentials/pypi`
     (bootstrap only; prefer OIDC).
   - npm: `npm publish --access public` with the token from Vault
     `/credentials/npm` (bootstrap only; prefer OIDC).
   - GHCR: build on the VM and push only if core changed (v0.1.6 did **not** push
     core — it stayed v0.1.5). Fetch `GHCR_TOKEN` from Vault and
     `docker login --password-stdin`; log out afterward.

The local release directory `reeflex/releases/<tag>/` is the source of truth; the
GitHub Release is the publication of those exact bytes.

---

## 7. After a release

- Confirm the job summary checklist is all ✅ (or the expected ⏭️ for GHCR on an
  adapters-only release).
- Verify each channel by read-back: `pip index versions reeflex-claude`,
  `npm view n8n-nodes-reeflex version`, `gh release view <tag>`, and (if pushed)
  an anonymous `docker pull ghcr.io/reeflex-io/reeflex-core:<tag>`.
- Update `MEMORY` / the report channel with the published versions + digests.
