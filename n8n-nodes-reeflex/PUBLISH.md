# Publishing n8n-nodes-reeflex (GATE - human only)

This package is 100% prepared to publish. **No agent may run any step in
this document.** Publishing a public npm package is an irreversible,
public action (CLAUDE.md SS0.3/SS6, GATE). This file exists so a human can
execute the release without having to reverse-engineer the tooling.

Everything below assumes you are in `n8n-nodes-reeflex/` (this directory).

## 0. Prerequisites (one-time, before the first publish)

- [ ] An npm account/org that will own the `n8n-nodes-reeflex` package name
      (npm packages are first-come; verify the name is still free at
      <https://www.npmjs.com/package/n8n-nodes-reeflex> before proceeding).
- [ ] `npm login` on the machine doing the first publish (only needed for
      the very first release - see "One-time npm Trusted Publisher setup"
      below for why later releases do not need a long-lived token).
- [ ] Confirm `package.json` `author`/`repository`/`homepage` fields still
      point where you want them (currently: Reeflex, hello@reeflex.io,
      `github.com/Reeflex-io/reeflex`, directory `n8n-nodes-reeflex`).

## 1. Local verification (repeat before every release)

```bash
cd n8n-nodes-reeflex
npm ci
npm run lint      # must be clean for nodes/ and credentials/
npm run build     # must produce dist/credentials/*.js and dist/nodes/**/*.js
npm test          # if the test suite is present and green (see NOTE below)
npx @n8n/scan-community-package n8n-nodes-reeflex  # only meaningful AFTER
                                                    # the package exists on
                                                    # npm - it 404s pre-publish
```

NOTE (updated - the import-restriction problem below is FIXED, a narrower
one remains): `test/reeflexGate.test.ts` originally used Node's built-in
`node:test`/`node:assert` runner, which the n8n Cloud lint profile flagged
under `@n8n/community-nodes/no-restricted-imports`. It has been rewritten to
import nothing beyond the local source module and `n8n-workflow` types (a
hand-rolled `it()`/`assertEqual()`/`assertRejects()` in the test file
itself) - confirmed empirically: `no-restricted-imports` no longer fires.
`npm run lint` now reports exactly 5 remaining errors, all from that same
test file, all `no-console` (the test reporter's `console.log` progress
output) and one `@n8n/community-nodes/no-restricted-globals` (`process`,
used for `process.exitCode` so a failing test suite exits non-zero for CI).
None of this originates from the shipped node code (verified:
`npx eslint nodes credentials` alone is clean) and none of it affects
`npm run build` or `npm test`, both of which are green.

This is now a **structural** tension, not a fixable bug: a plain Node CLI
test script legitimately needs `console`/`process` to report results and
signal pass/fail to CI, and `"strict": true` scans this whole package
directory (not just `dist/`) with zero exemption mechanism for non-shipped
files - confirmed empirically that editing `eslint.config.mjs` (e.g. an
`ignores` entry for `test/**`) makes `n8n-node lint` print a "Strict mode
violation: eslint.config.mjs has been modified from the default
configuration" and refuse to lint anything at all. **Do not attempt that
edit.** Three real options, in order of preference, left for a human /
product decision since they trade off Cloud-verification eligibility:

1. **Leave it as-is and treat "5 known test-only lint errors" as part of
   the accepted release checklist** (this document's section 5 checklist
   below reflects that reality rather than pretending it is clean).
2. **Move `test/` out of this npm package into a sibling location** (e.g.
   `n8n-nodes-reeflex-tests/` next to it, or a `.github/`-only CI step that
   checks out the test file from elsewhere) so `n8n-node lint`'s `**/*.ts`
   glob never sees it. Real fix, real cost: the test suite is no longer
   colocated with the code it tests.
3. **Run `npx n8n-node cloud-support disable`** (rewrites `package.json`'s
   `"n8n".strict` to `false` and switches to `@n8n/node-cli`'s
   `configWithoutCloudSupport`, its own first-class, tool-supported escape
   hatch for packages that are not pursuing n8n Cloud verification). Reeflex
   is on-prem-first (`docs/adr/0001-deployment-model.md`), so this may be
   the right call, but it is a scoped product decision (whether this
   package should ever be eligible for n8n Cloud's verified-nodes listing),
   not something to flip silently during a publish.

## 2. Manual smoke test in a real n8n instance (recommended before first publish)

```bash
npm run dev
```

This builds the package and starts a local n8n instance with Reeflex Gate
loaded. Open <http://localhost:5678>, add the node to a workflow, add a
Reeflex API credential pointing at a running `reeflex-core` (see
`../reeflex-core/README.md`), and confirm all three outputs fire correctly
against a real core instance (allow / require_approval / deny - see the
policy pack's R1-R5 in `../reeflex-core/policy/reeflex.rego` for scenarios
that trigger each).

## 3. One-time npm Trusted Publisher setup

n8n requires (as of May 1, 2026) that nodes submitted for Creator Portal
verification be published via GitHub Actions with an npm provenance
statement - see `.github/workflows/publish.yml` in this directory, which is
already written and ready. To let it publish without a long-lived secret:

1. Publish the package to npm manually ONE time first (npm requires the
   package to already exist before you can attach a Trusted Publisher to
   it): `npm login`, then `npm publish --access public` from a clean
   `npm run build`.
2. Log in to <https://www.npmjs.com/>, open the `n8n-nodes-reeflex` package
   settings.
3. Under **Publish access -> Trusted Publishers**, click **Add a
   publisher**, select **GitHub Actions**, and fill in:
   - Repository owner: `Reeflex-io`
   - Repository name: `reeflex`
   - Workflow name: `publish.yml` (the filename, not the workflow's
     `name:` field)
4. Leave `NPM_TOKEN` unset in the repository's GitHub Actions secrets - the
   workflow uses OIDC instead. (Fallback: if you would rather use a
   classic token, create a Granular Access Token on npmjs.com scoped to
   this package and store it as the `NPM_TOKEN` repository secret instead
   of doing steps 2-4.)

## 4. Every subsequent release

```bash
cd n8n-nodes-reeflex
npm run release
```

`n8n-node release` (via `release-it`) lints, builds, prompts for a version
bump, updates the changelog, commits, tags the release as
`n8n-nodes-reeflex-X.Y.Z`, and pushes. The tag push triggers
`.github/workflows/publish.yml`, which builds again in CI and publishes to
npm with a provenance attestation.

**Verify after every release (read-back, not assertion):**

```bash
npm view n8n-nodes-reeflex version   # matches the version you just released
npm view n8n-nodes-reeflex dist.integrity
```

## 5. Submitting for n8n Creator Portal verification (optional, separate GATE)

Verification is a separate, optional step from publishing - a package can
be a working, installable community node without ever being "verified."
Only do this once the package has real-world usage and you are ready for
n8n to list it as verified in the in-app nodes panel.

1. Re-read
   [Verification guidelines](https://docs.n8n.io/connect/create-nodes/build-your-node/reference/verification-guidelines.md)
   in full - n8n updates these periodically.
2. Confirm the checklist:
   - [ ] Package published via GitHub Actions with provenance (section 3-4
         above already satisfies this).
   - [ ] `npm run lint` clean for `nodes/` and `credentials/` (it is -
         verified with `npx eslint nodes credentials`). Decide on one of
         the three options in section 1's NOTE for the 5 remaining
         `test/`-only errors before treating `npm run lint` itself (run
         with no path filter) as a clean CI gate.
   - [ ] README present in the npm package (it is - `"files": ["dist"]`
         does NOT exclude `README.md`; npm always includes it regardless
         of the `files` field).
   - [ ] License is MIT (it is - see `LICENSE` and its licensing-scope
         note).
   - [ ] No runtime dependencies (`dependencies` in `package.json` is
         empty; `n8n-workflow` is a `peerDependency`, provided by the host
         n8n installation, not bundled).
   - [ ] English-only node interface and docs (it is).
3. Sign up / log in to the [n8n Creator Portal](https://creators.n8n.io/nodes)
   and submit `n8n-nodes-reeflex` for verification.
4. n8n reserves the right to reject nodes that compete with paid n8n
   features - Reeflex Gate does not (it governs actions in the user's own
   backend systems via reeflex-core, not an n8n platform feature).

## Rollback

If a published version is broken, npm does not allow re-publishing the
same version number. Publish a patch version with the fix, and consider
running `npm deprecate n8n-nodes-reeflex@<bad-version> "<reason>"` to warn
existing installs. Do not `npm unpublish` a version more than 72 hours old
except in genuine security-incident circumstances (npm's own unpublish
policy) - this is a human decision, not an automated one.
