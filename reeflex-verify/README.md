# reeflex-verify

**See Reeflex work on your own system.** Point this tool at a live install
where the Reeflex gate is running, and it fires a set of real actions and shows
you what Reeflex decided for each one — **allow**, **hold** (require approval),
or **deny**. One command, a table of verdicts, no developer setup.

One script, one subcommand per integration. Today: `wp` (WordPress). As new
integrations ship (databases, shell, …), each gets its own subcommand and its
own test fixtures — same tool, same shape.

Requirements: **Python 3.8+** (stdlib only, no `pip install`) and **`curl`** on
your PATH (built into Windows 10+, macOS, and virtually every Linux — the tool
uses it as the HTTP transport because it passes host WAFs that block generic
HTTP clients). Runs the same on Windows, Linux, and macOS.

You can run it straight from a clone of this repo, or download
`reeflex-verify.zip` from the
[latest release](https://github.com/Reeflex-io/reeflex/releases).

---

## WordPress — `reeflex-verify wp`

### What you need first

1. **The Reeflex gate installed** on the WordPress site (the plugin that
   actually intercepts — see [`../reeflex-wordpress/`](../reeflex-wordpress/)),
   configured to reach your `reeflex-core` (e.g. the public dev endpoint
   `https://api-dev.reeflex.io` — with the gate's `verify_ssl` off, since it
   carries a staging certificate — or an internal deployment).
2. **The test-abilities plugin installed** on the same site. A fresh WordPress
   has no write-abilities registered, so there is nothing to fire at. This small
   plugin registers a few **safe** abilities (they only ever touch their own
   `reeflex_test` posts, never your real content) so you have real targets.
   - File: `reeflex-test-abilities.zip` — download it from the
     [latest release](https://github.com/Reeflex-io/reeflex/releases), or use
     the copy in this repo at
     [`wordpress-test-plugin/`](wordpress-test-plugin/) (same file).
   - Install it like any plugin: **wp-admin → Plugins → Add New → Upload Plugin
     → choose the zip → Install → Activate.**
   - Remove it when you're done testing.
3. **An Application Password** for a user allowed to delete posts. Generate one
   in **wp-admin → Users → Profile → Application Passwords**. This is how the
   tool authenticates (the same way any external agent would).

### Run it

```bash
python reeflex-verify.py wp \
  --url https://your-site.tld \
  --user your-admin-username \
  --app-password "xxxx xxxx xxxx xxxx xxxx xxxx"
```

Or keep secrets out of the command line with environment variables:

```bash
export REEFLEX_WP_URL=https://your-site.tld
export REEFLEX_WP_USER=your-admin-username
export REEFLEX_WP_APP_PASSWORD="xxxx xxxx xxxx xxxx xxxx xxxx"
python reeflex-verify.py wp
```

Add `--verbose` to see the reasoning and raw HTTP detail for each action,
`--insecure` for a self-signed dev certificate.

### What you should see

The tool fires five actions and checks each verdict against what Reeflex should
decide in a production environment:

| Action fired | Expected verdict | Why |
|---|---|---|
| read a test item | **ALLOW** | read-only, no risk |
| delete 1 item (soft) | **ALLOW** | single, recoverable |
| bulk delete 50 (force) | **HOLD** | irreversible + broad in production |
| bulk delete 25 (soft, ≥20) | **HOLD** | ≥20 items counts as irreversible |
| delete ALL site data (force) | **DENY** | systemic blast radius — denied outright |

A run where all five match tells you the gate is intercepting and deciding
correctly on **your** site. The tool exits `0` on a full match, `1` otherwise.

> The "delete" actions are decided by Reeflex **before** the callback runs, so
> the HOLD and DENY cases never touch anything. The ALLOW cases run against the
> plugin's own `reeflex_test` posts only.

### Testing fail-closed (the important one)

Fail-closed means: **when Reeflex cannot decide, nothing is allowed through.**
To see it on your site:

1. Temporarily point the gate at a dead core (set `REEFLEX_CORE_URL` to an
   unreachable URL/port in your gate configuration), or stop `reeflex-core`.
2. Run with the fail-closed expectation:

   ```bash
   python reeflex-verify.py wp --url ... --user ... --app-password ... \
     --expect-fail-closed
   ```

3. **Every** action — including the harmless read — should come back blocked.
   If anything is allowed while core is unreachable, that is a serious bug; the
   audit log (`wp-content/reeflex-audit.jsonl`) will show what happened.

Restore the real core URL when you're done.

### How a verdict is read

Reeflex surfaces its decision to the caller as a specific error code, which this
tool maps to a verdict:

| What comes back | Verdict |
|---|---|
| the ability's own output (2xx, no Reeflex code) | ALLOW |
| `reeflex_hold` | HOLD |
| `reeflex_denied` | DENY |
| `reeflex_unavailable` | FAIL-CLOSED |

Rule names and reasons are not sent to the caller (by design — they could help
an attacker probe policy). They are written to the server error log and the
audit JSONL. If you want the *why*, read the audit log after a run.

---

## Adding more integrations

Each future integration adds a subcommand next to `wp` — e.g.
`reeflex-verify postgres --dsn ...` or `reeflex-verify shell ...` — with its own
scenarios and its own "what should be blocked" table. The point is the same
everywhere: install the gate, run one command, watch it decide.
