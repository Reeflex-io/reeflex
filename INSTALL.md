# Reeflex — Installation

> **Variant A — full on-prem.** These instructions cover running the engine on your own machine. A hosted/subscription variant is on the roadmap and not yet available — see [docs/adr/0001-deployment-model.md](docs/adr/0001-deployment-model.md).

This page covers everything you need before running the engine or the demo.
For the end-to-end demo walkthrough, see [QUICKSTART.md](QUICKSTART.md).

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12 | stdlib only — no pip, no virtualenv needed |
| OPA (Open Policy Agent) | 1.18.x | single static binary; see below |

No other runtime dependencies exist. The core server (`reeflex-core/main.py`) and
the demo (`reeflex-mock/demo.py`) both use Python stdlib exclusively.

Or skip local setup entirely with the prebuilt image (see [README](README.md)):
`docker run -d -p 8080:8080 ghcr.io/reeflex-io/reeflex-core:v0.1.2`.

---

## Getting OPA

OPA is a single static binary. Download it, make it executable, and put it on
your `PATH` (or point `REEFLEX_OPA_BIN` at the exact path — see env vars below).

### Windows

Download from:

```
https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe
```

Or from GitHub releases:

```
https://github.com/open-policy-agent/opa/releases
```

Rename the downloaded file to `opa.exe` and place it in any directory that is
on your `PATH`, for example `C:\tools\` (add that folder to the user PATH in
System Properties → Environment Variables).

Verify the install:

```
opa version
```

You should see output containing a line beginning `Version: 1.18.` (the binary prints `Version: 1.18.0`; a compatible later 1.x release is also acceptable).

### Linux

```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/opa
opa version
```

### macOS

```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64
chmod +x opa
sudo mv opa /usr/local/bin/opa
opa version
```

If you cannot install to a system location, place the binary anywhere and set
`REEFLEX_OPA_BIN` to the full path (see env vars below).

---

## Environment variables

For the demo and manual core start, set `REEFLEX_OPA_BIN` to the full absolute
path of the OPA binary you downloaded (e.g. `C:\tools\opa.exe` on Windows,
`/home/user/bin/opa` on Linux) unless `opa` is already on your `PATH`. The
remaining variables are optional and their defaults work for local development
when you run commands from the repo root.

| Variable | Default | What it controls |
|---|---|---|
| `REEFLEX_HOST` | `127.0.0.1` | IP address `reeflex-core` binds to |
| `REEFLEX_PORT` | `8080` | TCP port `reeflex-core` listens on |
| `REEFLEX_OPA_BIN` | `opa` | Full path to the OPA binary, or just `opa` if it is on `PATH` |
| `REEFLEX_POLICY_DIR` | `<repo>/reeflex-core/policy` | Directory containing `reeflex.rego` |
| `REEFLEX_AUDIT_LOG` | `<repo>/reeflex-core/audit/decisions.jsonl` | Path where the append-only JSONL audit log is written |
| `REEFLEX_WINDOW_SECONDS` | `3600` | Rolling window (seconds) for the per-session cumulative action ledger used by fragmentation-resistance rules |
| `REEFLEX_OPA_TIMEOUT` | `10` | Seconds before an OPA subprocess call is killed |

**Note on the demo:** the demo (`reeflex-mock/demo.py`) starts its own
`reeflex-core` subprocess on port **8181** (not 8080) and manages it internally.
You do not set `REEFLEX_PORT` for the demo; `REEFLEX_OPA_BIN` and
`REEFLEX_POLICY_DIR` are the only two variables the demo reads from the
environment.

---

## Installation steps

### 1. Clone the repository

```bash
git clone https://github.com/Reeflex-io/reeflex.git
cd reeflex
```

(If you received the repo as a directory, just `cd` into it.)

### 2. Verify Python

```bash
python --version
# must print Python 3.12.x
```

On some systems the binary is `python3`:

```bash
python3 --version
```

Use whichever form prints `3.12.x`. The commands in this document use `python`;
substitute `python3` if needed on your system.

### 3. Install and verify OPA

Follow the per-OS steps in the "Getting OPA" section above, then:

```bash
opa version
# expected: a line beginning "Version: 1.18." (e.g. "Version: 1.18.0")
```

### 4. Verify the policy directory

The policy directory must contain `reeflex.rego`. Check:

```bash
# Windows
dir reeflex-core\policy\reeflex.rego

# Linux / macOS
ls reeflex-core/policy/reeflex.rego
```

The file must be present. If `REEFLEX_POLICY_DIR` is set to a custom path, the
same check applies there.

### 5. Start reeflex-core and verify the health endpoint

```bash
# Windows (cmd or PowerShell)
set REEFLEX_OPA_BIN=opa
python reeflex-core\main.py

# Linux / macOS
export REEFLEX_OPA_BIN=opa
python reeflex-core/main.py
```

The server prints to stderr:

```
[reeflex-core] listening on http://127.0.0.1:8080/v1/decide
```

In a second terminal, verify the health endpoint:

```bash
# Windows (curl or PowerShell)
curl http://127.0.0.1:8080/healthz

# Linux / macOS
curl http://127.0.0.1:8080/healthz
```

Expected response:

```json
{"status":"ok"}
```

Stop the server with `Ctrl+C` before running the demo (which starts its own
instance on a different port).

---

## Troubleshooting

### `opa` not found — fail-closed deny fires

If `REEFLEX_OPA_BIN` points at a non-existent binary (or `opa` is not on
`PATH`), the core cannot invoke OPA. The decision pipeline is fail-closed: every
request returns HTTP 500 with:

```json
{
  "decision": "deny",
  "rule": "reeflex.core/fail_closed",
  "reason": "policy evaluation unavailable - failing closed"
}
```

If instead the adapter itself cannot reach the core server at all (connection
refused, core not started), the adapter emits its own fallback deny with reason
`"reeflex-core unreachable or error — failing closed: <detail>"`. These are two
distinct fail-closed paths; only the first applies when OPA is misconfigured but
core is running.

**Fix:** Ensure `opa version` succeeds in the same shell, or set
`REEFLEX_OPA_BIN` to the absolute path of the binary.

### Port already in use

If port 8080 (or whichever port you configure) is occupied, the server will fail
to start with a bind error.

```bash
# Windows — find what is using the port
netstat -ano | findstr :8080

# Linux / macOS
lsof -i :8080
```

Either stop the conflicting process or change the port:

```bash
# Windows
set REEFLEX_PORT=8090

# Linux / macOS
export REEFLEX_PORT=8090
```

### Wrong `REEFLEX_POLICY_DIR` — fail-closed deny fires

If `REEFLEX_POLICY_DIR` points at a directory that does not contain
`reeflex.rego`, OPA evaluation will fail for every request. The result is the
same fail-closed deny described above (`rule: reeflex.core/fail_closed`).

**Fix:** Verify the directory contains `reeflex.rego`. The default (no env var
set) resolves to `<repo root>/reeflex-core/policy`, which is correct when you
run from the repo root or pass absolute paths.

### Non-canonical axis values — coercion to most-restrictive

If an adapter sends axis values that are not in the canonical set (e.g.
`"Irreversible"` instead of `"irreversible"`, or a completely unknown string),
the envelope validation layer coerces them to the most-restrictive default:

| Axis | Most-restrictive default |
|---|---|
| `reversibility` | `irreversible` |
| `blast_radius` | `systemic` |
| `externality` | `physical` |

This means a production action with coerced axes is very likely to receive
`deny`. This is intentional. If you are testing and see unexpected denies, check
that your adapter sends lowercase canonical values.

Missing axis values (absent `axes` object) are handled the same way: all three
axes are set to their most-restrictive defaults.

### `GET /healthz` returns no response (core not running)

The demo and any adapter that calls `/v1/decide` require the core server to be
running. The demo starts its own subprocess automatically. If you are running
core manually and `/healthz` does not respond, check that:

1. The `python reeflex-core/main.py` process is still running (not exited with
   an error).
2. You are hitting the correct host and port.
3. No firewall rule is blocking loopback traffic on the chosen port.
