---
title: "The evidence connector: ship reeflex-core decisions to the Reeflex portal"
description: >-
  Run the published reeflex-evidence-connector image next to reeflex-core so
  every decision reaches app.reeflex.io as signed evidence: configuration,
  what it sends and does not send, and how to verify delivery.
---

# The evidence connector

The connector is a small container that runs **on your infrastructure, next to
your `reeflex-core`**. It tails the engine's append-only audit log
(`decisions.jsonl`), turns each decision into a signed evidence record, and
pushes it to the Reeflex portal (`app.reeflex.io`), where it appears under
**Decisions** and in Attest reports. If you opt in, it also carries held
actions to the portal for a human to approve, and carries that human's answer
back to your engine.

It does not take part in any decision. The engine decides exactly as it does
without it; the connector reports what was decided, after the fact.

```text
ghcr.io/reeflex-io/reeflex-evidence-connector
```

The image is public: `docker pull` needs no login and no credentials from us.
Its source is not public — see [Open core](open-core.md#the-evidence-connector-image).

!!! note "Not the same image as `reeflex-connector`"
    `ghcr.io/reeflex-io/reeflex-connector` is a different program — the
    [LiteLLM guardrail adapter](guides/litellm-docker.md), which lets a stock
    LiteLLM proxy ask reeflex-core for a verdict. The evidence connector on this
    page ships decisions *to the portal*; it is published under its own name so
    neither image's `:latest` can replace the other's.

## Before you start

You need two things the connector cannot make for you:

1. **A `reeflex-core` that writes decisions to a file you can mount.** The
   connector reads that file; it does not call `/v1/decide` and it cannot read
   a log on a host it does not run on. If your agents call an engine somebody
   else operates, that operator runs the connector, not you.
2. **A gate registered in the portal.** Registering one shows three secrets
   **once**: the gate token, the evidence key and the evidence signing key. The
   connector needs the gate token and the evidence signing key. Only hashes are
   stored on our side, so if they are lost, register a new gate and revoke the
   old one.

## Run it

This is the line the portal prints after you register a gate, with that gate's
values filled in. It assumes the engine was started the way the portal shows it
— a container named `reeflex-core` on a Docker network named `reeflex`, writing
its audit log into the `reeflex_core_audit` volume:

```bash
docker run -d --name reeflex-connector --network reeflex \
  -e REEFLEX_CONNECTOR_PORTAL_URL=https://app.reeflex.io \
  -e REEFLEX_CONNECTOR_GATE_TOKEN=rfx_gate_... \
  -e REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY=<64 hex characters> \
  -e REEFLEX_CONNECTOR_AUDIT_JSONL_PATH=/var/log/reeflex-core/decisions.jsonl \
  -e REEFLEX_CONNECTOR_CORE_URL=http://reeflex-core:8080 \
  -e REEFLEX_CONNECTOR_GATE_ID=<the gate's id> \
  -v reeflex_core_audit:/var/log/reeflex-core:ro \
  -v reeflex_connector_state:/var/lib/reeflex-connector \
  ghcr.io/reeflex-io/reeflex-evidence-connector:latest
```

The image runs as an unprivileged user (uid 10001), opens no port, and is built
for `linux/amd64` and `linux/arm64`. `docker run --rm
ghcr.io/reeflex-io/reeflex-evidence-connector:latest --version` prints the
release you have. To pin, use a version tag (`:0.1.0`) or the digest you
pulled:

```bash
docker inspect --format '{{ index .RepoDigests 0 }}' ghcr.io/reeflex-io/reeflex-evidence-connector:latest
```

Each release image carries an SBOM and build provenance as registry
attestations:

```bash
docker buildx imagetools inspect ghcr.io/reeflex-io/reeflex-evidence-connector:latest --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/reeflex-io/reeflex-evidence-connector:latest --format '{{ json .Provenance }}'
```

## Configuration

Every setting is an environment variable with the `REEFLEX_CONNECTOR_` prefix.
A YAML file passed with `-c` works too; the environment wins over it.

| Variable | Required | Default | What it is |
|---|---|---|---|
| `REEFLEX_CONNECTOR_PORTAL_URL` | yes | — | The portal's base URL, e.g. `https://app.reeflex.io` (no path). Evidence goes to `<this>/api/v1/evidence`. |
| `REEFLEX_CONNECTOR_GATE_TOKEN` | yes | — | The gate token (`rfx_gate_…`), sent as a bearer token. Authenticates the gate to the portal. |
| `REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY` | yes | — | The evidence signing key (64 hex characters). Every batch is HMAC-signed with it, so the portal can tell the records were not changed in transit. |
| `REEFLEX_CONNECTOR_AUDIT_JSONL_PATH` | yes | — | Path, **inside the container**, of the engine's `decisions.jsonl`. Mount its directory read-only. |
| `REEFLEX_CONNECTOR_CORE_URL` | for holds | — | Your engine's base URL, as the connector reaches it (e.g. `http://reeflex-core:8080` on a shared Docker network). Used for held actions only — see below. |
| `REEFLEX_CONNECTOR_GATE_ID` | for holds | — | The gate's id, shown in the portal. Holds are switched on only when both this and `CORE_URL` are set. |
| `REEFLEX_CONNECTOR_CORE_TOKEN` | no | — | Bearer for an engine started with `REEFLEX_AUTH_TOKEN`. |
| `REEFLEX_CONNECTOR_RESOLVER_CREDENTIALS` | for holds on core ≥ 0.2.0 | — | `{"<approver>": "<bearer token>"}`, inline JSON or a path to a JSON file. Core 0.2.0 and later refuse an approval that is not made with the approver's own credential. |
| `REEFLEX_CONNECTOR_FLUSH_INTERVAL_S` | no | `5` | Longest wait, in seconds, before buffered records are sent. The log itself is read every second. |
| `REEFLEX_CONNECTOR_FLUSH_COUNT` | no | `100` | Send early once this many records are buffered. |
| `REEFLEX_CONNECTOR_HOLDS_POLL_INTERVAL_S` | no | `30` | How often, in seconds, the connector asks the portal for approvals to carry back to the engine. |
| `REEFLEX_CONNECTOR_STATE_DIR` | no | `/var/lib/reeflex-connector` | Read position, unsent buffer, and records the portal rejected. Keep it on a volume so a restart neither re-sends nor skips. |
| `REEFLEX_CONNECTOR_VERIFY_TLS` | no | `true` | Set `false` only for a self-hosted portal with a self-signed certificate. |

Every secret (`GATE_TOKEN`, `EVIDENCE_SIGNING_KEY`, `CORE_TOKEN`,
`RESOLVER_CREDENTIALS`) can be given as a file instead: set
`REEFLEX_CONNECTOR_GATE_TOKEN_FILE=/run/secrets/gate_token` and mount the file.
None of them is written to the log — the startup line prints each as `set` or
`unset`.

### Held actions (opt-in)

When your engine answers `require_approval`, it raises a hold. With `CORE_URL`
and `GATE_ID` set, the connector pushes that hold to the portal's **Holds**
page, picks up the human's approve or deny, applies it to your engine
(`POST /v1/holds/{id}/resolve`), and reports the engine's answer back to the
portal. Without those two variables the connector still ships evidence — the
held decision shows under **Decisions** — but nothing appears under **Holds**,
so nobody can approve it.

## What it sends, and what it does not

**To the portal**, one record per decision:

- the decision id, the verdict, the rule that fired and the time;
- the action's verb, target environment and target system;
- a count, when the engine recorded one;
- a hash of the action envelope the engine judged;
- the agent id and trace context, when present;
- for a held action, the hold id and, once decided, the outcome and who decided.

A held action pushed to **Holds** also carries the engine's reason text and its
expiry time, so the person approving it can see why it was held.

**Not sent:** the action's payload, tool arguments or content; the ability
name; the session id; anything from your systems other than the engine's own
audit lines. Records are signed per batch with the evidence signing key.

**Connections:** all outbound. To the portal (`/api/v1/evidence`, and with
holds on, `/api/v1/holds`, `/api/v1/holds/resolutions`, `/api/v1/holds/acks`),
and with holds on, to your engine (`GET /v1/holds/{id}`,
`POST /v1/holds/{id}/resolve`). It listens on nothing.

**Delivery:** at least once. Records are buffered on disk before they are sent
and the portal discards duplicates by decision id, so a retry or a restart does
not double-count. A record the portal rejects as malformed is isolated from its
batch and set aside in the state directory (`poison_count` below), so the rest
are delivered and it is not retried forever. A `401` from the portal stops the
connector: the gate token or signing key is wrong or revoked, or this host's
clock is far enough off that the signed timestamp is refused — retrying would
not change any of those.

## Verify delivery

1. Make one decision happen on your engine (the portal's onboarding shows a
   `curl` to `/v1/decide` for this).
2. In the portal, open **Gates**: within a few seconds this gate's
   **Evidence received** count goes from 0 to 1 and **Last seen** updates. The
   decision is listed under **Decisions**.
3. On your side:

    ```bash
    docker exec reeflex-connector python -m reeflex_connector status
    ```

    prints a JSON snapshot. `cursor_offset` grows as the log is read,
    `buffer_depth` returns to 0 once records are accepted, and `poison_count`
    stays 0. The image's `HEALTHCHECK` runs the same command.

Nothing after a minute? `docker logs reeflex-connector`. A `401` usually means
a secret was truncated when it was copied (check the host clock too); register
a new gate for a fresh set if you no longer have the originals.
