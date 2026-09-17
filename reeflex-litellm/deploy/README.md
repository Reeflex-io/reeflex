# Deploying the Reeflex seat in front of a LiteLLM proxy running in Docker

Two paths, both walked end to end on the stock `ghcr.io/berriai/litellm:v1.101.0`
image on 2026-09-17. The full guide — with the scoping matrix, the measured
hold behaviour, the streaming limit and the latency numbers — is
[`docs/guides/litellm-docker.md`](../../docs/guides/litellm-docker.md).

| file | path |
|---|---|
| `docker-compose.connector.yml` + `config-connector.yaml` | **nothing in your image**: the stock proxy plus a `reeflex-connector` container answering LiteLLM's Generic Guardrail API |
| `docker-compose.in-image.yml` + `config-in-image.yaml` + `Dockerfile.litellm` | **inside your image**: a derived proxy image with the guardrail installed in-process |
| `tenancy.example.json` | the org binding both paths need; there is no default org |
| `.env.example` | the four values both compose files read, by reference |

```console
$ cp .env.example .env && $EDITOR .env
$ cp tenancy.example.json tenancy.json && $EDITOR tenancy.json
$ docker compose -f docker-compose.connector.yml up -d
```

Both compose files read `./tenancy.json`, and neither ships one: there is no
default org, so a map you have not edited is a map that binds none of your
keys and refuses every tool call. That is the intended failure — it is louder
than filing one department's actions under another's evidence.
