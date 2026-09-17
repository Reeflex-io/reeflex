# reeflex-connector — the Reeflex governance seat as a container.
#
# WHAT THIS IMAGE IS FOR
# ======================
# It serves LiteLLM's Generic Guardrail API, so a customer running the STOCK
# `ghcr.io/berriai/litellm` image can govern tool calls without installing
# anything into their proxy container and without rebuilding it on every
# LiteLLM upgrade:
#
#   guardrails:
#     - guardrail_name: reeflex
#       litellm_params:
#         guardrail: generic_guardrail_api
#         mode: post_call
#         api_base: http://reeflex-connector:8080
#
# The alternative path — `pip install 'reeflex-litellm[proxy]'` INSIDE a derived
# LiteLLM image and a dotted `guardrail:` path — still exists and is documented
# in docs/guides/litellm-docker.md. This image is the one that needs nothing in
# their container.
#
# Build context is `reeflex-litellm/`:
#   docker build -t reeflex-connector:local reeflex-litellm/
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/Reeflex-io/reeflex" \
      org.opencontainers.image.description="Reeflex connector — governs the tool calls an LLM gateway returns (LiteLLM Generic Guardrail API)" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# The package and its ONE runtime dependency (reeflex-claude, for the
# classifier and the envelope builder). litellm is NOT installed: this process
# is not a proxy and does not import it — which is the whole point of serving
# the guardrail over HTTP instead of loading it into theirs.
COPY . /app/
RUN pip install --no-cache-dir . \
    && rm -rf /root/.cache/pip

# Non-root, uid 10001, matching reeflex-core's image. The ledger directory is
# writable by that user; a deployment that wants the ledger to survive a
# recreate mounts a volume over it (see the guide — an unmounted ledger is
# discarded with the container).
RUN useradd --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin reeflex \
    && mkdir -p /app/ledger \
    && chown -R reeflex:reeflex /app

# Must bind 0.0.0.0, not 127.0.0.1: the port is reached from another container.
# REEFLEX_CONNECTOR_TOKEN is deliberately NOT given a default — the entrypoint
# refuses to start without it (or an explicit REEFLEX_CONNECTOR_ALLOW_ANONYMOUS)
# because anything that can reach this port can propose actions for any org in
# the tenancy map.
ENV REEFLEX_CONNECTOR_HOST=0.0.0.0 \
    REEFLEX_CONNECTOR_PORT=8080 \
    REEFLEX_LITELLM_LEDGER_PATH=/app/ledger/decisions.jsonl \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Liveness via the stdlib (the slim image has no curl/wget). /healthz answers
# without a token on purpose, so this check needs no secret.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)" || exit 1

USER reeflex

CMD ["reeflex-connector"]
