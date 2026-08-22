# reeflex-core — deterministic decision engine (v0.1)
# Python 3.12-slim with the OPA 1.18 binary baked INTO the image (no host dependency).
FROM python:3.12-slim

ARG OPA_VERSION=1.18.0

# OCI metadata — associates this image with its source repo (GHCR auto-links via image.source).
LABEL org.opencontainers.image.source="https://github.com/Reeflex-io/reeflex" \
      org.opencontainers.image.description="Reeflex — deterministic governance engine (reeflex-core)" \
      org.opencontainers.image.licenses="Apache-2.0"

# Bake the OPA binary into the image (linux static build). Self-contained: the
# container does not depend on an OPA install on the host.
ADD https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod +x /usr/local/bin/opa && /usr/local/bin/opa version

WORKDIR /app

# reeflex-core is pure Python stdlib — no pip dependencies to install.
COPY reeflex-core/ /app/

# --- non-root hardening: run as an unprivileged system user (uid 10001) ---
# Files are COPYed as root; chown the app tree so the audit log dir is writable
# by the unprivileged user. Port 8080 (>1024) binds without root privilege.
RUN useradd --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin reeflex \
    && mkdir -p /app/audit \
    && chown -R reeflex:reeflex /app

# Container must bind 0.0.0.0 (not 127.0.0.1) so the published port is reachable.
#
# REEFLEX_REQUIRE_VERIFIED_APPROVER=true is the SHIPPED DEFAULT (0.2.0, RFX-84).
# An approver this core cannot tie to the credential that resolved the hold is
# refused (403 principal_not_verified) rather than recorded as a human who
# exercised oversight. Stated here as well as in the code default so it is
# visible in `docker inspect` and overridable per deployment with `-e`:
#
#   -e REEFLEX_RESOLVER_TOKENS='{"tok":{"type":"human","id":"alice@example.com"}}'
#       the fix: bind each approver's bearer token to the principal it IS.
#   -e REEFLEX_REQUIRE_VERIFIED_APPROVER=false
#       the escape hatch: pre-0.2.0 behaviour, holds resolve on a self-asserted
#       approver and the record says decided_by_verified=false.
#
# See CHANGELOG 0.2.0 and docs/reference/configuration.md.
ENV REEFLEX_HOST=0.0.0.0 \
    REEFLEX_PORT=8080 \
    REEFLEX_OPA_BIN=/usr/local/bin/opa \
    REEFLEX_POLICY_DIR=/app/policy \
    REEFLEX_AUDIT_LOG=/app/audit/decisions.jsonl \
    REEFLEX_REQUIRE_VERIFIED_APPROVER=true \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Liveness via the stdlib (slim image has no curl/wget).
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else 1)" || exit 1

# Drop privileges: the service runs as the unprivileged 'reeflex' user.
USER reeflex

CMD ["python", "main.py"]
