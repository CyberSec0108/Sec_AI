# syntax=docker/dockerfile:1.7
ARG PGADMIN_BASE=docker.io/dpage/pgadmin4:9.16@sha256:66a300a7ecdcc1f325af0c430315329bca46cd4a7067227d6899802238167c6e
FROM ${PGADMIN_BASE}

USER root

COPY requirements/lock/pgadmin-security.lock /tmp/pgadmin-security.lock
COPY deploy/patches/cpython-3.14-CVE-2026-15308.patch /tmp/cpython-3.14-CVE-2026-15308.patch
RUN apk add --no-cache \
      "c-ares=1.34.8-r0" \
      "libcurl=8.21.0-r0" \
    && apk add --no-cache --virtual .pgadmin-build-deps patch \
    && patch --batch --forward -p2 \
      -d /usr/local/lib/python3.14 \
      < /tmp/cpython-3.14-CVE-2026-15308.patch \
    && /venv/bin/python -m pip install \
      --require-hashes \
      --no-deps \
      --no-cache-dir \
      -r /tmp/pgadmin-security.lock \
    && apk del .pgadmin-build-deps \
    && rm -f \
      /tmp/pgadmin-security.lock \
      /tmp/cpython-3.14-CVE-2026-15308.patch

COPY --chown=5050:5050 deploy/pgadmin/servers.json /pgadmin4/servers.json

USER 5050

LABEL org.opencontainers.image.title="Sec_AI MVP pgAdmin" \
      org.opencontainers.image.description="Local administrator UI for the Sec_AI PostgreSQL and pgvector store" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="pgadmin" \
      io.sec-ai-mvp.upstream.repository="docker.io/dpage/pgadmin4" \
      io.sec-ai-mvp.upstream.version="9.16" \
      io.sec-ai-mvp.upstream.digest="sha256:66a300a7ecdcc1f325af0c430315329bca46cd4a7067227d6899802238167c6e" \
      io.sec-ai-mvp.security.cve-2026-15308.patch="python/cpython@07efb08123ba9367a7107325adb9d5626dca1ca9"
