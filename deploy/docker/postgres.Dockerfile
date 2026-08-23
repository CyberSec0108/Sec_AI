# syntax=docker/dockerfile:1.7
ARG POSTGRES_BASE=docker.io/pgvector/pgvector:0.8.2-pg18-bookworm@sha256:2ac2c62ac8f030b414b19ea633a6d1d4d37c03abe52ce91887a4e5b4fbb5c73c
FROM ${POSTGRES_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP PostgreSQL + pgvector" \
      org.opencontainers.image.description="Sec_AI PostgreSQL 18.4 runtime with pgvector 0.8.2 for rebuildable guide search projections" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="postgres" \
      io.sec-ai-mvp.upstream.repository="docker.io/pgvector/pgvector" \
      io.sec-ai-mvp.upstream.version="0.8.2-pg18-bookworm" \
      io.sec-ai-mvp.upstream.digest="sha256:2ac2c62ac8f030b414b19ea633a6d1d4d37c03abe52ce91887a4e5b4fbb5c73c" \
      io.sec-ai-mvp.postgresql.version="18.4" \
      io.sec-ai-mvp.pgvector.version="0.8.2"
