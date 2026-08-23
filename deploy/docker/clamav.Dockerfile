# syntax=docker/dockerfile:1.7

ARG CLAMAV_BASE=docker.io/clamav/clamav:1.4.5@sha256:48eaad9644475c2d466ce6d4ba2da892dbd4dcd47713201d31b665364655cc3c
FROM ${CLAMAV_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP ClamAV" \
      org.opencontainers.image.description="Non-root ClamAV daemon with locked signatures for Sec_AI development" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="clamav"

USER 100:101
EXPOSE 3310

ENTRYPOINT ["clamd"]
CMD ["--foreground"]
