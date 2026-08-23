# syntax=docker/dockerfile:1.7

ARG NGINX_BASE=docker.io/library/nginx:1.30.4-alpine@sha256:8a4f4b94275ff59d809477799cbbaf1a7ab65ed1871403d05e31fd66bdb8db82
FROM ${NGINX_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP Gateway" \
      org.opencontainers.image.description="Internal development gateway for the Sec_AI audit service" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="gateway"

COPY deploy/gateway/nginx.conf /etc/nginx/nginx.conf

USER 101:101
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health/live"]

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
