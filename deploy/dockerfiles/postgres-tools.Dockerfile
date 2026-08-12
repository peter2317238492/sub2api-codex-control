ARG POSTGRES_IMAGE=postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
FROM ${POSTGRES_IMAGE}

ARG CONTROL_RELEASE=0.1.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Sub2API Codex PostgreSQL Tools" \
      org.opencontainers.image.version="${CONTROL_RELEASE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="sub2api-codex-control"

COPY deploy/scripts/backup-control-db.sh /usr/local/bin/backup-control-db
RUN chmod 0555 /usr/local/bin/backup-control-db

USER postgres
ENTRYPOINT ["/usr/local/bin/backup-control-db"]
