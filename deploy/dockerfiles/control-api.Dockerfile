ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

FROM ${PYTHON_IMAGE} AS builder

ENV PATH=/opt/venv/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv

COPY apps/control-api/pyproject.toml apps/control-api/README.md /src/apps/control-api/
COPY apps/control-api/src /src/apps/control-api/src
COPY deploy/constraints/control-api.txt /src/deploy/constraints/control-api.txt
RUN pip install --constraint /src/deploy/constraints/control-api.txt /src/apps/control-api
COPY deploy/scripts/verify-python-constraints.py /src/deploy/scripts/verify-python-constraints.py
RUN python /src/deploy/scripts/verify-python-constraints.py /src/deploy/constraints/control-api.txt


FROM ${PYTHON_IMAGE} AS runtime

ARG CONTROL_RELEASE=0.1.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Sub2API Codex Control API" \
      org.opencontainers.image.version="${CONTROL_RELEASE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="sub2api-codex-control"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONTROL_API_PORT=8090 \
    CONTROL_API_WORKERS=1

RUN groupadd --gid 10001 control \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin control

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY migrations /app/migrations
COPY deploy/scripts/control-api-entrypoint.sh /usr/local/bin/control-api-entrypoint
COPY deploy/scripts/probe-sub2api-auth-contract.py /usr/local/bin/probe-sub2api-auth-contract.py
RUN chmod 0555 \
      /usr/local/bin/control-api-entrypoint \
      /usr/local/bin/probe-sub2api-auth-contract.py \
    && chown -R 10001:10001 /app

USER 10001:10001
EXPOSE 8090

ENTRYPOINT ["/usr/local/bin/control-api-entrypoint"]
CMD ["api"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=4 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/v1/health/live', timeout=2).read()"]
