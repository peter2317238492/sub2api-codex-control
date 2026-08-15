FROM python:3.9.23-alpine3.22@sha256:7840735992b585fc50444ff15ad60bf9b6c5868d45ebf522a9b99b754dea308a

ARG CONTROL_MONITORING_HELPER_SOURCE_SHA256

LABEL org.opencontainers.image.title="codex-control-monitoring-helper" \
      org.opencontainers.image.base.name="python:3.9.23-alpine3.22" \
      org.opencontainers.image.base.digest="sha256:7840735992b585fc50444ff15ad60bf9b6c5868d45ebf522a9b99b754dea308a" \
      org.opencontainers.image.source-closure-sha256="${CONTROL_MONITORING_HELPER_SOURCE_SHA256}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --chmod=0555 collector/collector.py /opt/monitoring/collector.py
COPY --chmod=0555 evidence-receiver/receiver.py /opt/monitoring/receiver.py
COPY --chmod=0444 common.py /opt/monitoring/common.py
COPY --chmod=0555 alertmanager-proxy.py /opt/monitoring/alertmanager-proxy.py
COPY --chmod=0555 observability-admission.py /opt/monitoring/observability-admission.py
COPY --chmod=0555 external-delivery-relay.py /opt/monitoring/external-delivery-relay.py
COPY --chmod=0444 schemas/external-operator-delivery-receipt.schema.json /opt/monitoring/schemas/external-operator-delivery-receipt.schema.json
COPY --chmod=0444 schemas/release-observability-receipt.schema.json /opt/monitoring/schemas/release-observability-receipt.schema.json

USER 65532:65532
WORKDIR /opt/monitoring
