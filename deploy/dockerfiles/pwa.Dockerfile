ARG NODE_IMAGE=node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
ARG NGINX_IMAGE=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236

FROM ${NODE_IMAGE} AS builder

ARG VITE_CONTROL_CSRF_COOKIE_NAME=codex_csrf
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    VITE_CONTROL_CSRF_COOKIE_NAME=${VITE_CONTROL_CSRF_COOKIE_NAME}

WORKDIR /workspace
RUN corepack enable \
    && corepack prepare pnpm@11.7.0+sha512.19cc852c120c7125760f2443ee6be0ca5b40f9f50598de1a09a1f177503e010e57c23c77646e01e761de59bf874fb22a3398c33ab9691fc13eb946b6f0f4d620 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/pwa/package.json apps/pwa/package.json
COPY packages/control-protocol/package.json packages/control-protocol/package.json
COPY packages/appserver-schema/package.json packages/appserver-schema/package.json
RUN pnpm install --frozen-lockfile --filter @sub2api-codex/pwa...

COPY apps/pwa apps/pwa
COPY packages/control-protocol packages/control-protocol
COPY docs/contracts/sub2api-auth.v0.1.175.json docs/contracts/sub2api-auth.v0.1.175.json
RUN pnpm --filter @sub2api-codex/pwa build


FROM ${NGINX_IMAGE} AS runtime

ARG CONTROL_RELEASE=0.1.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Sub2API Codex Control PWA" \
      org.opencontainers.image.version="${CONTROL_RELEASE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="sub2api-codex-control"

COPY --chmod=0444 deploy/nginx/pwa-nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /workspace/apps/pwa/dist/ /usr/share/nginx/html/codex/
RUN chown -R nginx:nginx /usr/share/nginx/html/codex

USER nginx
EXPOSE 8080
ENTRYPOINT ["nginx", "-g", "daemon off;"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
