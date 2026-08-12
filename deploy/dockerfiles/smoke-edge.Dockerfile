ARG NGINX_IMAGE=nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
FROM ${NGINX_IMAGE}

RUN install -d -m 0755 /etc/nginx/codex /var/log/sub2api-codex-control \
    && ln -s /dev/stdout /var/log/sub2api-codex-control/nginx-access.log
COPY --chmod=0444 deploy/nginx/smoke-edge-nginx.conf /etc/nginx/nginx.conf
COPY --chmod=0444 deploy/nginx/server-locations.conf /etc/nginx/codex/server-locations.conf
COPY --chmod=0444 deploy/nginx/sub2api-logout-location.conf /etc/nginx/codex/sub2api-logout-location.conf
COPY --chmod=0444 deploy/nginx/browser-security-headers.conf /etc/nginx/codex/browser-security-headers.conf
COPY --chmod=0444 deploy/nginx/api-security-headers.conf /etc/nginx/codex/api-security-headers.conf
COPY --chmod=0444 deploy/nginx/hide-upstream-security-headers.conf /etc/nginx/codex/hide-upstream-security-headers.conf

USER nginx
EXPOSE 8080
ENTRYPOINT ["nginx", "-g", "daemon off;"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/codex/"]
