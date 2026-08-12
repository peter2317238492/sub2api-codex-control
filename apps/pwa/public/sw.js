const CACHE_PREFIX = "codex-control-";
const CACHE = `${CACHE_PREFIX}v5`;
const SHELL = [
  "/codex/",
  "/codex/manifest.webmanifest",
  "/codex/icon.svg",
  "/codex/icon-192.png",
  "/codex/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE).map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type !== "CACHE_URLS" || !Array.isArray(event.data.urls)) return;
  const urls = event.data.urls.flatMap((value) => {
    if (typeof value !== "string") return [];
    try {
      const url = new URL(value, self.location.origin);
      const allowed =
        url.origin === self.location.origin &&
        (url.pathname.startsWith("/codex/assets/") || SHELL.includes(url.pathname));
      return allowed ? [`${url.origin}${url.pathname}`] : [];
    } catch {
      return [];
    }
  });
  event.waitUntil(
    caches.open(CACHE).then(async (cache) => {
      const currentUrls = [...new Set(urls)];
      await cache.addAll(currentUrls);
      const retained = new Set([...SHELL, ...currentUrls].map((value) => new URL(value, self.location.origin).href));
      const cachedRequests = await cache.keys();
      await Promise.all(
        cachedRequests.map((request) => {
          const url = new URL(request.url);
          if (url.pathname.startsWith("/codex/assets/") && !retained.has(request.url)) {
            return cache.delete(request);
          }
          return Promise.resolve(false);
        }),
      );
    }),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith("/codex/")) return;

  const cacheKey = `${url.origin}${url.pathname}`;
  const network = fetch(request);
  const cacheUpdate = network
    .then(async (response) => {
      if (response.ok && url.pathname.startsWith("/codex/assets/")) {
        const cache = await caches.open(CACHE);
        await cache.put(cacheKey, response.clone());
      }
    })
    .catch(() => undefined);
  event.waitUntil(cacheUpdate);
  event.respondWith(
    network.catch(async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(cacheKey);
      if (cached) return cached;
      if (request.mode === "navigate") return (await cache.match("/codex/")) ?? Response.error();
      return Response.error();
    }),
  );
});
