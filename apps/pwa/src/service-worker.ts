export const SERVICE_WORKER_SCOPE = import.meta.env.BASE_URL;
export const SERVICE_WORKER_URL = `${SERVICE_WORKER_SCOPE}sw.js`;

function canonicalCacheUrl(value: string, baseUrl: string): string {
  try {
    const url = new URL(value, baseUrl);
    return `${url.origin}${url.pathname}`;
  } catch {
    return "";
  }
}

function cacheUrls(sourceDocument: Document, pageUrl: string): string[] {
  return [
    ...Array.from(sourceDocument.scripts, (script) => script.src),
    ...Array.from(sourceDocument.querySelectorAll<HTMLLinkElement>("link[href]"), (link) => link.href),
    pageUrl,
  ]
    .map((value) => canonicalCacheUrl(value, pageUrl))
    .filter(Boolean);
}

export async function registerCodexServiceWorker(
  container: ServiceWorkerContainer = navigator.serviceWorker,
  sourceDocument: Document = document,
  pageUrl: string = window.location.href,
): Promise<ServiceWorkerRegistration> {
  const registration = await container.register(SERVICE_WORKER_URL, { scope: SERVICE_WORKER_SCOPE });
  const urls = cacheUrls(sourceDocument, pageUrl);
  const tracked = new WeakSet<ServiceWorker>();

  const send = (worker: ServiceWorker | null): void => {
    if (!worker) return;
    worker.postMessage({ type: "CACHE_URLS", urls });
    if (tracked.has(worker)) return;
    tracked.add(worker);
    worker.addEventListener("statechange", () => worker.postMessage({ type: "CACHE_URLS", urls }));
  };
  const sendToRegistration = (candidate: ServiceWorkerRegistration): void => {
    send(candidate.installing);
    send(candidate.waiting);
    send(candidate.active);
  };

  sendToRegistration(registration);
  registration.addEventListener("updatefound", () => send(registration.installing));

  const readyRegistration = await container.ready;
  sendToRegistration(readyRegistration);
  send(container.controller);
  container.addEventListener("controllerchange", () => {
    sendToRegistration(registration);
    send(container.controller);
  });
  return registration;
}
