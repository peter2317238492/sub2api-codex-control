import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  registerCodexServiceWorker,
  SERVICE_WORKER_SCOPE,
  SERVICE_WORKER_URL,
} from "@/service-worker";
import workerSource from "../public/sw.js?raw";

const ORIGIN = "https://example.test";

type WorkerHandler = (event: Record<string, unknown>) => void;

interface WorkerHarness {
  handlers: Map<string, WorkerHandler>;
  scope: {
    clients: { claim: ReturnType<typeof vi.fn> };
    skipWaiting: ReturnType<typeof vi.fn>;
  };
}

function loadWorker(cacheStorage: object, fetcher: ReturnType<typeof vi.fn> = vi.fn()): WorkerHarness {
  const handlers = new Map<string, WorkerHandler>();
  const scope = {
    addEventListener: vi.fn((type: string, handler: WorkerHandler) => handlers.set(type, handler)),
    clients: { claim: vi.fn().mockResolvedValue(undefined) },
    location: { origin: ORIGIN },
    skipWaiting: vi.fn().mockResolvedValue(undefined),
  };
  new Function("self", "caches", "fetch", "URL", "Response", workerSource)(
    scope,
    cacheStorage,
    fetcher,
    URL,
    Response,
  );
  return { handlers, scope };
}

function lifetimeEvent(extra: Record<string, unknown> = {}): {
  event: Record<string, unknown>;
  lifetime: () => Promise<unknown>;
} {
  let promise: Promise<unknown> | null = null;
  return {
    event: {
      ...extra,
      waitUntil(value: Promise<unknown>) {
        promise = value;
      },
    },
    lifetime: () => {
      if (!promise) throw new Error("event.waitUntil was not called");
      return promise;
    },
  };
}

describe("Codex Control service worker", () => {
  it("pre-caches the complete shell and waits before skipping installation", async () => {
    let finishPrecache!: () => void;
    const precache = new Promise<void>((resolve) => {
      finishPrecache = resolve;
    });
    const cache = { addAll: vi.fn(() => precache) };
    const cacheStorage = { open: vi.fn().mockResolvedValue(cache) };
    const { handlers, scope } = loadWorker(cacheStorage);
    const install = lifetimeEvent();

    handlers.get("install")?.(install.event);
    await Promise.resolve();
    expect(cache.addAll).toHaveBeenCalledWith([
      "/codex/",
      "/codex/manifest.webmanifest",
      "/codex/icon.svg",
      "/codex/icon-192.png",
      "/codex/icon-512.png",
    ]);
    expect(scope.skipWaiting).not.toHaveBeenCalled();

    finishPrecache();
    await install.lifetime();
    expect(scope.skipWaiting).toHaveBeenCalledOnce();
  });

  it("deletes only stale Codex caches and claims clients after cleanup", async () => {
    let finishDelete!: () => void;
    const deletion = new Promise<boolean>((resolve) => {
      finishDelete = () => resolve(true);
    });
    const cacheStorage = {
      keys: vi.fn().mockResolvedValue(["sub2api-shell-v4", "codex-control-v4", "codex-control-v5"]),
      delete: vi.fn(() => deletion),
    };
    const { handlers, scope } = loadWorker(cacheStorage);
    const activation = lifetimeEvent();

    handlers.get("activate")?.(activation.event);
    await Promise.resolve();
    expect(cacheStorage.delete).toHaveBeenCalledWith("codex-control-v4");
    expect(scope.clients.claim).not.toHaveBeenCalled();

    finishDelete();
    await activation.lifetime();
    expect(cacheStorage.delete).toHaveBeenCalledTimes(1);
    expect(scope.clients.claim).toHaveBeenCalledOnce();
  });

  it("filters and deduplicates CACHE_URLS before pruning stale build assets", async () => {
    const cachedRequests = [
      new Request(`${ORIGIN}/codex/assets/current.js`),
      new Request(`${ORIGIN}/codex/assets/stale.js`),
      new Request(`${ORIGIN}/codex/icon.svg`),
    ];
    const cache = {
      addAll: vi.fn().mockResolvedValue(undefined),
      keys: vi.fn().mockResolvedValue(cachedRequests),
      delete: vi.fn().mockResolvedValue(true),
    };
    const cacheStorage = { open: vi.fn().mockResolvedValue(cache) };
    const { handlers } = loadWorker(cacheStorage);
    const message = lifetimeEvent({
      data: {
        type: "CACHE_URLS",
        urls: [
          `${ORIGIN}/codex/assets/current.js?access_token=must-not-persist#fragment`,
          `${ORIGIN}/codex/assets/current.js`,
          "/codex/manifest.webmanifest",
          "/codex/thread/not-a-build-asset",
          "https://other.test/codex/assets/foreign.js",
          "http://[malformed",
          42,
        ],
      },
    });

    handlers.get("message")?.(message.event);
    await message.lifetime();

    expect(cache.addAll).toHaveBeenCalledWith([
      `${ORIGIN}/codex/assets/current.js`,
      `${ORIGIN}/codex/manifest.webmanifest`,
    ]);
    expect(cache.delete).toHaveBeenCalledTimes(1);
    expect(cache.delete).toHaveBeenCalledWith(cachedRequests[1]);
  });

  it.each([
    ["Control API", { url: `${ORIGIN}/codex-api/v1/devices`, method: "GET", mode: "cors" }],
    ["Sub2API", { url: `${ORIGIN}/api/v1/auth/refresh`, method: "GET", mode: "cors" }],
    ["cross-origin", { url: "https://other.test/codex/assets/app.js", method: "GET", mode: "cors" }],
    ["non-GET", { url: `${ORIGIN}/codex/assets/app.js`, method: "POST", mode: "cors" }],
  ])("does not intercept %s requests", (_label, request) => {
    const fetcher = vi.fn();
    const { handlers } = loadWorker({}, fetcher);
    const respondWith = vi.fn();
    const waitUntil = vi.fn();

    handlers.get("fetch")?.({ request, respondWith, waitUntil });

    expect(respondWith).not.toHaveBeenCalled();
    expect(waitUntil).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("keeps an asset cache write alive with fetch-event waitUntil", async () => {
    let finishPut!: () => void;
    const pendingPut = new Promise<void>((resolve) => {
      finishPut = resolve;
    });
    const cache = { put: vi.fn(() => pendingPut), match: vi.fn() };
    const cacheStorage = { open: vi.fn().mockResolvedValue(cache) };
    const networkResponse = new Response("asset", { status: 200 });
    const fetcher = vi.fn().mockResolvedValue(networkResponse);
    const { handlers } = loadWorker(cacheStorage, fetcher);
    const request = new Request(`${ORIGIN}/codex/assets/app.js?access_token=must-not-persist`);
    const fetchEvent = lifetimeEvent({ request });
    let responsePromise: Promise<Response> | null = null;
    fetchEvent.event.respondWith = (value: Promise<Response>) => {
      responsePromise = value;
    };

    handlers.get("fetch")?.(fetchEvent.event);
    expect(responsePromise).not.toBeNull();
    await responsePromise;
    expect(cache.put).toHaveBeenCalledWith(`${ORIGIN}/codex/assets/app.js`, expect.any(Response));

    let lifetimeSettled = false;
    void fetchEvent.lifetime().then(() => {
      lifetimeSettled = true;
    });
    await Promise.resolve();
    expect(lifetimeSettled).toBe(false);
    finishPut();
    await fetchEvent.lifetime();
    expect(lifetimeSettled).toBe(true);
  });

  it("serves exact cached resources and the shell for offline navigation from only the current cache", async () => {
    const cachedAsset = new Response("cached asset");
    const shell = new Response("offline shell", { headers: { "Content-Type": "text/html" } });
    const cache = {
      put: vi.fn(),
      match: vi.fn((request: Request | string) => {
        const value = typeof request === "string" ? request : request.url;
        if (value === `${ORIGIN}/codex/assets/cached.js`) return Promise.resolve(cachedAsset);
        if (value === "/codex/") return Promise.resolve(shell);
        return Promise.resolve(undefined);
      }),
    };
    const cacheStorage = {
      open: vi.fn().mockResolvedValue(cache),
      match: vi.fn(() => Promise.resolve(new Response("foreign cache"))),
    };
    const fetcher = vi.fn().mockRejectedValue(new TypeError("offline"));
    const { handlers } = loadWorker(cacheStorage, fetcher);

    async function dispatch(request: Record<string, unknown>): Promise<Response> {
      const event = lifetimeEvent({ request });
      let responsePromise: Promise<Response> | null = null;
      event.event.respondWith = (value: Promise<Response>) => {
        responsePromise = value;
      };
      handlers.get("fetch")?.(event.event);
      if (!responsePromise) throw new Error("fetch was not intercepted");
      const response = await responsePromise;
      await event.lifetime();
      return response;
    }

    expect(
      await (
        await dispatch({
          url: `${ORIGIN}/codex/assets/cached.js?access_token=must-not-persist`,
          method: "GET",
          mode: "cors",
        })
      ).text(),
    ).toBe("cached asset");
    expect(
      await (
        await dispatch({ url: `${ORIGIN}/codex/threads/deep-link`, method: "GET", mode: "navigate" })
      ).text(),
    ).toBe("offline shell");
    const miss = await dispatch({ url: `${ORIGIN}/codex/assets/missing.js`, method: "GET", mode: "cors" });
    expect(miss.type).toBe("error");
    expect(cacheStorage.match).not.toHaveBeenCalled();
  });
});

describe("service worker registration", () => {
  it("registers under /codex and sends the current build to every worker generation", async () => {
    const listeners = new Map<string, () => void>();
    const worker = () => ({
      postMessage: vi.fn(),
      addEventListener: vi.fn(),
    });
    const installing = worker();
    const waiting = worker();
    const oldActive = worker();
    const newActive = worker();
    const controller = worker();
    const registration = {
      installing,
      waiting,
      active: oldActive,
      addEventListener: vi.fn((type: string, listener: () => void) => listeners.set(type, listener)),
    };
    const readyRegistration = { installing: null, waiting: null, active: newActive };
    const containerListeners = new Map<string, () => void>();
    const container = {
      controller,
      register: vi.fn().mockResolvedValue(registration),
      ready: Promise.resolve(readyRegistration),
      addEventListener: vi.fn((type: string, listener: () => void) => containerListeners.set(type, listener)),
    };
    const sourceDocument = {
      scripts: [{ src: `${ORIGIN}/codex/assets/app.js` }],
      querySelectorAll: vi.fn(() => [{ href: `${ORIGIN}/codex/manifest.webmanifest` }]),
    } as unknown as Document;

    await registerCodexServiceWorker(
      container as unknown as ServiceWorkerContainer,
      sourceDocument,
      `${ORIGIN}/codex/?access_token=must-not-persist#fragment`,
    );

    expect(SERVICE_WORKER_URL).toBe("/codex/sw.js");
    expect(SERVICE_WORKER_SCOPE).toBe("/codex/");
    expect(container.register).toHaveBeenCalledWith("/codex/sw.js", { scope: "/codex/" });
    for (const candidate of [installing, waiting, oldActive, newActive, controller]) {
      expect(candidate.postMessage).toHaveBeenCalledWith(
        {
          type: "CACHE_URLS",
          urls: [
            `${ORIGIN}/codex/assets/app.js`,
            `${ORIGIN}/codex/manifest.webmanifest`,
            `${ORIGIN}/codex/`,
          ],
        },
      );
    }

    const updateWorker = worker();
    registration.installing = updateWorker;
    listeners.get("updatefound")?.();
    expect(updateWorker.postMessage).toHaveBeenCalledOnce();

    container.controller = updateWorker;
    containerListeners.get("controllerchange")?.();
    expect(updateWorker.postMessage).toHaveBeenCalledTimes(3);
  });
});
