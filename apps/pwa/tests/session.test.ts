import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { resetApiSecurityConfig } from "@/api/client";
import { useSessionStore } from "@/stores/session";
import { MemoryStorage } from "./storage";

function sessionSnapshot(
  id = "session-1",
  reauthAt = "2026-07-13T10:10:00Z",
  expiresAt = "2026-07-13T10:10:00Z",
): Record<string, unknown> {
  return {
    id,
    user: { id: "user-1", username: "alice", email: null, display_name: null },
    issued_at: "2026-07-13T10:00:00Z",
    expires_at: expiresAt,
    reauth_at: reauthAt,
    csrf_header_name: "x-csrf-token",
  };
}

function refreshedSub2ApiAuth(accessToken: string, refreshToken: string): Response {
  return new Response(
    JSON.stringify({
      code: 0,
      message: "success",
      data: {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: 3600,
        token_type: "Bearer",
      },
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

describe("control session exchange", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: new MemoryStorage(),
    });
    document.cookie = "codex_csrf=; Max-Age=0; path=/";
    resetApiSecurityConfig();
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: <T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => callback(),
      },
    });
    vi.restoreAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T10:00:00Z"));
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("uses the CSRF header name returned by the Control API", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: "session-1",
            user: { id: "user-1", username: "alice", email: null, display_name: null },
            issued_at: "2026-07-13T10:00:00Z",
            expires_at: "2026-07-13T10:10:00Z",
            reauth_at: "2026-07-13T10:10:00Z",
            csrf_header_name: "x-control-csrf",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.exchange();
    document.cookie = "codex_csrf=csrf-value; path=/";
    await store.logout();

    const controlCall = (fetchMock.mock.calls as Array<[string, RequestInit]>).find(([url]) =>
      url.includes("/codex-api/v1/session/logout"),
    );
    expect(new Headers(controlCall?.[1].headers).get("x-control-csrf")).toBe("csrf-value");
    vi.unstubAllGlobals();
  });

  it("sends only the Sub2API access token in the strict exchange body", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    window.localStorage.setItem("refresh_token", "refresh-secret");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "session-1",
          user: { id: "user-1", username: "alice", email: null, display_name: null },
          issued_at: "2026-07-13T10:00:00Z",
          expires_at: "2026-07-13T10:10:00Z",
          reauth_at: "2026-07-13T10:10:00Z",
          csrf_header_name: "x-csrf-token",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.exchange();

    expect(store.authenticated).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).get("Authorization")).toBeNull();
    expect(JSON.parse(String(init.body))).toEqual({ access_token: "access-value" });
    expect(JSON.stringify(init)).not.toContain("refresh-secret");
    vi.unstubAllGlobals();
  });

  it("logs out both sessions without sending the refresh token to Control API", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    window.localStorage.setItem("refresh_token", "refresh-secret");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.logout();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const calls = fetchMock.mock.calls as Array<[string, RequestInit]>;
    const controlCall = calls.find(([url]) => url.includes("/codex-api/v1/session/logout"));
    const sub2ApiCall = calls.find(([url]) => url === "/api/v1/auth/logout");
    expect(controlCall).toBeDefined();
    expect(JSON.stringify(controlCall)).not.toContain("refresh-secret");
    expect(JSON.parse(String(sub2ApiCall?.[1].body))).toEqual({ refresh_token: "refresh-secret" });
    expect(window.localStorage.getItem("auth_token")).toBeNull();
    expect(window.localStorage.getItem("refresh_token")).toBeNull();
    vi.unstubAllGlobals();
  });

  it("surfaces Sub2API logout failure after clearing local credentials", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    window.localStorage.setItem("refresh_token", "refresh-secret");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/session/logout")) return Promise.resolve(new Response(null, { status: 204 }));
      if (url === "/api/v1/auth/logout") return Promise.resolve(new Response(null, { status: 503 }));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.logout();

    expect(store.state).toBe("missing_token");
    expect(store.error).toBe("Sub2API 注销失败（HTTP 503）");
    expect(window.localStorage.getItem("auth_token")).toBeNull();
    expect(window.localStorage.getItem("refresh_token")).toBeNull();
  });

  it("does not claim upstream logout succeeded for an access-only login", async () => {
    window.localStorage.setItem("auth_token", "access-only");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/session/logout")) return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.logout();

    expect(store.state).toBe("missing_token");
    expect(store.error).toContain("服务端会话未确认注销");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(window.localStorage.getItem("auth_token")).toBeNull();
  });

  it("does not let a late logout response clear a newer Sub2API login", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let resolveSub2ApiLogout!: (response: Response) => void;
    const pendingSub2ApiLogout = new Promise<Response>((resolve) => {
      resolveSub2ApiLogout = resolve;
    });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/auth/logout") return pendingSub2ApiLogout;
      if (url.includes("/session/logout")) return Promise.resolve(new Response(null, { status: 204 }));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    const loggingOut = store.logout();
    expect(store.state).toBe("missing_token");
    expect(window.localStorage.getItem("auth_token")).toBeNull();

    window.localStorage.setItem("auth_token", "new-access");
    window.localStorage.setItem("refresh_token", "new-refresh");
    resolveSub2ApiLogout(new Response(null, { status: 204 }));
    await loggingOut;

    expect(window.localStorage.getItem("auth_token")).toBe("new-access");
    expect(window.localStorage.getItem("refresh_token")).toBe("new-refresh");
  });

  it("renews before reauthentication, persists rotated tokens, and exchanges only the new access token", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T10:00:00Z"));
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-1", "2026-07-13T10:05:00Z")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(refreshedSub2ApiAuth("new-access", "rotated-refresh"))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-2", "2026-07-13T10:15:00Z")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.exchange();
    await vi.advanceTimersByTimeAsync(269_999);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const calls = fetchMock.mock.calls as Array<[string, RequestInit]>;
    expect(calls[1]?.[0]).toBe("/api/v1/auth/refresh");
    expect(JSON.parse(String(calls[1]?.[1].body))).toEqual({ refresh_token: "old-refresh" });
    expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ access_token: "new-access" });
    expect(JSON.stringify(calls[2]?.[1])).not.toContain("rotated-refresh");
    expect(window.localStorage.getItem("auth_token")).toBe("new-access");
    expect(window.localStorage.getItem("refresh_token")).toBe("rotated-refresh");
    expect(window.localStorage.getItem("token_expires_at")).toBe(String(Date.now() + 3_600_000));
    expect(store.session?.id).toBe("session-2");
    expect(store.renewalRevision).toBe(1);
    store.reset();
  });

  it("deduplicates overlapping renewal requests", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T10:00:00Z"));
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => pendingRefresh)
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-2")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    const first = store.renew();
    const second = store.renew();
    expect(fetchMock).toHaveBeenCalledOnce();

    resolveRefresh(refreshedSub2ApiAuth("new-access", "rotated-refresh"));
    await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    store.reset();
  });

  it("serializes refresh rotation across stores and reuses the winning tab credentials", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let lockTail = Promise.resolve();
    const lockRequest = vi.fn(<T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => {
      const result = lockTail.then(callback);
      lockTail = result.then(() => undefined, () => undefined);
      return result;
    });
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: { request: lockRequest },
    });
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    let refreshCalls = 0;
    let exchangeCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/auth/refresh") {
        refreshCalls += 1;
        return pendingRefresh;
      }
      if (url.endsWith("/session/exchange")) {
        exchangeCalls += 1;
        return Promise.resolve(
          new Response(JSON.stringify(sessionSnapshot(`session-${exchangeCalls}`)), {
            status: 201,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const firstStore = useSessionStore(createPinia());
    const secondStore = useSessionStore(createPinia());

    const first = firstStore.renew();
    const second = secondStore.renew();
    await Promise.resolve();
    expect(refreshCalls).toBe(1);

    resolveRefresh(refreshedSub2ApiAuth("winner-access", "winner-refresh"));

    await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
    expect(refreshCalls).toBe(1);
    expect(exchangeCalls).toBe(2);
    expect(window.localStorage.getItem("auth_token")).toBe("winner-access");
    expect(window.localStorage.getItem("refresh_token")).toBe("winner-refresh");
    firstStore.reset();
    secondStore.reset();
  });

  it("does not let an older terminal refresh response clear credentials replaced by another tab", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/auth/refresh") return pendingRefresh;
      if (url.endsWith("/session/exchange")) {
        expect(JSON.parse(String(init?.body))).toEqual({ access_token: "newer-access" });
        return Promise.resolve(
          new Response(JSON.stringify(sessionSnapshot("newer-session")), {
            status: 201,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const store = useSessionStore();

    const renewal = store.renew();
    window.localStorage.setItem("auth_token", "newer-access");
    window.localStorage.setItem("refresh_token", "newer-refresh");
    window.localStorage.setItem("token_expires_at", String(Date.now() + 3_600_000));
    resolveRefresh(
      new Response(JSON.stringify({ detail: "old refresh token was rotated" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(renewal).resolves.toBe(true);
    expect(window.localStorage.getItem("auth_token")).toBe("newer-access");
    expect(window.localStorage.getItem("refresh_token")).toBe("newer-refresh");
    store.reset();
  });

  it.each([
    ["network", null],
    ["HTTP 429", 429],
    ["HTTP 503", 503],
  ])("keeps an unexpired Control session visible after a retryable manual %s failure", async (_label, status) => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/session/exchange")) {
        return Promise.resolve(
          new Response(
            JSON.stringify(sessionSnapshot("session-1", "2026-07-13T09:59:00Z", "2026-07-13T10:10:00Z")),
            { status: 201, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      if (url === "/api/v1/auth/refresh") {
        return status === null
          ? Promise.reject(new TypeError("offline"))
          : Promise.resolve(new Response(null, { status }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const store = useSessionStore();
    await store.exchange();

    await expect(store.renew()).resolves.toBe(false);

    expect(store.authenticated).toBe(true);
    expect(store.session?.id).toBe("session-1");
    expect(store.error).toBe("会话续期暂时失败，请稍后重试");
    expect(window.localStorage.getItem("refresh_token")).toBe("old-refresh");
    store.reset();
  });

  it("reauthenticates with the current access token before rotating refresh credentials", async () => {
    window.localStorage.setItem("auth_token", "still-valid-access");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-old")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-reauthenticated")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const store = useSessionStore();
    await store.exchange();

    await expect(store.handleAuthenticationFailure()).resolves.toBe(true);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.every(([url]) => String(url).endsWith("/session/exchange"))).toBe(true);
    expect(store.session?.id).toBe("session-reauthenticated");
    expect(store.renewalRevision).toBe(1);
    store.reset();
  });

  it("does not restore rotated tokens when a refresh resolves after logout", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/auth/refresh") return pendingRefresh;
      if (url.includes("/session/logout") || url === "/api/v1/auth/logout") {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    const renewing = store.renew();
    expect(fetchMock).toHaveBeenCalledOnce();

    await store.logout();
    expect(store.state).toBe("missing_token");
    expect(window.localStorage.getItem("auth_token")).toBeNull();
    expect(window.localStorage.getItem("refresh_token")).toBeNull();

    resolveRefresh(refreshedSub2ApiAuth("late-access", "late-refresh"));
    await expect(renewing).resolves.toBe(false);

    expect(window.localStorage.getItem("auth_token")).toBeNull();
    expect(window.localStorage.getItem("refresh_token")).toBeNull();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/session/exchange"))).toBe(false);
  });

  it("expires a scheduled Control session without clearing an access-only Sub2API login", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T10:00:00Z"));
    window.localStorage.setItem("auth_token", "old-access");
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify(sessionSnapshot("session-1", "2026-07-13T10:05:00Z")), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.exchange();
    await vi.advanceTimersByTimeAsync(270_000);

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(store.state).toBe("expired");
    expect(store.session).toBeNull();
    expect(window.localStorage.getItem("auth_token")).toBe("old-access");
  });

  it("expires and clears local auth when Sub2API rejects the refresh token", async () => {
    vi.useFakeTimers();
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "invalid-refresh");
    const fetchMock = vi.fn((_input: RequestInfo | URL) =>
      Promise.resolve(
        new Response(JSON.stringify({ detail: "invalid refresh token" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await expect(store.handleAuthenticationFailure()).resolves.toBe(false);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain("/session/exchange");
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe("/api/v1/auth/refresh");
    expect(store.state).toBe("expired");
    expect(window.localStorage.getItem("auth_token")).toBeNull();
    expect(window.localStorage.getItem("refresh_token")).toBeNull();
  });

  it("recovers initial load from a refresh token when the access token is missing", async () => {
    window.localStorage.setItem("refresh_token", "refresh-only");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: "control session required" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(refreshedSub2ApiAuth("recovered-access", "rotated-refresh"))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(sessionSnapshot("session-recovered")), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.load();

    expect(store.authenticated).toBe(true);
    expect(store.session?.id).toBe("session-recovered");
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const calls = fetchMock.mock.calls as Array<[string, RequestInit]>;
    expect(calls[1]?.[0]).toBe("/api/v1/auth/refresh");
    expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ access_token: "recovered-access" });
  });

  it("cancels scheduled renewal when the session store is reset", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T10:00:00Z"));
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify(sessionSnapshot("session-1", "2026-07-13T10:05:00Z")), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const store = useSessionStore();
    await store.exchange();
    store.reset();
    await vi.advanceTimersByTimeAsync(600_000);

    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
