import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { logoutSub2Api, refreshAndPersistSub2ApiAuth, Sub2ApiRefreshError } from "@/api/sub2api";
import { readSub2ApiAccessToken } from "@/api/token";
import { useSessionStore } from "@/stores/session";
import contract from "../../../docs/contracts/sub2api-auth.v0.1.176.json";
import { MemoryStorage } from "./storage";

class SharedMemoryStorage implements Storage {
  constructor(private readonly values: Map<string, string>) {}

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function rotatedAuthResponse(accessToken = "new-access", refreshToken = "new-refresh"): Response {
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

function controlSession(): Response {
  return new Response(
    JSON.stringify({
      id: "session-contract",
      user: { id: "user-1", username: "alice", email: null, display_name: null },
      issued_at: "2026-07-13T10:00:00Z",
      expires_at: "2026-07-13T10:10:00Z",
      reauth_at: "2026-07-13T10:05:00Z",
      csrf_header_name: "x-csrf-token",
    }),
    { status: 201, headers: { "Content-Type": "application/json" } },
  );
}

describe(`frozen Sub2API ${contract.runtime.version} browser contract`, () => {
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
    setActivePinia(createPinia());
    Object.defineProperty(window, "localStorage", { configurable: true, value: storage });
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: <T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => callback(),
      },
    });
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("uses the frozen storage keys and refresh rotation request/response fields", async () => {
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "old-refresh");
    const responseData = Object.fromEntries(
      contract.endpoints.refresh.response_envelope.data_required.map((field) => {
        if (field === "access_token") return [field, "new-access"];
        if (field === "refresh_token") return [field, "new-refresh"];
        if (field === "expires_in") return [field, 3600];
        return [field, contract.endpoints.refresh.token_type];
      }),
    );
    const responseBody = {
      code: contract.endpoints.refresh.response_envelope.code,
      message: contract.endpoints.refresh.response_envelope.message,
      data: responseData,
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const refreshed = await refreshAndPersistSub2ApiAuth(storage);

    expect(refreshed?.accessToken).toBe("new-access");
    expect(readSub2ApiAccessToken(storage)).toBe("new-access");
    expect(storage.getItem(contract.local_storage.refresh_token)).toBe("new-refresh");
    expect(Number(storage.getItem(contract.local_storage.expires_at))).toBeGreaterThan(Date.now());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(contract.endpoints.refresh.path);
    expect(init.method).toBe(contract.endpoints.refresh.method);
    expect(Object.keys(JSON.parse(String(init.body)))).toEqual(contract.endpoints.refresh.request_required);
    expect(JSON.parse(String(init.body))).toEqual({ refresh_token: "old-refresh" });
  });

  it.each([
    {
      label: "legacy flat payload",
      body: { access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600, token_type: "Bearer" },
    },
    {
      label: "non-success code",
      body: {
        code: 1,
        message: "success",
        data: { access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600, token_type: "Bearer" },
      },
    },
    {
      label: "wrong success message",
      body: {
        code: 0,
        message: "ok",
        data: { access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600, token_type: "Bearer" },
      },
    },
    {
      label: "unexpected envelope field",
      body: {
        code: 0,
        message: "success",
        data: { access_token: "new-access", refresh_token: "new-refresh", expires_in: 3600, token_type: "Bearer" },
        metadata: {},
      },
    },
  ])("fails closed on $label without replacing browser credentials", async ({ body }) => {
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "old-refresh");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(refreshAndPersistSub2ApiAuth(storage)).rejects.toMatchObject({
      retryable: true,
      credentialRejected: false,
    });
    expect(storage.getItem(contract.local_storage.access_token)).toBe("old-access");
    expect(storage.getItem(contract.local_storage.refresh_token)).toBe("old-refresh");
  });

  it("uses the frozen logout endpoint without sending refresh credentials to Control API", async () => {
    storage.setItem(contract.local_storage.access_token, "access-value");
    storage.setItem(contract.local_storage.refresh_token, "refresh-secret");
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await logoutSub2Api(storage);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(contract.endpoints.logout.path);
    expect(init.method).toBe(contract.endpoints.logout.method);
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer access-value");
    expect(Object.keys(JSON.parse(String(init.body)))).toEqual(contract.endpoints.logout.request_required);
    expect(storage.getItem(contract.local_storage.access_token)).toBeNull();
    expect(storage.getItem(contract.local_storage.refresh_token)).toBeNull();
  });

  it("reports an unconfirmed upstream logout when only an access token exists", async () => {
    storage.setItem(contract.local_storage.access_token, "access-only");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(logoutSub2Api(storage)).rejects.toThrow(
      "本地登录已清除，但服务端会话未确认注销",
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(storage.getItem(contract.local_storage.access_token)).toBeNull();
  });

  it.each([400, 403, 404, 408, 429, 503])(
    "preserves browser credentials when refresh HTTP %s does not explicitly reject them",
    async (status) => {
      storage.setItem(contract.local_storage.access_token, "old-access");
      storage.setItem(contract.local_storage.refresh_token, "old-refresh");
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status })));

      await expect(refreshAndPersistSub2ApiAuth(storage)).rejects.toMatchObject({
        retryable: true,
        credentialRejected: false,
      });

      expect(storage.getItem(contract.local_storage.access_token)).toBe("old-access");
      expect(storage.getItem(contract.local_storage.refresh_token)).toBe("old-refresh");
    },
  );

  it("clears browser credentials only when refresh explicitly rejects them", async () => {
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "invalid-refresh");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 401 })));

    await expect(refreshAndPersistSub2ApiAuth(storage)).rejects.toMatchObject({
      retryable: false,
      credentialRejected: true,
    });

    expect(storage.getItem(contract.local_storage.access_token)).toBeNull();
    expect(storage.getItem(contract.local_storage.refresh_token)).toBeNull();
  });

  it("preserves an access token when the local refresh credential is missing", async () => {
    storage.setItem(contract.local_storage.access_token, "access-only");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(refreshAndPersistSub2ApiAuth(storage)).rejects.toMatchObject({
      retryable: false,
      credentialRejected: false,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(storage.getItem(contract.local_storage.access_token)).toBe("access-only");
  });

  it("times out a stalled refresh body and releases the refresh lock", async () => {
    vi.useFakeTimers();
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "old-refresh");
    let lockReleased = false;
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: async <T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => {
          try {
            return await callback();
          } finally {
            lockReleased = true;
          }
        },
      },
    });
    const stalled = {
      ok: true,
      status: 200,
      json: () => new Promise<never>(() => undefined),
    } as unknown as Response;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(stalled));

    const refresh = refreshAndPersistSub2ApiAuth(storage);
    const rejected = expect(refresh).rejects.toBeInstanceOf(Sub2ApiRefreshError);
    await vi.advanceTimersByTimeAsync(15_000);
    await rejected;

    expect(lockReleased).toBe(true);
    expect(storage.getItem(contract.local_storage.access_token)).toBe("old-access");
    expect(storage.getItem(contract.local_storage.refresh_token)).toBe("old-refresh");
  });

  it("times out while waiting for an abandoned fallback lease", async () => {
    vi.useFakeTimers();
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "old-refresh");
    storage.setItem(
      "sub2api_codex_control_auth_refresh_lock",
      JSON.stringify({ owner: "other-tab", expiresAt: Date.now() + 60_000 }),
    );
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const refresh = refreshAndPersistSub2ApiAuth(storage);
    const rejected = expect(refresh).rejects.toMatchObject({ retryable: true });
    await vi.advanceTimersByTimeAsync(15_000);
    await rejected;

    expect(fetchMock).not.toHaveBeenCalled();
    expect(storage.getItem(contract.local_storage.refresh_token)).toBe("old-refresh");
    expect(
      [...Array(storage.length).keys()]
        .map((index) => storage.key(index))
        .filter((key) => key?.includes(":contender:")),
    ).toEqual([]);
  });

  it("elects one fallback-lock winner across two tab storage objects", async () => {
    vi.useFakeTimers();
    Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    const sharedValues = new Map<string, string>();
    const firstTab = new SharedMemoryStorage(sharedValues);
    const secondTab = new SharedMemoryStorage(sharedValues);
    firstTab.setItem(contract.local_storage.access_token, "old-access");
    firstTab.setItem(contract.local_storage.refresh_token, "old-refresh");
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi.fn().mockImplementation(() => pendingRefresh);
    vi.stubGlobal("fetch", fetchMock);

    const first = refreshAndPersistSub2ApiAuth(firstTab);
    const second = refreshAndPersistSub2ApiAuth(secondTab);
    await vi.advanceTimersByTimeAsync(0);
    expect([...sharedValues.keys()].filter((key) => key.includes(":contender:"))).toHaveLength(2);
    expect(fetchMock).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(75);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(firstTab.getItem("sub2api_codex_control_auth_refresh_lock")).not.toBeNull();
    await vi.advanceTimersByTimeAsync(75);
    expect(fetchMock).toHaveBeenCalledOnce();
    resolveRefresh(rotatedAuthResponse("winner-access", "winner-refresh"));
    await vi.advanceTimersByTimeAsync(500);
    await expect(Promise.all([first, second])).resolves.toMatchObject([
      { accessToken: "winner-access", refreshToken: "winner-refresh" },
      { accessToken: "winner-access", refreshToken: "winner-refresh" },
    ]);

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(firstTab.getItem(contract.local_storage.refresh_token)).toBe("winner-refresh");
    expect([...sharedValues.keys()].filter((key) => key.includes(":contender:"))).toEqual([]);
    expect(firstTab.getItem("sub2api_codex_control_auth_refresh_lock")).toBeNull();
  });

  it("revokes credentials that rotate before logout acquires the lock", async () => {
    storage.setItem(contract.local_storage.access_token, "old-access");
    storage.setItem(contract.local_storage.refresh_token, "old-refresh");
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: <T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => {
          storage.setItem(contract.local_storage.access_token, "rotated-access");
          storage.setItem(contract.local_storage.refresh_token, "rotated-refresh");
          return callback();
        },
      },
    });
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await logoutSub2Api(storage);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer rotated-access");
    expect(JSON.parse(String(init.body))).toEqual({ refresh_token: "rotated-refresh" });
    expect(storage.getItem(contract.local_storage.access_token)).toBeNull();
    expect(storage.getItem(contract.local_storage.refresh_token)).toBeNull();
  });

  it("reports a failed remote logout while keeping local credentials cleared", async () => {
    storage.setItem(contract.local_storage.access_token, "access-value");
    storage.setItem(contract.local_storage.refresh_token, "refresh-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

    await expect(logoutSub2Api(storage)).rejects.toThrow("Sub2API 注销失败（HTTP 503）");

    expect(storage.getItem(contract.local_storage.access_token)).toBeNull();
    expect(storage.getItem(contract.local_storage.refresh_token)).toBeNull();
    expect(storage.getItem("sub2api_codex_control_logout_intent")).toBeNull();
  });

  it("sends exactly the frozen Control exchange field set", async () => {
    storage.setItem(contract.local_storage.access_token, "access-value");
    storage.setItem(contract.local_storage.refresh_token, "must-stay-local");
    const fetchMock = vi.fn().mockResolvedValue(controlSession());
    vi.stubGlobal("fetch", fetchMock);
    const store = useSessionStore();

    await store.exchange();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(contract.control_boundary.exchange_path);
    expect(init.method).toBe(contract.control_boundary.exchange_method);
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(contract.control_boundary.accepted_sub2api_fields);
    for (const forbidden of contract.control_boundary.forbidden_sub2api_fields) {
      expect(body).not.toHaveProperty(forbidden);
    }
    store.reset();
  });
});
