import { afterEach, describe, expect, it, vi } from "vitest";

import {
  apiRequest,
  onControlAuthenticationRequired,
  resetApiSecurityConfig,
} from "@/api/client";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("Control API safe request replay", () => {
  let unsubscribe: (() => void) | null = null;

  afterEach(() => {
    unsubscribe?.();
    unsubscribe = null;
    resetApiSecurityConfig();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("retries one lost idempotent sync response with the same key", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("connection reset after dispatch"))
      .mockResolvedValueOnce(jsonResponse({ id: "sync-1", state: "queued" }));
    vi.stubGlobal("fetch", fetchMock);
    const key = "2f26184c-14df-4d68-ac77-eac3d8a62435";

    await expect(
      apiRequest("/devices/device-1/threads/sync", {
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    ).resolves.toMatchObject({ id: "sync-1" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [, init] of fetchMock.mock.calls as Array<[string, RequestInit]>) {
      expect(new Headers(init.headers).get("Idempotency-Key")).toBe(key);
    }
  });

  it("does not retry a network failure without an idempotency key", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("offline"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest("/devices", { method: "GET" })).rejects.toThrow("offline");

    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("does not fetch when the caller signal is already aborted", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();
    const reason = new DOMException("principal changed", "AbortError");
    controller.abort(reason);

    await expect(
      apiRequest("/devices/device-1/threads/sync", {
        method: "POST",
        headers: { "Idempotency-Key": "1fcab920-0cfa-49e2-8566-7344883137e0" },
        signal: controller.signal,
      }),
    ).rejects.toBe(reason);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not retry a lost response after the caller aborts", async () => {
    const controller = new AbortController();
    const reason = new DOMException("principal changed", "AbortError");
    const fetchMock = vi.fn().mockImplementation(() => {
      controller.abort(reason);
      return Promise.reject(new TypeError("connection reset after dispatch"));
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      apiRequest("/devices/device-1/threads/sync", {
        method: "POST",
        headers: { "Idempotency-Key": "7d067225-ea33-45eb-9aa9-079aef0502b6" },
        signal: controller.signal,
      }),
    ).rejects.toBe(reason);

    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("recovers control_session_required once and reuses the original key", async () => {
    unsubscribe = onControlAuthenticationRequired(() => true);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ detail: "control_session_required" }, 401))
      .mockResolvedValueOnce(jsonResponse({ id: "sync-2", state: "queued" }));
    vi.stubGlobal("fetch", fetchMock);
    const key = "b81c08ce-38d9-41c3-a290-0d43ab12ae38";

    await expect(
      apiRequest("/threads/thread-1/sync", {
        method: "POST",
        headers: { "Idempotency-Key": key },
      }),
    ).resolves.toMatchObject({ id: "sync-2" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const keys = (fetchMock.mock.calls as Array<[string, RequestInit]>).map(([, init]) =>
      new Headers(init.headers).get("Idempotency-Key"),
    );
    expect(keys).toEqual([key, key]);
  });
});
