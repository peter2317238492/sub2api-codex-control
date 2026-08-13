import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { createPinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "@/App.vue";
import { SUB2API_LOGOUT_INTENT_STORAGE_KEY } from "@/api/sub2api";
import { useControlStore } from "@/stores/control";
import { useSessionStore } from "@/stores/session";
import { MemoryStorage } from "./storage";

class MockWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: MockWebSocket[] = [];

  readyState = MockWebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(readonly url: string) {
    MockWebSocket.instances.push(this);
  }

  close(code = 1000): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code } as CloseEvent);
  }

  serverClose(code: number): void {
    this.close(code);
  }

  message(event: Record<string, unknown>): void {
    this.onmessage?.({ data: JSON.stringify(event) } as MessageEvent);
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function sessionSnapshot(id = "session-1", userId = "user-1"): Record<string, unknown> {
  const issuedAt = new Date().toISOString();
  const deadline = new Date(Date.now() + 10 * 60_000).toISOString();
  return {
    id,
    user: { id: userId, username: userId === "user-1" ? "alice" : "bob", email: null, display_name: null },
    issued_at: issuedAt,
    expires_at: deadline,
    reauth_at: deadline,
    csrf_header_name: "x-csrf-token",
  };
}

function controlBootstrap(devices: Record<string, unknown>[] = []): Record<string, unknown> {
  return {
    event_cursor: "0",
    devices,
    threads: [],
    approvals: [],
    models_by_device: Object.fromEntries(devices.map((device) => [String(device.id), []])),
  };
}

async function settle(): Promise<void> {
  await flushPromises();
  await flushPromises();
}

function dispatchStorage(key: string | null, newValue: string | null): void {
  const event = new Event("storage") as StorageEvent;
  Object.defineProperties(event, {
    key: { value: key },
    newValue: { value: newValue },
    storageArea: { value: null },
  });
  window.dispatchEvent(event);
}

describe("App session recovery", () => {
  let wrapper: VueWrapper | null;

  beforeEach(() => {
    wrapper = null;
    MockWebSocket.instances = [];
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: new MemoryStorage(),
    });
    document.cookie = "codex_csrf=; Max-Age=0; path=/";
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: <T>(_name: string, _options: LockOptions, callback: () => Promise<T>) => callback(),
      },
    });
  });

  afterEach(() => {
    wrapper?.unmount();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("uses a newly available access token when the unauthenticated gate retries", async () => {
    let sessionLoads = 0;
    let deviceBootstraps = 0;
    let refreshCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) {
        sessionLoads += 1;
        return Promise.resolve(jsonResponse({ detail: "control session required" }, 401));
      }
      if (url.endsWith("/session/exchange")) return Promise.resolve(jsonResponse(sessionSnapshot(), 201));
      if (url.endsWith("/bootstrap")) {
        deviceBootstraps += 1;
        return Promise.resolve(jsonResponse(controlBootstrap()));
      }
      if (url.includes("/approvals?")) return Promise.resolve(jsonResponse({ items: [] }));
      if (url === "/api/v1/auth/refresh") {
        refreshCalls += 1;
        return Promise.resolve(new Response(null, { status: 500 }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();

    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    expect(wrapper.get(".session-gate h1").text()).toBe("需要登录 Sub2API");

    window.localStorage.setItem("auth_token", "access-only");
    await wrapper.get(".session-actions .primary-button").trigger("click");
    await settle();

    expect(wrapper.find(".app-shell").exists()).toBe(true);
    expect(sessionLoads).toBe(2);
    expect(refreshCalls).toBe(0);
    expect(deviceBootstraps).toBe(1);
    const exchange = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/session/exchange"));
    expect(JSON.parse(String(exchange?.[1]?.body))).toEqual({ access_token: "access-only" });
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("recovers from a refresh-only login and bootstraps control state once", async () => {
    let deviceBootstraps = 0;
    let refreshCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) {
        return Promise.resolve(jsonResponse({ detail: "control session required" }, 401));
      }
      if (url === "/api/v1/auth/refresh") {
        refreshCalls += 1;
        return Promise.resolve(
          jsonResponse({
            code: 0,
            message: "success",
            data: {
              access_token: "recovered-access",
              refresh_token: "rotated-refresh",
              expires_in: 3600,
              token_type: "Bearer",
            },
          }),
        );
      }
      if (url.endsWith("/session/exchange")) {
        return Promise.resolve(jsonResponse(sessionSnapshot("session-recovered"), 201));
      }
      if (url.endsWith("/bootstrap")) {
        deviceBootstraps += 1;
        return Promise.resolve(jsonResponse(controlBootstrap()));
      }
      if (url.includes("/approvals?")) return Promise.resolve(jsonResponse({ items: [] }));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();

    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    window.localStorage.setItem("refresh_token", "refresh-only");

    await wrapper.get(".session-actions .primary-button").trigger("click");
    await settle();

    expect(wrapper.find(".app-shell").exists()).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(deviceBootstraps).toBe(1);
    expect(window.localStorage.getItem("auth_token")).toBe("recovered-access");
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("coalesces simultaneous WebSocket 4401 and HTTP 401 recovery", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    window.localStorage.setItem("refresh_token", "old-refresh");
    let deviceBootstraps = 0;
    let refreshCalls = 0;
    let exchangeCalls = 0;
    let resolveRefresh!: (response: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) {
        deviceBootstraps += 1;
        return Promise.resolve(jsonResponse(controlBootstrap()));
      }
      if (url.includes("/approvals?")) return Promise.resolve(jsonResponse({ items: [] }));
      if (url.includes("/approvals/expired/decision")) {
        return Promise.resolve(jsonResponse({ detail: "control session expired" }, 401));
      }
      if (url === "/api/v1/auth/refresh") {
        refreshCalls += 1;
        return pendingRefresh;
      }
      if (url.endsWith("/session/exchange")) {
        exchangeCalls += 1;
        return exchangeCalls === 1
          ? Promise.resolve(jsonResponse({ detail: "expired Sub2API access token" }, 401))
          : Promise.resolve(jsonResponse(sessionSnapshot("session-2"), 201));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    expect(MockWebSocket.instances).toHaveLength(1);

    const controlStore = useControlStore(pinia);
    const deciding = controlStore.resolveApproval("expired", "deny").catch(() => undefined);
    MockWebSocket.instances[0]?.serverClose(4401);
    await settle();
    expect(refreshCalls).toBe(1);

    resolveRefresh(
      jsonResponse({
        code: 0,
        message: "success",
        data: {
          access_token: "new-access",
          refresh_token: "new-refresh",
          expires_in: 3600,
          token_type: "Bearer",
        },
      }),
    );
    await deciding;
    await settle();

    expect(refreshCalls).toBe(1);
    expect(deviceBootstraps).toBe(2);
    expect(MockWebSocket.instances).toHaveLength(2);
  });

  it("immediately closes the old principal event stream when another tab logs out", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    window.localStorage.setItem("refresh_token", "refresh-value");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      if (url.includes("/approvals?")) return Promise.resolve(jsonResponse({ items: [] }));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    const oldSocket = MockWebSocket.instances[0];
    expect(oldSocket).toBeDefined();

    window.localStorage.removeItem("auth_token");
    window.localStorage.removeItem("refresh_token");
    dispatchStorage(SUB2API_LOGOUT_INTENT_STORAGE_KEY, "peer-logout");
    await settle();

    expect(useSessionStore(pinia).authenticated).toBe(false);
    expect(wrapper.get(".session-gate h1").text()).toBe("需要登录 Sub2API");
    expect(oldSocket?.readyState).toBe(MockWebSocket.CLOSED);
    expect(oldSocket?.onclose).toBeNull();
    expect(useControlStore(pinia).devices).toEqual([]);
  });

  it("treats a peer localStorage.clear event as an immediate logout", async () => {
    window.localStorage.setItem("auth_token", "access-value");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    const oldSocket = MockWebSocket.instances[0];

    window.localStorage.clear();
    dispatchStorage(null, null);
    await settle();

    expect(useSessionStore(pinia).authenticated).toBe(false);
    expect(oldSocket?.readyState).toBe(MockWebSocket.CLOSED);
    expect(useControlStore(pinia).devices).toEqual([]);
  });

  it("keeps the current shell when cross-tab token exchange has a retryable failure", async () => {
    window.localStorage.setItem("auth_token", "old-access");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      if (url.endsWith("/session/exchange")) {
        return Promise.resolve(jsonResponse({ detail: "temporary outage" }, 503));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();
    const originalSocket = MockWebSocket.instances[0];

    window.localStorage.setItem("auth_token", "peer-rotated-access");
    dispatchStorage("auth_token", "peer-rotated-access");
    expect(originalSocket?.readyState).toBe(MockWebSocket.CLOSED);
    await expect(useControlStore(pinia).sendTurn("must not use the old principal")).resolves.toBe(false);
    await new Promise((resolve) => window.setTimeout(resolve, 120));
    await settle();

    expect(wrapper.find(".app-shell").exists()).toBe(true);
    expect(useSessionStore(pinia).authenticated).toBe(true);
    expect(useSessionStore(pinia).error).toBe("跨标签页登录同步暂时失败，正在重试");
    expect(originalSocket?.readyState).toBe(MockWebSocket.CLOSED);
    expect(useControlStore(pinia).devices).toEqual([]);
  });

  it("reauthenticates and retries a sensitive mutation once for the same principal", async () => {
    window.localStorage.setItem("auth_token", "same-user-access");
    let claimCalls = 0;
    let bootstrapCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/session/exchange")) {
        return Promise.resolve(jsonResponse(sessionSnapshot("session-reauthenticated"), 201));
      }
      if (url.endsWith("/bootstrap")) {
        bootstrapCalls += 1;
        return Promise.resolve(jsonResponse(controlBootstrap()));
      }
      if (url.endsWith("/pairings/claim")) {
        claimCalls += 1;
        return claimCalls === 1
          ? Promise.resolve(jsonResponse({ detail: "reauth_required" }, 401))
          : Promise.resolve(
              jsonResponse({
                pairing_id: "pairing-1",
                device_id: "device-1",
                device_name: "Device",
                status: "claimed",
              }),
            );
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();

    await expect(useControlStore(pinia).claimPairing("ONE-TIME-CODE")).resolves.toBe("device-1");
    await settle();

    expect(claimCalls).toBe(2);
    expect(bootstrapCalls).toBe(2);
    expect(useSessionStore(pinia).session?.id).toBe("session-reauthenticated");
  });

  it("keeps a claimed pairing pending until the Connector comes online", async () => {
    const offlineDevice = {
      id: "device-pairing",
      name: "New device",
      status: "offline",
      connector_version: "0.1.0",
      codex_version: "0.147.0",
      last_seen_at: null,
      workspace_roots: ["/work"],
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      if (url.endsWith("/pairings/claim")) {
        return Promise.resolve(
          jsonResponse({
            pairing_id: "pairing-1",
            device_id: "device-pairing",
            device_name: "New device",
            status: "claimed",
          }),
        );
      }
      if (url.endsWith("/devices/device-pairing/threads/sync") || url.endsWith("/devices/device-pairing/models/sync")) {
        return Promise.resolve(jsonResponse({ state: "queued" }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();

    await wrapper.get(".device-rail .pair-existing-button").trigger("click");
    await wrapper.get(".pair-code-field input").setValue("2345-6789-ABCD-EFGH");
    await wrapper.get(".pair-dialog form, .pair-dialog").trigger("submit");
    await settle();

    expect(wrapper.get(".pair-waiting").text()).toContain("配对码已认领");
    expect(wrapper.find(".pair-dialog").exists()).toBe(true);

    MockWebSocket.instances.at(-1)?.message({
      cursor: "1",
      type: "device.updated",
      occurred_at: "2026-08-13T00:00:00Z",
      data: offlineDevice,
    });
    await settle();

    expect(wrapper.get(".pair-waiting").text()).toContain("设备已完成配对");
    expect(wrapper.get(".pair-waiting").text()).toContain("等待 Connector 上线");
    expect(wrapper.find(".pair-dialog").exists()).toBe(true);

    MockWebSocket.instances.at(-1)?.message({
      cursor: "2",
      type: "device.updated",
      occurred_at: "2026-08-13T00:00:00Z",
      data: { ...offlineDevice, status: "online" },
    });
    await settle();

    expect(wrapper.find(".pair-dialog").exists()).toBe(false);
    expect(useControlStore(pinia).selectedDeviceId).toBe("device-pairing");
    expect(wrapper.get(".app-shell").attributes("data-mobile-panel")).toBe("threads");
  });

  it("opens the fail-closed setup flow and lets an existing Connector continue to pairing", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();

    await wrapper.get(".setup-connector-button").trigger("click");
    expect(wrapper.get(".setup-dialog").text()).toContain("正式安装包暂不可用");
    expect(wrapper.find(".asset-download").exists()).toBe(false);

    await wrapper.get(".existing-pair-button").trigger("click");
    expect(wrapper.find(".setup-dialog").exists()).toBe(false);
    expect(wrapper.find(".pair-dialog").exists()).toBe(true);
  });

  it("maps pairing failures to recovery guidance and opens device management", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) return Promise.resolve(jsonResponse(controlBootstrap()));
      if (url.endsWith("/pairings/claim")) {
        return Promise.resolve(jsonResponse({ detail: "device_capacity_exceeded" }, 409));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();

    await wrapper.get(".device-rail .pair-existing-button").trigger("click");
    await wrapper.get(".pair-code-field input").setValue("2345-6789-ABCD-EFGH");
    await wrapper.get(".pair-dialog form, .pair-dialog").trigger("submit");
    await settle();

    expect(wrapper.get(".form-error").text()).toContain("设备数量已达上限");
    await wrapper.get(".pair-manage-button").trigger("click");
    expect(wrapper.find(".pair-dialog").exists()).toBe(false);
    expect(wrapper.get(".app-shell").attributes("data-mobile-panel")).toBe("devices");
  });

  it("confirms local archive, reports unsafe conflicts, and removes the thread after success", async () => {
    let archiveCalls = 0;
    const confirm = vi.spyOn(window, "confirm")
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(true);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) return Promise.resolve(jsonResponse(sessionSnapshot()));
      if (url.endsWith("/bootstrap")) {
        return Promise.resolve(
          jsonResponse({
            ...controlBootstrap([
              {
                id: "device-1",
                name: "Device",
                status: "online",
                connector_version: "0.1.0",
                codex_version: "0.147.0",
                last_seen_at: null,
                workspace_roots: ["/work"],
              },
            ]),
            threads: [
              {
                id: "thread-1",
                device_id: "device-1",
                title: "Local record",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-30T00:00:00Z",
                status: "idle",
              },
            ],
          }),
        );
      }
      if (url.endsWith("/threads/thread-1") && !init?.method) {
        return Promise.resolve(
          jsonResponse({
            event_cursor: "0",
            thread: {
              id: "thread-1",
              device_id: "device-1",
              title: "Local record",
              cwd: "/work",
              model: "model",
              updated_at: "2026-07-30T00:00:00Z",
              status: "idle",
              messages: [],
            },
          }),
        );
      }
      if (url.endsWith("/threads/thread-1") && init?.method === "DELETE") {
        archiveCalls += 1;
        return archiveCalls === 1
          ? Promise.resolve(jsonResponse({ detail: "thread_not_archivable" }, 409))
          : Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { attachTo: document.body, global: { plugins: [pinia] } });
    await settle();
    const archiveButton = wrapper.get(".thread-archive-button");

    await archiveButton.trigger("click");
    await settle();
    expect(archiveCalls).toBe(0);

    await archiveButton.trigger("click");
    await settle();
    expect(archiveCalls).toBe(1);
    expect(wrapper.get(".error-toast").text()).toContain("线程仍有进行中的操作，暂时无法归档");
    expect(wrapper.find(".thread-item").exists()).toBe(true);

    await archiveButton.trigger("click");
    await settle();
    expect(archiveCalls).toBe(2);
    expect(wrapper.find(".thread-item").exists()).toBe(false);
    expect(wrapper.find(".error-toast").exists()).toBe(false);
    expect(document.activeElement).toBe(wrapper.get(".thread-list-panel .panel-title-row .icon-button").element);
    expect(confirm.mock.calls[0]?.[0]).toContain("设备上的 Codex 线程不会被删除");
  });

  it("never replays a sensitive mutation when reauthentication changes principal", async () => {
    window.localStorage.setItem("auth_token", "user-2-access");
    window.localStorage.setItem("refresh_token", "user-2-refresh");
    let claimCalls = 0;
    let deviceBootstraps = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/session") && !init?.method) {
        return Promise.resolve(jsonResponse(sessionSnapshot("session-user-1", "user-1")));
      }
      if (url.endsWith("/session/exchange")) {
        return Promise.resolve(jsonResponse(sessionSnapshot("session-user-2", "user-2"), 201));
      }
      if (url.endsWith("/bootstrap")) {
        deviceBootstraps += 1;
        return Promise.resolve(jsonResponse(controlBootstrap()));
      }
      if (url.includes("/approvals?")) return Promise.resolve(jsonResponse({ items: [] }));
      if (url.endsWith("/pairings/claim")) {
        claimCalls += 1;
        return Promise.resolve(jsonResponse({ detail: "reauth_required" }, 401));
      }
      return Promise.resolve(new Response(null, { status: 404 }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const pinia = createPinia();
    wrapper = mount(App, { global: { plugins: [pinia] } });
    await settle();

    await expect(useControlStore(pinia).claimPairing("ONE-TIME-CODE")).resolves.toBeNull();
    await settle();

    expect(claimCalls).toBe(1);
    expect(useSessionStore(pinia).session?.user.id).toBe("user-2");
    expect(deviceBootstraps).toBe(2);
    expect(MockWebSocket.instances).toHaveLength(2);
  });
});
