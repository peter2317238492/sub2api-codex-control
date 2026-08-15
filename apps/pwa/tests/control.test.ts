import type { BrowserEvent } from "@sub2api-codex/control-protocol";
import { createPinia, setActivePinia } from "pinia";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { onControlAuthenticationRequired } from "@/api/client";
import { useControlStore } from "@/stores/control";

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

  serverOpen(): void {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.({} as Event);
  }

  message(event: BrowserEvent): void {
    this.onmessage?.({ data: JSON.stringify(event) } as MessageEvent);
  }
}

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

function releaseAsset(os: "linux" | "darwin", arch: "amd64" | "arm64", packageFormat: "deb" | "rpm" | "pkg") {
  const filename = `sub2api-codex-connector_0.1.0_${os}_${arch}.${packageFormat}`;
  return {
    os,
    arch,
    package_format: packageFormat,
    filename,
    download_url: `https://github.com/peter2317238492/sub2api-codex-control/releases/download/connector-v0.1.0/${filename}`,
    sha256: "a".repeat(64),
    size: 1000,
    signature_bundle: `${filename}.sigstore.json`,
    sbom: {
      format: "SPDX-2.3-json",
      filename: `${filename}.spdx.json`,
      sha256: "b".repeat(64),
      size: 2000,
      signature_bundle: `${filename}.spdx.json.sigstore.json`,
    },
    provenance: {
      predicate_type: "https://slsa.dev/provenance/v1",
      filename: `${filename}.intoto.json`,
      sha256: "c".repeat(64),
      size: 3000,
      signature_bundle: `${filename}.intoto.json.sigstore.json`,
      attestation_bundle: `${filename}.intoto.sigstore.json`,
    },
  };
}

const connectorReleaseMetadata = {
  format_version: 1 as const,
  release_mode: "release" as const,
  releasable: true as const,
  source_repository: "https://github.com/peter2317238492/sub2api-codex-control" as const,
  source_commit: "d".repeat(40),
  version: "0.1.0",
  tag: "connector-v0.1.0",
  codex_version: "0.147.0",
  schema_digest: "5".repeat(64),
  manifest: {
    filename: "manifest.json",
    sha256: "e".repeat(64),
    size: 4000,
    signature_bundle: "manifest.json.sigstore.json",
  },
  config_path_hint: "~/.config/sub2api-codex-connector/connector.json",
  pair_command: "sub2api-codex-connector-ctl pair",
  start_command: "sub2api-codex-connector-ctl start",
  assets: [
    releaseAsset("linux", "amd64", "deb"),
    releaseAsset("linux", "amd64", "rpm"),
    releaseAsset("linux", "arm64", "deb"),
    releaseAsset("linux", "arm64", "rpm"),
    releaseAsset("darwin", "amd64", "pkg"),
    releaseAsset("darwin", "arm64", "pkg"),
  ],
};

describe("Control store session isolation and event coalescing", () => {
  let threadFetches: number;
  let bootstrapCursor: string;

  beforeEach(() => {
    setActivePinia(createPinia());
    MockWebSocket.instances = [];
    threadFetches = 0;
    bootstrapCursor = "0";
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: bootstrapCursor,
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "Thread",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:00Z",
                  status: "running",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
              connector_release: connectorReleaseMetadata,
            }),
          );
        }
        if (url.endsWith("/threads/thread-1")) {
          threadFetches += 1;
          return Promise.resolve(
            response({
              event_cursor: bootstrapCursor,
              thread: {
                id: "thread-1",
                device_id: "device-1",
                title: "Thread",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-13T00:00:00Z",
                status: "running",
                messages: [],
              },
            }),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("clears principal-scoped state and prevents an old socket from reconnecting", async () => {
    vi.useFakeTimers();
    const store = useControlStore();
    await store.bootstrap();
    const oldSocket = MockWebSocket.instances[0];
    expect(oldSocket).toBeDefined();
    expect(store.devices).toHaveLength(1);
    expect(store.connectorRelease).toEqual(connectorReleaseMetadata);

    store.reset();
    expect(store.devices).toEqual([]);
    expect(store.threads).toEqual([]);
    expect(store.approvals).toEqual([]);
    expect(store.selectedDeviceId).toBeNull();
    expect(store.selectedThreadId).toBeNull();
    expect(store.connectorRelease).toBeNull();
    expect(oldSocket?.onclose).toBeNull();

    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("discards bootstrap responses that arrive after the session is reset", async () => {
    let resolveDevices!: (response: Response) => void;
    const delayedDevices = new Promise<Response>((resolve) => {
      resolveDevices = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) return delayedDevices;
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );

    const store = useControlStore();
    const loading = store.bootstrap();
    store.reset();
    resolveDevices(
      response({
        event_cursor: "9",
        devices: [
          {
            id: "old-device",
            name: "Old principal device",
            status: "online",
            connector_version: "0.1.0",
            codex_version: "0.147.0",
            last_seen_at: null,
            workspace_roots: ["/old"],
          },
        ],
        threads: [],
        approvals: [],
        models_by_device: { "old-device": [] },
      }),
    );
    await loading;

    expect(store.devices).toEqual([]);
    expect(store.selectedDeviceId).toBeNull();
    expect(MockWebSocket.instances).toHaveLength(0);
  });

  it("discards create and pairing responses from a prior principal generation", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    let resolveCreate!: (response: Response) => void;
    const pendingCreate = new Promise<Response>((resolve) => {
      resolveCreate = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/devices/device-1/threads") && init?.method === "POST") return pendingCreate;
        return baselineFetch(input, init);
      }),
    );

    const creating = store.createThread("/work", "model");
    store.reset();
    resolveCreate(
      response({
        id: "old-thread",
        device_id: "device-1",
        title: "Old principal thread",
        cwd: "/work",
        model: "model",
        updated_at: "2026-07-13T00:00:00Z",
        status: "idle",
      }),
    );
    await expect(creating).resolves.toBe(false);
    expect(store.threads).toEqual([]);
    expect(store.activeThread).toBeNull();

    let resolveClaim!: (response: Response) => void;
    const pendingClaim = new Promise<Response>((resolve) => {
      resolveClaim = resolve;
    });
    vi.stubGlobal("fetch", vi.fn(() => pendingClaim));
    const claiming = store.claimPairing("ABC123");
    store.reset();
    resolveClaim(response({ pairing_id: "pairing-1", device_id: "old-device", device_name: "Old", status: "claimed" }));
    await expect(claiming).resolves.toBeNull();
    expect(store.devices).toEqual([]);
  });

  it("locks duplicate turn submissions until the first request completes", async () => {
    const store = useControlStore();
    await store.bootstrap();
    let resolveTurn!: (response: Response) => void;
    const pendingTurn = new Promise<Response>((resolve) => {
      resolveTurn = resolve;
    });
    const actionFetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => pendingTurn);
    vi.stubGlobal("fetch", actionFetch);

    const first = store.sendTurn("first");
    await expect(store.sendTurn("duplicate")).resolves.toBe(false);
    expect(store.turnSubmitting).toBe(true);
    expect(store.activeThread?.messages.filter((message) => message.role === "user")).toHaveLength(1);
    expect(actionFetch).toHaveBeenCalledOnce();
    const idempotencyKey = new Headers(actionFetch.mock.calls[0]?.[1]?.headers).get("Idempotency-Key");
    expect(idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
    expect(store.activeThread?.messages.find((message) => message.role === "user")?.id).toBe(idempotencyKey);

    resolveTurn(response({ command_id: "command-1" }));
    await expect(first).resolves.toBe(true);
    expect(store.turnSubmitting).toBe(false);
  });

  it("locks duplicate thread creation until the first request completes", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    let resolveCreate!: (response: Response) => void;
    const pendingCreate = new Promise<Response>((resolve) => {
      resolveCreate = resolve;
    });
    const actionFetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/devices/device-1/threads") && init?.method === "POST") return pendingCreate;
      if (url.endsWith("/threads/thread-new")) {
        return Promise.resolve(
          response({
            event_cursor: "0",
            thread: {
              id: "thread-new",
              device_id: "device-1",
              title: "New",
              cwd: "/work",
              model: "model",
              updated_at: "2026-07-13T00:00:01Z",
              status: "idle",
              messages: [],
            },
          }),
        );
      }
      return baselineFetch(input, init);
    });
    vi.stubGlobal("fetch", actionFetch);

    const first = store.createThread("/work", "model");
    await expect(store.createThread("/work", "model")).resolves.toBe(false);
    expect(store.creatingThread).toBe(true);
    expect(actionFetch).toHaveBeenCalledOnce();

    resolveCreate(
      response({
        id: "thread-new",
        device_id: "device-1",
        title: "New",
        cwd: "/work",
        model: "model",
        updated_at: "2026-07-13T00:00:01Z",
        status: "idle",
      }),
    );
    await expect(first).resolves.toBe(true);
    expect(store.creatingThread).toBe(false);
    expect(actionFetch).toHaveBeenCalledTimes(2);
  });

  it("locks a failed thread until its resume command reaches a terminal state", async () => {
    const store = useControlStore();
    await store.bootstrap();
    if (!store.activeThread || !store.threads[0]) throw new Error("expected the bootstrap thread");
    store.activeThread.status = "failed";
    store.threads[0].status = "failed";

    let resolveResume!: (response: Response) => void;
    const pendingResume = new Promise<Response>((resolve) => {
      resolveResume = resolve;
    });
    const resumeFetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => pendingResume);
    vi.stubGlobal("fetch", resumeFetch);

    const first = store.resumeThread();
    await expect(store.resumeThread()).resolves.toBe(false);
    await expect(store.sendTurn("must wait for resume")).resolves.toBe(false);
    expect(store.resumingThreadIds).toEqual(["thread-1"]);
    expect(resumeFetch).toHaveBeenCalledOnce();
    expect(String(resumeFetch.mock.calls[0]?.[0])).toMatch(/\/threads\/thread-1\/resume$/);
    expect(resumeFetch.mock.calls[0]?.[1]?.method).toBe("POST");
    expect(new Headers(resumeFetch.mock.calls[0]?.[1]?.headers).get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);

    resolveResume(response({ id: "resume-1", state: "queued", method: "thread/resume" }));
    await expect(first).resolves.toBe(true);
    expect(store.resumingThreadIds).toEqual(["thread-1"]);

    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "command.updated",
      occurred_at: "2026-07-30T00:00:01Z",
      data: {
        device_id: "device-1",
        command: { id: "resume-1", state: "succeeded", method: "thread/resume" },
      },
    });
    expect(store.resumingThreadIds).toEqual(["thread-1"]);

    MockWebSocket.instances[0]?.message({
      cursor: "2",
      type: "thread.updated",
      occurred_at: "2026-07-30T00:00:02Z",
      data: {
        thread_id: "thread-1",
        device_id: "device-1",
        title: "Thread",
        cwd: "/work",
        model: "model",
        updated_at: "2026-07-30T00:00:02Z",
        status: "idle",
      },
    });
    expect(store.activeThread.status).toBe("idle");
    expect(store.resumingThreadIds).toEqual([]);
    store.reset();
  });

  it("reconciles a resume failure event that arrives before the HTTP response", async () => {
    const store = useControlStore();
    await store.bootstrap();
    if (!store.activeThread || !store.threads[0]) throw new Error("expected the bootstrap thread");
    store.activeThread.status = "failed";
    store.threads[0].status = "failed";

    let resolveResume!: (response: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveResume = resolve;
          }),
      ),
    );
    const resuming = store.resumeThread();

    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "command.updated",
      occurred_at: "2026-07-30T00:00:01Z",
      data: {
        device_id: "device-1",
        command: {
          id: "resume-early",
          state: "failed",
          method: "thread/resume",
          error_message: "resume rejected",
        },
      },
    });
    expect(store.resumingThreadIds).toEqual(["thread-1"]);

    resolveResume(response({ id: "resume-early", state: "queued", method: "thread/resume" }));
    await expect(resuming).resolves.toBe(true);
    expect(store.resumingThreadIds).toEqual([]);
    expect(store.error).toBe("resume rejected");
    store.reset();
  });

  it("reuses a create-thread idempotency key when authentication recovery replays the request", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    const keys: Array<string | null> = [];
    const unsubscribe = onControlAuthenticationRequired(() => true);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/devices/device-1/threads") && init?.method === "POST") {
          keys.push(new Headers(init.headers).get("Idempotency-Key"));
          if (keys.length === 1) {
            return Promise.resolve(
              new Response(JSON.stringify({ detail: "reauth_required", code: "reauth_required" }), {
                status: 401,
                headers: { "Content-Type": "application/json" },
              }),
            );
          }
          return Promise.resolve(
            response({
              id: "thread-new",
              device_id: "device-1",
              title: "New",
              cwd: "/work/new",
              model: "model",
              updated_at: "2026-07-13T00:00:01Z",
              status: "idle",
            }),
          );
        }
        if (url.endsWith("/threads/thread-new")) {
          return Promise.resolve(
            response({
              event_cursor: "0",
              thread: {
                id: "thread-new",
                device_id: "device-1",
                title: "New",
                cwd: "/work/new",
                model: "model",
                updated_at: "2026-07-13T00:00:01Z",
                status: "idle",
                messages: [],
              },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );

    await expect(store.createThread("/work/new", "model")).resolves.toBe(true);
    expect(keys).toHaveLength(2);
    expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys[1]).toBe(keys[0]);
    unsubscribe();
    store.reset();
  });

  it("ignores a failed turn response that arrives after principal reset", async () => {
    const store = useControlStore();
    await store.bootstrap();
    let resolveTurn!: (response: Response) => void;
    const pendingTurn = new Promise<Response>((resolve) => {
      resolveTurn = resolve;
    });
    vi.stubGlobal("fetch", vi.fn(() => pendingTurn));

    const sending = store.sendTurn("old principal message");
    store.reset();
    resolveTurn(
      new Response(JSON.stringify({ detail: "request failed" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(sending).resolves.toBe(false);
    expect(store.activeThread).toBeNull();
    expect(store.turnSubmitting).toBe(false);
  });

  it("does not network-retry an idempotent mutation after its principal is reset", async () => {
    const store = useControlStore();
    await store.bootstrap();
    let rejectTurn!: (reason: unknown) => void;
    const pendingTurn = new Promise<Response>((_resolve, reject) => {
      rejectTurn = reject;
    });
    const actionFetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => pendingTurn);
    vi.stubGlobal("fetch", actionFetch);

    const sending = store.sendTurn("old principal message");
    rejectTurn(new TypeError("response lost"));
    store.reset();

    await expect(sending).resolves.toBe(false);
    expect(actionFetch).toHaveBeenCalledOnce();
  });

  it("locks an approval while its decision is in flight", async () => {
    const store = useControlStore();
    store.approvals = [
      {
        approval_id: "approval-1",
        command_id: "command-1",
        kind: "command",
        summary: "Run command",
        details: {},
        expires_at: "2099-07-13T00:02:00Z",
        device_id: "device-1",
        device_name: "Device",
        created_at: "2026-07-13T00:00:00Z",
      },
    ];
    let resolveDecision!: (response: Response) => void;
    const pendingDecision = new Promise<Response>((resolve) => {
      resolveDecision = resolve;
    });
    const actionFetch = vi.fn(() => pendingDecision);
    vi.stubGlobal("fetch", actionFetch);

    const first = store.resolveApproval("approval-1", "approve");
    await expect(store.resolveApproval("approval-1", "deny")).resolves.toBe(false);
    expect(store.decidingApprovalIds).toEqual(["approval-1"]);
    expect(actionFetch).toHaveBeenCalledOnce();

    resolveDecision(response({ state: "approved" }));
    await expect(first).resolves.toBe(true);
    expect(store.approvals).toEqual([]);
    expect(store.decidingApprovalIds).toEqual([]);
  });

  it("automatically removes an approval when its local deadline passes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T00:00:00Z"));
    const store = useControlStore();
    await store.bootstrap();

    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "approval.created",
      occurred_at: "2026-07-13T00:00:00Z",
      data: {
        approval_id: "approval-expiring",
        command_id: "command-1",
        kind: "permission",
        summary: "Grant permission",
        details: {},
        expires_at: "2026-07-13T00:00:01Z",
        device_id: "device-1",
        device_name: "Device",
        created_at: "2026-07-13T00:00:00Z",
      },
    });
    expect(store.approvals).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1_001);
    expect(store.approvals).toEqual([]);
    expect(store.error).toBe("审批已过期，已从待处理列表移除");
  });

  it.each([
    [404, "approval_not_found", "该审批已不存在，已从待处理列表移除"],
    [409, "approval_stale_epoch", "该审批已失效或已处理，已从待处理列表移除"],
    [410, "approval_expired", "该审批已过期，已从待处理列表移除"],
  ])("removes a server-invalid approval after HTTP %i", async (status, detail, message) => {
    const store = useControlStore();
    store.approvals = [
      {
        approval_id: "approval-stale",
        command_id: "command-1",
        kind: "command",
        summary: "Run command",
        details: {},
        expires_at: "2099-07-13T00:02:00Z",
        device_id: "device-1",
        device_name: "Device",
        created_at: "2026-07-13T00:00:00Z",
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({ detail }), {
        status,
        headers: { "Content-Type": "application/json" },
      }))),
    );

    await expect(store.resolveApproval("approval-stale", "approve")).resolves.toBe(false);
    expect(store.approvals).toEqual([]);
    expect(store.error).toBe(message);
    expect(store.decidingApprovalIds).toEqual([]);
  });

  it("retains an approval after a retryable server failure", async () => {
    const store = useControlStore();
    store.approvals = [
      {
        approval_id: "approval-retry",
        command_id: "command-1",
        kind: "command",
        summary: "Run command",
        details: {},
        expires_at: "2099-07-13T00:02:00Z",
        device_id: "device-1",
        device_name: "Device",
        created_at: "2026-07-13T00:00:00Z",
      },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({ detail: "temporary outage" }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      }))),
    );

    await expect(store.resolveApproval("approval-retry", "deny")).rejects.toMatchObject({ status: 503 });
    expect(store.approvals.map((approval) => approval.approval_id)).toEqual(["approval-retry"]);
    expect(store.decidingApprovalIds).toEqual([]);
  });

  it("applies deltas locally and coalesces terminal refreshes", async () => {
    vi.useFakeTimers();
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];
    expect(socket).toBeDefined();
    expect(threadFetches).toBe(1);

    socket?.message({
      cursor: "1",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-1", message_id: "message-1", delta: "hello" },
    });
    socket?.message({
      cursor: "2",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:02Z",
      data: { thread_id: "thread-1", message_id: "message-1", delta: " world" },
    });
    expect(store.activeThread?.messages[0]?.text).toBe("hello world");
    expect(threadFetches).toBe(1);

    for (let index = 0; index < 25; index += 1) {
      socket?.message({
        cursor: String(index + 3),
        type: "turn.completed",
        occurred_at: "2026-07-13T00:00:03Z",
        data: { thread_id: "thread-1" },
      });
    }
    await vi.advanceTimersByTimeAsync(300);
    await Promise.resolve();
    expect(threadFetches).toBe(2);
  });

  it("starts after the atomic snapshot watermark without duplicating snapshot text", async () => {
    const baselineFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "10",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "Thread",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:00Z",
                  status: "running",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-1")) {
          return Promise.resolve(
            response({
              event_cursor: "10",
              thread: {
                id: "thread-1",
                device_id: "device-1",
                title: "Thread",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-13T00:00:00Z",
                status: "running",
                messages: [
                    {
                      id: "message-1",
                      role: "assistant",
                      text: "hello",
                      created_at: "2026-07-13T00:00:00Z",
                    },
                  ],
              },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();

    const socket = MockWebSocket.instances[0];
    expect(new URL(socket?.url ?? "").searchParams.get("cursor")).toBe("10");
    expect(store.activeThread?.messages[0]?.text).toBe("hello");
    socket?.message({
      cursor: "11",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-1", message_id: "message-1", delta: " world" },
    });
    expect(store.activeThread?.messages[0]?.text).toBe("hello world");
    store.reset();
  });

  it("reconciles events received during a thread read against its atomic watermark", async () => {
    let resolveThread!: (value: Response) => void;
    const pendingThread = new Promise<Response>((resolve) => {
      resolveThread = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "10",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "Thread",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:00Z",
                  status: "running",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-1")) return pendingThread;
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );

    const store = useControlStore();
    const loading = store.bootstrap();
    await vi.waitFor(() => expect(MockWebSocket.instances).toHaveLength(1));
    const socket = MockWebSocket.instances[0];
    socket?.message({
      cursor: "11",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-1", message_id: "message-1", delta: " old" },
    });
    socket?.message({
      cursor: "12",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:02Z",
      data: { thread_id: "thread-1", message_id: "message-1", delta: " new" },
    });
    resolveThread(
      response({
        event_cursor: "11",
        thread: {
          id: "thread-1",
          device_id: "device-1",
          title: "Thread",
          cwd: "/work",
          model: "model",
          updated_at: "2026-07-13T00:00:01Z",
          status: "running",
          messages: [
            {
              id: "message-1",
              role: "assistant",
              text: "snapshot old",
              created_at: "2026-07-13T00:00:00Z",
            },
          ],
        },
      }),
    );
    await loading;

    expect(store.activeThread?.messages[0]?.text).toBe("snapshot old new");
    store.reset();
  });

  it("falls back to a backed-off atomic bootstrap for an incomplete unknown-thread event", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    let bootstrapReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          bootstrapReads += 1;
          return Promise.resolve(
            response({
              event_cursor: bootstrapReads === 1 ? "0" : "1",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads:
                bootstrapReads === 1
                  ? []
                  : [
                      {
                        id: "thread-new",
                        device_id: "device-1",
                        title: "Recovered",
                        cwd: "/work",
                        model: "model",
                        updated_at: "2026-07-13T00:00:01Z",
                        status: "idle",
                      },
                    ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-new")) {
          return Promise.resolve(
            response({
              event_cursor: "1",
              thread: {
                id: "thread-new",
                device_id: "device-1",
                title: "Recovered",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-13T00:00:01Z",
                status: "idle",
                messages: [],
              },
            }),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "thread.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-new", title: "partial" },
    });

    await vi.advanceTimersByTimeAsync(999);
    expect(bootstrapReads).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(bootstrapReads).toBe(2);
    expect(store.threads.map((thread) => thread.id)).toEqual(["thread-new"]);
    expect(store.activeThread?.id).toBe("thread-new");
    store.reset();
  });

  it("keeps deltas for an unselected snapshot thread and refreshes a newly announced thread on selection", async () => {
    const baselineFetch = globalThis.fetch;
    let newThreadFetches = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "10",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "First",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:02Z",
                  status: "running",
                },
                {
                  id: "thread-2",
                  device_id: "device-1",
                  title: "Second",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:01Z",
                  status: "running",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-2")) {
          return Promise.resolve(
            response({
              event_cursor: "11",
              thread: {
                id: "thread-2",
                device_id: "device-1",
                title: "Second",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-13T00:00:03Z",
                status: "running",
                messages: [
                  {
                    id: "message-2",
                    role: "assistant",
                    text: "cached delta",
                    created_at: "2026-07-13T00:00:00Z",
                  },
                ],
              },
            }),
          );
        }
        if (url.endsWith("/threads/thread-new")) {
          newThreadFetches += 1;
          return Promise.resolve(
            response({
              event_cursor: "12",
              thread: {
                id: "thread-new",
                device_id: "device-1",
                title: "New",
                cwd: "/work/new",
                model: "model",
                updated_at: "2026-07-13T00:00:04Z",
                status: "idle",
                messages: [],
              },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];

    socket?.message({
      cursor: "11",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:03Z",
      data: { thread_id: "thread-2", message_id: "message-2", delta: " delta" },
    });
    await store.selectThread("thread-2");
    expect(store.activeThread?.messages[0]?.text).toBe("cached delta");

    socket?.message({
      cursor: "12",
      type: "thread.updated",
      occurred_at: "2026-07-13T00:00:04Z",
      data: {
        thread_id: "thread-new",
        device_id: "device-1",
        title: "New",
        cwd: "/work/new",
        model: "model",
        updated_at: "2026-07-13T00:00:04Z",
        status: "idle",
      },
    });
    expect(store.threads.some((thread) => thread.id === "thread-new")).toBe(true);
    await store.selectThread("thread-new");
    expect(newThreadFetches).toBe(1);
    expect(store.activeThread?.id).toBe("thread-new");
    store.reset();
  });

  it("retains a thread announced for an unselected device until that device is selected", async () => {
    const baselineFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "10",
              devices: [
                {
                  id: "device-1",
                  name: "Online",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/one"],
                },
                {
                  id: "device-2",
                  name: "Offline",
                  status: "offline",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/two"],
                },
              ],
              threads: [],
              approvals: [],
              models_by_device: { "device-1": [], "device-2": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-2")) {
          return Promise.resolve(
            response({
              event_cursor: "11",
              thread: {
                id: "thread-2",
                device_id: "device-2",
                title: "Remote thread",
                cwd: "/two",
                model: "model",
                updated_at: "2026-07-13T00:00:01Z",
                status: "idle",
                messages: [],
              },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();

    MockWebSocket.instances[0]?.message({
      cursor: "11",
      type: "thread.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        thread_id: "thread-2",
        device_id: "device-2",
        title: "Remote thread",
        cwd: "/two",
        model: "model",
        updated_at: "2026-07-13T00:00:01Z",
        status: "idle",
      },
    });
    expect(store.threads).toEqual([]);

    await store.selectDevice("device-2");
    expect(store.threads.map((thread) => thread.id)).toEqual(["thread-2"]);
    expect(store.activeThread?.id).toBe("thread-2");
    store.reset();
  });

  it("quarantines actions and deltas while a newly selected thread detail is loading", async () => {
    let resolveSecondThread!: (value: Response) => void;
    const pendingSecondThread = new Promise<Response>((resolve) => {
      resolveSecondThread = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "0",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "First",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:02Z",
                  status: "idle",
                },
                {
                  id: "thread-2",
                  device_id: "device-1",
                  title: "Second",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:01Z",
                  status: "running",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-1")) {
          return Promise.resolve(
            response({
              event_cursor: "0",
              thread: {
                id: "thread-1",
                device_id: "device-1",
                title: "First",
                cwd: "/work",
                model: "model",
                updated_at: "2026-07-13T00:00:02Z",
                status: "idle",
                messages: [],
              },
            }),
          );
        }
        if (url.endsWith("/threads/thread-2")) return pendingSecondThread;
        throw new Error(`unexpected request: ${url}`);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();

    const selecting = store.selectThread("thread-2", false, false);
    expect(store.activeThread).toBeNull();
    await expect(store.sendTurn("must not send")).resolves.toBe(false);
    await expect(store.steerTurn("must not steer")).resolves.toBe(false);
    await expect(store.interruptTurn()).resolves.toBe(false);
    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "turn.delta",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-2", message_id: "message-2", delta: "second" },
    });
    resolveSecondThread(
      response({
        event_cursor: "0",
        thread: {
          id: "thread-2",
          device_id: "device-1",
          title: "Second",
          cwd: "/work",
          model: "model",
          updated_at: "2026-07-13T00:00:01Z",
          status: "running",
          messages: [],
        },
      }),
    );
    await selecting;
    expect(store.activeThread?.messages[0]?.text).toBe("second");

    await store.selectThread("thread-1", false, false);
    expect(store.activeThread?.messages).toEqual([]);
    store.reset();
  });

  it("retries an authoritative terminal refresh after a transient failure", async () => {
    vi.useFakeTimers();
    const baselineFetch = globalThis.fetch;
    let refreshAttempts = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/threads/thread-1")) {
          refreshAttempts += 1;
          if (refreshAttempts === 2) {
            return Promise.resolve(
              new Response(JSON.stringify({ detail: "temporary outage" }), {
                status: 503,
                headers: { "Content-Type": "application/json" },
              }),
            );
          }
          return Promise.resolve(
            response({
              event_cursor: refreshAttempts === 1 ? "0" : "1",
              thread: {
                id: "thread-1",
                device_id: "device-1",
                title: "Thread",
                cwd: "/work",
                model: "model",
                updated_at:
                  refreshAttempts === 1 ? "2026-07-13T00:00:00Z" : "2026-07-13T00:00:05Z",
                status: refreshAttempts === 1 ? "running" : "idle",
                messages:
                  refreshAttempts === 1
                    ? []
                    : [
                        {
                          id: "authoritative",
                          role: "assistant",
                          text: "complete",
                          created_at: "2026-07-13T00:00:05Z",
                        },
                      ],
              },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "turn.completed",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-1" },
    });

    await vi.advanceTimersByTimeAsync(300);
    expect(refreshAttempts).toBe(2);
    await vi.advanceTimersByTimeAsync(999);
    expect(refreshAttempts).toBe(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(refreshAttempts).toBe(3);
    expect(store.activeThread?.messages[0]?.text).toBe("complete");
    store.reset();
  });

  it("removes a missing thread after a terminal refresh without retrying permanent 404s", async () => {
    vi.useFakeTimers();
    const baselineFetch = globalThis.fetch;
    let detailReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/threads/thread-1")) {
          detailReads += 1;
          if (detailReads === 1) return baselineFetch(input, init);
          return Promise.resolve(
            new Response(JSON.stringify({ detail: "thread_not_found" }), {
              status: 404,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "turn.completed",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { thread_id: "thread-1" },
    });

    await vi.advanceTimersByTimeAsync(300);
    expect(detailReads).toBe(2);
    expect(store.threads).toEqual([]);
    expect(store.activeThread).toBeNull();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(detailReads).toBe(2);
    store.reset();
  });

  it("removes a stale summary when its first direct detail read returns 404", async () => {
    const baselineFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            response({
              event_cursor: "0",
              devices: [
                {
                  id: "device-1",
                  name: "Device",
                  status: "online",
                  connector_version: "0.1.0",
                  codex_version: "0.147.0",
                  last_seen_at: null,
                  workspace_roots: ["/work"],
                },
              ],
              threads: [
                {
                  id: "thread-1",
                  device_id: "device-1",
                  title: "Current",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:02Z",
                  status: "idle",
                },
                {
                  id: "thread-stale",
                  device_id: "device-1",
                  title: "Stale",
                  cwd: "/work",
                  model: "model",
                  updated_at: "2026-07-13T00:00:01Z",
                  status: "idle",
                },
              ],
              approvals: [],
              models_by_device: { "device-1": [] },
            }),
          );
        }
        if (url.endsWith("/threads/thread-stale")) {
          return Promise.resolve(
            new Response(JSON.stringify({ detail: "thread_not_found" }), {
              status: 404,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();

    await store.selectThread("thread-stale", false, false);
    expect(store.threads.map((thread) => thread.id)).toEqual(["thread-1"]);
    expect(store.selectedThreadId).toBe("thread-1");
    expect(store.activeThread?.id).toBe("thread-1");
    store.reset();
  });

  it("syncs only on explicit online selection and coalesces duplicate requests within the cooldown", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T00:00:00Z"));
    const baselineFetch = globalThis.fetch;
    const syncCalls: Array<[string, RequestInit | undefined]> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (init?.method === "POST" && url.endsWith("/sync")) {
          syncCalls.push([url, init]);
          return Promise.resolve(response({ id: crypto.randomUUID(), state: "queued", method: "thread/list" }));
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    expect(syncCalls).toEqual([]);

    await Promise.all([store.selectDevice("device-1"), store.selectDevice("device-1")]);
    expect(syncCalls.map(([url]) => url).sort()).toEqual(
      [
        "/codex-api/v1/devices/device-1/models/sync",
        "/codex-api/v1/devices/device-1/threads/sync",
        "/codex-api/v1/threads/thread-1/sync",
      ].sort(),
    );
    for (const [, init] of syncCalls) {
      expect(new Headers(init?.headers).get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    }

    await vi.advanceTimersByTimeAsync(29_999);
    await store.selectDevice("device-1");
    expect(syncCalls).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(1);
    await store.selectDevice("device-1");
    expect(syncCalls).toHaveLength(6);
    store.reset();
  });

  it("reuses the same sync idempotency key when a 401 recovery retries the request", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    const threadSyncKeys: Array<string | null> = [];
    const unsubscribe = onControlAuthenticationRequired(() => true);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (init?.method === "POST" && url.endsWith("/threads/thread-1/sync")) {
          threadSyncKeys.push(new Headers(init.headers).get("Idempotency-Key"));
          if (threadSyncKeys.length === 1) {
            return Promise.resolve(
              new Response(JSON.stringify({ detail: "reauth_required", code: "reauth_required" }), {
                status: 401,
                headers: { "Content-Type": "application/json" },
              }),
            );
          }
          return Promise.resolve(response({ id: "command-thread", state: "queued", method: "thread/read" }));
        }
        if (init?.method === "POST" && url.endsWith("/sync")) {
          return Promise.resolve(response({ id: "command-device", state: "queued", method: "thread/list" }));
        }
        return baselineFetch(input, init);
      }),
    );

    await store.syncSelection(true);
    expect(threadSyncKeys).toHaveLength(2);
    expect(threadSyncKeys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(threadSyncKeys[1]).toBe(threadSyncKeys[0]);
    unsubscribe();
    store.reset();
  });

  it("keeps in-flight sync operations coalesced across a same-principal bootstrap", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    const syncResolvers: Array<(value: Response) => void> = [];
    const syncUrls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (init?.method === "POST" && url.endsWith("/sync")) {
          syncUrls.push(url);
          return new Promise<Response>((resolve) => syncResolvers.push(resolve));
        }
        return baselineFetch(input, init);
      }),
    );

    const initialSync = store.syncSelection(true);
    await vi.waitFor(() => expect(syncUrls).toHaveLength(2));
    await store.bootstrap();
    const selecting = store.selectDevice("device-1");
    await Promise.resolve();
    expect(syncUrls).toHaveLength(2);
    for (const resolve of syncResolvers.slice(0, 2)) {
      resolve(response({ id: crypto.randomUUID(), state: "queued", method: "thread/list" }));
    }
    await vi.waitFor(() => expect(syncUrls).toHaveLength(3));
    syncResolvers[2]?.(response({ id: crypto.randomUUID(), state: "queued", method: "thread/read" }));
    await Promise.all([initialSync, selecting]);
    expect(syncUrls).toHaveLength(3);
    store.reset();
  });

  it("replays control_session_required sync once with the original idempotency key", async () => {
    const unsubscribe = onControlAuthenticationRequired(() => true);
    const baselineFetch = globalThis.fetch;
    const retriedKeys: string[] = [];
    let targetCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/devices/device-1/threads/sync")) {
          targetCalls += 1;
          retriedKeys.push(new Headers(init?.headers).get("Idempotency-Key") ?? "");
          if (targetCalls === 1) {
            return Promise.resolve(
              new Response(JSON.stringify({ detail: "control_session_required" }), {
                status: 401,
                headers: { "Content-Type": "application/json" },
              }),
            );
          }
          return Promise.resolve(response({ id: "sync-threads", state: "queued", method: "thread/list" }));
        }
        if (init?.method === "POST" && url.endsWith("/sync")) {
          return Promise.resolve(response({ id: crypto.randomUUID(), state: "queued", method: "thread/read" }));
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();

    await store.selectDevice("device-1");

    expect(targetCalls).toBe(2);
    expect(retriedKeys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(retriedKeys[1]).toBe(retriedKeys[0]);
    unsubscribe();
    store.reset();
  });

  it("syncs device caches once when a device transitions from offline to online", async () => {
    const baselineFetch = globalThis.fetch;
    const syncUrls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (init?.method === "POST" && url.endsWith("/sync")) {
          syncUrls.push(url);
          return Promise.resolve(response({ id: crypto.randomUUID(), state: "queued", method: "thread/list" }));
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];
    const device = {
      id: "device-1",
      name: "Device",
      connector_version: "0.1.0",
      codex_version: "0.147.0",
      last_seen_at: null,
      workspace_roots: ["/work"],
    };
    socket?.message({
      cursor: "1",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: { ...device, status: "offline" },
    });
    socket?.message({
      cursor: "2",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:02Z",
      data: { ...device, status: "online" },
    });
    socket?.message({
      cursor: "3",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:03Z",
      data: { ...device, status: "online" },
    });
    await vi.waitFor(() => expect(syncUrls).toHaveLength(3));
    expect(syncUrls.sort()).toEqual(
      [
        "/codex-api/v1/devices/device-1/models/sync",
        "/codex-api/v1/devices/device-1/threads/sync",
        "/codex-api/v1/threads/thread-1/sync",
      ].sort(),
    );
    store.reset();
  });

  it("refreshes the model catalog after a successful model-list command event", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const baselineFetch = globalThis.fetch;
    let modelReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/devices/device-1/models")) {
          modelReads += 1;
          return Promise.resolve(
            response({ items: [{ id: "model-new", display_name: "New model" }] }),
          );
        }
        return baselineFetch(input, init);
      }),
    );

    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "command.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        device_id: "device-1",
        command: { id: "command-1", method: "model/list", state: "succeeded" },
      },
    });

    await vi.waitFor(() => expect(store.models.map((model) => model.id)).toEqual(["model-new"]));
    expect(modelReads).toBe(1);
    store.reset();
  });

  it("performs a follow-up model read when another catalog command completes during an active read", async () => {
    const store = useControlStore();
    await store.bootstrap();
    let resolveFirstRead!: (value: Response) => void;
    const firstRead = new Promise<Response>((resolve) => {
      resolveFirstRead = resolve;
    });
    let modelReads = 0;
    const baselineFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/devices/device-1/models")) {
          modelReads += 1;
          if (modelReads === 1) return firstRead;
          return Promise.resolve(
            response({ items: [{ id: "model-second", display_name: "Second catalog" }] }),
          );
        }
        return baselineFetch(input, init);
      }),
    );
    const socket = MockWebSocket.instances[0];
    const commandEvent = (cursor: string): BrowserEvent => ({
      cursor,
      type: "command.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        device_id: "device-1",
        command: { id: `command-${cursor}`, method: "model/list", state: "succeeded" },
      },
    });

    socket?.message(commandEvent("1"));
    await vi.waitFor(() => expect(modelReads).toBe(1));
    socket?.message(commandEvent("2"));
    resolveFirstRead(response({ items: [{ id: "model-first", display_name: "First catalog" }] }));

    await vi.waitFor(() => expect(store.models.map((model) => model.id)).toEqual(["model-second"]));
    expect(modelReads).toBe(2);
    store.reset();
  });

  it("cascades a revoked device event through its cached thread state", async () => {
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];

    socket?.message({
      cursor: "1",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        id: "device-1",
        name: "Device",
        status: "revoked",
        connector_version: "0.1.0",
        codex_version: "0.147.0",
        last_seen_at: null,
        workspace_roots: ["/work"],
      },
    });
    socket?.message({
      cursor: "2",
      type: "thread.updated",
      occurred_at: "2026-07-13T00:00:02Z",
      data: {
        thread_id: "thread-1",
        device_id: "device-1",
        title: "Must stay removed",
        cwd: "/work",
        model: "model",
        updated_at: "2026-07-13T00:00:02Z",
        status: "idle",
      },
    });

    expect(store.devices).toEqual([]);
    expect(store.threads).toEqual([]);
    expect(store.selectedDeviceId).toBeNull();
    expect(store.selectedThreadId).toBeNull();
    expect(store.activeThread).toBeNull();
    expect(store.connectorRelease).toEqual(connectorReleaseMetadata);
    store.reset();
  });

  it("does not reconnect after WebSocket close 4401 and requests session renewal", async () => {
    vi.useFakeTimers();
    let authenticationFailures = 0;
    const unsubscribe = onControlAuthenticationRequired(() => {
      authenticationFailures += 1;
    });
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];

    socket?.serverClose(4401);
    expect(store.live).toBe("offline");
    expect(authenticationFailures).toBe(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(1);

    unsubscribe();
    store.reset();
  });

  it("backs off after a non-authentication close and resumes from the last committed cursor", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    const store = useControlStore();
    await store.bootstrap();
    const socket = MockWebSocket.instances[0];
    socket?.message({
      cursor: "42",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        id: "device-1",
        name: "Device",
        status: "online",
        connector_version: "0.1.0",
        codex_version: "0.147.0",
        last_seen_at: null,
        workspace_roots: ["/work"],
      },
    });

    socket?.serverClose(1012);
    expect(store.live).toBe("offline");
    await vi.advanceTimersByTimeAsync(999);
    expect(MockWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);

    expect(MockWebSocket.instances).toHaveLength(2);
    const resumed = new URL(MockWebSocket.instances[1]?.url ?? "");
    expect(resumed.searchParams.get("cursor")).toBe("42");
    store.reset();
  });

  it.each([1013, 4429])(
    "backs off after WebSocket close %s without requesting session renewal",
    async (closeCode) => {
      vi.useFakeTimers();
      vi.spyOn(Math, "random").mockReturnValue(1);
      let authenticationFailures = 0;
      const unsubscribe = onControlAuthenticationRequired(() => {
        authenticationFailures += 1;
      });
      const store = useControlStore();
      await store.bootstrap();

      MockWebSocket.instances[0]?.serverClose(closeCode);
      expect(store.live).toBe("offline");
      expect(authenticationFailures).toBe(0);
      await vi.advanceTimersByTimeAsync(999);
      expect(MockWebSocket.instances).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(MockWebSocket.instances).toHaveLength(2);
      expect(authenticationFailures).toBe(0);

      unsubscribe();
      store.reset();
    },
  );

  it("keeps exponential backoff across accept-then-drop loops and stops on terminal close codes", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    const store = useControlStore();
    await store.bootstrap();

    MockWebSocket.instances[0]?.serverOpen();
    MockWebSocket.instances[0]?.serverClose(1006);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(MockWebSocket.instances).toHaveLength(2);

    MockWebSocket.instances[1]?.serverOpen();
    MockWebSocket.instances[1]?.serverClose(1006);
    await vi.advanceTimersByTimeAsync(1_999);
    expect(MockWebSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(MockWebSocket.instances).toHaveLength(3);

    MockWebSocket.instances[2]?.serverClose(4403);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(MockWebSocket.instances).toHaveLength(3);
    expect(store.error).toBe("实时连接被拒绝");
    store.reset();
  });

  it("replaces an invalid cursor through atomic bootstrap after WebSocket close 4409", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    const store = useControlStore();
    bootstrapCursor = "10";
    await store.bootstrap();
    expect(new URL(MockWebSocket.instances[0]?.url ?? "").searchParams.get("cursor")).toBe("10");

    bootstrapCursor = "90";
    MockWebSocket.instances[0]?.serverClose(4409);
    await vi.advanceTimersByTimeAsync(999);
    expect(MockWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(MockWebSocket.instances).toHaveLength(2);
    expect(new URL(MockWebSocket.instances[1]?.url ?? "").searchParams.get("cursor")).toBe("90");
    store.reset();
  });

  it("backs off and retries atomic bootstrap when 4409 recovery hits a transient failure", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    const baselineFetch = globalThis.fetch;
    let bootstrapReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          bootstrapReads += 1;
          if (bootstrapReads === 2) {
            return Promise.resolve(
              new Response(JSON.stringify({ detail: "temporary outage" }), {
                status: 503,
                headers: { "Content-Type": "application/json" },
              }),
            );
          }
          if (bootstrapReads === 3) bootstrapCursor = "90";
        }
        return baselineFetch(input, init);
      }),
    );
    const store = useControlStore();
    bootstrapCursor = "10";
    await store.bootstrap();

    MockWebSocket.instances[0]?.serverClose(4409);
    await vi.advanceTimersByTimeAsync(999);
    expect(bootstrapReads).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(bootstrapReads).toBe(2);
    await vi.advanceTimersByTimeAsync(1_999);
    expect(MockWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(MockWebSocket.instances).toHaveLength(2);
    expect(new URL(MockWebSocket.instances[1]?.url ?? "").searchParams.get("cursor")).toBe("90");
    store.reset();
  });

  it("keeps backing off when each replacement cursor socket immediately closes 4409", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);
    const store = useControlStore();
    await store.bootstrap();

    MockWebSocket.instances[0]?.serverClose(4409);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(MockWebSocket.instances).toHaveLength(2);
    MockWebSocket.instances[1]?.serverClose(4409);
    await vi.advanceTimersByTimeAsync(1_999);
    expect(MockWebSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(MockWebSocket.instances).toHaveLength(3);
    store.reset();
  });

  it("replaces the event cursor with the new atomic baseline after renewal", async () => {
    const store = useControlStore();
    bootstrapCursor = "50";
    await store.bootstrap();
    MockWebSocket.instances[0]?.message({
      cursor: "43",
      type: "device.updated",
      occurred_at: "2026-07-13T00:00:01Z",
      data: {
        id: "device-1",
        name: "Device",
        status: "online",
        connector_version: "0.1.0",
        codex_version: "0.147.0",
        last_seen_at: null,
        workspace_roots: ["/work"],
      },
    });

    await store.bootstrap();

    expect(MockWebSocket.instances).toHaveLength(2);
    const resumed = new URL(MockWebSocket.instances[1]?.url ?? "");
    expect(resumed.searchParams.get("cursor")).toBe("50");
    store.reset();
  });

  it("locks a local archive request and removes the selected thread after success", async () => {
    const store = useControlStore();
    await store.bootstrap();
    let resolveArchive!: (response: Response) => void;
    const pendingArchive = new Promise<Response>((resolve) => {
      resolveArchive = resolve;
    });
    const archiveFetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => pendingArchive);
    vi.stubGlobal("fetch", archiveFetch);

    const first = store.archiveThread("thread-1");
    await expect(store.archiveThread("thread-1")).resolves.toBe(false);
    expect(store.archivingThreadIds).toEqual(["thread-1"]);
    expect(archiveFetch).toHaveBeenCalledOnce();
    expect(String(archiveFetch.mock.calls[0]?.[0])).toMatch(/\/threads\/thread-1$/);
    expect(archiveFetch.mock.calls[0]?.[1]?.method).toBe("DELETE");

    resolveArchive(new Response(null, { status: 204 }));
    await expect(first).resolves.toBe(true);
    expect(store.archivingThreadIds).toEqual([]);
    expect(store.threads).toEqual([]);
    expect(store.selectedThreadId).toBeNull();
    expect(store.activeThread).toBeNull();
    store.reset();
  });

  it("removes a thread when another client publishes its durable archive event", async () => {
    const store = useControlStore();
    await store.bootstrap();

    MockWebSocket.instances[0]?.message({
      cursor: "1",
      type: "thread.updated",
      occurred_at: "2026-07-30T00:00:01Z",
      data: { thread_id: "thread-1", archived: true },
    });

    expect(store.threads).toEqual([]);
    expect(store.selectedThreadId).toBeNull();
    expect(store.activeThread).toBeNull();
    store.reset();
  });

  it("signals session renewal when a Control API request returns HTTP 401", async () => {
    let authenticationFailures = 0;
    const unsubscribe = onControlAuthenticationRequired(() => {
      authenticationFailures += 1;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/bootstrap")) {
          return Promise.resolve(
            new Response(JSON.stringify({ detail: "control session expired" }), {
              status: 401,
              headers: { "Content-Type": "application/json" },
            }),
          );
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );

    const store = useControlStore();
    await store.bootstrap();

    expect(authenticationFailures).toBe(1);
    expect(MockWebSocket.instances).toHaveLength(0);
    unsubscribe();
  });
});
