import type { BrowserEvent } from "@sub2api-codex/control-protocol";
import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { ApiError, apiRequest, browserWebSocketUrl, notifyControlAuthenticationRequired } from "@/api/client";
import type {
  ApprovalItem,
  ControlBootstrapSnapshot,
  DeviceSummary,
  ManagedThreadSummary,
  ModelOption,
  PairingClaim,
  ThreadDetail,
  ThreadDetailSnapshot,
} from "@/types";

interface ThreadReadOperation {
  events: BrowserEvent[];
  promise: Promise<ThreadDetail | null>;
}

type CommandState =
  | "queued"
  | "dispatched"
  | "acknowledged"
  | "succeeded"
  | "failed"
  | "denied"
  | "cancelled"
  | "expired";
type TerminalCommandState = Exclude<CommandState, "queued" | "dispatched" | "acknowledged">;

interface CommandView {
  id: string;
  state: CommandState;
  method: string;
  error_message?: string | null;
}

interface ResumeCommandUpdate {
  state: TerminalCommandState;
  errorMessage: string | null;
}

export const useControlStore = defineStore("control", () => {
  const SYNC_COOLDOWN_MS = 30_000;
  const devices = ref<DeviceSummary[]>([]);
  const threads = ref<ManagedThreadSummary[]>([]);
  const models = ref<ModelOption[]>([]);
  const activeThread = ref<ThreadDetail | null>(null);
  const approvals = ref<ApprovalItem[]>([]);
  const selectedDeviceId = ref<string | null>(null);
  const selectedThreadId = ref<string | null>(null);
  const loading = ref(false);
  const turnSubmitting = ref(false);
  const decidingApprovalIds = ref<string[]>([]);
  const archivingThreadIds = ref<string[]>([]);
  const resumingThreadIds = ref<string[]>([]);
  const live = ref<"connecting" | "online" | "offline">("offline");
  const error = ref<string | null>(null);
  const lastCursor = ref<string | null>(null);
  const threadDetails = new Map<string, ThreadDetail>();
  const threadSummariesById = new Map<string, ManagedThreadSummary>();
  const threadWatermarks = new Map<string, string>();
  const threadReadOperations = new Map<string, ThreadReadOperation>();
  const modelsByDevice = new Map<string, ModelOption[]>();
  const snapshotDeviceIds = new Set<string>();
  const dirtyThreadIds = new Set<string>();
  const removedThreadIds = new Set<string>();
  let socket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let stableConnectionTimer: number | null = null;
  let cursorStabilityTimer: number | null = null;
  let cursorRecoveryTimer: number | null = null;
  let threadRefreshTimer: number | null = null;
  let threadRefreshAttempt = 0;
  let reconnectAttempt = 0;
  let cursorRecoveryAttempt = 0;
  let cursorRecoveryGeneration = 0;
  let cursorRecoveryPending = false;
  let cursorRecoveryPromise: Promise<boolean> | null = null;
  let lastBootstrapError: unknown = null;
  let connectionGeneration = 0;
  let stateGeneration = 0;
  let principalGeneration = 0;
  let principalAbortController = new AbortController();
  let threadRequestGeneration = 0;
  let turnOperation: symbol | null = null;
  const approvalDecisionOperations = new Map<string, symbol>();
  const archiveThreadOperations = new Map<string, symbol>();
  const resumeThreadOperations = new Map<string, symbol>();
  const resumeCommandThreads = new Map<string, string>();
  const earlyResumeCommandUpdates = new Map<string, ResumeCommandUpdate>();
  const syncOperations = new Map<string, Promise<boolean>>();
  const syncStartedAt = new Map<string, number>();
  const modelReadOperations = new Map<string, Promise<void>>();
  const modelRefreshTimers = new Map<string, number>();
  const modelRefreshAttempts = new Map<string, number>();
  const modelRefreshPending = new Set<string>();

  const selectedDevice = computed(
    () => devices.value.find((device) => device.id === selectedDeviceId.value) ?? null,
  );
  const pendingApprovals = computed(() => approvals.value.length);

  async function bootstrap(cursorRecovery = false): Promise<boolean> {
    if (!cursorRecovery) cancelCursorRecovery();
    resetView();
    const generation = stateGeneration;
    loading.value = true;
    error.value = null;
    lastBootstrapError = null;
    try {
      const snapshot = await apiRequest<ControlBootstrapSnapshot>("/bootstrap");
      if (generation !== stateGeneration) return false;
      devices.value = snapshot.devices;
      approvals.value = snapshot.approvals;
      lastCursor.value = snapshot.event_cursor;
      for (const thread of snapshot.threads) threadSummariesById.set(thread.id, thread);
      for (const device of snapshot.devices) snapshotDeviceIds.add(device.id);
      for (const [deviceId, catalog] of Object.entries(snapshot.models_by_device)) {
        modelsByDevice.set(deviceId, catalog);
      }
      const preferred = devices.value.find((device) => device.status === "online") ?? devices.value[0];
      const firstThreadId = preferred ? selectSnapshotDevice(preferred.id) : null;
      connectEvents();
      lastBootstrapError = null;
      if (firstThreadId) {
        try {
          await selectThread(firstThreadId, false, false);
        } catch (threadError) {
          if (generation === stateGeneration) handleThreadRefreshFailure(firstThreadId, threadError);
        }
      }
      return generation === stateGeneration;
    } catch (bootstrapError) {
      if (generation !== stateGeneration) return false;
      lastBootstrapError = bootstrapError;
      error.value = bootstrapError instanceof Error ? bootstrapError.message : "无法加载设备";
      return false;
    } finally {
      if (generation === stateGeneration) loading.value = false;
    }
  }

  function threadSummary(thread: ThreadDetail): ManagedThreadSummary {
    return {
      id: thread.id,
      device_id: thread.device_id,
      title: thread.title,
      cwd: thread.cwd,
      model: thread.model,
      updated_at: thread.updated_at,
      status: thread.status,
    };
  }

  function compareCursors(left: string, right: string): number {
    const leftValue = BigInt(left);
    const rightValue = BigInt(right);
    return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
  }

  function readThreadDetail(threadId: string): Promise<ThreadDetail | null> {
    const active = threadReadOperations.get(threadId);
    if (active) return active.promise;

    const generation = stateGeneration;
    const operation: ThreadReadOperation = {
      events: [],
      promise: Promise.resolve(null),
    };
    operation.promise = (async () => {
      const snapshot = await apiRequest<ThreadDetailSnapshot>(`/threads/${threadId}`);
      if (generation !== stateGeneration || removedThreadIds.has(threadId)) return null;
      if (snapshot.thread.id !== threadId) throw new Error("Control API returned a mismatched thread snapshot");

      const detail = snapshot.thread;
      threadWatermarks.set(threadId, snapshot.event_cursor);
      threadDetails.set(threadId, detail);
      threadSummariesById.set(threadId, threadSummary(detail));
      if (detail.status !== "failed") finishThreadResume(threadId);
      dirtyThreadIds.delete(threadId);
      if (selectedThreadId.value === threadId) activeThread.value = detail;
      refreshSelectedThreadSummaries();

      const replay = operation.events
        .filter((event) => compareCursors(event.cursor, snapshot.event_cursor) > 0)
        .sort((left, right) => compareCursors(left.cursor, right.cursor));
      for (const event of replay) applyThreadEventMutation(event);
      return detail;
    })().finally(() => {
      if (threadReadOperations.get(threadId) === operation) threadReadOperations.delete(threadId);
    });
    threadReadOperations.set(threadId, operation);
    return operation.promise;
  }

  function summariesForDevice(deviceId: string): ManagedThreadSummary[] {
    return [...threadSummariesById.values()]
      .filter((thread) => thread.device_id === deviceId)
      .sort((left, right) => right.updated_at.localeCompare(left.updated_at));
  }

  function refreshSelectedThreadSummaries(): void {
    const deviceId = selectedDeviceId.value;
    threads.value = deviceId ? summariesForDevice(deviceId) : [];
  }

  function selectSnapshotDevice(deviceId: string): string | null {
    threadRequestGeneration += 1;
    selectedDeviceId.value = deviceId;
    threads.value = summariesForDevice(deviceId);
    models.value = modelsByDevice.get(deviceId) ?? [];
    const firstThreadId = threads.value[0]?.id ?? null;
    selectedThreadId.value = firstThreadId;
    activeThread.value = firstThreadId ? (threadDetails.get(firstThreadId) ?? null) : null;
    return firstThreadId;
  }

  async function selectDevice(deviceId: string): Promise<void> {
    if (snapshotDeviceIds.has(deviceId)) {
      const firstThreadId = selectSnapshotDevice(deviceId);
      if (firstThreadId && (!threadDetails.has(firstThreadId) || dirtyThreadIds.has(firstThreadId))) {
        await selectThread(firstThreadId, false, false);
      }
      await syncDevice(deviceId);
      if (selectedThreadId.value) await syncThread(selectedThreadId.value);
      return;
    }
    const principalAtRequest = principalGeneration;
    const loaded = await bootstrap();
    if (loaded && principalAtRequest === principalGeneration && snapshotDeviceIds.has(deviceId)) {
      await selectDevice(deviceId);
    }
  }

  async function selectThread(threadId: string, force = false, synchronize = true): Promise<void> {
    selectedThreadId.value = threadId;
    const cached = threadDetails.get(threadId);
    activeThread.value = cached ?? null;
    if (cached && !force && !dirtyThreadIds.has(threadId)) {
      threadRequestGeneration += 1;
      if (synchronize) await syncThread(threadId);
      return;
    }
    const stateAtRequest = stateGeneration;
    const generation = ++threadRequestGeneration;
    let thread: ThreadDetail | null;
    try {
      thread = await readThreadDetail(threadId);
    } catch (selectionError) {
      if (
        stateAtRequest !== stateGeneration ||
        generation !== threadRequestGeneration ||
        selectedThreadId.value !== threadId
      ) {
        return;
      }
      if (selectionError instanceof ApiError && (selectionError.status === 404 || selectionError.status === 410)) {
        error.value = selectionError.message;
        removeMissingThread(threadId);
        return;
      }
      throw selectionError;
    }
    if (
      thread &&
      stateAtRequest === stateGeneration &&
      generation === threadRequestGeneration &&
      selectedThreadId.value === threadId
    ) {
      threadDetails.set(thread.id, thread);
      activeThread.value = thread;
      if (synchronize) await syncThread(threadId);
    }
  }

  async function createThread(cwd: string, model?: string): Promise<boolean> {
    const deviceId = selectedDeviceId.value;
    if (!deviceId) return false;
    const principalAtRequest = principalGeneration;
    const idempotencyKey = crypto.randomUUID();
    let thread: ManagedThreadSummary;
    try {
      thread = await apiRequest<ManagedThreadSummary>(`/devices/${deviceId}/threads`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({ cwd, model }),
        signal: principalAbortController.signal,
      });
    } catch (createError) {
      if (principalAtRequest !== principalGeneration) return false;
      throw createError;
    }
    if (principalAtRequest !== principalGeneration || selectedDeviceId.value !== deviceId) return false;
    removedThreadIds.delete(thread.id);
    threadSummariesById.set(thread.id, thread);
    refreshSelectedThreadSummaries();
    try {
      await selectThread(thread.id, false, false);
    } catch (selectionError) {
      if (principalAtRequest !== principalGeneration || selectedDeviceId.value !== deviceId) return false;
      throw selectionError;
    }
    return principalAtRequest === principalGeneration && selectedThreadId.value === thread.id;
  }

  async function archiveThread(threadId: string): Promise<boolean> {
    if (!threadSummariesById.has(threadId) || archiveThreadOperations.has(threadId)) return false;
    const operation = Symbol("archive-thread");
    const principalAtRequest = principalGeneration;
    archiveThreadOperations.set(threadId, operation);
    archivingThreadIds.value = [...archivingThreadIds.value, threadId];
    try {
      await apiRequest<void>(`/threads/${threadId}`, {
        method: "DELETE",
        signal: principalAbortController.signal,
      });
      if (principalAtRequest !== principalGeneration) return false;
      removeMissingThread(threadId);
      return true;
    } catch (archiveError) {
      if (principalAtRequest !== principalGeneration) return false;
      if (archiveError instanceof ApiError && (archiveError.status === 404 || archiveError.status === 410)) {
        removeMissingThread(threadId);
        return true;
      }
      throw archiveError;
    } finally {
      if (archiveThreadOperations.get(threadId) === operation) {
        archiveThreadOperations.delete(threadId);
        archivingThreadIds.value = archivingThreadIds.value.filter((item) => item !== threadId);
      }
    }
  }

  async function sendTurn(text: string): Promise<boolean> {
    const threadId = selectedThreadId.value;
    const threadAtRequest = activeThread.value;
    if (
      !threadId ||
      !threadAtRequest ||
      threadAtRequest.id !== threadId ||
      threadAtRequest.status === "failed" ||
      turnOperation !== null
    ) {
      return false;
    }
    const operation = Symbol("turn-operation");
    const principalAtRequest = principalGeneration;
    turnOperation = operation;
    turnSubmitting.value = true;
    const idempotencyKey = crypto.randomUUID();
    const optimisticId = idempotencyKey;
    threadAtRequest.messages.push({
      id: optimisticId,
      role: "user",
      text,
      created_at: new Date().toISOString(),
      pending: true,
    });
    try {
      await apiRequest(`/threads/${threadId}/turns`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({ text }),
        signal: principalAbortController.signal,
      });
    } catch (sendError) {
      const currentTarget =
        principalAtRequest === principalGeneration &&
        selectedThreadId.value === threadId &&
        activeThread.value === threadAtRequest;
      if (!currentTarget) return false;
      const message = threadAtRequest.messages.find((item) => item.id === optimisticId);
      if (message) {
        message.pending = false;
        message.error = true;
      }
      throw sendError;
    } finally {
      if (turnOperation === operation) {
        turnOperation = null;
        turnSubmitting.value = false;
      }
    }
    return principalAtRequest === principalGeneration && selectedThreadId.value === threadId;
  }

  async function steerTurn(text: string): Promise<boolean> {
    const threadId = selectedThreadId.value;
    if (!threadId || activeThread.value?.id !== threadId || turnOperation !== null) return false;
    const operation = Symbol("turn-operation");
    const principalAtRequest = principalGeneration;
    turnOperation = operation;
    turnSubmitting.value = true;
    try {
      await apiRequest(`/threads/${threadId}/turns/current/steer`, {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ text }),
        signal: principalAbortController.signal,
      });
      return principalAtRequest === principalGeneration && selectedThreadId.value === threadId;
    } catch (steerError) {
      if (principalAtRequest !== principalGeneration || selectedThreadId.value !== threadId) return false;
      throw steerError;
    } finally {
      if (turnOperation === operation) {
        turnOperation = null;
        turnSubmitting.value = false;
      }
    }
  }

  async function interruptTurn(): Promise<boolean> {
    const threadId = selectedThreadId.value;
    if (!threadId || activeThread.value?.id !== threadId) return false;
    const principalAtRequest = principalGeneration;
    try {
      await apiRequest(`/threads/${threadId}/turns/current/interrupt`, {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        signal: principalAbortController.signal,
      });
      return principalAtRequest === principalGeneration && selectedThreadId.value === threadId;
    } catch (interruptError) {
      if (principalAtRequest !== principalGeneration || selectedThreadId.value !== threadId) return false;
      throw interruptError;
    }
  }

  function finishThreadResume(threadId: string): void {
    resumeThreadOperations.delete(threadId);
    resumingThreadIds.value = resumingThreadIds.value.filter((item) => item !== threadId);
    for (const [commandId, commandThreadId] of resumeCommandThreads) {
      if (commandThreadId === threadId) {
        resumeCommandThreads.delete(commandId);
        earlyResumeCommandUpdates.delete(commandId);
      }
    }
  }

  function isTerminalCommandState(state: string): state is TerminalCommandState {
    return ["succeeded", "failed", "denied", "cancelled", "expired"].includes(state);
  }

  function applyResumeCommandUpdate(threadId: string, update: ResumeCommandUpdate): void {
    if (update.state === "succeeded") scheduleThreadRefresh(threadId, false);
    else {
      finishThreadResume(threadId);
      error.value = update.errorMessage || "线程恢复失败";
    }
  }

  async function resumeThread(): Promise<boolean> {
    const threadId = selectedThreadId.value;
    const threadAtRequest = activeThread.value;
    if (
      !threadId ||
      !threadAtRequest ||
      threadAtRequest.id !== threadId ||
      threadAtRequest.status !== "failed" ||
      selectedDevice.value?.status !== "online" ||
      resumeThreadOperations.has(threadId)
    ) {
      return false;
    }

    const operation = Symbol("resume-thread");
    const principalAtRequest = principalGeneration;
    resumeThreadOperations.set(threadId, operation);
    resumingThreadIds.value = [...resumingThreadIds.value, threadId];
    try {
      const command = await apiRequest<CommandView>(`/threads/${threadId}/resume`, {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        signal: principalAbortController.signal,
      });
      if (principalAtRequest !== principalGeneration) return false;
      if (command.method !== "thread/resume") throw new Error("Control API returned a mismatched resume command");
      resumeCommandThreads.set(command.id, threadId);
      const earlyUpdate = earlyResumeCommandUpdates.get(command.id);
      earlyResumeCommandUpdates.delete(command.id);
      if (threadDetails.get(threadId)?.status !== "failed") {
        finishThreadResume(threadId);
      } else if (earlyUpdate) {
        applyResumeCommandUpdate(threadId, earlyUpdate);
      } else if (isTerminalCommandState(command.state)) {
        applyResumeCommandUpdate(threadId, {
          state: command.state,
          errorMessage: command.error_message ?? null,
        });
      }
      return true;
    } catch (resumeError) {
      if (principalAtRequest !== principalGeneration) return false;
      finishThreadResume(threadId);
      throw resumeError;
    }
  }

  async function claimPairing(code: string): Promise<string | null> {
    const principalAtRequest = principalGeneration;
    try {
      const claim = await apiRequest<PairingClaim>("/pairings/claim", {
        method: "POST",
        body: JSON.stringify({ code }),
        signal: principalAbortController.signal,
      });
      return principalAtRequest === principalGeneration ? claim.device_id : null;
    } catch (claimError) {
      if (principalAtRequest !== principalGeneration) return null;
      throw claimError;
    }
  }

  async function revokeDevice(deviceId: string): Promise<boolean> {
    const principalAtRequest = principalGeneration;
    try {
      await apiRequest<void>(`/devices/${deviceId}`, {
        method: "DELETE",
        signal: principalAbortController.signal,
      });
    } catch (revokeError) {
      if (principalAtRequest !== principalGeneration) return false;
      throw revokeError;
    }
    if (principalAtRequest !== principalGeneration) return false;
    removeRevokedDevice(deviceId);
    return true;
  }

  async function resolveApproval(approvalId: string, decision: "approve" | "deny"): Promise<boolean> {
    if (approvalDecisionOperations.has(approvalId)) return false;
    const operation = Symbol("approval-decision");
    const principalAtRequest = principalGeneration;
    approvalDecisionOperations.set(approvalId, operation);
    decidingApprovalIds.value = [...decidingApprovalIds.value, approvalId];
    try {
      await apiRequest(`/approvals/${approvalId}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision }),
        signal: principalAbortController.signal,
      });
      if (principalAtRequest !== principalGeneration) return false;
      approvals.value = approvals.value.filter((approval) => approval.approval_id !== approvalId);
      return true;
    } catch (approvalError) {
      if (principalAtRequest !== principalGeneration) return false;
      throw approvalError;
    } finally {
      if (approvalDecisionOperations.get(approvalId) === operation) {
        approvalDecisionOperations.delete(approvalId);
        decidingApprovalIds.value = decidingApprovalIds.value.filter((item) => item !== approvalId);
      }
    }
  }

  function runSync(key: string, path: string, force: boolean): Promise<boolean> {
    const active = syncOperations.get(key);
    if (active) return active;
    const now = Date.now();
    if (!force && now - (syncStartedAt.get(key) ?? 0) < SYNC_COOLDOWN_MS) return Promise.resolve(false);
    syncStartedAt.set(key, now);
    const principalAtRequest = principalGeneration;
    const operation = apiRequest(path, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      signal: principalAbortController.signal,
    })
      .then(() => principalAtRequest === principalGeneration)
      .catch((syncError: unknown) => {
        if (principalAtRequest === principalGeneration) {
          error.value = syncError instanceof Error ? syncError.message : "同步请求失败";
        }
        return false;
      })
      .finally(() => {
        if (syncOperations.get(key) === operation) syncOperations.delete(key);
      });
    syncOperations.set(key, operation);
    return operation;
  }

  async function syncDevice(deviceId: string, force = false): Promise<void> {
    const device = devices.value.find((item) => item.id === deviceId);
    if (!device || device.status !== "online") return;
    await Promise.all([
      runSync(`device:${deviceId}:threads`, `/devices/${deviceId}/threads/sync`, force),
      runSync(`device:${deviceId}:models`, `/devices/${deviceId}/models/sync`, force),
    ]);
  }

  async function syncThread(threadId: string, force = false): Promise<void> {
    const detail = threadDetails.get(threadId);
    const summary = threadSummariesById.get(threadId);
    const deviceId = detail?.device_id ?? summary?.device_id;
    const device = devices.value.find((item) => item.id === deviceId);
    if (!device || device.status !== "online") return;
    await runSync(`thread:${threadId}`, `/threads/${threadId}/sync`, force);
  }

  async function syncSelection(force = false): Promise<void> {
    const deviceId = selectedDeviceId.value;
    if (!deviceId) return;
    await syncDevice(deviceId, force);
    if (selectedThreadId.value) await syncThread(selectedThreadId.value, force);
  }

  function refreshModels(deviceId: string): Promise<void> {
    const active = modelReadOperations.get(deviceId);
    if (active) {
      modelRefreshPending.add(deviceId);
      return active;
    }
    const generation = stateGeneration;
    const operation = apiRequest<{ items: ModelOption[] }>(`/devices/${deviceId}/models`)
      .then((result) => {
        if (generation !== stateGeneration || !devices.value.some((device) => device.id === deviceId)) return;
        modelsByDevice.set(deviceId, result.items);
        if (selectedDeviceId.value === deviceId) models.value = result.items;
        const retryTimer = modelRefreshTimers.get(deviceId);
        if (retryTimer !== undefined) window.clearTimeout(retryTimer);
        modelRefreshTimers.delete(deviceId);
        modelRefreshAttempts.delete(deviceId);
      })
      .catch((modelError: unknown) => {
        if (generation !== stateGeneration || !devices.value.some((device) => device.id === deviceId)) return;
        error.value = modelError instanceof Error ? modelError.message : "模型目录刷新失败";
        if (!isRetryableReadError(modelError) || modelRefreshTimers.has(deviceId)) return;
        const attempt = modelRefreshAttempts.get(deviceId) ?? 0;
        const delay = Math.min(30_000, 1_000 * 2 ** attempt);
        modelRefreshAttempts.set(deviceId, Math.min(attempt + 1, 30));
        modelRefreshTimers.set(
          deviceId,
          window.setTimeout(() => {
            modelRefreshTimers.delete(deviceId);
            void refreshModels(deviceId);
          }, delay),
        );
      })
      .finally(() => {
        if (modelReadOperations.get(deviceId) !== operation) return;
        modelReadOperations.delete(deviceId);
        if (
          modelRefreshPending.delete(deviceId) &&
          generation === stateGeneration &&
          devices.value.some((device) => device.id === deviceId)
        ) {
          const retryTimer = modelRefreshTimers.get(deviceId);
          if (retryTimer !== undefined) window.clearTimeout(retryTimer);
          modelRefreshTimers.delete(deviceId);
          void refreshModels(deviceId);
        }
      });
    modelReadOperations.set(deviceId, operation);
    return operation;
  }

  function applyEvent(event: BrowserEvent): void {
    if (lastCursor.value && compareCursors(event.cursor, lastCursor.value) <= 0) return;
    if (event.type === "device.updated") {
      const device = event.data as unknown as DeviceSummary;
      if (device.status === "revoked") {
        removeRevokedDevice(device.id);
        lastCursor.value = event.cursor;
        return;
      }
      const index = devices.value.findIndex((item) => item.id === device.id);
      const wasOnline = index !== -1 && devices.value[index]?.status === "online";
      if (index === -1) devices.value.push(device);
      else devices.value[index] = device;
      if (!wasOnline && device.status === "online") {
        void syncDevice(device.id).then(async () => {
          if (selectedDeviceId.value === device.id && selectedThreadId.value) {
            await syncThread(selectedThreadId.value);
          }
        });
      }
    }
    if (event.type === "approval.created") {
      const approval = event.data as unknown as ApprovalItem;
      approvals.value = [approval, ...approvals.value.filter((item) => item.approval_id !== approval.approval_id)];
    }
    if (event.type === "approval.resolved") {
      const approvalId = String(event.data.approval_id ?? "");
      approvals.value = approvals.value.filter((item) => item.approval_id !== approvalId);
    }
    if (event.type === "command.updated") {
      const deviceId = typeof event.data.device_id === "string" ? event.data.device_id : null;
      const command = event.data.command;
      if (
        deviceId &&
        command &&
        typeof command === "object" &&
        "method" in command &&
        command.method === "model/list" &&
        "state" in command &&
        command.state === "succeeded"
      ) {
        void refreshModels(deviceId);
      }
      if (command && typeof command === "object" && "id" in command && "method" in command && "state" in command) {
        const commandId = typeof command.id === "string" ? command.id : null;
        const state = typeof command.state === "string" ? command.state : null;
        const threadId = commandId ? resumeCommandThreads.get(commandId) : undefined;
        if (command.method === "thread/resume" && commandId && state && isTerminalCommandState(state)) {
          const message = "error_message" in command && typeof command.error_message === "string"
            ? command.error_message
            : null;
          if (threadId) applyResumeCommandUpdate(threadId, { state, errorMessage: message });
          else if (resumeThreadOperations.size > 0) {
            if (earlyResumeCommandUpdates.size >= 64) {
              const oldest = earlyResumeCommandUpdates.keys().next().value;
              if (oldest) earlyResumeCommandUpdates.delete(oldest);
            }
            earlyResumeCommandUpdates.set(commandId, { state, errorMessage: message });
          }
        }
      }
    }
    const threadId = String(event.data.thread_id ?? event.data.id ?? "");
    if (threadId && event.type === "thread.updated" && event.data.archived === true) {
      removeMissingThread(threadId);
      lastCursor.value = event.cursor;
      return;
    }
    if (
      threadId &&
      (event.type === "thread.updated" || event.type === "turn.delta" || event.type === "turn.completed")
    ) {
      const watermark = threadWatermarks.get(threadId);
      if (!watermark || compareCursors(event.cursor, watermark) > 0) {
        threadReadOperations.get(threadId)?.events.push(event);
        applyThreadEventMutation(event);
      }
    }
    lastCursor.value = event.cursor;
  }

  function applyThreadEventMutation(event: BrowserEvent): void {
    const threadId = String(event.data.thread_id ?? event.data.id ?? "");
    if (!threadId || removedThreadIds.has(threadId)) return;
    if (event.type === "thread.updated" && !upsertThreadEvent(threadId, event.data)) {
      recoverInvalidCursor();
    }
    if (event.type === "turn.delta") {
      const delta = typeof event.data.delta === "string" ? event.data.delta : "";
      if (delta) {
        const messageId = String(event.data.message_id ?? `assistant:${threadId}`);
        const detail =
          threadId === selectedThreadId.value && activeThread.value
            ? activeThread.value
            : threadDetails.get(threadId);
        if (detail) {
          let message = detail.messages.find((item) => item.id === messageId);
          if (!message) {
            message = {
              id: messageId,
              role: "assistant",
              text: "",
              created_at: event.occurred_at,
              pending: true,
            };
            detail.messages.push(message);
          }
          message.text += delta;
        } else {
          dirtyThreadIds.add(threadId);
        }
      }
    }
    if ((event.type === "turn.completed" || event.type === "thread.updated") && threadId) {
      dirtyThreadIds.add(threadId);
      if (threadId === selectedThreadId.value) scheduleThreadRefresh(threadId, false);
    }
  }

  function upsertThreadEvent(threadId: string, data: Record<string, unknown>): boolean {
    const existing =
      threadId === selectedThreadId.value && activeThread.value
        ? activeThread.value
        : threadDetails.get(threadId);
    if (existing) {
      if (typeof data.title === "string") existing.title = data.title;
      if (typeof data.cwd === "string") existing.cwd = data.cwd;
      if (typeof data.model === "string") existing.model = data.model;
      if (typeof data.updated_at === "string") existing.updated_at = data.updated_at;
      if (typeof data.status === "string") existing.status = data.status as ManagedThreadSummary["status"];
    }
    if (typeof data.status === "string" && data.status !== "failed") finishThreadResume(threadId);
    const priorSummary = threadSummariesById.get(threadId);
    const deviceId =
      typeof data.device_id === "string" ? data.device_id : (existing?.device_id ?? priorSummary?.device_id);
    const summary: ManagedThreadSummary | null = priorSummary
      ? {
          ...priorSummary,
          ...(typeof data.title === "string" ? { title: data.title } : {}),
          ...(typeof data.cwd === "string" ? { cwd: data.cwd } : {}),
          ...(typeof data.model === "string" ? { model: data.model } : {}),
          ...(typeof data.updated_at === "string" ? { updated_at: data.updated_at } : {}),
          ...(typeof data.status === "string"
            ? { status: data.status as ManagedThreadSummary["status"] }
            : {}),
          ...(deviceId ? { device_id: deviceId } : {}),
        }
      : existing
        ? threadSummary(existing)
      : typeof data.title === "string" &&
          typeof data.cwd === "string" &&
          typeof data.model === "string" &&
          typeof data.updated_at === "string" &&
          typeof data.status === "string" &&
          deviceId
        ? {
            id: threadId,
            device_id: deviceId,
            title: data.title,
            cwd: data.cwd,
            model: data.model,
            updated_at: data.updated_at,
            status: data.status as ManagedThreadSummary["status"],
          }
        : null;
    if (summary) {
      threadSummariesById.set(threadId, summary);
      refreshSelectedThreadSummaries();
      return true;
    }
    return false;
  }

  function isRetryableReadError(readError: unknown): boolean {
    if (readError instanceof ApiError) {
      return readError.status === 408 || readError.status === 429 || readError.status >= 500;
    }
    if (readError instanceof TypeError) return true;
    return (
      typeof DOMException !== "undefined" &&
      readError instanceof DOMException &&
      (readError.name === "AbortError" || readError.name === "TimeoutError")
    );
  }

  function removeThreadState(threadId: string): void {
    removedThreadIds.add(threadId);
    threadDetails.delete(threadId);
    threadSummariesById.delete(threadId);
    threadWatermarks.delete(threadId);
    dirtyThreadIds.delete(threadId);
  }

  function removeRevokedDevice(deviceId: string): void {
    const threadIds = new Set<string>();
    for (const summary of threadSummariesById.values()) {
      if (summary.device_id === deviceId) threadIds.add(summary.id);
    }
    for (const detail of threadDetails.values()) {
      if (detail.device_id === deviceId) threadIds.add(detail.id);
    }
    for (const threadId of threadIds) removeThreadState(threadId);

    devices.value = devices.value.filter((device) => device.id !== deviceId);
    snapshotDeviceIds.delete(deviceId);
    modelsByDevice.delete(deviceId);
    const modelTimer = modelRefreshTimers.get(deviceId);
    if (modelTimer !== undefined) window.clearTimeout(modelTimer);
    modelRefreshTimers.delete(deviceId);
    modelRefreshAttempts.delete(deviceId);
    modelRefreshPending.delete(deviceId);
    modelReadOperations.delete(deviceId);
    if (selectedDeviceId.value !== deviceId) {
      refreshSelectedThreadSummaries();
      return;
    }

    selectedDeviceId.value = null;
    selectedThreadId.value = null;
    activeThread.value = null;
    threads.value = [];
    models.value = [];
    const replacement = devices.value.find((device) => device.status === "online") ?? devices.value[0];
    if (!replacement) return;
    const firstThreadId = selectSnapshotDevice(replacement.id);
    if (firstThreadId && (!threadDetails.has(firstThreadId) || dirtyThreadIds.has(firstThreadId))) {
      void selectThread(firstThreadId, false, false).catch((replacementError: unknown) => {
        handleThreadRefreshFailure(firstThreadId, replacementError);
      });
    }
  }

  function removeMissingThread(threadId: string): void {
    removeThreadState(threadId);
    refreshSelectedThreadSummaries();
    if (selectedThreadId.value !== threadId) return;

    selectedThreadId.value = null;
    activeThread.value = null;
    const replacement = threads.value[0];
    if (!replacement) return;
    selectedThreadId.value = replacement.id;
    activeThread.value = threadDetails.get(replacement.id) ?? null;
    if (!activeThread.value || dirtyThreadIds.has(replacement.id)) {
      void selectThread(replacement.id, false, false).catch((replacementError: unknown) => {
        handleThreadRefreshFailure(replacement.id, replacementError);
      });
    }
  }

  function handleThreadRefreshFailure(threadId: string, refreshError: unknown): void {
    error.value = refreshError instanceof Error ? refreshError.message : "线程刷新失败";
    if (refreshError instanceof ApiError && (refreshError.status === 404 || refreshError.status === 410)) {
      threadRefreshAttempt = 0;
      removeMissingThread(threadId);
      return;
    }
    if (isRetryableReadError(refreshError) && threadId === selectedThreadId.value) {
      threadRefreshAttempt += 1;
      scheduleThreadRefresh(threadId, true);
      return;
    }
    threadRefreshAttempt = 0;
  }

  function scheduleThreadRefresh(threadId: string, retry: boolean): void {
    if (threadId !== selectedThreadId.value) return;
    if (threadRefreshTimer !== null) window.clearTimeout(threadRefreshTimer);
    if (!retry) threadRefreshAttempt = 0;
    const delay = retry ? Math.min(30_000, 1_000 * 2 ** Math.max(0, threadRefreshAttempt - 1)) : 300;
    threadRefreshTimer = window.setTimeout(() => {
      threadRefreshTimer = null;
      if (threadId === selectedThreadId.value) {
        void selectThread(threadId, true, false)
          .then(() => {
            threadRefreshAttempt = 0;
          })
          .catch((refreshError: unknown) => handleThreadRefreshFailure(threadId, refreshError));
      }
    }, delay);
  }

  function cancelCursorRecovery(): void {
    cursorRecoveryGeneration += 1;
    if (cursorRecoveryTimer !== null) window.clearTimeout(cursorRecoveryTimer);
    cursorRecoveryTimer = null;
    cursorRecoveryPromise = null;
    cursorRecoveryPending = false;
    cursorRecoveryAttempt = 0;
  }

  function runCursorRecovery(recoveryGeneration: number, principalAtRecovery: number): void {
    if (cursorRecoveryPromise || recoveryGeneration !== cursorRecoveryGeneration) return;
    const operation = bootstrap(true);
    cursorRecoveryPromise = operation;
    void operation.then((recovered) => {
      if (cursorRecoveryPromise === operation) cursorRecoveryPromise = null;
      if (
        recoveryGeneration !== cursorRecoveryGeneration ||
        principalAtRecovery !== principalGeneration
      ) {
        return;
      }
      if (recovered) {
        if (cursorRecoveryPending) {
          cursorRecoveryPending = false;
          recoverInvalidCursor();
        }
        return;
      }
      if (isRetryableReadError(lastBootstrapError)) recoverInvalidCursor();
    });
  }

  function recoverInvalidCursor(): void {
    if (cursorRecoveryPromise) {
      cursorRecoveryPending = true;
      return;
    }
    if (cursorRecoveryTimer !== null) return;
    const recoveryGeneration = cursorRecoveryGeneration;
    const principalAtRecovery = principalGeneration;
    const ceiling = Math.min(30_000, 1_000 * 2 ** cursorRecoveryAttempt);
    const delay = ceiling / 2 + Math.random() * (ceiling / 2);
    cursorRecoveryAttempt = Math.min(cursorRecoveryAttempt + 1, 30);
    cursorRecoveryTimer = window.setTimeout(() => {
      cursorRecoveryTimer = null;
      if (
        recoveryGeneration === cursorRecoveryGeneration &&
        principalAtRecovery === principalGeneration
      ) {
        runCursorRecovery(recoveryGeneration, principalAtRecovery);
      }
    }, delay);
  }

  function connectEvents(): void {
    if (socket && socket.readyState < WebSocket.CLOSING) return;
    const generation = connectionGeneration;
    live.value = "connecting";
    socket = new WebSocket(browserWebSocketUrl(lastCursor.value ?? undefined));
    socket.onopen = () => {
      if (generation !== connectionGeneration) return;
      live.value = "online";
      if (stableConnectionTimer !== null) window.clearTimeout(stableConnectionTimer);
      stableConnectionTimer = window.setTimeout(() => {
        stableConnectionTimer = null;
        reconnectAttempt = 0;
      }, 10_000);
      if (cursorStabilityTimer !== null) window.clearTimeout(cursorStabilityTimer);
      cursorStabilityTimer = window.setTimeout(() => {
        cursorStabilityTimer = null;
        cursorRecoveryAttempt = 0;
        cursorRecoveryPending = false;
      }, 10_000);
    };
    socket.onmessage = (message) => {
      if (generation !== connectionGeneration) return;
      try {
        applyEvent(JSON.parse(String(message.data)) as BrowserEvent);
        reconnectAttempt = 0;
        if (stableConnectionTimer !== null) window.clearTimeout(stableConnectionTimer);
        stableConnectionTimer = null;
      } catch {
        error.value = "收到无法解析的实时事件";
      }
    };
    socket.onclose = (event) => {
      if (generation !== connectionGeneration) return;
      live.value = "offline";
      socket = null;
      if (stableConnectionTimer !== null) window.clearTimeout(stableConnectionTimer);
      stableConnectionTimer = null;
      if (cursorStabilityTimer !== null) window.clearTimeout(cursorStabilityTimer);
      cursorStabilityTimer = null;
      if (event.code === 4401) {
        reconnectAttempt = 0;
        void notifyControlAuthenticationRequired();
        return;
      }
      if (event.code === 4409) {
        reconnectAttempt = 0;
        recoverInvalidCursor();
        return;
      }
      if (event.code === 4400 || event.code === 4403) {
        reconnectAttempt = 0;
        error.value = event.code === 4403 ? "实时连接被拒绝" : "实时连接参数无效";
        return;
      }
      const ceiling = Math.min(30_000, 1_000 * 2 ** reconnectAttempt);
      const delay = ceiling / 2 + Math.random() * (ceiling / 2);
      reconnectAttempt = Math.min(reconnectAttempt + 1, 30);
      reconnectTimer = window.setTimeout(connectEvents, delay);
    };
  }

  function disconnectEvents(): void {
    connectionGeneration += 1;
    if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
    if (stableConnectionTimer !== null) window.clearTimeout(stableConnectionTimer);
    stableConnectionTimer = null;
    if (cursorStabilityTimer !== null) window.clearTimeout(cursorStabilityTimer);
    cursorStabilityTimer = null;
    const activeSocket = socket;
    socket = null;
    if (activeSocket) {
      activeSocket.onopen = null;
      activeSocket.onmessage = null;
      activeSocket.onclose = null;
      activeSocket.close(1000, "session ended");
    }
    live.value = "offline";
  }

  function resetView(): void {
    stateGeneration += 1;
    disconnectEvents();
    if (threadRefreshTimer !== null) window.clearTimeout(threadRefreshTimer);
    threadRefreshTimer = null;
    threadRefreshAttempt = 0;
    threadRequestGeneration += 1;
    reconnectAttempt = 0;
    devices.value = [];
    threads.value = [];
    models.value = [];
    activeThread.value = null;
    approvals.value = [];
    selectedDeviceId.value = null;
    selectedThreadId.value = null;
    lastCursor.value = null;
    threadDetails.clear();
    threadSummariesById.clear();
    threadWatermarks.clear();
    threadReadOperations.clear();
    modelsByDevice.clear();
    snapshotDeviceIds.clear();
    dirtyThreadIds.clear();
    removedThreadIds.clear();
    for (const timer of modelRefreshTimers.values()) window.clearTimeout(timer);
    modelRefreshTimers.clear();
    modelRefreshAttempts.clear();
    modelRefreshPending.clear();
    modelReadOperations.clear();
    loading.value = false;
    error.value = null;
  }

  function reset(): void {
    principalGeneration += 1;
    principalAbortController.abort();
    principalAbortController = new AbortController();
    cancelCursorRecovery();
    turnOperation = null;
    turnSubmitting.value = false;
    approvalDecisionOperations.clear();
    decidingApprovalIds.value = [];
    archiveThreadOperations.clear();
    archivingThreadIds.value = [];
    resumeThreadOperations.clear();
    resumeCommandThreads.clear();
    earlyResumeCommandUpdates.clear();
    resumingThreadIds.value = [];
    resetView();
    syncStartedAt.clear();
    syncOperations.clear();
  }

  return {
    devices,
    threads,
    models,
    activeThread,
    approvals,
    selectedDeviceId,
    selectedThreadId,
    selectedDevice,
    pendingApprovals,
    loading,
    turnSubmitting,
    decidingApprovalIds,
    archivingThreadIds,
    resumingThreadIds,
    live,
    error,
    bootstrap,
    selectDevice,
    selectThread,
    createThread,
    archiveThread,
    sendTurn,
    steerTurn,
    interruptTurn,
    resumeThread,
    claimPairing,
    revokeDevice,
    resolveApproval,
    syncSelection,
    connectEvents,
    disconnectEvents,
    reset,
  };
});
