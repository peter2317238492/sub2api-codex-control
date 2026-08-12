import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { ApiError, apiRequest, resetApiSecurityConfig, setCsrfHeaderName } from "@/api/client";
import {
  clearSub2ApiAuthState,
  hasSub2ApiRefreshToken,
  isSub2ApiAccessTokenStorageKey,
  isSub2ApiAuthStorageKey,
  logoutSub2Api,
  refreshAndPersistSub2ApiAuth,
  Sub2ApiRefreshError,
  SUB2API_LOGOUT_INTENT_STORAGE_KEY,
} from "@/api/sub2api";
import { readSub2ApiAccessToken } from "@/api/token";
import type { SessionSnapshot } from "@/types";

type SessionState = "loading" | "authenticated" | "missing_token" | "expired" | "error";
type RenewalReason = "manual" | "scheduled" | "authentication_failure";

const RENEWAL_LEAD_MS = 30_000;
const RENEWAL_RETRY_MS = 5_000;

function timestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function storedTokenExpiry(storage: Storage = window.localStorage): number | null {
  const value = storage.getItem("token_expires_at")?.trim();
  if (!value) return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) return numeric < 1_000_000_000_000 ? numeric * 1000 : numeric;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function sessionDeadline(snapshot: SessionSnapshot): number | null {
  const reauthAt = timestamp(snapshot.reauth_at);
  const expiresAt = timestamp(snapshot.expires_at);
  if (reauthAt === null || expiresAt === null) return null;
  return Math.min(reauthAt, expiresAt);
}

function sessionExpiry(snapshot: SessionSnapshot): number | null {
  return timestamp(snapshot.expires_at);
}

function retryableRenewalError(error: unknown): boolean {
  if (error instanceof Sub2ApiRefreshError) return error.retryable;
  if (error instanceof ApiError) return error.status === 429 || error.status >= 500;
  return error instanceof TypeError;
}

export const useSessionStore = defineStore("session", () => {
  const state = ref<SessionState>("loading");
  const session = ref<SessionSnapshot | null>(null);
  const error = ref<string | null>(null);
  const busy = ref(false);
  const renewalRevision = ref(0);
  const externalAuthRevision = ref(0);

  let renewalTimer: number | null = null;
  let externalAuthTimer: number | null = null;
  let lifecycleGeneration = 0;
  let renewalPromise: Promise<boolean> | null = null;
  let renewalAbortController: AbortController | null = null;
  const busyOperations = new Set<symbol>();

  const authenticated = computed(() => state.value === "authenticated" && session.value !== null);

  function beginBusy(): symbol {
    const operation = Symbol("session-operation");
    busyOperations.add(operation);
    busy.value = true;
    return operation;
  }

  function endBusy(operation: symbol): void {
    busyOperations.delete(operation);
    busy.value = busyOperations.size > 0;
  }

  function cancelRenewalTimer(): void {
    if (renewalTimer !== null) window.clearTimeout(renewalTimer);
    renewalTimer = null;
  }

  function cancelExternalAuthTimer(): void {
    if (externalAuthTimer !== null) window.clearTimeout(externalAuthTimer);
    externalAuthTimer = null;
  }

  function invalidateOperations(): number {
    lifecycleGeneration += 1;
    cancelRenewalTimer();
    renewalAbortController?.abort();
    renewalAbortController = null;
    renewalPromise = null;
    cancelExternalAuthTimer();
    return lifecycleGeneration;
  }

  function scheduleRenewal(snapshot: SessionSnapshot): void {
    cancelRenewalTimer();
    const controlDeadline = sessionDeadline(snapshot);
    if (controlDeadline === null) throw new Error("Control API 返回了无效的会话期限");
    const accessDeadline = storedTokenExpiry();
    const deadline = accessDeadline === null ? controlDeadline : Math.min(controlDeadline, accessDeadline);
    const delay = Math.max(0, deadline - Date.now() - RENEWAL_LEAD_MS);
    renewalTimer = window.setTimeout(() => {
      renewalTimer = null;
      void renew("scheduled");
    }, delay);
  }

  function acceptSession(snapshot: SessionSnapshot): void {
    if (sessionDeadline(snapshot) === null) throw new Error("Control API 返回了无效的会话期限");
    setCsrfHeaderName(snapshot.csrf_header_name);
    session.value = snapshot;
    state.value = "authenticated";
    error.value = null;
    scheduleRenewal(snapshot);
  }

  function transitionUnauthenticated(nextState: SessionState, message: string | null): void {
    cancelRenewalTimer();
    session.value = null;
    resetApiSecurityConfig();
    state.value = nextState;
    error.value = message;
  }

  function expire(message: string, clearSub2ApiAuth: boolean): void {
    invalidateOperations();
    if (clearSub2ApiAuth) clearSub2ApiAuthState();
    transitionUnauthenticated("expired", message);
  }

  async function exchangeAccessToken(
    accessToken: string,
    generation: number,
    transitionOnError = true,
    signal?: AbortSignal,
  ): Promise<boolean> {
    try {
      const snapshot = await apiRequest<SessionSnapshot>("/session/exchange", {
        method: "POST",
        body: JSON.stringify({ access_token: accessToken }),
        signal: signal ?? null,
      });
      if (generation !== lifecycleGeneration) return false;
      acceptSession(snapshot);
      return true;
    } catch (exchangeError) {
      if (generation !== lifecycleGeneration) return false;
      if (!transitionOnError) throw exchangeError;
      const nextState = exchangeError instanceof ApiError && exchangeError.status === 401 ? "expired" : "error";
      transitionUnauthenticated(
        nextState,
        exchangeError instanceof Error ? exchangeError.message : "登录交换失败",
      );
      return false;
    }
  }

  function canRefreshAfterExchange(): boolean {
    return (state.value === "expired" || state.value === "missing_token") && hasSub2ApiRefreshToken();
  }

  async function load(): Promise<void> {
    const generation = invalidateOperations();
    const operation = beginBusy();
    state.value = "loading";
    error.value = null;
    try {
      const snapshot = await apiRequest<SessionSnapshot>("/session");
      if (generation !== lifecycleGeneration) return;
      acceptSession(snapshot);
      return;
    } catch (loadError) {
      if (generation !== lifecycleGeneration) return;
      if (!(loadError instanceof ApiError) || loadError.status !== 401) {
        transitionUnauthenticated("error", "控制服务暂时不可用");
        return;
      }
    } finally {
      endBusy(operation);
    }

    const exchanged = await exchange();
    if (!exchanged && canRefreshAfterExchange()) {
      await renew("authentication_failure");
    }
  }

  async function exchange(): Promise<boolean> {
    const generation = invalidateOperations();
    const token = readSub2ApiAccessToken();
    if (!token) {
      transitionUnauthenticated("missing_token", null);
      return false;
    }

    const operation = beginBusy();
    error.value = null;
    try {
      return await exchangeAccessToken(token, generation);
    } finally {
      endBusy(operation);
    }
  }

  async function performRenewal(
    reason: RenewalReason,
    generation: number,
    controller: AbortController,
  ): Promise<boolean> {
    try {
      const refreshed = await refreshAndPersistSub2ApiAuth(
        window.localStorage,
        controller.signal,
        () => generation === lifecycleGeneration,
      );
      if (!refreshed || generation !== lifecycleGeneration) return false;
      const exchanged = await exchangeAccessToken(refreshed.accessToken, generation, false, controller.signal);
      if (!exchanged || generation !== lifecycleGeneration) return false;
      renewalRevision.value += 1;
      return true;
    } catch (renewalError) {
      if (generation !== lifecycleGeneration) return false;
      return handleRenewalError(reason, renewalError);
    }
  }

  function handleRenewalError(reason: RenewalReason, renewalError: unknown): false {
    const retryable = retryableRenewalError(renewalError);
    const deadline = session.value ? sessionExpiry(session.value) : null;
    const remaining = deadline === null ? 0 : deadline - Date.now();
    if (retryable && remaining > 1_000 && session.value) {
      error.value = reason === "scheduled" ? "会话续期暂时失败，正在重试" : "会话续期暂时失败，请稍后重试";
      const delay = Math.min(RENEWAL_RETRY_MS, Math.max(0, remaining - 1_000));
      renewalTimer = window.setTimeout(() => {
        renewalTimer = null;
        void renew("scheduled");
      }, delay);
      return false;
    }

    expire(renewalError instanceof Error ? renewalError.message : "登录续期失败", false);
    return false;
  }

  function runRenewal(
    performer: (generation: number, controller: AbortController) => Promise<boolean>,
  ): Promise<boolean> {
    if (renewalPromise) return renewalPromise;
    const generation = invalidateOperations();
    const controller = new AbortController();
    renewalAbortController = controller;
    const operation = beginBusy();
    error.value = null;
    const currentPromise = performer(generation, controller).finally(() => {
      endBusy(operation);
      if (renewalAbortController === controller) renewalAbortController = null;
      if (renewalPromise === currentPromise) renewalPromise = null;
    });
    renewalPromise = currentPromise;
    return currentPromise;
  }

  function renew(reason: RenewalReason = "manual"): Promise<boolean> {
    return runRenewal((generation, controller) => performRenewal(reason, generation, controller));
  }

  function handleAuthenticationFailure(): Promise<boolean> {
    return runRenewal(async (generation, controller) => {
      const accessToken = readSub2ApiAccessToken();
      if (accessToken) {
        try {
          const exchanged = await exchangeAccessToken(accessToken, generation, false, controller.signal);
          if (!exchanged || generation !== lifecycleGeneration) return false;
          renewalRevision.value += 1;
          return true;
        } catch (exchangeError) {
          if (generation !== lifecycleGeneration) return false;
          if (!(exchangeError instanceof ApiError) || exchangeError.status !== 401) {
            return handleRenewalError("authentication_failure", exchangeError);
          }
        }
      }
      return performRenewal("authentication_failure", generation, controller);
    });
  }

  async function synchronizeExternalAuth(): Promise<void> {
    const accessToken = readSub2ApiAccessToken();
    if (!accessToken) {
      invalidateOperations();
      transitionUnauthenticated("missing_token", null);
      return;
    }
    const generation = invalidateOperations();
    const operation = beginBusy();
    const controller = new AbortController();
    renewalAbortController = controller;
    let refreshAfterFailure = false;
    try {
      const exchanged = await exchangeAccessToken(accessToken, generation, false, controller.signal);
      if (exchanged && generation === lifecycleGeneration) renewalRevision.value += 1;
    } catch (exchangeError) {
      if (generation !== lifecycleGeneration) return;
      if (exchangeError instanceof ApiError && exchangeError.status === 401) {
        refreshAfterFailure = true;
      } else {
        const deadline = session.value ? sessionExpiry(session.value) : null;
        const remaining = deadline === null ? 0 : deadline - Date.now();
        if (retryableRenewalError(exchangeError) && remaining > 1_000 && session.value) {
          error.value = "跨标签页登录同步暂时失败，正在重试";
          externalAuthTimer = window.setTimeout(() => {
            externalAuthTimer = null;
            void synchronizeExternalAuth();
          }, Math.min(RENEWAL_RETRY_MS, Math.max(0, remaining - 1_000)));
        } else {
          expire(exchangeError instanceof Error ? exchangeError.message : "登录同步失败", false);
        }
      }
    } finally {
      if (renewalAbortController === controller) renewalAbortController = null;
      endBusy(operation);
    }
    if (refreshAfterFailure && generation === lifecycleGeneration) await renew("authentication_failure");
  }

  function handleExternalAuthStorage(event: StorageEvent): void {
    if (event.storageArea && event.storageArea !== window.localStorage) return;
    if (event.key === SUB2API_LOGOUT_INTENT_STORAGE_KEY && event.newValue) {
      invalidateOperations();
      transitionUnauthenticated("missing_token", null);
      return;
    }
    if (event.key === null || (isSub2ApiAccessTokenStorageKey(event.key) && event.newValue === null)) {
      if (!readSub2ApiAccessToken()) {
        invalidateOperations();
        transitionUnauthenticated("missing_token", null);
        return;
      }
    }
    if (isSub2ApiAccessTokenStorageKey(event.key) && event.newValue) externalAuthRevision.value += 1;
    if (!isSub2ApiAuthStorageKey(event.key)) return;
    cancelExternalAuthTimer();
    externalAuthTimer = window.setTimeout(() => {
      externalAuthTimer = null;
      void synchronizeExternalAuth();
    }, 100);
  }

  window.addEventListener("storage", handleExternalAuthStorage);

  async function logout(): Promise<void> {
    invalidateOperations();
    const operation = beginBusy();
    let logoutError: string | null = null;
    const controlLogout = apiRequest<void>("/session/logout", { method: "POST" });
    const sub2ApiLogout = logoutSub2Api();
    transitionUnauthenticated("missing_token", null);
    try {
      const [controlResult, sub2ApiResult] = await Promise.allSettled([controlLogout, sub2ApiLogout]);
      const failures: string[] = [];
      if (controlResult.status === "rejected") {
        failures.push(controlResult.reason instanceof Error ? controlResult.reason.message : "控制会话注销失败");
      }
      if (sub2ApiResult.status === "rejected") {
        failures.push(sub2ApiResult.reason instanceof Error ? sub2ApiResult.reason.message : "Sub2API 注销失败");
      }
      logoutError = failures.length > 0 ? failures.join("；") : null;
    } finally {
      endBusy(operation);
      reset("missing_token");
      error.value = logoutError;
    }
  }

  function reset(nextState: SessionState = "missing_token"): void {
    invalidateOperations();
    busyOperations.clear();
    busy.value = false;
    session.value = null;
    error.value = null;
    resetApiSecurityConfig();
    state.value = nextState;
  }

  function dispose(): void {
    window.removeEventListener("storage", handleExternalAuthStorage);
    reset();
  }

  return {
    state,
    session,
    error,
    busy,
    renewalRevision,
    externalAuthRevision,
    authenticated,
    load,
    exchange,
    renew,
    handleAuthenticationFailure,
    logout,
    reset,
    dispose,
  };
});
