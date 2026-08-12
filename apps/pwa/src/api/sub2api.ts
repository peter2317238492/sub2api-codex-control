const AUTH_TOKEN_KEY = "auth_token";
const REFRESH_TOKEN_KEY = "refresh_token";
const AUTH_ROTATION_REVISION_KEY = "sub2api_codex_control_auth_rotation";
export const SUB2API_LOGOUT_INTENT_STORAGE_KEY = "sub2api_codex_control_logout_intent";
const AUTH_STATE_KEYS = [
  AUTH_TOKEN_KEY,
  REFRESH_TOKEN_KEY,
  "auth_user",
  "token_expires_at",
  AUTH_ROTATION_REVISION_KEY,
] as const;

const MAX_TOKEN_LENGTH = 64 * 1024;
const AUTH_REFRESH_LOCK_NAME = "sub2api-codex-control:auth-refresh";
const AUTH_REFRESH_LEASE_KEY = "sub2api_codex_control_auth_refresh_lock";
const AUTH_REFRESH_CONTENDER_PREFIX = `${AUTH_REFRESH_LEASE_KEY}:contender:`;
const AUTH_REFRESH_LEASE_MS = 20_000;
const AUTH_REFRESH_LEASE_HEARTBEAT_MS = 5_000;
const AUTH_REFRESH_LEASE_RETRY_MS = 50;
const AUTH_REFRESH_ELECTION_MS = 75;
const AUTH_REQUEST_TIMEOUT_MS = 15_000;
const fallbackRefreshQueues = new WeakMap<Storage, Promise<void>>();

export interface RefreshedSub2ApiAuth {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export class Sub2ApiRefreshError extends Error {
  readonly retryable: boolean;
  readonly credentialRejected: boolean;

  constructor(message: string, retryable: boolean, credentialRejected = false) {
    super(message);
    this.name = "Sub2ApiRefreshError";
    this.retryable = retryable;
    this.credentialRejected = credentialRejected;
  }
}

export class Sub2ApiLogoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Sub2ApiLogoutError";
  }
}

interface RefreshData {
  access_token: unknown;
  refresh_token: unknown;
  expires_in: unknown;
  token_type: unknown;
}

interface StoredAuthState {
  accessToken: string | null;
  refreshToken: string | null;
}

type RenewalGuard = () => boolean;

interface RefreshLease {
  owner: string;
  expiresAt: number;
}

interface RefreshContender extends RefreshLease {
  requestedAt: number;
}

function plainToken(value: string | null): string | null {
  const token = value?.trim();
  if (!token || token.length > MAX_TOKEN_LENGTH || token.startsWith("{") || token.startsWith("[")) return null;
  return token;
}

function responseToken(value: unknown): string | null {
  return typeof value === "string" ? plainToken(value) : null;
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function refreshData(value: unknown): RefreshData | null {
  if (!exactObject(value, ["code", "message", "data"])) return null;
  if (value.code !== 0 || value.message !== "success") return null;
  if (!exactObject(value.data, ["access_token", "refresh_token", "expires_in", "token_type"])) return null;
  return value.data as unknown as RefreshData;
}

function storedAuthState(storage: Storage): StoredAuthState {
  return {
    accessToken: plainToken(storage.getItem(AUTH_TOKEN_KEY)),
    refreshToken: plainToken(storage.getItem(REFRESH_TOKEN_KEY)),
  };
}

function sameAuthState(left: StoredAuthState, right: StoredAuthState): boolean {
  return left.accessToken === right.accessToken && left.refreshToken === right.refreshToken;
}

function clearAuthStateIfMatches(storage: Storage, expected: StoredAuthState): boolean {
  if (!sameAuthState(storedAuthState(storage), expected)) return false;
  clearSub2ApiAuthState(storage);
  return true;
}

function storedAuthResult(storage: Storage): RefreshedSub2ApiAuth | null {
  const state = storedAuthState(storage);
  if (!state.accessToken || !state.refreshToken) return null;
  const expiresAt = Number(storage.getItem("token_expires_at"));
  return {
    accessToken: state.accessToken,
    refreshToken: state.refreshToken,
    expiresAt: Number.isFinite(expiresAt) && expiresAt > 0 ? expiresAt : Date.now(),
  };
}

function parseLease(value: string | null): RefreshLease | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<RefreshLease>;
    return typeof parsed.owner === "string" && typeof parsed.expiresAt === "number"
      ? { owner: parsed.owner, expiresAt: parsed.expiresAt }
      : null;
  } catch {
    return null;
  }
}

function parseContender(value: string | null): RefreshContender | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<RefreshContender>;
    return typeof parsed.owner === "string" &&
      typeof parsed.requestedAt === "number" &&
      Number.isFinite(parsed.requestedAt) &&
      typeof parsed.expiresAt === "number" &&
      Number.isFinite(parsed.expiresAt)
      ? { owner: parsed.owner, requestedAt: parsed.requestedAt, expiresAt: parsed.expiresAt }
      : null;
  } catch {
    return null;
  }
}

function activeRefreshContenders(storage: Storage, now: number): RefreshContender[] {
  const entries: Array<{ key: string; raw: string; contender: RefreshContender }> = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (!key?.startsWith(AUTH_REFRESH_CONTENDER_PREFIX)) continue;
    const raw = storage.getItem(key);
    const contender = parseContender(raw);
    if (raw && contender) entries.push({ key, raw, contender });
  }
  for (const entry of entries) {
    if (entry.contender.expiresAt <= now && storage.getItem(entry.key) === entry.raw) {
      storage.removeItem(entry.key);
    }
  }
  return entries
    .filter((entry) => entry.contender.expiresAt > now)
    .map((entry) => entry.contender)
    .sort((left, right) => {
      if (left.requestedAt !== right.requestedAt) return left.requestedAt - right.requestedAt;
      return left.owner < right.owner ? -1 : left.owner > right.owner ? 1 : 0;
    });
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("Operation aborted", "AbortError");
}

function waitForAbortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortReason(signal));
  return new Promise<T>((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortReason(signal));
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    const abort = () => {
      window.clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      reject(signal ? abortReason(signal) : new DOMException("Operation aborted", "AbortError"));
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}

async function withTimeout<T>(
  externalSignal: AbortSignal | undefined,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort(externalSignal ? abortReason(externalSignal) : undefined);
  if (externalSignal?.aborted) abort();
  else externalSignal?.addEventListener("abort", abort, { once: true });
  const timeout = window.setTimeout(
    () => controller.abort(new DOMException("Sub2API request timed out", "TimeoutError")),
    AUTH_REQUEST_TIMEOUT_MS,
  );
  try {
    let pending: Promise<T>;
    try {
      pending = operation(controller.signal);
    } catch (error) {
      pending = Promise.reject(error);
    }
    return await waitForAbortable(pending, controller.signal);
  } finally {
    window.clearTimeout(timeout);
    externalSignal?.removeEventListener("abort", abort);
  }
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw abortReason(signal);
}

function abortLike(error: unknown): boolean {
  return error instanceof DOMException && (error.name === "AbortError" || error.name === "TimeoutError");
}

async function acquireFallbackRefreshLease(storage: Storage, signal?: AbortSignal): Promise<() => void> {
  const owner = crypto.randomUUID();
  const contenderKey = `${AUTH_REFRESH_CONTENDER_PREFIX}${owner}`;
  const requestedAt = Date.now();
  const writeContender = () => {
    storage.setItem(
      contenderKey,
      JSON.stringify({ owner, requestedAt, expiresAt: Date.now() + AUTH_REFRESH_LEASE_MS }),
    );
  };
  const removeOwnedState = () => {
    storage.removeItem(contenderKey);
    if (parseLease(storage.getItem(AUTH_REFRESH_LEASE_KEY))?.owner === owner) {
      storage.removeItem(AUTH_REFRESH_LEASE_KEY);
    }
  };

  writeContender();
  try {
    // A contender must be visible for a full election window before it can win.
    // The second window confirms that two tabs which observed an empty lease
    // cannot both enter after overwriting the shared lease key.
    await delay(AUTH_REFRESH_ELECTION_MS, signal);
    while (true) {
      if (signal?.aborted) throw abortReason(signal);
      writeContender();
      const now = Date.now();
      const lease = parseLease(storage.getItem(AUTH_REFRESH_LEASE_KEY));
      if (lease && lease.expiresAt > now && lease.owner !== owner) {
        await delay(AUTH_REFRESH_LEASE_RETRY_MS, signal);
        continue;
      }

      const winner = activeRefreshContenders(storage, now)[0];
      if (winner?.owner !== owner) {
        if (lease?.owner === owner) storage.removeItem(AUTH_REFRESH_LEASE_KEY);
        await delay(AUTH_REFRESH_LEASE_RETRY_MS, signal);
        continue;
      }

      storage.setItem(
        AUTH_REFRESH_LEASE_KEY,
        JSON.stringify({ owner, expiresAt: Date.now() + AUTH_REFRESH_LEASE_MS }),
      );
      await delay(AUTH_REFRESH_ELECTION_MS, signal);
      const confirmedLease = parseLease(storage.getItem(AUTH_REFRESH_LEASE_KEY));
      const confirmedWinner = activeRefreshContenders(storage, Date.now())[0];
      if (confirmedLease?.owner === owner && confirmedWinner?.owner === owner) {
        const heartbeat = window.setInterval(() => {
          const current = parseLease(storage.getItem(AUTH_REFRESH_LEASE_KEY));
          if (current?.owner === owner) {
            writeContender();
            storage.setItem(
              AUTH_REFRESH_LEASE_KEY,
              JSON.stringify({ owner, expiresAt: Date.now() + AUTH_REFRESH_LEASE_MS }),
            );
          }
        }, AUTH_REFRESH_LEASE_HEARTBEAT_MS);
        return () => {
          window.clearInterval(heartbeat);
          removeOwnedState();
        };
      }
      if (confirmedLease?.owner === owner) storage.removeItem(AUTH_REFRESH_LEASE_KEY);
      await delay(AUTH_REFRESH_LEASE_RETRY_MS, signal);
    }
  } catch (error) {
    removeOwnedState();
    throw error;
  }
}

async function withFallbackRefreshLock<T>(
  storage: Storage,
  callback: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const previous = fallbackRefreshQueues.get(storage) ?? Promise.resolve();
  const task = (async () => {
    await waitForAbortable(previous.catch(() => undefined), signal);
    const releaseLease = await acquireFallbackRefreshLease(storage, signal);
    try {
      if (signal?.aborted) throw abortReason(signal);
      return await callback();
    } finally {
      releaseLease();
    }
  })();
  fallbackRefreshQueues.set(storage, task.then(() => undefined, () => undefined));
  return task;
}

async function withRefreshLock<T>(
  storage: Storage,
  callback: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const locks = typeof navigator === "undefined" ? undefined : navigator.locks;
  if (!locks) return withFallbackRefreshLock(storage, callback, signal);
  const options: LockOptions = { mode: "exclusive" };
  if (signal) options.signal = signal;
  return locks.request(AUTH_REFRESH_LOCK_NAME, options, callback);
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit): Promise<Response> {
  const externalSignal = init.signal ?? undefined;
  return withTimeout(externalSignal, (signal) => fetch(input, { ...init, signal }));
}

async function requestSub2ApiRefresh(refreshToken: string, signal?: AbortSignal): Promise<RefreshedSub2ApiAuth> {
  let response: Response;
  let body: unknown = null;
  try {
    ({ response, body } = await withTimeout(signal, async (requestSignal) => {
      const requestResponse = await fetch("/api/v1/auth/refresh", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
        signal: requestSignal,
      });
      if (!requestResponse.ok) return { response: requestResponse, body: null };
      try {
        const parsed = await waitForAbortable(requestResponse.json(), requestSignal);
        return { response: requestResponse, body: parsed };
      } catch (parseError) {
        if (requestSignal.aborted) throw parseError;
        return { response: requestResponse, body: null };
      }
    }));
  } catch (requestError) {
    if (signal?.aborted) throw requestError;
    throw new Sub2ApiRefreshError("暂时无法刷新 Sub2API 登录", true);
  }

  if (!response.ok) {
    const credentialRejected = response.status === 401;
    throw new Sub2ApiRefreshError(
      credentialRejected ? "Sub2API 登录已过期" : "Sub2API 刷新服务暂时不可用",
      !credentialRejected,
      credentialRejected,
    );
  }

  const data = refreshData(body);
  const accessToken = responseToken(data?.access_token);
  const rotatedRefreshToken = responseToken(data?.refresh_token);
  const expiresIn = data?.expires_in;
  const tokenType = data?.token_type;
  if (
    !accessToken ||
    !rotatedRefreshToken ||
    typeof expiresIn !== "number" ||
    !Number.isSafeInteger(expiresIn) ||
    expiresIn <= 0 ||
    tokenType !== "Bearer"
  ) {
    throw new Sub2ApiRefreshError("Sub2API 返回了无效的刷新响应", true);
  }

  return {
    accessToken,
    refreshToken: rotatedRefreshToken,
    expiresAt: Date.now() + Math.floor(expiresIn * 1000),
  };
}

async function requestSub2ApiLogout(state: StoredAuthState, signal?: AbortSignal): Promise<void> {
  if (!state.refreshToken) {
    throw new Sub2ApiLogoutError("缺少 Sub2API 刷新凭据；本地登录已清除，但服务端会话未确认注销");
  }
  const headers = new Headers({ "Content-Type": "application/json" });
  if (state.accessToken) headers.set("Authorization", `Bearer ${state.accessToken}`);
  let response: Response;
  try {
    response = await fetchWithTimeout("/api/v1/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: JSON.stringify({ refresh_token: state.refreshToken }),
      signal: signal ?? null,
    });
  } catch (logoutError) {
    if (signal?.aborted && !abortLike(logoutError)) throw logoutError;
    throw new Sub2ApiLogoutError("暂时无法注销 Sub2API 登录");
  }
  if (!response.ok) {
    throw new Sub2ApiLogoutError(`Sub2API 注销失败（HTTP ${response.status}）`);
  }
}

export function clearSub2ApiAuthState(storage: Storage = window.localStorage): void {
  for (const key of AUTH_STATE_KEYS) storage.removeItem(key);
}

export function hasSub2ApiRefreshToken(storage: Storage = window.localStorage): boolean {
  return plainToken(storage.getItem(REFRESH_TOKEN_KEY)) !== null;
}

export function isSub2ApiAuthStorageKey(key: string | null): boolean {
  return key !== null && (AUTH_STATE_KEYS as readonly string[]).includes(key);
}

export function isSub2ApiAccessTokenStorageKey(key: string | null): boolean {
  return key === AUTH_TOKEN_KEY;
}

export async function refreshSub2ApiAuth(
  storage: Storage = window.localStorage,
  signal?: AbortSignal,
): Promise<RefreshedSub2ApiAuth> {
  const refreshToken = plainToken(storage.getItem(REFRESH_TOKEN_KEY));
  if (!refreshToken) throw new Sub2ApiRefreshError("Sub2API 刷新凭据缺失或无效", false);
  return requestSub2ApiRefresh(refreshToken, signal);
}

export function persistRefreshedSub2ApiAuth(
  refreshed: RefreshedSub2ApiAuth,
  storage: Storage = window.localStorage,
): void {
  const previous = AUTH_STATE_KEYS.map((key) => [key, storage.getItem(key)] as const);
  try {
    storage.setItem(AUTH_TOKEN_KEY, refreshed.accessToken);
    storage.setItem(REFRESH_TOKEN_KEY, refreshed.refreshToken);
    storage.setItem("token_expires_at", String(refreshed.expiresAt));
    storage.setItem(AUTH_ROTATION_REVISION_KEY, crypto.randomUUID());
  } catch {
    for (const [key, value] of previous) {
      if (value === null) storage.removeItem(key);
      else storage.setItem(key, value);
    }
    throw new Sub2ApiRefreshError("无法保存刷新的 Sub2API 登录", false);
  }
}

export async function refreshAndPersistSub2ApiAuth(
  storage: Storage = window.localStorage,
  signal?: AbortSignal,
  guard: RenewalGuard = () => true,
): Promise<RefreshedSub2ApiAuth | null> {
  const observed = storedAuthState(storage);
  const logoutIntentAtRequest = storage.getItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY);

  try {
    return await withTimeout(signal, (operationSignal) =>
      withRefreshLock(
        storage,
        async () => {
          throwIfAborted(operationSignal);
          if (!guard()) return null;
          if (storage.getItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY) !== logoutIntentAtRequest) return null;

          const current = storedAuthState(storage);
          // A different tab already rotated the credentials while this tab waited for
          // the exclusive lock. Reuse that result instead of replaying a one-time token.
          if (!sameAuthState(current, observed)) {
            const latest = storedAuthResult(storage);
            if (latest) return latest;
          }
          if (!current.refreshToken) {
            throw new Sub2ApiRefreshError("Sub2API 刷新凭据缺失或无效", false);
          }

          try {
            const refreshed = await requestSub2ApiRefresh(current.refreshToken, operationSignal);
            if (storage.getItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY) !== logoutIntentAtRequest) {
              await requestSub2ApiLogout(
                {
                  accessToken: refreshed.accessToken,
                  refreshToken: refreshed.refreshToken,
                },
                operationSignal,
              ).catch(() => undefined);
              return null;
            }
            throwIfAborted(operationSignal);
            if (!guard()) return null;

            // Logout and other tabs are allowed to win. An older request must never
            // overwrite credentials that appeared while its network request was live.
            if (!sameAuthState(storedAuthState(storage), current)) return storedAuthResult(storage);
            persistRefreshedSub2ApiAuth(refreshed, storage);
            return refreshed;
          } catch (refreshError) {
            if (signal?.aborted || !guard()) return null;

            // A stale rejection (for example from a rotated one-time refresh token)
            // must neither clear nor replace a newer login from another tab.
            if (!sameAuthState(storedAuthState(storage), current)) return storedAuthResult(storage);
            if (refreshError instanceof Sub2ApiRefreshError && refreshError.credentialRejected) {
              clearSub2ApiAuthState(storage);
            }
            throw refreshError;
          }
        },
        operationSignal,
      ),
    );
  } catch (refreshError) {
    if (signal?.aborted || !guard()) return null;
    if (abortLike(refreshError)) {
      throw new Sub2ApiRefreshError("等待 Sub2API 登录刷新超时", true);
    }
    throw refreshError;
  }
}

export async function logoutSub2Api(storage: Storage = window.localStorage): Promise<void> {
  const stateAtRequest = storedAuthState(storage);
  const intent = crypto.randomUUID();
  storage.setItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY, intent);
  clearSub2ApiAuthState(storage);
  try {
    await withTimeout(undefined, (operationSignal) =>
      withRefreshLock(
        storage,
        async () => {
          throwIfAborted(operationSignal);
          const latest = storedAuthState(storage);
          const revocationTarget = latest.refreshToken ? latest : stateAtRequest;
          clearAuthStateIfMatches(storage, latest);
          const clearedState = storedAuthState(storage);
          try {
            await requestSub2ApiLogout(revocationTarget, operationSignal);
          } finally {
            // A login that appeared after this logout acquired the lock wins, but
            // credentials observed by this logout are cleared again before release.
            clearAuthStateIfMatches(storage, clearedState);
          }
        },
        operationSignal,
      ),
    );
  } catch (logoutError) {
    if (abortLike(logoutError)) throw new Sub2ApiLogoutError("等待 Sub2API 注销超时");
    throw logoutError;
  } finally {
    if (storage.getItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY) === intent) {
      storage.removeItem(SUB2API_LOGOUT_INTENT_STORAGE_KEY);
    }
  }
}
