const API_BASE = import.meta.env.VITE_CONTROL_API_BASE ?? "/codex-api/v1";
const CSRF_COOKIE_NAME = import.meta.env.VITE_CONTROL_CSRF_COOKIE_NAME ?? "codex_csrf";
const DEFAULT_CSRF_HEADER_NAME = "x-csrf-token";
const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

let csrfHeaderName = DEFAULT_CSRF_HEADER_NAME;
type AuthenticationRequiredListener = () => boolean | void | Promise<boolean | void>;
const authenticationRequiredListeners = new Set<AuthenticationRequiredListener>();

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(message: string, status: number, code: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function csrfToken(): string | null {
  const prefix = `${CSRF_COOKIE_NAME}=`;
  const entry = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  if (!entry) return null;
  try {
    return decodeURIComponent(entry.slice(prefix.length));
  } catch {
    return null;
  }
}

export function setCsrfHeaderName(name: string): void {
  if (!HTTP_TOKEN.test(name)) throw new Error("Control API returned an invalid CSRF header name");
  csrfHeaderName = name;
}

export function resetApiSecurityConfig(): void {
  csrfHeaderName = DEFAULT_CSRF_HEADER_NAME;
}

export function onControlAuthenticationRequired(listener: AuthenticationRequiredListener): () => void {
  authenticationRequiredListeners.add(listener);
  return () => authenticationRequiredListeners.delete(listener);
}

export async function notifyControlAuthenticationRequired(): Promise<boolean> {
  const recoveries: Array<Promise<boolean | void>> = [];
  for (const listener of authenticationRequiredListeners) {
    try {
      recoveries.push(Promise.resolve(listener()));
    } catch {
      // Authentication recovery must not replace the original HTTP or WebSocket failure.
    }
  }
  const results = await Promise.allSettled(recoveries);
  return results.some((result) => result.status === "fulfilled" && result.value === true);
}

function requestAbortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("Request aborted", "AbortError");
}

function throwIfRequestAborted(signal: AbortSignal | null | undefined): void {
  if (signal?.aborted) throw requestAbortReason(signal);
}

async function performApiRequest<T>(
  path: string,
  init: RequestInit,
  allowReauthRetry: boolean,
  allowNetworkRetry: boolean,
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const csrf = csrfToken();
  if (csrf && !["GET", "HEAD", "OPTIONS"].includes((init.method ?? "GET").toUpperCase())) {
    headers.set(csrfHeaderName, csrf);
  }

  let response: Response;
  throwIfRequestAborted(init.signal);
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      credentials: "include",
      headers,
    });
  } catch (requestError) {
    const callerAborted = init.signal?.aborted === true;
    if (callerAborted && init.signal) throw requestAbortReason(init.signal);
    const idempotencyKey = headers.get("Idempotency-Key")?.trim();
    if (allowNetworkRetry && !callerAborted && requestError instanceof TypeError && idempotencyKey) {
      return performApiRequest<T>(path, init, allowReauthRetry, false);
    }
    throw requestError;
  }

  if (response.status === 204) return undefined as T;
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : `Request failed with ${response.status}`;
    const code = typeof body?.code === "string" ? body.code : null;
    if (
      allowReauthRetry &&
      response.status === 401 &&
      path !== "/session" &&
      path !== "/session/exchange" &&
      path !== "/session/logout"
    ) {
      const recovered = await notifyControlAuthenticationRequired();
      const recoverableCode = code ?? detail;
      if (recovered && (recoverableCode === "reauth_required" || recoverableCode === "control_session_required")) {
        return performApiRequest<T>(path, init, false, allowNetworkRetry);
      }
    }
    throw new ApiError(detail, response.status, code);
  }
  return body as T;
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  return performApiRequest<T>(path, init, true, true);
}

export function browserWebSocketUrl(cursor?: string): string {
  const configured = import.meta.env.VITE_BROWSER_WS_PATH ?? "/codex-ws/browser";
  const url = new URL(configured, window.location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (cursor) url.searchParams.set("cursor", cursor);
  return url.toString();
}
