import { ALLOWED_RPC_METHODS, type AllowedRpcMethod } from "./index";

const DENIED_PREFIXES = [
  "account/",
  "command/",
  "config/",
  "fs/",
  "plugin/",
  "process/",
  "thread/shellCommand",
] as const;

const allowed = new Set<string>(ALLOWED_RPC_METHODS);

export const RPC_POLICY_DESCRIPTOR = {
  version: 1,
  max_frame_bytes: 256 * 1_024,
  max_ensure_ascii_params_bytes: 224 * 1_024,
  max_ensure_ascii_projected_bytes: 224 * 1_024,
  max_ensure_ascii_text_bytes: 200_000,
  max_page_size: 100,
  max_cwd_filters: 32,
  max_text_items: 1,
  max_text_length: 200_000,
  max_opaque_length: 512,
  max_search_length: 512,
  max_path_length: 4_096,
  methods: {
    "model/list": ["cursor", "limit"],
    "thread/start": ["cwd", "model"],
    "thread/list": ["cursor", "limit", "cwd", "searchTerm"],
    "thread/read": ["threadId", "includeTurns"],
    "thread/resume": ["threadId"],
    "turn/start": ["threadId", "clientUserMessageId", "input"],
    "turn/steer": ["threadId", "clientUserMessageId", "input", "expectedTurnId"],
    "turn/interrupt": ["threadId", "turnId"],
  } satisfies Record<AllowedRpcMethod, readonly string[]>,
} as const;

const SAFE_PARAM_KEYS: Record<AllowedRpcMethod, ReadonlySet<string>> = {
  "model/list": new Set(RPC_POLICY_DESCRIPTOR.methods["model/list"]),
  "thread/start": new Set(RPC_POLICY_DESCRIPTOR.methods["thread/start"]),
  "thread/list": new Set(RPC_POLICY_DESCRIPTOR.methods["thread/list"]),
  "thread/read": new Set(RPC_POLICY_DESCRIPTOR.methods["thread/read"]),
  "thread/resume": new Set(RPC_POLICY_DESCRIPTOR.methods["thread/resume"]),
  "turn/start": new Set(RPC_POLICY_DESCRIPTOR.methods["turn/start"]),
  "turn/steer": new Set(RPC_POLICY_DESCRIPTOR.methods["turn/steer"]),
  "turn/interrupt": new Set(RPC_POLICY_DESCRIPTOR.methods["turn/interrupt"]),
};

export interface RpcProjectionContext {
  allowedCwds?: readonly string[];
  boundThreadIds?: readonly string[];
  activeTurnId?: string;
  maxPageSize?: number;
  maxTextLength?: number;
  maxTextEncodedBytes?: number;
}

export function isAllowedRpcMethod(method: string): method is AllowedRpcMethod {
  return allowed.has(method);
}

export function rpcPolicyReason(method: string): string | null {
  if (isAllowedRpcMethod(method)) {
    return null;
  }

  const deniedPrefix = DENIED_PREFIXES.find((prefix) => method.startsWith(prefix));
  if (deniedPrefix) {
    return `method family ${deniedPrefix} is explicitly denied`;
  }

  return "method is not present in the remote-control allowlist";
}

export function assertAllowedRpcMethod(method: string): asserts method is AllowedRpcMethod {
  const reason = rpcPolicyReason(method);
  if (reason) {
    throw new Error(`RPC policy denied ${method}: ${reason}`);
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("RPC params must be an object");
  }
  return value as Record<string, unknown>;
}

function rejectUnknownFields(method: AllowedRpcMethod, params: Record<string, unknown>): void {
  const safeKeys = SAFE_PARAM_KEYS[method];
  const unknown = Object.keys(params).filter((key) => !safeKeys.has(key));
  if (unknown.length) {
    throw new Error(`RPC policy denied ${method} fields: ${unknown.sort().join(", ")}`);
  }
}

function codePointLength(value: string): number {
  return Array.from(value).length;
}

export function ensureAsciiJsonByteLength(value: unknown): number {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("value is not JSON serializable");
  let bytes = 0;
  for (const character of encoded) {
    const codePoint = character.codePointAt(0)!;
    bytes += codePoint <= 0x7e ? 1 : codePoint <= 0xffff ? 6 : 12;
  }
  return bytes;
}

export function goJsonByteLength(value: unknown): number {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("value is not JSON serializable");
  let bytes = 0;
  for (const character of encoded) {
    const codePoint = character.codePointAt(0)!;
    if (character === "<" || character === ">" || character === "&" || codePoint === 0x2028 || codePoint === 0x2029) {
      bytes += 6;
    } else if (codePoint <= 0x7f) {
      bytes++;
    } else if (codePoint <= 0x7ff) {
      bytes += 2;
    } else if (codePoint <= 0xffff) {
      bytes += 3;
    } else {
      bytes += 4;
    }
  }
  return bytes;
}

function ensureAsciiStringContentByteLength(value: string): number {
  return ensureAsciiJsonByteLength(value) - 2;
}

function assertParamsBudget(params: Record<string, unknown>): Record<string, unknown> {
  const ensureAsciiSize = ensureAsciiJsonByteLength(params);
  if (ensureAsciiSize > RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes) {
    throw new Error(
      `RPC params exceed the ${RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes}-byte ensure_ascii budget`,
    );
  }
  const goSize = goJsonByteLength(params);
  if (goSize > RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes) {
    throw new Error(`RPC params exceed the ${RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes}-byte Go JSON budget`);
  }
  return params;
}

function optionalString(value: unknown, field: string, maximum: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length === 0 || codePointLength(value) > maximum) {
    throw new Error(`${field} must be a non-empty string of at most ${maximum} characters`);
  }
  return value;
}

function requiredString(value: unknown, field: string, maximum: number): string {
  const parsed = optionalString(value, field, maximum);
  if (!parsed) throw new Error(`${field} is required`);
  return parsed;
}

function projectPage(params: Record<string, unknown>, maxPageSize: number): Record<string, unknown> {
  const projected: Record<string, unknown> = {};
  const cursor = optionalString(params.cursor, "cursor", RPC_POLICY_DESCRIPTOR.max_opaque_length);
  if (cursor) projected.cursor = cursor;
  if (params.limit !== undefined && params.limit !== null) {
    if (!Number.isInteger(params.limit) || Number(params.limit) < 1 || Number(params.limit) > maxPageSize) {
      throw new Error(`limit must be an integer between 1 and ${maxPageSize}`);
    }
    projected.limit = params.limit;
  }
  return projected;
}

function assertBoundThread(threadId: string, context: RpcProjectionContext): void {
  if (!context.boundThreadIds || !context.boundThreadIds.includes(threadId)) {
    throw new Error("thread is not bound to this device session");
  }
}

function projectTextInput(
  value: unknown,
  maxTextLength: number,
  maxTextEncodedBytes: number,
): Array<Record<string, unknown>> {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error("remote turns require exactly one text input");
  }
  const item = asRecord(value[0]);
  const itemKeys = Object.keys(item).sort();
  const hasCanonicalKeys =
    (itemKeys.length === 2 && itemKeys[0] === "text" && itemKeys[1] === "type") ||
    (itemKeys.length === 3 &&
      itemKeys[0] === "text" &&
      itemKeys[1] === "text_elements" &&
      itemKeys[2] === "type" &&
      Array.isArray(item.text_elements) &&
      item.text_elements.length === 0);
  if (
    !hasCanonicalKeys ||
    item.type !== "text" ||
    typeof item.text !== "string"
  ) {
    throw new Error("remote turns allow text input only");
  }
  if (!item.text.trim() || codePointLength(item.text) > maxTextLength) {
    throw new Error(`turn text must contain 1 to ${maxTextLength} characters`);
  }
  if (ensureAsciiStringContentByteLength(item.text) > maxTextEncodedBytes) {
    throw new Error(`turn text exceeds the ${maxTextEncodedBytes}-byte ensure_ascii budget`);
  }
  return [{ type: "text", text: item.text, text_elements: [] }];
}

function projectThreadListCwds(value: unknown, allowedCwds: readonly string[]): string[] {
  if (value === undefined || value === null) return [...allowedCwds];
  const candidates = typeof value === "string" ? [value] : value;
  if (!Array.isArray(candidates) || candidates.length < 1 || candidates.length > RPC_POLICY_DESCRIPTOR.max_cwd_filters) {
    throw new Error(`thread/list cwd must contain 1 to ${RPC_POLICY_DESCRIPTOR.max_cwd_filters} paths`);
  }
  const projected: string[] = [];
  for (const candidate of candidates) {
    const cwd = requiredString(candidate, "cwd", RPC_POLICY_DESCRIPTOR.max_path_length);
    if (!allowedCwds.includes(cwd)) throw new Error("cwd is outside the connector allowlist");
    if (!projected.includes(cwd)) projected.push(cwd);
  }
  return projected;
}

export function projectRemoteRpcParams(
  method: string,
  rawParams: unknown,
  context: RpcProjectionContext = {},
): Record<string, unknown> {
  assertAllowedRpcMethod(method);
  const params = asRecord(rawParams);
  rejectUnknownFields(method, params);
  const maxPageSize = Math.min(
    context.maxPageSize ?? RPC_POLICY_DESCRIPTOR.max_page_size,
    RPC_POLICY_DESCRIPTOR.max_page_size,
  );
  const maxTextLength = Math.min(
    context.maxTextLength ?? RPC_POLICY_DESCRIPTOR.max_text_length,
    RPC_POLICY_DESCRIPTOR.max_text_length,
  );
  const maxTextEncodedBytes = Math.min(
    context.maxTextEncodedBytes ?? RPC_POLICY_DESCRIPTOR.max_ensure_ascii_text_bytes,
    RPC_POLICY_DESCRIPTOR.max_ensure_ascii_text_bytes,
  );

  if (method === "model/list") return assertParamsBudget(projectPage(params, maxPageSize));

  if (method === "thread/start") {
    const cwd = requiredString(params.cwd, "cwd", RPC_POLICY_DESCRIPTOR.max_path_length);
    if (!context.allowedCwds || !context.allowedCwds.includes(cwd)) {
      throw new Error("cwd is outside the connector allowlist");
    }
    const projected: Record<string, unknown> = { cwd };
    const model = optionalString(params.model, "model", RPC_POLICY_DESCRIPTOR.max_opaque_length);
    if (model) projected.model = model;
    return assertParamsBudget(projected);
  }

  if (method === "thread/list") {
    if (
      !context.allowedCwds ||
      context.allowedCwds.length === 0 ||
      context.allowedCwds.length > RPC_POLICY_DESCRIPTOR.max_cwd_filters
    ) {
      throw new Error("thread/list requires connector workspace roots");
    }
    const projected = projectPage(params, maxPageSize);
    projected.cwd = projectThreadListCwds(params.cwd, context.allowedCwds);
    const searchTerm = optionalString(params.searchTerm, "searchTerm", RPC_POLICY_DESCRIPTOR.max_search_length);
    if (searchTerm) projected.searchTerm = searchTerm;
    return assertParamsBudget(projected);
  }

  const threadId = requiredString(params.threadId, "threadId", RPC_POLICY_DESCRIPTOR.max_opaque_length);
  assertBoundThread(threadId, context);

  if (method === "thread/read") {
    if (params.includeTurns !== undefined && params.includeTurns !== null && typeof params.includeTurns !== "boolean") {
      throw new Error("includeTurns must be a boolean");
    }
    return assertParamsBudget({ threadId, includeTurns: params.includeTurns ?? false });
  }
  if (method === "thread/resume") return assertParamsBudget({ threadId });

  if (method === "turn/interrupt") {
    const turnId = requiredString(params.turnId, "turnId", RPC_POLICY_DESCRIPTOR.max_opaque_length);
    if (!context.activeTurnId || turnId !== context.activeTurnId) throw new Error("turn is no longer active");
    return assertParamsBudget({ threadId, turnId });
  }

  const input = projectTextInput(params.input, maxTextLength, maxTextEncodedBytes);
  const projected: Record<string, unknown> = { threadId, input };
  const clientUserMessageId = optionalString(
    params.clientUserMessageId,
    "clientUserMessageId",
    RPC_POLICY_DESCRIPTOR.max_opaque_length,
  );
  if (clientUserMessageId) projected.clientUserMessageId = clientUserMessageId;

  if (method === "turn/steer") {
    const expectedTurnId = requiredString(
      params.expectedTurnId,
      "expectedTurnId",
      RPC_POLICY_DESCRIPTOR.max_opaque_length,
    );
    if (!context.activeTurnId || expectedTurnId !== context.activeTurnId) {
      throw new Error("turn is no longer active");
    }
    projected.expectedTurnId = expectedTurnId;
  }

  return assertParamsBudget(projected);
}
