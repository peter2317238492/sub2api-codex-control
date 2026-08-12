export const CONTROL_PROTOCOL_VERSION = 1 as const;

export const ALLOWED_RPC_METHODS = [
  "model/list",
  "thread/start",
  "thread/list",
  "thread/read",
  "thread/resume",
  "turn/start",
  "turn/steer",
  "turn/interrupt",
] as const;

export type AllowedRpcMethod = (typeof ALLOWED_RPC_METHODS)[number];

export const PROTOCOL_ERROR_CODES = [
  "invalid_envelope",
  "unsupported_version",
  "unauthorized",
  "policy_denied",
  "invalid_epoch",
  "expired",
  "conflict",
  "upstream_error",
  "invalid_upstream",
  "indeterminate",
  "internal_error",
] as const;

export type ProtocolErrorCode = (typeof PROTOCOL_ERROR_CODES)[number];
export type CommandAckState = "accepted" | "running" | "completed" | "failed" | "expired" | "denied";
export type ApprovalKind = "command" | "file_change" | "permission";
export type ApprovalDecision = "approve" | "deny";

export interface DeviceHelloPayload {
  connector_version: string;
  codex_version: string;
  schema_digest: string;
  public_key: string;
  capabilities: AllowedRpcMethod[];
  workspace_roots: string[];
  resumed_from_seq?: number;
}

export interface DeviceHelloAckPayload {
  connection_id: string;
  protocol_version: typeof CONTROL_PROTOCOL_VERSION;
  device_id: string;
  epoch: string;
  schema_digest: string;
  received_seq: number;
  heartbeat_timeout_seconds: number;
}

export interface HeartbeatPayload {
  status: "ok";
}

export interface HeartbeatAckPayload {
  received_seq: number;
}

export interface CommandPayload {
  command_id: string;
  idempotency_key: string;
  method: AllowedRpcMethod;
  params: Record<string, unknown>;
  deadline_at: string;
}

export interface ProtocolError {
  code: ProtocolErrorCode;
  message: string;
  retryable: boolean;
}

interface CommandAckPayloadBase {
  command_id: string;
}

export type CommandAckPayload =
  | (CommandAckPayloadBase & {
      state: "accepted" | "running";
      result?: never;
      error?: never;
    })
  | (CommandAckPayloadBase & {
      state: "completed";
      result: unknown;
      error?: never;
    })
  | (CommandAckPayloadBase & {
      state: "failed" | "expired" | "denied";
      result?: never;
      error: ProtocolError;
    });

export interface DeviceEventPayload {
  method: string;
  params: Record<string, unknown>;
}

export interface ApprovalRequestPayload {
  approval_id: string;
  command_id: string;
  kind: ApprovalKind;
  summary: string;
  details: Record<string, unknown>;
  expires_at: string;
}

export interface ApprovalDecisionPayload {
  approval_id: string;
  decision: ApprovalDecision;
  decided_at: string;
}

export type TokenRefreshPayload = Record<string, never>;

export interface ControlEnvelopePayloadMap {
  hello: DeviceHelloPayload;
  hello_ack: DeviceHelloAckPayload;
  heartbeat: HeartbeatPayload;
  heartbeat_ack: HeartbeatAckPayload;
  command: CommandPayload;
  command_ack: CommandAckPayload;
  event: DeviceEventPayload;
  approval_request: ApprovalRequestPayload;
  approval_decision: ApprovalDecisionPayload;
  token_refresh: TokenRefreshPayload;
  error: ProtocolError;
}

export type EnvelopeType = keyof ControlEnvelopePayloadMap;
export type HandshakeEnvelopeType = "hello" | "hello_ack";

export type ControlEnvelopeOf<TType extends EnvelopeType> = {
  version: typeof CONTROL_PROTOCOL_VERSION;
  id: string;
  device_id: string;
  epoch: string;
  seq: TType extends HandshakeEnvelopeType ? 0 : number;
  ack?: number;
  type: TType;
  sent_at: string;
  payload: ControlEnvelopePayloadMap[TType];
};

export type ControlEnvelope = {
  [TType in EnvelopeType]: ControlEnvelopeOf<TType>;
}[EnvelopeType];

export interface DeviceSummary {
  id: string;
  name: string;
  status: "online" | "offline" | "revoked" | "upgrading";
  connector_version: string;
  codex_version: string;
  last_seen_at: string | null;
  workspace_roots: string[];
}

export interface ManagedThreadSummary {
  id: string;
  device_id: string;
  title: string;
  cwd: string;
  model: string;
  updated_at: string;
  status: "idle" | "running" | "waiting_for_approval" | "failed";
}

export interface BrowserEvent {
  cursor: string;
  type:
    | "device.updated"
    | "thread.updated"
    | "turn.delta"
    | "turn.completed"
    | "approval.created"
    | "approval.resolved"
    | "command.updated";
  occurred_at: string;
  data: Record<string, unknown>;
}

export * from "./policy";
