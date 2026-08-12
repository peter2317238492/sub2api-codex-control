import type { ApprovalRequestPayload, DeviceSummary, ManagedThreadSummary } from "@sub2api-codex/control-protocol";

export interface SessionUser {
  id: string;
  username: string | null;
  email: string | null;
  display_name: string | null;
}

export interface SessionSnapshot {
  id: string;
  user: SessionUser;
  issued_at: string;
  expires_at: string;
  reauth_at: string;
  csrf_header_name: string;
}

export interface PairingTicket {
  id: string;
  code: string;
  expires_at: string;
}

export interface PairingClaim {
  pairing_id: string;
  device_id: string;
  device_name: string;
  status: "claimed";
}

export interface ModelOption {
  id: string;
  display_name: string;
  description?: string | null;
}

export interface ThreadMessage {
  id: string;
  role: "user" | "assistant" | "system";
  text: string;
  created_at: string;
  pending?: boolean;
  error?: boolean;
}

export interface ThreadDetail extends ManagedThreadSummary {
  messages: ThreadMessage[];
}

export interface ApprovalItem extends ApprovalRequestPayload {
  device_id: string;
  device_name: string;
  created_at: string;
}

export interface ControlBootstrapSnapshot {
  event_cursor: string;
  devices: DeviceSummary[];
  threads: ManagedThreadSummary[];
  approvals: ApprovalItem[];
  models_by_device: Record<string, ModelOption[]>;
}

export interface ThreadDetailSnapshot {
  event_cursor: string;
  thread: ThreadDetail;
}

export type { DeviceSummary, ManagedThreadSummary };
