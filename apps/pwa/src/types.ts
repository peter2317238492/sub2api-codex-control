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

export type ConnectorOperatingSystem = "linux" | "darwin";
export type ConnectorArchitecture = "amd64" | "arm64";
export type ConnectorPackageFormat = "deb" | "rpm" | "pkg";

export interface ConnectorReleaseAsset {
  os: ConnectorOperatingSystem;
  arch: ConnectorArchitecture;
  package_format: ConnectorPackageFormat;
  download_url: string;
  sha256: string;
}

export interface ConnectorReleaseMetadata {
  release_mode: "release";
  releasable: true;
  version: string;
  tag: string;
  codex_version: string;
  schema_digest: string;
  config_path_hint: string;
  start_command: string;
  assets: ConnectorReleaseAsset[];
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
  connector_release?: ConnectorReleaseMetadata | null;
}

export interface ThreadDetailSnapshot {
  event_cursor: string;
  thread: ThreadDetail;
}

export type { DeviceSummary, ManagedThreadSummary };
