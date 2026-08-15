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

export interface ConnectorReleaseFileEvidence {
  filename: string;
  sha256: string;
  size: number;
  signature_bundle: string;
}

export interface ConnectorReleaseSbomEvidence extends ConnectorReleaseFileEvidence {
  format: "SPDX-2.3-json";
}

export interface ConnectorReleaseProvenanceEvidence extends ConnectorReleaseFileEvidence {
  predicate_type: "https://slsa.dev/provenance/v1";
  attestation_bundle: string;
}

export interface ConnectorReleaseAsset extends ConnectorReleaseFileEvidence {
  os: ConnectorOperatingSystem;
  arch: ConnectorArchitecture;
  package_format: ConnectorPackageFormat;
  download_url: string;
  sbom: ConnectorReleaseSbomEvidence;
  provenance: ConnectorReleaseProvenanceEvidence;
}

export interface ConnectorReleaseMetadata {
  format_version: 1;
  release_mode: "release";
  releasable: true;
  source_repository: "https://github.com/peter2317238492/sub2api-codex-control";
  source_commit: string;
  version: string;
  tag: string;
  codex_version: string;
  schema_digest: string;
  manifest: ConnectorReleaseFileEvidence;
  config_path_hint: "~/.config/sub2api-codex-connector/connector.json";
  pair_command: "sub2api-codex-connector-ctl pair";
  start_command: "sub2api-codex-connector-ctl start";
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
