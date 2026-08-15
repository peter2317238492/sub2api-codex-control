from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .security import canonicalize_workspace_roots


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExchangeRequest(StrictModel):
    access_token: str | None = Field(default=None, min_length=16, max_length=8192)


class UserView(StrictModel):
    id: str
    username: str | None = None
    email: str | None = None
    display_name: str | None = None


class SessionView(StrictModel):
    id: uuid.UUID
    user: UserView
    issued_at: datetime
    expires_at: datetime
    reauth_at: datetime
    csrf_header_name: str


class PairingStartRequest(StrictModel):
    protocol_version: Literal[2] = 2
    pairing_id: uuid.UUID
    created_at: datetime
    audience: str = Field(min_length=1, max_length=4096)
    public_key: str = Field(min_length=40, max_length=256)
    display_name: str = Field(min_length=1, max_length=255)
    connector_version: str = Field(min_length=1, max_length=64)
    codex_version: str = Field(min_length=1, max_length=64)
    workspace_roots: list[str] = Field(min_length=1, max_length=32)
    code_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    poll_token_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    refresh_credential_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(min_length=80, max_length=128)

    @field_validator("display_name", "connector_version", "codex_version")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be blank")
        return value

    @field_validator("workspace_roots")
    @classmethod
    def validate_workspace_roots(cls, value: list[str]) -> list[str]:
        return canonicalize_workspace_roots(value)


class PairingStartResponse(StrictModel):
    pairing_id: uuid.UUID
    expires_at: datetime
    poll_url: str


class PairingClaimRequest(StrictModel):
    code: str = Field(
        pattern=(
            r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}"
            r"(?:-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}){3}$"
        )
    )


class PairingClaimResponse(StrictModel):
    pairing_id: uuid.UUID
    device_id: uuid.UUID
    device_name: str
    status: Literal["claimed"] = "claimed"


class DeviceConnectTokenRequest(StrictModel):
    device_id: uuid.UUID
    public_key: str = Field(min_length=40, max_length=256)
    timestamp: str = Field(min_length=20, max_length=64)
    nonce: str = Field(min_length=32, max_length=128)
    signature: str = Field(min_length=80, max_length=128)


class DeviceConnectTokenResponse(StrictModel):
    access_token: str
    expires_at: datetime


class DeviceSummary(StrictModel):
    id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    status: Literal["online", "offline", "revoked", "upgrading"]
    connector_version: str = Field(max_length=64)
    codex_version: str = Field(max_length=64)
    last_seen_at: datetime | None
    workspace_roots: list[str] = Field(max_length=32)


class DeviceListResponse(StrictModel):
    items: list[DeviceSummary]


class ThreadMessage(StrictModel):
    id: str
    role: Literal["user", "assistant", "system"]
    text: str
    created_at: datetime
    pending: bool = False
    error: bool = False


class ManagedThreadSummary(StrictModel):
    id: uuid.UUID
    device_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    cwd: str = Field(max_length=4096)
    model: str = Field(max_length=128)
    updated_at: datetime
    status: Literal["idle", "running", "waiting_for_approval", "failed"]


class ManagedThreadListResponse(StrictModel):
    items: list[ManagedThreadSummary]


class ThreadDetail(ManagedThreadSummary):
    messages: list[ThreadMessage]


class ThreadDetailSnapshot(StrictModel):
    event_cursor: str
    thread: ThreadDetail


class ThreadStartRequest(StrictModel):
    cwd: str = Field(min_length=1, max_length=4096)
    model: str | None = Field(default=None, min_length=1, max_length=128)


class TurnTextRequest(StrictModel):
    text: str = Field(min_length=1, max_length=200_000)

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text cannot be blank")
        return value


class ApprovalDecisionRequest(StrictModel):
    decision: Literal["approve", "deny"]


class ApprovalItem(StrictModel):
    approval_id: uuid.UUID
    command_id: str
    kind: Literal["command", "file_change", "permission"]
    summary: str = Field(min_length=1, max_length=512)
    details: dict[str, Any]
    expires_at: datetime
    device_id: uuid.UUID
    device_name: str
    created_at: datetime


class ApprovalListResponse(StrictModel):
    items: list[ApprovalItem]


class CommandView(StrictModel):
    id: uuid.UUID
    state: Literal[
        "queued",
        "dispatched",
        "acknowledged",
        "succeeded",
        "failed",
        "denied",
        "cancelled",
        "expired",
    ]
    method: Literal[
        "model/list",
        "thread/start",
        "thread/list",
        "thread/read",
        "thread/resume",
        "turn/start",
        "turn/steer",
        "turn/interrupt",
    ]
    deadline_at: datetime | None
    result: dict[str, Any] | list[Any] | str | int | float | bool | None = None
    error_code: str | None = None
    error_message: str | None = None


class ModelSummary(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=512)


class ModelListResponse(StrictModel):
    items: list[ModelSummary]


class ConnectorReleaseFileEvidence(StrictModel):
    filename: str = Field(
        min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(gt=0, strict=True)
    signature_bundle: str = Field(
        min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )


class ConnectorReleaseSbomEvidence(ConnectorReleaseFileEvidence):
    format: Literal["SPDX-2.3-json"]


class ConnectorReleaseProvenanceEvidence(ConnectorReleaseFileEvidence):
    predicate_type: Literal["https://slsa.dev/provenance/v1"]
    attestation_bundle: str = Field(
        min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )


class ConnectorReleaseAsset(ConnectorReleaseFileEvidence):
    os: Literal["linux", "darwin"]
    arch: Literal["amd64", "arm64"]
    package_format: Literal["deb", "rpm", "pkg"]
    download_url: str = Field(min_length=1, max_length=2048)
    sbom: ConnectorReleaseSbomEvidence
    provenance: ConnectorReleaseProvenanceEvidence


class ConnectorReleaseMetadata(StrictModel):
    format_version: int = Field(ge=1, le=1, strict=True)
    release_mode: Literal["release"]
    releasable: bool = Field(strict=True)
    source_repository: Literal[
        "https://github.com/peter2317238492/sub2api-codex-control"
    ]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    version: str = Field(pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
    tag: str = Field(min_length=1, max_length=128)
    codex_version: str = Field(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    )
    schema_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest: ConnectorReleaseFileEvidence
    config_path_hint: Literal["~/.config/sub2api-codex-connector/connector.json"]
    pair_command: Literal["sub2api-codex-connector-ctl pair"]
    start_command: Literal["sub2api-codex-connector-ctl start"]
    assets: list[ConnectorReleaseAsset] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def validate_immutable_release_inventory(self) -> ConnectorReleaseMetadata:
        if self.releasable is not True:
            raise ValueError("Connector release is not releasable")
        expected_tag = f"connector-v{self.version}"
        if self.tag != expected_tag:
            raise ValueError("Connector release tag does not match its exact version")

        if (
            self.manifest.filename != "manifest.json"
            or self.manifest.signature_bundle != "manifest.json.sigstore.json"
        ):
            raise ValueError("Connector release manifest evidence is not canonical")

        expected_tuples = {
            ("linux", "amd64", "deb"),
            ("linux", "amd64", "rpm"),
            ("linux", "arm64", "deb"),
            ("linux", "arm64", "rpm"),
            ("darwin", "amd64", "pkg"),
            ("darwin", "arm64", "pkg"),
        }
        actual_tuples = {
            (asset.os, asset.arch, asset.package_format) for asset in self.assets
        }
        if actual_tuples != expected_tuples:
            raise ValueError(
                "Connector release does not contain the complete native package matrix"
            )

        release_base = f"{self.source_repository}/releases/download/{expected_tag}"
        for asset in self.assets:
            filename = (
                f"sub2api-codex-connector_{self.version}_{asset.os}_{asset.arch}."
                f"{asset.package_format}"
            )
            sbom_filename = f"{filename}.spdx.json"
            provenance_filename = f"{filename}.intoto.json"
            if (
                asset.filename != filename
                or asset.download_url != f"{release_base}/{filename}"
                or asset.signature_bundle != f"{filename}.sigstore.json"
            ):
                raise ValueError("Connector asset URL is not an exact immutable release URL")
            if (
                asset.sbom.filename != sbom_filename
                or asset.sbom.signature_bundle != f"{sbom_filename}.sigstore.json"
            ):
                raise ValueError("Connector asset SBOM evidence is not canonical")
            if (
                asset.provenance.filename != provenance_filename
                or asset.provenance.signature_bundle
                != f"{provenance_filename}.sigstore.json"
                or asset.provenance.attestation_bundle
                != f"{filename}.intoto.sigstore.json"
            ):
                raise ValueError("Connector asset provenance evidence is not canonical")
        return self


class ControlBootstrapResponse(StrictModel):
    event_cursor: str
    devices: list[DeviceSummary]
    threads: list[ManagedThreadSummary]
    approvals: list[ApprovalItem]
    models_by_device: dict[str, list[ModelSummary]]
    connector_release: ConnectorReleaseMetadata | None = None


class BrowserEvent(StrictModel):
    cursor: str
    type: Literal[
        "device.updated",
        "thread.updated",
        "turn.delta",
        "turn.completed",
        "approval.created",
        "approval.resolved",
        "command.updated",
    ]
    occurred_at: datetime
    data: dict[str, Any]


class PairingPendingResponse(StrictModel):
    status: Literal["pending"] = "pending"
    pairing_id: uuid.UUID
    expires_at: datetime


class PairingCompletedResponse(StrictModel):
    status: Literal["claimed"] = "claimed"
    device_id: uuid.UUID


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"


class ReadinessResponse(StrictModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, Literal["ok", "failed"]]
