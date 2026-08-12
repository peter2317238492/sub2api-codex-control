from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

BIGINT_PRIMARY_KEY = BigInteger().with_variant(Integer, "sqlite")
JSON_DOCUMENT = JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql")


def utc_now() -> datetime:
    return datetime.now(UTC)


def enum_column(
    enum_class: type[enum.Enum],
    name: str,
    *,
    length: int | None = None,
) -> Enum:
    length_option = {"length": length} if length is not None else {}
    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        validate_strings=True,
        values_callable=lambda members: [member.value for member in members],
        **length_option,
    )


class PairingStatus(enum.StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DeviceStatus(enum.StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ConnectionStatus(enum.StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"


class CommandStatus(enum.StrEnum):
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    ACKNOWLEDGED = "acknowledged"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ThreadBindingStatus(enum.StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    FAILED = "failed"
    CLOSED = "closed"
    STALE = "stale"


class ApprovalStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class AuditOutcome(enum.StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


class ControlSession(Base):
    __tablename__ = "control_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sub2api_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(255))
    token_version: Mapped[str | None] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    request_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))

    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="valid_lifetime"),
        Index("ix_control_sessions_active_user", "sub2api_user_id", "expires_at", "revoked_at"),
    )


class DevicePairing(Base):
    __tablename__ = "device_pairings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    poll_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    refresh_credential_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    protocol_version: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    proof_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    audience: Mapped[str | None] = mapped_column(String(4096))
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    device_name: Mapped[str] = mapped_column(String(255), nullable=False)
    device_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False, default=dict
    )
    workspace_roots: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False, default=list)
    status: Mapped[PairingStatus] = mapped_column(
        enum_column(PairingStatus, "pairing_status"),
        nullable=False,
        default=PairingStatus.PENDING,
        index=True,
    )
    claimed_by_user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    claimed_by_session_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("control_sessions.id", ondelete="SET NULL")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    credential_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="valid_lifetime"),
        CheckConstraint(
            "protocol_version IN (1, 2)",
            name="supported_protocol_version",
        ),
        Index("ix_device_pairings_expiry_status", "expires_at", "status"),
        Index(
            "uq_device_pairings_live_public_key",
            "public_key",
            unique=True,
            postgresql_where=text("status IN ('pending', 'claimed')"),
            sqlite_where=text("status IN ('pending', 'claimed')"),
        ),
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_credential_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credential_scheme: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[DeviceStatus] = mapped_column(
        enum_column(DeviceStatus, "device_status"),
        nullable=False,
        default=DeviceStatus.ACTIVE,
        index=True,
    )
    device_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False, default=dict
    )
    workspace_roots: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False, default=list)
    model_catalog: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_DOCUMENT, nullable=False, default=list
    )
    model_catalog_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active_epoch: Mapped[str | None] = mapped_column(String(128), index=True)
    active_connection_nonce: Mapped[str | None] = mapped_column(String(128), index=True)
    last_device_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_server_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_server_acked_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_event_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("credential_version >= 0", name="nonnegative_credential_version"),
        CheckConstraint("credential_scheme IN (1, 2)", name="supported_credential_scheme"),
        CheckConstraint("last_device_sequence >= 0", name="nonnegative_device_sequence"),
        CheckConstraint("last_server_sequence >= 0", name="nonnegative_server_sequence"),
        CheckConstraint(
            "last_server_acked_sequence >= 0", name="nonnegative_server_acked_sequence"
        ),
        CheckConstraint("last_event_sequence >= 0", name="nonnegative_event_sequence"),
        CheckConstraint(
            "last_server_acked_sequence <= last_server_sequence",
            name="valid_server_ack",
        ),
        Index(
            "uq_devices_live_public_key",
            "public_key",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
        Index("ix_devices_retention", "status", "revoked_at", "id"),
    )


class DeviceConnection(Base):
    __tablename__ = "device_connections"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    connection_nonce: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    status: Mapped[ConnectionStatus] = mapped_column(
        enum_column(ConnectionStatus, "connection_status"), nullable=False, index=True
    )
    appserver_epoch: Mapped[str | None] = mapped_column(String(128), index=True)
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remote_address: Mapped[str | None] = mapped_column(String(128))
    connector_version: Mapped[str | None] = mapped_column(String(64))
    codex_version: Mapped[str | None] = mapped_column(String(64))
    connection_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False, default=dict
    )
    last_device_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_server_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_server_acked_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    closed_reason: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        CheckConstraint("last_device_sequence >= 0", name="nonnegative_device_sequence"),
        CheckConstraint("last_server_sequence >= 0", name="nonnegative_server_sequence"),
        CheckConstraint(
            "last_server_acked_sequence >= 0", name="nonnegative_server_acked_sequence"
        ),
        Index(
            "ix_device_connections_retention",
            "status",
            "disconnected_at",
            "id",
        ),
    )


class DeviceOutbox(Base):
    __tablename__ = "device_outbox"

    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        primary_key=True,
    )
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    encoded_envelope: Mapped[str] = mapped_column(Text, nullable=False)
    ack_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    frame_type: Mapped[str] = mapped_column(String(32), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    retained_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        CheckConstraint("sequence > 0", name="positive_sequence"),
        CheckConstraint("ack_sequence >= 0", name="nonnegative_ack_sequence"),
        CheckConstraint("byte_size > 0", name="positive_byte_size"),
        CheckConstraint("retained_until > created_at", name="valid_retention"),
        CheckConstraint(
            "acked_at IS NULL OR acked_at >= created_at",
            name="valid_ack_time",
        ),
        CheckConstraint(
            "frame_type NOT IN ('hello', 'hello_ack')",
            name="non_handshake_frame",
        ),
    )


class ThreadBinding(Base):
    __tablename__ = "thread_bindings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    remote_thread_id: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[ThreadBindingStatus] = mapped_column(
        enum_column(ThreadBindingStatus, "thread_binding_status", length=32),
        nullable=False,
        default=ThreadBindingStatus.IDLE,
        index=True,
    )
    cwd: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="New thread")
    model: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    active_turn_id: Mapped[str | None] = mapped_column(String(255), index=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False, default=lambda: {"messages": []}
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    appserver_epoch: Mapped[str] = mapped_column(String(128), nullable=False)
    last_event_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        UniqueConstraint("device_id", "remote_thread_id", name="uq_thread_bindings_device_thread"),
        CheckConstraint("last_event_sequence >= 0", name="nonnegative_event_sequence"),
        Index("ix_thread_bindings_retention", "status", "updated_at", "id"),
    )


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    thread_binding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("thread_bindings.id", ondelete="SET NULL"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_scope: Mapped[str] = mapped_column(
        String(512), nullable=False, default="legacy", server_default="legacy"
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False, default=dict)
    status: Mapped[CommandStatus] = mapped_column(
        enum_column(CommandStatus, "command_status"),
        nullable=False,
        default=CommandStatus.QUEUED,
        index=True,
    )
    appserver_epoch: Mapped[str | None] = mapped_column(String(128), index=True)
    result: Mapped[Any | None] = mapped_column(JSON_DOCUMENT)
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        UniqueConstraint(
            "owner_user_id",
            "device_id",
            "idempotency_scope",
            "idempotency_key",
            name="uq_commands_scoped_idempotency",
        ),
        Index("ix_commands_retention", "status", "completed_at", "id"),
    )


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    command_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("commands.id", ondelete="SET NULL"), index=True
    )
    external_command_id: Mapped[str | None] = mapped_column(String(255), index=True)
    decided_by_session_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("control_sessions.id", ondelete="SET NULL")
    )
    approval_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    request: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    request_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="0" * 64,
    )
    status: Mapped[ApprovalStatus] = mapped_column(
        enum_column(ApprovalStatus, "approval_status"),
        nullable=False,
        default=ApprovalStatus.PENDING,
        index=True,
    )
    appserver_epoch: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("expires_at > requested_at", name="valid_lifetime"),
        CheckConstraint("length(request_hash) = 64", name="request_hash_length"),
        Index("ix_approvals_retention", "status", "decided_at", "id"),
        Index("ix_approvals_undispatched", "status", "decision_dispatched_at", "id"),
    )


class EventLog(Base):
    __tablename__ = "event_log"

    id: Mapped[int] = mapped_column(BIGINT_PRIMARY_KEY, primary_key=True, autoincrement=True)
    owner_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    thread_binding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("thread_bindings.id", ondelete="SET NULL"), index=True
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )

    __table_args__ = (
        UniqueConstraint("device_id", "sequence", name="uq_event_log_device_sequence"),
        UniqueConstraint("owner_user_id", "owner_cursor", name="uq_event_log_owner_cursor"),
        CheckConstraint("sequence >= 0", name="nonnegative_sequence"),
        CheckConstraint("owner_cursor > 0", name="positive_owner_cursor"),
        CheckConstraint(
            "owner_cursor <= 9223372036854775807",
            name="bounded_owner_cursor",
        ),
        Index("ix_event_log_owner_ingested", "owner_user_id", "ingested_at"),
    )


class EventOwnerCursor(Base):
    __tablename__ = "event_owner_cursors"

    owner_user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    minimum_resume_cursor: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    __table_args__ = (
        CheckConstraint("last_cursor >= 0", name="nonnegative_last_cursor"),
        CheckConstraint(
            "last_cursor <= 9223372036854775807",
            name="bounded_last_cursor",
        ),
        CheckConstraint(
            "minimum_resume_cursor >= 0",
            name="nonnegative_minimum_resume_cursor",
        ),
        CheckConstraint(
            "minimum_resume_cursor <= last_cursor",
            name="valid_resume_window",
        ),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BIGINT_PRIMARY_KEY, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    actor_session_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    actor_device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_column(AuditOutcome, "audit_outcome"), nullable=False, index=True
    )
    resource_type: Mapped[str | None] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON_DOCUMENT, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )

    __table_args__ = (Index("ix_audit_events_resource", "resource_type", "resource_id"),)
