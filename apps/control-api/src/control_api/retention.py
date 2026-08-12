from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .approvals import NON_DISPATCHABLE_APPROVAL_REASONS
from .config import Settings
from .models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    Command,
    CommandStatus,
    ConnectionStatus,
    ControlSession,
    Device,
    DeviceConnection,
    DeviceOutbox,
    DevicePairing,
    DeviceStatus,
    EventLog,
    PairingStatus,
    ThreadBinding,
    ThreadBindingStatus,
)

_TERMINAL_COMMAND_STATUSES = (
    CommandStatus.SUCCEEDED,
    CommandStatus.FAILED,
    CommandStatus.DENIED,
    CommandStatus.CANCELLED,
    CommandStatus.EXPIRED,
)
_TERMINAL_APPROVAL_STATUSES = (
    ApprovalStatus.APPROVED,
    ApprovalStatus.DENIED,
    ApprovalStatus.EXPIRED,
    ApprovalStatus.CANCELLED,
)
_TERMINAL_THREAD_STATUSES = (
    ThreadBindingStatus.CLOSED,
    ThreadBindingStatus.STALE,
)


@dataclass(frozen=True, slots=True)
class RetentionSweepResult:
    control_sessions: int = 0
    device_pairings: int = 0
    approvals: int = 0
    commands: int = 0
    device_connections: int = 0
    thread_bindings: int = 0
    devices: int = 0
    audit_events: int = 0

    @property
    def total(self) -> int:
        return sum(
            (
                self.control_sessions,
                self.device_pairings,
                self.approvals,
                self.commands,
                self.device_connections,
                self.thread_bindings,
                self.devices,
                self.audit_events,
            )
        )


class RetentionService:
    """Delete only old terminal state, in bounded and dependency-safe batches.

    The application-level state sweep already holds the Redis singleton lease.
    Each table is committed separately so a large retention pass does not keep
    locks open across unrelated tables and successful batches are not retried.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def sweep(
        self,
        db: AsyncSession,
        *,
        now: datetime | None = None,
    ) -> RetentionSweepResult:
        now = _utc(now or datetime.now(UTC))
        return RetentionSweepResult(
            control_sessions=await self._delete_control_sessions(db, now),
            device_pairings=await self._delete_device_pairings(db, now),
            approvals=await self._delete_approvals(db, now),
            commands=await self._delete_commands(db, now),
            device_connections=await self._delete_device_connections(db, now),
            thread_bindings=await self._delete_thread_bindings(db, now),
            devices=await self._delete_devices(db, now),
            audit_events=await self._delete_audit_events(db, now),
        )

    async def _delete_control_sessions(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.session_record_retention_days)
        terminal = and_(
            ControlSession.expires_at <= cutoff,
            or_(ControlSession.revoked_at.is_(None), ControlSession.revoked_at <= cutoff),
        )
        return await self._delete_batch(
            db,
            ControlSession,
            ControlSession.id,
            terminal,
            ControlSession.expires_at,
        )

    async def _delete_device_pairings(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.device_pairing_retention_days)
        terminal = and_(
            DevicePairing.expires_at <= cutoff,
            DevicePairing.status.in_(
                (
                    PairingStatus.COMPLETED,
                    PairingStatus.EXPIRED,
                    PairingStatus.CANCELLED,
                )
            ),
        )
        return await self._delete_batch(
            db,
            DevicePairing,
            DevicePairing.id,
            terminal,
            DevicePairing.expires_at,
        )

    async def _delete_approvals(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.approval_record_retention_days)
        safely_delivered = or_(
            Approval.decision_dispatched_at.is_not(None),
            and_(
                Approval.status == ApprovalStatus.DENIED,
                Approval.decision_reason.in_(NON_DISPATCHABLE_APPROVAL_REASONS),
            ),
            Approval.status.in_((ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED)),
        )
        no_unacknowledged_frames = ~exists(
            select(DeviceOutbox.sequence).where(
                DeviceOutbox.device_id == Approval.device_id,
                DeviceOutbox.acked_at.is_(None),
            )
        )
        terminal = and_(
            Approval.status.in_(_TERMINAL_APPROVAL_STATUSES),
            Approval.decided_at.is_not(None),
            Approval.decided_at <= cutoff,
            safely_delivered,
            no_unacknowledged_frames,
        )
        return await self._delete_batch(
            db,
            Approval,
            Approval.id,
            terminal,
            Approval.decided_at,
        )

    async def _delete_commands(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.command_record_retention_days)
        no_approval_reference = ~exists(
            select(Approval.id).where(Approval.command_id == Command.id)
        )
        no_unacknowledged_frames = ~exists(
            select(DeviceOutbox.sequence).where(
                DeviceOutbox.device_id == Command.device_id,
                DeviceOutbox.acked_at.is_(None),
            )
        )
        terminal = and_(
            Command.status.in_(_TERMINAL_COMMAND_STATUSES),
            Command.completed_at.is_not(None),
            Command.completed_at <= cutoff,
            no_approval_reference,
            no_unacknowledged_frames,
        )
        return await self._delete_batch(
            db,
            Command,
            Command.id,
            terminal,
            Command.completed_at,
        )

    async def _delete_device_connections(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.device_connection_retention_days)
        terminal = and_(
            DeviceConnection.status == ConnectionStatus.DISCONNECTED,
            DeviceConnection.disconnected_at.is_not(None),
            DeviceConnection.disconnected_at <= cutoff,
        )
        return await self._delete_batch(
            db,
            DeviceConnection,
            DeviceConnection.id,
            terminal,
            DeviceConnection.disconnected_at,
        )

    async def _delete_thread_bindings(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.thread_binding_retention_days)
        no_commands = ~exists(
            select(Command.id).where(Command.thread_binding_id == ThreadBinding.id)
        )
        no_events = ~exists(
            select(EventLog.id).where(EventLog.thread_binding_id == ThreadBinding.id)
        )
        no_unacknowledged_frames = ~exists(
            select(DeviceOutbox.sequence).where(
                DeviceOutbox.device_id == ThreadBinding.device_id,
                DeviceOutbox.acked_at.is_(None),
            )
        )
        no_unresolved_approvals = ~exists(
            select(Approval.id).where(
                Approval.device_id == ThreadBinding.device_id,
                or_(
                    Approval.status == ApprovalStatus.PENDING,
                    and_(
                        Approval.status.in_((ApprovalStatus.APPROVED, ApprovalStatus.DENIED)),
                        Approval.decision_dispatched_at.is_(None),
                        or_(
                            Approval.decision_reason.is_(None),
                            Approval.decision_reason.not_in(NON_DISPATCHABLE_APPROVAL_REASONS),
                        ),
                    ),
                ),
            )
        )
        terminal = and_(
            ThreadBinding.status.in_(_TERMINAL_THREAD_STATUSES),
            ThreadBinding.active_turn_id.is_(None),
            ThreadBinding.updated_at <= cutoff,
            no_commands,
            no_events,
            no_unacknowledged_frames,
            no_unresolved_approvals,
        )
        return await self._delete_batch(
            db,
            ThreadBinding,
            ThreadBinding.id,
            terminal,
            ThreadBinding.updated_at,
        )

    async def _delete_devices(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.revoked_device_retention_days)
        no_pairings = ~exists(select(DevicePairing.id).where(DevicePairing.device_id == Device.id))
        no_connections = ~exists(
            select(DeviceConnection.id).where(DeviceConnection.device_id == Device.id)
        )
        no_threads = ~exists(select(ThreadBinding.id).where(ThreadBinding.device_id == Device.id))
        no_commands = ~exists(select(Command.id).where(Command.device_id == Device.id))
        no_approvals = ~exists(select(Approval.id).where(Approval.device_id == Device.id))
        no_events = ~exists(select(EventLog.id).where(EventLog.device_id == Device.id))
        no_outbox = ~exists(
            select(DeviceOutbox.sequence).where(DeviceOutbox.device_id == Device.id)
        )
        terminal = and_(
            Device.status == DeviceStatus.REVOKED,
            Device.revoked_at.is_not(None),
            Device.revoked_at <= cutoff,
            Device.refresh_credential_hash.is_(None),
            Device.active_epoch.is_(None),
            Device.active_connection_nonce.is_(None),
            Device.last_server_acked_sequence == Device.last_server_sequence,
            no_pairings,
            no_connections,
            no_threads,
            no_commands,
            no_approvals,
            no_events,
            no_outbox,
        )
        return await self._delete_batch(
            db,
            Device,
            Device.id,
            terminal,
            Device.revoked_at,
        )

    async def _delete_audit_events(self, db: AsyncSession, now: datetime) -> int:
        cutoff = now - timedelta(days=self._settings.audit_event_retention_days)
        terminal = AuditEvent.created_at <= cutoff
        return await self._delete_batch(
            db,
            AuditEvent,
            AuditEvent.id,
            terminal,
            AuditEvent.created_at,
        )

    async def _delete_batch(
        self,
        db: AsyncSession,
        model: type[object],
        id_column: object,
        predicate: object,
        order_column: object,
    ) -> int:
        candidate_ids = list(
            (
                await db.scalars(
                    select(id_column)
                    .where(predicate)
                    .order_by(order_column, id_column)
                    .limit(self._settings.retention_sweep_batch_size)
                )
            ).all()
        )
        if not candidate_ids:
            await db.rollback()
            return 0
        await db.execute(delete(model).where(id_column.in_(candidate_ids), predicate))
        await db.commit()
        return len(candidate_ids)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
