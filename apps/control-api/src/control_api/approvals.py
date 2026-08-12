from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .events import EventService
from .models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    AuditOutcome,
    Command,
    Device,
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)
from .operational_metrics import OperationalMetrics
from .schemas import ApprovalItem, BrowserEvent
from .services import RequestMetadata
from .storage import KeyValueStore
from .views import thread_summary

_LOGGER = logging.getLogger(__name__)


class ApprovalError(Exception):
    pass


class ApprovalNotFound(ApprovalError):
    pass


class ApprovalExpired(ApprovalError):
    pass


class ApprovalStaleEpoch(ApprovalError):
    pass


class ApprovalDeviceOffline(ApprovalError):
    pass


class ApprovalDecisionConflict(ApprovalError):
    pass


NON_DISPATCHABLE_APPROVAL_REASONS = frozenset(
    {
        "device_offline_default_deny",
        "disconnect_default_deny",
        "device_revoked_default_deny",
        "stale_epoch_default_deny",
    }
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ApprovalService:
    def __init__(
        self,
        store: KeyValueStore,
        events: EventService,
        metrics: OperationalMetrics | None = None,
    ) -> None:
        self._store = store
        self._events = events
        self._metrics = metrics or OperationalMetrics()

    @staticmethod
    def item(approval: Approval, device: Device) -> ApprovalItem:
        return ApprovalItem(
            approval_id=approval.id,
            command_id=approval.external_command_id
            or (str(approval.command_id) if approval.command_id else ""),
            kind=approval.approval_kind,
            summary=approval.summary,
            details=approval.request,
            expires_at=approval.expires_at,
            device_id=device.id,
            device_name=device.name,
            created_at=approval.requested_at,
        )

    async def list_pending(
        self,
        db: AsyncSession,
        owner_user_id: str,
    ) -> list[ApprovalItem]:
        rows = (
            await db.execute(
                select(Approval, Device)
                .join(Device, Device.id == Approval.device_id)
                .where(
                    Approval.owner_user_id == owner_user_id,
                    Approval.status == ApprovalStatus.PENDING,
                    Approval.expires_at > datetime.now(UTC),
                    Device.status != DeviceStatus.REVOKED,
                )
                .order_by(Approval.requested_at.desc())
            )
        ).all()
        return [self.item(approval, device) for approval, device in rows]

    async def decide(
        self,
        db: AsyncSession,
        *,
        owner_user_id: str,
        approval_id: uuid.UUID,
        decision: str,
        session_id: uuid.UUID,
        metadata: RequestMetadata,
    ) -> Approval:
        device_id = await db.scalar(
            select(Approval.device_id).where(
                Approval.id == approval_id,
                Approval.owner_user_id == owner_user_id,
            )
        )
        if device_id is None:
            self._metrics.approval_outcome("denied", "not_found_or_not_owned")
            raise ApprovalNotFound("approval was not found")
        device = await db.scalar(select(Device).where(Device.id == device_id).with_for_update())
        if device is None:
            self._metrics.approval_outcome("denied", "not_found_or_not_owned")
            raise ApprovalNotFound("approval was not found")
        await self._events.lock_owner_cursor(db, owner_user_id)
        approval = await db.scalar(
            select(Approval)
            .where(
                Approval.id == approval_id,
                Approval.owner_user_id == owner_user_id,
                Approval.device_id == device.id,
            )
            .with_for_update()
        )
        if approval is None:
            self._metrics.approval_outcome("denied", "not_found_or_not_owned")
            raise ApprovalNotFound("approval was not found")

        desired_status = ApprovalStatus.APPROVED if decision == "approve" else ApprovalStatus.DENIED
        desired_reason = "user_approved" if decision == "approve" else "user_denied"
        if approval.status != ApprovalStatus.PENDING:
            if approval.status == desired_status and approval.decision_reason == desired_reason:
                await db.commit()
                await self._best_effort_notify(
                    owner_user_id,
                    device.id,
                    approval.id,
                    [],
                    dispatchable=(
                        approval.decision_dispatched_at is None
                        and device.status == DeviceStatus.ACTIVE
                        and bool(device.active_connection_nonce)
                        and approval.appserver_epoch == device.active_epoch
                        and approval.decision_reason not in NON_DISPATCHABLE_APPROVAL_REASONS
                    ),
                )
                return approval
            self._metrics.approval_outcome("denied", "decision_conflict")
            raise ApprovalDecisionConflict("approval has already been decided")

        if device.status != DeviceStatus.ACTIVE:
            events = await self._default_deny_tx(
                db,
                approval,
                device,
                datetime.now(UTC),
                reason="device_revoked_default_deny",
            )
            await db.commit()
            self._metrics.approval_outcome("denied", "device_revoked_default_deny")
            await self._best_effort_notify(
                owner_user_id,
                device.id,
                approval.id,
                events,
                dispatchable=False,
            )
            raise ApprovalNotFound("approval was not found")

        now = datetime.now(UTC)
        if not device.active_epoch or device.active_epoch != approval.appserver_epoch:
            events = await self._default_deny_tx(
                db,
                approval,
                device,
                now,
                reason="stale_epoch_default_deny",
            )
            await db.commit()
            self._metrics.approval_outcome("denied", "stale_epoch_default_deny")
            await self._best_effort_notify(
                owner_user_id,
                device.id,
                approval.id,
                events,
                dispatchable=False,
            )
            raise ApprovalStaleEpoch("approval belongs to a stale app-server epoch")
        if _utc(approval.expires_at) <= now:
            reason, dispatchable = await self._expired_denial(device, approval)
            events = await self._default_deny_tx(
                db,
                approval,
                device,
                now,
                reason=reason,
            )
            await db.commit()
            self._metrics.approval_outcome("denied", reason)
            await self._best_effort_notify(
                owner_user_id,
                device.id,
                approval.id,
                events,
                dispatchable=dispatchable,
            )
            raise ApprovalExpired("approval has expired")
        registry_raw = await self._store.get(f"connection:{device.id}")
        try:
            parsed_registry = json.loads(registry_raw) if registry_raw is not None else {}
        except json.JSONDecodeError:
            parsed_registry = {}
        registry = parsed_registry if isinstance(parsed_registry, dict) else {}
        if (
            not device.active_connection_nonce
            or registry.get("connection_nonce") != device.active_connection_nonce
            or registry.get("epoch") != device.active_epoch
        ):
            events = await self._default_deny_tx(
                db,
                approval,
                device,
                now,
                reason="device_offline_default_deny",
            )
            await db.commit()
            self._metrics.approval_outcome("denied", "device_offline_default_deny")
            await self._best_effort_notify(
                owner_user_id,
                device.id,
                approval.id,
                events,
                dispatchable=False,
            )
            raise ApprovalDeviceOffline("device is offline")

        approval.status = desired_status
        approval.decided_at = now
        approval.decided_by_session_id = session_id
        approval.decision_reason = desired_reason
        db.add(
            AuditEvent(
                actor_user_id=owner_user_id,
                actor_session_id=session_id,
                action="approval.decide",
                outcome=AuditOutcome.SUCCEEDED,
                resource_type="approval",
                resource_id=str(approval.id),
                request_id=metadata.request_id,
                source_ip=metadata.source_ip,
                user_agent=metadata.user_agent,
                details={
                    "decision": decision,
                    "device_id": str(device.id),
                    "epoch": approval.appserver_epoch,
                },
            )
        )
        event = await self._events.append(
            db,
            owner_user_id=owner_user_id,
            device_id=device.id,
            event_type="approval.resolved",
            data={"approval_id": str(approval.id), "decision": decision},
        )
        await db.commit()
        self._metrics.approval_outcome(
            "approved" if desired_status == ApprovalStatus.APPROVED else "denied",
            desired_reason,
        )
        await self._best_effort_notify(
            owner_user_id,
            device.id,
            approval.id,
            [event],
            dispatchable=True,
        )
        return approval

    async def deny_stale_epoch(
        self,
        db: AsyncSession,
        device: Device,
        current_epoch: str,
    ) -> list[BrowserEvent]:
        return await self._deny_undispatched(
            db,
            device,
            reason="stale_epoch_default_deny",
            audit_reason="stale_epoch",
            current_epoch=current_epoch,
        )

    async def deny_disconnected(
        self,
        db: AsyncSession,
        device: Device,
    ) -> list[BrowserEvent]:
        return await self._deny_undispatched(
            db,
            device,
            reason="disconnect_default_deny",
            audit_reason="disconnect",
        )

    async def deny_revoked(
        self,
        db: AsyncSession,
        device: Device,
    ) -> list[BrowserEvent]:
        return await self._deny_undispatched(
            db,
            device,
            reason="device_revoked_default_deny",
            audit_reason="device_revoked",
        )

    async def _deny_undispatched(
        self,
        db: AsyncSession,
        device: Device,
        *,
        reason: str,
        audit_reason: str,
        current_epoch: str | None = None,
    ) -> list[BrowserEvent]:
        now = datetime.now(UTC)
        await self._events.lock_owner_cursor(db, device.owner_user_id)
        not_already_reconciled = or_(
            Approval.status.in_([ApprovalStatus.PENDING, ApprovalStatus.APPROVED]),
            and_(
                Approval.status == ApprovalStatus.DENIED,
                or_(
                    Approval.decision_reason.is_(None),
                    Approval.decision_reason.not_in(NON_DISPATCHABLE_APPROVAL_REASONS),
                ),
            ),
        )
        conditions = [
            Approval.device_id == device.id,
            Approval.decision_dispatched_at.is_(None),
            not_already_reconciled,
        ]
        if current_epoch is not None:
            conditions.append(Approval.appserver_epoch != current_epoch)
        claimed_ids = list(
            (
                await db.scalars(
                    update(Approval)
                    .where(*conditions)
                    .values(
                        status=ApprovalStatus.DENIED,
                        decided_at=now,
                        decided_by_session_id=None,
                        decision_reason=reason,
                        external_command_id=None,
                        summary="Approval denied",
                        request={},
                    )
                    .returning(Approval.id)
                )
            ).all()
        )
        if not claimed_ids:
            return []
        approvals = list(
            (
                await db.scalars(
                    select(Approval)
                    .where(Approval.id.in_(claimed_ids))
                    .order_by(Approval.requested_at, Approval.id)
                )
            ).all()
        )
        events: list[BrowserEvent] = []
        for approval in approvals:
            details: dict[str, object] = {
                "reason": audit_reason,
                "epoch": approval.appserver_epoch,
            }
            if current_epoch is not None:
                details["current_epoch"] = current_epoch
            events.extend(
                await self._append_default_deny_effects(
                    db,
                    approval,
                    device,
                    now,
                    reason=reason,
                    audit_details=details,
                )
            )
            self._metrics.approval_outcome("denied", reason)
        return events

    async def expire_due(self, db: AsyncSession, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        candidates = list(
            (
                await db.execute(
                    select(Approval.id, Approval.device_id, Approval.owner_user_id)
                    .where(
                        Approval.status == ApprovalStatus.PENDING,
                        Approval.expires_at <= now,
                    )
                    .order_by(Approval.device_id, Approval.id)
                    .limit(500)
                )
            ).all()
        )
        await db.rollback()
        expired = 0
        for approval_id, device_id, owner_user_id in candidates:
            device = await db.scalar(
                select(Device)
                .where(
                    Device.id == device_id,
                    Device.owner_user_id == owner_user_id,
                )
                .with_for_update()
            )
            if device is None:
                await db.rollback()
                continue
            await self._events.lock_owner_cursor(db, owner_user_id)
            approval = await db.scalar(
                select(Approval)
                .where(
                    Approval.id == approval_id,
                    Approval.device_id == device_id,
                    Approval.owner_user_id == owner_user_id,
                    Approval.status == ApprovalStatus.PENDING,
                    Approval.expires_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
            if approval is None:
                await db.rollback()
                continue
            reason, dispatchable = await self._expired_denial(device, approval)
            events = await self._default_deny_tx(
                db,
                approval,
                device,
                now,
                reason=reason,
            )
            await db.commit()
            self._metrics.approval_outcome("denied", reason)
            expired += 1
            await self._best_effort_notify(
                owner_user_id,
                device_id,
                approval_id,
                events,
                dispatchable=dispatchable,
            )
        return expired

    async def _expired_denial(
        self,
        device: Device,
        approval: Approval,
    ) -> tuple[str, bool]:
        if device.status != DeviceStatus.ACTIVE:
            return "device_revoked_default_deny", False
        if not device.active_epoch or device.active_epoch != approval.appserver_epoch:
            return "stale_epoch_default_deny", False
        if not device.active_connection_nonce:
            return "device_offline_default_deny", False
        try:
            registry_raw = await self._store.get(f"connection:{device.id}")
        except Exception:
            _LOGGER.exception(
                "failed to inspect device registry while expiring approval",
                extra={"approval_id": str(approval.id)},
            )
            return "device_offline_default_deny", False
        try:
            parsed_registry = json.loads(registry_raw) if registry_raw is not None else {}
        except json.JSONDecodeError:
            parsed_registry = {}
        registry = parsed_registry if isinstance(parsed_registry, dict) else {}
        if (
            registry.get("connection_nonce") != device.active_connection_nonce
            or registry.get("epoch") != device.active_epoch
        ):
            return "device_offline_default_deny", False
        return "timeout_default_deny", True

    async def reconcile_undispatched(self, db: AsyncSession, *, limit: int = 500) -> int:
        rows = list(
            (
                await db.execute(
                    select(Approval.id, Approval.device_id)
                    .join(Device, Device.id == Approval.device_id)
                    .where(
                        Approval.status.in_([ApprovalStatus.APPROVED, ApprovalStatus.DENIED]),
                        Approval.decision_dispatched_at.is_(None),
                        or_(
                            Approval.decision_reason.is_(None),
                            Approval.decision_reason.not_in(NON_DISPATCHABLE_APPROVAL_REASONS),
                        ),
                        Device.status == DeviceStatus.ACTIVE,
                        Device.active_connection_nonce.is_not(None),
                        Approval.appserver_epoch == Device.active_epoch,
                    )
                    .order_by(Approval.decided_at, Approval.id)
                    .limit(limit)
                )
            ).all()
        )
        notified = 0
        for approval_id, device_id in rows:
            try:
                await self._store.publish(
                    f"device-dispatch:{device_id}",
                    json.dumps({"kind": "approval", "approval_id": str(approval_id)}),
                )
                notified += 1
            except Exception:
                _LOGGER.exception(
                    "failed to reconcile undispatched approval decision",
                    extra={"approval_id": str(approval_id)},
                )
        return notified

    async def _default_deny_tx(
        self,
        db: AsyncSession,
        approval: Approval,
        device: Device,
        now: datetime,
        *,
        reason: str,
    ) -> list[BrowserEvent]:
        approval.status = ApprovalStatus.DENIED
        approval.decided_at = now
        approval.decided_by_session_id = None
        approval.decision_reason = reason
        approval.external_command_id = None
        approval.summary = "Approval denied"
        approval.request = {}
        return await self._append_default_deny_effects(
            db,
            approval,
            device,
            now,
            reason=reason,
            audit_details={"reason": reason},
        )

    async def _append_default_deny_effects(
        self,
        db: AsyncSession,
        approval: Approval,
        device: Device,
        now: datetime,
        *,
        reason: str,
        audit_details: dict[str, object],
    ) -> list[BrowserEvent]:
        db.add(
            AuditEvent(
                actor_user_id=approval.owner_user_id,
                actor_device_id=device.id,
                action="approval.default_deny",
                outcome=AuditOutcome.DENIED,
                resource_type="approval",
                resource_id=str(approval.id),
                details=audit_details,
            )
        )
        events = [
            await self._events.append(
                db,
                owner_user_id=device.owner_user_id,
                device_id=device.id,
                event_type="approval.resolved",
                data={"approval_id": str(approval.id), "decision": "deny", "reason": reason},
            )
        ]
        command = (
            await db.scalar(
                select(Command).where(
                    Command.id == approval.command_id,
                    Command.device_id == approval.device_id,
                    Command.owner_user_id == approval.owner_user_id,
                )
            )
            if approval.command_id is not None
            else None
        )
        binding = (
            await db.scalar(
                select(ThreadBinding)
                .where(
                    ThreadBinding.id == command.thread_binding_id,
                    ThreadBinding.device_id == approval.device_id,
                    ThreadBinding.owner_user_id == approval.owner_user_id,
                )
                .with_for_update()
            )
            if command is not None and command.thread_binding_id is not None
            else None
        )
        if (
            reason != "device_revoked_default_deny"
            and binding is not None
            and binding.status
            not in {
                ThreadBindingStatus.CLOSED,
                ThreadBindingStatus.STALE,
            }
        ):
            binding.status = ThreadBindingStatus.FAILED
            binding.active_turn_id = None
            binding.last_error = reason
            binding.updated_at = now
            data = thread_summary(binding).model_dump(mode="json")
            data["thread_id"] = str(binding.id)
            events.append(
                await self._events.append(
                    db,
                    owner_user_id=device.owner_user_id,
                    device_id=device.id,
                    thread_binding_id=binding.id,
                    event_type="thread.updated",
                    data=data,
                )
            )
        return events

    async def _best_effort_notify(
        self,
        owner_user_id: str,
        device_id: uuid.UUID,
        approval_id: uuid.UUID,
        events: list[BrowserEvent],
        *,
        dispatchable: bool,
    ) -> None:
        if dispatchable:
            try:
                await self._store.publish(
                    f"device-dispatch:{device_id}",
                    json.dumps({"kind": "approval", "approval_id": str(approval_id)}),
                )
            except Exception:
                _LOGGER.exception(
                    "failed to wake approval decision dispatcher",
                    extra={"approval_id": str(approval_id)},
                )
        for event in events:
            try:
                await self._events.publish(owner_user_id, event)
            except Exception:
                # EventLog is authoritative; the browser catches up from its cursor.
                _LOGGER.exception(
                    "failed to publish durable approval event",
                    extra={"approval_id": str(approval_id)},
                )
