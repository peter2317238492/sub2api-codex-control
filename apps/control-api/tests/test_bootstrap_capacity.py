from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import ORIGIN, Harness, exchange
from pydantic import ValidationError
from sqlalchemy import func, select

from control_api.capacity import bounded_model_catalog, ensure_device_creation_capacity
from control_api.config import Settings
from control_api.models import (
    Approval,
    ApprovalStatus,
    Device,
    DeviceStatus,
    ThreadBinding,
    ThreadBindingStatus,
)


def test_settings_reject_bootstrap_quota_combination_above_response_cap() -> None:
    settings = Settings()
    assert settings.bootstrap_worst_case_bytes < settings.bootstrap_max_response_bytes
    with pytest.raises(ValidationError, match="configured bootstrap quotas can exceed"):
        Settings(bootstrap_max_response_bytes=settings.bootstrap_worst_case_bytes - 1)


async def test_maximum_bootstrap_projection_fits_and_101st_thread_is_rejected(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    settings = harness.settings
    now = datetime.now(UTC)
    connection_nonce = str(uuid.uuid4())
    long_roots = [f"/{prefix}{'r' * 3898}" for prefix in ("a", "b", "c")]
    model_result = {
        "data": [
            {
                "id": f"model-{index}",
                "displayName": f"Model {index} " + "n" * 48,
                "description": "d" * 128,
            }
            for index in range(settings.bootstrap_max_models_per_device)
        ]
    }
    catalog = bounded_model_catalog(model_result, settings)
    assert len(catalog) == settings.bootstrap_max_models_per_device

    devices = [
        Device(
            owner_user_id="42",
            name=f"Device {index} " + "q" * 230,
            public_key=f"capacity-device-{index}-{uuid.uuid4()}",
            status=DeviceStatus.ACTIVE,
            device_metadata={
                "connector_version": "c" * 64,
                "codex_version": "v" * 64,
            },
            workspace_roots=long_roots,
            model_catalog=catalog,
            active_epoch="epoch-0123456789abcdef0123456789" if index == 0 else None,
            active_connection_nonce=connection_nonce if index == 0 else None,
        )
        for index in range(settings.bootstrap_max_devices)
    ]
    async with harness.database.session_factory() as db:
        db.add_all(devices)
        await db.flush()
        threads = [
            ThreadBinding(
                owner_user_id="42",
                device_id=devices[index % len(devices)].id,
                remote_thread_id=f"capacity-thread-{index}",
                status=ThreadBindingStatus.IDLE,
                cwd="/" + "w" * 4095,
                title="t" * 255,
                model="m" * 128,
                appserver_epoch="epoch-0123456789abcdef0123456789",
                snapshot={"messages": [{"legacy": "not part of bootstrap"}]},
                updated_at=now + timedelta(microseconds=index),
            )
            for index in range(settings.bootstrap_max_threads)
        ]
        approvals = [
            Approval(
                owner_user_id="42",
                device_id=devices[index % len(devices)].id,
                external_command_id=f"capacity-approval-{index}",
                approval_kind="permission",
                summary="s" * 512,
                request={"blob": "x" * 64_000, "quoted": '\\"\u0000'},
                status=ApprovalStatus.PENDING,
                appserver_epoch="epoch-0123456789abcdef0123456789",
                requested_at=now + timedelta(microseconds=index),
                expires_at=now + timedelta(minutes=5),
            )
            for index in range(settings.bootstrap_max_pending_approvals)
        ]
        db.add_all([*threads, *approvals])
        await db.commit()

    await harness.store.set(
        f"connection:{devices[0].id}",
        json.dumps(
            {
                "connection_nonce": connection_nonce,
                "epoch": "epoch-0123456789abcdef0123456789",
                "instance_id": "capacity-test",
            }
        ),
        90,
    )

    bootstrap = await harness.client.get("/v1/bootstrap")
    assert bootstrap.status_code == 200, bootstrap.text
    assert len(bootstrap.content) <= settings.bootstrap_worst_case_bytes
    body = bootstrap.json()
    assert len(body["devices"]) == settings.bootstrap_max_devices
    assert len(body["threads"]) == settings.bootstrap_max_threads
    assert len(body["approvals"]) == settings.bootstrap_max_pending_approvals
    assert all("messages" not in item for item in body["threads"])

    headers = {
        "Origin": ORIGIN,
        settings.csrf_header_name: harness.client.cookies.get(settings.csrf_cookie_name),
        "Idempotency-Key": "thread-capacity-overflow",
    }
    rejected = await harness.client.post(
        f"/v1/devices/{devices[0].id}/threads",
        headers=headers,
        json={"cwd": long_roots[0], "model": "gpt-5.5"},
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "thread_capacity_exceeded"

    async with harness.database.session_factory() as db:
        count = int(
            await db.scalar(
                select(func.count(ThreadBinding.id)).where(ThreadBinding.owner_user_id == "42")
            )
            or 0
        )
    assert count == settings.bootstrap_max_threads
    assert (await harness.client.get("/v1/bootstrap")).status_code == 200


async def test_revoke_frees_active_device_and_thread_slots_without_list_leak(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.settings.bootstrap_max_devices = 1
    harness.settings.bootstrap_max_threads = 1
    epoch = "epoch-0123456789abcdef0123456789"
    old = Device(
        owner_user_id="42",
        name="Old",
        public_key=f"old-device-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        device_metadata={},
        workspace_roots=["/workspace"],
    )
    async with harness.database.session_factory() as db:
        db.add(old)
        await db.flush()
        old_thread = ThreadBinding(
            owner_user_id="42",
            device_id=old.id,
            remote_thread_id="old-thread",
            status=ThreadBindingStatus.IDLE,
            cwd="/workspace",
            title="Old thread",
            model="gpt",
            appserver_epoch=epoch,
            snapshot={"messages": []},
        )
        db.add(old_thread)
        await db.commit()

    csrf = harness.client.cookies.get(harness.settings.csrf_cookie_name)
    headers = {"Origin": ORIGIN, harness.settings.csrf_header_name: csrf}
    revoked = await harness.client.delete(f"/v1/devices/{old.id}", headers=headers)
    assert revoked.status_code == 204
    assert (await harness.client.get(f"/v1/devices/{old.id}/threads")).status_code == 404
    assert (await harness.client.get("/v1/devices")).json() == {"items": []}

    nonce = str(uuid.uuid4())
    replacement = Device(
        owner_user_id="42",
        name="Replacement",
        public_key=f"replacement-device-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        device_metadata={},
        workspace_roots=["/workspace"],
        active_epoch=epoch,
        active_connection_nonce=nonce,
    )
    async with harness.database.session_factory() as db:
        await ensure_device_creation_capacity(db, harness.app.state.events, harness.settings, "42")
        db.add(replacement)
        await db.commit()
    await harness.store.set(
        f"connection:{replacement.id}",
        json.dumps({"connection_nonce": nonce, "epoch": epoch, "instance_id": "replacement"}),
        90,
    )

    started = await harness.client.post(
        f"/v1/devices/{replacement.id}/threads",
        headers={**headers, "Idempotency-Key": "replacement-thread"},
        json={"cwd": "/workspace", "model": "gpt"},
    )
    assert started.status_code == 202, started.text
    bootstrap = await harness.client.get("/v1/bootstrap")
    assert bootstrap.status_code == 200
    body = bootstrap.json()
    assert [item["id"] for item in body["devices"]] == [str(replacement.id)]
    assert [item["id"] for item in body["threads"]] == [started.json()["id"]]

    async with harness.database.session_factory() as db:
        stored_old_thread = await db.get(ThreadBinding, old_thread.id)
        total_devices = int(
            await db.scalar(select(func.count(Device.id)).where(Device.owner_user_id == "42")) or 0
        )
    assert stored_old_thread is not None
    assert stored_old_thread.status == ThreadBindingStatus.CLOSED
    assert total_devices == 2
