from __future__ import annotations

import asyncio
import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from conftest import ORIGIN, Harness, exchange
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from control_api.models import (
    AuditEvent,
    Device,
    DevicePairing,
    DeviceStatus,
    PairingStatus,
)
from control_api.security import (
    TokenDigester,
    normalize_pairing_code,
    pairing_secret_commitment,
    pairing_start_proof,
)
from control_api.services import RequestMetadata


@dataclass(frozen=True)
class PairingAttempt:
    private_key: Ed25519PrivateKey
    code: str
    poll_token: str
    refresh_credential: str
    payload: dict[str, object]


def new_pairing_attempt(
    *,
    private_key: Ed25519PrivateKey | None = None,
    pairing_id: uuid.UUID | None = None,
    code: str = "ABCD-2345-CDEF-6789",
    poll_token: str | None = None,
    refresh_credential: str | None = None,
    display_name: str = "MacBook Pro",
    workspace_roots: list[str] | None = None,
    created_at: datetime | None = None,
) -> PairingAttempt:
    private_key = private_key or Ed25519PrivateKey.generate()
    pairing_id = pairing_id or uuid.uuid4()
    poll_token = poll_token or f"poll_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    refresh_credential = refresh_credential or f"dcr_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    roots = ["/Users/test/Projects"] if workspace_roots is None else workspace_roots
    proof_time = (created_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    created_text = proof_time.isoformat().replace("+00:00", "Z")
    public_key = (
        base64.urlsafe_b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        .rstrip(b"=")
        .decode()
    )
    code_commitment = pairing_secret_commitment(normalize_pairing_code(code))
    poll_commitment = pairing_secret_commitment(poll_token)
    refresh_commitment = pairing_secret_commitment(refresh_credential)
    audience = f"{ORIGIN}/codex-api/v1/device-pairings/start"
    proof = pairing_start_proof(
        pairing_id=pairing_id,
        created_at=created_text,
        audience=audience,
        public_key=public_key,
        code_commitment=code_commitment,
        poll_token_commitment=poll_commitment,
        refresh_credential_commitment=refresh_commitment,
        display_name=display_name,
        connector_version="0.1.11",
        codex_version="0.147.0",
        workspace_roots=roots,
    )
    signature = base64.urlsafe_b64encode(private_key.sign(proof)).rstrip(b"=").decode()
    return PairingAttempt(
        private_key=private_key,
        code=code,
        poll_token=poll_token,
        refresh_credential=refresh_credential,
        payload={
            "protocol_version": 2,
            "pairing_id": str(pairing_id),
            "created_at": created_text,
            "audience": audience,
            "public_key": public_key,
            "display_name": display_name,
            "connector_version": "0.1.11",
            "codex_version": "0.147.0",
            "workspace_roots": roots,
            "code_commitment": code_commitment,
            "poll_token_commitment": poll_commitment,
            "refresh_credential_commitment": refresh_commitment,
            "signature": signature,
        },
    )


def csrf_headers(harness: Harness) -> dict[str, str]:
    return {
        "Origin": ORIGIN,
        harness.settings.csrf_header_name: harness.client.cookies.get(
            harness.settings.csrf_cookie_name
        ),
    }


def signed_token_request(device: Device, attempt: PairingAttempt) -> dict[str, str]:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    nonce = (
        base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes[:8]).rstrip(b"=").decode()
    )
    proof = f"{device.id}\n{timestamp}\n{nonce}".encode()
    signature = base64.urlsafe_b64encode(attempt.private_key.sign(proof)).rstrip(b"=").decode()
    return {
        "device_id": str(device.id),
        "public_key": str(attempt.payload["public_key"]),
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }


async def start_pairing(harness: Harness, attempt: PairingAttempt):
    return await harness.client.post("/v1/device-pairings/start", json=attempt.payload)


async def claim_pairing(harness: Harness, attempt: PairingAttempt):
    return await harness.client.post(
        "/v1/pairings/claim",
        headers=csrf_headers(harness),
        json={"code": attempt.code},
    )


async def poll_pairing(harness: Harness, attempt: PairingAttempt):
    pairing_id = str(attempt.payload["pairing_id"])
    return await harness.client.get(
        f"/v1/device-pairings/{pairing_id}/poll",
        headers={"Authorization": f"Pairing {attempt.poll_token}"},
    )


async def test_pairing_is_retry_safe_and_server_never_receives_refresh_plaintext(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    attempt = new_pairing_attempt()
    start = await start_pairing(harness, attempt)
    assert start.status_code == 201
    start_body = start.json()
    assert start_body == {
        "pairing_id": str(attempt.payload["pairing_id"]),
        "expires_at": start_body["expires_at"],
        "poll_url": (f"/codex-api/v1/device-pairings/{attempt.payload['pairing_id']}/poll"),
    }
    serialized_response = start.text
    assert attempt.code not in serialized_response
    assert attempt.poll_token not in serialized_response
    assert attempt.refresh_credential not in serialized_response

    replayed_start = await start_pairing(harness, attempt)
    assert replayed_start.status_code == 201
    assert replayed_start.json() == start_body

    commitment_poll = await harness.client.get(
        f"/v1/device-pairings/{attempt.payload['pairing_id']}/poll",
        headers={"Authorization": f"Pairing {attempt.payload['poll_token_commitment']}"},
    )
    assert commitment_poll.status_code == 401

    pending = await poll_pairing(harness, attempt)
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"

    claim = await claim_pairing(harness, attempt)
    assert claim.status_code == 200
    device_id = claim.json()["device_id"]
    async with harness.database.session_factory() as db:
        provisional = await db.get(Device, uuid.UUID(device_id))
    assert provisional is None

    # A lost claim response can be retried after Control Session rotation by the
    # same stable Sub2API owner without creating another device or audit event.
    assert (await exchange(harness, "sub2api-access-token-rotated")).status_code == 201
    replayed_claim = await claim_pairing(harness, attempt)
    assert replayed_claim.status_code == 200
    assert replayed_claim.json()["device_id"] == device_id

    completed = await poll_pairing(harness, attempt)
    assert completed.status_code == 200
    assert completed.json() == {"status": "claimed", "device_id": device_id}
    repeated = await poll_pairing(harness, attempt)
    assert repeated.status_code == 200
    assert repeated.json() == completed.json()

    async with harness.database.session_factory() as db:
        pairing = await db.get(DevicePairing, uuid.UUID(str(attempt.payload["pairing_id"])))
        device = await db.get(Device, uuid.UUID(device_id))
        audits = list((await db.scalars(select(AuditEvent))).all())
    assert pairing is not None and pairing.status is PairingStatus.COMPLETED
    assert pairing.protocol_version == 2
    assert pairing.code_hash != attempt.payload["code_commitment"]
    assert pairing.poll_token_hash != attempt.payload["poll_token_commitment"]
    assert pairing.refresh_credential_hash != attempt.payload["refresh_credential_commitment"]
    assert device is not None and device.status is DeviceStatus.ACTIVE
    assert device.credential_scheme == 2
    assert device.credential_version == 1
    assert device.refresh_credential_hash == pairing.refresh_credential_hash

    token = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {attempt.refresh_credential}"},
        json=signed_token_request(device, attempt),
    )
    assert token.status_code == 200
    commitment_token = await harness.client.post(
        "/v1/device/connect-token",
        headers={"Authorization": f"Device {attempt.payload['refresh_credential_commitment']}"},
        json=signed_token_request(device, attempt),
    )
    assert commitment_token.status_code == 401

    stored_values = "|".join(
        str(value) for record in (pairing, device, *audits) for value in record.__dict__.values()
    )
    assert attempt.code not in stored_values
    assert attempt.poll_token not in stored_values
    assert attempt.refresh_credential not in stored_values
    assert [audit.action for audit in audits].count("pairing.start") == 1
    assert [audit.action for audit in audits].count("pairing.claim") == 1
    assert [audit.action for audit in audits].count("pairing.complete") == 1


async def test_completed_poll_replays_after_original_pairing_ttl(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    attempt = new_pairing_attempt()
    assert (await start_pairing(harness, attempt)).status_code == 201
    claim = await claim_pairing(harness, attempt)
    assert claim.status_code == 200
    assert (await poll_pairing(harness, attempt)).status_code == 200
    async with harness.database.session_factory() as db:
        pairing = await db.get(DevicePairing, uuid.UUID(str(attempt.payload["pairing_id"])))
        assert pairing is not None
        pairing.created_at = datetime.now(UTC) - timedelta(minutes=2)
        pairing.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()
    replay = await poll_pairing(harness, attempt)
    assert replay.status_code == 200
    assert replay.json()["device_id"] == claim.json()["device_id"]


async def test_concurrent_identical_starts_recover_the_committed_intent(
    harness: Harness,
) -> None:
    attempt = new_pairing_attempt()
    payload = attempt.payload
    second_reached_flush = asyncio.Event()
    first_committed = asyncio.Event()

    async with (
        harness.database.session_factory() as first_db,
        harness.database.session_factory() as second_db,
    ):
        original_first_flush = first_db.flush
        original_first_commit = first_db.commit
        original_second_flush = second_db.flush

        async def ordered_first_flush(*args, **kwargs):
            await asyncio.wait_for(second_reached_flush.wait(), timeout=2)
            return await original_first_flush(*args, **kwargs)

        async def notifying_first_commit(*args, **kwargs):
            result = await original_first_commit(*args, **kwargs)
            first_committed.set()
            return result

        async def conflicting_second_flush(*args, **kwargs):
            second_reached_flush.set()
            await asyncio.wait_for(first_committed.wait(), timeout=2)
            return await original_second_flush(*args, **kwargs)

        first_db.flush = ordered_first_flush  # type: ignore[method-assign]
        first_db.commit = notifying_first_commit  # type: ignore[method-assign]
        second_db.flush = conflicting_second_flush  # type: ignore[method-assign]

        async def start(db):
            return await harness.app.state.pairing_service.start(
                db,
                pairing_id=uuid.UUID(str(payload["pairing_id"])),
                proof_created_at=datetime.fromisoformat(
                    str(payload["created_at"]).replace("Z", "+00:00")
                ),
                audience=str(payload["audience"]),
                public_key=str(payload["public_key"]),
                device_name=str(payload["display_name"]),
                device_metadata={
                    "connector_version": str(payload["connector_version"]),
                    "codex_version": str(payload["codex_version"]),
                },
                workspace_roots=[str(root) for root in payload["workspace_roots"]],
                code_commitment=str(payload["code_commitment"]),
                poll_token_commitment=str(payload["poll_token_commitment"]),
                refresh_credential_commitment=str(payload["refresh_credential_commitment"]),
                signature=str(payload["signature"]),
                request_metadata=RequestMetadata("127.0.0.1", "test", None),
            )

        first, second = await asyncio.wait_for(
            asyncio.gather(start(first_db), start(second_db)),
            timeout=5,
        )

    assert first.record.id == second.record.id == uuid.UUID(str(payload["pairing_id"]))
    assert first.record.status is second.record.status is PairingStatus.PENDING
    async with harness.database.session_factory() as db:
        starts = await db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.action == "pairing.start")
        )
    assert starts == 1


async def test_completed_pairing_reconstructs_after_retention_row_is_deleted(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    attempt = new_pairing_attempt()
    assert (await start_pairing(harness, attempt)).status_code == 201
    claim = await claim_pairing(harness, attempt)
    assert claim.status_code == 200
    assert (await poll_pairing(harness, attempt)).status_code == 200

    pairing_id = uuid.UUID(str(attempt.payload["pairing_id"]))
    async with harness.database.session_factory() as db:
        pairing = await db.get(DevicePairing, pairing_id)
        assert pairing is not None
        await db.delete(pairing)
        await db.commit()

    conflicting = new_pairing_attempt(
        code="WXYZ-2345-CDEF-6789",
        refresh_credential=attempt.refresh_credential,
    )
    rejected = await start_pairing(harness, conflicting)
    assert rejected.status_code == 409

    recovered_start = await start_pairing(harness, attempt)
    assert recovered_start.status_code == 201
    recovered_poll = await poll_pairing(harness, attempt)
    assert recovered_poll.status_code == 200
    assert recovered_poll.json()["device_id"] == claim.json()["device_id"]
    async with harness.database.session_factory() as db:
        recovered = await db.get(DevicePairing, pairing_id)
    assert recovered is not None and recovered.status is PairingStatus.COMPLETED
    assert recovered.device_id == pairing_id


async def test_expired_unactivated_claim_releases_capacity_without_creating_device(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.settings.owner_max_device_records = 1
    first = new_pairing_attempt()
    assert (await start_pairing(harness, first)).status_code == 201
    first_claim = await claim_pairing(harness, first)
    assert first_claim.status_code == 200
    device_id = first_claim.json()["device_id"]
    now = datetime.now(UTC)
    async with harness.database.session_factory() as db:
        pairing = await db.get(DevicePairing, uuid.UUID(str(first.payload["pairing_id"])))
        assert pairing is not None
        pairing.created_at = now - timedelta(minutes=2)
        pairing.expires_at = now - timedelta(seconds=1)
        await db.commit()
    async with harness.database.session_factory() as db:
        assert await harness.app.state.pairing_service.expire_due(db, now) == 1
    async with harness.database.session_factory() as db:
        expired = await db.get(DevicePairing, uuid.UUID(str(first.payload["pairing_id"])))
        uncreated = await db.get(Device, uuid.UUID(device_id))
    assert expired is not None and expired.status is PairingStatus.EXPIRED
    assert uncreated is None

    second = new_pairing_attempt(code="CDEF-6789-GHJK-2345")
    assert (await start_pairing(harness, second)).status_code == 201
    second_claim = await claim_pairing(harness, second)
    assert second_claim.status_code == 200
    assert second_claim.json()["device_id"] != device_id
    async with harness.database.session_factory() as db:
        assert await db.scalar(select(func.count(Device.id))) == 0
        old_pairing = await db.get(DevicePairing, uuid.UUID(str(first.payload["pairing_id"])))
    assert old_pairing is not None and old_pairing.device_id is None
    assert (await poll_pairing(harness, second)).status_code == 200
    async with harness.database.session_factory() as db:
        assert await db.scalar(select(func.count(Device.id))) == 1


async def test_invalid_or_rebound_start_proof_is_rejected(harness: Harness) -> None:
    attempt = new_pairing_attempt()
    invalid = dict(attempt.payload)
    invalid["signature"] = "A" * 86
    rejected = await harness.client.post("/v1/device-pairings/start", json=invalid)
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "invalid_pairing_proof"}

    assert (await start_pairing(harness, attempt)).status_code == 201
    rebound = new_pairing_attempt(
        private_key=attempt.private_key,
        pairing_id=uuid.UUID(str(attempt.payload["pairing_id"])),
        code=attempt.code,
        poll_token=attempt.poll_token,
        refresh_credential=attempt.refresh_credential,
        display_name="Changed device",
    )
    conflict = await start_pairing(harness, rebound)
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "pairing_not_startable"}


async def test_pairing_claim_requires_csrf(harness: Harness) -> None:
    assert (await exchange(harness)).status_code == 201
    attempt = new_pairing_attempt()
    assert (await start_pairing(harness, attempt)).status_code == 201
    claim = await harness.client.post(
        "/v1/pairings/claim",
        headers={"Origin": ORIGIN},
        json={"code": attempt.code},
    )
    assert claim.status_code == 403
    assert claim.json() == {"detail": "csrf_validation_failed"}


async def test_pairing_claim_rejects_noncanonical_short_or_lowercase_codes(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    attempt = new_pairing_attempt()
    assert (await start_pairing(harness, attempt)).status_code == 201
    for code in ("ABCD-2345", attempt.code.lower(), "ABCD-2345-CDEF-678I"):
        response = await harness.client.post(
            "/v1/pairings/claim",
            headers=csrf_headers(harness),
            json={"code": code},
        )
        assert response.status_code == 422


async def test_pairing_start_is_rate_limited(harness: Harness) -> None:
    harness.settings.pairing_start_limit = 1
    first = await start_pairing(harness, new_pairing_attempt())
    second = await start_pairing(harness, new_pairing_attempt())
    assert first.status_code == 201
    assert second.status_code == 429
    assert second.headers["retry-after"] == str(harness.settings.rate_limit_window_seconds)


async def test_pairing_start_has_hard_live_source_cap(
    harness: Harness,
    monkeypatch,
) -> None:
    monkeypatch.setattr("control_api.services.MAX_LIVE_PAIRINGS_PER_SOURCE", 1)
    first = await start_pairing(harness, new_pairing_attempt())
    second = await start_pairing(harness, new_pairing_attempt())
    assert first.status_code == 201
    assert second.status_code == 429
    assert second.json() == {"detail": "pairing_capacity_exceeded"}


async def test_pairing_poll_global_ip_limit_blocks_rotating_pairing_ids(
    harness: Harness,
) -> None:
    harness.settings.pairing_poll_limit = 100
    harness.settings.pairing_poll_ip_limit = 1
    headers = {"Authorization": "Pairing invalid-but-nonempty"}
    first = await harness.client.get(f"/v1/device-pairings/{uuid.uuid4()}/poll", headers=headers)
    second = await harness.client.get(f"/v1/device-pairings/{uuid.uuid4()}/poll", headers=headers)
    assert first.status_code == 404
    assert second.status_code == 429
    assert second.json() == {"detail": "pairing_poll_rate_limited"}


async def test_pairing_rejects_noncanonical_workspace_roots(harness: Harness) -> None:
    for roots in (
        [],
        ["relative/path"],
        ["/"],
        ["/Users/test/../other"],
        ["/Users/test/Projects/"],
        ["/Users/test/Projects", "/Users/test/Projects"],
    ):
        attempt = new_pairing_attempt(workspace_roots=roots)
        response = await start_pairing(harness, attempt)
        assert response.status_code == 422, roots


async def test_pairing_claim_rejects_active_device_capacity_before_insert(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    harness.settings.bootstrap_max_devices = 1
    existing = Device(
        owner_user_id="42",
        name="Existing",
        public_key=f"existing-{uuid.uuid4()}",
        status=DeviceStatus.ACTIVE,
        device_metadata={},
        workspace_roots=["/workspace"],
    )
    async with harness.database.session_factory() as db:
        db.add(existing)
        await db.commit()
    attempt = new_pairing_attempt()
    assert (await start_pairing(harness, attempt)).status_code == 201
    claim = await claim_pairing(harness, attempt)
    assert claim.status_code == 409
    assert claim.json()["detail"] == "device_capacity_exceeded"
    async with harness.database.session_factory() as db:
        devices = list((await db.scalars(select(Device))).all())
        pairing = await db.get(DevicePairing, uuid.UUID(str(attempt.payload["pairing_id"])))
    assert [device.id for device in devices] == [existing.id]
    assert pairing is not None and pairing.status is PairingStatus.PENDING


async def test_pairing_claim_rejects_device_summary_over_byte_budget(
    harness: Harness,
) -> None:
    assert (await exchange(harness)).status_code == 201
    roots = [f"/{prefix}{'x' * 3998}" for prefix in ("a", "b", "c", "d", "e")]
    attempt = new_pairing_attempt(workspace_roots=roots)
    start = await start_pairing(harness, attempt)
    assert start.status_code == 429
    assert start.json()["detail"] == "pairing_capacity_exceeded"
    async with harness.database.session_factory() as db:
        assert list((await db.scalars(select(Device))).all()) == []


async def test_v2_refresh_hash_is_server_keyed(harness: Harness) -> None:
    attempt = new_pairing_attempt()
    digester = TokenDigester(harness.settings.session_hmac_secret.get_secret_value())
    expected = digester.digest(
        "device-refresh-v2", pairing_secret_commitment(attempt.refresh_credential)
    )
    assert expected != pairing_secret_commitment(attempt.refresh_credential)
