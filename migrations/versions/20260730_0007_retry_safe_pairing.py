"""Make Connector-generated pairing credentials retry safe.

Revision ID: 20260730_0007
Revises: 20260730_0006
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0007"
down_revision: str | None = "20260730_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UPGRADE_LIVE_PAIRING_GUARD = """
DO $codex_control$
BEGIN
    LOCK TABLE device_pairings IN SHARE ROW EXCLUSIVE MODE;
    IF EXISTS (
        SELECT 1
        FROM device_pairings
        WHERE status IN ('pending', 'claimed')
    ) THEN
        RAISE EXCEPTION
            'cannot enable retry-safe pairing while v1 pending or claimed pairings exist; '
            'stop v1 workers and terminalize or complete every live pairing first';
    END IF;
END
$codex_control$
"""


DOWNGRADE_IDENTITY_GUARD = """
DO $codex_control$
BEGIN
    LOCK TABLE device_pairings, devices IN SHARE ROW EXCLUSIVE MODE;
    IF EXISTS (
        SELECT 1
        FROM device_pairings
        WHERE protocol_version = 2
    ) OR EXISTS (
        SELECT 1
        FROM devices
        WHERE credential_scheme = 2
    ) THEN
        RAISE EXCEPTION
            'cannot remove retry-safe pairing while v2 pairing credentials exist';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM devices
        GROUP BY public_key
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot restore global device public-key uniqueness after identity re-pairing';
    END IF;
END
$codex_control$
"""


def upgrade() -> None:
    # A v1 live pairing cannot be resumed after its server-generated secrets are
    # replaced by the Connector-owned v2 credential protocol.
    op.execute(UPGRADE_LIVE_PAIRING_GUARD)

    op.add_column(
        "device_pairings",
        sa.Column(
            "protocol_version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
    )
    op.add_column(
        "device_pairings",
        sa.Column("refresh_credential_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "device_pairings",
        sa.Column("proof_created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "device_pairings",
        sa.Column("audience", sa.String(length=4096), nullable=True),
    )
    op.create_check_constraint(
        "ck_device_pairings_supported_protocol_version",
        "device_pairings",
        "protocol_version IN (1, 2)",
    )
    op.create_unique_constraint(
        "uq_device_pairings_refresh_credential_hash",
        "device_pairings",
        ["refresh_credential_hash"],
    )
    op.create_index(
        "uq_device_pairings_live_public_key",
        "device_pairings",
        ["public_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'claimed')"),
    )

    op.add_column(
        "devices",
        sa.Column(
            "credential_scheme",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_devices_supported_credential_scheme",
        "devices",
        "credential_scheme IN (1, 2)",
    )
    op.drop_constraint("uq_devices_public_key", "devices", type_="unique")
    op.create_index(
        "uq_devices_live_public_key",
        "devices",
        ["public_key"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.execute(DOWNGRADE_IDENTITY_GUARD)
    op.drop_index("uq_devices_live_public_key", table_name="devices")
    op.create_unique_constraint("uq_devices_public_key", "devices", ["public_key"])
    op.drop_constraint(
        "ck_devices_supported_credential_scheme",
        "devices",
        type_="check",
    )
    op.drop_column("devices", "credential_scheme")

    op.drop_index("uq_device_pairings_live_public_key", table_name="device_pairings")
    op.drop_constraint(
        "uq_device_pairings_refresh_credential_hash",
        "device_pairings",
        type_="unique",
    )
    op.drop_constraint(
        "ck_device_pairings_supported_protocol_version",
        "device_pairings",
        type_="check",
    )
    op.drop_column("device_pairings", "audience")
    op.drop_column("device_pairings", "proof_created_at")
    op.drop_column("device_pairings", "refresh_credential_hash")
    op.drop_column("device_pairings", "protocol_version")
